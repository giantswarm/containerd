/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package erofs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins/content/local"
)

type signedLayer struct {
	index, tar, tree, sig []byte
	rootHash              string
	hashOffset            uint64
	// device is the expected layer blob: index ‖ tar ‖ zero padding ‖ tree.
	device []byte
}

// newSignedLayer builds what a signer publishes for a layer: the tar index,
// the dm-verity superblock and tree over index ‖ tar padded to 512 bytes, and
// the root hash.
func newSignedLayer(t *testing.T, index, tar []byte) signedLayer {
	t.Helper()
	data := append(append([]byte{}, index...), tar...)
	data = append(data, make([]byte, int(alignUp(int64(len(data)), tarIndexBlockSize))-len(data))...)
	p := filepath.Join(t.TempDir(), "signer.erofs")
	require.NoError(t, os.WriteFile(p, data, 0644))
	opts := dmverity.DefaultDmverityOptions()
	opts.DataBlockSize = tarIndexBlockSize
	opts.HashBlockSize = tarIndexBlockSize
	require.NoError(t, dmverity.FormatLayer(context.Background(), p, opts))
	md, err := dmverity.ReadMetadata(p)
	require.NoError(t, err)
	device, err := os.ReadFile(p)
	require.NoError(t, err)
	return signedLayer{
		index: index, tar: tar, tree: device[md.HashOffset:], sig: []byte("pkcs7-signature"),
		rootHash: md.RootHash, hashOffset: md.HashOffset, device: device,
	}
}

func writeTestBlob(t *testing.T, cs content.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	require.NoError(t, content.WriteBlob(context.Background(), cs, desc.Digest.String(), bytes.NewReader(data), desc))
	return desc
}

// apply stores the layer and its artifacts, annotates the layer with rootHash
// as its signed target (unless rootHash is empty), and applies it.
func (l signedLayer) apply(t *testing.T, tar []byte, rootHash string) (string, ocispec.Descriptor, ocispec.Descriptor, error) {
	t.Helper()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	desc := writeTestBlob(t, cs, ocispec.MediaTypeImageLayer, tar)
	if rootHash != "" {
		target, err := json.Marshal(snapshotters.DmverityTarget{
			RootHash:  rootHash,
			Metadata:  writeTestBlob(t, cs, "application/vnd.containerd.erofs.metadata.v1", l.index),
			Tree:      writeTestBlob(t, cs, "application/vnd.containerd.erofs.dmverity.merkle-tree.v1", l.tree),
			Signature: writeTestBlob(t, cs, "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7", l.sig),
		})
		require.NoError(t, err)
		desc.Annotations = map[string]string{snapshotters.TargetLayerDmverityLabel: string(target)}
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".erofslayer"), nil, 0644))
	mounts := []mount.Mount{{Type: "bind", Source: filepath.Join(dir, "fs"), Options: []string{"rw", "rbind"}}}
	d := NewErofsDiffer(cs, WithTarIndexMode(), WithDmverity(), WithDmverityReferrers())
	applied, err := d.Apply(context.Background(), desc, mounts, snapshotters.WithDmverityReferrers())
	return filepath.Join(dir, "layer.erofs"), desc, applied, err
}

// kernelCheck is a call of the kernel's signature check, with what was stored
// next to the layer blob when it ran.
type kernelCheck struct {
	blob, name, rootHash, signaturePath string
	hashOffset                          uint64
	signature                           []byte
	metadataStored                      bool
}

// stubKernelCheck replaces the kernel's signature check, which needs root and
// device-mapper, with one that records its calls and returns refusal.
func stubKernelCheck(t *testing.T, refusal error) *[]kernelCheck {
	t.Helper()
	var calls []kernelCheck
	orig := dmverityVerifySignature
	t.Cleanup(func() { dmverityVerifySignature = orig })
	dmverityVerifySignature = func(blob, name, rootHash string, hashOffset uint64, signaturePath string) error {
		sig, _ := os.ReadFile(signaturePath)
		_, statErr := os.Stat(dmverity.MetadataPath(blob))
		calls = append(calls, kernelCheck{blob: blob, name: name, rootHash: rootHash, signaturePath: signaturePath,
			hashOffset: hashOffset, signature: sig, metadataStored: statErr == nil})
		return refusal
	}
	return &calls
}

func TestApplySignedTarIndex(t *testing.T) {
	index := bytes.Repeat([]byte{0xe0}, 2*tarIndexBlockSize)
	tar := bytes.Repeat([]byte("tar-bytes-"), 333) // not a multiple of 512
	l := newSignedLayer(t, index, tar)

	t.Run("assembles the device from the published artifacts", func(t *testing.T) {
		checks := stubKernelCheck(t, nil)
		blob, _, applied, err := l.apply(t, tar, strings.ToUpper(l.rootHash))
		require.NoError(t, err)
		assert.Equal(t, []kernelCheck{{blob: blob, name: verifyDeviceName(blob), rootHash: strings.ToUpper(l.rootHash),
			signaturePath: dmverity.SignaturePath(blob), hashOffset: l.hashOffset, signature: l.sig}}, *checks,
			"the kernel checks the stored signature once, before the metadata the mount needs is stored")
		assert.True(t, strings.HasPrefix(verifyDeviceName(blob), "containerd-erofs-verify-"), verifyDeviceName(blob))
		assert.Equal(t, digest.FromBytes(tar), applied.Digest, "the diff ID covers the whole uncompressed tar")
		assert.Equal(t, int64(len(tar)), applied.Size)

		device, err := os.ReadFile(blob)
		require.NoError(t, err)
		assert.Equal(t, l.device, device, "index ‖ tar ‖ zero padding ‖ published superblock and tree")

		sig, err := os.ReadFile(dmverity.SignaturePath(blob))
		require.NoError(t, err)
		assert.Equal(t, l.sig, sig, "the signature is stored with the snapshot")

		md, err := dmverity.ReadMetadata(blob)
		require.NoError(t, err)
		assert.Equal(t, l.hashOffset, md.HashOffset)
		assert.True(t, strings.EqualFold(l.rootHash, md.RootHash))
	})

	t.Run("refuses a signature the kernel does not accept", func(t *testing.T) {
		checks := stubKernelCheck(t, errors.New("failed to open dm-verity device: load table: dm table load 'dev': required key not available"))
		blob, desc, _, err := l.apply(t, tar, l.rootHash)
		require.EqualError(t, err, "layer "+desc.Digest.String()+": dm-verity signature "+digest.FromBytes(l.sig).String()+
			" not accepted by the kernel: failed to open dm-verity device: load table: dm table load 'dev': required key not available")
		assert.Len(t, *checks, 1)
		for _, p := range []string{dmverity.SignaturePath(blob), dmverity.MetadataPath(blob)} {
			_, statErr := os.Stat(p)
			assert.ErrorIs(t, statErr, os.ErrNotExist, "nothing is stored for a refused layer: %s", p)
		}
	})

	t.Run("refuses a root hash the tree does not end in", func(t *testing.T) {
		checks := stubKernelCheck(t, nil)
		signed := strings.Repeat("0", 64)
		blob, desc, _, err := l.apply(t, tar, signed)
		require.EqualError(t, err, "layer "+desc.Digest.String()+": dm-verity root hash mismatch: data has "+l.rootHash+", signed "+signed)
		_, statErr := os.Stat(dmverity.SignaturePath(blob))
		assert.ErrorIs(t, statErr, os.ErrNotExist, "nothing is stored for a refused layer")
		assert.Empty(t, *checks, "the kernel is not asked about data that does not match the signed root hash")
	})

	t.Run("refuses data the tree does not cover", func(t *testing.T) {
		stubKernelCheck(t, nil)
		tampered := bytes.Clone(tar)
		tampered[100] ^= 0xff
		_, desc, _, err := l.apply(t, tampered, l.rootHash)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "layer "+desc.Digest.String()+": dm-verity root hash mismatch: data has "), err.Error())
		assert.True(t, strings.HasSuffix(err.Error(), ", signed "+l.rootHash), err.Error())
		assert.NotContains(t, err.Error(), "data has "+l.rootHash)
	})

	t.Run("refuses a layer without a signed target", func(t *testing.T) {
		stubKernelCheck(t, nil)
		_, desc, _, err := l.apply(t, tar, "")
		require.EqualError(t, err, "layer "+desc.Digest.String()+" has no signed dm-verity root hash")
	})

	t.Run("refuses an index that is not block aligned", func(t *testing.T) {
		stubKernelCheck(t, nil)
		short := newSignedLayer(t, index[:100], tar)
		_, _, _, err := short.apply(t, tar, short.rootHash)
		require.ErrorContains(t, err, "is 100 bytes, not a multiple of 512")
	})
}
