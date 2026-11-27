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

package snapshotters

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/plugins/content/local"
)

type fakeReferrersFetcher struct {
	blobs     map[digest.Digest][]byte
	referrers []ocispec.Descriptor
}

func (f *fakeReferrersFetcher) Fetch(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	b, ok := f.blobs[desc.Digest]
	if !ok {
		return nil, errdefs.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *fakeReferrersFetcher) FetchReferrers(context.Context, digest.Digest, ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	return f.referrers, nil
}

func (f *fakeReferrersFetcher) add(mediaType string, data []byte, annotations map[string]string) ocispec.Descriptor {
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data)), Annotations: annotations}
	f.blobs[desc.Digest] = data
	return desc
}

var (
	testRootHash1 = strings.Repeat("ab", 32)
	testRootHash2 = strings.Repeat("cd", 32)
)

type testImage struct {
	fetcher  *fakeReferrersFetcher
	manifest ocispec.Descriptor
	children []ocispec.Descriptor
	layers   []ocispec.Descriptor
}

// newTestImage returns a manifest with two layers and a referrer carrying the
// artifacts in blobs, keyed by layer index.
func newTestImage(t *testing.T, skip map[string]bool) testImage {
	t.Helper()
	f := &fakeReferrersFetcher{blobs: map[digest.Digest][]byte{}}
	img := testImage{fetcher: f}
	img.layers = []ocispec.Descriptor{
		f.add(ocispec.MediaTypeImageLayerGzip, []byte("layer-1"), nil),
		f.add(ocispec.MediaTypeImageLayerGzip, []byte("layer-2"), map[string]string{
			// A manifest cannot pre-seed the signed identity.
			TargetLayerDmverityLabel:      `{"rootHash":"forged"}`,
			dmverityReferrerRootHashLabel: "forged",
		}),
	}
	config := f.add(ocispec.MediaTypeImageConfig, []byte("{}"), nil)
	img.children = append([]ocispec.Descriptor{config}, img.layers...)
	img.manifest = f.add(ocispec.MediaTypeImageManifest, []byte("manifest"), nil)

	var blobs []ocispec.Descriptor
	for i, layer := range img.layers {
		src := map[string]string{sourceLayerDigestAnnotation: layer.Digest.String()}
		root := []string{testRootHash1, testRootHash2}[i]
		if !skip["metadata"+layer.Digest.String()] {
			blobs = append(blobs, f.add(erofsMetadataArtifactMediaType, []byte("index-"+root), src))
		}
		if !skip["tree"+layer.Digest.String()] {
			blobs = append(blobs, f.add(merkleTreeArtifactMediaType, []byte("tree-"+root), src))
		}
		if !skip["signature"+layer.Digest.String()] {
			blobs = append(blobs, f.add(layerSignatureMediaType, []byte("sig-"+root), map[string]string{
				sourceLayerDigestAnnotation: layer.Digest.String(),
				layerRootHashAnnotation:     strings.ToUpper(root),
			}))
		}
	}
	referrer, err := json.Marshal(ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: signatureArtifactType,
		Config:       ocispec.DescriptorEmptyJSON,
		Layers:       blobs,
		Subject:      &img.manifest,
	})
	require.NoError(t, err)
	ref := f.add(ocispec.MediaTypeImageManifest, referrer, map[string]string{ocispec.AnnotationCreated: "2026-11-27T10:00:00Z"})
	ref.ArtifactType = signatureArtifactType
	f.referrers = []ocispec.Descriptor{ref}
	return img
}

func (img testImage) handle(t *testing.T) (content.Store, []ocispec.Descriptor, error) {
	t.Helper()
	store, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	inner := images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return img.children, nil
	})
	children, err := AppendDmverityReferrersHandlerWrapper(img.fetcher, store)(inner).Handle(context.Background(), img.manifest)
	return store, children, err
}

func TestDmverityReferrersHandlerAnnotatesLayers(t *testing.T) {
	img := newTestImage(t, nil)
	store, children, err := img.handle(t)
	require.NoError(t, err)
	require.Len(t, children, 3)
	assert.Empty(t, children[0].Annotations[TargetLayerDmverityLabel], "config is not annotated")

	for i, root := range []string{testRootHash1, testRootHash2} {
		layer := children[i+1]
		target, err := ParseDmverityTarget(layer.Annotations[TargetLayerDmverityLabel])
		require.NoError(t, err)
		assert.Equal(t, root, target.RootHash)
		assert.Equal(t, img.fetcher.referrers[0].Digest, target.Referrer)
		assert.Equal(t, root, layer.Annotations[dmverityReferrerRootHashLabel])
		assert.Equal(t, target.Signature.Digest.String(), layer.Annotations[dmverityReferrerSignatureDigestLabel])
		for _, blob := range []ocispec.Descriptor{target.Metadata, target.Tree, target.Signature} {
			_, err := store.Info(context.Background(), blob.Digest)
			assert.NoError(t, err, "artifact %s is in the content store", blob.MediaType)
		}
	}
	assert.Equal(t, "forged", img.children[2].Annotations[dmverityReferrerRootHashLabel], "the input is not mutated")
}

func TestDmverityReferrersHandlerRefusesUnsignedLayers(t *testing.T) {
	t.Run("no referrer", func(t *testing.T) {
		img := newTestImage(t, nil)
		img.fetcher.referrers = nil
		_, _, err := img.handle(t)
		require.EqualError(t, err, "layer "+img.layers[0].Digest.String()+
			" has no signed dm-verity root hash: image manifest "+img.manifest.Digest.String()+
			" has no application/vnd.containerd.erofs.dmverity.v1 referrer")
	})
	for _, missing := range []struct{ blob, text string }{
		{"signature", "signature"},
		{"metadata", "EROFS metadata"},
		{"tree", "Merkle tree"},
	} {
		t.Run("missing "+missing.blob, func(t *testing.T) {
			probe := newTestImage(t, nil)
			img := newTestImage(t, map[string]bool{missing.blob + probe.layers[1].Digest.String(): true})
			_, _, err := img.handle(t)
			require.ErrorContains(t, err, "incomplete dm-verity artifacts for layer "+img.layers[1].Digest.String()+": missing "+missing.text)
		})
	}
}

func TestSelectDmverityReferrer(t *testing.T) {
	ref := func(d, created string) ocispec.Descriptor {
		desc := ocispec.Descriptor{
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: signatureArtifactType,
			Digest:       digest.Digest("sha256:" + strings.Repeat(d, 64)),
			Size:         10,
		}
		if created != "" {
			desc.Annotations = map[string]string{ocispec.AnnotationCreated: created}
		}
		return desc
	}
	other := ref("f", "2030-01-01T00:00:00Z")
	other.ArtifactType = "application/vnd.example"

	selected, found, err := selectDmverityReferrer(context.Background(), []ocispec.Descriptor{
		ref("1", "2026-01-01T00:00:00Z"),
		ref("3", "2026-06-01T00:00:00Z"),
		ref("2", "2026-06-01T00:00:00Z"),
		ref("0", ""),
		other,
	})
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, ref("2", "").Digest, selected.Digest, "newest wins, ties go to the lowest digest")

	_, found, err = selectDmverityReferrer(context.Background(), []ocispec.Descriptor{other})
	require.NoError(t, err)
	assert.False(t, found)

	conflict := ref("2", "2026-06-01T00:00:00Z")
	conflict.Size = 11
	_, _, err = selectDmverityReferrer(context.Background(), []ocispec.Descriptor{ref("2", "2026-06-01T00:00:00Z"), conflict})
	assert.ErrorContains(t, err, "conflicting dm-verity referrer descriptors")
}

func TestReadDmverityBundleManifestRejects(t *testing.T) {
	layer := digest.FromString("layer").String()
	layers := map[string]struct{}{layer: {}}
	subject := ocispec.Descriptor{Digest: digest.FromString("subject")}
	referrer := ocispec.Descriptor{Digest: digest.FromString("referrer")}
	sig := func(data string) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: layerSignatureMediaType, Digest: digest.FromString(data), Size: 3,
			Annotations: map[string]string{sourceLayerDigestAnnotation: layer, layerRootHashAnnotation: testRootHash1}}
	}
	for name, tc := range map[string]struct {
		manifest ocispec.Manifest
		err      string
	}{
		"artifact type": {
			ocispec.Manifest{ArtifactType: "application/vnd.example", Subject: &subject},
			"unexpected artifact type",
		},
		"subject": {
			ocispec.Manifest{ArtifactType: signatureArtifactType, Subject: &referrer},
			"subject does not match image manifest " + subject.Digest.String(),
		},
		"duplicate signature": {
			ocispec.Manifest{ArtifactType: signatureArtifactType, Subject: &subject, Layers: []ocispec.Descriptor{sig("a"), sig("b")}},
			"duplicate signature descriptor for layer " + layer,
		},
		"invalid root hash": {
			ocispec.Manifest{ArtifactType: signatureArtifactType, Subject: &subject, Layers: []ocispec.Descriptor{{
				MediaType: layerSignatureMediaType, Digest: digest.FromString("a"), Size: 3,
				Annotations: map[string]string{sourceLayerDigestAnnotation: layer, layerRootHashAnnotation: "abc"},
			}}},
			"invalid SHA-256 dm-verity root hash",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readDmverityBundleManifest(tc.manifest, referrer, subject, layers)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestWithDmverityReferrersPassesTarget(t *testing.T) {
	info := &DmverityTarget{
		RootHash:  testRootHash1,
		Metadata:  ocispec.Descriptor{MediaType: erofsMetadataArtifactMediaType, Digest: digest.FromString("m"), Size: 1},
		Tree:      ocispec.Descriptor{MediaType: merkleTreeArtifactMediaType, Digest: digest.FromString("t"), Size: 1},
		Signature: ocispec.Descriptor{MediaType: layerSignatureMediaType, Digest: digest.FromString("s"), Size: 1},
	}
	value, err := targetAnnotation(info)
	require.NoError(t, err)

	var config diff.ApplyConfig
	desc := ocispec.Descriptor{Annotations: map[string]string{TargetLayerDmverityLabel: value}}
	require.NoError(t, WithDmverityReferrers()(context.Background(), desc, &config))
	target, err := DmverityApplyTarget(config)
	require.NoError(t, err)
	assert.Equal(t, info, target)

	config = diff.ApplyConfig{}
	require.NoError(t, WithDmverityReferrers()(context.Background(), ocispec.Descriptor{}, &config))
	target, err = DmverityApplyTarget(config)
	require.NoError(t, err)
	assert.Nil(t, target)
}

func TestValidateDmveritySnapshot(t *testing.T) {
	signed := map[string]string{
		dmverityReferrerRootHashLabel:        testRootHash1,
		dmverityReferrerSignatureDigestLabel: digest.FromString("sig").String(),
	}
	otherSig := map[string]string{
		dmverityReferrerRootHashLabel:        testRootHash1,
		dmverityReferrerSignatureDigestLabel: digest.FromString("other").String(),
	}
	otherRoot := map[string]string{
		dmverityReferrerRootHashLabel:        testRootHash2,
		dmverityReferrerSignatureDigestLabel: digest.FromString("sig").String(),
	}
	assert.NoError(t, ValidateDmveritySnapshot(signed, signed))
	assert.NoError(t, ValidateDmveritySnapshot(nil, nil), "an unsigned layer reuses any snapshot")
	assert.ErrorContains(t, ValidateDmveritySnapshot(nil, signed), "existing snapshot is not signed")
	assert.ErrorContains(t, ValidateDmveritySnapshot(otherRoot, signed), "different signed dm-verity root hash")
	assert.ErrorContains(t, ValidateDmveritySnapshot(otherSig, signed), "different signed dm-verity signature digest")
}
