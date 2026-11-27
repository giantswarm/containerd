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
	"context"
	"fmt"
	"io"
	"os"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/pkg/atomicfile"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// tarIndexBlockSize is the block size of an EROFS tar index and of the
// dm-verity data blocks over a tar-index layer.
const tarIndexBlockSize = 512

// applySignedTarIndex writes the layer blob from a signed dm-verity target:
// the published EROFS tar index, the whole uncompressed tar zero-padded to
// 512 bytes, then the published dm-verity superblock and hash tree. It checks
// once that the data verifies against the tree and that the tree's root is the
// signed root hash, and stores the signature and the dm-verity metadata next to
// the blob for the mount to open the device with.
func (s erofsDiff) applySignedTarIndex(ctx context.Context, desc ocispec.Descriptor, target *snapshotters.DmverityTarget, tar io.Reader, layerBlobPath string) error {
	f, err := os.Create(layerBlobPath)
	if err != nil {
		return err
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	indexSize, err := s.copyBlob(ctx, f, target.Metadata)
	if err != nil {
		return fmt.Errorf("layer %s: write EROFS metadata: %w", desc.Digest, err)
	}
	if indexSize%tarIndexBlockSize != 0 {
		return fmt.Errorf("layer %s: EROFS metadata %s is %d bytes, not a multiple of %d",
			desc.Digest, target.Metadata.Digest, indexSize, tarIndexBlockSize)
	}
	tarSize, err := io.Copy(f, tar)
	if err != nil {
		return fmt.Errorf("layer %s: write uncompressed tar: %w", desc.Digest, err)
	}
	hashOffset := alignUp(indexSize+tarSize, tarIndexBlockSize)
	if _, err := f.Seek(hashOffset, io.SeekStart); err != nil {
		return err
	}
	if _, err := s.copyBlob(ctx, f, target.Tree); err != nil {
		return fmt.Errorf("layer %s: write dm-verity hash tree: %w", desc.Digest, err)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	f = nil
	if err != nil {
		return err
	}

	if err := dmverity.VerifyLayer(layerBlobPath, uint64(hashOffset), target.RootHash); err != nil {
		return fmt.Errorf("layer %s: %w", desc.Digest, err)
	}

	sig, err := atomicfile.New(dmverity.SignaturePath(layerBlobPath), 0644)
	if err != nil {
		return err
	}
	if _, err := s.copyBlob(ctx, sig, target.Signature); err != nil {
		sig.Cancel()
		return fmt.Errorf("layer %s: write dm-verity signature: %w", desc.Digest, err)
	}
	if err := sig.Close(); err != nil {
		return err
	}
	if err := dmverity.WriteMetadata(layerBlobPath, dmverity.DmverityMetadata{
		RootHash:   target.RootHash,
		HashOffset: uint64(hashOffset),
	}); err != nil {
		return err
	}

	log.G(ctx).WithFields(log.Fields{
		"path":       layerBlobPath,
		"referrer":   target.Referrer,
		"rootHash":   target.RootHash,
		"hashOffset": hashOffset,
	}).Debug("Applied layer from signed dm-verity referrer")
	return nil
}

// copyBlob copies a blob of the content store to w and checks its size.
func (s erofsDiff) copyBlob(ctx context.Context, w io.Writer, desc ocispec.Descriptor) (int64, error) {
	ra, err := s.store.ReaderAt(ctx, desc)
	if err != nil {
		return 0, err
	}
	defer ra.Close()
	n, err := io.Copy(w, content.NewReader(ra))
	if err != nil {
		return n, err
	}
	if n != desc.Size {
		return n, fmt.Errorf("blob %s is %d bytes, expected %d", desc.Digest, n, desc.Size)
	}
	return n, nil
}

func alignUp(n, align int64) int64 {
	return (n + align - 1) / align * align
}
