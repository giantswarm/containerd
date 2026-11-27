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

package dmverity

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Offsets of fields in the dm-verity superblock.
const (
	sbHashType      = 12
	sbAlgorithm     = 32
	sbDataBlockSize = 64
	sbHashBlockSize = 68
	sbDataBlocks    = 72
	sbSaltSize      = 80
)

// formattedLayer writes a layer blob of 8 blocks of 512 bytes followed by its
// dm-verity superblock and hash tree, and returns its path, hash offset and
// root hash.
func formattedLayer(t *testing.T) (string, uint64, string) {
	t.Helper()
	blob := filepath.Join(t.TempDir(), "layer.erofs")
	require.NoError(t, os.WriteFile(blob, bytes.Repeat([]byte("layer-data"), 400), 0644))
	opts := DefaultDmverityOptions()
	opts.DataBlockSize = 512
	opts.HashBlockSize = 512
	require.NoError(t, FormatLayer(context.Background(), blob, opts))
	md, err := ReadMetadata(blob)
	require.NoError(t, err)
	return blob, md.HashOffset, md.RootHash
}

func TestVerifyLayer(t *testing.T) {
	t.Run("accepts the data the tree covers", func(t *testing.T) {
		blob, hashOffset, rootHash := formattedLayer(t)
		assert.NoError(t, VerifyLayer(blob, hashOffset, rootHash))
	})

	t.Run("names the data's root hash on a mismatch", func(t *testing.T) {
		blob, hashOffset, rootHash := formattedLayer(t)
		signed := "00" + rootHash[2:]
		assert.EqualError(t, VerifyLayer(blob, hashOffset, signed),
			"dm-verity root hash mismatch: data has "+rootHash+", signed "+signed)
	})

	// A published tree is untrusted: a superblock the device's open would
	// refuse fails the check with the field, and never sizes or indexes the
	// diagnostic that computes the data's root hash.
	for _, tc := range []struct {
		name   string
		offset int
		value  []byte
		err    string
	}{
		{"salt larger than the superblock holds", sbSaltSize, le16(257), "superblock salt too large: 257"},
		{"data block size not a power of two", sbDataBlockSize, le32(1000), "invalid block size in superblock: data 1000 hash 512"},
		{"data block size zero", sbDataBlockSize, le32(0), "invalid block size in superblock: data 0 hash 512"},
		{"hash block size beyond the maximum", sbHashBlockSize, le32(1 << 20), "invalid block size in superblock: data 512 hash 1048576"},
		{"unsupported hash type", sbHashType, le32(2), "unsupported hash type 2"},
		{"unsupported hash algorithm", sbAlgorithm, []byte("md5\x00\x00\x00"), "hash algorithm md5 not supported"},
		{"missing hash algorithm", sbAlgorithm, make([]byte, 32), "missing hash algorithm in superblock"},
		{"block count overflowing the data size", sbDataBlocks, le64(1<<55 + 8), "dm-verity superblock covers 36028797018963976 blocks of 512 bytes, the data is 4096 bytes"},
	} {
		t.Run("refuses a superblock with "+tc.name, func(t *testing.T) {
			blob, hashOffset, rootHash := formattedLayer(t)
			f, err := os.OpenFile(blob, os.O_WRONLY, 0)
			require.NoError(t, err)
			_, err = f.WriteAt(tc.value, int64(hashOffset)+int64(tc.offset))
			require.NoError(t, err)
			require.NoError(t, f.Close())

			err = VerifyLayer(blob, hashOffset, rootHash)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
