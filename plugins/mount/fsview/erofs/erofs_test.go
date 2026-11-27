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
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/errdefs"
	goerofs "github.com/erofs/go-erofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleMountUnsupportedCompression(t *testing.T) {
	const (
		superBlockOffset       = 1024
		superBlockSize         = 128
		blockSizeBitsOffset    = 12
		featureIncompatOffset  = 80
		unsupportedCompression = 0x2
		erofsMagic             = 0xe0f5e1e2
	)

	image := make([]byte, superBlockOffset+superBlockSize)
	superBlock := image[superBlockOffset:]
	binary.LittleEndian.PutUint32(superBlock, erofsMagic)
	superBlock[blockSizeBitsOffset] = 12
	binary.LittleEndian.PutUint32(superBlock[featureIncompatOffset:], unsupportedCompression)

	imagePath := filepath.Join(t.TempDir(), "compressed.erofs")
	require.NoError(t, os.WriteFile(imagePath, image, 0o600))

	view, err := handleMount(mount.Mount{
		Type:   "erofs",
		Source: imagePath,
	})
	require.Nil(t, view)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unsupported incompatible feature 0x2")
	require.ErrorIs(t, err, goerofs.ErrNotImplemented)
	assert.ErrorIs(t, err, errdefs.ErrNotImplemented)
}

func TestHandleMountDmverity(t *testing.T) {
	// The blob and its devices are not opened: a layer verified by dm-verity
	// is left to the mount handler, whatever its contents.
	dir := t.TempDir()
	layerPath := filepath.Join(dir, "layer.erofs")
	devicePath := filepath.Join(dir, "device-0.blob")

	for _, tc := range []struct {
		name    string
		options []string
	}{
		{
			name:    "layer",
			options: []string{"ro", "loop", dmverity.MountOption + layerPath + ".dmverity"},
		},
		{
			name:    "device",
			options: []string{"ro", "loop", "device=" + devicePath, dmverity.DeviceMountOption + "0=" + devicePath + ".dmverity"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view, err := handleMount(mount.Mount{
				Type:    "erofs",
				Source:  layerPath,
				Options: tc.options,
			})
			require.Nil(t, view)
			require.ErrorIs(t, err, errdefs.ErrNotImplemented)
			assert.NotErrorIs(t, err, os.ErrNotExist)
		})
	}
}
