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
	"encoding/binary"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/pkg/archive/tartest"
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

// makeTarIndexLayer writes a layer as the erofs differ does in tar index mode
// with mkfs.erofs: the index from mkfs.erofs --tar=i, followed by the tar it
// indexes.
func makeTarIndexLayer(t *testing.T, wt tartest.WriterToTar) string {
	t.Helper()
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		t.Skip("mkfs.erofs not found in PATH")
	}
	if supported, err := erofsutils.MkfsSupportsTar(); err != nil || !supported {
		t.Skipf("mkfs.erofs does not support --tar= mode: %v", err)
	}
	layerPath := filepath.Join(t.TempDir(), "layer.erofs")
	rc := tartest.TarFromWriterTo(wt)
	defer rc.Close()
	require.NoError(t, erofsutils.MkfsGenerateTarIndex(t.Context(), rc, layerPath, "", nil))
	return layerPath
}

func TestHandleMountTarIndex(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n")
	group := []byte("root:x:0:\napp:x:1000:\n")
	// Spans several of the index's 512-byte blocks.
	large := bytes.Repeat([]byte("0123456789abcdef"), 300)
	tc := tartest.TarContext{}.WithModTime(time.Now().UTC())
	layerPath := makeTarIndexLayer(t, tartest.TarAll(
		tc.Dir("etc", 0o755),
		tc.File("etc/passwd", passwd, 0o644),
		tc.File("etc/group", group, 0o644),
		tc.File("large", large, 0o644),
	))

	view, err := handleMount(mount.Mount{
		Type:    "erofs",
		Source:  layerPath,
		Options: []string{"ro", "loop"},
	})
	require.NoError(t, err)
	defer view.Close()

	for name, want := range map[string][]byte{
		"etc/passwd": passwd,
		"etc/group":  group,
		"large":      large,
	} {
		got, err := fs.ReadFile(view, name)
		require.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}
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

// TestHandleMountDeviceOutsideImage tests that an extra device the image does
// not hold is not read from the image when the mount does not name it.
func TestHandleMountDeviceOutsideImage(t *testing.T) {
	const (
		slotOffset = 9 // in device slots, right behind the superblock
		imageSize  = (slotOffset + 1) * deviceSlotSize
	)
	for _, tc := range []struct {
		name          string
		mappedBlkAddr uint32
		blocks        uint32
	}{
		{name: "beyond the image", mappedBlkAddr: 2, blocks: 8},
		{name: "not mapped", mappedBlkAddr: 0, blocks: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := make([]byte, imageSize)
			sb := image[superBlockOffset:]
			binary.LittleEndian.PutUint32(sb[0:], erofsMagic)
			sb[sbBlkSizeBits] = 9
			binary.LittleEndian.PutUint32(sb[sbFeatureIncompat:], featureIncompatDeviceTable)
			binary.LittleEndian.PutUint16(sb[sbExtraDevices:], 1)
			binary.LittleEndian.PutUint16(sb[sbDevtSlotOff:], slotOffset)
			slot := image[slotOffset*deviceSlotSize:]
			binary.LittleEndian.PutUint32(slot[slotBlocks:], tc.blocks)
			binary.LittleEndian.PutUint32(slot[slotMappedBlkAddr:], tc.mappedBlkAddr)

			imagePath := filepath.Join(t.TempDir(), "meta.erofs")
			require.NoError(t, os.WriteFile(imagePath, image, 0o600))

			view, err := handleMount(mount.Mount{
				Type:   "erofs",
				Source: imagePath,
			})
			require.Nil(t, view)
			require.ErrorContains(t, err, "extra devices count 1 does not match provided 0")
			assert.NotErrorIs(t, err, errdefs.ErrNotImplemented)
		})
	}
}
