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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/fsview"
	"github.com/containerd/errdefs"
	"github.com/erofs/go-erofs"
)

func init() {
	fsview.Register(fsview.FSHandler{
		HandleMount: handleMount,
		Getxattr:    getxattr,
		IsWhiteout:  isWhiteout,
	})
}

func handleMount(m mount.Mount) (fsview.View, error) {
	if m.Type != "erofs" {
		return nil, errdefs.ErrNotImplemented
	}

	for _, opt := range m.Options {
		if strings.HasPrefix(opt, dmverity.MountOption) || strings.HasPrefix(opt, dmverity.DeviceMountOption) {
			// Reading the blob or its devices directly would skip dm-verity's
			// check of every block read. Leave the layer to the mount handler,
			// which reads them through their dm-verity devices.
			return nil, fmt.Errorf("erofs layer %s is verified by dm-verity: %w", m.Source, errdefs.ErrNotImplemented)
		}
	}

	f, err := os.Open(m.Source)
	if err != nil {
		return nil, err
	}

	var extraDevices []io.ReaderAt
	var closers []io.Closer
	closers = append(closers, f)

	for _, opt := range m.Options {
		if devPath, ok := strings.CutPrefix(opt, "device="); ok {
			if devPath == "" {
				continue
			}
			df, err := os.Open(devPath)
			if err != nil {
				for _, c := range closers {
					c.Close()
				}
				return nil, err
			}
			closers = append(closers, df)
			extraDevices = append(extraDevices, df)
		}
	}

	if len(extraDevices) == 0 {
		extraDevices, err = flatDevices(f)
		if err != nil {
			f.Close()
			return nil, err
		}
	}

	var opts []erofs.OpenOpt
	if len(extraDevices) > 0 {
		opts = append(opts, erofs.WithExtraDevices(extraDevices...))
	}

	efs, err := erofs.Open(f, opts...)
	if err != nil {
		for _, c := range closers {
			c.Close()
		}
		if errors.Is(err, erofs.ErrNotImplemented) {
			err = fmt.Errorf("%w: %w", errdefs.ErrNotImplemented, err)
		}
		return nil, err
	}

	rlfs, ok := efs.(fs.ReadLinkFS)
	if !ok {
		for _, c := range closers {
			c.Close()
		}
		return nil, fmt.Errorf("erofs: filesystem does not implement fs.ReadLinkFS: %w", errdefs.ErrNotImplemented)
	}

	return &erofsView{
		ReadLinkFS: rlfs,
		closers:    closers,
	}, nil
}

// The on-disk format of the superblock and the device table, from the Linux
// kernel's fs/erofs/erofs_fs.h: struct erofs_super_block and struct
// erofs_deviceslot, with the offsets of the fields read here.
const (
	superBlockOffset           = 1024
	superBlockSize             = 128
	erofsMagic                 = 0xe0f5e1e2
	featureIncompatDeviceTable = 0x8

	sbBlkSizeBits     = 12 // u8
	sbFeatureIncompat = 80 // le32
	sbExtraDevices    = 86 // le16
	sbDevtSlotOff     = 88 // le16, in device slots

	deviceSlotSize    = 128
	slotBlocks        = 64 // le32
	slotMappedBlkAddr = 68 // le32
)

// flatDevices returns the extra devices of an EROFS image that holds them
// itself, each read from the image at the block address it is mapped to.
//
// A tar index layer is such an image: mkfs.erofs --tar=i writes an index that
// addresses the tar as an extra device mapped right behind the index, and the
// tar is appended to the index. Mounted without device= options, the kernel
// reads every extra device from the image this way (flat device mode).
//
// An image without a device table, or with a device that is not mapped within
// the image, gets no devices: it needs them named with device= options.
func flatDevices(f *os.File) ([]io.ReaderAt, error) {
	var sb [superBlockSize]byte
	if _, err := f.ReadAt(sb[:], superBlockOffset); err != nil {
		if errors.Is(err, io.EOF) {
			// Too short for an image. erofs.Open reports it.
			return nil, nil
		}
		return nil, err
	}
	if binary.LittleEndian.Uint32(sb[0:]) != erofsMagic ||
		binary.LittleEndian.Uint32(sb[sbFeatureIncompat:])&featureIncompatDeviceTable == 0 {
		return nil, nil
	}
	blkSizeBits := sb[sbBlkSizeBits]
	if blkSizeBits < 9 || blkSizeBits > 16 {
		// erofs.Open reports the invalid block size.
		return nil, nil
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	count := int64(binary.LittleEndian.Uint16(sb[sbExtraDevices:]))
	slotOffset := int64(binary.LittleEndian.Uint16(sb[sbDevtSlotOff:])) * deviceSlotSize
	devices := make([]io.ReaderAt, 0, count)
	for i := range count {
		var slot [deviceSlotSize]byte
		if _, err := f.ReadAt(slot[:], slotOffset+i*deviceSlotSize); err != nil {
			return nil, fmt.Errorf("failed to read erofs device slot %d: %w", i, err)
		}
		blocks := int64(binary.LittleEndian.Uint32(slot[slotBlocks:]))
		mappedBlkAddr := int64(binary.LittleEndian.Uint32(slot[slotMappedBlkAddr:]))
		offset, size := mappedBlkAddr<<blkSizeBits, blocks<<blkSizeBits
		if mappedBlkAddr == 0 || offset+size > fi.Size() {
			return nil, nil
		}
		devices = append(devices, io.NewSectionReader(f, offset, size))
	}
	return devices, nil
}

type erofsView struct {
	fs.ReadLinkFS
	closers []io.Closer
}

func (v *erofsView) Close() error {
	var errs []error
	for _, c := range v.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

func getxattr(f fs.File, name string) (string, bool) {
	fi, err := f.Stat()
	if err != nil {
		return "", false
	}
	estatfi, ok := fi.Sys().(*erofs.Stat)
	if !ok {
		return "", false
	}
	val, ok := estatfi.Xattrs[name]
	return val, ok
}

func isWhiteout(fi fs.FileInfo) bool {
	if (fi.Mode() & fs.ModeCharDevice) == 0 {
		return false
	}
	estatfi, ok := fi.Sys().(*erofs.Stat)
	if !ok {
		return false
	}
	return estatfi.Rdev == 0
}
