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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// stubDevice replaces opening and removing a device with fakes: open returns
// openErr, and each removal returns the next of removals (then nil). It
// returns the names the fakes were called with.
func stubDevice(t *testing.T, openErr error, removals ...error) (opened, removed *[]string) {
	t.Helper()
	opened, removed = &[]string{}, &[]string{}
	origOpen, origClose := openSigned, verityClose
	t.Cleanup(func() { openSigned, verityClose = origOpen, origClose })
	openSigned = func(data, name, hash, root string, offset uint64, sig string) (string, error) {
		*opened = append(*opened, fmt.Sprintf("%s %s %s %s %d %s", data, name, hash, root, offset, sig))
		return DevicePath(name), openErr
	}
	verityClose = func(name string) error {
		*removed = append(*removed, name)
		if len(removals) == 0 {
			return nil
		}
		err := removals[0]
		removals = removals[1:]
		return err
	}
	return opened, removed
}

// notFound is how the library reports a device that does not exist.
var notFound = fmt.Errorf("device 'dev' not found or inaccessible: %w", unix.ENXIO)

func TestVerifySignature(t *testing.T) {
	root := "ab"

	t.Run("opens the device with the signature and removes it", func(t *testing.T) {
		opened, removed := stubDevice(t, nil)
		assert.NoError(t, VerifySignature("layer.erofs", "dev", root, 4096, "layer.erofs.sig"))
		assert.Equal(t, []string{"layer.erofs dev layer.erofs ab 4096 layer.erofs.sig"}, *opened)
		assert.Equal(t, []string{"dev"}, *removed)
	})

	t.Run("retries the removal while udev holds the device", func(t *testing.T) {
		busy := fmt.Errorf("remove device: %w", unix.EBUSY)
		_, removed := stubDevice(t, nil, busy, busy)
		assert.NoError(t, VerifySignature("layer.erofs", "dev", root, 4096, "layer.erofs.sig"))
		assert.Equal(t, []string{"dev", "dev", "dev"}, *removed)
	})

	t.Run("returns the kernel's refusal, with no device left", func(t *testing.T) {
		refusal := errors.New("failed to open dm-verity device: load table: dm table load 'dev': required key not available")
		_, removed := stubDevice(t, refusal, notFound)
		assert.Equal(t, refusal, VerifySignature("layer.erofs", "dev", root, 4096, "layer.erofs.sig"))
		assert.Equal(t, []string{"dev"}, *removed, "a device the library left behind would be removed")
	})

	t.Run("fails when the device stays", func(t *testing.T) {
		denied := fmt.Errorf("remove device: %w", unix.EACCES)
		stubDevice(t, nil, denied)
		err := VerifySignature("layer.erofs", "dev", root, 4096, "layer.erofs.sig")
		assert.EqualError(t, err, `failed to close dm-verity device "dev": remove device: permission denied`)
		assert.ErrorIs(t, err, unix.EACCES)
	})

	t.Run("names both a refusal and a device that stays", func(t *testing.T) {
		refusal := errors.New("failed to open dm-verity device: resume device: invalid argument")
		denied := fmt.Errorf("remove device: %w", unix.EACCES)
		stubDevice(t, refusal, denied)
		err := VerifySignature("layer.erofs", "dev", root, 4096, "layer.erofs.sig")
		assert.EqualError(t, err, `failed to open dm-verity device: resume device: invalid argument (failed to close dm-verity device "dev": remove device: permission denied)`)
		assert.ErrorIs(t, err, refusal)
		assert.ErrorIs(t, err, unix.EACCES)
	})
}
