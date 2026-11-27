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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/internal/dmverity"
)

func TestOpenLayerDeviceHandsOverSignature(t *testing.T) {
	type call struct {
		signed                        bool
		source, name, hash, root, sig string
		offset                        uint64
	}
	var calls []call
	origOpen, origOpenSigned := dmverityOpen, dmverityOpenSigned
	t.Cleanup(func() { dmverityOpen, dmverityOpenSigned = origOpen, origOpenSigned })
	dmverityOpen = func(data, name, hash, root string, offset uint64, opts *dmverity.DmverityOptions) (string, error) {
		calls = append(calls, call{source: data, name: name, hash: hash, root: root, offset: offset})
		return "", nil
	}
	dmverityOpenSigned = func(data, name, hash, root string, offset uint64, sig string) (string, error) {
		calls = append(calls, call{signed: true, source: data, name: name, hash: hash, root: root, offset: offset, sig: sig})
		return "", nil
	}

	blob := filepath.Join(t.TempDir(), "layer.erofs")
	metadata := &dmverity.DmverityMetadata{RootHash: strings.Repeat("ab", 32), HashOffset: 4096}

	require.NoError(t, openLayerDevice(blob, "dev", metadata))
	assert.Equal(t, []call{{source: blob, name: "dev", hash: blob, root: metadata.RootHash, offset: 4096}}, calls,
		"a layer without a stored signature opens unsigned")

	calls = nil
	require.NoError(t, os.WriteFile(dmverity.SignaturePath(blob), []byte("pkcs7"), 0644))
	require.NoError(t, openLayerDevice(blob, "dev", metadata))
	assert.Equal(t, []call{{signed: true, source: blob, name: "dev", hash: blob, root: metadata.RootHash, offset: 4096,
		sig: blob + ".sig"}}, calls, "a layer's stored signature goes to dm-verity")
}

func TestOpenSignedRequiresSignature(t *testing.T) {
	_, err := dmverity.OpenSigned("data", "dev", "data", strings.Repeat("ab", 32), 0, "")
	assert.ErrorContains(t, err, "signature path cannot be empty")
}
