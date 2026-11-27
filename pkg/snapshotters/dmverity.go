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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	erofsAnnotationPrefix = "io.containerd.erofs.v1/"

	// TargetLayerDmverityLabel is the layer descriptor annotation, set by the
	// dm-verity referrer handler, that carries the layer's signed dm-verity
	// target (root hash, EROFS metadata, Merkle tree and signature descriptors)
	// as JSON. It is handed to the differ as a processor payload.
	TargetLayerDmverityLabel = erofsAnnotationPrefix + "dmverity.target"

	// Snapshot labels that record the signed identity a snapshot was unpacked
	// with. They carry the containerd.io/snapshot/ prefix so the unpacker
	// passes them to the snapshotter.
	dmverityReferrerRootHashLabel        = "containerd.io/snapshot/erofs.dmverity.root-hash"
	dmverityReferrerSignatureDigestLabel = "containerd.io/snapshot/erofs.dmverity.signature-digest"
)

// WithDmverityReferrers passes the layer's signed dm-verity target, if the
// referrer handler attached one, to the differ.
func WithDmverityReferrers() diff.ApplyOpt {
	return func(_ context.Context, desc ocispec.Descriptor, config *diff.ApplyConfig) error {
		value := desc.Annotations[TargetLayerDmverityLabel]
		if value == "" {
			return nil
		}
		payload, err := typeurl.MarshalAny(wrapperspb.String(value))
		if err != nil {
			return err
		}
		config.ProcessorPayloads = maps.Clone(config.ProcessorPayloads)
		if config.ProcessorPayloads == nil {
			config.ProcessorPayloads = make(map[string]typeurl.Any)
		}
		config.ProcessorPayloads[TargetLayerDmverityLabel] = payload
		return nil
	}
}

// DmverityApplyTarget returns the signed dm-verity target passed with
// WithDmverityReferrers, or nil if the layer has none.
func DmverityApplyTarget(config diff.ApplyConfig) (*DmverityTarget, error) {
	payload := config.ProcessorPayloads[TargetLayerDmverityLabel]
	if payload == nil {
		return nil, nil
	}
	value := &wrapperspb.StringValue{}
	if err := typeurl.UnmarshalTo(payload, value); err != nil {
		return nil, fmt.Errorf("decode dm-verity apply target: %w", err)
	}
	target, err := ParseDmverityTarget(value.Value)
	if err != nil {
		return nil, err
	}
	return &target, nil
}

// DmverityTarget is one layer's signed dm-verity materialization: the EROFS
// tar index that precedes the layer's tar, the dm-verity superblock and hash
// tree that follow it, and the PKCS#7 signature over the root hash.
type DmverityTarget struct {
	Referrer  digest.Digest      `json:"referrer,omitempty"`
	RootHash  string             `json:"rootHash"`
	Metadata  ocispec.Descriptor `json:"metadata"`
	Tree      ocispec.Descriptor `json:"tree"`
	Signature ocispec.Descriptor `json:"signature"`
}

// ParseDmverityTarget parses a TargetLayerDmverityLabel value.
func ParseDmverityTarget(value string) (DmverityTarget, error) {
	var target DmverityTarget
	if err := json.Unmarshal([]byte(value), &target); err != nil {
		return DmverityTarget{}, fmt.Errorf("parse dm-verity target: %w", err)
	}
	if target.RootHash == "" ||
		target.Metadata.Digest == "" ||
		target.Tree.Digest == "" ||
		target.Signature.Digest == "" {
		return DmverityTarget{}, errors.New("incomplete dm-verity target")
	}
	if err := validateRootHash(target.RootHash); err != nil {
		return DmverityTarget{}, err
	}
	return target, nil
}

func targetAnnotation(info *DmverityTarget) (string, error) {
	target := DmverityTarget{
		Referrer:  info.Referrer,
		RootHash:  info.RootHash,
		Metadata:  compactDescriptor(info.Metadata),
		Tree:      compactDescriptor(info.Tree),
		Signature: compactDescriptor(info.Signature),
	}
	data, err := json.Marshal(target)
	if err != nil {
		return "", fmt.Errorf("marshal dm-verity target: %w", err)
	}
	return string(data), nil
}

func compactDescriptor(desc ocispec.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

func validateRootHash(rootHash string) error {
	rootDigest, err := hex.DecodeString(rootHash)
	if err != nil || len(rootDigest) != sha256.Size {
		return fmt.Errorf("invalid SHA-256 dm-verity root hash %q", rootHash)
	}
	return nil
}

// GetDmveritySnapshotIdentity returns the signed identity recorded in
// snapshot labels; signed is false when the labels record none.
func GetDmveritySnapshotIdentity(labels map[string]string) (rootHash, signatureDigest string, signed bool, err error) {
	rootHash = labels[dmverityReferrerRootHashLabel]
	signatureDigest = labels[dmverityReferrerSignatureDigestLabel]
	if rootHash == "" && signatureDigest == "" {
		return "", "", false, nil
	}
	if rootHash == "" || signatureDigest == "" {
		return "", "", false, errors.New("incomplete signed dm-verity snapshot identity")
	}
	if err := validateRootHash(rootHash); err != nil {
		return "", "", false, fmt.Errorf("invalid signed dm-verity snapshot root hash: %w", err)
	}
	if _, err := digest.Parse(signatureDigest); err != nil {
		return "", "", false, fmt.Errorf("invalid signed dm-verity snapshot signature digest: %w", err)
	}
	return rootHash, signatureDigest, true, nil
}

// ValidateDmveritySnapshot checks that an existing snapshot may be reused for a
// layer expected to carry the signed identity in expected: it must carry the
// same root hash and signature digest. A layer without a signed identity
// accepts any snapshot.
func ValidateDmveritySnapshot(existing, expected map[string]string) error {
	expectedRootHash, expectedSignatureDigest, expectedSigned, err := GetDmveritySnapshotIdentity(expected)
	if err != nil {
		return fmt.Errorf("invalid expected dm-verity snapshot identity: %w", err)
	}
	if !expectedSigned {
		return nil
	}
	existingRootHash, existingSignatureDigest, existingSigned, err := GetDmveritySnapshotIdentity(existing)
	if err != nil {
		return fmt.Errorf("invalid existing dm-verity snapshot identity: %w", err)
	}
	if !existingSigned {
		return errors.New("existing snapshot is not signed for the requested dm-verity layer; remove the affected snapshot and descendants before retrying")
	}
	if !strings.EqualFold(existingRootHash, expectedRootHash) {
		return errors.New("existing snapshot has a different signed dm-verity root hash; remove the affected snapshot and descendants before retrying")
	}
	if existingSignatureDigest != expectedSignatureDigest {
		return errors.New("existing snapshot has a different signed dm-verity signature digest; remove the affected snapshot and descendants before retrying")
	}
	return nil
}
