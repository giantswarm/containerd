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
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	sourceLayerDigestAnnotation = erofsAnnotationPrefix + "dmverity.source-layer-digest"
	layerRootHashAnnotation     = erofsAnnotationPrefix + "dmverity.root-hash"

	signatureArtifactType          = "application/vnd.containerd.erofs.dmverity.v1"
	erofsMetadataArtifactMediaType = "application/vnd.containerd.erofs.metadata.v1"
	merkleTreeArtifactMediaType    = "application/vnd.containerd.erofs.dmverity.merkle-tree.v1"
	layerSignatureMediaType        = "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"

	// maxSignatureSize is the largest payload of a kernel "user" key, which
	// carries the signature to dm-verity.
	maxSignatureSize = 32767
)

type dmverityBundle struct {
	desc   ocispec.Descriptor
	layers map[string]*DmverityTarget
}

// AppendDmverityReferrersHandlerWrapper returns a handler wrapper that, for
// each image manifest, fetches the newest referrer of artifact type
// application/vnd.containerd.erofs.dmverity.v1 with fetcher, fetches each
// layer's EROFS metadata, Merkle tree and root-hash signature into store, and
// annotates the manifest's layers with their TargetLayerDmverityLabel.
//
// Every layer must be signed: a manifest without such a referrer, or a layer
// the referrer lacks any of the three blobs for, fails the handler with an
// error naming the layer. Use the pull's own fetcher, so the referrer is
// fetched with the pull's resolver and credentials.
func AppendDmverityReferrersHandlerWrapper(fetcher remotes.Fetcher, store content.Store) func(images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			children, err := f.Handle(ctx, desc)
			if err != nil || !images.IsManifestType(desc.MediaType) {
				return children, err
			}
			imageLayers := dmverityImageLayers(children)
			if len(imageLayers) == 0 {
				return children, nil
			}
			bundle, err := fetchSignatures(ctx, fetcher, store, desc, imageLayers)
			if err != nil {
				return nil, err
			}
			if bundle == nil {
				return nil, fmt.Errorf("layer %s has no signed dm-verity root hash: image manifest %s has no %s referrer",
					firstLayer(children), desc.Digest, signatureArtifactType)
			}
			for _, target := range bundle.layers {
				for _, blob := range []ocispec.Descriptor{target.Metadata, target.Tree, target.Signature} {
					if err := remotes.Fetch(ctx, store, fetcher, blob); err != nil && !errdefs.IsAlreadyExists(err) {
						return nil, fmt.Errorf("fetch dm-verity artifact %s of referrer %s: %w", blob.Digest, bundle.desc.Digest, err)
					}
				}
			}
			return annotateDmverityTargets(children, bundle.layers)
		})
	}
}

// fetchSignatures selects the subject's newest dm-verity referrer and reads
// its per-layer artifacts. It returns nil if the subject has no referrer.
func fetchSignatures(
	ctx context.Context,
	fetcher remotes.Fetcher,
	store content.Store,
	subject ocispec.Descriptor,
	imageLayers map[string]struct{},
) (*dmverityBundle, error) {
	refFetcher, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		return nil, fmt.Errorf("fetch dm-verity referrers for %s: fetcher does not support the referrers API", subject.Digest)
	}
	referrers, err := refFetcher.FetchReferrers(ctx, subject.Digest, remotes.WithReferrerArtifactTypes(signatureArtifactType))
	if err != nil {
		return nil, fmt.Errorf("fetch dm-verity referrers for %s: %w", subject.Digest, err)
	}
	selected, found, err := selectDmverityReferrer(ctx, referrers)
	if err != nil || !found {
		return nil, err
	}
	if err := remotes.Fetch(ctx, store, fetcher, selected); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, fmt.Errorf("fetch dm-verity referrer manifest %s: %w", selected.Digest, err)
	}
	data, err := content.ReadBlob(ctx, store, selected)
	if err != nil {
		return nil, fmt.Errorf("read dm-verity referrer %s: %w", selected.Digest, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse dm-verity referrer %s: %w", selected.Digest, err)
	}
	layers, err := readDmverityBundleManifest(manifest, selected, subject, imageLayers)
	if err != nil {
		return nil, fmt.Errorf("invalid dm-verity referrer %s: %w", selected.Digest, err)
	}
	log.G(ctx).WithFields(log.Fields{
		"bundle":   selected.Digest,
		"manifest": subject.Digest,
		"layers":   len(layers),
	}).Debug("selected signed EROFS dm-verity referrer")
	return &dmverityBundle{desc: selected, layers: layers}, nil
}

// selectDmverityReferrer picks the referrer with the newest
// org.opencontainers.image.created annotation; ties go to the lowest digest.
func selectDmverityReferrer(ctx context.Context, referrers []ocispec.Descriptor) (ocispec.Descriptor, bool, error) {
	var (
		selected            ocispec.Descriptor
		selectedCreatedTime time.Time
		found               bool
	)
	for _, referrer := range referrers {
		if referrer.ArtifactType != signatureArtifactType {
			continue
		}
		var createdTime time.Time
		if value := referrer.Annotations[ocispec.AnnotationCreated]; value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				log.G(ctx).WithField("bundle", referrer.Digest).WithError(err).
					Warn("Ignoring invalid dm-verity referrer creation time")
			} else {
				createdTime = parsed
			}
		}
		if found && (createdTime.Before(selectedCreatedTime) ||
			createdTime.Equal(selectedCreatedTime) && referrer.Digest >= selected.Digest) {
			continue
		}
		selected = referrer
		selectedCreatedTime = createdTime
		found = true
	}
	if !found {
		return ocispec.Descriptor{}, false, nil
	}
	for _, referrer := range referrers {
		if referrer.ArtifactType == signatureArtifactType && referrer.Digest == selected.Digest &&
			(referrer.MediaType != selected.MediaType || referrer.Size != selected.Size) {
			return ocispec.Descriptor{}, true, fmt.Errorf("conflicting dm-verity referrer descriptors for %s", selected.Digest)
		}
	}
	if err := selected.Digest.Validate(); err != nil {
		return ocispec.Descriptor{}, true, fmt.Errorf("invalid dm-verity referrer digest %q: %w", selected.Digest, err)
	}
	if selected.MediaType != ocispec.MediaTypeImageManifest {
		return ocispec.Descriptor{}, true, fmt.Errorf("dm-verity referrer %s has unexpected media type %q", selected.Digest, selected.MediaType)
	}
	if selected.Size <= 0 {
		return ocispec.Descriptor{}, true, fmt.Errorf("invalid dm-verity referrer size %d for %s", selected.Size, selected.Digest)
	}
	return selected, true, nil
}

// readDmverityBundleManifest groups the referrer's blobs by the image layer
// they belong to. Every image layer needs its EROFS metadata, Merkle tree and
// signature; blobs for layers outside imageLayers are ignored.
func readDmverityBundleManifest(
	manifest ocispec.Manifest,
	referrer ocispec.Descriptor,
	subject ocispec.Descriptor,
	imageLayers map[string]struct{},
) (map[string]*DmverityTarget, error) {
	if manifest.ArtifactType != signatureArtifactType {
		return nil, fmt.Errorf("dm-verity referrer %s has unexpected artifact type %q", referrer.Digest, manifest.ArtifactType)
	}
	if manifest.Subject == nil || manifest.Subject.Digest != subject.Digest {
		return nil, fmt.Errorf("dm-verity referrer %s subject does not match image manifest %s", referrer.Digest, subject.Digest)
	}

	infoMap := make(map[string]*DmverityTarget)
	for _, layer := range manifest.Layers {
		switch layer.MediaType {
		case erofsMetadataArtifactMediaType, merkleTreeArtifactMediaType, layerSignatureMediaType:
		default:
			continue
		}

		sourceDigest := layer.Annotations[sourceLayerDigestAnnotation]
		if sourceDigest == "" {
			return nil, fmt.Errorf("bundle descriptor %s is missing its source layer digest", layer.Digest)
		}
		if _, ok := imageLayers[sourceDigest]; !ok {
			continue
		}
		if err := layer.Digest.Validate(); err != nil {
			return nil, fmt.Errorf("bundle descriptor for layer %s has invalid payload digest %q: %w", sourceDigest, layer.Digest, err)
		}
		if layer.Size <= 0 {
			return nil, fmt.Errorf("bundle descriptor %s has invalid payload size %d", layer.Digest, layer.Size)
		}

		info := infoMap[sourceDigest]
		if info == nil {
			info = &DmverityTarget{Referrer: referrer.Digest}
			infoMap[sourceDigest] = info
		}
		switch layer.MediaType {
		case erofsMetadataArtifactMediaType:
			if info.Metadata.Digest != "" {
				return nil, fmt.Errorf("duplicate EROFS metadata descriptor for layer %s", sourceDigest)
			}
			info.Metadata = layer
		case merkleTreeArtifactMediaType:
			if info.Tree.Digest != "" {
				return nil, fmt.Errorf("duplicate Merkle-tree descriptor for layer %s", sourceDigest)
			}
			info.Tree = layer
		case layerSignatureMediaType:
			if layer.Size > maxSignatureSize {
				return nil, fmt.Errorf("signature descriptor for layer %s has size %d, maximum is %d bytes",
					sourceDigest, layer.Size, maxSignatureSize)
			}
			rootHash := layer.Annotations[layerRootHashAnnotation]
			if err := validateRootHash(rootHash); err != nil {
				return nil, fmt.Errorf("signature descriptor for layer %s: %w", sourceDigest, err)
			}
			if info.Signature.Digest != "" {
				return nil, fmt.Errorf("duplicate signature descriptor for layer %s", sourceDigest)
			}
			info.RootHash = strings.ToLower(rootHash)
			info.Signature = layer
		}
	}

	for _, sourceDigest := range slices.Sorted(maps.Keys(imageLayers)) {
		info := infoMap[sourceDigest]
		if info == nil {
			info = &DmverityTarget{}
		}
		var missing []string
		if info.Signature.Digest == "" {
			missing = append(missing, "signature")
		}
		if info.Metadata.Digest == "" {
			missing = append(missing, "EROFS metadata")
		}
		if info.Tree.Digest == "" {
			missing = append(missing, "Merkle tree")
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("incomplete dm-verity artifacts for layer %s: missing %s", sourceDigest, strings.Join(missing, ", "))
		}
	}
	return infoMap, nil
}

// dmverityImageLayers returns the digests of a manifest's layers.
func dmverityImageLayers(children []ocispec.Descriptor) map[string]struct{} {
	imageLayers := make(map[string]struct{})
	for _, child := range children {
		if images.IsLayerType(child.MediaType) {
			imageLayers[child.Digest.String()] = struct{}{}
		}
	}
	return imageLayers
}

func firstLayer(children []ocispec.Descriptor) string {
	for _, child := range children {
		if images.IsLayerType(child.MediaType) {
			return child.Digest.String()
		}
	}
	return ""
}

// annotateDmverityTargets sets each layer's TargetLayerDmverityLabel and the
// snapshot labels of its signed identity. Values the image manifest set for
// these keys are replaced, never trusted.
func annotateDmverityTargets(children []ocispec.Descriptor, infoMap map[string]*DmverityTarget) ([]ocispec.Descriptor, error) {
	children = slices.Clone(children)
	for i := range children {
		if !images.IsLayerType(children[i].MediaType) {
			continue
		}
		info := infoMap[children[i].Digest.String()]
		if info == nil {
			return nil, fmt.Errorf("incomplete dm-verity artifacts for layer %s: missing signature, EROFS metadata, Merkle tree", children[i].Digest)
		}
		value, err := targetAnnotation(info)
		if err != nil {
			return nil, err
		}
		annotations := maps.Clone(children[i].Annotations)
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations[TargetLayerDmverityLabel] = value
		annotations[dmverityReferrerRootHashLabel] = info.RootHash
		annotations[dmverityReferrerSignatureDigestLabel] = info.Signature.Digest.String()
		children[i].Annotations = annotations
	}
	return children, nil
}
