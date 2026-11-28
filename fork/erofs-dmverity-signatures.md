---
id: erofs-dmverity-signatures
fork: containerd
category: feature
status: carried
commits:
  - 'erofs: unpack layers from signed dm-verity referrers'
  - 'erofs: share the snapshot of a signed layer between differently signed images'
upstream:
  outcome: to-file
  refs: [containerd/containerd#12081]
  branch: upstream/erofs-dmverity-signatures
  exit: the first containerd release that unpacks EROFS layers from signed dm-verity referrers (milestone 1 of containerd/containerd#12081)
verified: 2026-11-28
---
# EROFS layers from signed dm-verity referrers

## Change

The erofs snapshotter and differ take per-layer dm-verity root-hash signatures published as OCI referrers (artifact
type `application/vnd.containerd.erofs.dmverity.v1`: each layer's EROFS tar index, dm-verity superblock and hash tree,
and root-hash signature, annotated with the layer digest), behind two options that default to off:

- `[plugins."io.containerd.snapshotter.v1.erofs"] enable_dmverity_referrers` advertises the `dmverity-referrers`
  capability; a pull (`client.Pull`, the transfer service) then fetches each manifest's newest referrer and its blobs
  with the pull's own credentials and fails, naming the layer, when one is incomplete or missing.
- `[plugins."io.containerd.differ.v1.erofs"] enable_dmverity_referrers` builds each layer from the published index, the
  uncompressed tar and the published hash tree (no `mkfs.erofs`), checks the data against the signed root hash once,
  and stores the signature next to the layer blob.
- Enabled means required: the differ refuses native EROFS layers (no signed target) before writing anything, and the
  snapshotter mounts no layer without its stored dm-verity metadata and signature (a snapshot unpacked before the
  option was enabled, a layer content cache entry), uses no merged fsmeta, and refuses `dmverity_mode = "off"`.
- Snapshot labels record the signed root hash and signature digest a layer was unpacked with. Snapshots stay keyed by
  chain ID: a layer another image already unpacked reuses that snapshot if it carries a signed identity, also when
  this image's referrer signs the layer with another key, again with a signer whose signatures are not deterministic,
  or over another root hash (an index built by another `mkfs.erofs`, the same tar compressed differently). The
  snapshot holds the same uncompressed layer with the index, hash tree and signature it was unpacked with, and the
  kernel checks that signature against those device bytes at every mount. A snapshot without a signed identity is not
  reused; the pull fails, naming the layer.
- The mount handler opens a signed layer with dm-verity's `root_hash_sig_key_desc`, on an OS-locked thread (the
  signature reaches the kernel through the thread keyring).

The referrer layout and annotations follow the signed dm-verity implementation of the RFC's authors (branch
`dadelan/ipe-audit-signature-fallback` of the `dallasd1/containerd` fork). Differences: enabled means required (no
unsigned fallback); snapshots stay keyed by chain ID instead of by parent, chain ID, root hash and signature digest, so
images that sign a shared layer differently share its snapshot and creating a container needs no lookup of a signed
chain; the mount reads the signature from a file next to the layer blob.

## Reason

The nodes this line serves boot with `dm_verity.require_signatures=1` (IPE): a dm-verity device opens only with a
trusted signature over its root hash. containerd 2.4.2 computes the root hash on the node and passes no signature, so
no EROFS layer mounts there. No containerd release implements milestone 1 of containerd/containerd#12081.

## History

- 2026-11-27: carried on the line at the `v2.4.2` pin. To file — prepared in the fork: branch
  `upstream/erofs-dmverity-signatures`, the same change on upstream `main` (`59228e1af476`), where it resolves two
  conflicts with upstream's Go EROFS converter (the differ's options and its `mkfs.erofs` probe, which upstream runs
  only when `mkfs.erofs` is configured).
- 2026-11-28: `erofs: share the snapshot of a signed layer between differently signed images`. A node that ran
  images sharing a layer failed the second pull with `existing snapshot has a different signed dm-verity signature
  digest` (or `root hash`): reuse required the referrer's identity to equal the snapshot's. Images built on a common
  base share layers, the certificates a node trusts overlap during a rotation, an ECDSA key in a KMS signs
  differently on every run, and another `mkfs.erofs` or another compression of the same tar gives another root hash,
  so the snapshot is now reused whenever it carries a signed identity. The line carries the change as a commit of its
  own after the patch; `upstream/erofs-dmverity-signatures` has it folded into the patch's one commit, whose message
  says the same.
