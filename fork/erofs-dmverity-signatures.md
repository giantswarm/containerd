---
id: erofs-dmverity-signatures
fork: containerd
category: feature
status: carried
commits:
  - 'erofs: unpack layers from signed dm-verity referrers'
upstream:
  outcome: to-file
  refs: [containerd/containerd#12081]
  branch: upstream/erofs-dmverity-signatures
  exit: the first containerd release that unpacks EROFS layers from signed dm-verity referrers (milestone 1 of containerd/containerd#12081)
verified: 2026-11-27
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
- Snapshot labels record the signed root hash and signature digest; a snapshot is reused only with the same ones.
- The mount handler opens a signed layer with dm-verity's `root_hash_sig_key_desc`, on an OS-locked thread (the
  signature reaches the kernel through the thread keyring).

The referrer layout and annotations follow the signed dm-verity implementation of the RFC's authors (branch
`dadelan/ipe-audit-signature-fallback` of the `dallasd1/containerd` fork). Differences: enabled means required (no
unsigned fallback); snapshots stay keyed by chain ID and are validated against the labels; the mount reads the
signature from a file next to the layer blob.

## Reason

The nodes this line serves boot with `dm_verity.require_signatures=1` (IPE): a dm-verity device opens only with a
trusted signature over its root hash. containerd 2.4.2 computes the root hash on the node and passes no signature, so
no EROFS layer mounts there. No containerd release implements milestone 1 of containerd/containerd#12081.

## History

- 2026-11-27: carried on the line at the `v2.4.2` pin. To file — prepared in the fork: branch
  `upstream/erofs-dmverity-signatures`, the same change on upstream `main` (`59228e1af476`), where it resolves two
  conflicts with upstream's Go EROFS converter (the differ's options and its `mkfs.erofs` probe, which upstream runs
  only when `mkfs.erofs` is configured).
