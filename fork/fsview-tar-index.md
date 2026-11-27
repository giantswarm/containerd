---
id: fsview-tar-index
fork: containerd
category: bugfix
status: carried
commits:
  - 'erofs: mount dm-verity layers instead of reading them in fsview'
  - 'erofs: read tar index layers in fsview'
upstream:
  outcome: to-file
  refs: []
  branch: upstream/fsview-tar-index
  exit: the first containerd release whose fsview erofs handler reads tar index layers and leaves dm-verity layers to the mount handler
verified: 2026-11-28
---
# fsview: tar index layers and dm-verity layers

## Change

Two commits to fsview's erofs handler (`plugins/mount/fsview/erofs`), which reads a container's image files without
mounting them, such as `/etc/passwd` and `/etc/group` when CRI creates a container with a user:

- `erofs: mount dm-verity layers instead of reading them in fsview`: a layer mount that carries the
  `X-containerd.dmverity=` option is no longer read from its blob. fsview returns `ErrNotImplemented`, so the caller
  activates the mounts through the mount manager, and the erofs mount handler opens the layer's dm-verity device (with
  its root-hash signature, when the layer carries one) as it does for the container's rootfs.
- `erofs: read tar index layers in fsview`: a layer the erofs differ wrote with `enable_tar_index` (the
  `mkfs.erofs --tar=i` index followed by the tar) is mounted without `device=` options, and the kernel reads the tar,
  an extra device mapped behind the index, from the image itself (flat device mode). fsview now hands go-erofs the
  image's own regions at the devices' mapped block addresses; before, go-erofs refused the layer with
  `invalid super block: extra devices count 1 does not match provided 0`. An image whose devices do not lie within it
  still needs them named and fails as before.

## Reason

With `enable_tar_index = true`, creating any container whose user needs `/etc/passwd` or `/etc/group` failed in
containerd v2.4.2, with or without dm-verity:

```
failed to handle lowerdir option: ... <overlay 0 14>: error calling overlay: failed to resolve mount 0: invalid super block: extra devices count 1 does not match provided 0
```

The nodes this line serves run every layer through dm-verity with a signed root hash. Reading a layer's blob directly
there would skip dm-verity's check of the blocks read, so a modified blob would decide the container's user and groups
unnoticed: a dm-verity layer takes the mount, which verifies every block, and only layers without dm-verity are read
directly. Neither change makes a layer usable that was not before: the snapshotter decides which layers mount and how.

## History

- 2026-11-28: carried on the line at the `v2.4.2` pin. Neither upstream `main` nor go-erofs (`v0.3.2`, `main`) reads
  a flat-device image without `device=` options, and fsview on upstream `main` reads dm-verity layers and their data
  devices from their blobs; no upstream issue or pull request covers either. To file — prepared in the fork: branch
  `upstream/fsview-tar-index`, the same two commits on upstream `main`, where the dm-verity check also covers the data
  devices' `X-containerd.dmverity.device.<index>=` options.
