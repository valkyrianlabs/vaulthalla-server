---
title: Filesystem Access
navTitle: Filesystem Access
description: How vaults are reached as files - the FUSE mount on Linux, its identity and permission model, mount modes, and the options on macOS where no mount ships yet.
order: 205
status: published
tags:
  - vaults
  - fuse
  - filesystem
  - platform
---

# Filesystem Access

Every vault can be reached through the web console, the CLI and the S3 gateway on every platform. On Linux, vaults are also a real filesystem: the daemon mounts them through its own FUSE driver, and ordinary programs read and write them as files. This page explains that mount, its permission model, and what to use on macOS, where the package does not include a mount yet.

:::toc[On this page]{depth="3" theme="compact"}
:::

## At A Glance

| Way in | Linux | macOS |
| --- | --- | --- |
| Web console (browse, upload, download, preview, share) | Yes | Yes |
| `vh fs ls`, `vh fs get`, `vh fs put` over the CLI socket | Yes | Yes (the interim file path on macOS) |
| S3 gateway (vaults as buckets) | Yes | Yes |
| Filesystem mount | `/mnt/vaulthalla` (FUSE) | Not in the package |

## The Linux Mount

The daemon mounts every vault you can reach under:

```text
/mnt/vaulthalla
```

It is a FUSE 3 filesystem (`fuse.vaulthalla-fuse`) mounted with `allow_other` and `auto_unmount`, served by the daemon itself. A process reading or writing it is identified by its Linux uid, mapped to a Vaulthalla user, and checked against the same roles and permissions as the console and the CLI: a user sees only the vaults and paths their roles allow.

Bytes stay encrypted at rest. The mount is the decrypting view: opening a file decrypts it into a private working copy (`0600`, inside the service's state directory) shared by all handles on that file, and closing, `fsync` or the last release seals it back with a fresh IV. A copy that fails to seal is kept aside rather than lost.

### Check The Mount

```bash
mount | grep vaulthalla
ls /mnt/vaulthalla
df -h -x fuse.vaulthalla-fuse     # list other filesystems without touching the mount
```

If the daemon stops uncleanly the mount can be left stale; see [FUSE Mount Fails](/linux/troubleshooting#fuse-mount-fails). Scripts and monitoring should not `stat` the mount point blindly: if the daemon is wedged, filesystem calls into the mount can block. Prefer `vh status`, which reports the mount state without entering it.

## Mount Modes

`mount.mode` in [config.yaml](/reference/configuration) records which mount the operator intends:

| Mode | Meaning | Shipped |
| --- | --- | --- |
| `multiuser` | One mount for every local user, each checked by uid. | Linux (the default there) |
| `service_private` | A mount only the service account can use, for internal tools. | Not shipped |
| `disabled` | No mount; storage is served over HTTP, WebSocket, the CLI and S3 only. | macOS (the package's state) |

An unknown value refuses to start rather than silently becoming another mode. `vh status` reports the configured mode and the actual state separately (for example `mount: disabled -> disabled`, or `mount: multiuser -> mounted`), and health never reports a mount that isn't there.

## On macOS

The macOS package does not include the FUSE bridge, so no vault is mounted and Finder shows no Vaulthalla volume. A per-user mount needs a FUSE implementation that can tell which macOS user is asking, and none has passed Vaulthalla's acceptance yet; until one does, Vaulthalla does not promise Finder integration or per-user isolation on a Mac.

Use these instead:

- **The web console** for browsing, uploads, downloads, previews and shares.
- **`vh fs`** for scripts and the command line. `vh fs ls`, `vh fs get` and `vh fs put` move files over the CLI socket with the same permissions as the console; downloads are written atomically and uploads are stored only when complete. It is an interim path until a macOS mount ships. See [Vault Files](/cli/command-reference#vault-files).
- **The S3 gateway** for tools and sync clients that speak S3. See [S3 Gateway](/s3-gateway).

HTTP uploads on macOS stage in a private directory under the service's state root instead of going through a mount, so the console works fully without one.
