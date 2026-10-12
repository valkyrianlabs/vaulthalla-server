# macOS FUSE proof matrix

Tooling for the decision gates in #213 (macOS 27 delta audit), #200 and #221. It answers two questions for a macFUSE
backend: does the kernel report the right caller for every request, and does any request get answered from a cache
without the daemon being asked? Vaulthalla's per-uid RBAC and "deny means hidden" rule need both.

- `vh_fuse_probe.c`: a libfuse3 low-level filesystem. It logs `fuse_req_ctx()` uid/gid/pid for every request and
  enforces deny-as-ENOENT from a policy file that it re-reads on every request.
- `matrix.sh`: mounts the probe and checks each item against the probe's request log: caller identity (user, second
  user, root), cross-uid cache hits, grant/revoke latency, open handles, rename flags, 32 MiB integrity, AppleDouble
  creates, and forced unmount.

Both need macFUSE installed (≥ 5.4.0). Installing it, enabling its FSKit module and, for the kernel backend, Reduced
Security are system changes that need the maintainer's approval (gates I0, K1/K2).

```sh
cc -std=c11 -Wall -Wextra -DFUSE_USE_VERSION=35 -DFUSE_DARWIN_ENABLE_EXTENSIONS=0 \
   $(pkg-config --cflags --libs fuse3) tools/macos/fuse-probe/vh_fuse_probe.c -o tools/macos/fuse-probe/vh_fuse_probe
tools/macos/fuse-probe/matrix.sh --backend fskit --other-user <second-local-user>   # gates F2/F3
tools/macos/fuse-probe/matrix.sh --backend kext  --other-user <second-local-user> -- -o novncache -o noattrcache  # K2
```

The headless gates (F1, K1) run the probe from a LaunchDaemon as a hidden service account before any login. They
are run by hand with the maintainer, because they create an account and a LaunchDaemon.
