# CI container

Vaulthalla's GitHub Actions run on the Valkyrian Labs VPS build pool (org runners labelled `vps-ci`, shared with the
other valkyrianlabs repositories). Every
run step, including the composite actions', executes in a disposable rootless Podman container:

```yaml
defaults:
  run:
    shell: bash ./ci/run-ci bash -euo pipefail {0}   # {0}: the step script (in RUNNER_TEMP)
```

- `ci/Containerfile`: Ubuntu 24.04 (pinned by digest) with `debian/control`'s Build-Depends (no CAD/media helper
  libraries, as before), g++ 14 + ccache, swtpm/tpm2-tools, Node (`web/.nvmrc`) + pnpm (`web/package.json`
  `packageManager`), Debian packaging tools, shellcheck, vl-release, pmdocs and gh. `sudo` works inside; container
  root is an unprivileged subordinate uid on the host. Keep it in step with `debian/control` and the version pins.
- `ci/run-ci`: the same script the ValkyrianLabs repositories use (see `payload-markdown/ci/README.md`), plus two
  options: `CI_CACHE_NAMES` (extra persistent caches, `<cache>/<name>` → `/cache/<name>`) and `CI_RO_MOUNTS`
  (read-only host paths). The workspace is `/workspace`; files stay owned by the runner user.
- Caches on the runner: `~/.cache/vaulthalla-ci/{ccache,pnpm-store,npm}` (`CCACHE_DIR=/cache/ccache`).
- The licensed icon store `/opt/ci/vaulthalla-web-icons` on the VPS is mounted read-only at `/opt/vaulthalla-web-icons`
  (`VAULTHALLA_WEB_ICON_SRC`); it is never copied into the repository.

Run any step locally the same way (needs Podman): `./ci/run-ci meson compile -C build`.
