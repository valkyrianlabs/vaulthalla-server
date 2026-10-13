<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- core: platform seams (core/include/platform, core/src/platform/{linux,darwin}) for the OS-specific syscalls;
  the Linux implementations are the previous inline code, moved. TPMKeyProvider is now crypto::secrets::KeyProvider
  over a platform sealer (Linux: TPM2/swtpm, unchanged blobs).
- core: the kernel FUSE bridge is a build feature (-Dfuse, required on Linux as before); libfuse types no longer
  leak outside core/src/fuse.
- build: Boost >= 1.89 (no boost_system library) and fmt >= 10 (CURLcode formatting) are supported.
- fix: `vh <command> --help` could read an unset color theme (undefined behavior) while rendering help.
- fix: the CLI's AF_UNIX address length is offsetof(sun_path)-based and over-long socket paths are refused.
- fix: the unprivileged daemon no longer tries to run `usermod` when binding the first CLI user to `admin`.
- tests: make test / make itest entry scripts are executable again (Permission denied on a fresh clone).
- macOS (development only, not packaged): the daemon, vh and the unit tests build and pass natively on Apple
  Silicon (tools/macos, .github/workflows/macos.yml); FUSE is off and secrets use a development file backend.
- fix(fuse): a rename with RENAME_EXCHANGE (or any flag besides RENAME_NOREPLACE) is refused with EINVAL; it used
  to be carried out as a plain rename that overwrote the entry the caller asked to swap.
- macOS (development, not packaged): launchd LaunchDaemons and an idempotent provisioning script for the headless
  `_vaulthalla` system service (deploy/launchd); Linux installs exactly the same files as before. Provisioning
  refuses a conflicting existing account, symlinked or foreign-owned paths, and a purge into a mounted namespace.
- vh: on macOS, the "not running", "not responding" and "permission denied" hints name launchctl, the log file and
  dseditgroup instead of systemctl, journalctl and usermod (Linux wording unchanged).
- macOS (development, not packaged): HTTP uploads stage in a private directory under the state root when the build
  has no FUSE bridge, and the daemon refuses to start unless that state root is private to it (no symlink, no
  writable ancestor, owned by the daemon user). Linux keeps staging through the FUSE mount (`http_upload_staging=auto`).
- build/dev: meson `-Dinstance=NAME` builds an isolated instance (own prefix, paths, account, units/LaunchDaemons,
  database, ports +100, `vh-NAME`); `make dev` now installs the `dev` instance beside production instead of over it,
  on Linux and macOS (`make dev-plan` prints the privileged steps, `make dev-uninstall` removes it). Production builds
  and `make install` are unchanged.
- feat(cli): `vh fs ls|get|put` (#229): vault file access over the CLI socket's existing length-prefixed JSON frames
  (256 KiB base64 data frames, every frame bounded before allocation, at most 4 downloads and 2 uploads in flight);
  authorization through the HTTP lanes' evaluator (http::access::resolveUserPath, re-checked every 8 MiB and before
  commit); uploads staged privately and sealed by fs::Filesystem::createFile (compare-and-swap on overwrite); the
  client keeps local files local, writes outputs atomically and caps every reply frame (64 MiB, 512 KiB in a transfer).
- feat(macos): installer package `vaulthalla-<version>-arm64.pkg` (tools/macos/pkg): self-contained (PostgreSQL 16
  built from verified source against the OS only; every non-system library bundled into /usr/local/lib/vaulthalla;
  Node 24; libmagic's database via VH_MAGIC_DB_PATH); postinstall runs `vaulthalla-provision --apply --enroll
  <console user>`: a private cluster (sh.vaulthalla.postgres, _vaulthalla, peer socket in a 0700 dir, scram on
  127.0.0.1:36971), a generated role password handed to the daemon, the CLI admin bound to the installing user.
  Homebrew cask (vaulthalla/homebrew-tap) wraps the same package; release.yml builds it on GitHub-hosted Apple
  Silicon (signed and notarized with Developer ID secrets), attaches it to the GitHub release and updates the cask,
  without gating the APT release.
- fix(macos): vaulthalla-provision reads dscl's native-attribute form (`dsAttrTypeNative:IsHidden`); a config.yaml
  still identical to the shipped template is rendered for the bundled database instead of kept.
