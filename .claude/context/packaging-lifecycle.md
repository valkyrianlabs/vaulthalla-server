# Deploy assets + Debian package lifecycle

Core binary package: **`vaulthalla`**, plus two optional helper packages, **`vaulthalla-preview-cad`** (STEP/STP ->
GLB, Open CASCADE) and **`vaulthalla-preview-media`** (libav*). Each ships one executable in
`/usr/lib/vaulthalla/helpers/`, `Depends: vaulthalla (= ${binary:Version})`, has no maintainer scripts, and is
dropped by the build profile `pkg.vaulthalla.nocad` / `pkg.vaulthalla.nomedia` (debian/rules then passes
`-Dpreview_*=disabled`; otherwise `enabled`, so a missing -dev package fails the build). The core only `Suggests:`
them (after the pinned Recommends) and never links OCCT/libav/libseccomp; helper shlibs land on the helper packages.
Pinned by `tools/contracts/test_preview_helper_packages_contract.py` and release.toml's per-package contracts.
Maintainer scripts are the lifecycle source of truth:
`debian/preinst`, `debian/postinst`, `debian/prerm`, `debian/postrm`. The `bin/` scripts are source/dev helpers, and their
semantics do **not** match `apt remove/purge`. Operator-facing detail lives in `debian/README.Debian`.

## Deploy assets (`deploy/`)

- `config/config.yaml` (default runtime config, ports 36969/36970/36972/39000; ws + preview bind `127.0.0.1`, S3
  gateway `0.0.0.0`, device listener loopback until `device_server.remote`, which only `vh device remote
  enable|disable` writes; an upgraded config without the section gets those defaults), `config/config_template.yaml.in`. Meson installs both to `/usr/share/vaulthalla/config/`.
  A gitignored repo-root `config.yaml` is used only by source installs: `bin/setup/install_dirs.sh` copies it,
  and meson installs it to `/etc/vaulthalla` only with `-Dinstall_local_config_override=true` (default off,
  never set by `debian/rules`, option lives in `meson.options`).
- `psql/000…113_*.sql`: schema + ordered migrations → `/usr/share/vaulthalla/psql`.
- `systemd/`: `vaulthalla.service.in` (server, user `vaulthalla`; `Wants=`+`After=postgresql.service`,
  `Restart=on-failure`, `RestartSec=10`, `StartLimitIntervalSec=600`/`StartLimitBurst=10`, `TimeoutStopSec=30s`,
  ExecStopPost lazy `fusermount3 -uz` guarded by `findmnt`; the daemon owns `/run/vaulthalla/cli.sock` and rebinds
  it within ~1s), `vaulthalla-web.service.in` (`node
  /usr/share/vaulthalla-web/server.js`, StartLimit too, `SuccessExitStatus=143` so node's SIGTERM exit on
  stop/upgrade isn't recorded as failed, pinned by `test_package_layout_contract.py`), `vaulthalla-swtpm.service.in` (software TPM fallback).
- `nginx/vaulthalla.conf` → `/usr/share/vaulthalla/nginx/vaulthalla` (template; proxies to 127.0.0.1).
- `lifecycle/` (Python `main.py` + tests) → `/usr/lib/vaulthalla/lifecycle`: backs `vh setup/teardown`
  host operations. `vh` (cli.cpp) passes argv straight through, so new flags need no C++ change (but
  `core/usage` help text is separate). Exception: `--help`/`-h` on a lifecycle command goes to the daemon's usage
  book (no sudo needed); only root with the daemon unreachable falls back to the utility's argparse help.
- `vaulthalla.env`, `bashrc` are **gitignored local secret files**. Never print or commit them.

## Installed payload (key paths)

Binaries `/usr/bin/{vaulthalla-server,vaulthalla-cli,vaulthalla,vh}` · default config `/usr/share/vaulthalla/config/` ·
live config `/etc/vaulthalla/config.yaml` (**not a conffile**; see below) · runtime `/run/vaulthalla` (CLI socket, transient
`db_password` seed) · state `/var/lib/vaulthalla` (sealed secrets `.sealed_<key>.blob/<key>.{priv,pub}`, markers) ·
logs `/var/log/vaulthalla` · mount `/mnt/vaulthalla` · web `/usr/share/vaulthalla-web` · SQL `/usr/share/vaulthalla/psql` ·
udev `/usr/lib/udev/rules.d/60-vaulthalla-tpm.rules` (only one; `dh_installudev` is overridden) · tmpfiles
`/usr/lib/tmpfiles.d/vaulthalla.conf` · needrestart policy conf (the only dpkg conffile) · `vh.1` manpage.
No static libs or headers ship (`debian/not-installed` satisfies `dh_missing --fail-missing`).
`vh setup nginx --certbot-dns-cloudflare <credentials>` installs `/etc/letsencrypt/renewal-hooks/deploy/vaulthalla-nginx-reload.sh`.

`debian/control`: Depends `adduser nodejs openssl fuse3 python3`. `nodejs` stays unversioned: Next 16 wants
>= 20.9, but noble ships 18.19. Recommends: `postgresql nginx swtpm swtpm-tools certbot python3-certbot-nginx
python3-certbot-dns-cloudflare`. Suggests: `vaulthalla-preview-cad vaulthalla-preview-media`. Build-Depends mirror `core/meson.build` pkg-config deps (verified with
`dpkg-checkbuilddeps` on the dev VM; the CI image `ci/Containerfile` must carry the same packages).

## State markers under `/var/lib/vaulthalla`

`nginx_site_managed` (package owns the site file), `nginx_default_site_disabled` (distro default symlink we removed;
`target=` line), `db_bootstrap_disabled` / `nginx_config_disabled` (persisted `VH_SKIP_*` opt-outs; `vh setup db` /
`vh setup nginx` delete them), `tpm_backend_deferred`, `.reinstall_from_config_files` (written by preinst),
`super_admin_initial_password` (the generated web `admin` password, written once by the daemon on a new database,
0600 daemon user; never recreated; removed on rotation; postinst's summary points at it when present).

## Output policy (`/var/log/vaulthalla-package.log`)

Terminal output is operator status. postinst/prerm route every step through `detail` (log only; terminal with
`VH_PACKAGE_VERBOSE=1`), `say` (log + stdout), `warn_nonfatal`/`report_error` (log + stderr). The log is root-owned in
`/var/log` (never the daemon-owned `/var/log/vaulthalla`: a planted symlink would redirect root's appends), refused
if it is a symlink, rotated to `.1` past 1 MiB, removed on purge. systemctl transition/enable output goes there too.
A clean upgrade prints `Upgraded A -> B: services restarted, daemon healthy. Log: …` plus an `Action:` line only when
the generated admin password file still exists. `mark_degraded` (core expected up but not active, CLI socket missing,
TPM deferred, DB bootstrap failed/deferred, config missing/failed) prints an ERROR line and the full summary; fresh
and reinstall always print the summary. prerm remove prints one line. Pinned by `PostinstOutputPolicyTests` and the
raw-`echo "[${PKG}]` guard in `test_maintainer_script_safety`.

## `preinst`

`install <old-version>` (only when reinstalling over config-files state after `apt remove`) writes
`.reinstall_from_config_files`. postinst then runs in `reinstall` mode.

## `postinst configure`

- `INSTALL_MODE`: `fresh` (`$2` empty), `reinstall` (preinst marker), `upgrade` (everything else, incl. `dpkg-reconfigure`).
- **Never blocks indefinitely:** `run_bounded` (`timeout --kill-after`) wraps every systemctl/psql/pg_isready/nginx/
  udevadm/apparmor_parser call; `PGCONNECT_TIMEOUT` is passed through `env` (sudo resets env). `/mnt/vaulthalla` is
  only inspected via `/proc/self/mountinfo` (`is_mountpoint`, octal-escaped exact match), and the mounted check runs
  before any `[ -d ]`.
- **Legacy CLI units (#110)**: `vaulthalla-cli.{socket,service}` shipped up to 1.6.6. The socket unit was an
  orphaned listener on the daemon's socket path that swallowed `vh` clients forever. They're no longer shipped
  (`forbidden_paths` in release.toml's package contract; `vlr validate-artifacts` rejects them). `retire_legacy_cli_units`
  runs early in configure (before DB bootstrap, so an abort can't leave the listener up). It only acts if unit files,
  deb-systemd-helper state, `.wants` links, or a non-inactive unit exist. It stops each unit with bounded
  `deb-systemd-invoke stop` (cgroup SIGKILL on timeout), runs `deb-systemd-helper purge` + `unmask`, removes the
  `.wants` links, and runs `daemon-reload`. Stopping the socket (RemoveOnStop) deletes `cli.sock`; the core
  `try-restart` re-binds it, and `verify_cli_socket_owned_by_daemon` reports `[ -S /run/vaulthalla/cli.sock ]` in the
  summary. Units aren't conffiles, so no `dpkg-maintscript-helper` is needed. postrm purge re-runs the enablement cleanup.
- Service transitions (`transition_unit_bounded`): `reset-failed` if failed, then bounded `systemctl <verb>`; on
  timeout, `systemctl kill -s KILL` (unit cgroup only) and continue. Never fails the package operation.
- Converges user/group, `tss` membership, runtime/state dirs. Installs `/etc/vaulthalla/config.yaml` from
  `/usr/share` **only if missing** (atomic temp + rename); refreshes the template every configure. Hosts upgraded from
  conffile-era releases keep their file (dpkg marks it obsolete).
- TPM: hardware → disable swtpm. No backend (no HW TPM, no swtpm, or swtpm fails) → **deferred, not fatal**: marker
  written, core not started, remediation `apt install swtpm swtpm-tools && dpkg-reconfigure vaulthalla`; the next
  configure finishes provisioning and starts the core.
- DB bootstrap order: `VH_SKIP_DB_BOOTSTRAP` (persist marker) → persisted marker → remote `database.host` → sealed
  `/var/lib/vaulthalla/.sealed_psql.blob/psql.priv` present (normal upgrades stop here) → local PG checks → pending
  seed present (resume: converge role to seed password) → role/DB exist (**orphan**) → fresh.
  Passwords: `openssl rand -hex 32`, seed written **before** the role (atomic, 0600), role SQL only via stdin heredoc;
  seed rolled back if the role step fails.
- Orphan (role/DB, no sealed secret, no seed): empty DB (no `public.users` rows) → auto-adopt. Otherwise
  `VH_EXISTING_DB_ACTION=adopt|overwrite|abort`, else interactive `[a]dopt / [o]verwrite / a[b]ort` from `/dev/tty`
  (EOF/invalid → abort; overwrite needs a typed phrase), noninteractive default abort. Abort = `exit 1` with
  `sudo env VH_EXISTING_DB_ACTION=… dpkg --configure -a`. Adopt = `ALTER ROLE … PASSWORD` + seed + loud key-loss
  warning. Overwrite = `DROP DATABASE … WITH (FORCE)` (terminate+drop on PG<13), drop role, fresh. On `upgrade`
  without an explicit action it only warns (never aborts an upgrade).
- `#DEBHELPER#` sits after DB bootstrap; after it: disable swtpm on HW TPM hosts (dh enables every unit on first
  install), then `configure_systemd_units`, then nginx. The token must only appear as a standalone line (dh
  substitutes it inside comments too).
- Units: upgrade → bounded `try-restart` of active units only (+ start core if TPM just recovered). fresh/reinstall →
  explicit `enable` (no presets), bounded starts; core started only with a TPM backend and a DB credential (sealed or
  seed), and its ActiveState is reported 3s later.
- nginx: `VH_SKIP_NGINX_CONFIG`/marker skip; **upgrades never create or re-enable the site** (only proceed when the
  managed marker and our link exist). Fresh/reinstall: install site if missing (+managed marker), link, disable the
  distro default symlink only if unmodified (md5 vs dpkg conffile record; marker), `nginx -t` (revert both on
  failure), reload, then probe `http://127.0.0.1/` (python3) and report verified / upstream-not-ready / shadowed.

## `prerm remove|deconfigure`

Stops units frontend-first. `stop_service_bounded` waits (45s, > `TimeoutStopSec`) for ActiveState
`inactive|failed` **and** MainPID 0 (`is-active` is false while `deactivating`), then `systemctl kill -s KILL` + settle.
Disables units (reinstall re-enables them), removes transient seed files and the TPM override, removes our nginx
link and restores the distro default site if we disabled it.

## `postrm`

`remove`: transient cleanup. **`purge`** runs as `purge_package_state || true` (nothing can fail it): web cache link/dir
+ `/var/cache/vaulthalla-web`, nginx site (marker-gated) + default-site restore + certbot deploy hook, optional DB drop
(interactive only; one statement per psql call), then user/group, then `purge_tree` of swtpm state,
`/var/lib/vaulthalla`, `/var/log/vaulthalla`, `/run/vaulthalla` (`find -xdev -mindepth 1 -delete`; a mount point keeps
its directory, re-owned `root:root 0755`), lazy-unmount a stale `/mnt/vaulthalla`, remove config files, and only
`rmdir /etc/vaulthalla`. `/etc/vaulthalla/certbot/` and the operator-managed `/etc/vaulthalla/testing/` are never
removed. The preserved-DB message prints raw `sudo -u postgres psql -c …` commands (`vh` is gone by then).

## `vh setup/teardown` (lifecycle)

- `setup db [--adopt|--overwrite]`: same orphan semantics as postinst (refuses data without a flag), passwords via
  stdin, seed-first with rollback, removes the DB opt-out marker, `reset-failed` + start/restart, then
  `wait_for_service_healthy` (active, NRestarts unchanged for 5s, seed consumed) or exit 2 pointing at journalctl.
- `setup remote-db`: same health verification.
- `teardown db`: stops `vaulthalla.service` first, then one psql call per statement (`DROP DATABASE … WITH (FORCE)`).
- `setup nginx` (catch-all only) disables the stock default site with the same marker; `teardown nginx` restores it.
- Every subprocess has a timeout.

## Invariants

- Maintainer scripts stay idempotent across repeated `configure` and upgrades.
- Upgrades never overwrite `/etc/vaulthalla/config.yaml` and never destructively reset the DB, nginx, TPM state, or web cache.
- An unavailable optional integration (nginx/PostgreSQL/swtpm/systemd, incl. systemctl present but systemd not PID 1)
  never hard-fails install or upgrade. The only intentional configure failure is abort on an orphan DB with data.
- Maintainer scripts never block indefinitely and never touch the FUSE mount except via mountinfo / lazy unmount.
- Pinned by `tools/contracts/test_maintainer_script_safety.py`, `test_package_layout_contract.py`,
  `test_maintainer_script_behavior.py` (runs script functions under dash with stubs), and
  `deploy/lifecycle/tests/test_db_lifecycle.py`.

## Open questions

- `tools/dev/verify.sh lifecycle` only runs `test_main`; `test_db_lifecycle` must be run by module until it's updated.

## Teardown safety (`bin/teardown/*`)

- **Never kill processes by substring** (`pkill -f`, `pgrep -f vaulthalla`, `killall`, `fuser -k`). JetBrains
  Remote and agent processes on dev VMs carry `/srv/vaulthalla` in their argv. The only permitted kill is the
  verified `vaulthalla.service` MainPID whose `/proc/$pid/exe` is the server binary, behind `--force-vaulthalla-pids`.
- A busy mount gets a diagnostics report (`lsof`, `fuser -vm`), and holders are never killed. Teardown still falls back
  to lazy unmount (`fusermount3 -uz`, `umount -l`).
- Unit and dir removal targets exact Vaulthalla paths only, and refuses to remove mounted paths.
