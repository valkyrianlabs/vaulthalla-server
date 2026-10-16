---
title: Install On Linux
navTitle: Install
description: Install Vaulthalla on Ubuntu or Debian from the signed APT repository, choose an install profile, upgrade, and remove it.
order: 41
status: published
tags:
  - linux
  - install
  - setup
  - operator
---

# Install On Linux

Vaulthalla is packaged for amd64 Linux systems that use APT, systemd, FUSE, PostgreSQL, nginx, and TPM-compatible secret protection; Ubuntu 24.04 LTS is the tested target. The recommended path is the signed APT repository. Source installs are useful for development only.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Before You Install

Plan these items first:

- A Linux host with systemd.
- A user account that will operate `vh`.
- PostgreSQL, either local or remote.
- Nginx if you want the web console exposed through a domain.
- Hardware TPM through `/dev/tpmrm0` or `/dev/tpm0`, or the packaged `swtpm` fallback.
- Enough disk space for `/var/lib/vaulthalla`, PostgreSQL, cache data, and any local vault bodies.

:::callout{theme="warning" title="Do not use the development install for production"}
`sudo make install -- -d` is a volatile development path. It can reset state and should not be used for production installs.
:::

## Recommended APT Install

Use the install script for the normal packaged install:

```bash
curl -fsSL https://apt.vaulthalla.sh/install.sh | bash
```

For an interactive install with prompts for optional setup:

```bash
curl -fsSL https://apt.vaulthalla.sh/install.sh | bash -s -- --interactive
```

From a checked-out repository, the same helper is available as:

```bash
./bin/vh/install.sh
./bin/vh/install.sh --interactive
```

## Manual APT Setup

If you prefer to add the repository yourself:

```bash
sudo curl -fsSL https://apt.vaulthalla.sh/pubkey.gpg -o /usr/share/keyrings/vaulthalla.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/vaulthalla.gpg] https://apt.vaulthalla.sh stable main" | sudo tee /etc/apt/sources.list.d/vaulthalla.list > /dev/null
sudo apt update
sudo apt install vaulthalla
```

`vaulthalla` depends on `vaulthalla-archive-keyring`, which takes over `/usr/share/keyrings/vaulthalla.gpg` and
keeps the repository's signing key current through normal upgrades (for example when its expiry changes). You don't
need to download the key again later. Existing installs pick it up with `sudo apt upgrade` (or `apt-get dist-upgrade`).
A plain `apt-get upgrade` never installs new packages, so it holds `vaulthalla` back until you do. To install
the keyring on its own: `sudo apt install vaulthalla-archive-keyring`.

The signing key fingerprint is `0657 4F63 2342 3EBC 99A1  DF7B E906 C69B 29C0 E706`.

:::callout{theme="info" title="apt.vaulthalla.sh is required"}
Vaulthalla depends on libraries that are built for it and published only in this repository (PDFium as `libpdfium<branch>`, for example `libpdfium8059`). Installing a downloaded `.deb` without the repository configured leaves those dependencies unresolved.
:::

## Install Profiles

The default package includes the core daemon, CLI, web runtime, systemd units, lifecycle utility, SQL assets, Nginx template, and recommended dependencies.

Use a lean install when the host already has the required services and you do not want recommended packages installed:

```bash
sudo apt install --no-install-recommends vaulthalla
```

Skip local database bootstrap during package install:

```bash
VH_SKIP_DB_BOOTSTRAP=1 sudo -E apt install vaulthalla
```

Skip Nginx setup during package install:

```bash
VH_SKIP_NGINX_CONFIG=1 sudo -E apt install vaulthalla
```

The repository helper also accepts install-time controls:

```bash
./bin/vh/install.sh --lean
./bin/vh/install.sh --no-db
./bin/vh/install.sh --no-nginx
./bin/vh/install.sh --assign-user <linux-user>
./bin/vh/install.sh --skip-admin-assign
```

## Optional Preview Packages

Two converter packages add previews that need heavy third-party libraries. `vaulthalla` only **Suggests** them, so a normal or lean install never pulls them in, and the core package installs and runs without Open CASCADE or FFmpeg's libraries:

| Package | Adds | Built on |
| --- | --- | --- |
| `vaulthalla-preview-cad` | STEP and STP models in the web console's 3D viewer (converted to glTF on the server) | Open CASCADE |
| `vaulthalla-preview-media` | Probing video and audio, poster frames, and **Convert for playback** for media the browser can't decode (H.264/AAC transcodes, including hardware encoders) | FFmpeg libraries |

Install either or both at any time:

```bash
sudo apt install vaulthalla-preview-cad vaulthalla-preview-media
```

Each package installs one helper program under `/usr/lib/vaulthalla/helpers/` and must match the installed `vaulthalla` version exactly. No restart or configuration is needed. The daemon never loads these libraries itself: it runs the helper as a separate process for each conversion, hands it the file's bytes over a private channel (nothing decrypted is written to disk), and the helper sandboxes itself so it cannot open files for writing, reach the network or start programs. Memory, CPU-time, wall-clock and output limits come from `preview.derive.*` in [Configuration](/reference/configuration#rich-previews).

Without the packages, STEP files are listed and downloadable but have no 3D preview, and browser-playable media still streams; the console explains that the converter isn't installed.

:::callout[Hardware video encoding is unvalidated]{variant="warning"}
`vaulthalla-preview-media` detects VAAPI, Intel Quick Sync and NVENC automatically (`preview.media.hwaccel: auto`) and falls back to software encoding (libx264) whenever a hardware encoder is missing or fails. The hardware paths have not yet been validated on real GPUs in this release; software encoding is the tested path.
:::

## What The Package Creates

The package installs these main runtime pieces:

- `vaulthalla.service` for the core daemon, which also owns the local CLI control socket `/run/vaulthalla/cli.sock`.
- `vaulthalla-web.service` for the packaged web console.
- `vaulthalla-swtpm.service` when the software TPM fallback is needed.
- `/usr/bin/vh` and `/usr/bin/vaulthalla`, both pointing at the CLI.
- `/etc/vaulthalla/config.yaml` for runtime configuration. It is copied from the packaged default at `/usr/share/vaulthalla/config/config.yaml` only when missing, and upgrades never overwrite it.
- `/var/lib/vaulthalla` for Vaulthalla state.
- `/run/vaulthalla` for sockets and runtime secrets.
- `/mnt/vaulthalla` for the FUSE filesystem surface.

See [Runtime Paths](/reference/runtime-paths) for the full path map.

## TPM Or Software TPM

Vaulthalla needs TPM-compatible key protection. The package prefers a hardware TPM when `/dev/tpmrm0` or `/dev/tpm0` is available. If no hardware TPM is available, the managed `swtpm` service provides a local software TPM with state under `/var/lib/swtpm/vaulthalla`.

If neither hardware TPM nor `swtpm` is usable (for example after `--no-install-recommends` on a VM), the install still completes, but the TPM backend is reported as deferred and `vaulthalla.service` is not started. Install the fallback and re-run configuration:

```bash
sudo apt install swtpm swtpm-tools
sudo dpkg-reconfigure vaulthalla
```

Use [Linux Troubleshooting](/linux/troubleshooting) to diagnose TPM and `swtpm` failures.

## Local PostgreSQL Bootstrap

When local PostgreSQL is installed and healthy, package setup creates the `vaulthalla` role and database and hands the generated password to the service, which seals it with the TPM. Upgrades never touch an existing role or database, and a remote database configured with `vh setup remote-db` is never bootstrapped locally.

If a `vaulthalla` database already exists but this host has no sealed credential for it (typically a reinstall after `apt purge`), setup asks whether to **adopt** it (keep the data and rotate the role password), **overwrite** it (drop and recreate), or **abort**. Noninteractive installs read `VH_EXISTING_DB_ACTION=adopt|overwrite|abort` and default to abort, which stops configuration without changing PostgreSQL:

```bash
sudo env VH_EXISTING_DB_ACTION=adopt dpkg --configure -a
sudo env VH_EXISTING_DB_ACTION=overwrite dpkg --configure -a
```

Adopting keeps users and vault metadata, but vault encryption keys and stored provider API keys are only recoverable if the original `/var/lib/vaulthalla/.sealed_*.blob` files and the same TPM are restored.

You can also bootstrap later:

```bash
sudo vh setup db
sudo vh setup db --adopt      # keep an existing database without a sealed credential
sudo vh setup db --overwrite  # drop it and start fresh
```

`vh setup db` reports success only after `vaulthalla.service` stays running and has consumed the password handoff.

`VH_SKIP_DB_BOOTSTRAP=1` and `VH_SKIP_NGINX_CONFIG=1` opt-outs are remembered across upgrades. `vh setup db` and `vh setup nginx` opt back in.

For a remote database, use:

```bash
sudo vh setup remote-db --host <host> --port 5432 --user <user> --database <name> --password-file <path>
```

## Nginx And TLS

Package setup configures an HTTP nginx site when nginx is active and the lifecycle checks are low risk. Upgrades never re-enable a site you removed. For a domain and certificates:

```bash
sudo vh setup nginx --domain vault.example.com --certbot
```

Modes, Cloudflare DNS-01, the S3 hostname and removal are covered in [Serve Vaulthalla With nginx](/https/nginx). The web console reaches the daemon through nginx; fresh installs bind the WebSocket (36969) and HTTP (36970) servers to `127.0.0.1`.

## Verify The Install

After installation:

```bash
vh status
systemctl status vaulthalla.service
systemctl status vaulthalla-web.service
```

If the CLI reports a socket or permission error, finish [CLI Access](/linux/administration#cli-access): the `vaulthalla` group and the admin UID binding.

## Upgrade

```bash
sudo apt update
sudo apt upgrade
```

Use `apt upgrade`, `apt full-upgrade`, or `sudo apt install vaulthalla`. A release can add a new library dependency (1.12 adds `libpdfium8059`), and plain `apt-get upgrade` never installs new packages: it reports Vaulthalla as "kept back" and leaves the old version running.

The upgrade restarts the running Vaulthalla services. Libraries the previous release needed and nothing needs anymore (after 1.12: `libpdfium-2025`, `libpqxx-7.10`) stay installed until `sudo apt autoremove`. Keep them until you no longer want to roll back: they are no longer published, and an older release can't be reinstalled without them.

The database server must be PostgreSQL 11 or newer; local installs on Ubuntu 24.04 use PostgreSQL 16.

## Remove Or Purge

Remove the package while preserving most state:

```bash
sudo apt remove vaulthalla
```

Purge package-managed config:

```bash
sudo apt purge vaulthalla
```

Purge removes `/etc/vaulthalla/config.yaml`, `/var/log/vaulthalla`, `/var/log/vaulthalla-package.log`, the web cache, and the contents of `/var/lib/vaulthalla`, including the sealed secrets. If `/var/lib/vaulthalla` is a mount point, such as a dedicated data disk, purge empties it without crossing into other filesystems and keeps the directory. Operator-provided certbot credentials under `/etc/vaulthalla/certbot/` are kept because certbot renewal still references them.

Package purge does not silently destroy a preserved database. Interactive purge flows may offer database cleanup. Noninteractive purge preserves database state. `vh` is gone after purge, so remove a preserved database with:

```bash
sudo -u postgres psql -c 'DROP DATABASE IF EXISTS vaulthalla WITH (FORCE);'
sudo -u postgres psql -c 'DROP ROLE IF EXISTS vaulthalla;'
```

While the package is installed, tear down the local database with this command, which stops `vaulthalla.service` first:

```bash
sudo vh teardown db
```

Reinstalling after `apt remove` re-enables and starts the services.

To remove managed Nginx configuration:

```bash
sudo vh teardown nginx
```
