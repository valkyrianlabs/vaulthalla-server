---
title: Install On macOS
navTitle: Install
description: Install Vaulthalla on an Apple Silicon Mac from the installer package or the Homebrew cask, then upgrade or remove it.
order: 51
status: published
tags:
  - macos
  - install
  - operator
---

# Install On macOS

Vaulthalla ships for macOS as one installer package, `vaulthalla-<version>-arm64.pkg`. The Homebrew cask installs that same package, so both paths set up the service identically and without further steps: the installer creates the service account and its private directories, initializes a private PostgreSQL database, starts the LaunchDaemons, and enrolls you as the CLI administrator.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Choose An Install Path

:::tabs{default="brew"}

:::tab[Homebrew]{value="brew"}
```bash
brew install --cask vaulthalla/tap/vaulthalla
```

Homebrew asks for your password and installs the package with macOS's `installer`, which does not show the Gatekeeper prompt described below.
:::

:::tab[Installer package]{value="pkg"}
Download `vaulthalla-<version>-arm64.pkg` (and its `.sha256`) from the [GitHub releases](https://github.com/vaulthalla/server/releases), check it, and install it from the command line:

```bash
shasum -a 256 -c vaulthalla-<version>-arm64.pkg.sha256
sudo installer -pkg vaulthalla-<version>-arm64.pkg -target /
```

Or open it in Finder: see [Open The Package](#open-the-package).
:::

:::

## Open The Package

The package is not signed by Apple yet. The first time you open it from Finder, macOS refuses with a message that it can't verify the developer.

:::steps

### Try to open it once

Double-click the `.pkg`. macOS shows the warning and does not open it.

### Allow it

Open **System Settings → Privacy & Security**, scroll to the message about `vaulthalla-<version>-arm64.pkg`, and choose **Open Anyway**. Confirm with your password.

### Run the installer

Open the package again and follow Installer. It needs an administrator password.

:::

Command-line installs (`sudo installer -pkg …`) and the Homebrew cask are not affected by this prompt. Signing and notarization are planned.

## What The Installer Does

The package's post-install step runs `vaulthalla-provision --apply --enroll <you>`, which is idempotent: upgrades take the same path and change only what is missing.

| Step | Result |
| --- | --- |
| Service account | Creates `_vaulthalla`, a hidden role account (no shell, no home, no password) with a uid in 450–499, and the alias `vaulthalla`. An existing `_vaulthalla` is used only if it matches exactly; otherwise the install stops without changing it. |
| Private directories | `/Library/Application Support/Vaulthalla` with `state`, `run`, `mount`, `postgres` and, later, `caddy`. Everything holding data is owned by `_vaulthalla` and closed to other users. |
| Database | Initializes the bundled PostgreSQL 16 cluster, creates the `vaulthalla` role and database with a generated password, and hands that password to the daemon, which seals it. |
| Configuration | Writes `config.yaml` pointed at the bundled database, only if none exists. An edited config is never replaced. |
| LaunchDaemons | Installs and starts `sh.vaulthalla.postgres`, `sh.vaulthalla.server` and `sh.vaulthalla.web`. |
| CLI access | Adds you (the user logged in at the console) to the `_vaulthalla` group and binds you to the built-in `admin` account, unless someone is already bound. |

When it finishes, the installer log shows:

```text
Vaulthalla is installed and running.
  Web console: http://127.0.0.1:36968 -- sign in as 'admin'; the first password is in
    "/Library/Application Support/Vaulthalla/state/super_admin_initial_password" (sudo cat it, then change it).
  CLI: vh status (<you> is enrolled)
  Uninstall: sudo "/Library/Application Support/Vaulthalla/uninstall.sh" (keeps vault data; --purge deletes it)
```

## First Sign-In

```bash
sudo cat "/Library/Application Support/Vaulthalla/state/super_admin_initial_password"
open http://127.0.0.1:36968
```

Sign in as `admin` with that password, then change it:

```bash
vh setup set-super-admin-password
```

That removes the plaintext copy. The console only answers on this Mac until you set up HTTPS with [`vh setup caddy`](/https/caddy). Continue with [First Run](/getting-started/first-run).

## Verify The Install

```bash
vh status
sudo launchctl print system/sh.vaulthalla.server | grep -E 'state|pid'
```

`vh status` reports the daemon, database and storage health. Two lines are expected on macOS and are reported as they are rather than hidden:

```text
  mount: disabled -> disabled — the server never mounts on this platform; Finder access is provided by Vaulthalla Desktop
  secrets backend: file (development: no hardware binding)
```

The server never mounts vaults on macOS (Finder access belongs to Vaulthalla Desktop, in development), and master keys are protected by file permissions rather than hardware. See [Vaulthalla On macOS](/macos#not-yet-supported).

## What Gets Installed Where

| Path | Contents |
| --- | --- |
| `/usr/local/bin/vh`, `vaulthalla`, `vaulthalla-cli`, `vaulthalla-server` | The CLI (both names) and the daemon. |
| `/usr/local/lib/vaulthalla` | `vaulthalla-provision`, `vaulthalla-caddy`, the lifecycle utility and bundled libraries. |
| `/usr/local/libexec/vaulthalla` | The bundled PostgreSQL, Node runtime and Caddy. |
| `/usr/local/share/vaulthalla`, `/usr/local/share/vaulthalla-web` | SQL migrations, templates, the web console. |
| `/Library/Application Support/Vaulthalla` | Configuration, state, the database, the CLI socket. |
| `/Library/Logs/Vaulthalla` | Logs. |
| `/Library/LaunchDaemons/sh.vaulthalla.*.plist` | The LaunchDaemons. |

The full map is in [Runtime Paths](/reference/runtime-paths).

## Upgrade

Install the newer package the same way, or with Homebrew:

```bash
brew upgrade --cask vaulthalla
sudo installer -pkg vaulthalla-<new-version>-arm64.pkg -target /
```

The installer stops the LaunchDaemons, replaces the files, and provisioning starts them again, including Caddy if you configured it. Vaults, the database, configuration and the CLI binding are kept. Reinstalling the same version is safe and repairs a damaged install.

## Uninstall

Remove the program and keep your data, so a later install picks up where you left off:

```bash
sudo "/Library/Application Support/Vaulthalla/uninstall.sh"
```

Remove everything, including vault data, the database, logs, configuration, certificates and the `_vaulthalla` account:

```bash
sudo "/Library/Application Support/Vaulthalla/uninstall.sh" --purge
```

With Homebrew, `brew uninstall --cask vaulthalla` keeps data and `brew uninstall --zap --cask vaulthalla` purges it.

:::callout[Purge is permanent]{variant="danger"}
`--purge` deletes local vault data and the keys that decrypt it. Export vault keys and back up first: see [Backup And Recovery](/vaults/backup-and-recovery). Devices that trusted the Vaulthalla CA keep trusting it until you remove it there, and lines added with `vh setup caddy --hosts-entry` are removed by `vh teardown caddy`, not by the uninstaller.
:::
