---
title: Administer On macOS
navTitle: Administration
description: Run the macOS service day to day - launchd, logs, CLI access for other users, the bundled database, configuration and provisioning.
order: 52
status: published
tags:
  - macos
  - operations
  - launchd
---

# Administer On macOS

The macOS service is four LaunchDaemons in the system domain, all running as the hidden `_vaulthalla` account. This page covers the day-to-day operations: controlling the daemons, reading logs, giving other local users CLI access, the bundled database, configuration, and the provisioning tool that keeps all of it in shape.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Control The Daemons

| Label | What it is |
| --- | --- |
| `sh.vaulthalla.postgres` | Bundled PostgreSQL |
| `sh.vaulthalla.server` | Vaulthalla daemon |
| `sh.vaulthalla.web` | Web console |
| `sh.vaulthalla.caddy` | HTTPS front end (after [`vh setup caddy`](/https/caddy)) |

```bash
sudo launchctl print system/sh.vaulthalla.server            # state, pid, last exit code
sudo launchctl kickstart -k system/sh.vaulthalla.server     # restart
sudo launchctl bootout system/sh.vaulthalla.server          # stop (and unload until the next bootstrap)
sudo launchctl bootstrap system /Library/LaunchDaemons/sh.vaulthalla.server.plist   # start again
```

The daemons start at boot, before anyone logs in, and keep running across logouts. launchd restarts the server whenever it exits with an error (at most every 10 seconds) and keeps the web console, PostgreSQL and Caddy running whatever their exit status. The server tolerates a database that is not up yet: it exits and launchd retries until PostgreSQL answers.

Stopping the server gives it 30 seconds to shut down cleanly before launchd stops it hard; it normally takes about a second.

## Logs

| File | Contents |
| --- | --- |
| `/Library/Logs/Vaulthalla/vaulthalla.log` | The daemon's own log (runtime, storage, sync, auth, audit). |
| `/Library/Logs/Vaulthalla/server.log` | The daemon's standard output and errors, including start-up failures. |
| `/Library/Logs/Vaulthalla/web.log` | The web console. |
| `/Library/Logs/Vaulthalla/postgres.log` | The bundled PostgreSQL. |
| `/Library/Logs/Vaulthalla/caddy.log` | Caddy (warnings and errors only). |

The files are private to `_vaulthalla`, so reading them takes `sudo`:

```bash
sudo tail -n 50 /Library/Logs/Vaulthalla/vaulthalla.log
sudo tail -f /Library/Logs/Vaulthalla/server.log
```

## CLI Access

`vh` talks to the daemon over `/Library/Application Support/Vaulthalla/run/cli.sock`. Only members of the `_vaulthalla` group (and root) can open it, and each member is mapped to a Vaulthalla user by uid.

The person who installed the package is already enrolled and bound to the built-in `admin` account. To give another local user CLI access:

:::steps

### Enroll them in the group

```bash
sudo dseditgroup -o edit -a alice -t user _vaulthalla
```

Membership takes effect immediately. If `vh` still reports permission denied, run `sudo dscacheutil -flushcache`.

### Map them to a Vaulthalla user

As an administrator, create (or update) a Vaulthalla user with their uid:

```bash
vh user create alice --role unprivileged --linux-uid "$(id -u alice)"
vh user set alice --linux-uid "$(id -u alice)"      # for an existing user
```

The option is named `--linux-uid` on every platform; on macOS it takes the macOS uid.

### Grant access

Give them roles on the vaults they should reach: see [Users, Groups And Roles](/admin/users-groups-roles).

:::

To revoke CLI access, remove them from the group (`sudo dseditgroup -o edit -d alice -t user _vaulthalla`) or clear their mapping. A local account that is not in the group is refused at the socket before any Vaulthalla check runs.

:::callout[The admin binding]{variant="info"}
`admin` is bound to the uid of the user who installed the package, unless someone was already bound. To check which account holds it, run `vh setup assign-admin` as that user: it reports whether the binding is new or already in place, and refuses to rebind to another account.
:::

## Configuration

The configuration file is `/Library/Application Support/Vaulthalla/config.yaml`, owned by root and readable by `_vaulthalla` (mode `0640`). The keys are the same as on Linux: see [Configuration](/reference/configuration). After editing it, restart the server:

```bash
sudo "${EDITOR:-nano}" "/Library/Application Support/Vaulthalla/config.yaml"
sudo launchctl kickstart -k system/sh.vaulthalla.server
```

Installs and upgrades never replace an edited config. A config that is still byte-for-byte the shipped template is treated as never configured and is pointed at the bundled database.

## The Bundled Database

The package's PostgreSQL 16 cluster lives in `/Library/Application Support/Vaulthalla/postgres`. It listens on `127.0.0.1:36971` (password authentication, used by the daemon) and on a socket inside that directory (peer authentication for `_vaulthalla`, used for administration). No other local user can reach the socket.

```bash
PG=/usr/local/libexec/vaulthalla/postgresql/bin
SOCK="/Library/Application Support/Vaulthalla/postgres"
sudo -u _vaulthalla "$PG/pg_isready" -h "$SOCK" -p 36971
sudo -u _vaulthalla "$PG/psql" -h "$SOCK" -p 36971 -d vaulthalla
sudo -u _vaulthalla "$PG/pg_dump" -h "$SOCK" -p 36971 -Fc vaulthalla > vaulthalla-db.dump
```

The daemon's database password was generated at install time and handed over through `run/db_password`, which the daemon sealed and removed on its first start. Pointing macOS at a remote PostgreSQL is not automated (`vh setup remote-db` is a Linux command).

## Provisioning

`vaulthalla-provision` sets up and repairs everything outside the program files: the account, directories, database, configuration and LaunchDaemons. The installer runs it; you can run it to check or repair an install. Without options it only prints what it would change.

```bash
P=/usr/local/lib/vaulthalla/vaulthalla-provision
sudo "$P"                          # plan: what would change (nothing, on a healthy install)
sudo "$P" --apply                  # make it so
sudo "$P" --apply --enroll alice   # also enroll alice for vh (and bind admin if nobody holds it)
sudo "$P" --remove                 # stop and remove the LaunchDaemons; data and account stay
```

It refuses rather than repairs anything that doesn't look like its own: a `_vaulthalla` account with different settings, a symlinked or foreign-owned directory, a non-empty database directory that isn't a cluster. `--remove --purge` additionally deletes the data and the account, after checking that nothing is mounted under the directories; prefer the [uninstaller](/macos/installation#uninstall), which also removes the program files.

## Disk Encryption And Key Protection

The macOS secrets backend stores master keys as `0600` files in the `0700` state directory. Anyone who can read that directory as root or as `_vaulthalla`, or who can read the disk without FileVault, can read them. Keep FileVault on, keep `/Library/Application Support/Vaulthalla` out of shared or synced folders, and export vault keys to a GPG recipient for recovery: see [Encryption](/vaults/encryption#how-master-keys-are-protected) and [Backup And Recovery](/vaults/backup-and-recovery).

## Isolated Development Instance

Contributors can install a development build beside the packaged service with `make dev`. It uses its own account (`_vaulthalla_dev`), paths (`…/Vaulthalla-dev`), LaunchDaemons (`sh.vaulthalla.dev.*`), database and ports (+100), and a `vh-dev` CLI, so it never touches the production install. See [Development Setup](/contributors/development-setup#preferred-dev-workflow).
