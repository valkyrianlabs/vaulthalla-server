---
title: macOS Troubleshooting
navTitle: Troubleshooting
description: Diagnose a macOS Vaulthalla install - the installer, launchd daemons, the bundled database, CLI access, Caddy and certificates.
order: 53
status: published
tags:
  - macos
  - troubleshooting
  - operations
---

# macOS Troubleshooting

Start with the quick checks, then jump to the symptom. Problems that are the same on every platform (sync, S3 vaults, previews, shares) are in [General Troubleshooting](/troubleshooting/general-troubleshooting).

:::toc[On this page]{depth="3" theme="compact"}
:::

## Quick Checks

```bash
vh status
for d in postgres server web caddy; do
  printf '%-10s ' "$d"; sudo launchctl print "system/sh.vaulthalla.$d" 2>/dev/null | awk '$1=="state" {print $3; exit}' || echo "not loaded"
done
sudo tail -n 40 /Library/Logs/Vaulthalla/server.log
sudo tail -n 40 /Library/Logs/Vaulthalla/vaulthalla.log
sudo /usr/local/lib/vaulthalla/vaulthalla-provision
```

The last command changes nothing: on a healthy install it ends with `0 change(s) to make`. Anything it lists is something missing or out of place, and `--apply` repairs it.

## macOS Won't Open The Package

Packages from 1.18.0 are signed and notarized and open normally; if macOS still says it can't verify the developer, the download is not the published file. Check it against its `.sha256` and with `spctl --assess --type install -v <pkg>` (it should say `source=Notarized Developer ID`), and download it again from the [GitHub releases](https://github.com/valkyrianlabs/vaulthalla-server/releases).

Packages before 1.18.0 are unsigned: the first time, open **System Settings → Privacy & Security** and choose **Open Anyway** next to the message about the package, then open it again. See [Install On macOS](/macos/installation#open-the-package).

## The Installation Failed

Installer reports "The installation failed" when the package's post-install provisioning stops. It stops rather than guesses whenever something on the Mac isn't what it would have created itself. The reason is in the installer log:

```bash
grep -E 'postinstall|preinstall' /var/log/install.log | tail -40
```

| Message | Meaning and fix |
| --- | --- |
| `an existing _vaulthalla account doesn't match what this script creates (…)` | An account with that name exists with different settings (listed in the parentheses). Inspect it with `dscl . -read /Users/_vaulthalla`. Vaulthalla never adopts or changes an account it didn't create. |
| `a user named 'vaulthalla' already exists` / `a group named 'vaulthalla' already exists` | Another account already uses the alias the service needs. |
| `… exists, owned by … (expected _vaulthalla:_vaulthalla); refusing to take it over` | A directory under `/Library/Application Support/Vaulthalla` belongs to someone else. |
| `… is a symlink; refusing to use it` | A path the service owns was replaced by a symlink. |
| `…/postgres/data exists but is not a PostgreSQL cluster` | Leftovers in the database directory. Move them aside. |
| `the bundled PostgreSQL did not come up` | See [The Database Doesn't Start](#the-database-doesnt-start). |

After fixing the cause, install the package again; provisioning picks up where it stopped.

## vh Says Permission Denied

```text
vh: permission denied opening /Library/Application Support/Vaulthalla/run/cli.sock.
```

Your account isn't in the `_vaulthalla` group. The installing user is enrolled automatically; others are enrolled by an administrator:

```bash
dsmemberutil checkmembership -U "$USER" -G _vaulthalla
sudo dseditgroup -o edit -a "$USER" -t user _vaulthalla
sudo dscacheutil -flushcache
```

If the socket opens but `vh` reports `user not found: no Vaulthalla user is mapped to Linux UID …` (the wording is the same on macOS), the account is enrolled but not mapped to a Vaulthalla user. See [CLI Access](/macos/administration#cli-access).

## vh Says The Daemon Is Not Running

```text
vh: the vaulthalla daemon is not running (nothing is listening at …/cli.sock).
```

```bash
sudo launchctl print system/sh.vaulthalla.server | grep -E 'state|last exit|runs'
sudo tail -n 60 /Library/Logs/Vaulthalla/server.log
```

A `state = spawn scheduled` with a growing `runs` count means the server starts and exits: the reason is at the end of `server.log`. The most common one is the database (next section). If the daemon isn't loaded at all, start it with `sudo launchctl bootstrap system /Library/LaunchDaemons/sh.vaulthalla.server.plist`, or run `sudo /usr/local/lib/vaulthalla/vaulthalla-provision --apply`.

## The Database Doesn't Start

```bash
sudo launchctl print system/sh.vaulthalla.postgres | grep -E 'state|last exit'
sudo -u _vaulthalla /usr/local/libexec/vaulthalla/postgresql/bin/pg_isready \
  -h "/Library/Application Support/Vaulthalla/postgres" -p 36971
sudo tail -n 60 /Library/Logs/Vaulthalla/postgres.log
```

- **Port 36971 in use:** another program holds it (`sudo lsof -nP -iTCP:36971 -sTCP:LISTEN`).
- **"database files are incompatible" or a damaged cluster:** restore from a dump (see [Backup And Recovery](/vaults/backup-and-recovery)); never initialize over the data directory.
- **The server can't authenticate after a restore:** the daemon's sealed password no longer matches the role. Set a new password on the role and hand it to the daemon through `run/db_password` (owned by `_vaulthalla`, mode `0600`); the daemon seals it on its next start.

The server also survives a database restart on its own: its connections reconnect once PostgreSQL is back, and when PostgreSQL starts after it (at boot), launchd retries the server until it can connect.

## The Web Console Doesn't Load

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:36968/
sudo launchctl print system/sh.vaulthalla.web | grep -E 'state|last exit'
sudo tail -n 40 /Library/Logs/Vaulthalla/web.log
```

Without HTTPS the console answers only at `http://127.0.0.1:36968` on the Mac itself. From other devices, set up [Caddy](/https/caddy).

## HTTPS Through Caddy

```bash
sudo vh setup caddy --status
sudo tail -n 40 /Library/Logs/Vaulthalla/caddy.log
```

| Symptom | Cause and fix |
| --- | --- |
| `port 443 is in use by …` | Another program listens on :80 or :443. Stop it, or bind Caddy to one address with `--listen`. |
| The browser says the certificate isn't trusted (internal name) | The device doesn't trust the Vaulthalla CA yet. See [Trust The Vaulthalla CA](/https/client-trust). |
| The hostname doesn't resolve | Add a DNS record on your router, or `--hosts-entry` for the Mac itself. |
| A public certificate never arrives | Without `--dns-cloudflare`, Let's Encrypt must reach the Mac on ports 80/443 at that name. Check `caddy.log`, then try `--dns-cloudflare`. Rehearse with `--acme-staging` to avoid rate limits. |
| `the generated configuration didn't validate; nothing was changed` | The working configuration is still in place. The lines before the message say why (for example, a malformed Cloudflare token). |
| `has no Cloudflare DNS module` | The Caddy in use isn't the package's. Source builds use Homebrew's Caddy, which has no DNS providers. |

More in [Serve Vaulthalla With Caddy](/https/caddy#troubleshooting).

## Health Shows Warnings You Didn't Expect

`vh status` on macOS always shows `mount: disabled -> disabled`: the server never mounts vaults (Finder access belongs to Vaulthalla Desktop). It is reported, not hidden, so that health never claims more than the host provides.

`secrets backend` should read `secure-enclave`. It reads `file (development: no hardware binding)` only on a Mac without a Secure Enclave, such as a virtual machine, where the master keys are plain files protected by permissions and FileVault; the daemon log says the same at startup.

## The Server Stops At Startup: Secure Enclave Unsealing Failed

The log (`/Library/Logs/Vaulthalla/vaulthalla.log`) says `Secure Enclave: unsealing … failed` and the daemon keeps restarting. Sealed keys open only on the Mac that sealed them and only inside the daemon that launchd starts:

- **The server was started by hand** (from a terminal, with `sudo`, or under a debugger). That copy can't open the keys, even as root. Stop it and let launchd run the service: `sudo launchctl kickstart -k system/sh.vaulthalla.server`.
- **The state directory came from another Mac, or macOS was erased and reinstalled.** The old blobs can never open here. Follow [macOS Key Recovery](/vaults/backup-and-recovery#macos-key-recovery): remove them, hand the database password to the daemon, and import the key exports.
- **After a restart with FileVault on**, the daemon doesn't run at all until the disk is unlocked; see [Restarts And FileVault](/macos/administration#restarts-and-filevault).

## Start Over Without Losing Data

Reinstalling the same package repairs program files and provisioning without touching vaults:

```bash
sudo installer -pkg vaulthalla-<version>-arm64.pkg -target /
```

`sudo "/Library/Application Support/Vaulthalla/uninstall.sh"` followed by a fresh install also keeps data. Only `--purge` deletes it.

## Collect Information For A Bug Report

```bash
vh version; vh status
sw_vers; uname -m
sudo /usr/local/lib/vaulthalla/vaulthalla-provision
sudo tail -n 200 /Library/Logs/Vaulthalla/server.log /Library/Logs/Vaulthalla/vaulthalla.log
grep -E 'postinstall|preinstall' /var/log/install.log | tail -60
```

The install acceptance checks that logs never contain the admin or database password; still, check anything you paste for vault or file names you'd rather not share.
