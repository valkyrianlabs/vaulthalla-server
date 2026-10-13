---
title: Linux Troubleshooting
navTitle: Troubleshooting
description: Diagnose a Linux Vaulthalla install - the APT package, systemd services, database bootstrap, TPM and swtpm, nginx, Certbot and the FUSE mount.
order: 43
status: published
tags:
  - linux
  - troubleshooting
  - install
  - operations
redirectFrom:
  - /troubleshooting/install-troubleshooting
---

# Linux Troubleshooting

Use this guide when the package install, first-run setup, services, database bootstrap, TPM setup, nginx, Certbot, or the FUSE mount does not behave as expected. Problems that are the same on every platform (sync, S3 vaults, previews, shares) are in [General Troubleshooting](/troubleshooting/general-troubleshooting).

:::toc[On this page]{depth="3" theme="compact"}
:::

## Start With Status

```bash
vh status
systemctl status vaulthalla.service
systemctl status vaulthalla-web.service
systemctl status vaulthalla-swtpm.service
```

Follow logs:

```bash
journalctl -fu vaulthalla.service
journalctl -fu vaulthalla-web.service
```

If you are working from a repository clone, the installed-system doctor script inspects Vaulthalla paths, services, and ownership:

```bash
bash bin/doctor.sh
```

## APT Repository Or Package Fails

Check repository configuration:

```bash
ls -l /etc/apt/sources.list.d/vaulthalla.list
ls -l /etc/apt/trusted.gpg.d/vaulthalla.gpg
sudo apt update
apt-cache policy vaulthalla
```

Package install and upgrade steps are logged to `/var/log/vaulthalla-package.log`. A clean upgrade prints a single status line; the log has every step and the full summary. To see everything on the terminal, rerun configuration verbosely:

```bash
sudo tail -n 60 /var/log/vaulthalla-package.log
sudo env VH_PACKAGE_VERBOSE=1 dpkg-reconfigure vaulthalla
```

If the package is partially configured:

```bash
sudo dpkg --configure -a
sudo apt -f install
```

Then rerun the relevant setup step instead of reinstalling blindly.

## CLI Cannot Connect

Check the socket:

```bash
ls -l /run/vaulthalla/cli.sock
systemctl status vaulthalla.service
```

`vaulthalla.service` owns `/run/vaulthalla/cli.sock` and re-creates it within about a second if it disappears. Releases up to 1.6.6 also shipped `vaulthalla-cli.socket` and `vaulthalla-cli.service`. Upgrades stop and remove them, because the socket unit could hold the socket path and make `vh` hang. If either unit still shows as active, run `sudo systemctl disable --now vaulthalla-cli.socket vaulthalla-cli.service`, then `sudo systemctl restart vaulthalla`.

Check group membership:

```bash
id
getent group vaulthalla
```

If the user was just added to the group:

```bash
newgrp vaulthalla
```

or log out and back in.

## Admin UID Not Assigned

Run as the intended operator Linux user:

```bash
vh setup assign-admin
```

If the admin user is already bound to a different Linux UID, stop and decide whether the original binding is correct. Do not try to work around the check by changing random database rows.

## Database Bootstrap Fails

Check local PostgreSQL:

```bash
systemctl status postgresql
pg_isready
```

Run local setup:

```bash
sudo vh setup db
```

For remote PostgreSQL, validate the password file and network path:

```bash
sudo vh setup remote-db --host <host> --port 5432 --user <user> --database <name> --password-file <path>
```

Check that `/run/vaulthalla/db_password` exists when the service expects a runtime database password file:

```bash
sudo ls -l /run/vaulthalla/db_password
```

For a preserved database after reinstall (the install stopped with an "existing Vaulthalla PostgreSQL database" error, or `vaulthalla.service` cannot authenticate), choose adopt or overwrite:

```bash
sudo env VH_EXISTING_DB_ACTION=adopt dpkg --configure -a      # package still half-configured
sudo vh setup db --adopt                                       # package already configured
sudo vh setup db --overwrite                                   # discard the old database
```

If you exported the original role password, you can instead reseed it manually:

```bash
sudo install -d -m 0755 /run/vaulthalla
sudo install -m 0600 -o vaulthalla -g vaulthalla /path/to/db_password /run/vaulthalla/db_password
sudo systemctl reset-failed vaulthalla
sudo systemctl restart vaulthalla
```

`vaulthalla.service` stops retrying after 10 failed starts within 10 minutes. After fixing the cause, run `sudo systemctl reset-failed vaulthalla`. The `vh setup` commands do this for you.

## TPM Or swtpm Fails

Check hardware TPM devices:

```bash
ls -l /dev/tpmrm0 /dev/tpm0
```

Check software TPM:

```bash
systemctl status vaulthalla-swtpm.service
journalctl -u vaulthalla-swtpm.service
```

Check the core daemon logs for TPM/TCTI errors:

```bash
journalctl -u vaulthalla.service
```

If the host has no hardware TPM, make sure `swtpm` and `swtpm-tools` are installed and the managed service can write `/var/lib/swtpm/vaulthalla`.

## Crypto Initialization Fails

If logs mention missing AES or PCLMUL support, the production host may not meet the AES-256-GCM runtime requirements. Move to supported hardware or a supported VM shape. Development overrides are not production fixes.

## Nginx Setup Fails

Validate Nginx:

```bash
sudo nginx -t
systemctl status nginx
```

Run setup:

```bash
sudo vh setup nginx --domain vault.example.com
```

If Certbot was requested:

```bash
sudo vh setup nginx --domain vault.example.com --certbot
sudo vh setup nginx --domain vaulthalla.dev --s3-domain s3.vaulthalla.dev --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
```

For `--s3-domain` and Cloudflare credentials errors, see [S3 Gateway Setup](/s3-gateway/setup#troubleshooting).

Check for conflicting sites before rerunning. The lifecycle command manages the Vaulthalla site and should roll back failed low-risk changes.

## Web Service Fails

```bash
systemctl status vaulthalla-web.service
journalctl -fu vaulthalla-web.service
```

Confirm the core daemon is also running:

```bash
systemctl status vaulthalla.service
```

If Nginx serves an error page, verify both the web service and proxy configuration.

## FUSE Mount Fails

Check the mount:

```bash
mount | grep vaulthalla
ls -ld /mnt/vaulthalla
```

If the mount is stale after a crash or forced stop:

```bash
sudo fusermount3 -uz /mnt/vaulthalla
sudo systemctl restart vaulthalla.service
```

Check `/etc/fuse.conf` if your deployment requires `allow_other` behavior:

```bash
grep user_allow_other /etc/fuse.conf
```

## When To Stop

Stop and take a backup before destructive choices such as database teardown, package purge, or manual state deletion. If the host already contains production vault data, preserve PostgreSQL, `/etc/vaulthalla`, `/var/lib/vaulthalla`, and any `swtpm` state before continuing.
