---
title: Administer On Linux
navTitle: Administration
description: Run the Linux service day to day - systemd units, logs, CLI access through the vaulthalla group and the admin UID binding, and the lifecycle commands.
order: 42
status: published
tags:
  - linux
  - operations
  - systemd
  - cli
---

# Administer On Linux

On Linux, Vaulthalla runs as systemd units under the `vaulthalla` system user, and operators work from their own Linux accounts. This page covers the units and logs, CLI access, and the privileged lifecycle commands that manage PostgreSQL and nginx.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Services

```bash
systemctl status vaulthalla.service vaulthalla-web.service
sudo systemctl restart vaulthalla.service
journalctl -fu vaulthalla.service
journalctl -fu vaulthalla-web.service
```

| Unit | Notes |
| --- | --- |
| `vaulthalla.service` | The daemon. Owns `/run/vaulthalla/cli.sock` and re-creates it within about a second if it disappears. It stops retrying after 10 failed starts within 10 minutes; after fixing the cause, run `sudo systemctl reset-failed vaulthalla` (the `vh setup` commands do this for you). |
| `vaulthalla-web.service` | The web console on `127.0.0.1:36968`. |
| `vaulthalla-swtpm.service` | The software TPM on hosts without a hardware TPM; its state is in `/var/lib/swtpm/vaulthalla`. |

Releases up to 1.6.6 also shipped `vaulthalla-cli.socket` and `vaulthalla-cli.service`. Upgrades stop and remove them, because the socket unit could hold the socket path and make `vh` hang. If either still shows as active, run `sudo systemctl disable --now vaulthalla-cli.socket vaulthalla-cli.service`, then `sudo systemctl restart vaulthalla`.

Package install and upgrade steps are logged to `/var/log/vaulthalla-package.log`.

## CLI Access

The CLI talks to `/run/vaulthalla/cli.sock`. Non-root users must be in the `vaulthalla` group and mapped to a Vaulthalla user by Linux UID.

### Group Membership

The interactive installer can add an operator to the group. To do it manually:

```bash
sudo usermod -aG vaulthalla <linux-user>
newgrp vaulthalla        # or log out and back in
id
getent group vaulthalla
```

### The Admin UID Binding

The built-in `admin` account is bound to the Linux UID of the operator who claims it:

```bash
vh setup assign-admin
```

Run it as the Linux account that should operate Vaulthalla. It binds `admin` to that UID when it is still unbound, reports when it is already bound to the same UID, and refuses to rebind to a different one. That account is also the only one that can change the web console password of `admin` with `vh setup set-super-admin-password`.

:::callout[The first non-root CLI user can become the CLI owner]{variant="warning"}
If setup is skipped and `admin` is still unbound, the first eligible non-root user (UID 1000 or above) that reaches the CLI socket claims it. Choose the operator intentionally during install, or run `vh setup assign-admin` as the intended user right away.
:::

### More Operators

```bash
sudo usermod -aG vaulthalla alice
vh user create alice --role unprivileged --linux-uid "$(id -u alice)"
```

Then grant roles on the vaults they should reach: see [Users, Groups And Roles](/admin/users-groups-roles).

## Lifecycle Commands

These change host services or privileged configuration and must run with `sudo`:

```bash
sudo vh setup db
sudo vh setup db --adopt                 # keep an existing database without a sealed credential
sudo vh setup db --overwrite             # drop it and start fresh
sudo vh setup remote-db --host <host> --port 5432 --user <user> --database <name> --password-file <path>
sudo vh setup nginx --domain vault.example.com --certbot
sudo vh teardown nginx
sudo vh teardown db
```

`vh setup db` reports success only after `vaulthalla.service` stays running and has consumed the password handoff. Details: [Install On Linux](/linux/installation#local-postgresql-bootstrap) for the database and [Serve Vaulthalla With nginx](/https/nginx) for nginx.

For unattended automation, set `VAULTHALLA_NONINTERACTIVE=1` (with `sudo -E`), or pass `--non-interactive` or `--yes` where a command supports it.

## Health Checks

```bash
vh status
ls -l /run/vaulthalla/cli.sock
mount | grep vaulthalla
```

`vh status` exits `0` when healthy, `1` when degraded and `2` when critical, so it works in monitoring scripts. See [CLI Guide](/cli#exit-codes).

## Configuration

`/etc/vaulthalla/config.yaml` is the runtime configuration. The package copies it from `/usr/share/vaulthalla/config/config.yaml` only when it is missing, and upgrades never overwrite it. Restart the daemon after editing it. Every key is in [Configuration](/reference/configuration).

## Isolated Development Instance

Contributors can install a development build beside the packaged service with `make dev`: `/opt/vaulthalla-dev`, `vaulthalla-dev*.service`, the `vaulthalla-dev` account and database, a mount at `/mnt/vh_dev`, ports +100 and a `vh-dev` CLI, so it never touches the production install. See [Development Setup](/contributors/development-setup#preferred-dev-workflow).
