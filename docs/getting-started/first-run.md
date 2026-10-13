---
title: First Run
description: After installing on Linux or macOS - sign in, secure the admin account, confirm CLI access, serve HTTPS, create a vault and set up recovery.
order: 20
status: published
tags:
  - setup
  - cli
  - admin
---

# First Run

After installation, a few steps turn a fresh install into one you can rely on: secure the built-in `admin` account, confirm that `vh` works from your account, put the console behind HTTPS, create a vault, and set up recovery material before important data goes in.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Checklist

:::steps

### Confirm the service is healthy

```bash
vh status
```

`vh status` exits `0` when healthy, `1` degraded, `2` critical. If `vh` can't connect, see [CLI Access](#cli-access) below.

### Sign in and change the admin password

Each install generates its own `admin` password and keeps a plaintext copy readable only by root. Sign in with it, then change it (or keep it and delete the file).

### Confirm CLI access

Run `vh` from your own account, not with `sudo`.

### Serve the console over HTTPS

[nginx on Linux](/https/nginx), [Caddy on macOS](/https/caddy).

### Create a vault and export its keys

[Local Vaults](/vaults/local-vaults) or [S3 And R2 Vaults](/vaults/s3-r2-vaults), then [Backup And Recovery](/vaults/backup-and-recovery).

:::

## Sign In

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
```bash
sudo cat /var/lib/vaulthalla/super_admin_initial_password
```

Open `http://<host>/` (through the nginx site the package set up) and sign in as `admin`.
:::

:::tab[macOS]{value="macos"}
```bash
sudo cat "/Library/Application Support/Vaulthalla/state/super_admin_initial_password"
open http://127.0.0.1:36968
```

Without HTTPS the console answers only on the Mac itself. Sign in as `admin`.
:::

:::

Then change the password from the account bound to `admin`:

```bash
vh setup set-super-admin-password
```

It asks for the new password and removes the plaintext copy. More about signing in, password policy and the console's areas: [Web Console](/getting-started/web-console#first-login).

## CLI Access

`vh` talks to the daemon over a local socket that only members of the service's group can open, and maps each caller to a Vaulthalla user by uid.

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
The socket is `/run/vaulthalla/cli.sock` and the group is `vaulthalla`. If the installer didn't enroll you:

```bash
sudo usermod -aG vaulthalla "$USER"
newgrp vaulthalla
vh setup assign-admin
```

`vh setup assign-admin` binds `admin` to your Linux UID when it is still unbound. Until someone claims it, the first non-root user to reach the socket can. Details: [CLI Access on Linux](/linux/administration#cli-access).
:::

:::tab[macOS]{value="macos"}
The socket is `/Library/Application Support/Vaulthalla/run/cli.sock` and the group is `_vaulthalla`. The installer enrolled you and bound you to `admin`, so `vh` works right away. To add other local users: [CLI Access on macOS](/macos/administration#cli-access).
:::

:::

Day-to-day commands (`vh vault`, `vh user`, `vh api-key`, `vh vault sync`) need no `sudo`. Only lifecycle commands do: [CLI Guide](/cli#lifecycle-commands).

## Database

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
The package bootstraps a local PostgreSQL database when one is installed and healthy. If you skipped it (`VH_SKIP_DB_BOOTSTRAP=1`) or use a remote database:

```bash
sudo vh setup db
sudo vh setup remote-db --host db.example.com --port 5432 --user vaulthalla \
  --database vaulthalla --password-file /root/vaulthalla-db-password
```

See [Local PostgreSQL Bootstrap](/linux/installation#local-postgresql-bootstrap).
:::

:::tab[macOS]{value="macos"}
Nothing to do: the package runs its own PostgreSQL 16 cluster, private to Vaulthalla, and set it up at install time. See [The Bundled Database](/macos/administration#the-bundled-database).
:::

:::

## Next Steps

- [Create a local vault](/vaults/local-vaults) or [an S3/R2 vault](/vaults/s3-r2-vaults) (an S3/R2 vault needs an API key first).
- [Share files](/sharing) and [add users and roles](/admin/users-groups-roles).
- [Export vault keys and plan backups](/vaults/backup-and-recovery) before putting important data in.
- On Linux, browse vaults through the [FUSE mount](/vaults/filesystem-access).
