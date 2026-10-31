---
title: Web Console
description: Use the Vaulthalla browser console for files, shares, vaults, users, groups, roles, provider credentials, cost control, the S3 gateway, health, notifications, and settings.
order: 30
status: published
tags:
  - web
  - admin
  - operator
---

# Web Console

The Vaulthalla web console is a packaged Next.js application served locally (by `vaulthalla-web.service` on Linux, the `sh.vaulthalla.web` LaunchDaemon on macOS) and normally exposed through the HTTPS proxy that `sudo vh setup nginx` (Linux) or `sudo vh setup caddy` (macOS) configures.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Access

After HTTPS setup, open the configured hostname:

```text
https://vault.example.com
https://vault.home.arpa
```

The web runtime listens on `127.0.0.1:36968`, and the daemon's WebSocket and HTTP endpoints listen on local ports for the proxy (see [HTTPS And Reverse Proxies](/https)). Operators normally do not connect to those ports directly; on a Mac without HTTPS, `http://127.0.0.1:36968` works on the Mac itself.

Relevant services:

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
```bash
systemctl status vaulthalla-web.service
systemctl status vaulthalla.service
```
:::

:::tab[macOS]{value="macos"}
```bash
sudo launchctl print system/sh.vaulthalla.web | grep -E 'state|pid'
sudo launchctl print system/sh.vaulthalla.server | grep -E 'state|pid'
```
:::

:::

### HTTP And HTTPS

A fresh Linux package install serves the console over plain HTTP on port 80 (`http://<host>/`), which is enough to finish first run on a trusted network; a fresh Mac install serves it only on `http://127.0.0.1:36968`. The session cookie is marked `Secure` only when the browser-facing request arrived over HTTPS, as reported by the local proxy (`X-Forwarded-Proto`), so login works on both.

:::callout{theme="warning" title="Use HTTPS beyond a trusted LAN"}
Over plain HTTP, passwords and session tokens cross the network unencrypted. Before exposing the console, enable TLS: `sudo vh setup nginx --domain vault.example.com --certbot` on Linux, `sudo vh setup caddy --domain vault.home.arpa` on macOS.
:::

### First Login

There is no default password. When the service first starts with a new database, it generates a strong password for the web `admin` account (16 random bytes, shown as 32 hex characters), unique to this install, and writes a copy to a root-readable file:

```bash
sudo cat /var/lib/vaulthalla/super_admin_initial_password                                 # Linux
sudo cat "/Library/Application Support/Vaulthalla/state/super_admin_initial_password"     # macOS
```

Sign in as `admin` with it. The session is a normal one; nothing forces you to change the password first. Repeated failed logins are rate-limited per client address and account.

Changing it is recommended but not required:

- Change it with `vh setup set-super-admin-password`, run as the local user bound as the Vaulthalla super admin (on Linux see `vh setup assign-admin`; on macOS the installing user is bound), without `sudo`. Changing it from the web console works too. Either way the file is removed.
- Or keep the generated password and delete the file (`sudo rm` the path above). Deleting the file doesn't change the password.

Until you do one or the other, the console shows the super admin a warning, and on Linux `vh setup nginx` asks what to do before putting the console behind nginx. The file is written only once: deleting it never makes a new one appear, and upgrades, reinstalls and restarts keep the existing password.

Installs older than 1.8.0 seeded the same default password everywhere. If `admin` still uses it, the first start of 1.8.0 replaces it with a generated one, writes it to the file above, and ends the account's web sessions. Passwords you set yourself are not touched.

## Main Areas

One sidebar groups the console. It only shows the areas your role can use:

| Section | Pages |
|---|---|
| (top) | **Files**, **Shares**, **Vaults** |
| Access | **Users**, **Groups**, **Roles** (admin and vault roles in one list) |
| Storage & cost | **Provider credentials** (S3/R2 API keys), **Cost control**, **S3 gateway** |
| System | **Health** (runtime, filesystem, storage and activity telemetry), **Notifications** (operator email), **Settings** |

Press `⌘K` (`Ctrl+K`) anywhere to jump to a page, a vault, a user or an action. Your account menu (top right) opens **Your account**, where you change your own password. Older console addresses such as `/dashboard`, `/api-keys`, `/pricing-budget` and `/operator-email` redirect to their new pages.

## Files

**Files** browses your vaults through Vaulthalla permissions (the same tree as `/mnt/vaulthalla`). The vault switcher sits next to the folder path, and the path is part of the address, so back, refresh and links to a folder work.

- **Upload** with the Upload button (files or a whole folder), or drop files and folders anywhere on the page.
- Open a folder or preview a file by double-clicking it or pressing Enter. Each row has a `⋯` menu, and right-click opens the same menu: download (folders download as a zip), share, rename, move to, copy to and delete. Deleting always asks first.
- Copying a folder copies everything in it, and the copies open right away. Copying needs permission to copy and download what you copy and to create it where it lands, and it is refused if the vault's quota can't hold it.
- Deleting a file leaves its folder in place, even when the folder ends up empty, here and in `/mnt/vaulthalla`. Delete a folder to remove it.
- Keyboard: arrow keys move, Shift/Ctrl extend the selection, Ctrl+A selects all, F2 renames, Delete deletes, Backspace goes up a folder.
- The preview sheet shows images, PDFs (every page), video and audio with seeking, 3D models (GLB, glTF, STL, OBJ, and STEP with the optional CAD helper) and text or Markdown, which you can also edit and save in place. See [File Previews](/web-console/previews).
- The transfers indicator in the top bar shows progress, speed and time left. Uploads can be cancelled, briefly interrupted files are retried, and the browser warns before you close a tab mid-upload. On current servers uploads resume where they stopped, even after a reload: see [Uploads](/web-console/uploads). File downloads stream at any size; a download the server refuses (for example for missing permission) is reported there instead of replacing the page.

The actions offered depend on your role; the daemon enforces every permission.

People who open a share link see the same file browser, limited to the operations the link grants (for example browse and download). A preview-only link shows image and PDF previews only; video, audio, 3D models and text need a link that allows downloads. An **Upload dropbox** link shows only an upload area: recipients can send files into the folder but can't see what's already there.

## Vaults

**Vaults** lists every vault you can manage with its storage, owner, usage and status. **New vault** creates a local or S3-compatible vault. Opening a vault shows its tabs:

- **Overview**: capacity, sync health, activity, recovery readiness, security, share links, retention, cost and trends, as reported by the daemon.
- **Access**: who has which vault role (users and groups), assign, change or remove a role, and path-scoped permission overrides.
- **Shares**: the vault's share links.
- **Sync & cost**: the S3 sync policy and request guardrails, and a summary of the vault's price budget.
- **Gateway**: S3 gateway bucket bindings for this vault.
- **Settings**: name, description, quota, owner, slug and FUSE name, and deleting the vault. A vault's storage type can't be changed after creation. Deleting a vault removes it from Vaulthalla; the data on disk or in the bucket is left in place.

For S3-compatible vaults, creation asks for:

- Provider credential.
- Bucket.
- Storage tier or storage class.
- Sync strategy: `cache`, `sync`, or `mirror`.
- Conflict policy.
- Sync interval.
- Upstream encryption.
- Request budget preset or custom request limits.
- Maximum remote index age.

The form defaults new S3 vaults toward bounded behavior: cache-style sync, upstream encryption enabled, balanced request budgeting, and a finite remote-index freshness window.

## Health

**Health** shows the daemon's own view of runtime, filesystem, storage and activity, with a customizable overview of cards. Severity always comes from the daemon: when a value isn't measured, or the daemon can't be reached, the console says "not available" or "unknown" rather than showing it as healthy. The dot next to the search box in the top bar shows the overall status.

Health and the top-bar dot need the `admin.stats.view` admin permission. The built-in `admin`, `auditor`, `platform_operator` and `super_admin` roles have it; grant it to another role in **Roles** (Health and stats) or with `vh role admin update <role> --allow-stats-view`. A vault's own statistics on its **Overview** tab don't need it: they are shown to the vault's owner and to admins whose role can view that vault's statistics (`admin.vaults.*.view_stats`).

## Cost Control

**Cost control** manages price budgets. Use it to set global, provider-level, or vault-level policies; review status and ledger entries; and handle approved overrides. Request budgets for a specific S3/R2 vault are configured on the vault sync policy and are covered in [Request Budgets](/cost-control/request-budgets).

## S3 Gateway

**S3 gateway** manages downstream S3-compatible access. Credential creation chooses the effective principal from a relational user selector when the actor has `admin.s3_gateway.assign_principal`; users without that permission see their own principal only.

Gateway authorization is RBAC-native. `user_access` credentials inherit the principal user's Vaulthalla RBAC without gateway role rows. `vault_allowlist` credentials are managed through selected vaults, default vault roles, role exceptions, and path overrides in the credential role editor. Boolean scope flags are CLI/API shorthand only and are not the web-console policy model.

## Notifications

Use **Notifications** (operator email) to configure provider credentials, run dry-run and send tests, inspect delivery history, and confirm notification routing. See [Operator Emails](/admin/operator-emails).

## Troubleshooting Access

If the web console is unavailable on Linux:

```bash
systemctl status vaulthalla-web.service
journalctl -fu vaulthalla-web.service
systemctl status vaulthalla.service
journalctl -fu vaulthalla.service
sudo nginx -t
```

On macOS, see [The Web Console Doesn't Load](/macos/troubleshooting#the-web-console-doesnt-load).

If the console says it can't reach the server, the daemon is down or restarting, or the WebSocket proxy path (`/ws`) is wrong; the page reconnects on its own once it's back. If login succeeds but a page shows an error, check the core daemon logs first. If previews or downloads fail, also check the preview endpoint proxy and vault permissions.
