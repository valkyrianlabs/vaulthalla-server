---
title: Sharing
description: Create and manage Vaulthalla public or email-validated share links with scoped file operations.
order: 400
status: published
tags:
  - sharing
  - web
  - access
---

# Sharing

Vaulthalla shares expose selected file or directory access through scoped links. A share can be public or email-validated, and it only grants the operations included in the selected share role.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Share Types

| Access mode | Behavior |
| --- | --- |
| Public | Anyone with the link can use the share within its allowed operations. |
| Email-validated | Recipients verify through email before access. |

Use email validation for sensitive data or when you need recipient-level control.

## Turning Sharing Off

Operators control which links work with the `sharing` section of [`config.yaml`](/reference/configuration), or **Settings → Sharing** in the web console (super admins):

```yaml
sharing:
  enabled: true
  enable_anonymous: true
  enable_email_validated: true
```

| Key | Turns off |
| --- | --- |
| `enabled` | Every share link. |
| `enable_anonymous` | Public links (anyone with the URL). |
| `enable_email_validated` | Email-validated links. |

A switch that is off refuses new links of that kind, and links already handed out stop opening, previewing, downloading and accepting uploads; recipients see that sharing is disabled on this server. Nothing is deleted: the links come back when the switch is turned on again. Share owners can still list, revoke and rotate their links while sharing is off. Console changes apply at once; edits to `config.yaml` apply after restarting the daemon (`sudo systemctl restart vaulthalla` on Linux, `sudo launchctl kickstart -k system/sh.vaulthalla.server` on macOS).

Older configuration files name `enable_email_validated` `enable_public_links`. That name is still read (the daemon logs a deprecation warning at startup); rename it when convenient. If both are present, `enable_email_validated` wins.

## Presets

Common presets include:

| Preset | Typical permissions |
| --- | --- |
| Browse + Download | Metadata, list, preview, and download. |
| Download Only | File download without broader browsing. |
| Upload Dropbox | Directory upload-oriented access. |
| Custom Role | Operator-selected operation set. |

Available operation bits include metadata, list, preview, download, upload, mkdir, and overwrite.

## Create A Share

In the web filesystem browser, select a file or directory and open the share action. Choose the access mode, preset or custom role, recipient rules, and expiration or limits where available.

After creation, copy the generated URL immediately.

:::callout{theme="warning" title="Share URLs are shown only at create or rotate time"}
Vaulthalla intentionally displays public share URLs only immediately after creation or rotation. If the URL is lost, rotate the share to generate a new one.
:::

## Manage Shares

Use the Shares page to review active shares, rotate URLs, disable access, or inspect share metadata. Public links should be rotated if they were sent to the wrong recipient or exposed in an untrusted place.

## Share-Mode Filesystem

When a recipient opens a share link, the web UI switches into share mode. Only the share's allowed operations are available. For example, a download-only share should not expose upload or mkdir actions.

## Preview Versus Download

`preview` and `download` are separate operations, and the server enforces the difference on every request:

| Operation | What recipients receive |
| --- | --- |
| `preview` | Lossy, server-rendered JPEGs only: image previews, PDF pages and thumbnails. Never the original bytes. |
| `download` | Original bytes: file downloads, SVG/WebP and other images shown as they are, video and audio playback, 3D models (including STEP models converted by the server), and text and Markdown views. |

A preview-only link is therefore safe for "look but don't take" sharing of photos and documents, but recipients can't play media, open 3D models or read text files through it; the web console tells them the link's permissions don't allow it. To let recipients play or view those, include `download` (the **Browse & download** preset does).

See [File Previews](/web-console/previews) for what each file type looks like in the browser.

## Download Counting And Limits

Share access is recorded once per **logical** access, not per HTTP request: one audit event per share session, file version and kind of access (viewing in the browser, downloading, a server conversion, or a preview) within 30 minutes. Every access that needs `download` also uses one unit of the link's download count, including playing a video or viewing a text file in the browser; previews never do. Playing and seeking through a video issues many small range requests, and those count once; the `HEAD` checks the console makes before a download don't count at all. Downloading a folder as a ZIP counts once, however many files it holds. Changing the file starts a new count for it.

A link's `max_downloads` limit, when one is set through the share API (the console's share dialog sets an expiry but no download limit), is enforced atomically: the download that would exceed it is refused with "This link's download limit was reached", and the refusal is audited. The **Shares** page shows each link's opens, downloads and uploads.

## Editing

Share links never edit files in place. Text editing in the preview sheet is a console feature for signed-in users with **Overwrite** permission; share recipients get a read-only view (with `download`). Uploads into a share follow the link's `upload` and `overwrite` operations as before.

## Operator Email Dependency

Email-validated shares depend on working operator email configuration. Before using email-validated access for production workflows, verify:

```bash
vh email doctor
vh email test --dry-run
vh email test --send --to ops@example.com
```

See [Operator Emails](/admin/operator-emails).

## Security Practices

- Prefer email validation for sensitive shares.
- Scope shares to the narrowest file or directory.
- Use download-only links when browsing is not needed.
- Rotate public URLs after accidental exposure.
- Disable old shares instead of leaving stale access in place.
- Review vault roles before creating a share on behalf of another user.
