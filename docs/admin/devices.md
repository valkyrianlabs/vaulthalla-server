---
title: Paired Devices
navTitle: Devices
description: Pair Vaulthalla Desktop with your account, approve it by number matching, manage and revoke devices, and control whether devices on other hosts may connect.
order: 40
status: published
tags:
  - admin
  - devices
  - security
  - cli
---

# Paired Devices

Vaulthalla Desktop (the native macOS app) talks to a node through the **device listener**, a separate endpoint
the daemon serves itself on port `36972`. A paired device acts as the account that approved it, with that account's
permissions: there are no device-specific permissions to manage. Pairing never asks for a password and never uses
a browser cookie; each side pins the other's key instead.

:::toc[On this page]{depth="3" theme="compact"}
:::

## How the device listener works

- It uses TLS 1.3 with a certificate on both sides. Both certificates are self-signed and both sides pin each
  other's key, so no certificate authority, nginx or Let's Encrypt is involved, and a renewed certificate for the
  same key changes nothing.
- The daemon creates its key on first start and seals it like its other secrets (the TPM on Linux). The certificate
  lives next to them in the state directory (see [Runtime Paths](/reference/runtime-paths)).
- **It listens on loopback only by default**, so only a Desktop on the same machine can connect. Turn on remote
  connections (below) to let Macs on your network pair.
- A connection is authorized once, when it connects, by the key it presents. A key that isn't a paired device can
  only ask to pair; everything else is refused.

## Pair a device

Any signed-in user can pair devices to their own account, from the web console or the CLI.

### In the web console

1. Open **Devices** (in the navigation, or **Your devices** in the account menu) and click **Pair a device**. The
   dialog opens a pairing window for your account and counts down the time it stays open.
2. In Vaulthalla Desktop, add this server and choose **Pair**. The Mac shows a six-digit code, for example
   `482 913`.
3. The dialog lists the Mac's request (its name, platform, app version and address) with three codes. Click the
   one the Mac shows. The dialog says **Paired** and the Mac appears in your list; Desktop finishes connecting on
   its own.

A wrong click declines the request ("That code didn't match, so the request was declined"); start pairing again on
the Mac and it shows a new code. **Deny** declines a request you didn't start. Closing the dialog closes your
pairing window. If another user is pairing on the node at that moment, the dialog says so; try again when they're
done.

The dialog shows the address and port to enter in Desktop, how long the pairing window stays open (by the node's
clock), and a warning when remote connections are off.

### With the CLI

1. On the node, open a pairing window (it lasts 10 minutes):

   ```bash
   vh device pair
   ```

2. In Vaulthalla Desktop, add the node (its address and port `36972`). The Mac shows a six-digit code, for
   example `482 913`.
3. `vh device pair` lists the request with the Mac's name, platform and address, and offers three codes. Pick the
   one the Mac shows. A wrong pick **denies** the request; the Mac then starts over with a new code.

```text
Pairing request 7f3a9c1d2e4b6a80 from "Studio Mac" (macOS 1.0.0) at 192.168.1.42
Which code does the device show?  [1] 019 337   [2] 482 913   [3] 760 001
```

Without a terminal (scripts, `--non-interactive`), `vh device pair` only opens the window. Then:

```bash
vh device pending                                  # the requests and their three codes
vh device approve 7f3a9c1d2e4b6a80 --code 482913   # the code the Mac shows
vh device deny 7f3a9c1d2e4b6a80
vh device pair --close                             # close your window early
```

Only one pairing window is open on a node at a time; while another user's window is open, `vh device pair` says
until when. A super admin can close it early with `vh device pair --close --any`.

:::callout[Compare the codes, every time]{variant="warning"}
The code is what proves the Mac is talking to this node and not to something in between. Never approve a request
you didn't start, and never pick a code the Mac isn't showing.
:::

## What a paired device can reach

Over its connection to the device listener, a paired device can use the web console's operations (as its account),
download, preview and upload files (the same permission checks as the web console; share links are not offered there)
and, for AI agents on the Mac, remote MCP at `/mcp`: the same tools, limits and confirmations as `vh mcp` (see
[AI Agents And MCP](/admin/mcp-and-agents)). An agent can never approve pairing requests, turn remote connections on
or off, or export keys or secrets.

## Manage devices

**Devices** in the web console lists your devices: name, platform, app version, when it was paired and last seen,
its last address and its device id (the short form; the copy button copies all of it). Use the pencil to rename a
device and the revoke button to unpair it. Revoked devices stay in the list behind **Show revoked**. Super admins
also get **Devices → All devices**, which lists every user's devices with their owner.

From the CLI:

```bash
vh device list                      # your devices, revoked ones included
vh device list --all                # every user's devices (super admins)
vh device rename 3 "Studio Mac"
vh device revoke 3                  # or the first 8+ characters of its device id
```

Revoking is final: the device's open connections close at once and its key is never accepted again. To use that Mac
again, pair it again (Desktop creates a new key). A user can revoke their own devices, a super admin can revoke
anyone's, and Desktop can unpair itself.

A device follows its account:

- Permission and role changes apply to its open connections on the next request.
- Deactivating the account refuses the device's requests; reactivating it restores them.
- A password reset, role change or deactivation closes the device's open connections, which then reconnect.
- Deleting the account deletes its devices.

## Remote connections

Remote connections are a node setting, changed by super admins. In the web console, **Devices → All devices →
Remote connections** shows whether the listener is listening, its address and port, its open connections, any bind
error and the server key fingerprint (the pin Desktop records), with an **Allow remote connections** switch. Off,
only this machine can pair and connect; on, Macs on your network can pair and reconnect. **Settings → Device
listener** links there. From the CLI:

```bash
vh device remote status    # where the listener listens, and the node's key fingerprint (the pin)
vh device remote enable    # every interface: Macs on the network can pair and connect
vh device remote disable   # back to loopback; connections from other hosts close
```

The listener moves at once, without restarting the daemon. The choice is saved in `config.yaml`
(`device_server.remote`) and kept across restarts and upgrades. Before enabling it, make sure port `36972/tcp` is
reachable only from networks you trust (a firewall rule), even though every connection needs a paired key.

## Troubleshooting

- **`vh device remote status` says it is not listening:** the reason follows (usually the port is in use by
  another program). The daemon keeps retrying every 30 seconds; nothing else is affected.
- **Desktop says the node's identity changed:** the node's key was replaced (for example the state directory was
  restored without its sealed secrets). Pair again; the old pin can't be trusted automatically.
- **Desktop says this Mac was unpaired:** the device was revoked, or its account deleted. Pair again.
