---
title: Security-Sensitive Work
description: Contributor guidance for auth, permissions, crypto, secrets, and privileged host changes.
order: 940
status: published
tags:
  - contributors
  - security
---

# Security-Sensitive Work

If your change touches auth, permissions, crypto, secrets, local trust boundaries, or privileged host behavior, slow down and read this first.

Vaulthalla is infrastructure software. Security-sensitive work is not restricted because contributions are unwelcome. It is restricted because a sloppy patch here can create real data loss, privilege escalation, or secret-handling failures.

## What Counts As Security-Sensitive

This includes work in or around:

- authentication and session handling
- access tokens and refresh tokens
- RBAC and permission resolution
- encryption and decryption behavior
- key management and secret storage
- local socket trust boundaries
- privileged lifecycle commands
- install scripts that modify system state
- TPM and `swtpm` behavior
- preview or proxy routes that can expose data unexpectedly

Common repo surfaces:

- `core/src/auth/*`
- `core/src/rbac/*`
- `core/src/crypto/*`
- `core/src/protocols/shell/*`
- `core/src/protocols/http/*`, `core/src/storage/{PlaintextReader,GcmFileReader}.cpp`, `core/src/preview/*`, `core/tools/*`
- `web/middleware.ts`
- `web/src/lib/session.ts`
- `debian/postinst`, `debian/prerm`, `debian/postrm`
- `deploy/lifecycle/main.py`
- `deploy/systemd/vaulthalla-swtpm.service.in`

## Preview And Download Invariants

The HTTP preview, download and text-save lanes hand out decrypted vault content, so changes there are security-sensitive even when they look like plumbing. These rules hold today and need maintainer approval to change:

- **No plaintext at rest from these lanes.** Previews, downloads, playback and conversions decrypt vault content only into process memory, pipes and socketpairs. No temporary plaintext files, no plaintext caches: every derived artifact (thumbnail, page render, poster, GLB, transcode) is encrypted with the vault key before it touches disk. Legacy plaintext thumbnail directories are deleted at startup. Nginx must not spool `/preview` or `/download` responses to disk (`proxy_buffering off` on fresh installs, `X-Accel-Buffering: no` from the daemon everywhere).
- **Preview is not Download.** The `preview` capability only ever returns lossy server renders (JPEG thumbnails, PDF pages, posters). Anything that gives the browser original bytes or a full-fidelity reconstruction (SVG/WebP originals, media, 3D models, text, GLB from STEP, transcodes) requires `download`. The daemon decides this per file type in `preview::classify`; the web console only follows it.
- **RBAC is authoritative and lives in one place.** `protocols/http/Access.cpp` maps each route's need onto filesystem RBAC (signed-in users) or the share operation (share links), before any cache lookup, decryption or rendering. Nothing beneath a handler authorizes. `HEAD` runs exactly the same checks as `GET`. Callers who can't read a vault learn nothing about which paths exist in it.
- **Text saves are conditional.** `PUT /upload/text` requires `If-Match` on the version the editor opened and filesystem Overwrite, and re-seals through the normal filesystem path. Share links can't edit.
- **Converters never run in the daemon.** STEP and media parsing happen in separate helper executables from optional packages, under resource limits, Landlock and a seccomp filter, fed through a range-pull channel. Their libraries are never linked into `vaulthalla-server`.
- **Plaintext that has to sit on disk while in use is a `crypto::ScratchFile`.** FUSE working copies and upload and `vh fs put` staging are block-encrypted (XChaCha20-Poly1305, fresh nonce per block write, AAD bound to the file and block) under a key that exists only in the daemon's memory, so a crash leaves nothing readable. New staging or spool code uses it, or the vault key when the bytes must survive a restart (the resumable upload spool). Never write plaintext to a temporary file. The S3 gateway's request-body spool and multipart parts are the known exception (#345).
- **Integrity failures stop streams.** A file version whose AES-GCM tag fails is aborted for every reader and refused afterwards; don't add paths that read ciphertext without going through `storage::PlaintextReader`.

## Decide Which Path To Use

| Situation | What to do |
| --- | --- |
| You found a likely auth bypass, privilege escalation, secret disclosure path, or exploitable trust-boundary failure | Do not open a public issue with exploit details. Report it privately. |
| You want to harden a sharp area but are not reporting an active vulnerability | Open an issue first and ask for maintainer guidance before implementing. |
| You are improving docs, tests, comments, or validation around a sensitive area without exposing exploit details | A normal public PR is usually fine, but keep scope narrow. |
| You are changing auth, RBAC, crypto, session, TPM, or privileged lifecycle behavior | Get maintainer approval before writing the patch. |

## Private Reporting

If you believe you found a real vulnerability:

1. do not post exploit details in a public issue or PR
2. ask for a private reporting route if one is not already published
3. share reproduction, impact, and affected paths privately

This repository does not currently document a dedicated security mailbox in-tree. If no private contact route is published at the time you are reporting, open a minimal issue asking for a private channel without posting the vulnerability details themselves.

Before broader external contribution, Vaulthalla should publish a dedicated `SECURITY.md` or enable a private vulnerability reporting route. Until then, do not post exploit details publicly; ask for a private channel first.

## Public Hardening Work

The following can still be reasonable public contributions when handled carefully:

- tighter validation around sensitive paths
- documentation that clarifies trust boundaries
- better error handling that does not change security behavior
- additional tests for already-approved fixes
- small defense-in-depth changes that have already been discussed

Public hardening work still needs to avoid dumping exploit writeups into the PR thread.

## What Requires Approval Before Implementation

Do not start coding first if the work changes:

- token issuance or refresh behavior
- session validation
- permission resolution
- vault or admin role semantics
- encryption, decryption, or key-rotation logic
- local socket authentication or UID trust behavior
- TPM backend selection or fallback logic
- package-time privileged setup with security impact

For those changes, the design discussion comes first.

## PR Expectations For Approved Sensitive Work

If the maintainer has approved a security-sensitive patch, keep the PR:

- narrow
- explicit about risk and impact
- honest about validation
- free of secrets, credentials, or exploit dumps

Useful things to include:

- affected paths
- threat or failure mode being addressed
- before and after behavior
- tests or manual validation run
- any remaining risk or follow-up work

## The Short Version

- Security work is welcome.
- Security theater is not.
- Public exploit PRs are not.
- When in doubt, ask first.
