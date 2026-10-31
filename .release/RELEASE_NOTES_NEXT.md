<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Resumable uploads

## Uploads resume where they stopped

Vaulthalla now offers resumable uploads (`/upload/sessions`, capability `http.upload.resumable`) on the web console
listener and on the Vaulthalla Desktop device listener, share links included. A client uploads a file in parts, in
any order and in parallel; every acknowledged part is durable, survives a dropped connection or a daemon restart,
and a client resuming asks which byte ranges the server holds and sends only the gaps. Resending a part is
harmless (same bytes are accepted, different bytes are refused), and an optional `Content-Digest` catches corruption
in transit.

- Files may now be as large as the vault format allows (about 64 GiB per file) instead of 8 GiB.
- Nothing is stored in plaintext while an upload is in flight: each part is encrypted the moment it arrives, and the
  server seals the file in the background as its parts come in, so finishing a large upload takes seconds instead of
  re-encrypting the whole file.
- Create-only and compare-and-swap replacement work per file, exactly as on `PUT /upload/content`; a file that
  appears at the target before the upload commits is reported, never overwritten or silently dropped.
- Sessions expire 24 hours after their last part (at most 7 days after they began) and their temporary data is
  removed. New `transfer:` settings in `config.yaml` tune part sizes and limits; out-of-range values are refused.

The existing upload lanes keep working unchanged for older clients.

