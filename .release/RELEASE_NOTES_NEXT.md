<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Resumable uploads and direct device endpoints

## Web console

- **Large uploads survive interruptions.** On servers that offer resumable uploads, the console sends files in parts
  of up to 64 MiB (under Cloudflare's 100 MB request limit), up to three at a time, each checked with a SHA-256
  digest on HTTPS. A dropped connection, a busy server or a daemon restart no longer restarts the file: the console
  waits, asks the server which bytes it already has and sends only the rest. After a page reload, choosing the same
  file again in the same place picks up where it stopped ("Resuming … already on the server"). Shared upload links
  get the same behavior. Older servers keep the previous whole-file uploads.
- When some files of a batch fail, the transfers panel now names each one and why (already exists, no room left in
  the vault, the vault key changed so the file must be uploaded again, and so on).
- **Pair a device** lists the addresses this server can be reached on (copyable) and offers **Open in Vaulthalla
  Desktop**, which fills in Desktop's Add Node sheet with those addresses and the server key. The six-digit code match
  stays the proof that you are pairing with the right server.
