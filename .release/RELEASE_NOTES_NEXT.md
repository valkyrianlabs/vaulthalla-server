<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Large uploads to S3 and R2 no longer fail silently

- Uploading a file of 5 MiB or more to an S3 or R2 vault could fail partway (a timeout, a SlowDown, a dropped
  connection) and still be treated as uploaded. Vaulthalla cancelled the incomplete upload at the provider but then
  carried on as if the file had arrived, so the bucket could be missing a file that the vault showed as synced. A
  failed part now fails the upload, and the file stays pending for the next sync pass.

## Under the hood

- Requests to S3, R2, SQS and STS for bucket administration, event notifications, full bucket listings and
  file-version recovery are now signed by vl-sigv4, Valkyrian Labs' shared AWS Signature Version 4 library, instead
  of a copy inside Vaulthalla. The signed requests are byte-for-byte the same, so nothing changes for providers or
  keys.
