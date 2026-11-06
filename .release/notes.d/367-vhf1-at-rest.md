- **New file content is stored in an authenticated, chunked format (VHF1).** Every file written from this release
  on (saves through the mount, web and device uploads, resumable uploads, the S3 gateway, restores, sync downloads and
  key rotation) is sealed in VHF1: a 120-byte authenticated header that names the vault and the file's generation,
  then 64 KiB AES-256-GCM chunks, each authenticated with its position and with whether it is the last one. Truncated,
  reordered, spliced or swapped content is refused instead of served, and partial reads (video seeking, previews,
  downloads with a range, `preview.media.remote: ranged`) now authenticate every byte they return. Uploaded objects
  of encrypting S3/R2 vaults are the same bytes: still one object per file version (multipart is only transport, never
  one object per chunk), about 0.025 % larger for big files and 120 bytes larger for small ones; an empty file is a
  136-byte object.
- **Existing content keeps reading normally.** Files, local versions and snapshots written by earlier releases are
  converted to VHF1 in the background after the upgrade (see "Existing files and recovery points are converted to
  VHF1"); bucket objects of existing encrypted S3/R2 vaults keep their format until the layout migration of a later
  release. A later release retires the old format (#376). A resumable upload that was in progress during the upgrade
  finishes in the format it started in.
- The upgrade adds a generated `content_format` column to the file and recovery tables (one table rewrite); it changes
  no data.
