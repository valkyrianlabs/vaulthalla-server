- **Existing files and recovery points are converted to VHF1 in the background.** After the upgrade, the daemon
  re-seals every file, snapshot, local version and upstream backlog entry still stored in the legacy encryption format
  as VHF1, under the key version it already had: no key is rotated, and generations kept under a retired key stay
  under it. Each item is verified before its old form is removed (the old authentication tag over the whole file,
  then the new file read back in full with a matching plaintext digest), no plaintext is written to disk, and a crash
  at any point leaves everything readable and the conversion resumes. A snapshot that shares a file's bytes is
  converted once, with the file. The conversion pauses during a key rotation or salvage, is rate-limited
  (`vaults.format_conversion`: 32 MiB/s and 25 % of one CPU core by default), and `vh vault format status all` shows
  what is left per vault in items and bytes. S3/R2 vaults with upstream encryption convert their live files together
  with the bucket's layout migration in a later release; their recovery points convert now. Nothing needs to be done:
  converted files read exactly as before. The legacy format is retired in a later release (#376), which will refuse
  to install while anything legacy is left.
