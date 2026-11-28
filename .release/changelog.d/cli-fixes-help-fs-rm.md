- CLI: `--help`/`-h`/`-?` anywhere on a line is answered by the router with that command's usage; no handler runs
  (`vh peer pair --help` opened a pairing window).
- CLI: `vh fs rm <vault> <path> [--recursive]`, `vh fs mkdir` and `vh fs mv` through ops::fs (files to the trash,
  audited fs.delete/fs.mkdir/fs.move/fs.rename, mirror gate); rm is a destructive command for MCP.
- Mirror (migration 173_mirror_folder_time.sql): a folder's state document carries `folder_modified_at`, outside the
  entry hash; the applier applies it, and a first copy's pages keep folder times (vh.keep_folder_times). Folder-time
  changes alone still write no log row and change no digest.
- Peer and mirror refusals name who may and the signed-in account; root is told to run vh without sudo.
