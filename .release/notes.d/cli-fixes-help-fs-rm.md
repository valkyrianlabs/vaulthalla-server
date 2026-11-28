## Command line

- **`--help` never runs a command.** `--help` (or `-h`) anywhere on a `vh` command line prints that command's usage
  and does nothing else. Before, `vh peer pair --help` opened a real pairing window and `vh peer link --help`
  complained about its arguments.
- **`vh fs rm`, `vh fs mkdir` and `vh fs mv`.** Delete, create folders and move or rename from the command line, with
  the web console's permissions and audit events. `vh fs rm <vault> <path>` moves a file to the vault's trash; a
  folder that isn't empty needs `--recursive`.
- **Folder times on a mirrored vault.** A server holding a copy of another server's vault now shows the core's
  modification time for its folders (in `vh fs ls` and the console), not the time the copy created them.
- **Clearer refusals for linked servers and mirrors.** `vh peer ...` and `vh mirror ...` refused to someone else now
  say who may run them and who you are signed in as. Run with `sudo`, they explain that root, the host's system
  account, is not a super admin for these commands: run `vh` without `sudo`, as your own account.
