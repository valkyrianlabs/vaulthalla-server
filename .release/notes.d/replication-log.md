## Folders and linked servers

- **Groundwork for mirroring a vault between two servers: the replication log.** The upgrade adds the tables and
  database triggers that will record, on the server a mirrored vault belongs to, every change to that vault in the
  order it was made. No vault can be mirrored yet, so nothing is recorded: the upgrade changes no existing row, writes
  no log entry, and file operations cost one extra lookup each (under 0.1 ms per write on the test machine). There is
  nothing to do before or after upgrading.
