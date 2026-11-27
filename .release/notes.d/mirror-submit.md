## Folders and linked servers

- **Mirrored vaults: changes made on the mirror.** On a server that holds a mirror of another server's vault, a person
  allowed to change it (within what the vault's own server grants) can now work in it while the link is up, through the
  mount, the web console, uploads, `vh fs put`, shares and the S3 gateway: creating folders and files, writing,
  renaming, moving, deleting, and changing a file's mode or time. They see the change at once; its sealed bytes go to
  the vault's own server, which checks them, carries out the change as that person and sends it back, and both copies
  stay identical. When the other server refuses (the name was taken there meanwhile, the file changed there, or the
  change is not allowed), nothing the person did is lost: it becomes a copy named "name (conflict ...)" or is kept aside
  as a held change with the reason (`vh mirror held`, `vh mirror retry`, `vh mirror discard`), while the entry goes back
  to the other server's state. A file open for writing when the link drops is kept and sent when the link returns;
  anything new waits until then (the copy is read-only while the link is down). A copy made on the mirror is carried
  out by the vault's own server and appears when it comes back; owners and symlinks are not changed on a mirror. All of
  it is behind the experimental linked-servers switch; the upgrade adds four empty tables, and the replication log
  stops recording web uploads' temporary staging files (`.upload-http-*.part`), which were never content; nothing runs
  on a server that mirrors nothing. There is nothing to do before or after upgrading.
