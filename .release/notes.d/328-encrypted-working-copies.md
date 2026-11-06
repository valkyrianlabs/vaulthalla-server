- **Files in use are no longer stored as plaintext.** While a file is open through the mounted filesystem, and while
  an upload or `vh fs put` is in flight, its working copy on disk is now encrypted with a key that exists only in the
  daemon's memory and changes every time the daemon starts. Nothing a crash or power loss leaves behind can be read,
  and the next start deletes it.
- **If a change can't be saved back to its vault**, the daemon now keeps it (encrypted) and retries every minute, on
  the next save or close of the file, and once more when it shuts down; reopening the file shows the change, and a
  file deleted in the meantime comes back as a new file where it was. The log says when that happens and when it
  succeeds. **The trade-off:** such a change lives only as long as the daemon process. If the daemon stops before a
  retry succeeds, or crashes, the change is lost, and the log names how many files were affected at shutdown or at
  the next start. Earlier versions kept these changes in plaintext in `/var/lib/vaulthalla/.fuse-plaintext/unsaved/`
  across restarts; if you see a log warning that plaintext files are still there, recover what you need from them
  and delete them (the upgrade never deletes them).
