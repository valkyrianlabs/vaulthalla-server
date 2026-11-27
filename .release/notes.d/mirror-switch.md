## Folders and linked servers

- **Mirrored vaults: starting a stopped copy over.** A copy that stopped following its vault's own server (it no
  longer matched, fell too far behind, or was stopped) can now be brought back without making it again:
  `vh mirror resync <vault>` on the server that holds the copy. Files whose bytes it already holds are not downloaded
  again. Nothing a person wrote there is lost: changes that were waiting, its own version of a file the other server
  replaced, and anything the other server does not have are kept aside as held changes (`vh mirror held`) for a super
  admin to look at, retry or discard. Both servers now also check each mirrored vault once a day and stop it, with the
  reason, if its files no longer match what was recorded. All of it is behind the experimental linked-servers switch;
  the upgrade adds four columns and nothing runs on a server that mirrors nothing.
