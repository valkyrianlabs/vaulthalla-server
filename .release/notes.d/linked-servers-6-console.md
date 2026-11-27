## Linked servers and mirrored vaults

- **Mirrored vaults in the web console.** Beside Linked servers, super admins get a **Mirrored vaults** tab with what
  `vh mirror` offers: every vault mirrored with another server, whether this server is its core or holds a copy, the
  state with its reason in plain words (live, first copy with its progress, read-only because the link is down,
  paused, diverged, expired, the core deleting it and when, switching, the old core replaced, both servers having
  taken over) and the changes held here; **Mirror a vault** (it asks you to confirm it's you, since the vault's keys
  go to the other server), the offers other servers make (accept or decline) and each linked server's settings
  (accept every vault it offers, keep the vaults it removes). A vault's page says what to do next, shows the
  server's own advice when it has some, and offers only the actions that fit: switch the core (and what the old core
  keeps), resync, take over as core (with what happens, the warning about changes the old core may hold, the vault's
  name typed and a confirmation that it's you), detach (with what it gives first: the files whose contents never
  arrived, the new owner, the vault's name typed), detach a copy (its progress, cancel and the files left out),
  versions kept on the mirror, ending a mirror or removing an orphaned copy, and the held changes (retry, discard,
  save the person's version).
- **Deleting a mirrored vault in the console** asks what happens to the copy on the other server, and explains that
  a copy held here can't be deleted as a vault.
