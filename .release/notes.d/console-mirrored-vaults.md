## Linked servers (experimental, off by default)

- **Mirrored vaults in the web console.** Beside Linked servers, super admins get a **Mirrored vaults** tab with what
  `vh mirror` offers: every mirrored vault on this server with the other server, whether this server is its core or
  holds a copy, the state with its reason in plain words (live, first copy with its progress, read-only because the
  link is down, paused, diverged, expired, the core deleting it and when, switching) and the changes held here;
  **Mirror a vault**, the offers other servers make (accept or decline) and each linked server's settings (accept
  every vault it offers, keep the vaults it removes). A vault's page says what to do next and offers only the actions
  that fit: switch the core (and what the old core keeps), resync, detach with what it gives first (the files whose
  contents never arrived, the new owner, the vault's name typed), versions kept on the mirror, ending a mirror or
  removing an orphaned copy, and the held changes (retry, discard, save the person's version). Deleting a mirrored
  vault now asks what happens to the copy on the other server. With linked servers off (the default) none of it shows.
- **Take over and detach a copy in the console.** A mirrored vault's page on the copy now offers **Take over as core**
  when the main server is gone (it says what happens, warns that the old server may hold changes this one never
  received, and asks for the vault's name and a confirmation that it is you; a refusal, such as the old server still
  answering, is shown in its own words), and **Detach a copy** next to Detach: a new, separate vault written from the
  copy, which stays as it is, with its progress, a cancel button and the files left out. The states a take over brings
  (the old main server replaced, both servers having taken over, the old one not back yet) read in plain words, and
  the server's own advice is shown when it has some.
