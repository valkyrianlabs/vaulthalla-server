## Linked servers and mirrored vaults

- **Starting a stopped copy over.** A copy that stopped following its core (it no longer matched, fell too far
  behind, or was stopped) is brought back with `vh mirror resync <vault>` on the server that holds it, without making
  it again: files whose bytes it already holds are not downloaded again. Nothing a person wrote there is lost:
  changes that were waiting, its own version of a file the core replaced, and anything the core does not have are
  kept as held changes for a super admin to look at, retry or discard. Both servers also check each mirrored vault
  once a day and stop it, with the reason, if its files no longer match what was recorded.
- **Moving the core by agreement.** `vh mirror switch <vault>`, asked on either server by a super admin there, swaps
  the two servers' roles. For a few moments the vault is read-only on both (writes say why), the copy catches up with
  the last change, and then the other server is the core. If anything gets in the way (changes made on the copy not
  confirmed yet, files whose contents have not arrived, the link dropping, either server stopping) the switch is
  abandoned, nothing changes, and the command says why. The server that hands the role over keeps the vault only
  through the role the new core gives it; with none the switch is refused (so its people would not lose the vault)
  unless you add `--accept-no-access`, and the command says which role it keeps. Vaults with a cloud remote can't be
  switched.
- **Taking over when the core is gone.** If a vault's core stops for good, a super admin on the mirror (or someone
  given the new admin permission "Take over as core", `admin.mirror.takeover`) makes that server the core:
  `vh mirror takeover <vault> --confirm <vault name>`. Changes made on the copy that were still waiting become
  ordinary changes there; changes the old core had refused stay listed as held changes. It warns that the old core
  may hold changes this server never received, and is refused while the old core still answers (use `vh mirror
  switch` then). It is also the way out of a switch whose other server never came back, which `vh mirror info`
  explains, and it works while the old core was deleting the vault (the copy is then kept).
- **The old core comes back.** A server that was taken over stops taking changes to the vault at once. If it made no
  changes since, it becomes the new core's mirror by itself. If it did, it keeps them and stays read-only, and
  `vh mirror info` on both servers says how many changes the new core never received; `vh mirror resync` on the old
  one brings it back, keeping those changes as held changes. If both servers took over while cut off, both stay
  read-only until you pick the one to keep. Detaching either server's copy ends a take over cleanly
  on both.
