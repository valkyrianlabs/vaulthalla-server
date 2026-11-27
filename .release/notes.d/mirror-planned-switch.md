## Folders and linked servers

- **Mirrored vaults: moving the main server by agreement.** The two servers of a mirrored vault can now swap roles:
  `vh mirror switch <vault>`, asked on either server by a super admin there. For a few moments the vault is read-only
  on both servers (writes say why), the copy catches up with the last change, and then the other server is the one
  every change goes to first. If anything gets in the way (changes made on the copy that have not been confirmed
  yet, files whose contents have not arrived, the link dropping, either server stopping) the switch is abandoned and
  nothing changes; the command says why. Vaults with a cloud remote cannot be switched yet. Behind the experimental
  linked-servers switch; the upgrade adds one table and nothing runs on a server that mirrors nothing.
