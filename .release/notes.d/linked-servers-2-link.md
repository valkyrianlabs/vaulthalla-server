## Linked servers and mirrored vaults

- **Linking two servers.** `vh peer pair` on one server opens a 10-minute window (one at a time, shared with device
  pairing); `vh peer link <address>` on the other dials it on its device port (36972 by default; `vh device remote
  enable` opens the listener beyond this host) and shows a six-digit code, which a super admin picks among three on
  the first server. `--fingerprint <key>` on either side refuses any other server key. Each server pins the other's
  key (no certificate authority, no trust store), either side dials, the link comes back by itself after a restart or
  a network loss, and `vh peer list` and `vh peer info <server>` show its health. `vh peer rename` names it.
- **Unlinking.** `vh peer unlink <server>` refuses the other server's key from then on and closes the link; the other
  server is told and unlinks too. Every mirror between them ends, and each server keeps the copies it holds as
  orphaned copies (read-only, see "Leaving a mirror").
- **What a linked server may do with your vaults.** A linked server is never a user: on the core, its access to a
  vault is a vault role, the default for its link (`vh peer policy set <server> <role>`, `vh peer policy show
  <server>`) or one for a single vault (`vh vault role assign <vault> <role> --peer <server>`; `implicit_deny` means
  no access to that vault whatever the default says; `vh vault role remove ... --peer` goes back to the default).
  It is sent to the mirror with the vault and every time it changes, and it is the limit on what the mirror's people
  may change there. Whoever may assign vault roles on a vault may set it (for the link's default, on every vault);
  `vh vault role list` shows a linked server's role by name.
- **Identity rotation keeps links.** `vh secret device-identity rotate` tells connected linked servers of the new key
  first (signed by the old one), and they keep their links; servers that weren't connected are unlinked and must be
  linked again. `--revoke-peers` is the emergency rotation: it tells no one and drops every link.
- **Who may.** Super admins, on the server's `vh`, in the web console (making a link asks you to confirm it's you) or
  from a fully trusted Vaulthalla Desktop connected directly. Agents, devices with limited access and connections
  through Vaulthalla Cloud can't. A linked server's key can never be paired as a device, and a device's key can never
  link. Every change is audited with the linked server named.
- **In the web console**, super admins get System › **Linked servers**: each link's health (connected since when,
  which side dialled, round trip, the other server's version), who compared the code (a person, or Vaulthalla
  Desktop when it brokered the link), rename and unlink; **Accept a link** opens the window, shows this server's key
  and addresses and approves the server whose code you pick; **Link a server** dials another by address and port,
  optionally pinned to its key, and shows the code to pick there.
