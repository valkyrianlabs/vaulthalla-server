## Linked servers (experimental, off by default)

- **What a linked server may do with a vault: its vault role.** Groundwork for mirroring a vault between two servers.
  On the server a vault belongs to, a linked server can be given a default vault role for its link
  (`vh peer policy set <server> <role>`, `vh peer policy show <server>`) and a role of its own on one vault
  (`vh vault role assign <vault> <role> --peer <server>`; `implicit_deny` means no access to that vault whatever the
  default says; `vh vault role remove ... --peer` goes back to the default). The role will be the limit on what that
  server may change in a vault it mirrors; nothing sends it to the other server or enforces it yet. Like the rest of
  linking these commands are **experimental and off by default** (`peers.experimental: true` in
  `/etc/vaulthalla/config.yaml`). Who may: whoever may assign vault roles on that vault (for the link's default, on
  every vault; super admins can), as a person on the server's `vh`, in the web console or from a fully trusted
  Vaulthalla Desktop: never an agent or a device with limited access. Every change is audited with the linked server
  named. `vh vault role list` shows a linked server's role with its name.
- **A vault held as another server's copy** (none can exist yet) is used only by this server's super admins, within
  exactly the role the other server granted: no local role, group, admin role, vault policy or ownership gives access
  to it, and its access list is shown read-only, marked as the other server's.

Requires migration 162 (additive: a `peer` subject for vault role assignments, a `peer_vault_policy` table, and the
granted role on `mirror_vault`). Existing assignments are untouched; nothing to do before or after upgrading.
