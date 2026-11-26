- A linked server's vault role (migration 162_peer_vault_role.sql; design/peers/identity.md "As built"): vault role
  assignments take subject_type peer (a peer row; no path overrides), peer_vault_policy holds a link's default role,
  and mirror_vault records the role a core granted this server (name, permissions, granting node, time). The effective
  role is the per-vault assignment (implicit_deny: no access), else the link's default, else none; a revoked peer holds
  nothing. rbac::resolver::PeerVault (role, may) is the API the mirror protocol will call; nothing calls it yet.
  - Mirror-side rule (rbac::mirrored, service MirrorAccessWatcher, loaded at startup before any engine serves): a
    vault whose mirror_vault role is mirror or orphaned resolves from its grant alone, for this server's super admins
    only; no local assignment, group, admin vault permission, global vault policy or ownership applies; no grant means
    no access. One atomic load on the permission path while no vault is held.
  - Commands, experimental and off by default (peers.experimental): vh peer policy show|set, ws peer.policy.get|set
    (identity.admin step-up), vh vault role assign|remove --peer and role.vault.assign|unassign subject_type peer;
    refused to agents, scoped and relayed devices (peer_forbidden). Audited peer.policy.set and
    rbac.vault_role.assign|unassign with the server's node id. roles.vault.list.assigned annotates peer subjects and,
    on a mirrored vault, lists the core's grant (subject_type server, owned_by, editable false).
