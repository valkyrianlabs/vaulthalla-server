- Folder, symlink and snapshot ids for every vault (migrations 158_permanent_ids.sql,
  159_permanent_ids_required.sql; design/peers/mirror.md): directories.uid, symlinks.uid and recovery_snapshot.uid
  are assigned at insert for every vault type and NOT NULL; a copied folder or symlink gets its own. The deployer's
  data step backfills existing rows and never changes a uid already set; trashed files get their missing object uid
  except on opaque_v1 vaults.
  - Manifest::collect is read-only: the lazy directory, symlink and snapshot uid assignment is gone.
- Remote-account groundwork (design/peers/identity.md): home_node, home_id and remote on users and groups (a remote
  row is named by its home server's node id and its id there, unique per home server). Remote accounts never
  authorize (identities::UserState::authorizing) and are refused by every authentication path; the database refuses
  them a password hash, Linux uid, credentials, admin roles and global vault policies, and a local account never
  becomes one. users.name, users.email and groups.name are unique among local rows only.
