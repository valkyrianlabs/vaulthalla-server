# Accounts, ownership and audits across linked servers

Status: design, phase 0 of the server mirror plan (2026-11-25); nothing here is implemented. It covers how two
linked servers refer to the same person, who owns a mirrored vault, who may use and administer it, how two existing
servers become one deployment, and how audits stay effective. The link is in [`link.md`](link.md); what travels for a
vault's files is in [`mirror.md`](mirror.md).

## Decided and given

- **The owner of a mirrored vault is its owner on the core server; the other server takes part through a vault
  policy** (Cooper's direction, 2026-11-25). This needs shared users, which this document supplies.
- **A full 1:1 deployment mirror, accounts and settings included, is wanted** (Cooper, 2026-11-25). It is designed
  here and built after vault mirroring works.
- **Every change to a mirrored vault commits on its core first** (`mirror.md`). Account and access changes follow the
  same rule.
- **A mirror can detach without the core's consent** (Cooper, 2026-11-25), so the permission for it cannot live in
  anything the core governs.
- **Audits must stay effective** (Cooper, 2026-11-25).
- **Decided in this design** (Claude, 2026-11-25, under the standing instruction of 2026-11-14 to decide, build and
  log; entries in the decisions log on Cooper's Desktop; Cooper has not reviewed them and may overturn any): the two
  sharing depths, "accounts are never matched by name", and the local effect of removals. They are marked
  **(design decision)** where they appear.

## Today

- `users.id`, `groups.id`, `vault_role.id` and `admin_role.id` are per-server serials. `users.name` and `users.email`
  are unique per server (`deploy/psql/010_auth.sql`); nothing says two rows on two servers are one person.
- `vault.owner_id`, `fs_entry.created_by` and `last_modified_by`, `vault_role_assignments.subject_id` and
  `audit_event.actor_id` are those integers.
- `vault_role_assignments.subject_type` is `user` or `group` (`deploy/psql/060_acl.sql:92-101`).
- `identity_change_log` records every change to users, groups and role templates in commit order
  (`deploy/psql/108_identity_revision.sql`). Password, last-login and timestamp changes are deliberately left out.
- The audit trail is a hash chain per server (`audit_event.prev_hash`, `hash`) with chain heads signed by the
  server's attestation key and naming its node id (`audit_head`, `deploy/psql/117_audit_trail.sql`).
- Built-in principals are flagged `protected` or `system_only` (`deploy/psql/083`).

## Permanent ids

Every user, group, vault role and admin role gets `uid UUID NOT NULL UNIQUE`, assigned at creation and never
changed. Users and groups also get `home_node`: the node id of the server the account belongs to.

- Local integer ids stay as they are, as internal keys. No foreign key changes.
- Everything that crosses the link names a principal as `{uid, kind, name, home_node}`. A server resolves the uid to
  its own integer id, creating a remote account (below) when it has none.
- **Built-in principals** get fixed, well-known uids derived from their role, so they are the same on every server
  without being exchanged.
- The migration only adds columns and fills them with fresh random uids.

## Sharing depth

Each link has one depth (`peer.sharing`, `link.md`), raised from the first to the second by the join below.

| | `identities` | `full` (a deployment mirror) |
|---|---|---|
| For | Mirroring chosen vaults between servers that keep their own accounts | One Vaulthalla on two machines |
| Shared | The people, groups and roles a mirrored vault refers to | Every account, group, role, assignment, share, shared setting and credential |
| The other server's people appear as | Remote accounts | Ordinary accounts that sign in on either server |

### Remote accounts

A remote account is a row in `users` (or `groups`) with `home_node` set to the peer and `remote = true`. It exists so
that an owner, an access-list entry, "last modified by" and an audit line can name a real person.

- It **cannot sign in**: it has no password hash, no factors and no sessions, and every authentication path refuses
  it at the one place identities are loaded for authorisation.
- It **holds no admin role** and no global vault policy.
- It is **shown qualified** wherever it could be confused with a local account: "cooper (vps)". The uniqueness of
  `users.name` narrows to local accounts.
- It is **created by the stream**, never by hand: the record for a principal always arrives before the first change
  that names it.
- Raising the link to `full` fills the same rows in with credentials. There is no second kind of account.

## A mirrored vault's owner and access list

- **Owner.** One owner, the same uid on both servers: the vault's owner on its core. `vault.owner_id` on the mirror
  points at the local row for that uid, a remote account if the person cannot sign in there.
- **Access list.** `vault_role_assignments` and `vault_permission_overrides` for a mirrored vault are shared vault
  state, identical on both servers, and so are the role templates they use. A shared role is edited on the core and
  is read-only on the mirror.
- **The peer in the access list.** `vault_role_assignments.subject_type` gains `peer`. The mirror server holds a vault
  role on every vault it mirrors. That role is the ceiling on what the core accepts from it: a mirror people work on
  holds a writing role, a standby holds a reading one and can submit nothing.
- **Where an entry takes effect.** Wherever its person can sign in. An entry for a remote account does nothing on
  the server where that account is remote, and is still listed there.
- **Who decides on the mirror.** For a mirrored vault the mirror resolves permissions from the shared access list
  alone. Its own server-wide sources (admin roles, a user's global vault policy) do not apply to that vault, so a
  super admin of the mirror is not thereby an admin of a vault whose core is elsewhere. On the core, the core's
  admin roles apply as they do for any vault.
- **Who checks.** Both. The mirror checks before applying a change locally; the core checks again, for the named
  person, before committing it (`mirror.md`). A person who is a remote account on the core has exactly the rights the
  access list gives them and nothing more.

This is enforced in Vaulthalla. The mirror's operating-system administrator holds the files and the keys, and no
access list changes that.

### Changing it

A change to the owner, an access-list entry, an override or a shared role is a change like any other: it commits on
the core, and it is made by someone the access list itself allows (the owner, or a role with the manage-access
permission), from either server. Made on the mirror, it is submitted to the core and takes effect when the core
confirms it.

**Removals take effect locally at once (design decision).** Revoking a role, removing an entry, deactivating an account and
revoking a device also apply immediately on the server where they are made, with the link up or down, and are then
submitted to the core. Mechanically the server writes a local denial that its resolver consults first
(`mirror_local_denial`: subject uid, vault uid or all, who, when), and deletes it when the core's stream carries the
real removal.

- A removal can therefore never be undone by the stream.
- A grant can never appear on one server without the core having committed it.
- If the core refuses the removal (the person who made it had no right to), the local denial is lifted and the
  refusal is audited on both sides.

### The permission to leave

Detaching a mirrored vault and taking over as its core are **admin permissions on the mirror server**, outside the
shared access list: "Detach mirrored vaults" and "Take over as core" (`mirror.md`). Super admins hold both. With
`identities` sharing, the mirror's admin roles are its own. With `full` sharing, admin roles are shared, so these
two are held by super admins by definition and cannot be removed from that role: a deployment can never reach a
state in which nobody on the surviving server may act.

## Attribution

- `fs_entry.created_by` and `last_modified_by` travel as uids and are stored as the local row for that uid.
- A change submitted from the mirror names the acting person's uid. The core records that person, not the peer, as
  the one who changed the file; the peer is recorded as how the change arrived.

## Deployment mirror (`full`)

One directory, one set of settings, every vault mirrored. One server is the **core for the directory**; a vault's
core is, by default, the same server.

### What is shared

| Item | Shared | How |
|---|---|---|
| Users, groups, memberships, admin and vault roles, assignments, global vault policies | Yes | By uid, in `identity_change_log` order |
| Password hashes | Yes | As stored: self-contained Argon2id strings with no host secret in them (`core/src/crypto/util/hash.cpp:54-65`) |
| TOTP seeds | Yes | Sealed under a host secret with the local user id in the AAD (`deploy/psql/120_mfa_factors.sql`); unsealed, wrapped to the peer's wrap key, and sealed again there under its own secret and id |
| MFA recovery codes | Yes | Their hashes use a host pepper (`mfa_pepper`); the pepper is wrapped to the peer once, at the join |
| Passkeys | The credential rows, yes | Usable on a server only if both are served under the same `auth.webauthn.rp_id`. The join says so when they differ |
| Storage API keys, S3 gateway access keys | Yes | Secrets wrapped to the peer's wrap key |
| Share links | Yes | The share-token pepper is wrapped to the peer at the join, so a link resolves on either host name |
| Paired devices | Yes | The `devices` rows by owner uid. The core tells each connected device the mirror's fingerprint and endpoints over its authenticated session, and the device adds the node without pairing again |
| Shared settings | Yes | Each setting is classified `shared` or `machine` in the settings schema; only `shared` ones travel |
| Sessions, refresh tokens, the JWT secret | No | Signing in is per server |
| The server's own keys, TLS, paths, ports, host names, listener and endpoint settings | No | Machine settings |

Every secret in this table moves only inside a message sealed to the peer's wrap key (`link.md`), never as a field
of an ordinary wire message, and is sealed to the receiving machine on arrival.

### After the join

- Directory and settings changes commit on the directory's core, in order, and stream to the mirror. Made on the
  mirror, they are submitted to the core, exactly like a file change.
- Sign-in works on either server whether or not the link is up, because each holds the credentials.
- A password or factor change made on the mirror while the link is down is refused with the reason. Removals still
  apply locally, as above.
- The directory's core moves with the planned switch and the forced promotion of `mirror.md`.

### The join: making two servers one deployment

The server that stays authoritative is the base. The other joins it. The join is an **adoption**: the joining server
takes on the base's directory. It is never an automatic merge of two directories.

1. **Plan.** `vh peer join --plan` (or the console) lists every account, group, role, vault, share and shared
   setting on the joining server and what the join would do with each. It changes nothing.
2. **Resolve every local account.** For each user and group on the joining server, one of:

   | Resolution | Effect |
   |---|---|
   | *Same as* a base account | The local row takes the base account's uid. Its vaults, files, roles and history follow, because they refer to the row. The base's name, email and credentials replace the local ones |
   | *Add* | The account becomes a shared account under its own uid. Refused while its name or email collides with a base account |
   | *Remove* | The account is deactivated. Vaults it owns must be given an owner first |

3. **Accounts are never matched by name or email alone (design decision).** Two servers can each have a "cooper" who are
   different people, and matching them would hand one person the other's vaults. The join proposes a match only on
   evidence:
   - built-in principals, by their well-known uid;
   - a Desktop paired with both servers, which shows that one person controls its account on each;
   - an explicit choice by the super admin running the join.
4. **Roles** with the same name and the same permissions are offered as the same role; any other clash is renamed.
5. **Settings.** The base's shared settings replace the joining server's. The plan lists each difference.
6. **Commit.** After approval, the uids are assigned, the base's directory streams in, secrets are wrapped across,
   and the link's depth becomes `full`. Every step is resumable; a failure leaves the link at `identities` with
   nothing half-shared.
7. **Vaults.** Each vault of either server becomes a mirrored vault with its current server as its core. The join
   ends by offering to move every core to the base.

A server with only its built-in accounts and no vaults joins without questions.

## Audits

- **One ordered record per vault.** The core's trail holds every change to a mirrored vault, each naming the person
  by uid, the server they acted on, and the origin there (web, CLI, device).
- **New on every event:** `actor_uid` beside `actor_id`. For a change that arrived over the link, `origin` reads
  `peer <node> for <uid> via <origin there>`, and the details carry the originating server's event sequence number.
- **Each server sends its trail to its peer.** Events travel with the signed chain heads that exist today. The
  receiver verifies the hash chain and the head signatures against the attestation key it pinned at pairing, and
  stores them read-only as that server's trail (`peer_audit_event`). Either console shows both trails, merged by
  time or filtered by server.
- **With `identities` sharing** a server sends in full only the events about mirrored vaults, shared principals and
  the link. Every other event travels as its sequence number and hash alone, so the chain still verifies end to end
  and nothing else is disclosed. With `full` sharing every event travels in full.
- **What this adds over one server.** A server cannot rewrite or truncate its history unnoticed: its peer holds the
  chain and the signed heads.
- **What stays a matter of trust.** The core verifies that the named person is allowed to make a change. That it
  was that person who signed in on the mirror is the mirror's word.

## Invariants (each gets a test)

1. A remote account can authenticate through no path: password, passkey, token, device, share or `vh`.
2. A principal record always precedes the first stream entry that names it.
3. On the mirror, no server-wide role or policy grants access to a mirrored vault.
4. No grant takes effect on either server before the core has committed it.
5. A removal made on either server is effective there immediately and is never undone by the stream.
6. The join changes nothing before approval, and matches no account on its name or email alone.
7. No secret crosses the link outside a message sealed to the peer's wrap key.
8. A received trail whose chain or signed head does not verify is refused and reported, never stored.
9. With `full` sharing, super admins always hold "Detach mirrored vaults" and "Take over as core".

## Work items

1. Migration: `uid` and `home_node`, well-known uids, `remote`, `subject_type = 'peer'`, `mirror_local_denial`,
   `actor_uid`, `peer_audit_event`.
2. Identity loading: remote accounts refused for authentication in one place; the resolver's rule for mirrored
   vaults; local denials.
3. The principal record and its stream (`peer.identity.*`), ahead of first use.
4. Shared access lists and roles for mirrored vaults, on the submit-and-confirm path of `mirror.md`.
5. Audit: the new fields, the trail exchange with withheld events as hashes, verification, the merged view.
6. `full` sharing: the directory and credential streams, the sealed secret transfer, the settings classification.
7. The join: plan, resolutions, evidence-based proposals, the resumable commit.
8. Devices shared across a deployment, and the notice that gives a device its second node (server and Desktop).
9. Console and Desktop: remote accounts in user lists and access lists, the join, both audit trails.

Items 1 to 5 belong to phases 1 and 2 of the plan; 6 to 8 to phase 4.

## Open

- **A vault name already taken on the mirror.** `vault.name` is unique per server. Proposed: the mirror shows the
  vault as "name (vps)" and keeps the shared name for the core.
- **Linux uids and gids.** A remote account has none, so on the mirror's mounted filesystem its files appear owned
  by the vault's service owner. With `full` sharing, `linux_uid` is a machine setting per account unless both
  servers are told to share uid numbers.
