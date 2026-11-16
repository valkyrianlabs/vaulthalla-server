// ws models: vaults — the vault record, its remote sync policy, deletions, the removal plan and upstream API keys
// (core/src/vault/model, core/src/sync/model, core/src/protocols/ws/handler/vault). Checked against their
// serializers by core/tests/unit/contract/models_vaults.cpp.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField vaultModelTimestamp(std::string name) {
    return str(std::move(name)).desc("ISO-8601 UTC (\"2026-10-20T12:00:00Z\").");
}

}

std::vector<WsModel> vaultModels() {
    std::vector<WsModel> out;

    out.push_back(model("Vault",
        "A vault (vault::model::to_json(Vault), core/src/vault/model/Vault.cpp). S3 vaults add their upstream members "
        "(to_json(S3Vault)) where the vault is serialized as its dynamic type: storage.vault.list rows and "
        "storage.vault.get. storage.vault.list and storage.vault.get add `owner`; storage.vault.get adds an S3 vault's "
        "`sync` (handler::Vaults::detailsJson). storage.vault.add/update/restore send the base members only.",
        {uinteger("id"),
         str("name"),
         str("slug"),
         str("fuse_name").nullable().desc("The configured FUSE directory name; null = derived from the slug."),
         str("effective_fuse_name"),
         str("type").oneOf({"local", "s3"}),
         str("description"),
         uinteger("quota").desc("Bytes, 0 = unlimited."),
         uinteger("owner_id"),
         str("mount_point").desc("The backing directory name."),
         boolean("allow_fs_write"),
         boolean("is_active"),
         vaultModelTimestamp("created_at"),
         str("vault_uid").nullable().desc("The vault's uid (26 base32 symbols), as recovery kits and managed storage "
                                          "name it: an identifier, not a secret."),
         uinteger("api_key_id").opt().desc("S3 vaults."),
         str("bucket").opt().desc("S3 vaults."),
         str("storage_tier_id").opt().nullable().desc("S3 vaults."),
         boolean("encrypt_upstream").opt().desc("S3 vaults: objects are encrypted with the vault key."),
         str("storage_layout").opt().oneOf({"transparent", "path_v0", "opaque_v1"})
             .desc("S3 vaults, read-only: how objects sit in the bucket (design/encryption/01 §4.6). transparent: "
                   "readable names, unencrypted objects; path_v0: encrypted objects under their file paths; "
                   "opaque_v1: opaque object ids. It follows encrypt_upstream; no request sets it."),
         str("owner").opt().desc("The owner's name (\"\" when it no longer resolves): list and get."),
         str("remote").opt().desc("storage.vault.get: none (a local vault), attaching:<state> (a remote is being "
                                  "attached: vault.remote.status), attached (an S3 vault) or detaching:<state> (an "
                                  "S3 vault becoming local)."),
         object("sync", "RemoteSyncPolicy").opt().desc("storage.vault.get of an S3 vault."),
         object("manifest", "VaultManifestStatus").opt().desc("storage.vault.get of an opaque_v1 S3 vault: its "
                                                              "encrypted manifest.")}));

    out.push_back(model("VaultManifestStatus",
        "The encrypted manifest of an opaque_v1 vault (db::query::sync::ManifestApply::status): the recorded root, an "
        "apply in progress, the root's writers, entries waiting for an open file to close and the last apply of a root "
        "this server did not publish (design/sync/manifest-applier.md).",
        {uinteger("epoch").nullable().desc("The recorded root's epoch; null before the first."),
         uinteger("own_epoch").nullable().desc("The last root this server published itself."),
         uinteger("applying_epoch").nullable().desc("An apply that has not finished: nothing is published meanwhile."),
         strArray("writers").desc("The node ids the recorded root names as its writers."),
         uinteger("deferred").desc("Entries an apply deferred until their open file closes."),
         object("last_apply", "ManifestApplyReport").nullable().desc("null: no root was applied here yet."),
         objectArray("replicas", "ManifestReplica").desc("Each writer the recorded root names (a replicated vault has "
                                                         "several; experimental, design/cloud/mirrors.md)."),
         object("writers_change", "ManifestWritersChange").nullable().desc(
             "A join, leave or replica removal this server's publishes carry until a recorded root shows it."),
         boolean("behind").desc("This server has not taken in everything the bucket's head says: an apply in "
                                "progress, skipped or stopped, entries waiting for an open file, or a writers change "
                                "not published yet."),
         objectArray("cloud_only", "ManifestCloudOnly").desc(
             "Servers the linked account's replica set lists as holding the vault that the recorded root doesn't name "
             "(joining, or removed here and not yet by the account holder); empty when unlinked.")}));

    out.push_back(model("ManifestCloudOnly", "A server the linked account lists for the vault that isn't one of its writers.",
        {str("deployment_id"), str("name"), str("node_id"),
         str("unlisted_by").nullable().desc("The server that reported removing it from the manifest; null: none did.")}));

    out.push_back(model("ManifestReplica", "One writer of a vault's manifest (manifest_writer_root, migration 150).",
        {str("node_id"),
         boolean("self").desc("This server."),
         uinteger("last_epoch").nullable().desc("Its last root this server recorded; null: none since this server "
                                                "held the vault."),
         str("last_root_sha256").nullable(),
         str("last_published_at").nullable().desc("ISO-8601 UTC, as the root says."),
         str("cloud").nullable().oneOf({"listed", "unlisted", "former", "not_listed"}).desc(
             "The linked account's replica set at the last poll: listed, listed but reported removed from the manifest "
             "(unlisted), removed there (former: the next publish drops it), or not listed; null: not linked or not "
             "polled yet.")}));

    out.push_back(model("ManifestWritersChange", "remote_manifest_state.writers_change (migration 150).",
        {str("kind").oneOf({"add", "remove"}), str("node")}));

    out.push_back(model("ManifestApplyReport",
        "The last apply of another writer's root (manifest_apply_report, migration 147).",
        {uinteger("epoch"),
         str("producer").desc("The node id that published the root."),
         boolean("recorded").desc("The root became the recorded one; false: an operation was skipped (a local write "
                                  "since the collect) and the next pass applies it again."),
         boolean("union_base").desc("No usable base copy: merged without one (nothing deleted)."),
         uinteger("applied"), uinteger("skipped"), uinteger("deferred"),
         uinteger("kept").desc("Left to the planner, or kept for a local edit."),
         uinteger("conflicts_decided"), uinteger("conflicts_open"),
         strArray("notes"),
         str("at").desc("ISO-8601 UTC."),
         str("stopped").nullable().desc("The reason the last apply stopped at its root (the pass stalls; alerted once): "
                                        "manifest_key_missing, manifest_key_mismatch, manifest_head_incomplete, "
                                        "manifest_mirror_shared, manifest_writer_floor (the root was written by a "
                                        "newer Vaulthalla: upgrade this server; a refused publish records it too); "
                                        "null when it did not stop.")}));

    out.push_back(model("AccessibleVault",
        "A vault the caller reaches (ops::vaults::toJson(AccessibleVault), core/src/ops/Vaults.cpp): a summary of the "
        "vault (no backing directory or upstream details; storage.vault.get has them, behind manage) and what the "
        "resolvers that enforce access grant at its root. storage.vault.accessible.list rows, `vh vault list "
        "--accessible --json`.",
        {uinteger("id"),
         str("name"),
         str("slug"),
         str("effective_fuse_name").desc("The vault's directory under the FUSE mount."),
         str("type").oneOf({"local", "s3"}),
         str("description"),
         uinteger("quota").desc("Bytes, 0 = unlimited."),
         uinteger("owner_id").desc("0 when the owner account was deleted."),
         str("owner").desc("The owner's name; \"\" when it no longer resolves."),
         boolean("is_active"),
         vaultModelTimestamp("created_at"),
         boolean("browse").desc("Filesystem List at the vault root (rbac::resolver::Vault, FilesystemAction::List on "
                                "the root's FUSE path): the file browser can open it."),
         boolean("manage").desc("Admin vault View (rbac::resolver::Admin, admin.vaults.<scope>.view): its settings "
                                "and storage.vault.get."),
         strArray("via", {"owner", "vault_role", "group_role", "admin_policy", "super_admin"})
             .desc("Every path by which the caller reaches the vault, in this order; never empty. admin_policy: the "
                   "admin role's vault permissions grant manage, or its global vault filesystem policy grants browse "
                   "where no vault role applies."),
         str("vault_uid").nullable().desc("The vault's uid (26 base32 symbols): an identifier, not a secret.")}));

    out.push_back(model("RemoteSyncPolicy",
        "An S3 vault's sync policy (sync::model::to_json(RemotePolicy), core/src/sync/model/RemotePolicy.cpp, over "
        "to_json(Policy) in Policy.cpp).",
        {uinteger("id"),
         uinteger("vault_id"),
         str("interval").desc("Sync interval as text (\"5m 0s\", \"1d 0h 0m 0s\")."),
         boolean("enabled"),
         vaultModelTimestamp("last_sync_at"),
         vaultModelTimestamp("last_success_at"),
         vaultModelTimestamp("created_at"),
         vaultModelTimestamp("updated_at"),
         str("strategy").oneOf({"cache", "sync", "mirror"}),
         str("conflict_policy").oneOf({"keep_local", "keep_remote", "keep_newest", "ask"}),
         object("s3_request_budget", "",
                {uinteger("list_requests").nullable(), uinteger("head_requests").nullable(),
                 uinteger("get_requests").nullable(), uinteger("put_requests").nullable(),
                 uinteger("copy_requests").nullable(), uinteger("delete_requests").nullable(),
                 uinteger("downloaded_bytes").nullable()})
             .desc("Per-pass S3 request limits; null = unlimited."),
         uinteger("max_remote_index_age_seconds").nullable()}));

    out.push_back(model("VaultDeletion",
        "A scheduled, running or finished vault deletion (vault::model::to_json(Deletion), "
        "core/src/vault/model/Deletion.cpp).",
        {uinteger("vault_id"),
         str("vault_name"),
         uinteger("owner_id").nullable(),
         str("owner"),
         str("type").oneOf({"local", "s3"}),
         str("provider").nullable(),
         str("bucket").nullable(),
         boolean("encrypt_upstream").nullable(),
         boolean("delete_upstream"),
         uinteger("deleted_by").nullable(),
         vaultModelTimestamp("deleted_at"),
         vaultModelTimestamp("purge_after"),
         vaultModelTimestamp("key_retain_until"),
         uinteger("key_version").nullable(),
         vaultModelTimestamp("key_exported_at").nullable(),
         boolean("key_retained"),
         boolean("upstream_key_at_risk").desc("Encrypted upstream data whose key was never exported and is kept."),
         str("export_command"),
         str("state").oneOf({"pending", "purging", "purged"}),
         boolean("restorable"),
         vaultModelTimestamp("purge_started_at").nullable(),
         vaultModelTimestamp("upstream_purged_at").nullable(),
         vaultModelTimestamp("purged_at").nullable(),
         vaultModelTimestamp("key_purged_at").nullable(),
         vaultModelTimestamp("next_attempt_at").nullable(),
         uinteger("attempts"),
         str("last_error").nullable()}));

    out.push_back(model("VaultRemovalPlan",
        "What deleting a vault would do (protocols::ws::handler::Vaults::removalPlanJson over "
        "ops::vaults::RemovalPlan).",
        {uinteger("vault_id"),
         str("name"),
         str("type").oneOf({"local", "s3"}),
         str("provider").nullable().desc("S3: the API key's provider; null for local vaults."),
         str("bucket").nullable().desc("S3: the bucket; null for local vaults."),
         boolean("encrypted_upstream").desc("S3 objects are encrypted with the vault key."),
         uinteger("key_version"),
         boolean("key_exported").desc("Whether the current key version was ever exported."),
         vaultModelTimestamp("key_exported_at").nullable(),
         str("retention_window").desc("The restore window as config text (\"30d\")."),
         integer("retention_window_seconds"),
         str("key_retention_window"),
         integer("key_retention_window_seconds"),
         str("export_command").desc("The CLI command that exports the vault key.")}));

    out.push_back(model("APIKey",
        "An upstream S3 API key's metadata; the secret is never sent (vault::model::to_json(APIKey), "
        "core/src/vault/model/APIKey.cpp).",
        {uinteger("api_key_id"),
         uinteger("user_id"),
         str("name"),
         vaultModelTimestamp("created_at"),
         str("provider").oneOf({"AWS", "Cloudflare R2", "Wasabi", "Backblaze B2", "DigitalOcean", "MinIO", "Ceph",
                                "Storj", "Other"}),
         str("access_key"),
         str("region"),
         str("endpoint"),
         boolean("admin_enabled").desc("Provider administration (#237) is on."),
         str("provider_account_id").nullable(),
         boolean("has_provider_token"),
         vaultModelTimestamp("admin_validated_at").nullable(),
         str("origin").oneOf({"customer", "cloud"})
             .desc("Who issued the key: a person (customer) or managed storage for a vault's bucket (cloud)."),
         boolean("editable").desc("False for a key managed storage issued: shown, never changed by people (its "
                                  "update and removal are refused).")}));

    return out;
}

}
