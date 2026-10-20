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
         uinteger("api_key_id").opt().desc("S3 vaults."),
         str("bucket").opt().desc("S3 vaults."),
         str("storage_tier_id").opt().nullable().desc("S3 vaults."),
         boolean("encrypt_upstream").opt().desc("S3 vaults: objects are encrypted with the vault key."),
         str("owner").opt().desc("The owner's name (\"\" when it no longer resolves): list and get."),
         object("sync", "RemoteSyncPolicy").opt().desc("storage.vault.get of an S3 vault.")}));

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
         vaultModelTimestamp("admin_validated_at").nullable()}));

    return out;
}

}
