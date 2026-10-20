// ws book: storage.vault.* lifecycle (core/src/protocols/ws/handler/vault/Vaults.cpp → ops::vaults).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField vaultIdPayload() { return uinteger("id").gen(gen::ref("vault", {"id"})).desc("Vault id."); }

WsField vaultObject() { return object("vault", "Vault"); }

// What storage.vault.remove.plan answers (built inline by handler::Vaults::removalPlan).
std::vector<WsField> vaultRemovalPlanFields() {
    return {uinteger("vault_id"),
            str("name"),
            str("type").oneOf({"local", "s3"}),
            str("provider").nullable().desc("S3: the API key's provider; null for local vaults."),
            str("bucket").nullable().desc("S3: the bucket; null for local vaults."),
            boolean("encrypted_upstream").desc("S3 objects are encrypted with the vault key."),
            uinteger("key_version"),
            boolean("key_exported").desc("Whether the current key version was ever exported."),
            str("key_exported_at").nullable(),
            str("retention_window").desc("The restore window as config text (\"30d\")."),
            uinteger("retention_window_seconds"),
            str("key_retention_window"),
            uinteger("key_retention_window_seconds"),
            str("export_command").desc("The CLI command that exports the vault key.")};
}

// The sync policy patch both storage.vault.add and storage.vault.update read (syncPatchFromPayload).
WsField vaultSyncPatch() {
    return object("sync").opt().desc("Sync policy patch (absent keys unchanged): interval (seconds or text such as "
                                     "\"15m\"), enabled, strategy (S3: cache|sync|mirror), conflict_policy, "
                                     "max_remote_index_age_seconds (S3, null clears), s3_request_budget (S3: "
                                     "{list_requests, head_requests, get_requests, put_requests, copy_requests, "
                                     "delete_requests, downloaded_bytes}, each a number or null).");
}

}

std::vector<WsCommandUsage> vaultCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "storage.vault.add",
        .description = "Create a vault. owner_id, description and quota (bytes, 0 = unlimited) are optional; the "
                       "daemon picks the backing directory. S3 vaults also need api_key_id and bucket. A refusal with "
                       "data.code 'encryption_waiver' means the bucket already holds data: resend with "
                       "accept_encryption_waiver once the person accepts. With provision (#237) the daemon creates a managed "
                       "bucket or adopts an existing one; 'upstream_adoption' asks for provision.accept_adoption.",
        .payload = {str("name").gen(gen::freshName("vault_")),
                    str("type").oneOf({"local", "s3"}).gen(gen::constant("local")),
                    uinteger("owner_id").opt().nullable().gen(gen::ref("user", {"id"})),
                    str("description").opt().gen(gen::pattern("vault {a}{a}{a}{a}{a}")),
                    uinteger("quota").opt().gen(gen::constant("0")),
                    str("slug").opt(),
                    str("fuse_name").opt().nullable(),
                    uinteger("api_key_id").opt().gen(gen::ref("api_key", {"id"})).desc("S3 vaults: required."),
                    str("bucket").opt().desc("S3 vaults: required."),
                    str("storage_tier_id").opt().nullable(),
                    boolean("encrypt_upstream").opt(),
                    vaultSyncPatch(),
                    boolean("accept_encryption_waiver").opt(),
                    object("provision").opt().desc("S3 vaults with an admin-enabled key (#237): {mode: existing|create|"
                                                   "adopt, region, generate_name, lifecycle, events, events_prefix, "
                                                   "accept_adoption}. bucket may be empty with generate_name.")},
        .response = {vaultObject()},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "encryption_waiver",
                          "upstream_adoption"},
        .untyped_refusals = {"invalid"},
        .operation = "vaults.create",
        .client_timeout = 180s,
    });

    out.push_back({
        .command = "storage.vault.remove",
        .description = "Delete a vault: restorable until the retention window ends, or purged on the next pass with "
                       "`now`. Refusals with data.code 'vault_upstream_key_loss' (resend with accept_key_loss) or "
                       "'vault_delete_now' (resend with confirm_now).",
        .payload = {vaultIdPayload(),
                    boolean("now").opt(),
                    boolean("delete_upstream").opt().nullable(),
                    boolean("confirm_now").opt(),
                    boolean("accept_key_loss").opt()},
        .response = {object("deletion", "VaultDeletion").nullable()},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "vault_upstream_key_loss",
                          "vault_delete_now"},
        .operation = "vaults.delete",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.vault.get",
        .description = "One vault with its owner's name (and sync policy for S3 vaults).",
        .payload = {vaultIdPayload()},
        .response = {vaultObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.vault.list",
        .description = "Vaults visible to the caller; each row carries the owner's name.",
        .input = "none",
        .response = {objectArray("vaults", "Vault")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.vault.update",
        .description = "Patch a vault (absent or null members are unchanged; a vault's type never changes). Owner "
                       "reassignment also needs Create for the new owner, a key change needs Consume on the key, sync "
                       "settings need vault sync.config.edit. A refusal with data.code 'encryption_waiver' means the "
                       "bucket already holds data: resend with accept_encryption_waiver once the person accepts.",
        .payload = {vaultIdPayload(),
                    str("type").opt().oneOf({"local", "s3"}).desc("Must equal the vault's current type."),
                    str("name").opt().nullable(),
                    str("description").opt().nullable(),
                    uinteger("quota").opt().nullable().desc("Bytes, 0 = unlimited."),
                    uinteger("owner_id").opt().nullable().gen(gen::ref("user", {"id"})),
                    str("slug").opt().nullable(),
                    str("fuse_name").opt().nullable().desc("null or \"\" clears it."),
                    boolean("is_active").opt().nullable(),
                    uinteger("api_key_id").opt().nullable().gen(gen::ref("api_key", {"id"})).desc("S3 vaults."),
                    str("bucket").opt().nullable().desc("S3 vaults."),
                    str("storage_tier_id").opt().nullable().desc("S3 vaults; null clears it."),
                    boolean("encrypt_upstream").opt().nullable().desc("S3 vaults."),
                    vaultSyncPatch(),
                    boolean("accept_encryption_waiver").opt()},
        .response = {vaultObject()},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "encryption_waiver"},
        .untyped_refusals = {"invalid"},
        .client_timeout = 60s,
    });

    out.push_back({
        .command = "storage.vault.remove.plan",
        .description = "What deleting the vault would do (provider, bucket, key export state, the restore and key "
                       "retention windows, the key export command). Changes nothing; needs vault Remove.",
        .payload = {vaultIdPayload()},
        .response = {object("plan", "", vaultRemovalPlanFields())},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.vault.deleted.list",
        .description = "Deletions the caller could have made: pending, purging and purged tombstones, newest first.",
        .input = "none",
        .response = {objectArray("deleted", "VaultDeletion")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.vault.restore",
        .description = "Restore a vault whose deletion is still pending (conflict once its purge has started).",
        .payload = {vaultIdPayload()},
        .response = {vaultObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "storage.vault.sync",
        .description = "Run the vault's sync now, or queue a rerun when one is already running.",
        .payload = {vaultIdPayload()},
        .response = {str("status").oneOf({"started", "rerun_queued"})},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
