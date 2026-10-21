// ws book: storage.vault.* lifecycle (core/src/protocols/ws/handler/vault/Vaults.cpp → ops::vaults).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField vaultIdPayload() { return uinteger("id").gen(gen::ref("vault", {"id"})).desc("Vault id."); }

WsField vaultObject() { return object("vault", "Vault"); }

// The sync policy patch both storage.vault.add and storage.vault.update read (syncPatchFromPayload).
WsField vaultSyncPatch() {
    const auto budgetLimit = [](std::string name) {
        return uinteger(std::move(name)).opt().nullable().desc("A per-pass limit; null = unlimited.");
    };
    return object("sync", "",
                  {anyOf("interval", {"integer", "string"})
                       .opt()
                       .alternatives({alt({"integer"}).desc("Seconds."),
                                      alt({"string"}).desc("Interval text: \"15m\", \"1h 30m\", \"1d\".")})
                       .desc("How often the vault syncs (clamped to the minimum)."),
                   boolean("enabled").opt(),
                   str("strategy").opt().oneOf({"cache", "sync", "mirror"}).desc("S3 vaults only."),
                   str("conflict_policy")
                       .opt()
                       .oneOf({"overwrite", "keep_both", "ask", "keep_local", "keep_remote", "keep_newest"})
                       .desc("Local vaults: overwrite|keep_both|ask; S3 vaults: keep_local|keep_remote|keep_newest|ask."),
                   uinteger("max_remote_index_age_seconds").opt().nullable().desc("S3 vaults only; null clears it."),
                   object("s3_request_budget", "",
                          {budgetLimit("list_requests"), budgetLimit("head_requests"), budgetLimit("get_requests"),
                           budgetLimit("put_requests"), budgetLimit("copy_requests"), budgetLimit("delete_requests"),
                           budgetLimit("downloaded_bytes")})
                       .opt()
                       .desc("S3 vaults only; absent members are unchanged.")})
        .opt()
        .desc("Sync policy patch: absent members are unchanged (handler::Vaults syncPatchFromPayload).");
}

// storage.vault.add's provision object (ops::upstream::provisionFromJson; null members read as absent).
WsField vaultProvision() {
    return object("provision", "",
                  {str("mode").opt().nullable().oneOf({"existing", "create", "adopt"}).desc("Default existing."),
                   str("region").opt().nullable().desc("AWS region or R2 location hint; default: the key's region."),
                   boolean("generate_name").opt().nullable().desc("create: pick an available bucket name."),
                   object("lifecycle", "",
                          {uinteger("abort_incomplete_multipart_days").opt().nullable().desc("0 removes it."),
                           uinteger("expire_current_days").opt().nullable().desc("0 removes it; destructive."),
                           uinteger("expire_noncurrent_days").opt().nullable().desc("0 removes it; destructive."),
                           str("prefix").opt().nullable(),
                           boolean("clear").opt().nullable(),
                           boolean("accept_destructive").opt().nullable()})
                       .opt()
                       .nullable()
                       .desc("create/adopt: Vaulthalla's lifecycle rule."),
                   boolean("events").opt().nullable().desc("Subscribe for event-driven sync."),
                   str("events_prefix").opt().nullable(),
                   boolean("accept_adoption").opt().nullable().desc("adopt: accepts 'upstream_adoption'.")})
        .opt()
        .nullable()
        .desc("S3 vaults with an admin-enabled key (#237): create a managed bucket or adopt an existing one. Absent or "
              "mode existing binds `bucket` as before; bucket may be empty with generate_name.");
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
                    vaultProvision()},
        .response = {vaultObject()},
        .refusal_codes = opsRefusals(),
        .confirmations = {{.code = "encryption_waiver",
                           .accept_field = "accept_encryption_waiver",
                           .description = "The bucket already holds data Vaulthalla did not write (or encryption "
                                          "is being switched on over it): resend with accept_encryption_waiver once "
                                          "the person accepts."},
                          {.code = "upstream_adoption",
                           .accept_field = "provision.accept_adoption",
                           .description = "provision mode adopt (or an existing unmanaged bucket) needs consent to "
                                          "adopt the bucket: resend with provision.accept_adoption."}},
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
        .refusal_codes = opsRefusals(),
        .confirmations = {{.code = "vault_upstream_key_loss",
                           .accept_field = "accept_key_loss",
                           .description = "The vault key was never exported and its S3 data would become "
                                          "unreadable: resend with accept_key_loss once the person accepts."},
                          {.code = "vault_delete_now",
                           .accept_field = "confirm_now",
                           .description = "Deleting now skips the restore window: resend with confirm_now."}},
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
        .command = "storage.vault.accessible.list",
        .description = "Every live vault the caller reaches, by any path: as its owner, through a vault role of its "
                       "own or of one of its groups, or through its admin role (admin.vaults.<scope>.view, or the "
                       "global vault filesystem policy); a super admin reaches all of them. Each row is a vault summary "
                       "plus what the enforcing resolvers grant: browse (filesystem List at the vault root, what "
                       "fs.dir.list {path: \"/\"} needs), manage (admin vault View, what storage.vault.get needs) and "
                       "via (owner, vault_role, group_role, admin_policy, super_admin; at least one). Unlike "
                       "storage.vault.list it does not follow the admin role alone. A deactivated account gets an "
                       "empty list. Read-only; also answers paired devices (`vh vault list --accessible`).",
        .input = "none",
        .response = {objectArray("vaults", "AccessibleVault").desc("By vault id.")},
        .refusal_codes = {"denied", "unauthorized"},
        .operation = "vaults.accessible.list",
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
        .refusal_codes = opsRefusals(),
        .confirmations = {{.code = "encryption_waiver",
                           .accept_field = "accept_encryption_waiver",
                           .description = "The bucket already holds data Vaulthalla did not write (or encryption "
                                          "is being switched on over it): resend with accept_encryption_waiver once "
                                          "the person accepts."}},
        .client_timeout = 60s,
    });

    out.push_back({
        .command = "storage.vault.remove.plan",
        .description = "What deleting the vault would do (provider, bucket, key export state, the restore and key "
                       "retention windows, the key export command). Changes nothing; needs vault Remove.",
        .payload = {vaultIdPayload()},
        .response = {object("plan", "VaultRemovalPlan")},
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
