// ws book: storage.vault.* lifecycle (core/src/protocols/ws/handler/vault/Vaults.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField vaultIdPayload() { return uinteger("id").gen(gen::ref("vault", {"id"})).desc("Vault id."); }

WsField vaultObject() { return object("vault", "Vault"); }

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
                    object("sync").opt().desc("Sync policy patch: interval, enabled, strategy, conflict_policy, "
                                              "max_remote_index_age_seconds, s3_request_budget."),
                    boolean("accept_encryption_waiver").opt(),
                    object("provision").opt().desc("S3 vaults with an admin-enabled key (#237): {mode: existing|create|"
                                                   "adopt, region, generate_name, lifecycle, events, events_prefix, "
                                                   "accept_adoption}. bucket may be empty with generate_name.")},
        .response = {vaultObject()},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "encryption_waiver",
                          "upstream_adoption"},
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

    return out;
}

}
