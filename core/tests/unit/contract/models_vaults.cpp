// Contract models: vault serializers (Vault, AccessibleVault, RemoteSyncPolicy, VaultDeletion, VaultRemovalPlan,
// APIKey) against their declared shapes (see model_suites.hpp). DB-free: seeded in-memory instances through the real
// serializers.

#include "model_suites.hpp"

#include "ops/Vaults.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <chrono>
#include <memory>
#include <vector>

namespace vh::test_contract_models_vaults {

using json = nlohmann::json;
using vault::model::S3Vault;
using vault::model::Vault;
using vault::model::VaultType;

constexpr std::time_t kT0 = 1792483200;  // 2026-10-20T00:00:00Z

std::shared_ptr<Vault> localVault() {
    auto v = std::make_shared<Vault>();
    v->id = 3;
    v->owner_id = 7;
    v->name = "docs";
    v->description = "team documents";
    v->slug = "docs";
    v->fuse_name = "Docs";
    v->quota = 1024;
    v->type = VaultType::Local;
    v->mount_point = "docs-3";
    v->allow_fs_write = true;
    v->created_at = kT0;
    return v;
}

std::shared_ptr<S3Vault> s3Vault() {
    auto v = std::make_shared<S3Vault>("media", 5, "vh-media-bucket");
    v->id = 4;
    v->owner_id = 7;
    v->slug = "media";
    v->mount_point = "media-4";
    v->storage_tier_id = "STANDARD_IA";
    v->created_at = kT0;
    return v;
}

std::shared_ptr<sync::model::RemotePolicy> remotePolicy(const bool limited) {
    auto p = std::make_shared<sync::model::RemotePolicy>();
    p->id = 9;
    p->vault_id = 4;
    p->last_sync_at = kT0 + 60;
    p->last_success_at = kT0 + 60;
    p->created_at = kT0;
    p->updated_at = kT0 + 30;
    if (limited) {
        auto& b = p->s3_request_budget;
        b.max_list_requests = 10;
        b.max_head_requests = 20;
        b.max_get_requests = 30;
        b.max_put_requests = 40;
        b.max_copy_requests = 50;
        b.max_delete_requests = 60;
        b.max_downloaded_bytes = 1 << 20;
    } else {
        p->max_remote_index_age = std::nullopt;
    }
    return p;
}

}

namespace vh::test::contract_models {

void checkVaultModels(Checker& c) {
    using namespace test_contract_models_vaults;
    using protocols::ws::handler::Vaults;

    // Vault: the base members (add/update/restore), list rows as the dynamic type, get with owner and sync.
    const auto local = localVault();
    c.check(json(*local), "Vault", "local vault (storage.vault.add/update/restore)");
    auto noFuse = localVault();
    noFuse->fuse_name.reset();
    c.check(json(*noFuse), "Vault", "local vault without fuse_name");
    const auto s3 = s3Vault();
    for (const auto& row : json(std::vector<std::shared_ptr<Vault>>{local, s3}))
        c.check(row, "Vault", "storage.vault.list row (before the handler adds owner)");
    c.check(Vaults::detailsJson({.vault = s3, .sync = remotePolicy(true), .owner_name = "alice"}), "Vault",
            "storage.vault.get of an S3 vault with request limits");
    c.check(Vaults::detailsJson({.vault = s3, .sync = remotePolicy(false), .owner_name = "alice"}), "Vault",
            "storage.vault.get of an S3 vault, unlimited");
    c.check(Vaults::detailsJson({.vault = local, .sync = nullptr, .owner_name = ""}), "Vault",
            "storage.vault.get of a local vault");

    // AccessibleVault (ops::vaults::toJson): an owned local vault reached several ways, an S3 vault reachable only
    // for management, and a super admin's row.
    using ops::vaults::AccessVia;
    c.check(ops::vaults::toJson({.vault = local, .owner_name = "alice", .browse = true, .manage = true,
                                 .via = {AccessVia::Owner, AccessVia::VaultRole, AccessVia::GroupRole,
                                         AccessVia::AdminPolicy}}),
            "AccessibleVault", "owned local vault, every relationship");
    c.check(ops::vaults::toJson({.vault = s3, .owner_name = "", .browse = false, .manage = true,
                                 .via = {AccessVia::AdminPolicy}}),
            "AccessibleVault", "S3 vault reachable only for management, owner gone");
    c.check(ops::vaults::toJson({.vault = noFuse, .owner_name = "bob", .browse = true, .manage = true,
                                 .via = {AccessVia::SuperAdmin}}),
            "AccessibleVault", "super admin");

    // VaultDeletion: a fresh S3 deletion with every optional set, and a purged local one with none.
    vault::model::Deletion full;
    full.vault_id = 4;
    full.vault_name = "media";
    full.owner_id = 7;
    full.owner_name = "alice";
    full.vault_type = VaultType::S3;
    full.provider = "AWS";
    full.bucket = "vh-media-bucket";
    full.encrypt_upstream = true;
    full.delete_upstream = false;
    full.deleted_by = 1;
    full.deleted_at = kT0;
    full.purge_after = kT0 + 86400;
    full.key_retain_until = kT0 + 2 * 86400;
    full.key_version = 2;
    full.key_exported_at = kT0 - 60;
    full.state = vault::model::DeletionState::Purging;
    full.purge_started_at = kT0 + 86400;
    full.upstream_purged_at = kT0 + 86500;
    full.purged_at = kT0 + 86600;
    full.key_purged_at = kT0 + 2 * 86400;
    full.next_attempt_at = kT0 + 87000;
    full.attempts = 2;
    full.last_error = "upstream timeout";
    c.check(json(full), "VaultDeletion", "S3 deletion, every optional set");
    vault::model::Deletion bare;
    bare.vault_id = 3;
    bare.vault_name = "docs";
    bare.vault_type = VaultType::Local;
    bare.deleted_at = kT0;
    bare.purge_after = kT0 + 86400;
    bare.key_retain_until = kT0 + 86400;
    c.check(json(bare), "VaultDeletion", "pending local deletion, no optionals");

    // VaultRemovalPlan (Vaults::removalPlanJson): an S3 vault whose key was exported, and a local vault.
    ops::vaults::RemovalPlan plan{.vault = s3,
                                  .provider = "AWS",
                                  .bucket = "vh-media-bucket",
                                  .encrypted_upstream = true,
                                  .key_version = 2,
                                  .key_exported_at = kT0,
                                  .retention_window = std::chrono::hours(24 * 30),
                                  .key_retention_window = std::chrono::hours(24 * 90),
                                  .export_command = vault::model::keyExportCommand(4)};
    c.check(Vaults::removalPlanJson(plan), "VaultRemovalPlan", "S3 vault, key exported");
    c.check(Vaults::removalPlanJson({.vault = local,
                                     .provider = {},
                                     .bucket = {},
                                     .retention_window = std::chrono::hours(24),
                                     .key_retention_window = std::chrono::hours(24),
                                     .export_command = vault::model::keyExportCommand(3)}),
            "VaultRemovalPlan", "local vault");

    // APIKey: administration enabled (every optional set) and a plain key.
    vault::model::APIKey key;
    key.id = 5;
    key.user_id = 7;
    key.name = "aws-main";
    key.created_at = kT0;
    key.provider = vault::model::S3Provider::AWS;
    key.access_key = "AKIAEXAMPLE";
    key.region = "us-east-2";
    key.endpoint = "https://s3.us-east-2.amazonaws.com";
    key.admin_enabled = true;
    key.provider_account_id = "123456789012";
    key.admin_validated_at = kT0;
    key.provider_token = "runtime-only";
    c.check(json(key), "APIKey", "admin-enabled key");
    vault::model::APIKey plain;
    plain.id = 6;
    plain.user_id = 7;
    plain.name = "r2";
    plain.provider = vault::model::S3Provider::CloudflareR2;
    c.check(json(plain), "APIKey", "plain key");
}

}
