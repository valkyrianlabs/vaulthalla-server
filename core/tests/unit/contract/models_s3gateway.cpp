// Contract models: s3gateway serializers against their declared shapes (see model_suites.hpp). The shapes are
// S3GatewayJson's (protocols/ws/handler/S3GatewayJson.hpp), fed in-memory rows the way S3Gateway.cpp feeds them
// after its lookups.

#include "model_suites.hpp"

#include "db/query/s3/Gateway.hpp"
#include "identities/User.hpp"
#include "protocols/ws/handler/S3GatewayJson.hpp"
#include "rbac/fs/glob/model/Pattern.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/permission/Permission.hpp"
#include "rbac/role/Vault.hpp"
#include "vault/model/Vault.hpp"

#include <memory>
#include <string>

namespace vh::test_contract_models_s3gateway {

using json = nlohmann::json;
using GwJson = protocols::ws::handler::S3GatewayJson;

db::query::s3::GatewayCredential fullCredential() {
    db::query::s3::GatewayCredential c;
    c.id = 11;
    c.user_id = 3;
    c.created_by = 1;
    c.principal_user_id = 3;
    c.name = "backup";
    c.access_key = "VHAKEXAMPLE";
    c.enabled = true;
    c.enforce_budget_for_local_requests = true;
    c.scope_mode = "vault_allowlist";
    c.description = "nightly backup";
    c.created_at = 1'700'000'000;
    c.last_used_at = 1'700'000'100;
    c.expires_at = 1'800'000'000;
    return c;
}

db::query::s3::GatewayCredential bareCredential() {
    db::query::s3::GatewayCredential c;
    c.id = 12;
    c.user_id = 4;
    c.principal_user_id = 4;
    c.name = "plain";
    c.access_key = "VHAKPLAIN";
    c.enabled = false;
    c.scope_mode = "user_access";
    c.created_at = 1'700'000'000;
    return c;
}

std::shared_ptr<identities::User> principal() {
    identities::UserState state;
    state.name = "alice";
    state.email = "alice@example.com";
    return identities::User::detached(3, std::move(state));
}

std::shared_ptr<identities::User> principalWithoutEmail() {
    identities::UserState state;
    state.name = "bob";
    return identities::User::detached(4, std::move(state));
}

std::shared_ptr<vault::model::Vault> vaultRow(const bool withFuseName) {
    auto v = std::make_shared<vault::model::Vault>();
    v->id = 21;
    v->owner_id = 3;
    v->name = "Photos";
    v->slug = "photos";
    if (withFuseName) v->fuse_name = "photos-mount";
    return v;
}

json vaultRole() {
    rbac::role::Vault role;
    role.id = 7;
    role.name = "reader";
    role.description = "Read-only access";
    return role;
}

rbac::permission::Override overrideRule(const rbac::permission::OverrideOpt effect) {
    rbac::permission::Override o;
    o.id = 31;
    o.assignment_id = 41;
    o.permission = rbac::permission::Permission(2, "vault.filesystem.files.download", "Download files");
    o.permission.id = 9;
    o.permission.value = true;
    o.effect = effect;
    o.enabled = effect == rbac::permission::OverrideOpt::ALLOW;
    o.pattern = rbac::fs::glob::model::Pattern::make("/docs/*");
    return o;
}

}

namespace vh::test::contract_models {

void checkS3GatewayModels(Checker& c) {
    namespace t = test_contract_models_s3gateway;
    using t::GwJson;

    const auto fullCredential = GwJson::credential(t::fullCredential(), t::principal());
    c.check(fullCredential, "S3GatewayCredential", "credential with every optional member set");
    c.check(GwJson::credential(t::bareCredential(), t::principalWithoutEmail()), "S3GatewayCredential",
            "credential without description/expiry, principal without email");
    c.check(GwJson::credential(t::bareCredential(), nullptr), "S3GatewayCredential", "credential whose principal is gone");

    const auto vault = GwJson::vault(t::vaultRow(true));
    c.check(vault, "S3GatewayVaultRef", "vault with a fuse_name");
    c.check(GwJson::vault(t::vaultRow(false)), "S3GatewayVaultRef", "vault without a fuse_name");

    db::query::s3::CredentialVaultRoleAssignment assignment;
    assignment.id = 51;
    assignment.credential_id = 11;
    assignment.vault_id = 21;
    assignment.vault_role_id = 7;
    assignment.created_by = 1;
    assignment.created_at = 1'700'000'000;
    assignment.updated_at = 1'700'000'500;
    c.check(GwJson::assignment(assignment, fullCredential, vault, t::vaultRole()), "S3GatewayRoleAssignment",
            "assignment with credential, vault and role");
    assignment.created_by.reset();
    assignment.enabled = false;
    c.check(GwJson::assignment(assignment, nullptr, nullptr, nullptr), "S3GatewayRoleAssignment",
            "assignment whose credential, vault and role are gone");

    db::query::s3::CredentialDefaultVaultRole defaultRole;
    defaultRole.id = 61;
    defaultRole.credential_id = 11;
    defaultRole.vault_role_id = 7;
    defaultRole.created_by = 1;
    defaultRole.created_at = 1'700'000'000;
    defaultRole.updated_at = 1'700'000'500;
    c.check(GwJson::defaultRole(defaultRole, fullCredential, t::vaultRole()), "S3GatewayDefaultRole",
            "default role with credential and role");
    defaultRole.created_by.reset();
    c.check(GwJson::defaultRole(defaultRole, nullptr, nullptr), "S3GatewayDefaultRole",
            "default role whose credential and role are gone");

    db::query::s3::CredentialSelectedVault selected;
    selected.credential_id = 11;
    selected.vault_id = 21;
    selected.created_by = 1;
    selected.created_at = 1'700'000'000;
    selected.updated_at = 1'700'000'500;
    c.check(GwJson::selectedVault(selected, vault), "S3GatewaySelectedVault", "selected vault");
    selected.created_by.reset();
    c.check(GwJson::selectedVault(selected, nullptr), "S3GatewaySelectedVault", "selected vault that is gone");

    c.check(GwJson::roleOverride(11, fullCredential, vault, t::overrideRule(rbac::permission::OverrideOpt::ALLOW)),
            "S3GatewayRoleOverride", "per-vault allow override");
    c.check(GwJson::roleOverride(11, fullCredential, nullptr, t::overrideRule(rbac::permission::OverrideOpt::DENY)),
            "S3GatewayRoleOverride", "per-vault deny override whose vault is gone");
    c.check(GwJson::defaultRoleOverride(11, fullCredential, t::overrideRule(rbac::permission::OverrideOpt::DENY)),
            "S3GatewayDefaultRoleOverride", "default-role override");
    c.allowUnseen("S3GatewayDefaultRoleOverride.vault_id", "always null: a default-role override has no vault");
    c.allowUnseen("S3GatewayDefaultRoleOverride.vault", "always null: a default-role override has no vault");

    db::query::s3::BucketBinding bucket;
    bucket.vault_id = 21;
    bucket.bucket_name = "photos";
    bucket.api_exclusive = true;
    bucket.mode = "remote_cache";
    bucket.created_by = 1;
    bucket.created_at = 1'700'000'000;
    bucket.updated_at = 1'700'000'500;
    c.check(GwJson::bucket(bucket), "S3GatewayBucket", "bucket binding");
    bucket.created_by.reset();
    bucket.mode = "local";
    c.check(GwJson::bucket(bucket), "S3GatewayBucket", "local binding without creator");
}

}
