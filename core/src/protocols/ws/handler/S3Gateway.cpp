#include "protocols/ws/handler/S3Gateway.hpp"

#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/S3Gateway.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/role/Vault.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <ctime>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>

// ws s3.gateway.*: payload parsing and JSON shaping only. Who may do what, and what it changes, is
// ops::s3_gateway, shared with `vh s3-gateway`.
namespace vh::protocols::ws::handler {
namespace {

namespace gw = ::vh::ops::s3_gateway;

const std::shared_ptr<identities::User>& gwActor(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw std::runtime_error("User not authenticated");
    return session->user;
}

std::optional<std::string> optionalString(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    const auto value = payload.at(key).get<std::string>();
    return value.empty() ? std::optional<std::string>{} : std::make_optional(value);
}

std::optional<std::uint32_t> optionalUInt(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    return payload.at(key).get<std::uint32_t>();
}

std::uint32_t gwLimitFromPayload(const json& payload, const std::uint32_t fallback = 50) {
    if (!payload.is_object()) return fallback;
    return std::clamp<std::uint32_t>(payload.value("limit", fallback), 1, 500);
}

// ------------------------------------------------------------------------------------------------- JSON

json credentialJson(const db::query::s3::GatewayCredential& credential) {
    json principalJson = nullptr;
    if (const auto principal = vh::identities::manager().user(credential.principal_user_id)) {
        principalJson = {
            {"id", principal->id},
            {"name", principal->name()},
            {"email", principal->email() ? json(*principal->email()) : json(nullptr)}
        };
    }

    return {
        {"id", credential.id},
        {"user_id", credential.user_id},
        {"principal_user_id", credential.principal_user_id},
        {"principal_user", principalJson},
        {"created_by", credential.created_by ? json(*credential.created_by) : json(nullptr)},
        {"name", credential.name},
        {"access_key", credential.access_key},
        {"enabled", credential.enabled},
        {"scope_mode", credential.scope_mode},
        {"enforce_budget_for_local_requests", credential.enforce_budget_for_local_requests},
        {"description", credential.description ? json(*credential.description) : json(nullptr)},
        {"created_at", credential.created_at},
        {"last_used_at", credential.last_used_at ? json(*credential.last_used_at) : json(nullptr)},
        {"expires_at", credential.expires_at ? json(*credential.expires_at) : json(nullptr)}
    };
}

json vaultJson(const std::shared_ptr<::vh::vault::model::Vault>& vault) {
    if (!vault) return nullptr;
    return {
        {"id", vault->id},
        {"name", vault->name},
        {"slug", vault->slug},
        {"fuse_name", vault->fuse_name ? json(*vault->fuse_name) : json(nullptr)},
        {"effective_fuse_name", vault->effectiveFuseName()},
        {"owner_id", vault->owner_id}
    };
}

json vaultJson(const std::uint32_t vaultId) { return vaultJson(db::query::vault::Vault::getVault(vaultId)); }

json roleJson(const std::shared_ptr<::vh::rbac::role::Vault>& role) {
    if (!role) return nullptr;
    json out = *role;
    return out;
}

json credentialJsonById(const std::uint32_t credentialId) {
    for (const auto& item : db::query::s3::Gateway::listCredentialsAdmin(true))
        if (item.id == credentialId) return credentialJson(item);
    return nullptr;
}

json assignmentJson(const db::query::s3::CredentialVaultRoleAssignment& assignment) {
    return {
        {"id", assignment.id},
        {"assignment_id", assignment.id},
        {"credential_id", assignment.credential_id},
        {"credential", credentialJsonById(assignment.credential_id)},
        {"vault_id", assignment.vault_id},
        {"vault", vaultJson(assignment.vault_id)},
        {"vault_role_id", assignment.vault_role_id},
        {"role", roleJson(db::query::rbac::role::Vault::get(assignment.vault_role_id))},
        {"enabled", assignment.enabled},
        {"created_by", assignment.created_by ? json(*assignment.created_by) : json(nullptr)},
        {"created_at", assignment.created_at},
        {"updated_at", assignment.updated_at}
    };
}

json defaultRoleJson(const db::query::s3::CredentialDefaultVaultRole& defaultRole) {
    return {
        {"id", defaultRole.id},
        {"default_role_id", defaultRole.id},
        {"credential_id", defaultRole.credential_id},
        {"credential", credentialJsonById(defaultRole.credential_id)},
        {"vault_role_id", defaultRole.vault_role_id},
        {"role", roleJson(db::query::rbac::role::Vault::get(defaultRole.vault_role_id))},
        {"enabled", defaultRole.enabled},
        {"created_by", defaultRole.created_by ? json(*defaultRole.created_by) : json(nullptr)},
        {"created_at", defaultRole.created_at},
        {"updated_at", defaultRole.updated_at}
    };
}

json optionalDefaultRoleJson(const std::optional<db::query::s3::CredentialDefaultVaultRole>& defaultRole) {
    return defaultRole ? defaultRoleJson(*defaultRole) : json(nullptr);
}

json selectedVaultJson(const db::query::s3::CredentialSelectedVault& selectedVault) {
    return {
        {"credential_id", selectedVault.credential_id},
        {"vault_id", selectedVault.vault_id},
        {"vault", vaultJson(selectedVault.vault_id)},
        {"enabled", selectedVault.enabled},
        {"created_by", selectedVault.created_by ? json(*selectedVault.created_by) : json(nullptr)},
        {"created_at", selectedVault.created_at},
        {"updated_at", selectedVault.updated_at}
    };
}

json selectedVaultsJson(const std::vector<db::query::s3::CredentialSelectedVault>& selectedVaults) {
    json rows = json::array();
    for (const auto& selectedVault : selectedVaults) rows.push_back(selectedVaultJson(selectedVault));
    return rows;
}

json overrideJson(
    const db::query::s3::GatewayCredential& credential,
    const json& vault,
    const ::vh::rbac::permission::Override& overrideRule) {
    return {
        {"id", overrideRule.id},
        {"override_id", overrideRule.id},
        {"assignment_id", overrideRule.assignment_id},
        {"credential_id", credential.id},
        {"credential", credentialJson(credential)},
        {"vault_id", vault.is_object() ? vault.at("id") : json(nullptr)},
        {"vault", vault},
        {"permission_id", overrideRule.permission.id},
        {"permission_name", overrideRule.permission.qualified_name},
        {"permission_qualified", overrideRule.permission.qualified_name},
        {"permission", overrideRule.permission},
        {"glob_path", overrideRule.glob_path()},
        {"effect", ::vh::rbac::permission::to_string(overrideRule.effect)},
        {"enabled", overrideRule.enabled}
    };
}

json defaultOverrideJson(
    const db::query::s3::GatewayCredential& credential,
    const ::vh::rbac::permission::Override& overrideRule) {
    auto out = overrideJson(credential, nullptr, overrideRule);
    out["default_role_id"] = overrideRule.assignment_id;
    out["gateway_credential_default_role_id"] = overrideRule.assignment_id;
    return out;
}

json bucketJson(const db::query::s3::BucketBinding& bucket) {
    return {
        {"bucket_name", bucket.bucket_name},
        {"bucket", bucket.bucket_name},
        {"vault_id", bucket.vault_id},
        {"mode", bucket.mode},
        {"api_exclusive", bucket.api_exclusive},
        {"created_by", bucket.created_by ? json(*bucket.created_by) : json(nullptr)},
        {"created_at", bucket.created_at},
        {"updated_at", bucket.updated_at}
    };
}

// ------------------------------------------------------------------------------------------------- payload

// s3.gateway.* never reads a bare `id`: it used to mean a credential, a role override or a permission depending
// on the command (#165). A payload that carries one is refused (ops::Invalid, ws code "invalid") naming the
// explicit field(s) the command takes, instead of being guessed at.
constexpr const char* kCredentialField = "'credential_id' (or access_key / name)";
constexpr const char* kCredentialAndPermissionFields =
    "'credential_id' (or access_key / name) for the credential and 'permission_id' "
    "(or permission_qualified / permission_name) for the permission";
constexpr const char* kCredentialAndOverrideFields =
    "'credential_id' (or access_key / name) for the credential and 'override_id' for the override";

void refuseBareId(const json& payload, const char* expected) {
    if (payload.is_object() && payload.contains("id"))
        throw ::vh::ops::Invalid(std::string("bare 'id' is not accepted by S3 gateway commands; send ") + expected);
}

// The credential a payload names: credential_id, then an access key or name.
gw::Ref credentialRefFromPayload(const json& payload) {
    if (const auto id = optionalUInt(payload, "credential_id")) return *id;
    for (const auto* key : {"access_key", "credential_access_key", "name", "credential_name", "credential"})
        if (const auto value = optionalString(payload, key)) return *value;
    throw ::vh::ops::Invalid("credential_id, access_key or name is required");
}

gw::Credential credentialFromPayload(const std::shared_ptr<Session>& session, const json& payload) {
    return gw::getCredential(gwActor(session), credentialRefFromPayload(payload));
}

// vault_id, or a vault name (under owner_id when given; never "the first vault with that name").
std::uint32_t vaultIdFromPayload(const std::shared_ptr<Session>& session, const json& payload) {
    if (const auto id = optionalUInt(payload, "vault_id")) return *id;
    auto name = optionalString(payload, "vault_name");
    if (!name) name = optionalString(payload, "vault");
    if (!name) throw std::runtime_error("vault_id or vault_name is required");
    return gw::vaultIdByName(gwActor(session), *name, optionalUInt(payload, "owner_id"));
}

std::uint32_t vaultRoleIdFromPayload(const json& payload) {
    auto roleId = optionalUInt(payload, "vault_role_id");
    if (!roleId) roleId = optionalUInt(payload, "role_id");
    if (roleId) return *roleId;
    auto roleName = optionalString(payload, "vault_role_name");
    if (!roleName) roleName = optionalString(payload, "role_name");
    if (!roleName) roleName = optionalString(payload, "role");
    if (!roleName) throw std::runtime_error("vault_role_id or vault_role_name is required");
    const auto role = db::query::rbac::role::Vault::get(*roleName);
    if (!role) throw std::runtime_error("vault role not found");
    return role->id;
}

std::optional<std::uint32_t> defaultVaultRoleIdFromPayload(const json& payload) {
    if (const auto id = optionalUInt(payload, "default_vault_role_id")) return id;
    if (const auto id = optionalUInt(payload, "default_role_id")) return id;
    if (payload.contains("vault_role_id") || payload.contains("role_id") ||
        payload.contains("vault_role_name") || payload.contains("role_name") || payload.contains("role"))
        return vaultRoleIdFromPayload(payload);
    return std::nullopt;
}

std::vector<gw::VaultAccess> accessFromPayload(const json& payload) {
    std::vector<gw::VaultAccess> out;
    if (!payload.contains("vault_scopes") || !payload.at("vault_scopes").is_array()) return out;
    for (const auto& item : payload.at("vault_scopes"))
        out.push_back({
            .vault_id = item.at("vault_id").get<std::uint32_t>(),
            .list = item.value("can_list", true),
            .read = item.value("can_read", true),
            .write = item.value("can_write", false),
            .del = item.value("can_delete", false),
            .admin = item.value("can_admin", false)
        });
    return out;
}

bool hasSelectedVaultIds(const json& payload) {
    return payload.contains("selected_vault_ids") || payload.contains("vault_ids");
}

std::vector<std::uint32_t> selectedVaultIdsFromPayload(const json& payload) {
    std::vector<std::uint32_t> vaultIds;
    const json* source = nullptr;
    if (payload.contains("selected_vault_ids") && payload.at("selected_vault_ids").is_array())
        source = &payload.at("selected_vault_ids");
    else if (payload.contains("vault_ids") && payload.at("vault_ids").is_array())
        source = &payload.at("vault_ids");
    if (!source) return vaultIds;

    for (const auto& item : *source) {
        if (item.is_number_unsigned()) vaultIds.push_back(item.get<std::uint32_t>());
        else if (item.is_object() && item.contains("vault_id")) vaultIds.push_back(item.at("vault_id").get<std::uint32_t>());
        else if (item.is_object() && item.contains("id")) vaultIds.push_back(item.at("id").get<std::uint32_t>());
    }
    return vaultIds;
}

std::optional<std::time_t> expiresFromPayload(const json& payload) {
    if (const auto raw = optionalUInt(payload, "expires_at")) return static_cast<std::time_t>(*raw);
    return std::nullopt;
}

gw::OverrideSpec overrideSpecFromPayload(const json& payload) {
    gw::OverrideSpec spec;
    if (const auto id = optionalUInt(payload, "permission_id")) spec.permission = std::to_string(*id);
    else
        for (const auto* key : {"permission_qualified", "permission_name", "permission"})
            if (const auto value = optionalString(payload, key)) {
                spec.permission = *value;
                break;
            }
    spec.effect = optionalString(payload, "effect").value_or("");
    spec.pattern = optionalString(payload, "glob_path").value_or(optionalString(payload, "path").value_or(""));
    spec.enabled = payload.value("enabled", true);
    return spec;
}

std::uint32_t overrideIdFromPayload(const json& payload) {
    if (const auto id = optionalUInt(payload, "override_id")) return *id;
    throw ::vh::ops::Invalid("override_id is required");
}

gw::BudgetScope budgetScopeFromPayload(const json& payload) {
    const auto scope = payload.at("scope").get<std::string>();
    if (scope == "gateway_credential") return gw::BudgetScope::Key;
    if (scope == "gateway_credential_vault") return gw::BudgetScope::KeyVault;
    throw std::runtime_error("S3 gateway budget endpoints only manage gateway credential budget policies.");
}

gw::BudgetSpec budgetSpecFromPayload(const json& payload) {
    const auto credentialId = optionalUInt(payload, "gateway_credential_id");
    if (!credentialId) throw std::runtime_error("gateway_credential_id is required");
    gw::BudgetSpec spec{
        .scope = budgetScopeFromPayload(payload),
        .credential_id = *credentialId,
        .vault_id = optionalUInt(payload, "vault_id"),
        .mode = optionalString(payload, "mode"),
        .currency = optionalString(payload, "currency"),
        .max_run_cost = optionalString(payload, "max_run_cost"),
        .max_daily_cost = optionalString(payload, "max_daily_cost"),
        .max_monthly_cost = optionalString(payload, "max_monthly_cost")
    };
    if (payload.contains("require_verified_catalog")) spec.require_verified_catalog = payload.at("require_verified_catalog").get<bool>();
    if (payload.contains("allow_stale_catalog")) spec.allow_stale_catalog = payload.at("allow_stale_catalog").get<bool>();
    if (const auto maxAge = optionalUInt(payload, "max_catalog_age_seconds")) spec.max_catalog_age_seconds = *maxAge;
    return spec;
}

gw::BudgetFilter budgetFilterFromPayload(const json& payload) {
    return {
        .credential_id = optionalUInt(payload, "gateway_credential_id"),
        .vault_id = optionalUInt(payload, "vault_id"),
        .include_inactive = payload.is_object() ? payload.value("include_inactive", true) : true
    };
}

} // namespace

json S3Gateway::status(const json&, const std::shared_ptr<Session>& session) {
    const auto status = gw::status(gwActor(session));
    return {{"status", {
        {"running", status.running},
        {"configured", status.configured},
        {"ready", status.ready},
        {"host", status.host},
        {"port", status.port},
        {"endpoint", status.host + ":" + std::to_string(status.port)},
        {"active_sessions", status.activeSessions},
        {"total_requests", status.totalRequests},
        {"failed_requests", status.failedRequests}
    }}};
}

json S3Gateway::credentialsCreate(const json& payload, const std::shared_ptr<Session>& session) {
    auto principalId = optionalUInt(payload, "principal_user_id");
    if (const auto userId = optionalUInt(payload, "user_id")) principalId = userId;
    auto scopeMode = optionalString(payload, "scope_mode");
    if (!scopeMode) scopeMode = optionalString(payload, "scope");
    const auto created = gw::createCredential(gwActor(session), {
        .name = payload.at("name").get<std::string>(),
        .principal_id = principalId,
        .scope_mode = scopeMode,
        .description = optionalString(payload, "description"),
        .expires_at = expiresFromPayload(payload),
        .default_role_id = defaultVaultRoleIdFromPayload(payload),
        .selected_vault_ids = selectedVaultIdsFromPayload(payload),
        .vault_access = accessFromPayload(payload),
        .enforce_budget_for_local_requests = payload.value("enforce_budget_for_local_requests", false)
    });
    return {
        {"credential", credentialJson(created.credential)},
        {"secret_access_key", created.secret_access_key}
    };
}

json S3Gateway::credentialsList(const json& payload, const std::shared_ptr<Session>& session) {
    const auto includeDisabled = payload.is_object() ? payload.value("include_disabled", true) : true;
    json rows = json::array();
    for (const auto& credential : gw::listCredentials(gwActor(session), std::nullopt, includeDisabled))
        rows.push_back(credentialJson(credential));
    return {{"credentials", rows}};
}

json S3Gateway::credentialsRevoke(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, "'access_key' or 'name'");
    const auto value = payload.value("access_key", payload.value("name", std::string{}));
    if (value.empty()) throw ::vh::ops::Invalid("access_key or name is required");
    (void)gw::revokeCredential(gwActor(session), gw::Ref{value});
    return {{"revoked", true}};
}

json S3Gateway::credentialsScopeUpdate(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    gw::ScopeUpdate req;
    req.scope_mode = optionalString(payload, "scope_mode");
    req.principal_id = optionalUInt(payload, "principal_user_id");
    if (payload.contains("description")) req.description = optionalString(payload, "description");
    if (payload.contains("expires_at")) req.expires_at = expiresFromPayload(payload);
    if (payload.contains("enforce_budget_for_local_requests"))
        req.enforce_budget_for_local_requests = payload.at("enforce_budget_for_local_requests").get<bool>();
    if (payload.contains("vault_scopes")) req.vault_access = accessFromPayload(payload);
    if (hasSelectedVaultIds(payload)) req.selected_vault_ids = selectedVaultIdsFromPayload(payload);
    req.default_role_id = defaultVaultRoleIdFromPayload(payload);
    return {{"credential", credentialJson(gw::updateScope(gwActor(session), credentialRefFromPayload(payload), req))}};
}

json S3Gateway::credentialsDefaultRoleGet(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    return {
        {"credential", credentialJson(credential)},
        {"default_role", optionalDefaultRoleJson(gw::getDefaultRole(gwActor(session), credential.id))}
    };
}

json S3Gateway::credentialsDefaultRoleSet(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto saved = gw::setDefaultRole(gwActor(session), credential.id, vaultRoleIdFromPayload(payload),
                                          payload.value("enabled", true));
    return {{"credential", credentialJson(credential)}, {"default_role", defaultRoleJson(saved)}};
}

json S3Gateway::credentialsDefaultRoleClear(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    return {
        {"cleared", gw::clearDefaultRole(gwActor(session), credential.id)},
        {"credential", credentialJson(credential)}
    };
}

json S3Gateway::credentialsSelectedVaultsList(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto rows = selectedVaultsJson(gw::listSelectedVaults(gwActor(session), credential.id));
    return {{"credential", credentialJson(credential)}, {"selected_vaults", rows}, {"vaults", rows}};
}

json S3Gateway::credentialsSelectedVaultsReplace(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto rows = selectedVaultsJson(
        gw::replaceSelectedVaults(gwActor(session), credential.id, selectedVaultIdsFromPayload(payload)));
    return {{"credential", credentialJson(credential)}, {"selected_vaults", rows}, {"vaults", rows}};
}

json S3Gateway::credentialsSelectedVaultsAdd(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto selected = gw::addSelectedVault(gwActor(session), credential.id, vaultIdFromPayload(session, payload),
                                               payload.value("enabled", true));
    return {{"credential", credentialJson(credential)}, {"selected_vault", selectedVaultJson(selected)}};
}

json S3Gateway::credentialsSelectedVaultsRemove(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto vaultId = vaultIdFromPayload(session, payload);
    gw::removeVault(gwActor(session), credential.id, vaultId);
    return {{"removed", true}, {"credential", credentialJson(credential)}, {"vault", vaultJson(vaultId)}};
}

json S3Gateway::credentialsDefaultRoleOverridesList(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    json rows = json::array();
    for (const auto& overrideRule : gw::listDefaultRoleOverrides(gwActor(session), credential.id))
        rows.push_back(defaultOverrideJson(credential, overrideRule));
    return {
        {"credential", credentialJson(credential)},
        {"default_role", optionalDefaultRoleJson(db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id))},
        {"overrides", rows}
    };
}

json S3Gateway::credentialsDefaultRoleOverridesAdd(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialAndPermissionFields);
    const auto credential = credentialFromPayload(session, payload);
    const auto saved = gw::addDefaultRoleOverride(gwActor(session), credential.id, overrideSpecFromPayload(payload));
    return {{"override", defaultOverrideJson(credential, saved)}};
}

json S3Gateway::credentialsDefaultRoleOverridesRemove(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialAndOverrideFields);
    const auto credential = credentialFromPayload(session, payload);
    gw::removeDefaultRoleOverride(gwActor(session), credential.id, overrideIdFromPayload(payload));
    return {{"removed", true}, {"credential", credentialJson(credential)}};
}

json S3Gateway::credentialsRolesList(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    json rows = json::array();
    for (const auto& assignment : gw::listRoleAssignments(gwActor(session), credential.id))
        rows.push_back(assignmentJson(assignment));
    return {{"credential", credentialJson(credential)}, {"roles", rows}, {"assignments", rows}};
}

json S3Gateway::credentialsRolesAssign(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto assignment = gw::assignRole(gwActor(session), credential.id, vaultIdFromPayload(session, payload),
                                           vaultRoleIdFromPayload(payload), payload.value("enabled", true));
    const auto out = assignmentJson(assignment);
    return {{"assignment", out}, {"role", out}};
}

json S3Gateway::credentialsRolesRevoke(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto vaultId = vaultIdFromPayload(session, payload);
    gw::revokeRole(gwActor(session), credential.id, vaultId);
    return {{"revoked", true}, {"credential", credentialJson(credential)}, {"vault", vaultJson(vaultId)}};
}

json S3Gateway::credentialsRoleOverridesList(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialField);
    const auto credential = credentialFromPayload(session, payload);
    const auto vaultId = vaultIdFromPayload(session, payload);
    const auto vault = vaultJson(vaultId);
    json rows = json::array();
    for (const auto& overrideRule : gw::listRoleOverrides(gwActor(session), credential.id, vaultId))
        rows.push_back(overrideJson(credential, vault, overrideRule));
    return {{"credential", credentialJson(credential)}, {"vault", vault}, {"overrides", rows}};
}

json S3Gateway::credentialsRoleOverridesAdd(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialAndPermissionFields);
    const auto credential = credentialFromPayload(session, payload);
    const auto vaultId = vaultIdFromPayload(session, payload);
    const auto saved = gw::addRoleOverride(gwActor(session), credential.id, vaultId, overrideSpecFromPayload(payload));
    return {{"override", overrideJson(credential, vaultJson(vaultId), saved)}};
}

json S3Gateway::credentialsRoleOverridesRemove(const json& payload, const std::shared_ptr<Session>& session) {
    refuseBareId(payload, kCredentialAndOverrideFields);
    const auto credential = credentialFromPayload(session, payload);
    const auto vaultId = vaultIdFromPayload(session, payload);
    gw::removeRoleOverride(gwActor(session), credential.id, vaultId, overrideIdFromPayload(payload));
    return {{"removed", true}, {"credential", credentialJson(credential)}, {"vault", vaultJson(vaultId)}};
}

json S3Gateway::bucketsList(const json&, const std::shared_ptr<Session>& session) {
    json rows = json::array();
    for (const auto& bucket : gw::listBuckets(gwActor(session))) rows.push_back(bucketJson(bucket));
    return {{"buckets", rows}};
}

json S3Gateway::bucketsBind(const json& payload, const std::shared_ptr<Session>& session) {
    (void)gw::bindBucket(gwActor(session), {
        .vault_id = vaultIdFromPayload(session, payload),
        .bucket_name = optionalString(payload, "bucket_name"),
        .mode = optionalString(payload, "mode"),
        .api_exclusive = payload.value("api_exclusive", false)
    });
    return {{"bound", true}};
}

json S3Gateway::bucketsUnbind(const json& payload, const std::shared_ptr<Session>& session) {
    gw::unbindBucket(gwActor(session), payload.at("bucket_name").get<std::string>());
    return {{"unbound", true}};
}

json S3Gateway::bucketsCreateLocal(const json& payload, const std::shared_ptr<Session>& session) {
    const auto bucket = gw::createLocalBucket(gwActor(session), {
        .bucket_name = optionalString(payload, "bucket_name"),
        .owner_id = optionalUInt(payload, "owner_id"),
        .quota = payload.value("quota_bytes", static_cast<uintmax_t>(0)),
        .name = optionalString(payload, "name"),
        .description = optionalString(payload, "description")
    });
    return {{"bucket", bucketJson(bucket)}};
}

json S3Gateway::bucketsCreateRemoteCache(const json& payload, const std::shared_ptr<Session>& session) {
    std::shared_ptr<::vh::vault::model::APIKey> apiKey;
    if (const auto id = optionalUInt(payload, "api_key_id")) apiKey = db::query::vault::APIKey::getAPIKey(*id);
    else if (const auto name = optionalString(payload, "api_key")) apiKey = db::query::vault::APIKey::getAPIKey(*name);
    if (!apiKey) throw std::runtime_error("Upstream API key not found.");
    const auto bucket = gw::createRemoteCacheBucket(gwActor(session), {
        .bucket_name = optionalString(payload, "bucket_name"),
        .owner_id = optionalUInt(payload, "owner_id"),
        .api_key_id = apiKey->id,
        .upstream_bucket = payload.at("upstream_bucket").get<std::string>(),
        .encrypt_upstream = payload.value("encrypt_upstream", true),
        .name = optionalString(payload, "name"),
        .description = optionalString(payload, "description"),
        .accept_waiver = payload.value("accept_encryption_waiver", false)
    });
    return {{"bucket", bucketJson(bucket)}};
}

json S3Gateway::budgetPolicyList(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"policies", gw::listBudgets(gwActor(session), budgetFilterFromPayload(payload))}};
}

json S3Gateway::budgetPolicyUpsert(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"policy", gw::upsertBudget(gwActor(session), budgetSpecFromPayload(payload))}};
}

json S3Gateway::budgetPolicyDisable(const json& payload, const std::shared_ptr<Session>& session) {
    const auto credentialId = optionalUInt(payload, "gateway_credential_id");
    if (!credentialId) throw std::runtime_error("gateway_credential_id is required");
    return {{"disabled", gw::disableBudget(gwActor(session), budgetScopeFromPayload(payload), *credentialId,
                                           optionalUInt(payload, "vault_id"))}};
}

json S3Gateway::budgetLedgerList(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"ledger", gw::budgetLedger(gwActor(session), budgetFilterFromPayload(payload), gwLimitFromPayload(payload))}};
}

json S3Gateway::budgetStatus(const json& payload, const std::shared_ptr<Session>& session) {
    const auto status = gw::budgetStatus(gwActor(session), budgetFilterFromPayload(payload), gwLimitFromPayload(payload, 20));
    return {
        {"policies", status.policies},
        {"ledger", status.ledger},
        {"trends", status.trends}
    };
}

} // namespace vh::protocols::ws::handler
