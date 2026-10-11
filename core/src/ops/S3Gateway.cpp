#include "ops/S3Gateway.hpp"

#include "ops/Vaults.hpp"
#include "config/Registry.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/Permission.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "protocols/s3/Error.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "rbac/fs/glob/model/Pattern.hpp"
#include "rbac/permission/admin/S3Gateway.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/permission/vault/Roles.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "runtime/Manager.hpp"
#include "storage/Manager.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <set>

namespace vh::ops::s3_gateway {

namespace {

using GwPerm = rbac::permission::admin::S3GatewayPermissions;
using RolePerm = rbac::permission::vault::RolePermissions;
using FsAction = rbac::permission::vault::FilesystemAction;
using AdminVaultPerm = rbac::permission::admin::VaultPermissions;
using VaultRolePtr = std::shared_ptr<rbac::role::Vault>;
using UserPtr = std::shared_ptr<identities::User>;
namespace pricing = storage::s3::pricing;

constexpr const char* USER_ACCESS = "user_access";
constexpr const char* GLOBAL = "global";
constexpr const char* VAULT_ALLOWLIST = "vault_allowlist";

// ------------------------------------------------------------------------------------------------- permissions

bool hasGw(const Actor& actor, const GwPerm perm) {
    if (actor->isSuperAdmin()) return true;
    return rbac::resolver::Admin::has<GwPerm>({.user = actor, .permission = perm});
}

void requireGw(const Actor& actor, const GwPerm perm, const char* permName, const std::string& what) {
    if (!hasGw(actor, perm)) throw Denied(std::string("admin.s3_gateway.") + permName + " is required to " + what);
}

bool canManageCredentials(const Actor& actor) { return hasGw(actor, GwPerm::ManageCredentials); }

bool canSeeAllBudgets(const Actor& actor) { return hasGw(actor, GwPerm::View) || hasGw(actor, GwPerm::ManageBudgets); }

bool ownsVault(const Actor& actor, const uint32_t vaultId) {
    try {
        return db::query::vault::Vault::getVaultOwnerId(vaultId) == actor->id;
    } catch (const std::exception&) {
        return false;
    }
}

bool canEditVault(const Actor& actor, const uint32_t vaultId) {
    if (ownsVault(actor, vaultId)) return true;
    return rbac::resolver::Admin::has<AdminVaultPerm>({.user = actor, .permission = AdminVaultPerm::Edit, .vault_id = vaultId});
}

bool canViewVault(const Actor& actor, const uint32_t vaultId) {
    if (ownsVault(actor, vaultId)) return true;
    return rbac::resolver::Admin::has<AdminVaultPerm>({
        .user = actor, .permissions = {AdminVaultPerm::View, AdminVaultPerm::ViewStats}, .vault_id = vaultId});
}

UserPtr requireUser(const uint32_t id, const char* what) {
    auto user = vh::identities::manager().user(id);
    if (!user) throw NotFound(std::string(what) + " not found: " + std::to_string(id));
    return user;
}

std::shared_ptr<vault::model::Vault> requireVault(const uint32_t id) {
    auto vault = db::query::vault::Vault::getVault(id);
    if (!vault) throw NotFound("vault not found: " + std::to_string(id));
    return vault;
}

VaultRolePtr requireVaultRole(const uint32_t id) {
    auto role = db::query::rbac::role::Vault::get(id);
    if (!role) throw NotFound("vault role not found: " + std::to_string(id));
    return role;
}

// Acting on another principal's credential policy.
void requireActFor(const Actor& actor, const uint32_t principalId) {
    if (principalId != actor->id && !hasGw(actor, GwPerm::AssignPrincipal))
        throw Denied("admin.s3_gateway.assign_principal is required to act for another principal");
}

void requireVaultRoleOver(const Actor& actor, const Credential& credential, const uint32_t vaultId, const RolePerm perm,
                          const std::string& what) {
    requireActFor(actor, credential.principal_user_id);
    if (!rbac::resolver::Vault::has<RolePerm>({
            .user = actor,
            .permission = perm,
            .target_subject_type = std::string{"user"},
            .target_subject_id = credential.principal_user_id,
            .vault_id = vaultId
        })) throw Denied("you do not have permission to " + what + " for this principal on vault " + std::to_string(vaultId));
}

bool principalCan(const UserPtr& principal, const uint32_t vaultId, const FsAction action) {
    if (!principal) return false;
    if (principal->isSuperAdmin()) return true;
    return rbac::resolver::Vault::has<FsAction>({.user = principal, .permission = action, .vault_id = vaultId, .path = "/"});
}

bool principalReaches(const UserPtr& principal, const uint32_t vaultId) {
    return principalCan(principal, vaultId, FsAction::List) || principalCan(principal, vaultId, FsAction::Read) ||
           principalCan(principal, vaultId, FsAction::Write) || principalCan(principal, vaultId, FsAction::Delete);
}

// Granting S3 gateway access to a vault: vault-role Assign over the principal there, and the principal must
// already reach the vault itself.
void requireGrantOn(const Actor& actor, const UserPtr& principal, const uint32_t vaultId) {
    if (!actor->isSuperAdmin() && !rbac::resolver::Vault::has<RolePerm>({
            .user = actor,
            .permission = RolePerm::Assign,
            .target_subject_type = std::string{"user"},
            .target_subject_id = principal->id,
            .vault_id = vaultId
        })) throw Denied("you cannot grant S3 gateway access to vault " + std::to_string(vaultId));
    if (!principalReaches(principal, vaultId))
        throw Invalid("the principal cannot access vault " + std::to_string(vaultId));
}

// The single rule for what a credential's vault policy may grant (it was CredentialManager::validateScopeMutation,
// and each surface re-checked parts of it first, differently).
void requireScopeMutation(const Actor& actor, const uint32_t principalId, const std::string& mode,
                          const std::vector<VaultAccess>& access, const std::vector<uint32_t>& selectedVaultIds,
                          const std::optional<uint32_t> defaultRoleId) {
    if (!actor->isActive()) throw Denied("your account is not active");
    const auto principal = requireUser(principalId, "principal");
    if (!principal->isActive()) throw Invalid("the credential principal is not active");
    requireActFor(actor, principalId);

    if (mode == GLOBAL) {
        if (!canManageCredentials(actor))
            throw Denied("admin.s3_gateway.manage_credentials is required for global credentials");
        if (!principal->isAdmin()) throw Invalid("global credentials need an admin principal");
        if (!defaultRoleId) throw Invalid("global credentials need a default vault role");
        return;
    }
    if (mode == USER_ACCESS) return;

    std::set<uint32_t> vaultIds(selectedVaultIds.begin(), selectedVaultIds.end());
    for (const auto& a : access) if (a.vault_id != 0) vaultIds.insert(a.vault_id);
    if (!defaultRoleId && access.empty()) throw Invalid("vault-allowlist credentials need a default vault role");
    if (vaultIds.empty()) throw Invalid("vault-allowlist credentials need at least one selected vault");

    for (const auto vaultId : vaultIds) requireGrantOn(actor, principal, vaultId);

    // A grant never exceeds the principal, and only admins grant role administration.
    if (actor->isAdmin()) return;
    for (const auto& a : access) {
        if (a.admin) throw Denied("only admins can grant S3 gateway admin access");
        if (a.list && !principalCan(principal, a.vault_id, FsAction::List))
            throw Invalid("the principal cannot list vault " + std::to_string(a.vault_id));
        if (a.read && !principalCan(principal, a.vault_id, FsAction::Read))
            throw Invalid("the principal cannot read vault " + std::to_string(a.vault_id));
        if (a.write && !principalCan(principal, a.vault_id, FsAction::Write))
            throw Invalid("the principal cannot write to vault " + std::to_string(a.vault_id));
        if (a.del && !principalCan(principal, a.vault_id, FsAction::Delete))
            throw Invalid("the principal cannot delete from vault " + std::to_string(a.vault_id));
    }
}

void requireGrantVault(const Actor& actor, const Credential& credential, const uint32_t vaultId) {
    requireActFor(actor, credential.principal_user_id);
    requireGrantOn(actor, requireUser(credential.principal_user_id, "principal"), vaultId);
}

// ------------------------------------------------------------------------------------------------- credentials

std::string normalizeScopeMode(std::string mode) {
    std::ranges::transform(mode, mode.begin(), [](const unsigned char c) {
        return c == '-' ? '_' : static_cast<char>(std::tolower(c));
    });
    if (mode == USER_ACCESS || mode == GLOBAL || mode == VAULT_ALLOWLIST) return mode;
    throw Invalid("credential scope must be user-access, global, or vault-allowlist");
}

bool matches(const Credential& c, const Ref& ref) {
    if (const auto* id = std::get_if<uint32_t>(&ref)) return c.id == *id;
    const auto& value = std::get<std::string>(ref);
    return c.access_key == value || c.name == value || std::to_string(c.id) == value;
}

std::optional<Credential> findIn(const std::vector<Credential>& credentials, const Ref& ref) {
    for (const auto& c : credentials) if (matches(c, ref)) return c;
    return std::nullopt;
}

std::vector<Credential> visibleCredentials(const Actor& actor) {
    return canManageCredentials(actor) ? db::query::s3::Gateway::listCredentialsAdmin(true)
                                       : db::query::s3::Gateway::listCredentialsForPrincipal(actor->id);
}

Credential reload(const Credential& credential) {
    auto updated = db::query::s3::Gateway::getCredentialByAccessKey(credential.access_key);
    if (!updated) throw NotFound("credential not found: " + credential.name);
    return *updated;
}

std::vector<uint32_t> enabledSelected(const uint32_t credentialId) {
    std::vector<uint32_t> out;
    for (const auto& s : db::query::s3::Gateway::listCredentialSelectedVaults(credentialId))
        if (s.enabled) out.push_back(s.vault_id);
    return out;
}

db::query::s3::CredentialVaultAccessShorthand shorthandOf(const VaultAccess& a, const uint32_t credentialId) {
    return {.credential_id = credentialId, .vault_id = a.vault_id, .can_list = a.list, .can_read = a.read,
            .can_write = a.write, .can_delete = a.del, .can_admin = a.admin};
}

std::vector<db::query::s3::CredentialVaultAccessShorthand> shorthandsOf(const std::vector<VaultAccess>& access,
                                                                       const uint32_t credentialId) {
    std::vector<db::query::s3::CredentialVaultAccessShorthand> out;
    for (const auto& a : access) out.push_back(shorthandOf(a, credentialId));
    return out;
}

// The vault role a boolean shorthand stands for.
VaultRolePtr roleForAccess(const VaultAccess& a) {
    const char* name = a.admin || a.del ? "manager" : a.write ? "contributor" : a.read ? "reader" : a.list ? "guest" : "implicit_deny";
    auto role = db::query::rbac::role::Vault::get(name);
    if (!role) throw NotFound(std::string("the built-in vault role '") + name + "' is not seeded");
    return role;
}

// What a vault role lets the principal do, in shorthand terms (for the ceiling check).
VaultAccess accessForRole(const uint32_t vaultId, const rbac::role::Vault& role) {
    return {
        .vault_id = vaultId,
        .list = role.directories().canList(),
        .read = role.files().canDownload() || role.directories().canDownload(),
        .write = role.files().canUpload() || role.files().canOverwrite() || role.directories().canUpload() ||
                 role.directories().canTouch(),
        .del = role.files().canDelete() || role.directories().canDelete(),
        .admin = role.rolesPerms().canAssign() || role.rolesPerms().canModify() || role.rolesPerms().canRevoke()
    };
}

void requireRoleWithinPrincipal(const Actor& actor, const Credential& credential, const uint32_t vaultId,
                                const rbac::role::Vault& role) {
    requireScopeMutation(actor, credential.principal_user_id, VAULT_ALLOWLIST, {accessForRole(vaultId, role)}, {}, std::nullopt);
}

void requireDefaultOverrideAuthority(const Actor& actor, const Credential& credential, const RolePerm perm,
                                     const std::string& what) {
    if (credential.scope_mode == GLOBAL) {
        requireGw(actor, GwPerm::ManageCredentials, "manage_credentials", what + " on a global credential");
        return;
    }
    for (const auto vaultId : enabledSelected(credential.id)) requireVaultRoleOver(actor, credential, vaultId, perm, what);
}

std::shared_ptr<rbac::permission::Permission> resolvePermission(const std::string& ref) {
    if (ref.empty()) throw Invalid("an override needs a permission");
    unsigned int id = 0;
    if (const auto [end, ec] = std::from_chars(ref.data(), ref.data() + ref.size(), id); ec == std::errc{} && end == ref.data() + ref.size()) {
        try {
            if (auto p = db::query::rbac::Permission::getPermission(id)) return p;
        } catch (const std::exception&) {
        }
        throw NotFound("permission not found: " + ref);
    }
    std::vector<std::string> candidates{ref};
    if (ref.find('.') == std::string::npos) {
        candidates.push_back("vault.fs.files." + ref);
        candidates.push_back("vault.fs.directories." + ref);
    }
    for (const auto& candidate : candidates) {
        try {
            if (auto p = db::query::rbac::Permission::getPermissionByName(candidate)) return p;
        } catch (const std::exception&) {
        }
    }
    throw NotFound("permission not found: " + ref);
}

Override overrideFrom(const OverrideSpec& spec) {
    // Both are required: the web used to default to allow on "**", granting everything the permission covers.
    if (spec.effect.empty()) throw Invalid("an override needs an effect: allow or deny");
    if (spec.pattern.empty()) throw Invalid("an override needs a path pattern");
    Override out;
    out.permission = *resolvePermission(spec.permission);
    try {
        out.effect = rbac::permission::overrideOptFromString(spec.effect);
    } catch (const std::exception&) {
        throw Invalid("override effect must be allow or deny, got '" + spec.effect + "'");
    }
    try {
        out.pattern = rbac::fs::glob::model::Pattern::make(spec.pattern);
    } catch (const std::exception& e) {
        throw Invalid("invalid override pattern '" + spec.pattern + "': " + e.what());
    }
    out.enabled = spec.enabled;
    return out;
}

// ------------------------------------------------------------------------------------------------- buckets

std::string bucketMode(const vault::model::Vault& vault, const std::optional<std::string>& requested) {
    const bool s3Backed = vault.type == vault::model::VaultType::S3;
    auto mode = requested.value_or(s3Backed ? "remote_cache" : "local");
    std::ranges::transform(mode, mode.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (mode != "local" && mode != "remote_cache" && mode != "remote_proxy")
        throw Invalid("bucket mode must be local, remote_cache, or remote_proxy");
    if (s3Backed && mode == "local") throw Invalid("S3/R2 vaults must use remote_cache or remote_proxy mode");
    if (!s3Backed && mode != "local") throw Invalid("local vaults can only use local mode");
    return mode;
}

void requireBucketName(const std::string& name) {
    try {
        vault::model::requireValidS3Name(name);
    } catch (const std::exception& e) {
        throw Invalid("invalid bucket name '" + name + "': " + e.what());
    }
}

void requireBucketFree(const std::string& name) {
    if (db::query::s3::Gateway::resolveBucket(name)) throw Conflict("bucket '" + name + "' is already bound");
}

void requireManageBucketsOn(const Actor& actor, const uint32_t vaultId, const std::string& what) {
    requireGw(actor, GwPerm::ManageBuckets, "manage_buckets", what);
    if (!canEditVault(actor, vaultId)) throw Denied("you do not have permission to manage this vault's bucket");
}

Bucket requireBucket(const std::string& name) {
    auto bucket = db::query::s3::Gateway::resolveBucket(name);
    if (!bucket) throw NotFound("bucket not found: " + name);
    return *bucket;
}

// Binds a vault that was just created for the bucket; a failed bind takes the vault back out.
Bucket bindNewVault(const ops::vaults::VaultPtr& vault, const std::string& bucketName, const bool apiExclusive,
                    const std::string& mode, const Actor& actor) {
    try {
        db::query::s3::Gateway::bindBucket({
            .vault_id = vault->id, .bucket_name = bucketName, .api_exclusive = apiExclusive, .mode = mode,
            .created_by = actor->id});
        return requireBucket(bucketName);
    } catch (...) {
        try {
            runtime::Deps::get().storageManager->removeVault(vault->id);
        } catch (...) {
        }
        throw;
    }
}

// ------------------------------------------------------------------------------------------------- budgets

pricing::PriceBudgetScope scopeOf(const BudgetScope scope) {
    return scope == BudgetScope::Key ? pricing::PriceBudgetScope::GatewayCredential
                                     : pricing::PriceBudgetScope::GatewayCredentialVault;
}

bool isGatewayScope(const pricing::PriceBudgetScope scope) {
    return scope == pricing::PriceBudgetScope::GatewayCredential || scope == pricing::PriceBudgetScope::GatewayCredentialVault;
}

bool ownsCredential(const Actor& actor, const uint32_t credentialId) {
    return std::ranges::any_of(db::query::s3::Gateway::listCredentialsForPrincipal(actor->id),
                               [&](const Credential& c) { return c.id == credentialId; });
}

void requireBudgetAuthority(const Actor& actor, const BudgetScope scope, const uint32_t credentialId,
                            const std::optional<uint32_t> vaultId) {
    requireGw(actor, GwPerm::ManageBudgets, "manage_budgets", "manage S3 gateway budgets");
    if (!findIn(db::query::s3::Gateway::listCredentialsAdmin(true), credentialId))
        throw NotFound("credential not found: " + std::to_string(credentialId));
    if (scope == BudgetScope::KeyVault) {
        if (!vaultId) throw Invalid("a key/vault budget needs a vault");
        (void)requireVault(*vaultId);
        if (!canEditVault(actor, *vaultId)) throw Denied("you do not have permission to manage this vault's budgets");
    }
}

bool canViewPolicy(const Actor& actor, const Policy& policy) {
    if (canSeeAllBudgets(actor)) return true;
    if (!isGatewayScope(policy.scope)) return false;
    return (policy.gateway_credential_id && ownsCredential(actor, *policy.gateway_credential_id)) ||
           (policy.vault_id && canViewVault(actor, *policy.vault_id));
}

void requireBudgetVisibility(const Actor& actor, const BudgetFilter& filter) {
    if (canSeeAllBudgets(actor)) return;
    if (filter.vault_id && canViewVault(actor, *filter.vault_id)) return;
    if (filter.credential_id && ownsCredential(actor, *filter.credential_id)) return;
    throw Denied("scope S3 gateway budget views to a vault you can view or a credential you own");
}

}

// ------------------------------------------------------------------------------------------------- lookups

uint32_t vaultIdByName(const Actor& actor, const std::string& name, const std::optional<uint32_t> owner) {
    requireActor(actor);
    if (owner) {
        const auto vault = db::query::vault::Vault::getVault(name, *owner);
        if (!vault) throw NotFound("vault '" + name + "' not found for owner " + std::to_string(*owner));
        return vault->id;
    }
    if (const auto own = db::query::vault::Vault::getVault(name, actor->id)) return own->id;
    std::optional<uint32_t> found;
    for (const auto& vault : db::query::vault::Vault::listVaults()) {
        if (!vault || vault->name != name) continue;
        if (found) throw Invalid("more than one vault is named '" + name + "'; name it by id or owner");
        found = vault->id;
    }
    if (!found) throw NotFound("vault not found: " + name);
    return *found;
}

Credential getCredential(const Actor& actor, const Ref& credential) {
    requireActor(actor);
    auto found = findIn(visibleCredentials(actor), credential);
    if (!found) throw NotFound("S3 gateway credential not found");
    return *found;
}

Credential getBudgetCredential(const Actor& actor, const Ref& credential, const std::optional<uint32_t> scopedToVault) {
    requireActor(actor);
    if (!canSeeAllBudgets(actor) && !(scopedToVault && canViewVault(actor, *scopedToVault)))
        return getCredential(actor, credential);
    auto found = findIn(db::query::s3::Gateway::listCredentialsAdmin(true), credential);
    if (!found) throw NotFound("S3 gateway credential not found");
    return *found;
}

// ------------------------------------------------------------------------------------------------- service

protocols::s3::GatewayService::RuntimeStatus status(const Actor& actor) {
    requireActor(actor);
    requireGw(actor, GwPerm::View, "view", "view S3 gateway status");
    const auto service = runtime::Manager::instance().getS3GatewayService();
    return service ? service->gatewayStatus() : protocols::s3::GatewayService::RuntimeStatus{};
}

// ------------------------------------------------------------------------------------------------- credentials

CreatedCredential createCredential(const Actor& actor, const CreateCredential& req) {
    requireActor(actor);
    if (req.name.empty()) throw Invalid("a credential needs a name");
    const auto principalId = req.principal_id.value_or(actor->id);
    const bool namesVaults = !req.selected_vault_ids.empty() || !req.vault_access.empty();
    std::string mode;
    if (req.scope_mode) {
        mode = normalizeScopeMode(*req.scope_mode);
        if (mode == USER_ACCESS && namesVaults)
            throw Invalid("user-access credentials use the principal's own access; selecting vaults needs vault-allowlist");
    } else {
        mode = namesVaults ? VAULT_ALLOWLIST : USER_ACCESS;
    }
    if (req.default_role_id) (void)requireVaultRole(*req.default_role_id);
    requireScopeMutation(actor, principalId, mode, req.vault_access, req.selected_vault_ids, req.default_role_id);

    protocols::s3::CredentialCreateOptions options;
    options.created_by = actor->id;
    options.principal_user_id = principalId;
    options.name = req.name;
    options.scope_mode = mode;
    options.description = req.description;
    options.expires_at = req.expires_at;
    options.default_vault_role_id = req.default_role_id;
    options.selected_vault_ids = req.selected_vault_ids;
    options.vault_scopes = shorthandsOf(req.vault_access, 0);
    options.enforce_budget_for_local_requests = req.enforce_budget_for_local_requests;
    auto secret = protocols::s3::CredentialManager{}.createCredential(options);
    return {.credential = std::move(secret.credential), .secret_access_key = std::move(secret.secret_access_key)};
}

std::vector<Credential> listCredentials(const Actor& actor, const std::optional<uint32_t> principal, const bool includeDisabled) {
    requireActor(actor);
    std::vector<Credential> out;
    if (principal) {
        if (*principal != actor->id && !canManageCredentials(actor))
            throw Denied("admin.s3_gateway.manage_credentials is required to list another principal's credentials");
        out = db::query::s3::Gateway::listCredentials(*principal);
    } else {
        out = visibleCredentials(actor);
    }
    if (!includeDisabled) std::erase_if(out, [](const Credential& c) { return !c.enabled; });
    return out;
}

Credential revokeCredential(const Actor& actor, const Ref& ref) {
    const auto credential = getCredential(actor, ref);
    if (!db::query::s3::Gateway::deleteCredentialByAccessKey(credential.access_key))
        throw NotFound("S3 gateway credential not found");
    return credential;
}

Credential updateScope(const Actor& actor, const Ref& ref, const ScopeUpdate& req) {
    const auto credential = getCredential(actor, ref);
    if (!req.scope_mode && !req.principal_id && !req.description && !req.expires_at &&
        !req.enforce_budget_for_local_requests && !req.vault_access && !req.selected_vault_ids && !req.default_role_id)
        throw Invalid("nothing to update: give a scope or a setting");

    const auto principalId = req.principal_id.value_or(credential.principal_user_id);
    const auto mode = req.scope_mode ? normalizeScopeMode(*req.scope_mode) : credential.scope_mode;
    if (req.default_role_id) (void)requireVaultRole(*req.default_role_id);
    const auto existingDefault = db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    const auto effectiveDefault = req.default_role_id ? req.default_role_id
        : existingDefault && existingDefault->enabled ? std::make_optional(existingDefault->vault_role_id) : std::nullopt;
    const auto selected = req.selected_vault_ids ? *req.selected_vault_ids
        : mode == VAULT_ALLOWLIST ? enabledSelected(credential.id) : std::vector<uint32_t>{};
    const auto access = req.vault_access.value_or(std::vector<VaultAccess>{});
    requireScopeMutation(actor, principalId, mode, access, selected, effectiveDefault);

    db::query::s3::Gateway::updateCredentialScopeMode(
        credential.id, mode, principalId, mode == GLOBAL ? std::make_optional(actor->id) : credential.created_by,
        req.description ? *req.description : credential.description,
        req.expires_at ? *req.expires_at : credential.expires_at,
        req.enforce_budget_for_local_requests);
    if (mode == USER_ACCESS) {
        db::query::s3::Gateway::replaceCredentialScopeShorthand(credential.id, {});
    } else if (req.vault_access) {
        db::query::s3::Gateway::replaceCredentialScopeShorthand(credential.id, shorthandsOf(access, credential.id));
    } else {
        if (req.default_role_id)
            (void)db::query::s3::Gateway::upsertCredentialDefaultVaultRole(credential.id, *req.default_role_id, true, actor->id);
        if (mode == VAULT_ALLOWLIST && req.selected_vault_ids)
            db::query::s3::Gateway::replaceCredentialSelectedVaults(credential.id, selected, actor->id);
    }
    return reload(credential);
}

Credential allowVault(const Actor& actor, const Ref& ref, const VaultAccess& access) {
    const auto credential = getCredential(actor, ref);
    (void)requireVault(access.vault_id);
    auto selected = enabledSelected(credential.id);
    std::erase(selected, access.vault_id);
    selected.push_back(access.vault_id);

    const auto inferred = roleForAccess(access);
    const auto existingDefault = db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    const bool hasDefault = existingDefault && existingDefault->enabled;
    const auto effectiveDefault = hasDefault ? existingDefault->vault_role_id : inferred->id;
    requireScopeMutation(actor, credential.principal_user_id, VAULT_ALLOWLIST, {access}, selected, effectiveDefault);

    db::query::s3::Gateway::updateCredentialScopeMode(credential.id, VAULT_ALLOWLIST, credential.principal_user_id,
                                                      credential.created_by, credential.description, credential.expires_at);
    if (!hasDefault)
        (void)db::query::s3::Gateway::upsertCredentialDefaultVaultRole(credential.id, inferred->id, true, actor->id);
    (void)db::query::s3::Gateway::upsertCredentialSelectedVault(credential.id, access.vault_id, true, actor->id);
    if (effectiveDefault != inferred->id)
        (void)db::query::s3::Gateway::upsertCredentialVaultRoleAssignment({
            .credential_id = credential.id, .vault_id = access.vault_id, .vault_role_id = inferred->id,
            .enabled = true, .created_by = actor->id});
    else
        (void)db::query::s3::Gateway::deleteCredentialVaultRoleAssignment(credential.id, access.vault_id);
    return reload(credential);
}

void removeVault(const Actor& actor, const Ref& ref, const uint32_t vaultId) {
    const auto credential = getCredential(actor, ref);
    // Dropping a vault grant is a vault-role revoke for the credential's principal, not just a scope edit.
    requireVaultRoleOver(actor, credential, vaultId, RolePerm::Revoke, "revoke S3 gateway vault access");
    const bool assignment = db::query::s3::Gateway::deleteCredentialVaultRoleAssignment(credential.id, vaultId);
    const bool selection = db::query::s3::Gateway::deleteCredentialSelectedVault(credential.id, vaultId);
    if (!assignment && !selection) throw NotFound("vault " + std::to_string(vaultId) + " is not granted to this credential");
}

std::optional<DefaultRole> getDefaultRole(const Actor& actor, const Ref& ref) {
    return db::query::s3::Gateway::getCredentialDefaultVaultRole(getCredential(actor, ref).id);
}

DefaultRole setDefaultRole(const Actor& actor, const Ref& ref, const uint32_t roleId, const bool enabled) {
    const auto credential = getCredential(actor, ref);
    if (credential.scope_mode == USER_ACCESS) throw Invalid("user-access credentials do not use gateway vault roles");
    const auto role = requireVaultRole(roleId);
    if (credential.scope_mode == GLOBAL) {
        requireGw(actor, GwPerm::ManageCredentials, "manage_credentials", "set a global credential's default role");
    } else {
        // The default role applies on every selected vault, so it is granted on each of them.
        for (const auto vaultId : enabledSelected(credential.id)) {
            requireGrantVault(actor, credential, vaultId);
            requireRoleWithinPrincipal(actor, credential, vaultId, *role);
        }
    }
    (void)db::query::s3::Gateway::upsertCredentialDefaultVaultRole(credential.id, role->id, enabled, actor->id);
    auto saved = db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    if (!saved) throw std::runtime_error("the default role was not saved");
    return *saved;
}

bool clearDefaultRole(const Actor& actor, const Ref& ref) {
    const auto credential = getCredential(actor, ref);
    if (credential.scope_mode == GLOBAL)
        requireGw(actor, GwPerm::ManageCredentials, "manage_credentials", "clear a global credential's default role");
    return db::query::s3::Gateway::deleteCredentialDefaultVaultRole(credential.id);
}

std::vector<SelectedVault> listSelectedVaults(const Actor& actor, const Ref& ref) {
    return db::query::s3::Gateway::listCredentialSelectedVaults(getCredential(actor, ref).id);
}

std::vector<SelectedVault> replaceSelectedVaults(const Actor& actor, const Ref& ref, const std::vector<uint32_t>& vaultIds) {
    const auto credential = getCredential(actor, ref);
    if (credential.scope_mode != VAULT_ALLOWLIST) throw Invalid("only vault-allowlist credentials select vaults");
    for (const auto vaultId : vaultIds) requireGrantVault(actor, credential, vaultId);
    db::query::s3::Gateway::replaceCredentialSelectedVaults(credential.id, vaultIds, actor->id);
    return db::query::s3::Gateway::listCredentialSelectedVaults(credential.id);
}

SelectedVault addSelectedVault(const Actor& actor, const Ref& ref, const uint32_t vaultId, const bool enabled) {
    const auto credential = getCredential(actor, ref);
    if (credential.scope_mode != VAULT_ALLOWLIST) throw Invalid("only vault-allowlist credentials select vaults");
    requireGrantVault(actor, credential, vaultId);
    return db::query::s3::Gateway::upsertCredentialSelectedVault(credential.id, vaultId, enabled, actor->id);
}

std::vector<Assignment> listRoleAssignments(const Actor& actor, const Ref& ref) {
    const auto credential = getCredential(actor, ref);
    auto assignments = db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id);
    if (credential.principal_user_id == actor->id) return assignments;
    std::erase_if(assignments, [&](const Assignment& a) {
        return !rbac::resolver::Vault::has<RolePerm>({
            .user = actor,
            .permission = RolePerm::View,
            .target_subject_type = std::string{"user"},
            .target_subject_id = credential.principal_user_id,
            .vault_id = a.vault_id
        });
    });
    return assignments;
}

Assignment assignRole(const Actor& actor, const Ref& ref, const uint32_t vaultId, const uint32_t roleId, const bool enabled) {
    const auto credential = getCredential(actor, ref);
    (void)requireVault(vaultId);
    const auto role = requireVaultRole(roleId);
    if (credential.scope_mode == GLOBAL)
        requireGw(actor, GwPerm::ManageCredentials, "manage_credentials", "manage a global credential's vault roles");
    // S7: the web only checked Assign; the role must also fit the principal, and role administration needs an admin.
    requireRoleWithinPrincipal(actor, credential, vaultId, *role);

    const auto nextMode = credential.scope_mode == GLOBAL ? GLOBAL : VAULT_ALLOWLIST;
    db::query::s3::Gateway::updateCredentialScopeMode(credential.id, nextMode, credential.principal_user_id,
                                                      credential.created_by, credential.description, credential.expires_at);
    if (!db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id)) {
        const auto implicitDeny = db::query::rbac::role::Vault::get("implicit_deny");
        (void)db::query::s3::Gateway::upsertCredentialDefaultVaultRole(credential.id, implicitDeny ? implicitDeny->id : role->id,
                                                                      true, actor->id);
    }
    if (std::string(nextMode) == VAULT_ALLOWLIST)
        (void)db::query::s3::Gateway::upsertCredentialSelectedVault(credential.id, vaultId, true, actor->id);
    const auto id = db::query::s3::Gateway::upsertCredentialVaultRoleAssignment({
        .credential_id = credential.id, .vault_id = vaultId, .vault_role_id = role->id, .enabled = enabled,
        .created_by = actor->id});
    for (const auto& a : db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id))
        if (a.id == id) return a;
    throw std::runtime_error("the S3 gateway role assignment was not saved");
}

void revokeRole(const Actor& actor, const Ref& ref, const uint32_t vaultId) {
    const auto credential = getCredential(actor, ref);
    requireVaultRoleOver(actor, credential, vaultId, RolePerm::Revoke, "revoke S3 gateway vault roles");
    if (!db::query::s3::Gateway::deleteCredentialVaultRoleAssignment(credential.id, vaultId))
        throw NotFound("no S3 gateway role is assigned on vault " + std::to_string(vaultId));
}

std::vector<Override> listDefaultRoleOverrides(const Actor& actor, const Ref& ref) {
    const auto credential = getCredential(actor, ref);
    if (!db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id)) return {};
    requireDefaultOverrideAuthority(actor, credential, RolePerm::ViewOverride, "view default role overrides");
    return db::query::s3::Gateway::listCredentialDefaultVaultRoleOverrides(credential.id);
}

Override addDefaultRoleOverride(const Actor& actor, const Ref& ref, const OverrideSpec& spec) {
    const auto credential = getCredential(actor, ref);
    if (credential.scope_mode == USER_ACCESS) throw Invalid("user-access credentials do not use gateway role overrides");
    if (!db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id))
        throw Invalid("set a default vault role before adding default overrides");
    requireDefaultOverrideAuthority(actor, credential, RolePerm::AssignOverride, "add default role overrides");
    const auto id = db::query::s3::Gateway::upsertCredentialDefaultVaultRoleOverride(credential.id, overrideFrom(spec));
    for (const auto& saved : db::query::s3::Gateway::listCredentialDefaultVaultRoleOverrides(credential.id))
        if (saved.id == id) return saved;
    throw std::runtime_error("the default role override was not saved");
}

void removeDefaultRoleOverride(const Actor& actor, const Ref& ref, const uint32_t overrideId) {
    const auto credential = getCredential(actor, ref);
    requireDefaultOverrideAuthority(actor, credential, RolePerm::RevokeOverride, "remove default role overrides");
    if (!db::query::s3::Gateway::deleteCredentialDefaultVaultRoleOverride(credential.id, overrideId))
        throw NotFound("default role override not found: " + std::to_string(overrideId));
}

std::vector<Override> listRoleOverrides(const Actor& actor, const Ref& ref, const uint32_t vaultId) {
    const auto credential = getCredential(actor, ref);
    requireVaultRoleOver(actor, credential, vaultId, RolePerm::ViewOverride, "view S3 gateway role overrides");
    if (!db::query::s3::Gateway::getCredentialVaultRoleForVault(credential.id, vaultId)) return {};
    return db::query::s3::Gateway::listCredentialVaultRoleOverrides(credential.id, vaultId);
}

Override addRoleOverride(const Actor& actor, const Ref& ref, const uint32_t vaultId, const OverrideSpec& spec) {
    const auto credential = getCredential(actor, ref);
    requireVaultRoleOver(actor, credential, vaultId, RolePerm::AssignOverride, "add S3 gateway role overrides");
    if (credential.scope_mode == VAULT_ALLOWLIST && !std::ranges::contains(enabledSelected(credential.id), vaultId))
        throw Invalid("per-vault overrides need the vault to be selected for this credential");
    const auto rule = overrideFrom(spec);
    if (!db::query::s3::Gateway::getCredentialVaultRoleForVault(credential.id, vaultId)) {
        const auto defaultRole = db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
        if (!defaultRole || !defaultRole->enabled) throw Invalid("set a default vault role before adding per-vault overrides");
        (void)db::query::s3::Gateway::upsertCredentialVaultRoleAssignment({
            .credential_id = credential.id, .vault_id = vaultId, .vault_role_id = defaultRole->vault_role_id,
            .enabled = true, .created_by = actor->id});
    }
    const auto id = db::query::s3::Gateway::upsertCredentialVaultRoleOverride(credential.id, vaultId, rule);
    for (const auto& saved : db::query::s3::Gateway::listCredentialVaultRoleOverrides(credential.id, vaultId))
        if (saved.id == id) return saved;
    throw std::runtime_error("the role override was not saved");
}

void removeRoleOverride(const Actor& actor, const Ref& ref, const uint32_t vaultId, const uint32_t overrideId) {
    const auto credential = getCredential(actor, ref);
    requireVaultRoleOver(actor, credential, vaultId, RolePerm::RevokeOverride, "remove S3 gateway role overrides");
    if (!db::query::s3::Gateway::getCredentialVaultRoleForVault(credential.id, vaultId) ||
        !db::query::s3::Gateway::deleteCredentialVaultRoleOverride(credential.id, vaultId, overrideId))
        throw NotFound("role override not found: " + std::to_string(overrideId));
}

// ------------------------------------------------------------------------------------------------- buckets

std::vector<Bucket> listBuckets(const Actor& actor) {
    requireActor(actor);
    return protocols::s3::ObjectStore{}.listBuckets(actor);
}

Bucket bindBucket(const Actor& actor, const BindBucket& req) {
    requireActor(actor);
    const auto vault = requireVault(req.vault_id);
    requireManageBucketsOn(actor, vault->id, "bind S3 gateway buckets");
    const auto name = req.bucket_name.value_or(vault->slug);
    requireBucketName(name);
    if (const auto existing = db::query::s3::Gateway::resolveBucket(name); existing && existing->vault_id != vault->id)
        throw Conflict("bucket '" + name + "' is already bound to another vault");
    db::query::s3::Gateway::bindBucket({
        .vault_id = vault->id, .bucket_name = name, .api_exclusive = req.api_exclusive,
        .mode = bucketMode(*vault, req.mode), .created_by = actor->id});
    return requireBucket(name);
}

Bucket requireManageableBucket(const Actor& actor, const std::string& bucketName) {
    requireActor(actor);
    // The permission first: the web used to answer "not bound" to anyone, revealing which buckets exist.
    requireGw(actor, GwPerm::ManageBuckets, "manage_buckets", "manage S3 gateway buckets");
    const auto bucket = requireBucket(bucketName);
    if (!canEditVault(actor, bucket.vault_id)) throw Denied("you do not have permission to manage this vault's bucket");
    return bucket;
}

void unbindBucket(const Actor& actor, const std::string& bucketName) {
    (void)requireManageableBucket(actor, bucketName);
    if (!db::query::s3::Gateway::unbindBucket(bucketName)) throw NotFound("bucket not found: " + bucketName);
}

Bucket createLocalBucket(const Actor& actor, const CreateLocalBucket& req) {
    requireActor(actor);
    const auto ownerId = req.owner_id.value_or(actor->id);
    const auto owner = requireUser(ownerId, "owner");
    if (ownerId != actor->id)
        requireGw(actor, GwPerm::ManageBuckets, "manage_buckets", "create gateway buckets for another owner");
    if (req.bucket_name) {
        requireBucketName(*req.bucket_name);
        requireBucketFree(*req.bucket_name);
    }
    const auto name = req.name.value_or(req.bucket_name.value_or("S3 gateway local bucket for " + owner->name()));
    const auto vault = ops::vaults::create(actor, {
        .name = name,
        .type = vault::model::VaultType::Local,
        .owner_id = ownerId,
        .description = req.description.value_or("S3 gateway bucket " + name),
        .quota = req.quota,
        .sync = {.conflict_policy = std::string{"keep_both"}}
    });
    return bindNewVault(vault, req.bucket_name.value_or(vault->slug), vh::config::Registry::get().s3_gateway.default_api_exclusive,
                        "local", actor);
}

Bucket createRemoteCacheBucket(const Actor& actor, const CreateRemoteCacheBucket& req) {
    requireActor(actor);
    requireGw(actor, GwPerm::ManageBuckets, "manage_buckets", "create remote-cache S3 gateway buckets");
    if (req.upstream_bucket.empty()) throw Invalid("an upstream bucket is required");
    if (req.bucket_name) {
        requireBucketName(*req.bucket_name);
        requireBucketFree(*req.bucket_name);
    }
    const auto name = req.name.value_or(req.bucket_name.value_or("S3 gateway remote-cache bucket"));
    // Through the vault op, so the key needs Consume and an encryption change over existing data needs the waiver.
    const auto vault = ops::vaults::create(actor, {
        .name = name,
        .type = vault::model::VaultType::S3,
        .owner_id = req.owner_id,
        .description = req.description.value_or("S3 gateway remote-cache bucket " + name),
        .s3 = ops::vaults::S3Spec{.api_key_id = req.api_key_id, .bucket = req.upstream_bucket,
                                  .encrypt_upstream = req.encrypt_upstream},
        .sync = {
            .strategy = std::string{"cache"},
            .conflict_policy = std::string{"keep_local"},
            .max_remote_index_age = std::optional<std::chrono::seconds>{std::chrono::hours(24)},
            .s3_budget_preset = std::string{"balanced"}
        },
        .accept_waiver = req.accept_waiver
    });
    return bindNewVault(vault, req.bucket_name.value_or(vault->slug), true, "remote_cache", actor);
}

// ------------------------------------------------------------------------------------------------- budgets

Policy upsertBudget(const Actor& actor, const BudgetSpec& spec) {
    requireActor(actor);
    requireBudgetAuthority(actor, spec.scope, spec.credential_id, spec.vault_id);
    Policy policy;
    policy.scope = scopeOf(spec.scope);
    policy.gateway_credential_id = spec.credential_id;
    policy.vault_id = spec.scope == BudgetScope::KeyVault ? spec.vault_id : std::nullopt;
    // One set of defaults for every surface (the CLI enforced, the web only reported).
    try {
        policy.mode = pricing::priceBudgetModeFromString(spec.mode.value_or("enforce"));
    } catch (const std::exception& e) {
        throw Invalid(e.what());
    }
    policy.currency = spec.currency.value_or("USD");
    policy.max_run_cost = spec.max_run_cost;
    policy.max_daily_cost = spec.max_daily_cost;
    policy.max_monthly_cost = spec.max_monthly_cost;
    for (const auto& cost : {spec.max_run_cost, spec.max_daily_cost, spec.max_monthly_cost})
        if (cost && !pricing::isValidPriceBudgetDecimal(*cost))
            throw Invalid("budget limits must be non-negative decimals with at most 8 fractional digits: " + *cost);
    policy.require_verified_catalog = spec.require_verified_catalog.value_or(true);
    policy.allow_stale_catalog = spec.allow_stale_catalog.value_or(false);
    policy.max_catalog_age_seconds = spec.max_catalog_age_seconds.value_or(43200);
    try {
        return pricing::PriceBudgetService{}.upsertPolicy(std::move(policy));
    } catch (const std::invalid_argument& e) {
        throw Invalid(e.what());
    }
}

bool disableBudget(const Actor& actor, const BudgetScope scope, const uint32_t credentialId, const std::optional<uint32_t> vaultId) {
    requireActor(actor);
    requireBudgetAuthority(actor, scope, credentialId, vaultId);
    return pricing::PriceBudgetService{}.disablePolicy(scopeOf(scope), std::nullopt,
                                                       scope == BudgetScope::KeyVault ? vaultId : std::nullopt, credentialId);
}

std::vector<Policy> listBudgets(const Actor& actor, const BudgetFilter& filter) {
    requireActor(actor);
    auto policies = pricing::PriceBudgetService{}.listPolicies(filter.include_inactive);
    std::erase_if(policies, [&](const Policy& policy) {
        if (!isGatewayScope(policy.scope)) return true;
        if (filter.credential_id && policy.gateway_credential_id != filter.credential_id) return true;
        if (filter.vault_id) {
            if (policy.scope == pricing::PriceBudgetScope::GatewayCredentialVault && policy.vault_id != filter.vault_id) return true;
            if (policy.scope == pricing::PriceBudgetScope::GatewayCredential && !filter.credential_id) return true;
        }
        return !canViewPolicy(actor, policy);
    });
    return policies;
}

std::vector<pricing::PriceBudgetLedgerEntry> budgetLedger(const Actor& actor, const BudgetFilter& filter, const uint32_t limit) {
    requireActor(actor);
    requireBudgetVisibility(actor, filter);
    auto ledger = pricing::PriceBudgetService{}.listLedger(std::clamp<uint32_t>(limit, 1, 500), filter.vault_id, filter.credential_id);
    std::erase_if(ledger, [](const auto& entry) { return !entry.gateway_credential_id; });
    return ledger;
}

BudgetStatus budgetStatus(const Actor& actor, const BudgetFilter& filter, const uint32_t limit) {
    requireActor(actor);
    requireBudgetVisibility(actor, filter);
    pricing::PriceBudgetService service;
    service.expireStaleReservations();
    BudgetStatus out;
    out.policies = listBudgets(actor, filter);
    out.ledger = budgetLedger(actor, filter, limit);
    out.trends = service.trendStats(filter.vault_id, filter.credential_id);
    std::erase_if(out.trends, [](const auto& t) { return t.scope != "gateway_credential" && t.scope != "gateway_credential_vault"; });
    return out;
}

}
