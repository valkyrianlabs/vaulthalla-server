#include "ops/Users.hpp"

#include "ops/Roles.hpp"
#include "ops/Vaults.hpp"
#include "config/util.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "vault/Retention.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"
#include "auth/Bootstrap.hpp"
#include "auth/Manager.hpp"
#include "auth/registration/Validator.hpp"
#include "crypto/util/hash.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/permission/admin/identities/Base.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"

#include <paths.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <tuple>

namespace vh::ops::users {

namespace {

using IdPerm = rbac::permission::admin::identities::IdentityPermissions;
using Entity = rbac::resolver::admin::Entity;
using AdminRolePtr = std::shared_ptr<rbac::role::Admin>;

constexpr const char* SUPER_ADMIN_ROLE = "super_admin";

bool roleIsAdminIdentity(const AdminRolePtr& role) { return role && isAdminIdentity(*role); }

bool can(const Actor& actor, const IdPerm perm, const AdminRolePtr& role) {
    return rbac::resolver::Admin::has<IdPerm>({
        .user = actor,
        .permission = perm,
        .identity = roleIsAdminIdentity(role) ? Entity::Admin : Entity::User
    });
}

const char* kindOf(const AdminRolePtr& role) { return roleIsAdminIdentity(role) ? "admin accounts" : "user accounts"; }

std::shared_ptr<identities::User> requireUser(const uint32_t id) {
    auto user = vh::identities::manager().user(id);
    if (!user) throw NotFound("user not found: " + std::to_string(id));
    return user;
}

// The account's admin role as a mutable copy (role objects in published states are immutable).
AdminRolePtr adminRoleOf(const identities::UserState& s) {
    return s.roles.admin ? std::make_shared<rbac::role::Admin>(*s.roles.admin) : nullptr;
}

AdminRolePtr requireRole(const std::string& ref) {
    if (ref.empty()) throw Invalid("a role is required");
    unsigned int id = 0;
    const auto [end, ec] = std::from_chars(ref.data(), ref.data() + ref.size(), id);
    auto role = ec == std::errc{} && end == ref.data() + ref.size() ? db::query::rbac::role::Admin::get(id)
                                                                   : db::query::rbac::role::Admin::get(ref);
    if (!role) throw NotFound("admin role not found: " + ref);
    return role;
}

// The ceiling, for an account's current role or a role about to be assigned.
void requireWithinActor(const Actor& actor, const AdminRolePtr& role, const std::string& refusal) {
    if (!role || actor->isSuperAdmin()) return;
    const auto beyond = roles::permissionsBeyondActor(actor, *role);
    if (beyond.empty()) return;
    std::string msg = refusal + ":";
    for (const auto& name : beyond) msg += " " + name;
    throw Denied(msg);
}

void requireAssignable(const Actor& actor, const AdminRolePtr& role) {
    if (role->name == SUPER_ADMIN_ROLE) throw Denied("the super_admin role cannot be assigned");
    requireWithinActor(actor, role, "you cannot assign a role with admin permissions you do not hold");
}

// Managing an existing account: its class decides the permission, and an account above the actor is off limits.
void requireManage(const Actor& actor, const identities::UserState& target, const IdPerm perm,
                   const std::string& verb) {
    if (target.isProtected) throw Denied("protected accounts cannot be " + verb + " here: " + target.name);
    if (target.hasSuperAdminRole()) throw Denied("the super admin account cannot be " + verb + ": " + target.name);
    const auto role = adminRoleOf(target);
    if (!can(actor, perm, role))
        throw Denied(std::string("you do not have permission to manage ") + kindOf(role));
    requireWithinActor(actor, role, "you cannot manage an account whose role grants admin permissions you do not hold");
}

void requireValidName(const std::string& name) {
    if (!auth::registration::Validator::isValidName(name))
        throw Invalid("user names must be 3 to 50 characters: " + name);
}

void requireValidEmail(const std::optional<std::string>& email) {
    if (email && !email->empty() && !auth::registration::Validator::isValidEmail(*email))
        throw Invalid("invalid email address: " + *email);
}

void requireBindableUid(const uint32_t uid, const std::optional<uint32_t> currentOwner) {
    if (uid == 0) throw Invalid("linux uid must be a positive integer");
    if (uid == ::getuid()) throw Invalid("the Vaulthalla service account cannot be bound to a user");
    if (const auto holder = vh::identities::manager().userByLinuxUid(uid); holder && holder->id != currentOwner)
        throw Conflict("linux uid " + std::to_string(uid) + " is already bound to " + holder->name());
}

// The account's global vault policy (user_global_vault_policy) is seeded from its role when the role is assigned,
// then owned by the account. Roles loaded from admin_role carry none: a built-in role seeds its preset, a custom role
// seeds unprivileged.
void applyRolePreset(rbac::role::Admin& role, const uint32_t userId) {
    const auto preset = rbac::role::Admin::builtin(role.name, userId);
    role.vGlobals = (preset ? *preset : rbac::role::Admin::None(userId)).vGlobals;
}

// The users list (filter on name, sort, page) over the identities::Manager index; the same semantics the SQL list had
// (ILIKE '%filter%', ORDER BY <column> <direction> with id ascending by default, LIMIT/OFFSET with 100 per page).
std::vector<UserPtr> listUsersPage(db::model::ListQueryParams params) {
    auto all = vh::identities::manager().users();
    std::vector<std::pair<UserPtr, std::shared_ptr<const identities::UserState>>> rows;
    rows.reserve(all.size());
    const auto lower = [](std::string v) {
        std::ranges::transform(v, v.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return v;
    };
    const auto needle = params.filter ? lower(*params.filter) : std::string{};
    for (auto& u : all) {
        auto s = u->state();
        if (params.filter && lower(s->name).find(needle) == std::string::npos) continue;
        rows.emplace_back(std::move(u), std::move(s));
    }

    const std::string column = params.sort.value_or("id");
    const bool desc = params.sort && params.direction == db::model::SortDirection::DESC;
    const auto key = [&](const auto& row) -> std::tuple<int64_t, std::string> {
        const auto& [u, s] = row;
        if (column == "id") return {u->id, {}};
        if (column == "name") return {0, s->name};
        if (column == "email") return {0, s->email.value_or("")};
        if (column == "created_at") return {s->meta.created_at, {}};
        if (column == "updated_at") return {s->meta.updated_at, {}};
        if (column == "last_login") return {s->meta.last_login.value_or(0), {}};
        if (column == "is_active") return {s->meta.is_active ? 1 : 0, {}};
        if (column == "linux_uid") return {s->meta.linux_uid ? static_cast<int64_t>(*s->meta.linux_uid) : -1, {}};
        throw Invalid("Invalid sort column: " + column);
    };
    std::ranges::stable_sort(rows, [&](const auto& a, const auto& b) {
        const auto ka = key(a), kb = key(b);
        return desc ? kb < ka : ka < kb;
    });

    const uint64_t page = std::max<uint64_t>(params.page.value_or(1), 1);
    const uint64_t limit = params.limit.value_or(100);
    std::vector<UserPtr> out;
    for (uint64_t i = (page - 1) * limit; i < rows.size() && out.size() < limit; ++i) out.push_back(rows[i].first);
    return out;
}

std::string generatePassword() {
    const std::size_t length = paths::testMode ? 8 : 84;
    for (int attempt = 0; attempt < 4096; ++attempt)
        if (auto password = crypto::hash::generate_secure_password(length);
            auth::registration::Validator::isValidPassword(password)) return password;
    throw std::runtime_error("failed to generate a password that meets the password policy");
}

}

bool isAdminIdentity(const rbac::role::Admin& role) {
    return role.identities.toMask() || role.audits.toMask() || role.stats.toMask() || role.upstream.toMask() ||
           role.settings.toMask() || role.roles.toMask() || role.s3Gateway.toMask() || role.vaults.admin.raw() || role.vaults.user.raw() ||
           role.keys.apiKeys.admin.raw() || role.keys.apiKeys.user.raw() || role.keys.encryptionKeys.raw();
}

Created create(const Actor& actor, const Create& req) {
    requireActor(actor);
    const auto role = requireRole(req.role);
    if (!can(actor, IdPerm::Add, role)) throw Denied(std::string("you do not have permission to create ") + kindOf(role));
    requireAssignable(actor, role);

    requireValidName(req.name);
    requireValidEmail(req.email);
    if (vh::identities::manager().userByName(req.name)) throw Conflict("a user named '" + req.name + "' already exists");
    if (req.linux_uid) requireBindableUid(*req.linux_uid, std::nullopt);

    identities::UserState draft;
    draft.name = req.name;
    draft.email = req.email && !req.email->empty() ? req.email : std::nullopt;
    draft.meta.is_active = req.is_active;
    applyRolePreset(*role, 0);
    draft.roles.admin = role;
    draft.meta.linux_uid = req.linux_uid;
    draft.meta.created_by = actor->id;
    draft.meta.updated_by = actor->id;

    Created out;
    if (!req.password) out.generated_password = generatePassword();
    try {
        out.user = runtime::Deps::get().authManager->registerUser(draft, req.password ? *req.password : *out.generated_password);
    } catch (const std::exception& e) {
        // The registration validator refuses a weak or breached password; that is the request's fault.
        throw Invalid(e.what());
    }
    log::Registry::audit()->info("[ops::users] {} created user {} with role {}", actor->name(), req.name, role->name);
    return out;
}

UserPtr update(const Actor& actor, const Update& req) {
    requireActor(actor);
    const auto target = requireUser(req.id);
    // Decisions are taken against one state; the edit below is applied to a copy of the newest one.
    const auto current = target->state();
    const bool isSelf = target->id == actor->id;
    if (isSelf) {
        if (current->isProtected) throw Denied("protected accounts cannot be updated here: " + current->name);
    } else {
        requireManage(actor, *current, IdPerm::Edit, "updated");
    }

    bool endSessions = false;
    std::optional<std::string> name;
    std::optional<std::optional<std::string>> email;
    std::optional<bool> active;
    AdminRolePtr newRole;
    std::optional<std::optional<uint32_t>> linuxUid;

    if (req.name && *req.name != current->name) {
        if (current->hasSuperAdminRole()) throw Denied("the super admin account cannot be renamed");
        requireValidName(*req.name);
        if (vh::identities::manager().userByName(*req.name))
            throw Conflict("a user named '" + *req.name + "' already exists");
        name = *req.name;
    }
    if (req.email) {
        requireValidEmail(*req.email);
        email = *req.email && !(*req.email)->empty() ? *req.email : std::nullopt;
    }
    if (req.is_active && *req.is_active != current->meta.is_active) {
        if (isSelf) throw Denied("you cannot deactivate or reactivate your own account");
        active = *req.is_active;
        if (!*req.is_active) endSessions = true;
    }
    if (req.role) {
        const auto role = requireRole(*req.role);
        if (!current->roles.admin || role->id != current->roles.admin->id) {
            // Role changes are privilege changes: never on your own account, and judged by the resolved role.
            if (isSelf) throw Denied("you cannot change your own role; ask another administrator");
            requireAssignable(actor, role);
            if (!can(actor, IdPerm::Edit, role))
                throw Denied(std::string("you do not have permission to manage ") + kindOf(role));
            role->user_id = target->id;
            applyRolePreset(*role, target->id);
            newRole = role;
            endSessions = true;   // live sessions carry the old role
        }
    }
    if (req.linux_uid && req.linux_uid != current->meta.linux_uid) {
        // The CLI authenticates by Linux UID: rebinding your own would let you take over another account's.
        if (isSelf) throw Denied("you cannot change your own Linux UID binding; ask another administrator");
        requireBindableUid(*req.linux_uid, target->id);
        linuxUid = req.linux_uid;
    }

    (void)vh::identities::manager().updateUser(target->id, [&](identities::UserState& s) {
        if (name) s.name = *name;
        if (email) s.email = *email;
        if (active) {
            s.meta.is_active = *active;
            s.meta.deactivated_at = *active ? std::nullopt : std::make_optional(std::time(nullptr));
        }
        if (newRole) s.roles.admin = newRole;
        if (linuxUid) s.meta.linux_uid = *linuxUid;
        s.meta.updated_by = actor->id;
    });
    if (endSessions) runtime::Deps::get().authManager->revokeSessions(target->id);
    return target;
}

UserPtr remove(const Actor& actor, const Remove& req) {
    requireActor(actor);
    const auto target = requireUser(req.id);
    if (target->id == actor->id) throw Denied("you cannot delete your own account; ask another administrator");
    requireManage(actor, *target->state(), IdPerm::Delete, "deleted");
    const auto targetName = target->name();

    std::shared_ptr<identities::User> heir;
    if (req.transfer_to) {
        heir = requireUser(*req.transfer_to);
        if (heir->id == target->id) throw Invalid("vaults can't be transferred to the account being deleted");
        if (!heir->isActive()) throw Invalid("vaults can't be transferred to a deactivated account: " + heir->name());
    }

    const auto owned = db::query::vault::Vault::listUserVaults(target->id);

    // The account's API keys go with it (api_keys.user_id cascades), and a key still bound to a vault blocks it
    // (s3.api_key_id is ON DELETE RESTRICT; it used to cascade and silently drop the vault's S3 binding). A deleted
    // vault keeps its binding until it is purged (#162: a restore or an upstream purge needs the key), so the
    // account's own S3 vaults block it too until they are purged. Refuse up front, before anything changes.
    std::string blocked;
    for (const auto& key : db::query::vault::APIKey::listAPIKeys(target->id))
        for (const auto& [vaultId, vaultName] : db::query::vault::APIKey::listVaultsUsingKey(key->id))
            blocked += (blocked.empty() ? "" : ", ") + vaultName + " (ID " + std::to_string(vaultId) + ", API key " +
                       key->name + ")";
    if (!blocked.empty())
        throw Invalid(targetName + " owns API keys still used by vaults: " + blocked +
                      ". Move those vaults to another API key, or delete them and let them be purged "
                      "(`vh vault delete <id> --now`) first.");

    if (!req.confirmed) {
        std::string text = USER_DELETE_CONFIRMATION;
        if (!owned.empty()) {
            text += "\n" + targetName + " owns " + std::to_string(owned.size()) + " vault(s):";
            for (const auto& v : owned) text += " " + v->name + ";";
            if (heir) text += "\nThey will be transferred to " + heir->name() + ".";
            else {
                // Deleted like any vault (#162): restorable for the retention window, keys kept for theirs.
                text += "\nThey will be deleted: restorable with `vh vault restore` for " +
                        vh::config::durationToString(vault::retention::windowsFor(vault::model::VaultType::Local).retention_window) +
                        ", then purged. Their encryption keys are kept for the key retention window.";
                for (const auto& v : owned) {
                    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(v);
                    if (s3 && s3->encrypt_upstream && !db::query::vault::Key::currentKeyExportedAt(v->id))
                        text += "\nWARNING: " + v->name + " keeps encrypted data in bucket '" + s3->bucket +
                                "' and its key was never exported; without it that data can never be decrypted. Export "
                                "it first: " + vault::model::keyExportCommand(v->id);
                }
            }
        }
        throw NeedsConfirmation("user_delete", text);
    }

    // Every vault is checked before anything changes, so a refusal leaves the account and its vaults as they were.
    for (const auto& v : owned) {
        if (heir) vaults::requireTransferable(actor, v->id, heir->id);
        else vaults::requireRemovable(actor, v->id);
    }
    for (const auto& v : owned) {
        if (heir) (void)vaults::update(actor, {.id = v->id, .owner_id = heir->id});
        // The user_delete confirmation above listed the key warnings: it is the acceptance.
        else (void)vaults::remove(actor, {.id = v->id, .accept_key_loss = true});
    }

    runtime::Deps::get().authManager->revokeSessions(target->id);
    vh::identities::manager().deleteUser(target->id);
    // Every outstanding reference to the account now holds a non-authorizing tombstone.
    if (!target->deleted() || vh::identities::manager().user(target->id))
        throw std::runtime_error("failed to delete user " + std::to_string(target->id));
    log::Registry::audit()->info("[ops::users] {} deleted user {} ({} vault(s) {})", actor->name(), targetName, owned.size(),
                                 heir ? "transferred to " + heir->name() : std::string("destroyed"));
    return target;
}

UserPtr get(const Actor& actor, const uint32_t id) {
    requireActor(actor);
    auto target = requireUser(id);
    const auto role = adminRoleOf(*target->state());
    if (target->id != actor->id && !can(actor, IdPerm::View, role))
        throw Denied(std::string("you do not have permission to view ") + kindOf(role));
    return target;
}

UserPtr getByName(const Actor& actor, const std::string& name) {
    requireActor(actor);
    const auto target = vh::identities::manager().userByName(name);
    if (!target) throw NotFound("user not found: " + name);
    return get(actor, target->id);
}

std::vector<UserPtr> list(const Actor& actor, db::model::ListQueryParams params) {
    requireActor(actor);
    const bool users = can(actor, IdPerm::View, nullptr);
    const bool admins = rbac::resolver::Admin::has<IdPerm>({.user = actor, .permission = IdPerm::View, .identity = Entity::Admin});
    if (!users && !admins) throw Denied("you do not have permission to list users");

    auto all = listUsersPage(std::move(params));
    if (users && admins) return all;
    std::erase_if(all, [&](const UserPtr& u) {
        return u->id != actor->id && roleIsAdminIdentity(adminRoleOf(*u->state())) != admins;
    });
    return all;
}

UserPtr requireSuperAdminOperator(const Actor& actor) {
    requireActor(actor);
    const auto admin = vh::identities::manager().userByName(auth::bootstrap::kSuperAdminName);
    if (!admin) throw NotFound(std::string("the '") + auth::bootstrap::kSuperAdminName + "' account does not exist");
    const auto adminUid = admin->linuxUid();
    if (!adminUid)
        throw Denied("no Linux user is bound as the Vaulthalla super admin yet; run 'vh setup assign-admin' as that user");
    if (actor->id != admin->id || actor->linuxUid() != adminUid)
        throw Denied("only the Linux user bound as the Vaulthalla super admin (UID " +
                     std::to_string(*adminUid) + ") may set this password; run it as that user, without sudo");
    return admin;
}

SuperAdminPasswordSet setSuperAdminPassword(const Actor& actor, const std::string& newPassword) {
    const auto admin = requireSuperAdminOperator(actor);
    const auto& auth = runtime::Deps::get().authManager;
    SuperAdminPasswordSet out;
    try {
        out.user = auth->resetPassword(admin->id, newPassword);   // records the rotation and removes the copy
    } catch (const Error&) {
        throw;
    } catch (const std::exception& e) {
        throw Invalid(e.what());   // the password policy refused it
    }
    auth->revokeSessions(admin->id);
    if (auth::bootstrap::initialPasswordFileExists()) out.leftover_file = auth::bootstrap::removeInitialPasswordFile();
    return out;
}

UserPtr changePassword(const Actor& actor, const uint32_t id, const std::optional<std::string>& currentPassword,
                       const std::string& newPassword) {
    requireActor(actor);
    const auto target = requireUser(id);
    const auto& auth = runtime::Deps::get().authManager;
    try {
        if (target->id == actor->id) {
            if (!currentPassword || currentPassword->empty()) throw Invalid("your current password is required");
            return auth->changePassword(target->id, *currentPassword, newPassword);
        }
        requireManage(actor, *target->state(), IdPerm::ResetPassword, "reset");
        auto updated = auth->resetPassword(target->id, newPassword);
        auth->revokeSessions(target->id);
        return updated;
    } catch (const Error&) {
        throw;
    } catch (const std::exception& e) {
        // Wrong current password, or a new one the policy refuses.
        throw Invalid(e.what());
    }
}

}
