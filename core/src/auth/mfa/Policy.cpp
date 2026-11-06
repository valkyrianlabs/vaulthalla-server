#include "auth/mfa/Policy.hpp"

#include "auth/mfa/Factors.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/session/Assurance.hpp"
#include "identities/User.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/permission/admin/all.hpp"

#include <atomic>
#include <mutex>
#include <unordered_map>

namespace vh::auth::mfa::policy {

namespace {

std::atomic<Level>& policyLevel() {
    static std::atomic<Level> level{Level::Admins};  // D2: every install, new or upgraded
    return level;
}

// user_mfa.required per account, valid for one policy epoch: a requirement change bumps the epoch (#360's
// auth.mfa.admin.require calls assurance::policyChanged()).
struct PolicyRequiredCache {
    std::mutex mutex;
    uint64_t epoch{0};
    std::unordered_map<uint32_t, bool> required;
};

PolicyRequiredCache& policyRequiredCache() {
    static PolicyRequiredCache cache;
    return cache;
}

bool policyUserRequired(const uint32_t userId) {
    const auto state = userState(userId);
    return state && state->required;
}

bool policyUserRequiredCached(const uint32_t userId) {
    auto& cache = policyRequiredCache();
    const auto epoch = rbac::policyEpoch();
    {
        std::lock_guard lock(cache.mutex);
        if (cache.epoch != epoch) {
            cache.required.clear();
            cache.epoch = epoch;
        }
        if (const auto it = cache.required.find(userId); it != cache.required.end()) return it->second;
    }
    const bool required = policyUserRequired(userId);
    std::lock_guard lock(cache.mutex);
    if (cache.epoch == epoch) cache.required[userId] = required;
    return required;
}

bool policySettingsEditable(const rbac::permission::admin::Settings& s) {
    return s.websocket.canEdit() || s.http.canEdit() || s.database.canEdit() || s.auth.canEdit() ||
           s.logging.canEdit() || s.caching.canEdit() || s.sharing.canEdit() || s.services.canEdit();
}

// The level's own answer, without the per-account flag.
Reason policyLevelReason(const identities::User& user) {
    switch (level()) {
        case Level::All: return Reason::PolicyAll;
        case Level::Admins: return privileged(user) ? Reason::PolicyAdmins : Reason::None;
        case Level::Optional: return Reason::None;
    }
    return Reason::None;
}

}

std::string_view to_string(const Level level) noexcept {
    switch (level) {
        case Level::Optional: return "optional";
        case Level::Admins: return "admins";
        case Level::All: return "all";
    }
    return "admins";
}

std::string_view to_string(const Reason reason) noexcept {
    switch (reason) {
        case Reason::None: return "none";
        case Reason::PolicyAdmins: return "policy_admins";
        case Reason::PolicyAll: return "policy_all";
        case Reason::UserRequired: return "user_required";
    }
    return "none";
}

Level level() noexcept { return policyLevel().load(std::memory_order_acquire); }

void setLevel(const Level next) {
    policyLevel().store(next, std::memory_order_release);
    session::assurance::policyChanged();
}

bool privileged(const identities::User& user) {
    if (!user.authorizing() || user.systemOnly()) return false;
    if (user.isSuperAdmin() || user.isAdmin()) return true;
    const auto users = user.users();
    const auto admins = user.admins();
    for (const auto* identity : {static_cast<const rbac::permission::admin::identities::Base*>(&users),
                                 static_cast<const rbac::permission::admin::identities::Base*>(&admins)})
        if (identity->canAdd() || identity->canEdit() || identity->canDelete() || identity->canResetPassword())
            return true;
    const auto adminRoles = user.adminRolePerms();
    const auto vaultRoles = user.vaultRolePerms();
    for (const auto* roles : {static_cast<const rbac::permission::admin::roles::Base*>(&adminRoles),
                              static_cast<const rbac::permission::admin::roles::Base*>(&vaultRoles)})
        if (roles->canAdd() || roles->canEdit() || roles->canDelete()) return true;
    if (policySettingsEditable(user.settings())) return true;
    const auto keys = user.encryptionKeysPerms();
    return keys.canExport() || keys.canRotate();
}

Requirement requirement(const identities::User& user) {
    if (user.systemOnly()) return {};
    if (const auto reason = policyLevelReason(user); reason != Reason::None) return {.required = true, .reason = reason};
    if (policyUserRequired(user.id)) return {.required = true, .reason = Reason::UserRequired};
    return {};
}

bool rowSatisfies(const identities::User& user, const model::RefreshToken& row) {
    if (row.aal >= 2) return true;
    if (policyLevelReason(user) != Reason::None) return false;
    // A database error propagates: the request is refused (never the row revoked) until the flag can be read.
    return !policyUserRequiredCached(user.id);
}

void install() { session::assurance::setPolicy(&rowSatisfies); }

}
