#include "auth/mfa/Policy.hpp"

#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Passkeys.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/session/Assurance.hpp"
#include "config/Registry.hpp"
#include "identities/User.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/permission/admin/all.hpp"

#include <algorithm>
#include <mutex>
#include <unordered_map>

namespace vh::auth::mfa::policy {

namespace {

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

std::optional<Level> parseLevel(const std::string_view name) noexcept {
    for (const auto l : {Level::Optional, Level::Admins, Level::All})
        if (to_string(l) == name) return l;
    return std::nullopt;
}

Level level() noexcept {
    // config validation admits only the three names; anything else reads as the default (D2), never as optional.
    return parseLevel(config::Registry::get().auth.mfa.policy).value_or(Level::Admins);
}

void setLevel(const Level next) {
    auto cfg = config::Registry::get();
    cfg.auth.mfa.policy = std::string(to_string(next));
    config::Registry::set(cfg);
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

FactorRule factorRule(const identities::User& user) {
    const auto& mfa = config::Registry::get().auth.mfa;
    if (!(mfa.admin_webauthn_only || mfa.admin_device_bound_only) || !privileged(user)) return {};
    return {.totp = false, .synced_passkeys = !mfa.admin_device_bound_only};
}

bool factorAllowed(const identities::User& user, const FactorKind kind, const bool backupEligible) {
    const auto rule = factorRule(user);
    if (kind == FactorKind::Totp) return rule.totp;
    return rule.synced_passkeys || !backupEligible;
}

bool factorAllowed(const identities::User& user, const Factor& factor) {
    return factorAllowed(user, factor.kind, factor.backup_eligible.value_or(false));
}

bool hasAllowedFactor(const identities::User& user) {
    if (!factorRule(user).restricted()) return hasUsableFactor(user.id);
    return std::ranges::any_of(factors(user.id),
                               [&](const Factor& f) { return !f.suspended && factorAllowed(user, f); });
}

std::vector<WebAuthnCredential> allowedPasskeys(const identities::User& user, const bool excludeRecovery) {
    auto out = passkeys::usableCredentials(user.id);
    std::erase_if(out, [&](const WebAuthnCredential& c) {
        return !factorAllowed(user, FactorKind::WebAuthn, c.backup_eligible) ||
               (excludeRecovery && c.created_during_recovery);
    });
    return out;
}

bool hasAllowedTotp(const identities::User& user, const bool excludeRecovery) {
    if (!factorRule(user).totp) return false;
    return std::ranges::any_of(factors(user.id), [&](const Factor& f) {
        return f.kind == FactorKind::Totp && !f.suspended && !(excludeRecovery && f.created_during_recovery);
    });
}

bool rowSatisfies(const identities::User& user, const model::RefreshToken& row) {
    if (row.aal >= 2) {
        const auto rule = factorRule(user);
        if (!rule.restricted()) return true;
        // An admin held to passkeys (or device-bound ones): only a proof the rule allows keeps the session. A
        // recovery-code session stays, to enroll an allowed factor.
        return std::ranges::any_of(row.amr, [&](const std::string& m) {
            return m == session::assurance::kHardwareKey || m == session::assurance::kRecoveryCode ||
                   (m == session::assurance::kSoftwareKey && rule.synced_passkeys);
        });
    }
    if (policyLevelReason(user) != Reason::None) return false;
    // A database error propagates: the request is refused (never the row revoked) until the flag can be read.
    return !policyUserRequiredCached(user.id);
}

void install() { session::assurance::setPolicy(&rowSatisfies); }

std::vector<std::string> weakenings(const config::AuthConfig& from, const config::AuthConfig& to) {
    std::vector<std::string> out;
    // How many accounts a level holds to MFA: optional < admins < all.
    const auto rank = [](const std::string& name) { return static_cast<int>(parseLevel(name).value_or(Level::Admins)); };
    if (rank(to.mfa.policy) < rank(from.mfa.policy)) out.emplace_back("policy");
    if (from.mfa.admin_webauthn_only && !to.mfa.admin_webauthn_only) out.emplace_back("admin_webauthn_only");
    if (from.mfa.admin_device_bound_only && !to.mfa.admin_device_bound_only) out.emplace_back("admin_device_bound_only");
    // Passkeys registered for the old relying party stop working (turning passkeys on for the first time doesn't).
    if (!from.webauthn.rp_id.empty() && from.webauthn.rp_id != to.webauthn.rp_id) out.emplace_back("webauthn.rp_id");
    return out;
}

bool policyChanged(const config::AuthConfig& from, const config::AuthConfig& to) {
    return from.mfa.policy != to.mfa.policy || from.mfa.admin_webauthn_only != to.mfa.admin_webauthn_only ||
           from.mfa.admin_device_bound_only != to.mfa.admin_device_bound_only ||
           from.webauthn.rp_id != to.webauthn.rp_id;
}

}
