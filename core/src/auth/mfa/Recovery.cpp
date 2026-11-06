#include "auth/mfa/Recovery.hpp"

#include "audit/Trail.hpp"
#include "auth/Manager.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/device/Device.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "notifications/AccountSecurity.hpp"
#include "ops/Sessions.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <algorithm>
#include <ctime>

namespace vh::auth::mfa::recovery {

namespace {

int64_t recoveryNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string recoveryTime(const int64_t unix) {
    const auto t = static_cast<std::time_t>(unix);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

std::size_t recoveryLiveRows(const uint32_t userId) {
    std::size_t n = 0;
    for (const auto& row : db::query::auth::RefreshToken::list(userId))
        if (row && !row->revoked) ++n;
    return n;
}

}

std::string_view to_string(const Reason reason) noexcept {
    switch (reason) {
        case Reason::RecoveryCode: return "recovery_code";
        case Reason::AdminReset: return "admin_reset";
        case Reason::CliReset: return "cli_reset";
    }
    return "recovery_code";
}

std::chrono::hours cooldown() {
    return std::chrono::hours(std::clamp(config::Registry::get().auth.mfa.recovery_cooldown_hours, 1u, 168u));
}

namespace {
std::function<std::optional<int64_t>(uint32_t)>& recoveryCooldownSource() {
    static std::function<std::optional<int64_t>(uint32_t)> source;
    return source;
}
}

CooldownSourceForTesting::CooldownSourceForTesting(std::function<std::optional<int64_t>(uint32_t)> source) {
    recoveryCooldownSource() = std::move(source);
}

CooldownSourceForTesting::~CooldownSourceForTesting() { recoveryCooldownSource() = nullptr; }

std::optional<int64_t> cooldownUntil(const uint32_t userId) {
    if (const auto& source = recoveryCooldownSource()) return source(userId);
    const auto state = userState(userId);
    if (!state || !state->recovery_cooldown_until || *state->recovery_cooldown_until <= recoveryNow())
        return std::nullopt;
    return state->recovery_cooldown_until;
}

bool enrollingDuringRecovery(const uint32_t userId, const bool recoveryRestrictedSession) {
    return recoveryRestrictedSession || cooldownUntil(userId).has_value();
}

void to_json(nlohmann::json& j, const DeviceSummary& d) {
    j = {{"id", d.id},
         {"name", d.name},
         {"platform", d.platform},
         {"last_seen_at", d.last_seen_at ? nlohmann::json(*d.last_seen_at) : nlohmann::json(nullptr)},
         {"key_backup_revoked", d.key_backup_revoked}};
}

void to_json(nlohmann::json& j, const ResetEffects& e) {
    j = {{"factors_disabled", e.factors_disabled},
         {"recovery_batches_voided", e.recovery_batches_voided},
         {"sessions_revoked", e.sessions_revoked},
         {"grants_revoked", e.grants_revoked},
         {"cooldown_until", e.cooldown_until}};
}

std::vector<DeviceSummary> devices(const uint32_t userId) {
    std::vector<DeviceSummary> out;
    for (const auto& d : db::query::device::Devices::listForUser(userId)) {
        if (d.revoked()) continue;
        out.push_back({.id = d.id,
                       .name = d.name,
                       .platform = d.platform,
                       .last_seen_at = d.last_seen_at ? std::optional<int64_t>(*d.last_seen_at) : std::nullopt,
                       .key_backup_revoked = d.key_backup_revoked_at.has_value()});
    }
    return out;
}

std::size_t revokeKeyBackupGrants(const uint32_t userId, const Reason reason, const std::optional<uint32_t> actorId) {
    const auto ids = db::query::device::Devices::revokeKeyBackup(userId, std::string(to_string(reason)));
    for (const auto id : ids)
        vh::audit::record({.action = "keys.backup.grant.revoke",
                           .actor_id = actorId,
                           .details = {{"device", id}, {"user_id", userId}, {"reason", std::string(to_string(reason))}}},
                          "[auth::mfa] the key-backup grant of device " + std::to_string(id) + " (user " +
                              std::to_string(userId) + ") was revoked: " + std::string(to_string(reason)),
                          spdlog::level::warn);
    return ids.size();
}

SignInEffects afterRecoveryCodeSignIn(const std::shared_ptr<protocols::ws::Session>& session,
                                      const std::string& batchId, const std::size_t codesRemaining) {
    if (!session || !session->user || !session->tokens || !session->tokens->refreshToken)
        throw std::logic_error("a recovery-code sign-in has a signed-in session");
    const auto& user = session->user;
    SignInEffects out;
    out.cooldown_until = startRecoveryCooldown(user->id, cooldown());
    out.sessions_revoked =
        ops::sessions::revoke(user, session->tokens->refreshToken->jti, {.all_others = true}, session);
    out.grants_revoked = revokeKeyBackupGrants(user->id, Reason::RecoveryCode, user->id);
    out.devices = devices(user->id);

    vh::audit::record({.action = "auth.mfa.recovery.signin", .outcome = vh::audit::Outcome::Info,
                       .actor_id = user->id, .actor = user->name(),
                       .details = {{"batch_id", batchId}, {"remaining", codesRemaining},
                                   {"sessions_revoked", out.sessions_revoked}, {"grants_revoked", out.grants_revoked},
                                   {"devices", out.devices.size()}, {"cooldown_until", out.cooldown_until}}},
                      "[auth] " + user->name() + " signed in with a recovery code; other web sessions were signed "
                      "out and key-backup grants revoked",
                      spdlog::level::warn);

    notifications::account::send({
        .event = "mfa.recovery_signin",
        .title = "Recovery code used",
        .summary = "Someone signed in to this account with its password and a recovery code. Every other browser was "
                   "signed out, and sensitive actions wait until the cooldown ends.",
        .user_id = user->id,
        .facts = {{"Recovery codes left", std::to_string(codesRemaining)},
                  {"Other sessions signed out", std::to_string(out.sessions_revoked)},
                  {"Device key backups paused", std::to_string(out.grants_revoked)},
                  {"Cooldown until", recoveryTime(out.cooldown_until)},
                  {"From", session->ipAddress}},
        .advice = "If this wasn't you, ask an administrator to reset this account's MFA and change its password now.",
    });
    return out;
}

ResetEffects reset(const identities::User& target, const Resetter& by, const std::string_view reason) {
    ResetEffects out;
    (void)ensureUser(target.id);
    const auto hours = static_cast<int>(cooldown().count());
    std::vector<std::pair<std::string, uint32_t>> disabled;  // kind, id
    db::Transactions::exec("auth::mfa::recovery::reset", [&](pqxx::work& txn) {
        for (const auto& r : txn.exec("UPDATE webauthn_credentials SET disabled_at = NOW() WHERE user_id = $1 "
                                      "AND disabled_at IS NULL RETURNING id",
                                      pqxx::params{target.id}))
            disabled.emplace_back("webauthn", r[0].as<uint32_t>());
        // Unfinished authenticator setups go too; only confirmed ones were factors.
        for (const auto& r : txn.exec("UPDATE totp_factors SET disabled_at = NOW() WHERE user_id = $1 "
                                      "AND disabled_at IS NULL RETURNING id, confirmed_at IS NOT NULL",
                                      pqxx::params{target.id}))
            if (r[1].as<bool>()) disabled.emplace_back("totp", r[0].as<uint32_t>());
        out.recovery_batches_voided = static_cast<std::size_t>(
            txn.exec("UPDATE recovery_code_batches SET superseded_at = NOW() WHERE user_id = $1 "
                     "AND superseded_at IS NULL",
                     pqxx::params{target.id}).affected_rows());
        // required: the next sign-in is the guided enrollment, whatever the policy level.
        out.cooldown_until =
            txn.exec("UPDATE user_mfa SET required = TRUE, reset_at = NOW(), reset_by = $2, "
                     "recovery_cooldown_until = GREATEST(COALESCE(recovery_cooldown_until, NOW()), "
                     "NOW() + make_interval(hours => $3)) WHERE user_id = $1 "
                     "RETURNING EXTRACT(EPOCH FROM recovery_cooldown_until)::BIGINT",
                     pqxx::params{target.id, by.id, hours}).one_field().as<int64_t>();
    });
    out.factors_disabled = disabled.size();
    session::assurance::policyChanged();

    const auto channel = std::string(to_string(by.channel));
    for (const auto& [kind, id] : disabled)
        vh::audit::record({.action = "auth.mfa.factor.remove", .actor_id = by.id, .actor = by.name,
                           .details = {{"factor_id", id}, {"kind", kind}, {"target_id", target.id},
                                       {"reason", channel}}},
                          "[auth::mfa] " + std::string(kind) + " factor " + std::to_string(id) + " of user " +
                              std::to_string(target.id) + " was disabled by an MFA reset");

    out.sessions_revoked = recoveryLiveRows(target.id);
    if (const auto& auth = runtime::Deps::get().authManager) auth->revokeSessions(target.id);
    out.grants_revoked = revokeKeyBackupGrants(target.id, by.channel, by.id);

    vh::audit::record({.action = "auth.mfa.admin.reset", .actor_id = by.id, .actor = by.name,
                       .details = {{"target_id", target.id}, {"reason", std::string(reason)}, {"channel", channel},
                                   {"factors_disabled", out.factors_disabled},
                                   {"recovery_batches_voided", out.recovery_batches_voided},
                                   {"sessions_revoked", out.sessions_revoked}, {"grants_revoked", out.grants_revoked},
                                   {"cooldown_until", out.cooldown_until}}},
                      "[auth::mfa] " + (by.name.empty() ? std::string("the host") : by.name) + " reset the MFA of " +
                          target.name() + " (" + channel + ")",
                      spdlog::level::warn);
    log::Registry::auth()->warn("[auth::mfa] MFA of user {} reset ({}): {} factors disabled, {} sessions signed out",
                                target.id, channel, out.factors_disabled, out.sessions_revoked);

    notifications::account::send({
        .event = "mfa.reset",
        .title = "MFA reset",
        .summary = "This account's passkeys, authenticator apps and recovery codes were reset. It must set up a new "
                   "second factor at its next sign-in, and sensitive actions wait until the cooldown ends.",
        .user_id = target.id,
        .facts = {{"Reset by", by.name.empty() ? std::string("the server host") : by.name},
                  {"Through", by.channel == Reason::CliReset ? "vh CLI on the server" : "web console"},
                  {"Factors disabled", std::to_string(out.factors_disabled)},
                  {"Sessions signed out", std::to_string(out.sessions_revoked)},
                  {"Cooldown until", recoveryTime(out.cooldown_until)}},
        .advice = "If you didn't ask for this, tell your administrator now.",
    });
    return out;
}

}
