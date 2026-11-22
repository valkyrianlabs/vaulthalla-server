#include "connector/Grants.hpp"

#include "audit/Trail.hpp"
#include "crypto/util/hash.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "notifications/AccountSecurity.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <ctime>

namespace vh::connector {

// Named, not anonymous: the unity build joins this file with others that have helpers of the same names.
namespace connector_grants_detail {

using Json = nlohmann::json;
namespace q = db::query::connector;

constexpr std::array kRevocations{
    std::pair{Revocation::Manual, std::string_view("manual")},
    std::pair{Revocation::UserInactive, std::string_view("user_inactive")},
    std::pair{Revocation::GrantorPolicy, std::string_view("grantor_policy")},
    std::pair{Revocation::RefreshReuse, std::string_view("refresh_reuse")},
    std::pair{Revocation::CodeReuse, std::string_view("code_reuse")},
    std::pair{Revocation::SwitchOff, std::string_view("switch_off")},
    std::pair{Revocation::Expired, std::string_view("expired")},
    std::pair{Revocation::ClientRemoved, std::string_view("client_removed")},
    std::pair{Revocation::SessionsRevoked, std::string_view("sessions_revoked")},
    std::pair{Revocation::MfaRecovery, std::string_view("mfa_recovery")},
};

Grant toGrant(q::GrantRow row) {
    const auto scope = vh::mcp::parseCeiling(row.scope).value_or(Scope::Read);  // the CHECK allows only the three
    return {.row = std::move(row), .scope = scope};
}

std::string actorName(const std::optional<uint32_t> id) {
    if (!id) return "vaulthalla";
    const auto u = identities::manager().user(*id);
    return u ? u->name() : "user " + std::to_string(*id);
}

std::string shortId(const std::string& grantId) { return grantId.substr(0, 8); }

void grantAudit(const std::string& action, const q::GrantRow& g, const std::optional<uint32_t> actorId,
                const std::string& actor, Json extra, const std::string& message,
                const spdlog::level::level_enum level = spdlog::level::info) {
    Json details{{"grant_id", g.id}, {"user_id", g.user_id}, {"scope", g.scope}};
    for (auto& [k, v] : extra.items()) details[k] = std::move(v);
    vh::audit::record({.action = action, .actor_id = actorId, .actor = actor, .details = std::move(details)}, message,
                      level);
}

void auditRevoked(const q::GrantRow& g, const Revocation why, const Revoker& by) {
    grantAudit("connector.grant.revoke", g, by.id, by.name.empty() ? actorName(by.id) : by.name,
               {{"reason", std::string(to_string(why))}},
               "[connector] grant " + shortId(g.id) + " of user " + std::to_string(g.user_id) + " was revoked (" +
                   std::string(to_string(why)) + ")",
               why == Revocation::RefreshReuse || why == Revocation::CodeReuse ? spdlog::level::warn : spdlog::level::info);
}

void noticeReuse(const q::GrantRow& g, const Revocation why) {
    notifications::account::send({
        .event = "connector.grant.reuse",
        .title = "A connected app was disconnected",
        .summary = "A sign-in token of an app connected to your account was used twice, which can mean it was copied. "
                   "The connection was ended; reconnect the app if you still use it.",
        .user_id = g.user_id,
        .facts = {{"grant", shortId(g.id)}, {"reason", std::string(to_string(why))}},
        .advice = std::string("If you did not expect this, review your connected apps and sign-in factors."),
    });
}

}

std::string_view to_string(const Revocation r) noexcept {
    for (const auto& [value, name] : connector_grants_detail::kRevocations)
        if (value == r) return name;
    return "?";
}

std::optional<Revocation> parseRevocation(const std::string_view s) noexcept {
    for (const auto& [value, name] : connector_grants_detail::kRevocations)
        if (name == s) return value;
    return std::nullopt;
}

std::string auditOrigin(const Grant& grant) {
    return "connector " + grant.row.id.substr(0, 8) + " scope " + std::string(protocols::shell::effectName(grant.scope));
}

bool mayGrant(const identities::User& user) { return user.authorizing() && user.isSuperAdmin(); }

std::string mintToken(const std::string_view prefix) {
    std::array<unsigned char, 32> raw{};
    randombytes_buf(raw.data(), raw.size());
    std::array<char, 64> b64{};
    sodium_bin2base64(b64.data(), b64.size(), raw.data(), raw.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    sodium_memzero(raw.data(), raw.size());
    return std::string(prefix) + b64.data();
}

std::string digestOf(const std::string_view token) { return crypto::hash::tokenDigest(token); }

Grant create(const identities::User& approver, const NewGrant& g) {
    namespace d = connector_grants_detail;
    const auto now = std::time(nullptr);
    auto row = d::q::Grants::create({.user_id = approver.id,
                                     .client_row = g.client_row,
                                     .client_id = g.client_id,
                                     .client_name = g.client_name,
                                     .redirect_uri = g.redirect_uri,
                                     .scope = std::string(protocols::shell::effectName(g.scope)),
                                     .resource = g.resource,
                                     .label = g.label,
                                     .approved_via = g.approved_via,
                                     .expires_at = now + std::chrono::duration_cast<std::chrono::seconds>(kGrantLifetime).count()});
    d::grantAudit("connector.grant.create", row, approver.id, approver.name(),
                  {{"client_host", g.client_host.value_or("")}, {"redirect_host", g.redirect_host.value_or("")},
                   {"via", g.approved_via}, {"expires_at", static_cast<int64_t>(row.expires_at)}},
                  "[connector] " + approver.name() + " connected an app (grant " + d::shortId(row.id) + ", " + row.scope + ")");
    return d::toGrant(std::move(row));
}

std::optional<std::string> issueFirstRefreshToken(const std::string& grantId) {
    namespace d = connector_grants_detail;
    auto token = mintToken(kRefreshTokenPrefix);
    const auto expires = std::time(nullptr) + std::chrono::duration_cast<std::chrono::seconds>(kRefreshIdle).count();
    if (!d::q::Grants::insertFirstRefreshToken(grantId, digestOf(token), expires)) return std::nullopt;
    if (const auto row = d::q::Grants::byId(grantId))
        d::grantAudit("connector.token.issue", *row, row->user_id, d::actorName(row->user_id), {{"from", "code"}},
                      "[connector] grant " + d::shortId(row->id) + " redeemed its authorization code");
    return token;
}

std::variant<Refreshed, RefreshRefusal> refresh(const std::string& refreshToken, const std::string& clientId) {
    namespace d = connector_grants_detail;
    using O = db::query::connector::Rotation::Outcome;
    if (!refreshToken.starts_with(kRefreshTokenPrefix) || refreshToken.size() > 128) return RefreshRefusal::Unknown;
    auto successor = mintToken(kRefreshTokenPrefix);
    const auto r = d::q::Grants::rotate(
        digestOf(refreshToken), clientId, digestOf(successor),
        std::chrono::duration_cast<std::chrono::seconds>(kRefreshIdle).count(), kLostResponseAllowance.count());
    switch (r.outcome) {
        case O::Rotated:
        case O::Allowance: {
            const bool allowance = r.outcome == O::Allowance;
            d::grantAudit("connector.token.issue", *r.grant, r.grant->user_id, d::actorName(r.grant->user_id),
                          {{"from", "refresh"}, {"allowance", allowance}},
                          "[connector] grant " + d::shortId(r.grant->id) + " refreshed its tokens" +
                              (allowance ? " (a retry after a lost answer)" : ""));
            return Refreshed{.grant = d::toGrant(*r.grant), .refresh_token = std::move(successor), .allowance = allowance};
        }
        case O::Reused:
            d::auditRevoked(*r.grant, Revocation::RefreshReuse, {});
            d::noticeReuse(*r.grant, Revocation::RefreshReuse);
            return RefreshRefusal::Reused;
        case O::Expired:
            if (r.grant) d::auditRevoked(*r.grant, Revocation::Expired, {});
            return RefreshRefusal::Expired;
        case O::GrantEnded: return RefreshRefusal::Ended;
        case O::WrongClient: return RefreshRefusal::WrongClient;
        case O::Unknown: break;
    }
    return RefreshRefusal::Unknown;
}

std::optional<Grant> get(const std::string& id) {
    namespace d = connector_grants_detail;
    auto row = d::q::Grants::byId(id);
    if (!row) return std::nullopt;
    return d::toGrant(std::move(*row));
}

std::vector<Grant> list(const std::optional<uint32_t> userId) {
    namespace d = connector_grants_detail;
    std::vector<Grant> out;
    for (auto& row : d::q::Grants::list(userId)) out.push_back(d::toGrant(std::move(row)));
    return out;
}

bool revoke(const std::string& grantId, const Revocation why, const Revoker& by) {
    namespace d = connector_grants_detail;
    if (!d::q::Grants::revoke(grantId, std::string(to_string(why)), by.id)) return false;
    if (const auto row = d::q::Grants::byId(grantId)) {
        d::auditRevoked(*row, why, by);
        if (why == Revocation::CodeReuse) d::noticeReuse(*row, why);
    }
    return true;
}

std::size_t revokeForUser(const uint32_t userId, const Revocation why, const Revoker& by) {
    namespace d = connector_grants_detail;
    std::size_t n = 0;
    for (const auto& g : d::q::Grants::listLive(std::vector<uint32_t>{userId}))
        if (revoke(g.id, why, by)) ++n;
    return n;
}

std::size_t revokeAll(const Revocation why, const Revoker& by) {
    namespace d = connector_grants_detail;
    std::size_t n = 0;
    for (const auto& g : d::q::Grants::listLive())
        if (revoke(g.id, why, by)) ++n;
    return n;
}

std::optional<Revocation> endCondition(const Grant& grant, const std::time_t now) {
    const auto& g = grant.row;
    if (!g.live()) return std::nullopt;
    const auto user = identities::manager().user(g.user_id);
    if (!user || !user->authorizing()) return Revocation::UserInactive;
    if (!mayGrant(*user)) return Revocation::GrantorPolicy;
    if (now >= g.expires_at) return Revocation::Expired;
    if (!g.redeemed && now - g.created_at >= std::chrono::duration_cast<std::chrono::seconds>(kUnredeemedGrant).count())
        return Revocation::Expired;
    if (g.redeemed && (!g.refresh_expires_at || now >= *g.refresh_expires_at)) return Revocation::Expired;
    return std::nullopt;
}

std::size_t reconcile(const std::optional<std::vector<uint32_t>>& userIds) {
    namespace d = connector_grants_detail;
    std::size_t n = 0;
    const auto now = std::time(nullptr);
    for (auto& row : d::q::Grants::listLive(userIds)) {
        const auto g = d::toGrant(std::move(row));
        if (const auto why = endCondition(g, now); why && revoke(g.row.id, *why)) ++n;
    }
    return n;
}

}
