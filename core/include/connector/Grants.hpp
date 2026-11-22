#pragma once

#include "Mcp.hpp"  // vh::mcp: the effect ceiling a grant's scope is
#include "db/query/connector/Connector.hpp"
#include "identities/Fwd.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// Remote-connector grants (design/core/mcp-remote-signin.md): each approval is its own revocable identity, bound to
// the user who approved it, one client, one exact redirect URI and one scope (an effect ceiling: read, write or
// destructive). This layer mints and rotates the grant's refresh tokens (stored only as digests), revokes grants and
// checks the end conditions; it audits every change. Who may ask for what is ops::connector's.
//
// Decided 2026-11-22 (the design's open questions, by the coordinator with the recommended defaults; each is one
// constant or setting so it can change later): only super admins may grant (mayGrant); the widest scope is write unless
// the operator raises connector_settings.max_scope; a grant lasts at most kGrantLifetime and ends after kRefreshIdle
// without a refresh.
namespace vh::connector {

using Scope = protocols::shell::CommandEffect;

inline constexpr std::chrono::minutes kAccessTokenLifetime{15};
inline constexpr std::chrono::seconds kCodeLifetime{60};
inline constexpr std::chrono::hours kRefreshIdle{24 * 30};
inline constexpr std::chrono::hours kGrantLifetime{24 * 90};
// A refresh whose answer was lost may be retried with the previous token this long after it was used.
inline constexpr std::chrono::seconds kLostResponseAllowance{10};
// A grant whose code was never redeemed ends after this.
inline constexpr std::chrono::minutes kUnredeemedGrant{10};

inline constexpr std::string_view kRefreshTokenPrefix = "vh_rt_";
inline constexpr std::string_view kAccessTokenPrefix = "vh_at_";
inline constexpr std::string_view kCodePrefix = "vh_ac_";

// Why a grant ended (connector_grants.revoked_reason).
enum class Revocation {
    Manual,           // its user or a super admin revoked it
    UserInactive,     // its user was deactivated or deleted
    GrantorPolicy,    // its user may no longer grant
    RefreshReuse,     // a rotated refresh token was presented again
    CodeReuse,        // its authorization code was redeemed twice
    SwitchOff,        // remote connectors were switched off
    Expired,          // absolute lifetime, refresh idle, or a code never redeemed
    ClientRemoved,    // its client was removed
    SessionsRevoked,  // the user's sessions were revoked (sign out everywhere, password change, MFA reset)
    MfaRecovery,      // a recovery-code sign-in
};
[[nodiscard]] std::string_view to_string(Revocation r) noexcept;
[[nodiscard]] std::optional<Revocation> parseRevocation(std::string_view s) noexcept;

// The grantor policy: who may approve a grant (for their own account only). Super admins (decided 2026-11-22).
[[nodiscard]] bool mayGrant(const identities::User& user);

// `prefix` + base64url of 32 random bytes.
[[nodiscard]] std::string mintToken(std::string_view prefix);
// What is stored for a token: crypto::hash::tokenDigest (sha256:<hex>).
[[nodiscard]] std::string digestOf(std::string_view token);

struct Grant {
    db::query::connector::GrantRow row;
    Scope scope{Scope::Read};
};

struct NewGrant {
    std::string client_row{};
    std::string client_id{};
    std::string client_name{};
    std::string redirect_uri{};
    Scope scope{Scope::Read};
    std::string resource{};
    std::optional<std::string> label{};
    std::string approved_via{};
    std::optional<std::string> client_host{};    // for the audit event
    std::optional<std::string> redirect_host{};  // for the audit event
};

// A grant for `approver`'s own account; the caller checked mayGrant, the scope against the node's maximum, and the
// approver's step-up. Audited connector.grant.create.
Grant create(const identities::User& approver, const NewGrant& grant);

// The first refresh token of a grant whose code is being redeemed; nullopt when the grant ended or already has one
// (a second redemption: the caller then revokes it, CodeReuse). Audited connector.token.issue {from: code}.
[[nodiscard]] std::optional<std::string> issueFirstRefreshToken(const std::string& grantId);

struct Refreshed {
    Grant grant;
    std::string refresh_token;
    bool allowance{false};  // the lost-response allowance was used
};
enum class RefreshRefusal { Unknown, WrongClient, Ended, Expired, Reused };
// One refresh-token rotation (see db::query::connector::Rotation). Reuse revokes the grant (audited
// connector.grant.revoke {reason: refresh_reuse}); a success is audited connector.token.issue {from: refresh}.
[[nodiscard]] std::variant<Refreshed, RefreshRefusal> refresh(const std::string& refreshToken, const std::string& clientId);

[[nodiscard]] std::optional<Grant> get(const std::string& id);
// Every grant, or one user's; live first, newest first.
[[nodiscard]] std::vector<Grant> list(std::optional<uint32_t> userId = std::nullopt);

struct Revoker {
    std::optional<uint32_t> id{};
    std::string name{};  // empty: the node itself (a trigger, the sweeper)
};
// Ends a live grant and its tokens; true when it was live. Audited connector.grant.revoke {grant_id, reason}.
bool revoke(const std::string& grantId, Revocation why, const Revoker& by = {});
std::size_t revokeForUser(uint32_t userId, Revocation why, const Revoker& by = {});
std::size_t revokeAll(Revocation why, const Revoker& by = {});

// Why a live grant may no longer act now, if it may not: its user inactive or gone (UserInactive), no longer a grantor
// (GrantorPolicy), past its lifetime or never redeemed in time (Expired).
[[nodiscard]] std::optional<Revocation> endCondition(const Grant& grant, std::time_t now);
// Revokes every live grant (or those of `userIds`) that has an end condition. Returns how many.
std::size_t reconcile(const std::optional<std::vector<uint32_t>>& userIds = std::nullopt);

}
