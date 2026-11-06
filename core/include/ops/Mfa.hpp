#pragma once

#include "auth/mfa/Recovery.hpp"
#include "ops/Actor.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <optional>
#include <string>

// Managing another account's MFA (#360; MFA design note sections 7.1 and 7.4), shared by the ws auth.mfa.admin.*
// commands and `vh user mfa ...`:
//
//   status   the account's factors (no secrets), recovery codes left, whether MFA is required and why, the cooldown
//   require  sets user_mfa.required (identity.admin step-up); applies at the account's next request (its sessions are
//            re-judged, never grandfathered)
//   reset    disables every factor, voids the recovery codes, signs every session out, revokes the key-backup grants,
//            requires enrollment at the next sign-in and starts the recovery cooldown (auth/mfa/Recovery.hpp)
//
// Who: whoever may reset the account's password (ops::users::requireMfaManager); a super admin's MFA only another
// super admin. The two channels differ:
//   - Web: never your own account (manage your own factors in Account > Security), under account.credentials step-up
//     (identity.admin for require).
//   - Cli (`vh`, the documented host recovery, design 5.6): also the Linux user bound to the account itself, which is
//     how the sole super admin recovers. root and sudo are refused: run it as the bound user, like
//     `vh setup set-super-admin-password`. The host is exempt from step-up; an agent call (`vh mcp`) is refused by it.
// Every reset, require and refusal is audited (auth.mfa.admin.reset / .require, actor = the admin or CLI user).
namespace vh::ops::mfa {

enum class Channel : uint8_t { Web, Cli };

struct Status {
    uint32_t user_id{};
    bool required{false};
    std::string reason{};       // auth::mfa::policy::to_string(Reason)
    bool required_flag{false};  // user_mfa.required itself
    nlohmann::json factors{};   // [MfaFactor] (with "allowed")
    std::size_t recovery_remaining{};
    bool recovery_active{false};
    std::optional<int64_t> cooldown_until{};
    std::optional<int64_t> reset_at{};
};
void to_json(nlohmann::json& j, const Status& s);

[[nodiscard]] Status status(const Actor& actor, uint32_t userId, Channel channel);
void require(const Actor& actor, uint32_t userId, bool required, Channel channel);
// `reason`: 1..200 printable characters, required (it is in the audit trail).
auth::mfa::recovery::ResetEffects reset(const Actor& actor, uint32_t userId, const std::string& reason,
                                        Channel channel);

inline constexpr std::size_t kMaxReasonLength = 200;

}
