#pragma once

#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Step-up (#359; MFA design note docs/dev/mfa-design.md section 5.4, decisions D3 and D6): a fresh, scoped,
// short-lived proof that the person behind a signed-in web session is present, asked for right before a sensitive
// mutation runs.
//
// Where it is checked. require(family, target) is called in the ops layer (and in the few handlers that are their own
// operation: the MFA factor commands), after validation and typed confirmations, immediately before the mutation, so
// the person approves exactly what will run. Who is asking comes from a thread-local Scope that the request's entry
// point sets:
//   - the ws router, for every routed command: Web (a signed-in console session) or Device (a paired device's session);
//   - the CLI server over the unix socket: Host (kernel peer credentials; the host account is the trust anchor, design
//     section 5.6), or Agent when `vh mcp` marks the call agent: true;
//   - the device listener's /mcp: Agent.
// Host never prompts: RBAC, typed confirmations and the audit trail still apply, and `vh` stays the documented host
// recovery path. Agent can never produce a step-up, so an annotated operation refuses under it. A Device session never
// sees step_up_required for routine sync (a contract test enumerates them); for an annotated command it is refused
// (methods device_approval and/or console_approval) until a grant on that device session covers it: one made by the
// device's approval key (keys and device.trust only, D6) or by a person's passkey in the web console (#361,
// auth/approval/Approvals.hpp), or the key-backup grant (#362). No Scope at all means no request: the
// daemon's own callers and tests, which call ops:: directly and are trusted like the host (ops/Actor.hpp).
//
// How it is satisfied (web sessions only): a grant, made by auth.stepup.finish after
//   - a WebAuthn assertion with UV over a step-up challenge bound to this session, the family and the target; or
//   - the account's password and a TOTP code together (a code alone never is); or
//   - D3: the password alone, only for an account that need not have MFA and has no usable factor, and never for
//     keys, device.trust or data.destroy;
// or, for the family-wide families only, a sign-in at aal 2 within the step-up window (not a recovery-code one).
// Recovery codes, a refresh token, an open session and Desktop mTLS never satisfy it.
//
// Grants live in memory on the ws session they were made on (never visible to another), bound to its user and refresh
// token jti, for auth.mfa.step_up_ttl_seconds (default 300, 60..900). Target-bound families' grants are single use.
// Logout, idle sign-out, revocation, a policy refusal and the socket closing drop them (session::Manager::invalidate).
// Five failed ceremonies within 15 minutes revoke the session. Every grant, failure and refusal is audited:
// auth.stepup.grant, auth.stepup.fail, auth.stepup.required.
namespace vh::auth::stepup {

enum class Family : uint8_t { Keys, DeviceTrust, AccountCredentials, IdentityAdmin, Secrets, Settings, DataDestroy };

inline constexpr std::array<Family, 7> kFamilies{Family::Keys,          Family::DeviceTrust, Family::AccountCredentials,
                                                 Family::IdentityAdmin, Family::Secrets,     Family::Settings,
                                                 Family::DataDestroy};

// "keys", "device.trust", "account.credentials", "identity.admin", "secrets", "settings", "data.destroy".
[[nodiscard]] std::string_view to_string(Family family) noexcept;
[[nodiscard]] std::optional<Family> parseFamily(std::string_view name) noexcept;

// keys, device.trust and data.destroy: a grant names the exact target and is spent by one use.
[[nodiscard]] bool targetBound(Family family) noexcept;
// D3: the password alone may satisfy only these (account.credentials, identity.admin, secrets, settings), and only for
// an account that need not have MFA and has no usable factor.
[[nodiscard]] bool passwordMaySatisfy(Family family) noexcept;
// D6 (#361's extension point): a registered Secure Enclave approval key may satisfy only keys and device.trust (the
// key-backup grant commands are device.trust).
[[nodiscard]] bool deviceApprovalMaySatisfy(Family family) noexcept;

// The recovery cooldown's families (#360; design 7.4, D4): keys, device.trust, identity.admin, secrets, settings. While
// the account's cooldown runs (a recovery-code sign-in or an MFA reset, auth/mfa/Recovery.hpp) require() refuses them
// on web and device sessions with ops::RecoveryCooldown, before any grant is looked at, and no ceremony for them
// begins. Factors enrolled meanwhile are marked created_during_recovery and are not offered for these families until
// the cooldown ends. account.credentials (enrolling the replacement factor, removing the lost one) and data.destroy are
// not held back.
[[nodiscard]] bool cooldownFamily(Family family) noexcept;
// Throws ops::RecoveryCooldown when `family` is a cooldown family and `userId`'s cooldown runs.
void requireNoCooldown(uint32_t userId, Family family);

// The grant window: auth.mfa.step_up_ttl_seconds, clamped to 60..900.
[[nodiscard]] std::chrono::seconds ttl();
inline constexpr std::chrono::seconds kMinTtl{60};
inline constexpr std::chrono::seconds kMaxTtl{900};
inline constexpr std::chrono::seconds kDefaultTtl{300};

inline constexpr int kMaxFailures = 5;
inline constexpr std::chrono::minutes kFailureWindow{15};
// A begun ceremony (its WebAuthn challenge) lives this long.
inline constexpr std::chrono::seconds kCeremonyTtl{120};
// Targets are opaque to clients (they echo the refusal's); bounded so a client can't make the daemon hold much.
inline constexpr std::size_t kMaxTargetLength = 256;

// ---- who is asking ----------------------------------------------------------------------------------------------------

enum class Channel : uint8_t { Web, Device, Host, Agent };
[[nodiscard]] std::string_view to_string(Channel channel) noexcept;

class Scope {
public:
    // The ws router: Web for a signed-in console session, Device for a paired device's (anything else: Web, and an
    // unsigned socket never reaches an operation).
    explicit Scope(std::shared_ptr<protocols::ws::Session> session);
    // The CLI server (Host or Agent) and /mcp (Agent).
    explicit Scope(Channel channel);
    ~Scope();
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

    [[nodiscard]] static Scope* current() noexcept;

    [[nodiscard]] Channel channel() const noexcept { return channel_; }
    [[nodiscard]] const std::shared_ptr<protocols::ws::Session>& session() const noexcept { return session_; }

    // What this request already proved (require) and whether an outer operation's approval covers it (Covered).
    [[nodiscard]] bool satisfied(Family family, const std::optional<std::string>& target) const;
    void markSatisfied(Family family, const std::optional<std::string>& target);
    [[nodiscard]] bool covered() const noexcept { return covered_ > 0; }
    void enterCovered() noexcept { ++covered_; }
    void leaveCovered() noexcept { --covered_; }

private:
    Channel channel_;
    std::shared_ptr<protocols::ws::Session> session_;
    // What this request already proved: an operation that checks the same family and target twice spends a single-use
    // grant once.
    std::vector<std::pair<Family, std::optional<std::string>>> satisfied_;
    int covered_{0};
    Scope* previous_;
};

// Inside an operation that has passed its own step-up, what it does on that approval's behalf (auth.user.delete
// removing the account's vaults it listed in its confirmation) needs no other.
class Covered {
public:
    Covered() noexcept;
    ~Covered();
    Covered(const Covered&) = delete;
    Covered& operator=(const Covered&) = delete;

private:
    Scope* scope_;
};

// ---- the check ---------------------------------------------------------------------------------------------------------

// Throws ops::StepUpRequired (ws: ERROR {code: step_up_required, family, target, methods, max_age_seconds}) unless the
// caller in scope may run an operation of `family` on `target` now (see the namespace comment). `target` is required
// for target-bound families and ignored otherwise.
void require(Family family, const std::optional<std::string>& target = std::nullopt);

// vault.keys.export on a paired device (#362's extension point): an export inside the device's key-backup grant needs
// no step-up (design 6.4: Desktop's background 1Password backup never prompts). Until #362 adds the grant table, every
// paired device holds what D1 migrates to an `origin = migrated` grant: its user's existing export authority, which
// RBAC (encryption-key Export) has already checked. So this is true on a Device channel whose device's grant was not
// revoked (#360: a recovery-code sign-in or an MFA reset of its user revokes it, devices.key_backup_revoked_at), and
// nowhere else.
[[nodiscard]] bool keyBackupGrantCovers(uint32_t vaultId);

// What `user` can answer a step-up of `family` with on a web session: "webauthn" (a usable passkey and passkeys
// configured), "password_totp" (a confirmed authenticator app), "password" (D3). Empty when nothing can (an account
// with no factor asked for keys, device.trust or data.destroy). Factors the account's policy rule refuses
// (auth.mfa.admin_webauthn_only / admin_device_bound_only) are never offered, nor, for a cooldown family while the
// cooldown runs, factors enrolled during recovery.
[[nodiscard]] std::vector<std::string> methods(const identities::User& user, Family family);

// The refusal for `family`/`target` as the caller in scope sees it (methods for its channel). Not audited.
[[noreturn]] void refuse(Family family, const std::optional<std::string>& target, std::vector<std::string> methods,
                         const std::string& text);

// ---- grants -------------------------------------------------------------------------------------------------------------

struct Grant {
    uint32_t user_id{};
    std::string refresh_jti{};            // empty on a device session (it has no refresh token)
    Family family{Family::Settings};
    std::optional<std::string> target{};  // target-bound families only
    std::string method{};                 // webauthn, password_totp, password; on a device: the two below
    std::chrono::system_clock::time_point expires_at{};
};

// How a device session's grant was made (#361, auth/approval/Approvals.hpp): a signature by the device's approval
// key (D6: keys and device.trust only), or a person's passkey in the web console (design 6.3: any family).
inline constexpr std::string_view kDeviceApprovalMethod{"device_approval"};
inline constexpr std::string_view kConsoleApprovalMethod{"console_approval"};

// A begun ceremony: auth.stepup.begin to auth.stepup.finish, one per session (a new one replaces it).
struct Ceremony {
    std::string id{};
    uint32_t user_id{};
    Family family{Family::Settings};
    std::optional<std::string> target{};
    std::vector<std::string> methods{};
    std::chrono::steady_clock::time_point expires{};
};

// The step-up state of one ws session (protocols::ws::Session::stepUp()). Dies with the socket.
class SessionState {
public:
    void addGrant(Grant grant);
    // A live grant of `user`/`jti` for family (and target, when target-bound): spent when target-bound. Expired and
    // foreign grants are dropped on the way.
    [[nodiscard]] std::optional<Grant> use(uint32_t userId, const std::string& jti, Family family,
                                           const std::optional<std::string>& target,
                                           std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    // The live grants (auth.mfa.status).
    [[nodiscard]] std::vector<Grant> grants(std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

    void setCeremony(Ceremony ceremony);
    // The open ceremony with this id (removed: a ceremony is finished once), unless expired.
    [[nodiscard]] std::optional<Ceremony> takeCeremony(std::string_view id);

    // A failed ceremony now; returns the failures within kFailureWindow, this one included.
    int recordFailure(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    [[nodiscard]] int failures(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    // Drops every grant, the open ceremony and the failure count (sign-out, invalidation, socket closed).
    void clear();

private:
    std::mutex mutex_;
    std::vector<Grant> grants_;
    std::optional<Ceremony> ceremony_;
    std::deque<std::chrono::steady_clock::time_point> failures_;
};

// ---- the ceremony (protocols/ws/handler/StepUp.cpp) ---------------------------------------------------------------------

// auth.stepup.begin: {stepup_id, family, target, methods, webauthn?: {publicKey}, expires_at}. Web sessions only;
// ops::Refused("step_up_unavailable") when the account has nothing that can satisfy `family`.
[[nodiscard]] nlohmann::json begin(const std::shared_ptr<protocols::ws::Session>& session, Family family,
                                   const std::optional<std::string>& target);

// auth.stepup.finish: verifies the answer to the ceremony `stepup_id` ({method: webauthn, credential},
// {method: password_totp, password, code} or D3's {method: password, password}) and, when it holds, makes the grant.
// A wrong answer is recorded; the fifth within kFailureWindow revokes the session (its refresh row, every socket on it).
// ops::NotFound when the ceremony expired or was used; ops::Invalid for a method it didn't offer.
struct Finished {
    std::optional<Grant> grant{};  // set when the answer held
    int attempts_remaining{};      // otherwise: how many more may fail before the session is revoked (0: it was)
};
[[nodiscard]] Finished finish(const std::shared_ptr<protocols::ws::Session>& session, const nlohmann::json& payload);

// The WebAuthn challenge scope of a step-up: "stepup\x1f<family>\x1f<target>".
[[nodiscard]] std::string challengeScope(Family family, const std::optional<std::string>& target);

}
