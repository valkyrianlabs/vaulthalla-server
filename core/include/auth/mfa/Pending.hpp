#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Pending-MFA (#357; MFA design note docs/dev/mfa-design.md section 5.2): a socket whose password was correct but
// whose sign-in still owes a factor (kind Mfa) or, for an account that must have MFA and has none, a first factor
// (kind Enrollment).
//
// It is not a signed-in session. Nothing here sets ws::Session::user, issues an access token or writes a refresh row:
// those happen once, when the factor succeeds (auth::mfa::signin::complete). So every gate that keys off the session
// user (the router's modes, session::Manager::validate, the HTTP lanes, idle sign-out, RBAC) refuses a pending socket
// by construction, and its refresh cookie, which has no row, is refused like any unknown token by auth.refresh, a
// reconnect, another tab and the HTTP lanes.
//
// The state lives in memory on the socket only: it ends after 5 minutes (10 for enrollment), after 5 failed factors,
// on auth.mfa.cancel or auth.logout, or when the socket closes. It survives neither a reconnect nor a daemon restart.
namespace vh::auth::mfa {

enum class PendingKind : uint8_t { Mfa, Enrollment };

// The ws refusal code auth.login answers with: "mfa_required" / "mfa_enrollment_required".
[[nodiscard]] std::string_view refusalCode(PendingKind kind) noexcept;

inline constexpr std::chrono::minutes kPendingMfaTtl{5};
inline constexpr std::chrono::minutes kPendingEnrollmentTtl{10};
inline constexpr int kPendingMaxFailures = 5;

// The router's pending mode runs exactly these (protocols/ws/Router.cpp; mirrored in web/src/lib/session.ts
// LIFECYCLE, checked by tools/contracts/test_mfa_pending_contract.py). Everything else is UNAUTHORIZED, auth.login
// (no second password attempt on a pending socket) and meta.hello included.
inline constexpr std::array<std::string_view, 3> kPendingCommands{"auth.mfa.verify", "auth.mfa.cancel", "auth.logout"};
// ... plus these while the kind is Enrollment.
inline constexpr std::array<std::string_view, 5> kPendingEnrollmentCommands{
    "auth.mfa.webauthn.register.options", "auth.mfa.webauthn.register.finish", "auth.mfa.totp.enroll.start",
    "auth.mfa.totp.enroll.confirm", "auth.mfa.recovery.acknowledge"};

[[nodiscard]] bool pendingAllows(PendingKind kind, std::string_view command) noexcept;

struct Pending {
    uint32_t user_id{};
    PendingKind kind{PendingKind::Mfa};
    std::vector<std::string> methods{};  // webauthn, totp, recovery_code: what the person may answer with
    std::chrono::system_clock::time_point expires_at{};
    int failures{0};
    // Enrollment: the first factor's ceremony succeeded (its amr: hwk, swk or otp), and acknowledging
    // `recovery_batch` completes the sign-in.
    std::optional<std::string> enrolled_amr{};
    std::optional<std::string> recovery_batch{};

    [[nodiscard]] bool expired(std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) const {
        return now >= expires_at;
    }
};

// A passkey registration between its options and its finish (pending enrollment or Account → Security).
struct Registration {
    std::string id{};
    uint32_t user_id{};
    std::string label{};
    std::chrono::steady_clock::time_point expires{};
};

// The socket's MFA state (protocols::ws::Session::mfa()).
class SessionState {
public:
    [[nodiscard]] std::optional<Pending> pending() const;
    [[nodiscard]] std::optional<PendingKind> pendingKind() const;
    void setPending(Pending pending);
    void clearPending();
    // Runs fn on the pending state under the lock; false when there is none.
    template <class Fn>
    bool updatePending(Fn&& fn) {
        std::lock_guard lock(mutex_);
        if (!pending_) return false;
        fn(*pending_);
        return true;
    }

    // One open registration per socket: a new one replaces the last.
    void setRegistration(Registration registration);
    // The open registration with this id (removed: a registration is finished once), unless expired.
    [[nodiscard]] std::optional<Registration> takeRegistration(std::string_view id);

    void clear();

private:
    mutable std::mutex mutex_;
    std::optional<Pending> pending_;
    std::optional<Registration> registration_;
};

}
