#include "auth/mfa/SignIn.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Passkeys.hpp"
#include "auth/mfa/Pending.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/session/Manager.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "notifications/AccountSecurity.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace vh::auth::mfa::signin {

namespace {

struct SignInFailures {
    std::mutex mutex;
    std::unordered_map<uint32_t, AccountBackoff> byAccount;
};

SignInFailures& signInFailures() {
    static SignInFailures failures;
    return failures;
}

// Audit details hold scalars: lists are written joined ("pwd+otp", "webauthn,totp").
std::string signInJoin(const std::vector<std::string>& items, const std::string_view separator) {
    std::string out;
    for (const auto& item : items) {
        if (!out.empty()) out += separator;
        out += item;
    }
    return out;
}

}

std::vector<std::string> methods(const identities::User& user) {
    std::vector<std::string> out;
    if (!policy::allowedPasskeys(user).empty()) out.emplace_back("webauthn");
    if (policy::hasAllowedTotp(user)) out.emplace_back("totp");
    if (const auto recovery = recoveryStatus(user.id); recovery.active_batch && recovery.remaining > 0)
        out.emplace_back("recovery_code");
    return out;
}

bool beginIfDue(const std::shared_ptr<protocols::ws::Session>& session, const std::shared_ptr<identities::User>& user) {
    if (!session || !user) throw std::invalid_argument("A sign-in needs a session and an account");
    const auto requirement = policy::requirement(*user);
    const bool enrolled = policy::hasAllowedFactor(*user);
    if (!enrolled && !requirement.required) return false;

    Pending pending{.user_id = user->id, .kind = enrolled ? PendingKind::Mfa : PendingKind::Enrollment};
    if (enrolled) {
        pending.methods = methods(*user);
        if (pending.methods.empty()) {
            log::Registry::auth()->warn("[auth::mfa] {} has factors but none usable here (passkeys need "
                                        "auth.webauthn.rp_id and origins)", user->name());
            audit::record({.action = "auth.mfa.challenge", .outcome = audit::Outcome::Denied, .actor_id = user->id,
                           .actor = user->name(), .details = {{"reason", "no_usable_method"}}},
                          "[auth] " + user->name() + " has no second factor usable on this server",
                          spdlog::level::warn);
            throw ops::Refused("mfa_unavailable",
                               "Your second factor can't be used on this server right now (passkeys are not "
                               "configured). Ask an administrator.");
        }
    } else {
        if (passkeys::available()) pending.methods.emplace_back("webauthn");
        if (policy::factorRule(*user).totp) pending.methods.emplace_back("totp");
    }
    pending.expires_at = std::chrono::system_clock::now() +
                         (pending.kind == PendingKind::Enrollment ? std::chrono::minutes(kPendingEnrollmentTtl)
                                                                  : std::chrono::minutes(kPendingMfaTtl));
    const auto kind = pending.kind;
    const auto methodList = signInJoin(pending.methods, ",");
    session->mfa().setPending(std::move(pending));

    audit::record({.action = "auth.mfa.challenge", .outcome = audit::Outcome::Info, .actor_id = user->id,
                   .actor = user->name(),
                   .details = {{"methods", methodList},
                               {"kind", kind == PendingKind::Enrollment ? "enrollment" : "mfa"},
                               {"reason", std::string(policy::to_string(requirement.reason))},
                               {"ip", session->ipAddress}}},
                  "[auth] " + user->name() + (kind == PendingKind::Enrollment
                                                  ? " must enroll a second factor to sign in"
                                                  : " entered the password; a second factor is due"));
    return true;
}

void complete(const std::shared_ptr<protocols::ws::Session>& session, const std::shared_ptr<identities::User>& user,
              const session::assurance::Proof& proof, const std::string_view method) {
    if (!session || !user) throw std::invalid_argument("A sign-in needs a session and an account");
    if (user->systemOnly() || !user->authorizing()) {
        end(session, "account_unavailable");
        throw std::runtime_error("Invalid username or password");
    }
    session->mfa().clearPending();
    passkeys::forgetSession(session->uuid);
    session->setAuthenticatedUser(user);
    try {
        runtime::Deps::get().sessionManager->promote(session, proof);
    } catch (...) {
        session->user = nullptr;  // no row was written for this socket: it is not signed in
        throw;
    }
    vh::identities::manager().recordLogin(user->id);
    session->sendAccessTokenOnNextResponse();

    log::Registry::auth()->info("[auth::mfa] {} signed in ({}, aal {})", user->name(), method,
                                static_cast<int>(proof.aal));
    audit::record({.action = "auth.login.success", .actor_id = user->id, .actor = user->name(),
                   .details = {{"method", std::string(method)}, {"aal", proof.aal}, {"amr", signInJoin(proof.amr, "+")},
                               {"ip", session->ipAddress}}},
                  "[auth] " + user->name() + " signed in");
}

void end(const std::shared_ptr<protocols::ws::Session>& session, const std::string_view reason) {
    if (!session) return;
    const auto pending = session->mfa().pending();
    session->mfa().clearPending();
    passkeys::forgetSession(session->uuid);
    if (pending)
        log::Registry::auth()->info("[auth::mfa] pending sign-in of user {} ended: {}", pending->user_id, reason);
}

std::chrono::seconds AccountBackoff::delayFor(const int failures) noexcept {
    if (failures < kAccountFailureLimit) return std::chrono::seconds(0);
    const int doublings = std::min(failures - kAccountFailureLimit, 8);
    const auto delay = std::chrono::duration_cast<std::chrono::seconds>(kAccountFirstDelay) * (1 << doublings);
    return std::min(delay, std::chrono::duration_cast<std::chrono::seconds>(kAccountMaxDelay));
}

bool AccountBackoff::expired(const Clock::time_point now) const {
    return failures_ > 0 && now - std::max(last_, lockedUntil_) >= kAccountFailureWindow;
}

AccountBackoff::Failure AccountBackoff::fail(const Clock::time_point now) {
    if (expired(now)) *this = AccountBackoff{};
    ++failures_;
    last_ = now;
    Failure out{.failures = failures_, .delay = delayFor(failures_)};
    if (out.delay.count() > 0) lockedUntil_ = now + out.delay;
    if (failures_ >= kAccountNotifyAt && !notified_) {
        notified_ = true;
        out.notify = true;
    }
    return out;
}

std::chrono::seconds AccountBackoff::retryAfter(const Clock::time_point now) const {
    if (now >= lockedUntil_) return std::chrono::seconds(0);
    return std::max(std::chrono::seconds(1), std::chrono::ceil<std::chrono::seconds>(lockedUntil_ - now));
}

std::chrono::seconds accountRetryAfter(const uint32_t userId, const AccountBackoff::Clock::time_point now) {
    auto& f = signInFailures();
    std::lock_guard lock(f.mutex);
    const auto it = f.byAccount.find(userId);
    if (it == f.byAccount.end()) return std::chrono::seconds(0);
    if (it->second.expired(now)) {
        f.byAccount.erase(it);
        return std::chrono::seconds(0);
    }
    return it->second.retryAfter(now);
}

AccountBackoff::Failure recordAccountFailure(const uint32_t userId, const AccountBackoff::Clock::time_point now) {
    AccountBackoff::Failure out;
    {
        auto& f = signInFailures();
        std::lock_guard lock(f.mutex);
        out = f.byAccount[userId].fail(now);
    }
    if (out.delay.count() > 0)
        audit::record({.action = "auth.mfa.lockout", .outcome = audit::Outcome::Denied, .actor_id = userId,
                       .details = {{"failures", out.failures}, {"retry_after", static_cast<int64_t>(out.delay.count())},
                                   {"notified", out.notify}}},
                      "[auth] second factors of user " + std::to_string(userId) + " are delayed " +
                          std::to_string(out.delay.count()) + "s after " + std::to_string(out.failures) +
                          " failures",
                      spdlog::level::warn);
    if (out.notify)
        notifications::account::send({
            .event = "mfa.failures",
            .title = "Repeated failed sign-in codes",
            .summary = "Someone entered this account's password and then failed its second factor " +
                       std::to_string(out.failures) + " times. Each new attempt now waits up to 15 minutes.",
            .user_id = userId,
            .facts = {{"Failed attempts", std::to_string(out.failures)}},
            .advice = "If this wasn't you, the password is known to someone else: change it now.",
        });
    return out;
}

void clearAccountFailures(const uint32_t userId) {
    auto& f = signInFailures();
    std::lock_guard lock(f.mutex);
    f.byAccount.erase(userId);
}

void resetAccountFailuresForTesting() {
    auto& f = signInFailures();
    std::lock_guard lock(f.mutex);
    f.byAccount.clear();
}

}
