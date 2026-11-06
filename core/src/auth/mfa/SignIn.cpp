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
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace vh::auth::mfa::signin {

namespace {

using SteadyClock = std::chrono::steady_clock;

struct SignInFailures {
    std::mutex mutex;
    std::unordered_map<uint32_t, std::deque<SteadyClock::time_point>> byAccount;
};

SignInFailures& signInFailures() {
    static SignInFailures failures;
    return failures;
}

void signInPrune(std::deque<SteadyClock::time_point>& times, const SteadyClock::time_point now) {
    while (!times.empty() && now - times.front() >= kAccountFailureWindow) times.pop_front();
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

std::vector<std::string> methods(const uint32_t userId) {
    std::vector<std::string> out;
    if (!passkeys::usableCredentials(userId).empty()) out.emplace_back("webauthn");
    if (std::ranges::any_of(factors(userId), [](const Factor& f) { return f.kind == FactorKind::Totp; }))
        out.emplace_back("totp");
    if (const auto recovery = recoveryStatus(userId); recovery.active_batch && recovery.remaining > 0)
        out.emplace_back("recovery_code");
    return out;
}

bool beginIfDue(const std::shared_ptr<protocols::ws::Session>& session, const std::shared_ptr<identities::User>& user) {
    if (!session || !user) throw std::invalid_argument("A sign-in needs a session and an account");
    const auto requirement = policy::requirement(*user);
    const bool enrolled = hasUsableFactor(user->id);
    if (!enrolled && !requirement.required) return false;

    Pending pending{.user_id = user->id, .kind = enrolled ? PendingKind::Mfa : PendingKind::Enrollment};
    if (enrolled) {
        pending.methods = methods(user->id);
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
        pending.methods.emplace_back("totp");
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

std::chrono::seconds accountRetryAfter(const uint32_t userId) {
    auto& f = signInFailures();
    const auto now = SteadyClock::now();
    std::lock_guard lock(f.mutex);
    const auto it = f.byAccount.find(userId);
    if (it == f.byAccount.end()) return std::chrono::seconds(0);
    signInPrune(it->second, now);
    if (std::cmp_less(it->second.size(), kAccountFailureLimit)) return std::chrono::seconds(0);
    const auto wait = kAccountFailureWindow - (now - it->second.front());
    return std::max(std::chrono::seconds(1), std::chrono::ceil<std::chrono::seconds>(wait));
}

void recordAccountFailure(const uint32_t userId) {
    auto& f = signInFailures();
    const auto now = SteadyClock::now();
    std::lock_guard lock(f.mutex);
    auto& times = f.byAccount[userId];
    signInPrune(times, now);
    times.push_back(now);
    while (times.size() > static_cast<std::size_t>(kAccountFailureLimit)) times.pop_front();
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
