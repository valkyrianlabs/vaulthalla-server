#include "auth/stepup/StepUp.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Passkeys.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "config/Registry.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"

#include <algorithm>

namespace vh::auth::stepup {

namespace {

thread_local Scope* tlsStepUpScope = nullptr;

using StepUpSysClock = std::chrono::system_clock;

std::optional<std::string> stepUpBoundTarget(const Family family, const std::optional<std::string>& target) {
    return targetBound(family) ? target : std::nullopt;
}

// A sign-in at aal 2, within the step-up window, that wasn't a recovery code: it stands in for a family-wide grant
// (design 5.4: enrolling a second passkey right after signing in doesn't prompt twice). Never for a target-bound one.
bool stepUpFreshSignIn(const model::RefreshToken& row) {
    if (row.aal < 2) return false;
    if (std::ranges::find(row.amr, std::string(session::assurance::kRecoveryCode)) != row.amr.end()) return false;
    return StepUpSysClock::now() - row.authTime <= ttl();
}

nlohmann::json stepUpTargetJson(const std::optional<std::string>& target) {
    return target ? nlohmann::json(*target) : nlohmann::json(nullptr);
}

}

std::string_view to_string(const Family family) noexcept {
    switch (family) {
        case Family::Keys: return "keys";
        case Family::DeviceTrust: return "device.trust";
        case Family::AccountCredentials: return "account.credentials";
        case Family::IdentityAdmin: return "identity.admin";
        case Family::Secrets: return "secrets";
        case Family::Settings: return "settings";
        case Family::DataDestroy: return "data.destroy";
    }
    return "?";
}

std::optional<Family> parseFamily(const std::string_view name) noexcept {
    for (const auto f : kFamilies)
        if (to_string(f) == name) return f;
    return std::nullopt;
}

bool targetBound(const Family family) noexcept {
    return family == Family::Keys || family == Family::DeviceTrust || family == Family::DataDestroy;
}

bool passwordMaySatisfy(const Family family) noexcept { return !targetBound(family); }

bool deviceApprovalMaySatisfy(const Family family) noexcept {
    return family == Family::Keys || family == Family::DeviceTrust;
}

std::chrono::seconds ttl() {
    const auto configured = std::chrono::seconds(config::Registry::get().auth.mfa.step_up_ttl_seconds);
    return std::clamp(configured, kMinTtl, kMaxTtl);
}

std::string_view to_string(const Channel channel) noexcept {
    switch (channel) {
        case Channel::Web: return "web";
        case Channel::Device: return "device";
        case Channel::Host: return "host";
        case Channel::Agent: return "agent";
    }
    return "?";
}

// ---- Scope -----------------------------------------------------------------------------------------------------------

Scope::Scope(std::shared_ptr<protocols::ws::Session> session)
    : channel_(session && session->onDeviceListener() ? Channel::Device : Channel::Web),
      session_(std::move(session)),
      previous_(std::exchange(tlsStepUpScope, this)) {}

Scope::Scope(const Channel channel) : channel_(channel), previous_(std::exchange(tlsStepUpScope, this)) {}

Scope::~Scope() { tlsStepUpScope = previous_; }

Scope* Scope::current() noexcept { return tlsStepUpScope; }

bool Scope::satisfied(const Family family, const std::optional<std::string>& target) const {
    return std::ranges::find(satisfied_, std::pair{family, target}) != satisfied_.end();
}

void Scope::markSatisfied(const Family family, const std::optional<std::string>& target) {
    if (!satisfied(family, target)) satisfied_.emplace_back(family, target);
}

Covered::Covered() noexcept : scope_(Scope::current()) {
    if (scope_) scope_->enterCovered();
}

Covered::~Covered() {
    if (scope_) scope_->leaveCovered();
}

// ---- the check -------------------------------------------------------------------------------------------------------

std::vector<std::string> methods(const identities::User& user, const Family family) {
    std::vector<std::string> out;
    if (mfa::passkeys::available() && !mfa::passkeys::usableCredentials(user.id).empty()) out.emplace_back("webauthn");
    for (const auto& f : mfa::factors(user.id))
        if (f.kind == mfa::FactorKind::Totp && !f.suspended) {
            out.emplace_back("password_totp");
            break;
        }
    // D3: an account that need not have MFA and has no usable factor re-enters its password, for the lower-risk
    // families only. Decided here, on the server, every time (begin and finish both ask).
    if (passwordMaySatisfy(family) && !mfa::hasUsableFactor(user.id) && !mfa::policy::requirement(user).required)
        out.emplace_back("password");
    return out;
}

void refuse(const Family family, const std::optional<std::string>& target, std::vector<std::string> methods,
            const std::string& text) {
    throw ops::StepUpRequired(std::string(to_string(family)), stepUpBoundTarget(family, target), std::move(methods),
                              ttl().count(), text);
}

bool keyBackupGrantCovers(const uint32_t vaultId) {
    (void)vaultId;  // #362: the device's grant lists its vaults explicitly
    const auto* scope = Scope::current();
    return scope && scope->channel() == Channel::Device;
}

void require(const Family family, const std::optional<std::string>& target) {
    auto* scope = Scope::current();
    if (!scope) return;  // no request: the daemon's own callers and tests (see the header)
    const auto bound = stepUpBoundTarget(family, target);
    if (targetBound(family) && (!bound || bound->empty()))
        throw std::logic_error("step-up: family " + std::string(to_string(family)) + " needs a target");
    if (scope->covered() || scope->satisfied(family, bound)) return;

    const auto familyName = std::string(to_string(family));
    switch (scope->channel()) {
        case Channel::Host:
            return;  // the CLI over the unix socket: peer credentials, the host account is the trust anchor (5.6)

        case Channel::Agent:
            audit::record({.action = "auth.stepup.required", .outcome = audit::Outcome::Denied,
                           .details = {{"family", familyName}, {"target", stepUpTargetJson(bound)},
                                       {"channel", "agent"}}},
                          "[auth::stepup] an agent call was refused a " + familyName + " operation: agents can't "
                          "step up", spdlog::level::warn);
            refuse(family, bound, {}, "This needs a person to confirm it in the web console or the vh CLI: agents "
                                      "can't step up");

        case Channel::Device: {
            const auto& session = scope->session();
            const auto userId = session && session->user ? std::optional<uint32_t>(session->user->id) : std::nullopt;
            // #361 adds grants made on a device session by its approval key (keys and device.trust only, D6) or by a
            // console approval; they are found here like a web session's.
            if (userId && deviceApprovalMaySatisfy(family) && session->stepUp().use(*userId, {}, family, bound)) {
                scope->markSatisfied(family, bound);
                return;
            }
            audit::record({.action = "auth.stepup.required", .outcome = audit::Outcome::Denied, .actor_id = userId,
                           .actor = session && session->user ? session->user->name() : std::string{},
                           .details = {{"family", familyName}, {"target", stepUpTargetJson(bound)},
                                       {"channel", "device"}}},
                          "[auth::stepup] a paired device was refused a " + familyName + " operation: it needs a "
                          "person's approval", spdlog::level::warn);
            refuse(family, bound, {}, "A paired device can't approve this by itself: do it in the web console");
        }

        case Channel::Web: {
            const auto& session = scope->session();
            if (!session || !session->user || !session->tokens || !session->tokens->refreshToken)
                throw ops::Denied("not signed in");
            const auto& user = session->user;
            const auto& row = *session->tokens->refreshToken;
            if (const auto grant = session->stepUp().use(user->id, row.jti, family, bound)) {
                scope->markSatisfied(family, bound);
                log::Registry::auth()->debug("[auth::stepup] {} used a {} grant ({})", user->name(), familyName,
                                             grant->method);
                return;
            }
            if (!targetBound(family) && stepUpFreshSignIn(row)) {
                scope->markSatisfied(family, bound);
                return;
            }
            auto ways = methods(*user, family);
            audit::record({.action = "auth.stepup.required", .outcome = audit::Outcome::Info, .actor_id = user->id,
                           .actor = user->name(),
                           .details = {{"family", familyName}, {"target", stepUpTargetJson(bound)},
                                       {"methods", static_cast<int64_t>(ways.size())}}},
                          "[auth::stepup] " + user->name() + " was asked to step up for a " + familyName +
                              " operation");
            refuse(family, bound, std::move(ways),
                   "Confirm it's you to continue: this change needs a fresh passkey or password check");
        }
    }
    throw std::logic_error("step-up: unknown channel");
}

// ---- SessionState ----------------------------------------------------------------------------------------------------

void SessionState::addGrant(Grant grant) {
    std::lock_guard lock(mutex_);
    // One live grant per family and target: a new one replaces it.
    std::erase_if(grants_, [&](const Grant& g) { return g.family == grant.family && g.target == grant.target; });
    grants_.push_back(std::move(grant));
}

std::optional<Grant> SessionState::use(const uint32_t userId, const std::string& jti, const Family family,
                                       const std::optional<std::string>& target,
                                       const std::chrono::system_clock::time_point now) {
    std::lock_guard lock(mutex_);
    // Expired grants, and any made for another account or refresh token (a session can't change either, but a grant
    // never outlives the binding it was made under), are dropped.
    std::erase_if(grants_, [&](const Grant& g) {
        return now >= g.expires_at || g.user_id != userId || g.refresh_jti != jti;
    });
    const auto bound = targetBound(family) ? target : std::nullopt;
    const auto it = std::ranges::find_if(grants_, [&](const Grant& g) {
        return g.family == family && g.target == bound;
    });
    if (it == grants_.end()) return std::nullopt;
    auto out = *it;
    if (targetBound(family)) grants_.erase(it);  // single use
    return out;
}

std::vector<Grant> SessionState::grants(const std::chrono::system_clock::time_point now) {
    std::lock_guard lock(mutex_);
    std::erase_if(grants_, [&](const Grant& g) { return now >= g.expires_at; });
    return grants_;
}

void SessionState::setCeremony(Ceremony ceremony) {
    std::lock_guard lock(mutex_);
    ceremony_ = std::move(ceremony);
}

std::optional<Ceremony> SessionState::takeCeremony(const std::string_view id) {
    std::lock_guard lock(mutex_);
    if (!ceremony_ || ceremony_->id != id) return std::nullopt;
    auto out = std::move(*ceremony_);
    ceremony_.reset();
    if (std::chrono::steady_clock::now() >= out.expires) return std::nullopt;
    return out;
}

int SessionState::recordFailure(const std::chrono::steady_clock::time_point now) {
    std::lock_guard lock(mutex_);
    while (!failures_.empty() && now - failures_.front() >= kFailureWindow) failures_.pop_front();
    failures_.push_back(now);
    return static_cast<int>(failures_.size());
}

int SessionState::failures(const std::chrono::steady_clock::time_point now) {
    std::lock_guard lock(mutex_);
    while (!failures_.empty() && now - failures_.front() >= kFailureWindow) failures_.pop_front();
    return static_cast<int>(failures_.size());
}

void SessionState::clear() {
    std::lock_guard lock(mutex_);
    grants_.clear();
    ceremony_.reset();
    failures_.clear();
}

}
