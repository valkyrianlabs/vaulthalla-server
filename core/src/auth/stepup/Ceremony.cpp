// The step-up ceremony (auth.stepup.begin / auth.stepup.finish; auth/stepup/StepUp.hpp, design section 5.4).

#include "auth/stepup/StepUp.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/Passkeys.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Manager.hpp"
#include "crypto/util/hash.hpp"
#include "crypto/util/uuid.hpp"
#include "db/query/identities/Loader.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/Sessions.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace vh::auth::stepup {

namespace {

struct StepUpCaller {
    std::shared_ptr<identities::User> user;
    std::string jti;
};

// A signed-in console session: the only place a person can step up (a paired device approves with its approval key,
// #361; agents never can).
StepUpCaller stepUpWebCaller(const std::shared_ptr<protocols::ws::Session>& session) {
    if (!session) throw std::runtime_error("No session");
    if (session->onDeviceListener())
        throw ops::Denied("A paired device can't confirm this by itself: do it in the web console");
    if (session->isShareSession() || !session->user || !session->tokens || !session->tokens->refreshToken)
        throw ops::Denied("Sign in first");
    return {.user = session->user, .jti = session->tokens->refreshToken->jti};
}

int64_t stepUpUnix(const std::chrono::system_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

bool stepUpPrintable(const std::string& s) {
    return std::ranges::all_of(s, [](const char c) { return c >= 0x20 && c < 0x7f; });
}

bool stepUpPasswordMatches(const uint32_t userId, const std::string& password) {
    const auto credentials = db::query::identities::Loader::credentialsById(userId);
    if (!credentials || credentials->systemOnly || !credentials->active) return false;
    return crypto::hash::verifyPassword(password, credentials->passwordHash);
}

std::string stepUpString(const nlohmann::json& payload, const char* key) {
    if (!payload.contains(key) || !payload.at(key).is_string()) throw ops::Invalid(std::string(key) + " is required");
    return payload.at(key).get<std::string>();
}

nlohmann::json stepUpTarget(const std::optional<std::string>& target) {
    return target ? nlohmann::json(*target) : nlohmann::json(nullptr);
}

}

std::string challengeScope(const Family family, const std::optional<std::string>& target) {
    return "stepup\x1f" + std::string(to_string(family)) + "\x1f" + (targetBound(family) ? target.value_or("") : "");
}

nlohmann::json begin(const std::shared_ptr<protocols::ws::Session>& session, const Family family,
                     const std::optional<std::string>& target) {
    const auto caller = stepUpWebCaller(session);
    std::optional<std::string> bound;
    if (targetBound(family)) {
        if (!target || target->empty() || target->size() > kMaxTargetLength || !stepUpPrintable(*target))
            throw ops::Invalid("target is required for " + std::string(to_string(family)) +
                               ": pass the one the step_up_required refusal named");
        bound = target;
    }
    auto ways = methods(*caller.user, family);
    if (ways.empty())
        throw ops::Refused("step_up_unavailable",
                           "Add a passkey or an authenticator app to your account first (Account > Security): this "
                           "change can't be confirmed with a password alone");

    Ceremony ceremony{.id = crypto::util::uuid4_hex(),
                      .user_id = caller.user->id,
                      .family = family,
                      .target = bound,
                      .methods = ways,
                      .expires = std::chrono::steady_clock::now() + kCeremonyTtl};
    nlohmann::json out{{"stepup_id", ceremony.id},
                       {"family", std::string(to_string(family))},
                       {"target", stepUpTarget(bound)},
                       {"methods", ways},
                       {"expires_at", stepUpUnix(std::chrono::system_clock::now() + kCeremonyTtl)},
                       {"max_age_seconds", ttl().count()}};
    if (std::ranges::find(ways, "webauthn") != ways.end()) {
        const auto credentials = mfa::passkeys::usableCredentials(caller.user->id);
        out["webauthn"] = {{"publicKey", mfa::passkeys::stepUpOptions(session->uuid, caller.user->id, credentials,
                                                                      challengeScope(family, bound))}};
    }
    session->stepUp().setCeremony(std::move(ceremony));
    return out;
}

Finished finish(const std::shared_ptr<protocols::ws::Session>& session, const nlohmann::json& payload) {
    const auto caller = stepUpWebCaller(session);
    // A ceremony is the person's input: it keeps the session from idling out (design 5.5).
    if (const auto& manager = runtime::Deps::get().sessionManager) manager->noteUserActivity(session);

    const auto id = stepUpString(payload, "stepup_id");
    const auto method = stepUpString(payload, "method");
    const auto ceremony = session->stepUp().takeCeremony(id);
    if (!ceremony || ceremony->user_id != caller.user->id)
        throw ops::NotFound("That confirmation expired. Start again.");
    if (std::ranges::find(ceremony->methods, method) == ceremony->methods.end())
        throw ops::Invalid("That method can't confirm this change");
    const auto familyName = std::string(to_string(ceremony->family));

    bool ok = false;
    std::optional<uint32_t> factorId;
    try {
        if (method == "webauthn") {
            if (!payload.contains("credential") || !payload.at("credential").is_object())
                throw ops::Invalid("credential is a PublicKeyCredential's JSON form");
            if (const auto v = mfa::passkeys::verifyStepUp(session->uuid, caller.user->id,
                                                           payload.at("credential").dump(),
                                                           challengeScope(ceremony->family, ceremony->target))) {
                ok = true;
                factorId = v->factor_id;
            }
        } else if (method == "password_totp") {
            // Both, always: a TOTP code alone is never enough. The code is only tried (and its step spent) after the
            // password held.
            const auto password = stepUpString(payload, "password");
            const auto code = stepUpString(payload, "code");
            if (stepUpPasswordMatches(caller.user->id, password))
                if (const auto totp = mfa::verifyTotp(caller.user->id, code)) {
                    ok = true;
                    factorId = *totp;
                }
        } else if (method == "password") {
            // D3, decided again now: the account may have enrolled a factor or become required since begin.
            const auto now = methods(*caller.user, ceremony->family);
            if (std::ranges::find(now, "password") == now.end())
                throw ops::Invalid("A password alone can't confirm this change");
            ok = stepUpPasswordMatches(caller.user->id, stepUpString(payload, "password"));
        } else {
            throw ops::Invalid("method is webauthn, password_totp or password");
        }
    } catch (const mfa::keys::Unavailable&) {
        throw std::runtime_error("Authenticator codes can't be checked on this server right now. Use a passkey.");
    }

    if (!ok) {
        const int failures = session->stepUp().recordFailure();
        const int remaining = std::max(0, kMaxFailures - failures);
        audit::record({.action = "auth.stepup.fail", .outcome = audit::Outcome::Failure, .actor_id = caller.user->id,
                       .actor = caller.user->name(),
                       .details = {{"family", familyName}, {"target", stepUpTarget(ceremony->target)},
                                   {"method", method}, {"failures", failures}}},
                      "[auth::stepup] a " + familyName + " step-up (" + method + ") failed for " +
                          caller.user->name(),
                      spdlog::level::warn);
        if (remaining == 0) {
            // Five failures in 15 minutes: a session guessing is likely not its person's. Revoked: its row and every
            // socket on it (this one after the answer).
            std::size_t revoked = 0;
            try {
                revoked = ops::sessions::revoke(caller.user, caller.jti, {.id = ops::sessions::handle(caller.jti)},
                                                session);
            } catch (const std::exception& e) {
                log::Registry::auth()->error("[auth::stepup] revoking the session of {} failed: {}",
                                             caller.user->name(), e.what());
                if (const auto& manager = runtime::Deps::get().sessionManager) manager->invalidate(session);
                session->closeAfterReply();
            }
            audit::record({.action = "auth.stepup.fail", .outcome = audit::Outcome::Denied,
                           .actor_id = caller.user->id, .actor = caller.user->name(),
                           .details = {{"family", familyName}, {"reason", "too_many_failures"},
                                       {"sessions_revoked", static_cast<int64_t>(revoked)}}},
                          "[auth::stepup] " + caller.user->name() + "'s session was signed out after " +
                              std::to_string(kMaxFailures) + " failed step-ups",
                          spdlog::level::warn);
        }
        return {.grant = std::nullopt, .attempts_remaining = remaining};
    }

    Grant grant{.user_id = caller.user->id,
                .refresh_jti = caller.jti,
                .family = ceremony->family,
                .target = ceremony->target,
                .method = method,
                .expires_at = std::chrono::system_clock::now() + ttl()};
    session->stepUp().addGrant(grant);
    audit::record({.action = "auth.stepup.grant", .actor_id = caller.user->id, .actor = caller.user->name(),
                   .details = {{"family", familyName}, {"target", stepUpTarget(grant.target)}, {"method", method},
                               {"factor_id", factorId ? nlohmann::json(*factorId) : nlohmann::json(nullptr)},
                               {"ttl_seconds", ttl().count()}}},
                  "[auth::stepup] " + caller.user->name() + " stepped up for " + familyName + " (" + method + ")");
    return {.grant = std::move(grant), .attempts_remaining = std::max(0, kMaxFailures - session->stepUp().failures())};
}

}
