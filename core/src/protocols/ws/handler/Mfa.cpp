#include "protocols/ws/handler/Mfa.hpp"

#include "audit/Trail.hpp"
#include "auth/Manager.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/Passkeys.hpp"
#include "auth/mfa/Pending.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/mfa/SignIn.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "auth/stepup/StepUp.hpp"
#include "crypto/util/uuid.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/Sessions.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/Refusal.hpp"
#include "protocols/ws/handler/Auth.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>

namespace vh::protocols::ws::handler {

namespace {

namespace mfa = auth::mfa;
using SysClock = std::chrono::system_clock;

int64_t mfaWsUnix(const SysClock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

// The refresh row a signed-in web session holds (its proof is the authority, never a claim).
const auth::model::RefreshToken* mfaWsRow(const std::shared_ptr<Session>& session) {
    if (!session || !session->tokens || !session->tokens->refreshToken) return nullptr;
    return session->tokens->refreshToken.get();
}

// A session signed in with a recovery code (design section 7.4: RecoveryRestricted). Factors it enrolls are flagged.
bool mfaWsRecoveryRestricted(const std::shared_ptr<Session>& session) {
    const auto* row = mfaWsRow(session);
    return session && session->user && row &&
           std::ranges::find(row->amr, std::string(auth::session::assurance::kRecoveryCode)) != row->amr.end();
}

[[noreturn]] void mfaWsExpired(const std::shared_ptr<Session>& session) {
    mfa::signin::end(session, "expired");
    throw ops::Refused("mfa_expired", "The sign-in timed out. Enter your password again.");
}

// Who an enrollment command acts for: the signed-in web user, or the account of a pending enrollment.
struct MfaWsTarget {
    std::shared_ptr<identities::User> user;
    bool pending{false};
    bool during_recovery{false};
};

std::shared_ptr<identities::User> mfaWsPendingUser(const std::shared_ptr<Session>& session, const mfa::Pending& p) {
    auto user = vh::identities::manager().user(p.user_id);
    if (!user || user->systemOnly() || !user->authorizing()) {
        mfa::signin::end(session, "account_unavailable");
        throw std::runtime_error(auth::Manager::kLoginFailed);
    }
    return user;
}

void mfaWsWebOnly(const std::shared_ptr<Session>& session) {
    if (!session) throw std::runtime_error("No session");
    if (session->onDeviceListener() || session->isShareSession())
        throw ops::Denied("Sign-in factors are managed in the web console");
}

// `afterFirstFactor`: the pending enrollment already has its factor (only the recovery acknowledgement remains).
MfaWsTarget mfaWsTarget(const std::shared_ptr<Session>& session, const bool afterFirstFactor = false) {
    mfaWsWebOnly(session);
    if (session->user) return {.user = session->user, .during_recovery = mfaWsRecoveryRestricted(session)};
    const auto p = session->mfa().pending();
    if (!p || p->kind != mfa::PendingKind::Enrollment) throw ops::Denied("Sign in first");
    if (p->expired()) mfaWsExpired(session);
    if (!afterFirstFactor && p->enrolled_amr)
        throw ops::Conflict("A first factor is set up: save your recovery codes to finish signing in");
    return {.user = mfaWsPendingUser(session, *p), .pending = true};
}

// Adding a factor to an account that already has one is a credential change (account.credentials step-up, design
// 5.4): the first factor of an account needs none (there is nothing to step up with), a pending enrollment is the
// sign-in itself, and a recovery-code session may enroll its replacement factor (design 7.4: required next; the factor
// is flagged created_during_recovery). Checked when the ceremony starts, so the console asks before the
// authenticator does, and again before the factor is stored.
void mfaWsRequireForAnotherFactor(const MfaWsTarget& target) {
    if (target.pending || target.during_recovery || !mfa::hasUsableFactor(target.user->id)) return;
    auth::stepup::require(auth::stepup::Family::AccountCredentials);
}

const std::shared_ptr<identities::User>& mfaWsSignedIn(const std::shared_ptr<Session>& session) {
    mfaWsWebOnly(session);
    if (!session->user) throw std::runtime_error("User not authenticated");
    return session->user;
}

std::optional<mfa::Factor> mfaWsFactor(const uint32_t userId, const mfa::FactorKind kind, const uint32_t id) {
    for (auto& f : mfa::factors(userId))
        if (f.kind == kind && f.id == id) return f;
    return std::nullopt;
}

std::string mfaWsLabel(const json& payload, const std::string& fallback) {
    if (payload.contains("label") && payload.at("label").is_string() && !payload.at("label").get<std::string>().empty())
        return payload.at("label").get<std::string>();
    return fallback;
}

// A first factor ends with ten recovery codes, shown once (inactive until acknowledged). A pending enrollment then
// waits for that acknowledgement: it is what completes the sign-in.
json mfaWsAfterEnroll(const std::shared_ptr<Session>& session, const MfaWsTarget& target, const bool first,
                      const std::string& amr, const mfa::Factor& factor) {
    json out{{"factor", factor}};
    if (!first && !target.pending) return out;
    const auto batch = mfa::generateRecoveryCodes(target.user->id);
    out["recovery_codes"] = {{"batch_id", batch.batch_id}, {"codes", batch.codes}};
    if (target.pending)
        (void)session->mfa().updatePending([&](mfa::Pending& p) {
            p.enrolled_amr = amr;
            p.recovery_batch = batch.batch_id;
        });
    return out;
}

std::string mfaWsMethodName(const std::string& amr) {
    if (amr == auth::session::assurance::kOneTimeCode) return "totp";
    if (amr == auth::session::assurance::kRecoveryCode) return "recovery_code";
    return "passkey";
}

json mfaWsSignedInAnswer(const std::shared_ptr<Session>& session) {
    const auto* row = mfaWsRow(session);
    return {{"user", Auth::sessionUser(*session->user)}, {"aal", row ? row->aal : 1}};
}

// This session's live step-up grants (auth.mfa.status step_up): never another session's.
json mfaWsStepUpGrants(const std::shared_ptr<Session>& session) {
    json out = json::array();
    for (const auto& g : session->stepUp().grants())
        out.push_back({{"family", std::string(auth::stepup::to_string(g.family))},
                       {"target", g.target ? json(*g.target) : json(nullptr)},
                       {"expires_at", mfaWsUnix(g.expires_at)}});
    return out;
}

[[noreturn]] void mfaWsRateLimited(const std::chrono::seconds retryAfter) {
    throw core::DetailedRefusal("rate_limited",
                                "Too many failed attempts on this account. Try again in " +
                                    std::to_string(retryAfter.count()) + "s.",
                                {{"retry_after", retryAfter.count()}});
}

}

json Mfa::pending(const std::shared_ptr<Session>& session) {
    const auto p = session ? session->mfa().pending() : std::nullopt;
    if (!p) throw ops::Denied("Sign in first");
    json out{{"kind", p->kind == mfa::PendingKind::Enrollment ? "enrollment" : "mfa"},
             {"expires_at", mfaWsUnix(p->expires_at)},
             {"methods", p->methods},
             {"attempts_remaining", std::max(0, mfa::kPendingMaxFailures - p->failures)}};
    if (p->kind == mfa::PendingKind::Mfa && std::ranges::find(p->methods, "webauthn") != p->methods.end()) {
        const auto credentials = mfa::passkeys::usableCredentials(p->user_id);
        if (!credentials.empty())
            out["webauthn"] = {{"publicKey", mfa::passkeys::requestOptions(session->uuid, p->user_id, credentials)}};
    }
    return out;
}

void Mfa::throwPending(const std::shared_ptr<Session>& session) {
    const auto kind = session->mfa().pendingKind();
    if (!kind) throw std::runtime_error("No pending sign-in");
    throw core::DetailedRefusal(std::string(mfa::refusalCode(*kind)),
                                *kind == mfa::PendingKind::Enrollment
                                    ? "Set up a second factor to finish signing in"
                                    : "Confirm it's you with your second factor",
                                {{"pending", pending(session)}});
}

json Mfa::verify(const json& payload, const std::shared_ptr<Session>& session) {
    if (!session) throw std::runtime_error("No session");
    const auto p = session->mfa().pending();
    if (!p) throw ops::Denied("Sign in first");
    if (p->expired()) mfaWsExpired(session);
    if (p->kind != mfa::PendingKind::Mfa)
        throw ops::Invalid("This sign-in sets up a first factor: there is nothing to verify yet");

    const auto method = payload.at("method").get<std::string>();
    // A passkey ceremony asks for a fresh challenge first when the one it holds has expired (120 s): not an attempt.
    if (method == "webauthn" && !payload.contains("credential")) throwPending(session);
    if (std::ranges::find(p->methods, method) == p->methods.end())
        throw ops::Invalid("That method can't be used for this sign-in");
    if (const auto wait = mfa::signin::accountRetryAfter(p->user_id); wait.count() > 0) mfaWsRateLimited(wait);

    std::optional<std::string> amr;
    std::optional<uint32_t> factorId;
    std::optional<mfa::RecoveryUse> recovery;
    try {
        if (method == "webauthn") {
            const auto& credential = payload.at("credential");
            if (!credential.is_object()) throw ops::Invalid("credential is a PublicKeyCredential's JSON form");
            if (const auto ok = mfa::passkeys::verifyAssertion(session->uuid, p->user_id, credential.dump())) {
                amr = std::string(ok->backup_eligible ? auth::session::assurance::kSoftwareKey
                                                      : auth::session::assurance::kHardwareKey);
                factorId = ok->factor_id;
            }
        } else if (method == "totp") {
            if (const auto id = mfa::verifyTotp(p->user_id, payload.at("code").get<std::string>())) {
                amr = std::string(auth::session::assurance::kOneTimeCode);
                factorId = *id;
            }
        } else if (method == "recovery_code") {
            recovery = mfa::useRecoveryCode(p->user_id, payload.at("code").get<std::string>(), session->ipAddress);
            if (recovery) amr = std::string(auth::session::assurance::kRecoveryCode);
        } else {
            throw ops::Invalid("method is webauthn, totp or recovery_code");
        }
    } catch (const mfa::keys::Unavailable&) {
        // The server can't check this kind of factor now (its sealed key): not the person's failure.
        throw std::runtime_error("This kind of code can't be checked on this server right now. Use another method.");
    }

    if (!amr) {
        mfa::signin::recordAccountFailure(p->user_id);
        int failures = 0;
        (void)session->mfa().updatePending([&](mfa::Pending& state) { failures = ++state.failures; });
        const int remaining = std::max(0, mfa::kPendingMaxFailures - failures);
        audit::record({.action = "auth.mfa.verify", .outcome = remaining == 0 ? audit::Outcome::Denied
                                                                              : audit::Outcome::Failure,
                       .actor_id = p->user_id,
                       .details = {{"method", method}, {"attempts", failures}, {"ip", session->ipAddress}}},
                      "[auth] a second factor (" + method + ") was refused for user " + std::to_string(p->user_id),
                      spdlog::level::warn);
        if (remaining == 0) {
            mfa::signin::end(session, "too_many_failures");
            throw core::DetailedRefusal("mfa_invalid", "Too many attempts. Enter your password again.",
                                        {{"attempts_remaining", 0}});
        }
        json details{{"attempts_remaining", remaining}};
        try {
            details["pending"] = pending(session);
        } catch (const std::exception&) {
            // No fresh passkey challenge (store full): the codes still work.
        }
        throw core::DetailedRefusal("mfa_invalid", "That didn't work. Try again.", std::move(details));
    }

    const auto user = mfaWsPendingUser(session, *p);
    const auto attempts = p->failures + 1;
    mfa::signin::complete(session, user,
                          {.aal = 2, .amr = {std::string(auth::session::assurance::kPassword), *amr}},
                          "password+" + mfaWsMethodName(*amr));
    mfa::signin::clearAccountFailures(user->id);
    audit::record({.action = "auth.mfa.verify", .actor_id = user->id, .actor = user->name(),
                   .details = {{"method", method}, {"factor_id", factorId ? json(*factorId) : json(nullptr)},
                               {"attempts", attempts}}},
                  "[auth] " + user->name() + " confirmed the sign-in with a second factor (" + method + ")");

    json out = mfaWsSignedInAnswer(session);
    if (recovery) {
        // RecoveryRestricted (design 7.4, D4): every other web session of the account is signed out now; paired
        // devices are not touched (a lost browser factor never breaks a Desktop's sync). The cooldown starts; what
        // it refuses is the policy issue's (#360).
        const auto cooldown = mfa::startRecoveryCooldown(user->id);
        const auto jti = session->tokens->refreshToken->jti;
        const auto revoked = ops::sessions::revoke(user, jti, {.all_others = true}, session);
        audit::record({.action = "auth.mfa.recovery.signin", .outcome = audit::Outcome::Info, .actor_id = user->id,
                       .actor = user->name(),
                       .details = {{"batch_id", recovery->batch_id}, {"remaining", recovery->remaining},
                                   {"sessions_revoked", revoked}, {"cooldown_until", cooldown}}},
                      "[auth] " + user->name() + " signed in with a recovery code; other web sessions were "
                      "signed out");
        out["recovery"] = {{"codes_remaining", recovery->remaining}, {"cooldown_until", cooldown},
                           {"sessions_revoked", revoked}};
    }
    return out;
}

json Mfa::cancel(const std::shared_ptr<Session>& session) {
    if (!session || !session->mfa().pendingKind()) throw ops::Denied("Sign in first");
    mfa::signin::end(session, "cancelled");
    return json::object();
}

json Mfa::status(const std::shared_ptr<Session>& session) {
    const auto& user = mfaWsSignedIn(session);
    const auto requirement = mfa::policy::requirement(*user);
    const auto recovery = mfa::recoveryStatus(user->id);
    const auto state = mfa::userState(user->id);
    json factors = json::array();
    for (const auto& f : mfa::factors(user->id)) factors.push_back(f);
    return {{"policy", {{"level", std::string(mfa::policy::to_string(mfa::policy::level()))},
                        {"required", requirement.required},
                        {"reason", std::string(mfa::policy::to_string(requirement.reason))},
                        {"webauthn_available", mfa::passkeys::available()},
                        {"admin_webauthn_only", false},
                        {"admin_device_bound_only", false}}},
            {"factors", std::move(factors)},
            {"recovery", {{"active", recovery.active_batch.has_value()},
                          {"remaining", recovery.remaining},
                          {"acknowledged", recovery.active_batch.has_value()},
                          {"pending", recovery.pending_batch.has_value()}}},
            {"cooldown_until", state && state->recovery_cooldown_until ? json(*state->recovery_cooldown_until)
                                                                      : json(nullptr)},
            {"recovery_restricted", mfaWsRecoveryRestricted(session)},
            {"step_up", mfaWsStepUpGrants(session)}};
}

json Mfa::registerOptions(const json& payload, const std::shared_ptr<Session>& session) {
    const auto target = mfaWsTarget(session);
    if (!mfa::passkeys::available())
        throw ops::Invalid("Passkeys are not configured on this server (auth.webauthn.rp_id and origins)");
    mfaWsRequireForAnotherFactor(target);
    auto options = mfa::passkeys::creationOptions(session->uuid, target.user->id, target.user->name());
    const auto id = crypto::util::uuid4_hex();
    session->mfa().setRegistration({.id = id,
                                    .user_id = target.user->id,
                                    .label = mfaWsLabel(payload, "Passkey"),
                                    .expires = std::chrono::steady_clock::now() + mfa::passkeys::kChallengeTtl});
    return {{"registration_id", id}, {"publicKey", std::move(options)}};
}

json Mfa::registerFinish(const json& payload, const std::shared_ptr<Session>& session) {
    const auto target = mfaWsTarget(session);
    mfaWsRequireForAnotherFactor(target);  // before the registration is spent: a resend after a step-up still has it
    const auto registration = session->mfa().takeRegistration(payload.at("registration_id").get<std::string>());
    if (!registration || registration->user_id != target.user->id)
        throw ops::NotFound("That passkey setup expired. Start again.");
    const auto& credential = payload.at("credential");
    if (!credential.is_object()) throw ops::Invalid("credential is a PublicKeyCredential's JSON form");

    const bool first = !mfa::hasUsableFactor(target.user->id);
    const auto stored = mfa::passkeys::registerCredential(
        session->uuid, target.user->id, credential.dump(),
        {.label = mfaWsLabel(payload, registration->label), .during_recovery = target.during_recovery});
    if (!stored) throw ops::Invalid("The passkey could not be registered. Try again.");
    const auto factor = mfaWsFactor(target.user->id, mfa::FactorKind::WebAuthn, stored->id);
    if (!factor) throw std::runtime_error("The passkey was stored but can't be read back");
    return mfaWsAfterEnroll(session, target, first,
                            std::string(stored->backup_eligible ? auth::session::assurance::kSoftwareKey
                                                                : auth::session::assurance::kHardwareKey),
                            *factor);
}

json Mfa::totpStart(const json& payload, const std::shared_ptr<Session>& session) {
    const auto target = mfaWsTarget(session);
    mfaWsRequireForAnotherFactor(target);
    try {
        const auto started = mfa::startTotp(target.user->id, {.label = mfaWsLabel(payload, "Authenticator app"),
                                                              .account = target.user->name(),
                                                              .during_recovery = target.during_recovery});
        return {{"enrollment_id", started.factor_id},
                {"secret_base32", started.secret_base32},
                {"otpauth_uri", started.otpauth_uri},
                {"expires_at", started.expires_at}};
    } catch (const mfa::keys::Unavailable&) {
        throw std::runtime_error("Authenticator apps can't be set up on this server right now (its sealed key is "
                                 "unavailable). Use a passkey.");
    }
}

json Mfa::totpConfirm(const json& payload, const std::shared_ptr<Session>& session) {
    const auto target = mfaWsTarget(session);
    mfaWsRequireForAnotherFactor(target);
    const bool first = !mfa::hasUsableFactor(target.user->id);
    try {
        const auto factor = mfa::confirmTotp(target.user->id, payload.at("enrollment_id").get<uint32_t>(),
                                             payload.at("code").get<std::string>());
        if (!factor) throw ops::Invalid("That code didn't match. Check the time on your device and try again.");
        return mfaWsAfterEnroll(session, target, first, std::string(auth::session::assurance::kOneTimeCode),
                                *factor);
    } catch (const mfa::keys::Unavailable&) {
        throw std::runtime_error("Authenticator apps can't be set up on this server right now. Use a passkey.");
    }
}

json Mfa::renameFactor(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& user = mfaWsSignedIn(session);
    const auto kindName = payload.at("kind").get<std::string>();
    if (kindName != "webauthn" && kindName != "totp") throw ops::Invalid("kind is webauthn or totp");
    const auto kind = kindName == "webauthn" ? mfa::FactorKind::WebAuthn : mfa::FactorKind::Totp;
    const auto id = payload.at("id").get<uint32_t>();
    if (!mfa::renameFactor(user->id, kind, id, payload.at("label").get<std::string>()))
        throw ops::NotFound("No such factor on your account");
    const auto factor = mfaWsFactor(user->id, kind, id);
    if (!factor) throw ops::NotFound("No such factor on your account");
    return {{"factor", *factor}};
}

json Mfa::removeFactor(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& user = mfaWsSignedIn(session);
    const auto kindName = payload.at("kind").get<std::string>();
    if (kindName != "webauthn" && kindName != "totp") throw ops::Invalid("kind is webauthn or totp");
    const auto kind = kindName == "webauthn" ? mfa::FactorKind::WebAuthn : mfa::FactorKind::Totp;
    const auto id = payload.at("id").get<uint32_t>();
    if (!mfaWsFactor(user->id, kind, id)) throw ops::NotFound("No such factor on your account");

    // Design 7.2: never the last usable factor of an account that must have MFA.
    bool anotherUsable = false;
    for (const auto& f : mfa::factors(user->id))
        if (!(f.kind == kind && f.id == id) && !f.suspended) anotherUsable = true;
    if (!anotherUsable && mfa::policy::requirement(*user).required)
        throw ops::Refused("mfa_last_factor",
                           "This is the last sign-in factor of an account that must have MFA: add another one first");

    auth::stepup::require(auth::stepup::Family::AccountCredentials);
    // Disabled and kept for the audit trail (auth.mfa.factor.remove), never usable again.
    if (!mfa::removeFactor(user->id, kind, id)) throw ops::NotFound("No such factor on your account");

    // Removing a factor signs the account's other web sessions out (design 7.2): one of them may hold it.
    std::size_t revoked = 0;
    if (const auto* row = mfaWsRow(session))
        revoked = ops::sessions::revoke(user, row->jti, {.all_others = true}, session);
    return {{"sessions_revoked", revoked}};
}

json Mfa::generateRecovery(const std::shared_ptr<Session>& session) {
    const auto& user = mfaWsSignedIn(session);
    if (!mfa::hasUsableFactor(user->id))
        throw ops::Invalid("Add a passkey or an authenticator app first: recovery codes stand in for them");
    // Replacing working codes is a credential change (account.credentials step-up), except for the recovery-code
    // session that is spending the old batch (design 7.4: new codes are required next).
    if (mfa::recoveryStatus(user->id).active_batch && !mfaWsRecoveryRestricted(session))
        auth::stepup::require(auth::stepup::Family::AccountCredentials);
    try {
        const auto batch = mfa::generateRecoveryCodes(user->id);
        return {{"batch_id", batch.batch_id}, {"codes", batch.codes}};
    } catch (const mfa::keys::Unavailable&) {
        throw std::runtime_error("Recovery codes can't be made on this server right now (its sealed key is "
                                 "unavailable).");
    }
}

json Mfa::acknowledgeRecovery(const json& payload, const std::shared_ptr<Session>& session) {
    const auto target = mfaWsTarget(session, true);
    const auto batchId = payload.at("batch_id").get<std::string>();
    if (!target.pending) return {{"remaining", mfa::acknowledgeRecoveryCodes(target.user->id, batchId)}};

    const auto p = session->mfa().pending();
    if (!p || !p->enrolled_amr || !p->recovery_batch)
        throw ops::Invalid("Set up a passkey or an authenticator app first");
    if (*p->recovery_batch != batchId) throw ops::NotFound("no such pending recovery code batch");
    const auto remaining = mfa::acknowledgeRecoveryCodes(target.user->id, batchId);
    const auto amr = *p->enrolled_amr;
    mfa::signin::complete(session, target.user,
                          {.aal = 2, .amr = {std::string(auth::session::assurance::kPassword), amr}},
                          "enrollment+" + mfaWsMethodName(amr));
    json out = mfaWsSignedInAnswer(session);
    out["remaining"] = remaining;
    return out;
}

}
