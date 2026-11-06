#include "protocols/ws/handler/Mfa.hpp"

#include "audit/Trail.hpp"
#include "auth/Manager.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/Passkeys.hpp"
#include "auth/mfa/Pending.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/mfa/Recovery.hpp"
#include "auth/mfa/SignIn.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "crypto/util/uuid.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/Mfa.hpp"
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
    bool recovery_session{false};  // signed in with a recovery code (its replacement factor needs no step-up)
    bool during_recovery{false};   // a factor enrolled now is marked created_during_recovery (that, or the cooldown)
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
    if (session->user) {
        const bool restricted = mfaWsRecoveryRestricted(session);
        return {.user = session->user, .recovery_session = restricted,
                .during_recovery = mfa::recovery::enrollingDuringRecovery(session->user->id, restricted)};
    }
    const auto p = session->mfa().pending();
    if (!p || p->kind != mfa::PendingKind::Enrollment) throw ops::Denied("Sign in first");
    if (p->expired()) mfaWsExpired(session);
    if (!afterFirstFactor && p->enrolled_amr)
        throw ops::Conflict("A first factor is set up: save your recovery codes to finish signing in");
    auto user = mfaWsPendingUser(session, *p);
    // After an MFA reset the guided enrollment runs inside the cooldown: its factor is flagged.
    const bool during = mfa::recovery::enrollingDuringRecovery(user->id, false);
    return {.user = std::move(user), .pending = true, .during_recovery = during};
}

// Adding a factor to an account that already has one is a credential change (account.credentials step-up, design
// 5.4): the first factor of an account needs none (there is nothing to step up with), a pending enrollment is the
// sign-in itself, and a recovery-code session may enroll its replacement factor (design 7.4: required next; the factor
// is flagged created_during_recovery). Checked when the ceremony starts, so the console asks before the
// authenticator does, and again before the factor is stored.
void mfaWsRequireForAnotherFactor(const MfaWsTarget& target) {
    if (target.pending || target.recovery_session || !mfa::policy::hasAllowedFactor(*target.user)) return;
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

// Discoverable sign-in (#358) refuses with one answer whatever went wrong: no passkey, an unknown or suspended one,
// another account's user handle, no user verification, a spent challenge, a deactivated account.
constexpr auto kPasskeySignInFailed = "That passkey couldn't sign you in. Try again, or sign in with your password.";

// auth.passkey.* run on an anonymous web socket only: never on one that is signed in (a connection signs in once,
// #354) or finishing a password sign-in (the router's pending allowlist refuses them too).
void mfaWsAnonymousWeb(const std::shared_ptr<Session>& session) {
    mfaWsWebOnly(session);
    if (session->user)
        throw ops::Refused(std::string(auth::Manager::kAlreadySignedIn), "This connection is already signed in");
    if (session->mfa().pendingKind()) throw ops::Denied("This connection is finishing a sign-in");
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
        const auto user = vh::identities::manager().user(p->user_id);
        const auto credentials = user ? mfa::policy::allowedPasskeys(*user) : std::vector<mfa::WebAuthnCredential>{};
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
            const auto owner = vh::identities::manager().user(p->user_id);
            if (const auto ok = mfa::passkeys::verifyAssertion(session->uuid, p->user_id, credential.dump());
                ok && owner && mfa::policy::factorAllowed(*owner, mfa::FactorKind::WebAuthn, ok->backup_eligible)) {
                amr = std::string(ok->backup_eligible ? auth::session::assurance::kSoftwareKey
                                                      : auth::session::assurance::kHardwareKey);
                factorId = ok->factor_id;
            }
        } else if (method == "totp") {
            // methods() offers totp only when the policy rule allows it (checked above).
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
        // RecoveryRestricted (design 7.4, D4): every other web session of the account is signed out and the key-backup
        // grants of its paired devices revoked; the devices themselves are listed for the person to revoke, never
        // revoked here (a lost browser factor never breaks a Desktop's sync). The cooldown starts.
        const auto effects = mfa::recovery::afterRecoveryCodeSignIn(session, recovery->batch_id, recovery->remaining);
        out["recovery"] = {{"codes_remaining", recovery->remaining}, {"cooldown_until", effects.cooldown_until},
                           {"sessions_revoked", effects.sessions_revoked},
                           {"grants_revoked", effects.grants_revoked}, {"devices", effects.devices}};
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
    const auto& cfg = config::Registry::get().auth.mfa;
    const auto rule = mfa::policy::factorRule(*user);
    const auto cooldown = mfa::recovery::cooldownUntil(user->id);
    json factors = json::array();
    for (const auto& f : mfa::factors(user->id)) {
        json j = f;
        j["allowed"] = mfa::policy::factorAllowed(*user, f);
        factors.push_back(std::move(j));
    }
    return {{"policy", {{"level", std::string(mfa::policy::to_string(mfa::policy::level()))},
                        {"required", requirement.required},
                        {"reason", std::string(mfa::policy::to_string(requirement.reason))},
                        {"webauthn_available", mfa::passkeys::available()},
                        {"admin_webauthn_only", cfg.admin_webauthn_only || cfg.admin_device_bound_only},
                        {"admin_device_bound_only", cfg.admin_device_bound_only},
                        {"totp_allowed", rule.totp},
                        {"synced_passkeys_allowed", rule.synced_passkeys}}},
            {"factors", std::move(factors)},
            {"recovery", {{"active", recovery.active_batch.has_value()},
                          {"remaining", recovery.remaining},
                          {"acknowledged", recovery.active_batch.has_value()},
                          {"pending", recovery.pending_batch.has_value()}}},
            {"cooldown_until", cooldown ? json(*cooldown) : json(nullptr)},
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

    const bool first = !mfa::policy::hasAllowedFactor(*target.user);
    const auto stored = mfa::passkeys::registerCredential(
        session->uuid, target.user->id, credential.dump(),
        {.label = mfaWsLabel(payload, registration->label), .during_recovery = target.during_recovery,
         .device_bound_only = !mfa::policy::factorRule(*target.user).synced_passkeys});
    if (!stored)
        throw ops::Invalid(mfa::policy::factorRule(*target.user).synced_passkeys
                               ? "The passkey could not be registered. Try again."
                               : "The passkey could not be registered. This server accepts only device-bound passkeys "
                                 "(a security key) for administrators, not synced ones.");
    const auto factor = mfaWsFactor(target.user->id, mfa::FactorKind::WebAuthn, stored->id);
    if (!factor) throw std::runtime_error("The passkey was stored but can't be read back");
    return mfaWsAfterEnroll(session, target, first,
                            std::string(stored->backup_eligible ? auth::session::assurance::kSoftwareKey
                                                                : auth::session::assurance::kHardwareKey),
                            *factor);
}

namespace {
// auth.mfa.admin_webauthn_only / admin_device_bound_only: an admin can't set up an authenticator app.
void mfaWsTotpAllowed(const identities::User& user) {
    if (!mfa::policy::factorRule(user).totp)
        throw ops::Invalid("This server's policy allows only passkeys for administrators: set up a passkey instead");
}
}

json Mfa::totpStart(const json& payload, const std::shared_ptr<Session>& session) {
    const auto target = mfaWsTarget(session);
    mfaWsTotpAllowed(*target.user);
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
    mfaWsTotpAllowed(*target.user);
    mfaWsRequireForAnotherFactor(target);
    const bool first = !mfa::policy::hasAllowedFactor(*target.user);
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
        if (!(f.kind == kind && f.id == id) && !f.suspended && mfa::policy::factorAllowed(*user, f))
            anotherUsable = true;
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

json Mfa::passkeyOptions(const std::shared_ptr<Session>& session) {
    mfaWsAnonymousWeb(session);
    if (!mfa::passkeys::available()) throw ops::Invalid("Passkeys are not configured on this server");
    auto publicKey = mfa::passkeys::loginOptions(session->uuid);
    return {{"publicKey", std::move(publicKey)},
            {"expires_at", mfaWsUnix(SysClock::now() + mfa::passkeys::kChallengeTtl)}};
}

json Mfa::passkeyLogin(const json& payload, const std::shared_ptr<Session>& session) {
    mfaWsAnonymousWeb(session);
    const auto credential = payload.find("credential");
    if (credential == payload.end() || !credential->is_object())
        throw ops::Invalid("credential is a PublicKeyCredential's JSON form");

    const auto signedIn = mfa::passkeys::verifyLogin(session->uuid, credential->dump());
    std::shared_ptr<identities::User> user;
    if (signedIn) {
        user = vh::identities::manager().user(signedIn->user_id);
        if (user && (user->systemOnly() || !user->authorizing())) {
            log::Registry::auth()->warn("[auth::mfa] passkey sign-in refused for {}: the account can't sign in",
                                        user->name());
            user = nullptr;
        } else if (user && !mfa::policy::factorAllowed(*user, mfa::FactorKind::WebAuthn,
                                                       signedIn->factor.backup_eligible)) {
            log::Registry::auth()->warn("[auth::mfa] passkey sign-in refused for {}: the policy allows only "
                                        "device-bound passkeys for this account", user->name());
            user = nullptr;
        }
    }
    if (!user) {
        audit::record({.action = "auth.passkey.login", .outcome = audit::Outcome::Failure,
                       .actor_id = signedIn ? std::optional<uint32_t>(signedIn->user_id) : std::nullopt,
                       .details = {{"ip", session->ipAddress}}},
                      "[auth] a passkey sign-in was refused", spdlog::level::warn);
        throw std::runtime_error(kPasskeySignInFailed);
    }

    // A UV passkey alone is aal 2 (design 4.1): possession plus the authenticator's own PIN or biometric.
    const auto amr = std::string(signedIn->factor.backup_eligible ? auth::session::assurance::kSoftwareKey
                                                                  : auth::session::assurance::kHardwareKey);
    mfa::signin::complete(session, user, {.aal = 2, .amr = {amr}}, "passkey");
    audit::record({.action = "auth.passkey.login", .actor_id = user->id, .actor = user->name(),
                   .details = {{"factor_id", signedIn->factor.factor_id}, {"amr", amr}, {"ip", session->ipAddress}}},
                  "[auth] " + user->name() + " signed in with a passkey");
    return mfaWsSignedInAnswer(session);
}

json Mfa::adminStatus(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& user = mfaWsSignedIn(session);
    return ops::mfa::status(user, payload.at("user_id").get<uint32_t>(), ops::mfa::Channel::Web);
}

json Mfa::adminRequire(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& user = mfaWsSignedIn(session);
    const auto id = payload.at("user_id").get<uint32_t>();
    ops::mfa::require(user, id, payload.at("required").get<bool>(), ops::mfa::Channel::Web);
    return ops::mfa::status(user, id, ops::mfa::Channel::Web);
}

json Mfa::adminReset(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& user = mfaWsSignedIn(session);
    return ops::mfa::reset(user, payload.at("user_id").get<uint32_t>(), payload.at("reason").get<std::string>(),
                           ops::mfa::Channel::Web);
}

}
