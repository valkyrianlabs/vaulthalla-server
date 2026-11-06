#include "auth/mfa/Passkeys.hpp"

#include "audit/Trail.hpp"
#include "auth/webauthn/Base64Url.hpp"
#include "auth/webauthn/Challenge.hpp"
#include "auth/webauthn/Verifier.hpp"
#include "auth/webauthn/Wire.hpp"
#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

namespace vh::auth::mfa::passkeys {

namespace {

webauthn::ChallengeStore& passkeyChallenges() {
    static webauthn::ChallengeStore store(kChallengeTtl);
    return store;
}

// Discoverable sign-in (purpose login): anonymous sockets ask for these, so they never share capacity with the
// ceremonies of signed-in and pending sockets.
webauthn::ChallengeStore& passkeyLoginChallenges() {
    static webauthn::ChallengeStore store(kChallengeTtl, kMaxLoginChallenges);
    return store;
}

nlohmann::json passkeyDescriptor(const WebAuthnCredential& c) {
    return {{"type", "public-key"}, {"id", webauthn::base64urlEncode(c.credential_id)}, {"transports", c.transports}};
}

std::string passkeyChallenge(const webauthn::Expectation& binding,
                             webauthn::ChallengeStore& store = passkeyChallenges()) {
    const auto challenge = store.issue(binding);
    if (!challenge) throw ops::Refused("rate_limited", "Too many passkey requests are open. Try again shortly.");
    return webauthn::base64urlEncode(*challenge);
}

void passkeyRefusal(const char* ceremony, const uint32_t userId, const webauthn::Failure failure) {
    log::Registry::auth()->warn("[auth::mfa::passkeys] {} refused for user {}: {}", ceremony, userId,
                                webauthn::toString(failure));
}

// An assertion against a challenge of `store` bound to `expected` (purpose mfa for a known account, login for
// discoverable sign-in), then the write-back: the counter and backup state, a suspension on a device-bound counter
// regression, the audit of a synced one. The owner it returns is the credential's, which the verifier has checked
// against expected.user (mfa) or the assertion's userHandle (login).
std::optional<SignedInPasskey> passkeyAssert(webauthn::ChallengeStore& challenges, const webauthn::Expectation& expected,
                                             const std::string_view credentialJson) {
    const auto who = expected.user ? "for user " + std::to_string(*expected.user) : std::string("for a passkey sign-in");
    const auto refuse = [&](const webauthn::Failure failure) {
        log::Registry::auth()->warn("[auth::mfa::passkeys] assertion {} refused: {}", who, webauthn::toString(failure));
    };
    const auto response = webauthn::wire::parseAssertion(credentialJson);
    if (!response) {
        refuse(webauthn::Failure::MalformedResponse);
        return std::nullopt;
    }
    const CredentialStore store;
    const auto before = store.find(response->rawId);  // the count the write-back compares against
    const webauthn::Verifier verifier(relyingParty(), challenges, store);
    const auto outcome = verifier.assertion(*response, expected);
    const auto row = webAuthnCredential(response->rawId);
    if (!outcome) {
        refuse(outcome.failure);
        // The verifier asks for a suspension only once the owner, the user handle and the signature checked out.
        if (outcome.suspendCredential && row && (!expected.user || row->user_id == *expected.user))
            (void)suspendWebAuthnCredential(row->user_id, row->id, "sign_count_regression");
        return std::nullopt;
    }
    const auto owner = static_cast<uint32_t>(outcome.value->userId);
    if (!before || !row || row->user_id != owner || (expected.user && row->user_id != *expected.user) ||
        !recordAssertion(*outcome.value, before->signCount)) {
        log::Registry::auth()->warn("[auth::mfa::passkeys] assertion {} lost a race with another use of its "
                                    "credential", who);
        return std::nullopt;
    }
    if (outcome.value->counterRegression)
        audit::record({.action = "auth.mfa.webauthn.counter_regression", .outcome = audit::Outcome::Info,
                       .actor_id = owner, .details = {{"factor_id", row->id}}},
                      "[auth::mfa] a synced passkey of user " + std::to_string(owner) +
                          " reported a sign count that did not grow");
    return SignedInPasskey{.user_id = owner,
                           .factor = {.factor_id = row->id, .backup_eligible = row->backup_eligible}};
}

}

webauthn::RelyingParty relyingParty() {
    const auto& c = config::Registry::get().auth.webauthn;
    webauthn::RelyingParty rp;
    rp.id = c.rp_id;
    if (!rp.id.empty()) rp.origins = c.origins;
    return rp;
}

bool available() { return relyingParty().configured(); }

void forgetSession(const std::string_view sessionUuid) noexcept {
    try {
        passkeyChallenges().forgetSession(sessionUuid);
        passkeyLoginChallenges().forgetSession(sessionUuid);
    } catch (...) {
        // Nothing to undo: an open challenge expires in kChallengeTtl on its own.
    }
}

std::vector<WebAuthnCredential> usableCredentials(const uint32_t userId) {
    const auto rp = relyingParty();
    std::vector<WebAuthnCredential> out;
    if (!rp.configured()) return out;
    for (auto& c : webAuthnCredentials(userId))
        if (!c.suspended_at && !c.disabled_at && c.rp_id == rp.id) out.push_back(std::move(c));
    return out;
}

nlohmann::json requestOptions(const std::string& sessionUuid, const uint32_t userId,
                              const std::vector<WebAuthnCredential>& credentials) {
    const auto rp = relyingParty();
    if (!rp.configured()) throw ops::Invalid("Passkeys are not configured on this server");
    nlohmann::json allow = nlohmann::json::array();
    for (const auto& c : credentials) allow.push_back(passkeyDescriptor(c));
    return {{"challenge", passkeyChallenge({.session = sessionUuid, .purpose = webauthn::Purpose::Mfa,
                                            .user = static_cast<int64_t>(userId), .scope = {}})},
            {"rpId", rp.id},
            {"timeout", std::chrono::milliseconds(kChallengeTtl).count()},
            {"userVerification", "required"},
            {"allowCredentials", std::move(allow)}};
}

nlohmann::json loginOptions(const std::string& sessionUuid) {
    const auto rp = relyingParty();
    if (!rp.configured()) throw ops::Invalid("Passkeys are not configured on this server");
    return {{"challenge", passkeyChallenge({.session = sessionUuid, .purpose = webauthn::Purpose::Login,
                                            .user = std::nullopt, .scope = {}},
                                           passkeyLoginChallenges())},
            {"rpId", rp.id},
            {"timeout", std::chrono::milliseconds(kChallengeTtl).count()},
            {"userVerification", "required"},
            {"allowCredentials", nlohmann::json::array()}};
}

nlohmann::json creationOptions(const std::string& sessionUuid, const uint32_t userId, const std::string& userName) {
    const auto rp = relyingParty();
    if (!rp.configured())
        throw ops::Invalid("Passkeys are not configured on this server (auth.webauthn.rp_id and origins)");
    const auto mfa = ensureUser(userId);
    nlohmann::json exclude = nlohmann::json::array();
    for (const auto& c : webAuthnCredentials(userId)) exclude.push_back(passkeyDescriptor(c));
    nlohmann::json params = nlohmann::json::array();
    for (const int alg : {-8, -7, -257}) params.push_back({{"type", "public-key"}, {"alg", alg}});
    return {{"rp", {{"id", rp.id}, {"name", config::Registry::get().auth.webauthn.rp_name}}},
            {"user", {{"id", webauthn::base64urlEncode(mfa.webauthn_user_handle)},
                      {"name", userName},
                      {"displayName", userName}}},
            {"challenge", passkeyChallenge({.session = sessionUuid, .purpose = webauthn::Purpose::Register,
                                            .user = static_cast<int64_t>(userId), .scope = {}})},
            {"pubKeyCredParams", std::move(params)},
            {"timeout", std::chrono::milliseconds(kChallengeTtl).count()},
            {"excludeCredentials", std::move(exclude)},
            {"authenticatorSelection", {{"residentKey", "preferred"},
                                        {"requireResidentKey", false},
                                        {"userVerification", "required"}}},
            {"attestation", "none"},
            {"extensions", {{"credProps", true}}}};
}

std::optional<WebAuthnCredential> registerCredential(const std::string& sessionUuid, const uint32_t userId,
                                                     const std::string_view credentialJson,
                                                     const RegistrationDetails& details) {
    const auto response = webauthn::wire::parseRegistration(credentialJson);
    if (!response) {
        passkeyRefusal("registration", userId, webauthn::Failure::MalformedResponse);
        return std::nullopt;
    }
    const CredentialStore store;
    const webauthn::Verifier verifier(relyingParty(), passkeyChallenges(), store);
    const auto outcome = verifier.registration(*response, {.session = sessionUuid,
                                                           .purpose = webauthn::Purpose::Register,
                                                           .user = static_cast<int64_t>(userId), .scope = {}});
    if (!outcome) {
        passkeyRefusal("registration", userId, outcome.failure);
        return std::nullopt;
    }
    const auto stored = fromVerified(*outcome.value, details);
    if (details.device_bound_only && stored.backup_eligible) {
        log::Registry::auth()->warn("[auth::mfa] user {} tried to register a synced passkey; the policy allows only "
                                    "device-bound ones (auth.mfa.admin_device_bound_only)", userId);
        return std::nullopt;
    }
    auto withHints = details;
    withHints.transports = response->transports;
    withHints.discoverable = response->residentKey;
    try {
        return addWebAuthnCredential(userId, fromVerified(*outcome.value, withHints));
    } catch (const ops::Conflict&) {
        passkeyRefusal("registration", userId, webauthn::Failure::CredentialAlreadyRegistered);
        return std::nullopt;
    }
}

std::optional<VerifiedFactor> verifyAssertion(const std::string& sessionUuid, const uint32_t userId,
                                              const std::string_view credentialJson) {
    const auto ok = passkeyAssert(passkeyChallenges(),
                                  {.session = sessionUuid, .purpose = webauthn::Purpose::Mfa,
                                   .user = static_cast<int64_t>(userId), .scope = {}},
                                  credentialJson);
    if (!ok) return std::nullopt;
    return ok->factor;
}

std::optional<SignedInPasskey> verifyLogin(const std::string& sessionUuid, const std::string_view credentialJson) {
    return passkeyAssert(passkeyLoginChallenges(),
                         {.session = sessionUuid, .purpose = webauthn::Purpose::Login, .user = std::nullopt,
                          .scope = {}},
                         credentialJson);
}

nlohmann::json stepUpOptions(const std::string& sessionUuid, const uint32_t userId,
                             const std::vector<WebAuthnCredential>& credentials, const std::string& scope) {
    const auto rp = relyingParty();
    if (!rp.configured()) throw ops::Invalid("Passkeys are not configured on this server");
    nlohmann::json allow = nlohmann::json::array();
    for (const auto& c : credentials) allow.push_back(passkeyDescriptor(c));
    return {{"challenge", passkeyChallenge({.session = sessionUuid, .purpose = webauthn::Purpose::StepUp,
                                            .user = static_cast<int64_t>(userId), .scope = scope})},
            {"rpId", rp.id},
            {"timeout", std::chrono::milliseconds(kChallengeTtl).count()},
            {"userVerification", "required"},
            {"allowCredentials", std::move(allow)}};
}

std::optional<VerifiedFactor> verifyStepUp(const std::string& sessionUuid, const uint32_t userId,
                                           const std::string_view credentialJson, const std::string& scope) {
    const auto ok = passkeyAssert(passkeyChallenges(),
                                  {.session = sessionUuid, .purpose = webauthn::Purpose::StepUp,
                                   .user = static_cast<int64_t>(userId), .scope = scope},
                                  credentialJson);
    if (!ok) return std::nullopt;
    return ok->factor;
}

}
