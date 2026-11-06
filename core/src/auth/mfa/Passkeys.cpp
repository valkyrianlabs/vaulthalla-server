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

nlohmann::json passkeyDescriptor(const WebAuthnCredential& c) {
    return {{"type", "public-key"}, {"id", webauthn::base64urlEncode(c.credential_id)}, {"transports", c.transports}};
}

std::string passkeyChallenge(const webauthn::Expectation& binding) {
    const auto challenge = passkeyChallenges().issue(binding);
    if (!challenge) throw ops::Refused("rate_limited", "Too many passkey requests are open. Try again shortly.");
    return webauthn::base64urlEncode(*challenge);
}

void passkeyRefusal(const char* ceremony, const uint32_t userId, const webauthn::Failure failure) {
    log::Registry::auth()->warn("[auth::mfa::passkeys] {} refused for user {}: {}", ceremony, userId,
                                webauthn::toString(failure));
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
    const auto response = webauthn::wire::parseAssertion(credentialJson);
    if (!response) {
        passkeyRefusal("assertion", userId, webauthn::Failure::MalformedResponse);
        return std::nullopt;
    }
    const CredentialStore store;
    const auto before = store.find(response->rawId);  // the count the write-back compares against
    const webauthn::Verifier verifier(relyingParty(), passkeyChallenges(), store);
    const auto outcome = verifier.assertion(*response, {.session = sessionUuid,
                                                        .purpose = webauthn::Purpose::Mfa,
                                                        .user = static_cast<int64_t>(userId), .scope = {}});
    const auto row = webAuthnCredential(response->rawId);
    if (!outcome) {
        passkeyRefusal("assertion", userId, outcome.failure);
        if (outcome.suspendCredential && row && row->user_id == userId)
            (void)suspendWebAuthnCredential(userId, row->id, "sign_count_regression");
        return std::nullopt;
    }
    if (!before || !row || row->user_id != userId || !recordAssertion(*outcome.value, before->signCount)) {
        log::Registry::auth()->warn("[auth::mfa::passkeys] assertion of user {} lost a race with another use of "
                                    "its credential", userId);
        return std::nullopt;
    }
    if (outcome.value->counterRegression)
        audit::record({.action = "auth.mfa.webauthn.counter_regression", .outcome = audit::Outcome::Info,
                       .actor_id = userId, .details = {{"factor_id", row->id}}},
                      "[auth::mfa] a synced passkey of user " + std::to_string(userId) +
                          " reported a sign count that did not grow");
    return VerifiedFactor{.factor_id = row->id, .backup_eligible = row->backup_eligible};
}

}
