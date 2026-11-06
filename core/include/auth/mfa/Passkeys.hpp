#pragma once

#include "auth/mfa/Factors.hpp"
#include "auth/webauthn/Types.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The daemon's side of the WebAuthn verifier (#357; MFA design note section 4.1): the relying party as configured
// (auth.webauthn.*, never request headers), the process-wide challenge store (single use, 120 s, bound to the ws
// session, purpose and account), the ceremony options in their WebAuthn L3 JSON forms, and the two ceremonies the
// sign-in flow runs: registering a passkey and asserting one as the second factor (purpose `mfa`). Every refusal is
// uniform to the caller; the verifier's reason goes to the auth log.
namespace vh::auth::mfa::passkeys {

inline constexpr std::chrono::seconds kChallengeTtl{120};

[[nodiscard]] webauthn::RelyingParty relyingParty();
// Whether passkeys can be used at all: an rp_id and origins are configured.
[[nodiscard]] bool available();

// Drops a socket's open challenges (sign-out, cancel, socket closed).
void forgetSession(std::string_view sessionUuid) noexcept;

// The account's passkeys the configured relying party can use now: not suspended, made for this rp_id.
[[nodiscard]] std::vector<WebAuthnCredential> usableCredentials(uint32_t userId);

// PublicKeyCredentialRequestOptionsJSON for the sign-in second factor (purpose mfa): allowCredentials = `credentials`,
// userVerification required. ops::Refused("rate_limited") when the challenge store is full.
[[nodiscard]] nlohmann::json requestOptions(const std::string& sessionUuid, uint32_t userId,
                                            const std::vector<WebAuthnCredential>& credentials);

// PublicKeyCredentialCreationOptionsJSON for a new passkey on the account (purpose register): the account's random
// user handle, -8/-7/-257, residentKey preferred, userVerification required, attestation none, credProps, and
// excludeCredentials = its existing passkeys. ops::Invalid when passkeys are unavailable.
[[nodiscard]] nlohmann::json creationOptions(const std::string& sessionUuid, uint32_t userId,
                                             const std::string& userName);

// Verifies a RegistrationResponseJSON against a challenge this socket holds for the account and stores the
// credential (audited as auth.mfa.factor.enroll). nullopt when refused.
[[nodiscard]] std::optional<WebAuthnCredential> registerCredential(const std::string& sessionUuid, uint32_t userId,
                                                                   std::string_view credentialJson,
                                                                   const RegistrationDetails& details);

struct VerifiedFactor {
    uint32_t factor_id{};
    bool backup_eligible{false};  // a synced passkey (amr swk) rather than a device-bound one (hwk)
};

// Verifies an AuthenticationResponseJSON as the second factor of `userId`'s sign-in on this socket, and writes the
// counter and backup state back. A device-bound counter regression suspends the credential. nullopt when refused.
[[nodiscard]] std::optional<VerifiedFactor> verifyAssertion(const std::string& sessionUuid, uint32_t userId,
                                                            std::string_view credentialJson);

}
