#pragma once

#include "auth/webauthn/Types.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// MFA factor storage (#356; MFA design note docs/dev/mfa-design.md sections 4 and 9, migration 120): the account's
// MFA row (user_mfa), passkeys (webauthn_credentials), TOTP factors with sealed seeds (totp_factors) and recovery
// code batches (recovery_code_batches, recovery_codes). This is the storage and model layer the sign-in flow (#357),
// step-up (#359) and the admin reset (#360) build on; nothing here signs anyone in or decides policy.
//
// Everything is keyed by user id, not by an ops::Actor: a pending-MFA sign-in has no signed-in user yet.
//
// Single use is enforced in the database, never by a read followed by a write: a TOTP step is claimed by
// `UPDATE ... WHERE last_step < step`, a recovery code by `UPDATE ... WHERE used_at IS NULL` on an acknowledged,
// unsuperseded batch, so a replay and two concurrent uses of the same code both fail.
//
// Secrets (seeds, their base32 and otpauth forms, codes) are returned only where the person must see them once, in
// types that wipe themselves, and are never logged or audited. Log lines and audit events name accounts and factors
// by id. TOTP and recovery codes refuse with keys::Unavailable (auth/mfa/Keys.hpp) when their key can't be unsealed;
// passkeys don't depend on either key.
namespace vh::auth::mfa {

enum class FactorKind : uint8_t { WebAuthn, Totp };
[[nodiscard]] std::string_view to_string(FactorKind kind) noexcept;

// One factor as the account sees it (the ws MfaFactor shape). Carries no secret and no full credential id.
struct Factor {
    uint32_t id{};
    FactorKind kind{FactorKind::Totp};
    std::string label{};
    int64_t created_at{};                    // Unix seconds
    std::optional<int64_t> last_used_at{};   // Unix seconds
    std::optional<bool> backup_eligible{};   // passkeys only
    std::optional<bool> backup_state{};      // passkeys only
    std::vector<std::string> transports{};   // passkeys only
    std::optional<std::string> aaguid{};     // passkeys only
    bool suspended{false};
    bool created_during_recovery{false};
};
void to_json(nlohmann::json& j, const Factor& factor);

// ---- the account's MFA row

struct UserMfa {
    uint32_t user_id{};
    std::vector<uint8_t> webauthn_user_handle{};  // 32 random bytes: WebAuthn's user.id, never the numeric id
    bool required{false};
    std::optional<int64_t> recovery_cooldown_until{};
};

// The row, created on first use with a fresh random user handle.
[[nodiscard]] UserMfa ensureUser(uint32_t userId);
[[nodiscard]] std::optional<UserMfa> userState(uint32_t userId);

// The account's factors that are enrolled and not removed (confirmed TOTP, passkeys including suspended ones), oldest
// first.
[[nodiscard]] std::vector<Factor> factors(uint32_t userId);
// Whether the account has a factor it can sign in with now (a confirmed TOTP factor or a passkey that is not
// suspended).
[[nodiscard]] bool hasUsableFactor(uint32_t userId);

// Renames a factor of the account (1..64 characters). False when it has no such factor.
bool renameFactor(uint32_t userId, FactorKind kind, uint32_t id, std::string_view label);
// Removes a factor: it is disabled and kept for the audit trail, never usable again. False when it has no such factor.
// Whether removal is allowed (the last factor under a policy) is the caller's decision.
bool removeFactor(uint32_t userId, FactorKind kind, uint32_t id);

// ---- TOTP

inline constexpr std::chrono::minutes kTotpEnrollmentTtl{10};

struct TotpStart {
    std::string label{};                // 1..64 characters
    std::string account{};              // the otpauth label's account part (the user name)
    std::string issuer{"Vaulthalla"};
    bool during_recovery{false};
};

// What enrollment shows the person once. Wiped when destroyed.
struct TotpEnrollment {
    uint32_t factor_id{};
    std::string secret_base32{};
    std::string otpauth_uri{};
    int64_t expires_at{};  // Unix seconds: confirm before this or start again

    TotpEnrollment() = default;
    TotpEnrollment(TotpEnrollment&& other) noexcept = default;
    TotpEnrollment& operator=(TotpEnrollment&&) = delete;
    TotpEnrollment(const TotpEnrollment&) = delete;
    TotpEnrollment& operator=(const TotpEnrollment&) = delete;
    ~TotpEnrollment();
};

// Generates and seals a seed and stores an unconfirmed factor (unusable until confirmTotp). Replaces the account's
// earlier unconfirmed enrollment, if any. ops::Invalid for a bad label; keys::Unavailable without mfa_seal.
[[nodiscard]] TotpEnrollment startTotp(uint32_t userId, const TotpStart& request);

// Confirms an enrollment with its first correct code (window +-1), within kTotpEnrollmentTtl of starting it: the
// factor becomes usable and the code's step is spent. nullopt for a wrong code; ops::NotFound when there is no such
// pending enrollment (unknown, already confirmed or expired). Audited as auth.mfa.factor.enroll.
[[nodiscard]] std::optional<Factor> confirmTotp(uint32_t userId, uint32_t factorId, std::string_view code,
                                                std::chrono::system_clock::time_point now =
                                                    std::chrono::system_clock::now());

// A sign-in or step-up code: the id of the confirmed factor it matched, claiming its step, or nullopt (wrong code,
// replayed step, drift beyond one step, no TOTP factor). keys::Unavailable without mfa_seal. Not audited here: the
// flow records auth.mfa.verify with its attempt count.
[[nodiscard]] std::optional<uint32_t> verifyTotp(uint32_t userId, std::string_view code,
                                                 std::chrono::system_clock::time_point now =
                                                     std::chrono::system_clock::now());

// Deletes enrollments never confirmed within kTotpEnrollmentTtl (the database sweeper). Returns how many.
std::size_t purgeExpiredTotpEnrollments();

// ---- recovery codes

// A new batch as shown once. Wiped when destroyed.
struct RecoveryBatch {
    std::string batch_id{};
    std::vector<std::string> codes{};  // XXXXX-XXXXX

    RecoveryBatch() = default;
    RecoveryBatch(RecoveryBatch&& other) noexcept = default;
    RecoveryBatch& operator=(RecoveryBatch&&) = delete;
    RecoveryBatch(const RecoveryBatch&) = delete;
    RecoveryBatch& operator=(const RecoveryBatch&) = delete;
    ~RecoveryBatch();
};

// Ten fresh codes in a batch that stays inactive until acknowledged; any earlier unacknowledged batch of the account
// is dropped. The account's active batch keeps working until this one is acknowledged. keys::Unavailable without
// mfa_pepper. Audited as auth.mfa.recovery.generate.
[[nodiscard]] RecoveryBatch generateRecoveryCodes(uint32_t userId);

// Activates the account's pending batch `batchId` and supersedes the previously active one. Returns the codes it
// holds. ops::NotFound when `batchId` is not the account's pending batch. Audited as auth.mfa.recovery.acknowledge.
std::size_t acknowledgeRecoveryCodes(uint32_t userId, const std::string& batchId);

struct RecoveryUse {
    std::string batch_id{};
    std::size_t remaining{};
};
// Spends one code of the account's active batch. nullopt when it is wrong, already used, or belongs to a batch that
// is unacknowledged or superseded. keys::Unavailable without mfa_pepper. Audited as auth.mfa.recovery.use.
[[nodiscard]] std::optional<RecoveryUse> useRecoveryCode(uint32_t userId, std::string_view code,
                                                         const std::string& ip = {});

struct RecoveryStatus {
    std::optional<std::string> active_batch{};
    std::size_t remaining{};                     // unused codes of the active batch
    std::optional<std::string> pending_batch{};  // generated, not yet acknowledged
};
[[nodiscard]] RecoveryStatus recoveryStatus(uint32_t userId);

// ---- passkeys (WebAuthn credentials; the verifier is auth/webauthn, #355)

struct WebAuthnCredential {
    uint32_t id{};
    uint32_t user_id{};
    std::vector<uint8_t> credential_id{};
    std::vector<uint8_t> public_key_cose{};
    int cose_alg{};
    std::string rp_id{};
    std::optional<std::string> aaguid{};
    int64_t sign_count{};
    bool backup_eligible{false};
    bool backup_state{false};
    std::optional<bool> discoverable{};
    std::vector<std::string> transports{};
    std::string attestation_fmt{};
    std::string label{};
    bool created_during_recovery{false};
    int64_t created_at{};
    std::optional<int64_t> last_used_at{};
    std::optional<int64_t> suspended_at{};
    std::optional<std::string> suspended_reason{};
    std::optional<int64_t> disabled_at{};
};

// What a verified registration stores.
struct NewWebAuthnCredential {
    std::vector<uint8_t> credential_id{};  // 16..1023 bytes
    std::vector<uint8_t> public_key_cose{};
    int cose_alg{};                         // -8, -7 or -257
    std::string rp_id{};
    std::optional<std::string> aaguid{};    // canonical UUID
    int64_t sign_count{};
    bool backup_eligible{false};
    bool backup_state{false};
    std::optional<bool> discoverable{};
    std::vector<std::string> transports{};  // lower-case tokens (usb, nfc, ble, internal, hybrid, ...)
    std::string attestation_fmt{};
    std::string label{};                    // 1..64 characters
    bool created_during_recovery{false};
};

// Stores a credential for the account. ops::Conflict when the credential id is registered already (to anyone);
// ops::Invalid for values the table refuses. Audited as auth.mfa.factor.enroll.
[[nodiscard]] WebAuthnCredential addWebAuthnCredential(uint32_t userId, const NewWebAuthnCredential& credential);
// A credential by its credential id, whoever owns it (assertion lookup), unless removed.
[[nodiscard]] std::optional<WebAuthnCredential> webAuthnCredential(std::span<const uint8_t> credentialId);
// The account's credentials that are not removed, oldest first.
[[nodiscard]] std::vector<WebAuthnCredential> webAuthnCredentials(uint32_t userId);
// After a verified assertion: stores the new signCount and backup state, compare-and-set on the count the verifier
// read (`expectedSignCount`), so two concurrent assertions can't both move it. False when the row changed, is
// suspended or was removed.
bool recordWebAuthnUse(uint32_t id, int64_t expectedSignCount, int64_t signCount, bool backupState);
// ---- the verifier's side (auth/webauthn, #355)

// What the registration ceremony reports beside the signed data: the label the person chose, and the client's
// unsigned hints (getTransports(), credProps.rk), stored as hints only.
struct RegistrationDetails {
    std::string label{};
    std::vector<std::string> transports{};
    std::optional<bool> discoverable{};
    bool during_recovery{false};
};

// The storage form of a verified registration (webauthn::verifyRegistration's NewCredential). An all-zero AAGUID is
// stored as none; transport hints that aren't lower-case tokens are dropped.
[[nodiscard]] NewWebAuthnCredential fromVerified(const webauthn::NewCredential& verified,
                                                 const RegistrationDetails& details);

// The verifier's credential lookup (check 11) over webauthn_credentials joined with the owner's user_mfa handle.
// Returns disabled and suspended credentials too, flagged, as the interface asks: the verifier refuses them.
class CredentialStore final : public webauthn::CredentialLookup {
public:
    [[nodiscard]] std::optional<webauthn::StoredCredential> find(webauthn::ByteView credentialId) const override;
};

// Writes back a verified assertion: the new signCount when the verifier says to store it (otherwise the count stays),
// the reported backup state and last_used_at, compare-and-set on `expectedSignCount` (the count the lookup returned).
// False when the row changed meanwhile, or is suspended or removed.
bool recordAssertion(const webauthn::VerifiedAssertion& assertion, uint32_t expectedSignCount);

// Suspends a credential (a device-bound counter regression: possible clone). False when the account has no such live
// credential. Audited as auth.mfa.factor.suspend.
bool suspendWebAuthnCredential(uint32_t userId, uint32_t id, std::string_view reason);

}
