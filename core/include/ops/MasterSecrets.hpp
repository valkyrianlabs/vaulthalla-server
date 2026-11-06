#pragma once

#include "crypto/secrets/Reseal.hpp"
#include "crypto/secrets/Rewrap.hpp"
#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"

#include <chrono>
#include <cstddef>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// The rotation of the installation's master secrets (#352, #353; design/sealing/master-secrets.md §6). Super admins
// only; every attempt is audited, refusals and failures included. Every mutation needs an explicit confirmation
// (NeedsConfirmation): the CLI asks, or takes --yes. The shell refuses all of them under an agent and MCP never offers
// them (mcp::exclusions).
//
//   `vh secret master status|rotate|finalize|rollback [--slot vault|api-keys|s3-gateway]`
//       the staged rewrap (crypto/secrets/Rewrap.hpp) of a data-wrapping master: vault_master, ak_master, s3gw_master.
//       Audited as secrets.master.{status,rotate,finalize,rollback} with the slot; confirmation codes
//       <slot>_rotate / <slot>_finalize / <slot>_rollback (vault_master_rotate, ak_master_rotate, ...).
//   `vh secret jwt rotate`
//       a fresh JWT secret: every refresh token is revoked and every live session ends, so everyone signs in again.
//       Audited as secrets.jwt.rotate; confirmation code jwt_secret_rotate.
//   `vh secret device-identity rotate`
//       a fresh device listener key: every paired device is revoked and disconnected and has to pair again.
//       Audited as secrets.device_identity.rotate; confirmation code device_identity_rotate.
//   `vh secret reseal [--pcr7|--none]` and `vh secret policy` (#351, design/sealing/master-secrets.md §5)
//       the sealing policy of the installation's sealed secrets (TPM PCR 7, Linux). `policy` shows the configured
//       policy and what every blob carries; `reseal` rebinds every sealed secret to the configured policy at the
//       current PCR values, staged and verified, never changing a secret (crypto/secrets/Reseal.hpp). Binding to PCR 7
//       is refused unless a hardware TPM seals the secrets, every vault's key versions have a confirmed backup and a
//       `vh secret export all` is under 24 hours old; removing the policy asks only for the confirmation. Audited as
//       secrets.reseal / secrets.policy / secrets.export; confirmation code sealing_policy_reseal.
namespace vh::ops::master_secrets {

using Slot = crypto::secrets::versioned::Slot;

[[nodiscard]] crypto::secrets::rewrap::Status status(const Actor& actor, Slot slot);

struct RotateRequest {
    Slot slot{Slot::VaultMaster};
    std::optional<std::chrono::seconds> window{};  // the recovery window (default 7 days)
    std::optional<unsigned int> batch{};           // rows per staging transaction
    bool confirmed{false};
};
[[nodiscard]] crypto::secrets::rewrap::RotateResult rotate(const Actor& actor, const RotateRequest& request);
[[nodiscard]] crypto::secrets::rewrap::FinalizeResult finalize(const Actor& actor, Slot slot, bool confirmed);
[[nodiscard]] crypto::secrets::rewrap::RollbackResult rollback(const Actor& actor, Slot slot, bool confirmed);

struct JwtRotation {
    std::size_t refresh_tokens_revoked{};
    std::size_t sessions_ended{};
};
// No rollback: the old secret is discarded (the tokens it signed are revoked anyway).
[[nodiscard]] JwtRotation rotateJwtSecret(const Actor& actor, bool confirmed);

struct DeviceIdentityRotation {
    unsigned int from{}, to{};
    std::string spki_sha256{}, previous_spki_sha256{};
    std::size_t devices_revoked{};
    std::size_t sessions_closed{};
    std::size_t pairing_requests_dropped{};
    bool listener_updated{false};  // the running listener presents the new identity now (else: from its next start)
};
// No rollback: the old key is deleted, and every device paired with it is revoked.
[[nodiscard]] DeviceIdentityRotation rotateDeviceIdentity(const Actor& actor, bool confirmed);

// ---- the sealing policy (#351) ---------------------------------------------------------------------------------

inline constexpr std::chrono::hours kExportFreshForReseal{24};    // `reseal --pcr7` needs an export this young
inline constexpr std::chrono::hours kExportWarnAfter{24 * 30};    // health warns when a PCR-bound host has none younger

struct SealedSecret {
    std::string name{};
    std::string policy{};  // none | pcr7
    bool complete{true};
};

struct PolicyStatus {
    std::string configured{};  // secrets.tpm_pcr_policy: none | pcr7
    bool supported{false};     // this platform has PCRs (Linux TPM); macOS' Secure Enclave is unaffected
    std::string posture{};
    std::vector<SealedSecret> secrets{};
    std::size_t bound{};       // blobs carrying a PCR 7 policy
    std::optional<std::time_t> last_export_at{};
    std::optional<std::string> warning{};  // PCR-bound with no export newer than 30 days; blobs not matching the config
};
[[nodiscard]] PolicyStatus policyStatus(const Actor& actor);
// The same without an actor: nothing secret in it, so health and `vh status` read it directly.
[[nodiscard]] PolicyStatus currentPolicyStatus();

// What stands between the operator and `reseal --pcr7` (empty: nothing). Pure so the refusals test without a TPM.
struct ResealGate {
    bool supported{false};
    std::string posture{};
    std::optional<std::time_t> last_export_at{};
    std::time_t now{};
    std::vector<vault_keys::KeyStatus> vaults{};
};
[[nodiscard]] std::vector<std::string> resealRefusals(const ResealGate& gate);
// A vault whose every needed key version is not backed up: its current version exported (the CLI export carries every
// needed version, a device confirmation records the current one) or covered by recovery recipients.
[[nodiscard]] bool keysBackedUp(const vault_keys::KeyStatus& vault);

struct ResealRequest {
    // --pcr7 / --none: must equal secrets.tpm_pcr_policy. The setting is read from config.yaml at start, so changing
    // the policy is: edit config.yaml, restart, reseal. The flag keeps a mistyped command from doing the other thing.
    std::optional<platform::sealer::Policy> expect{};
    bool confirmed{false};
};
[[nodiscard]] crypto::secrets::reseal::Report reseal(const Actor& actor, const ResealRequest& request);

// `vh secret export all` was taken now: kept (not the secrets) for the reseal gate and the health warning.
void recordSecretsExport(const Actor& actor, const std::vector<std::string>& secrets);

// The health warning for a host with `bound` PCR-bound blobs (nullopt: none).
[[nodiscard]] std::optional<std::string> pcrExportWarning(std::size_t bound, const std::optional<std::time_t>& lastExport,
                                                          std::time_t now);

[[nodiscard]] nlohmann::json toJson(const PolicyStatus& status);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::reseal::Report& report);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::Status& status);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::RotateResult& result);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::FinalizeResult& result);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::RollbackResult& result);
[[nodiscard]] nlohmann::json toJson(const JwtRotation& result);
[[nodiscard]] nlohmann::json toJson(const DeviceIdentityRotation& result);

}
