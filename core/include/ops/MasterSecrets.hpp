#pragma once

#include "crypto/secrets/Rewrap.hpp"
#include "ops/Actor.hpp"

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>

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

[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::Status& status);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::RotateResult& result);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::FinalizeResult& result);
[[nodiscard]] nlohmann::json toJson(const crypto::secrets::rewrap::RollbackResult& result);
[[nodiscard]] nlohmann::json toJson(const JwtRotation& result);
[[nodiscard]] nlohmann::json toJson(const DeviceIdentityRotation& result);

}
