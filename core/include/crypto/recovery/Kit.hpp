#pragma once

#include "crypto/id/ObjectUid.hpp"
#include "crypto/recovery/Seed.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// The recovery kit (design/encryption/03-metadata-recovery.md §5.3): what a customer keeps (Desktop: in the vault's
// 1Password item; otherwise printed or on offline media) to recover vaults from their buckets. Generated on a
// customer device, never on the server; one kit can serve many vaults.
//
//   {"type": "vh.recovery-kit", "v": 1,
//    "recovery_seed": "<27 symbols>",
//    "vaults": [{"vault_uid": "<b32>", "origin": {"node_id": "…", "vault_id": 42},
//                "attestation_public_keys": [{"key_id": 3, "public_key": "<b64>"}],
//                "checkpoint": {"epoch": 812, "root_sha256": "<hex>", "at": "…"}}]}
//
// `attestation_public_keys` pin the original node's signing keys (key_attestation_keys), the trust anchor a restore on
// another node uses (§6.2, #371). `checkpoint` bounds rollback (§4.5). Members a reader doesn't know are ignored.
namespace vh::crypto::recovery {

inline constexpr std::string_view kKitType = "vh.recovery-kit";
inline constexpr unsigned kKitVersion = 1;

// code(): "bad_kit" (not a kit, or a member of the wrong type), "unsupported_version", or a SeedError code.
class KitError : public std::runtime_error {
public:
    KitError(std::string code, const std::string& detail);
    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

struct KitAttestationKey {
    unsigned key_id{};
    std::vector<uint8_t> public_key;  // Ed25519, 32 bytes
    [[nodiscard]] bool operator==(const KitAttestationKey&) const = default;
};

struct KitCheckpoint {
    uint64_t epoch{};
    std::string root_sha256;
    std::optional<std::string> at;
    [[nodiscard]] bool operator==(const KitCheckpoint&) const = default;
};

struct KitVault {
    id::ObjectUid vault_uid{};
    std::optional<std::string> origin_node_id;
    std::optional<uint64_t> origin_vault_id;
    std::vector<KitAttestationKey> attestation_public_keys;
    std::optional<KitCheckpoint> checkpoint;
    [[nodiscard]] bool operator==(const KitVault&) const = default;
};

struct Kit {
    RecoverySeed seed;
    std::vector<KitVault> vaults;

    [[nodiscard]] const KitVault* find(const id::ObjectUid& vaultUid) const;
};

// Throws KitError. The seed text in `j` is left as it is (the caller wipes its copy).
[[nodiscard]] Kit parseKit(const nlohmann::json& j);
[[nodiscard]] nlohmann::json toJson(const Kit& kit);
[[nodiscard]] nlohmann::json toJson(const KitVault& vault);
[[nodiscard]] KitVault kitVaultFromJson(const nlohmann::json& j);  // KitError("bad_kit")

}
