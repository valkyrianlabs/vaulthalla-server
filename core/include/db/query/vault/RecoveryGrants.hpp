#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Recovery recipients (vault_recovery_grant) and the KEV1 envelopes written for them (vault_key_envelope), migration
// 126; design/encryption/03-metadata-recovery.md §5. Public keys and envelope names only: nothing here is secret.
namespace vh::db::query::vault {

struct RecoveryGrant {
    uint32_t vault_id{};
    std::string grant_id;                  // base32, 26 symbols
    std::string recipient_id;              // hex SHA-256 of public_key
    std::vector<uint8_t> public_key;       // X25519, 32 bytes
    uint16_t suite{1};
    std::string recipient_class{"customer"};
    std::optional<std::string> label;
    std::time_t added_at{};
    std::string authorized_by;             // "user:<id>" or "device:<id16>"
    std::optional<std::time_t> revoked_at;
    std::optional<std::string> revoked_by;

    // Customer class, not revoked: the only grants envelopes are written for.
    [[nodiscard]] bool usable() const { return recipient_class == "customer" && !revoked_at; }
};

struct KeyEnvelope {
    std::string grant_id;
    uint32_t key_version{};
    std::string kid;
};

class RecoveryGrants {
public:
    // Every grant of the vault (revoked ones too), oldest first.
    [[nodiscard]] static std::vector<RecoveryGrant> list(uint32_t vaultId);
    [[nodiscard]] static std::vector<RecoveryGrant> usable(uint32_t vaultId);
    [[nodiscard]] static std::optional<RecoveryGrant> get(uint32_t vaultId, const std::string& grantId);
    // Inserts a customer grant. Returns false (nothing written) when the vault already has an active grant for the
    // same recipient.
    [[nodiscard]] static bool add(const RecoveryGrant& grant);
    // Marks the grant revoked; false when it doesn't exist or already was.
    [[nodiscard]] static bool revoke(uint32_t vaultId, const std::string& grantId, const std::string& revokedBy);

    // Envelopes of the vault, by key version then grant.
    [[nodiscard]] static std::vector<KeyEnvelope> envelopes(uint32_t vaultId);
    static void recordEnvelopes(uint32_t vaultId, uint32_t keyVersion, const std::vector<KeyEnvelope>& written);
    // Usable grants without an envelope for `keyVersion`.
    [[nodiscard]] static std::vector<RecoveryGrant> missingFor(uint32_t vaultId, uint32_t keyVersion);
    // Key versions among `versions` for which no usable grant holds an envelope.
    [[nodiscard]] static std::vector<uint32_t> uncovered(uint32_t vaultId, const std::vector<uint32_t>& versions);
    // A revoked grant holds an envelope of a version among `versions` (still needed): only a rotation (and, where it
    // could read old data, re-encryption) cuts its access off.
    [[nodiscard]] static bool revokedWithAccess(uint32_t vaultId, const std::vector<uint32_t>& versions);
};

}
