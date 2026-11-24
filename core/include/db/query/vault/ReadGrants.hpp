#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Vault read grants and their pinned OpenPGP recipients (migration 155; ops/ReadGrants.hpp authorizes). Trusted: no
// RBAC here. Nothing stored here is secret: recipients are public keys, a grant records the ids of the credentials it
// created (gateway credential id and access key id, the provider's key id) and the OpenPGP message it was returned
// as, never a secret.
namespace vh::db::query::vault {

struct ReadGrantRecipient {
    uint32_t id{};
    std::string fingerprint;                 // 40 upper-case hex digits
    std::optional<std::string> label;
    std::vector<std::string> user_ids;
    std::string algorithm;
    std::optional<std::time_t> key_created_at;
    std::optional<std::time_t> key_expires_at;
    std::string public_key;                  // armored, exactly as pinned
    std::string source{"input"};             // input | keyserver
    std::optional<std::string> source_url;
    std::optional<uint32_t> pinned_by;
    std::string pinned_by_name;
    std::time_t pinned_at{};
    std::optional<std::time_t> removed_at;
    std::optional<std::string> removed_by;
};

struct ReadGrant {
    uint32_t row_id{};
    std::string grant_id;                    // base32, 26 symbols
    std::optional<uint32_t> vault_id;        // unset once the vault is gone
    std::string vault_name;
    std::string state{"issuing"};            // issuing | active | revocation_incomplete | revoked
    bool gateway_only{false};
    std::optional<uint32_t> gateway_credential_id;
    std::optional<std::string> gateway_access_key;
    std::optional<std::string> gateway_bucket;
    std::optional<uint32_t> api_key_id;
    std::optional<std::string> upstream_provider;
    std::optional<std::string> upstream_endpoint;
    std::optional<std::string> upstream_region;
    std::optional<std::string> upstream_bucket;
    std::optional<std::string> upstream_key_id;
    std::optional<std::string> upstream_key_name;
    std::optional<uint32_t> issued_by;
    std::string issued_by_name;
    std::time_t issued_at{};
    std::optional<std::time_t> revoked_at;
    std::optional<std::string> revoked_by;
    std::optional<std::string> revocation_error;
    std::optional<std::string> ciphertext;
    std::vector<std::string> recipients;     // fingerprints, as the grant was encrypted to them
};

class ReadGrants {
public:
    // ---- recipients
    // Inserts a pin; nullopt (nothing written) when the fingerprint is already pinned.
    [[nodiscard]] static std::optional<uint32_t> pinRecipient(const ReadGrantRecipient& recipient);
    [[nodiscard]] static std::vector<ReadGrantRecipient> listRecipients(bool includeRemoved);
    [[nodiscard]] static std::optional<ReadGrantRecipient> liveRecipient(const std::string& fingerprint);
    // Marks the live pin removed; false when there is none.
    [[nodiscard]] static bool removeRecipient(const std::string& fingerprint, const std::string& removedBy);

    // ---- grants
    // Reserves a grant row (state issuing) for the vault, in one transaction holding the vault's advisory lock: nullopt
    // (nothing written) when the vault already holds `maxLive` grants that are not revoked. The recipients are
    // recorded with it.
    [[nodiscard]] static std::optional<uint32_t> reserve(const ReadGrant& grant, const std::vector<uint32_t>& recipientIds,
                                                         uint32_t maxLive);
    [[nodiscard]] static uint32_t liveCount(uint32_t vaultId);
    [[nodiscard]] static uint32_t liveCountForApiKey(uint32_t apiKeyId);
    static void recordGateway(uint32_t rowId, uint32_t credentialId, const std::string& accessKey,
                              const std::string& bucket);
    static void recordUpstream(uint32_t rowId, uint32_t apiKeyId, const std::string& provider,
                               const std::string& endpoint, const std::string& region, const std::string& bucket,
                               const std::string& keyId, const std::string& keyName);
    // issuing → active, with the message it was returned as.
    static void activate(uint32_t rowId, const std::string& ciphertext);
    // Removes a reservation that never became a grant (everything it created was rolled back).
    static void discard(uint32_t rowId);
    // The gateway credential / upstream key is gone: forget it on the row.
    static void clearGateway(uint32_t rowId);
    static void clearUpstream(uint32_t rowId);
    static void markRevoked(uint32_t rowId, const std::string& revokedBy);
    static void markRevocationIncomplete(uint32_t rowId, const std::string& error);

    [[nodiscard]] static std::optional<ReadGrant> get(const std::string& grantId);
    // Newest first; every vault when none is given.
    [[nodiscard]] static std::vector<ReadGrant> list(std::optional<uint32_t> vaultId, bool includeRevoked);
};

}
