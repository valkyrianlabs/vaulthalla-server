#pragma once

#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The account recovery key generations this server has seen (cloud_account_key, migration 141) and the policy each
// covered vault applied (cloud_account_policy_vault). Trusted primitives: the MAC (cloud/AccountPin.hpp) is computed
// and checked by the caller; nothing here is secret.
namespace vh::db::query::cloud {

struct AccountKeyRow {
    std::string account_public_id;
    uint32_t generation{};
    std::string fingerprint;  // computed here from the statement, never taken from the cloud
    std::array<uint8_t, 32> x25519_public{};
    std::array<uint8_t, 32> ed25519_public{};
    std::string statement;
    std::array<uint8_t, 64> signature{};
    std::optional<std::array<uint8_t, 64>> previous_signature;
    std::string link;   // initial | rotation | replacement
    std::string state;  // pending | pinned | superseded | refused
    std::optional<std::string> confirmed_by;  // user:<id> via cli|device, or chain:<previous generation>
    std::optional<std::time_t> confirmed_at;
    // The policy floor (on the pinned row): the highest accepted recovery policy, or sequence 0.
    uint32_t policy_sequence{};
    std::optional<std::array<uint8_t, 32>> policy_sha256;
    std::optional<std::string> policy;
    std::optional<std::array<uint8_t, 64>> policy_signature;
    std::time_t stored_at{};
    std::array<uint8_t, 32> mac{};
};

struct AccountKeys {
    // The account's rows by generation, or every row (all accounts) when accountPublicId is empty.
    [[nodiscard]] static std::vector<AccountKeyRow> list(const std::string& accountPublicId);
    // Writes the rows in one transaction: each one replaces the row of its (account, generation). `drop` lists
    // generations of the account to delete in the same transaction (a pending key a newer one replaced).
    static void put(const std::vector<AccountKeyRow>& rows, const std::vector<uint32_t>& drop = {});
    // Deletes every row (vh cloud key forget).
    static void clear();
};

struct PolicyVaultRow {
    uint32_t vault_id{};
    std::string account_public_id;
    uint32_t sequence{};
    std::time_t applied_at{};
};

struct PolicyVaults {
    [[nodiscard]] static std::vector<PolicyVaultRow> list();
    static void applied(uint32_t vaultId, const std::string& accountPublicId, uint32_t sequence);
};

}
