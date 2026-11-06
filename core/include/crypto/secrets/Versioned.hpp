#pragma once

#include "crypto/secrets/KeyProvider.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The data-wrapping master secrets, by version (#352, #353; design/sealing/master-secrets.md §6; migrations 121, 122).
// Each slot wraps the rows of its own tables; every row records the version that wraps it (master_version), and
// master_secret_state.version is the one every row is wrapped under outside a rewrap (crypto/secrets/Rewrap.hpp).
//
//   slot            wraps                                                      version 1 / version N > 1
//   vault_master    vault_keys, vault_keys_trashed, vault_deletion_key         "vault_master" / "vault_master.vN"
//   ak_master       api_keys (the S3 secret and the provider token)            "ak_master"    / "ak_master.vN"
//   s3gw_master     s3_gateway_credentials (the credential secret)             "s3gw_master"  / "s3gw_master.vN"
//
// (In test mode every name has the "test_" prefix.) Unwrap a row with provider(slot, row.master_version). Wrap new rows
// inside a Writer, which holds the slot's current version for as long as it lives: a switch waits for every Writer of
// its slot, so no row is ever wrapped under a master the switch just replaced. The database refuses such a row too
// (the slot's guard trigger).
namespace vh::crypto::secrets::versioned {

enum class Slot : uint8_t { VaultMaster, ApiKeyMaster, GatewayMaster };
inline constexpr std::array<Slot, 3> kSlots{Slot::VaultMaster, Slot::ApiKeyMaster, Slot::GatewayMaster};

// The slot's id in master_secret_state and the audit trail: "vault_master", "ak_master", "s3gw_master".
[[nodiscard]] std::string_view id(Slot slot) noexcept;
// What an operator reads: "vault master", "API key master", "S3 gateway master".
[[nodiscard]] std::string_view noun(Slot slot) noexcept;
// The CLI's --slot value: "vault", "api-keys", "s3-gateway".
[[nodiscard]] std::string_view cliName(Slot slot) noexcept;
// From an id or a CLI name; nullopt for anything else.
[[nodiscard]] std::optional<Slot> parse(std::string_view text) noexcept;

// The sealed slot name of `version` (>= 1).
[[nodiscard]] std::string slotName(Slot slot, unsigned int version);
// master_secret_state.version of the slot.
[[nodiscard]] unsigned int currentVersion(Slot slot);

// The master of `version`, unsealed once per process and kept (locked, zeroed on release). The current version is
// opened with KeyProvider::initGuarded: generated only while no dependent row exists, else MasterSecretLost (with a
// rollback hint while a recovery window is open). Any other version must already be sealed here (MasterSecretLost
// otherwise): it is never generated.
[[nodiscard]] std::shared_ptr<const KeyProvider> provider(Slot slot, unsigned int version);

// Decrypts bytes the slot's master `masterVersion` wrapped. Throws MasterSecretLost when that master is gone and
// std::runtime_error when the bytes don't authenticate under it. The caller wipes the result (crypto::WipedKeyCopy).
[[nodiscard]] std::vector<uint8_t> unwrap(Slot slot, const std::vector<uint8_t>& ciphertext,
                                          const std::vector<uint8_t>& iv, unsigned int masterVersion);

struct Wrapped {
    std::vector<uint8_t> ciphertext{}, iv{};
    unsigned int master_version{};
};

// Wraps secrets under the slot's current master and holds that version until destroyed: write the rows while it lives,
// declaring version(). Keep it for one wrap-and-write; never nest two of one slot on one thread.
class Writer {
public:
    // allowCreate: the current master may be generated even though rows exist (vault key import under a new master
    // after the old one was lost: the approved recovery route, #326). Everything else uses the guarded default.
    explicit Writer(Slot slot, bool allowCreate = false);
    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;

    [[nodiscard]] Slot slot() const noexcept { return slot_; }
    [[nodiscard]] unsigned int version() const noexcept { return version_; }
    [[nodiscard]] Wrapped wrap(std::span<const uint8_t> secret) const;
    // Decrypts under this Writer's master (bytes the row stores under version()).
    [[nodiscard]] std::vector<uint8_t> unwrap(const std::vector<uint8_t>& ciphertext,
                                              const std::vector<uint8_t>& iv) const;

private:
    Slot slot_;
    std::shared_lock<std::shared_mutex> lock_;
    unsigned int version_{};
    std::shared_ptr<const KeyProvider> provider_;
};

// The switch, rollback and finalize of a slot hold this exclusively while they change which master wraps its rows.
[[nodiscard]] std::shared_mutex& gate(Slot slot);

// Drops the cached master of `version` (after its slot was deleted or replaced).
void forget(Slot slot, unsigned int version);
// Tests: drops every cached master of every slot (a test that deletes sealed slots, or swaps paths::backingPath).
void resetForTesting();

}
