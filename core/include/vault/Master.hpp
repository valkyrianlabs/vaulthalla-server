#pragma once

#include "crypto/secrets/KeyProvider.hpp"

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <span>
#include <string>
#include <vector>

// The installation's vault master, by version (#352, design/sealing/master-secrets.md §6; migration 120). It wraps
// every vault key version (vault_keys, vault_keys_trashed, vault_deletion_key); each row records the version that
// wraps it (master_version), and vault_master_state.version is the one every row is wrapped under outside a rewrap.
//
//   version 1   sealed slot "vault_master" ("test_vault_master" in test mode): the master every install started with
//   version N   sealed slot "vault_master.vN" (a rewrap stages it beside the current one)
//
// Unwrap a row with provider(row.master_version). Wrap new rows inside a Writer, which holds the current version for
// as long as it lives: a switch (vault/MasterRewrap.hpp) waits for every Writer, so no row is ever wrapped under a
// master the switch just replaced. The database refuses such a row too (trigger vh_vault_master_guard).
namespace vh::vault::master {

// The sealed slot name of `version` (>= 1).
[[nodiscard]] std::string slotName(unsigned int version);
// vault_master_state.version.
[[nodiscard]] unsigned int currentVersion();

// The master of `version`, unsealed once per process and kept (locked, zeroed on release). The current version is
// opened with KeyProvider::initGuarded: generated only while no vault key row exists, else MasterSecretLost. Any
// other version must already be sealed here (MasterSecretLost otherwise): it is never generated.
[[nodiscard]] std::shared_ptr<const crypto::secrets::KeyProvider> provider(unsigned int version);

// Unwraps a sealed vault key under master `masterVersion`. Throws MasterSecretLost when that master is gone and
// std::runtime_error when the bytes don't authenticate under it. The caller wipes the result (crypto::WipedKeyCopy).
[[nodiscard]] std::vector<uint8_t> unwrap(const std::vector<uint8_t>& encryptedKey, const std::vector<uint8_t>& iv,
                                          unsigned int masterVersion);

struct Wrapped {
    std::vector<uint8_t> encrypted_key{}, iv{};
    unsigned int master_version{};
};

// Wraps vault keys under the current master and holds that version until destroyed: write the rows while it lives,
// declaring master_version(). Keep it for one wrap-and-write; never nest two on one thread.
class Writer {
public:
    // allowCreate: the current master may be generated even though rows exist (key import under a new master after
    // the old one was lost: the approved recovery route, #326). Everything else uses the guarded default.
    explicit Writer(bool allowCreate = false);
    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;

    [[nodiscard]] unsigned int version() const noexcept { return version_; }
    [[nodiscard]] Wrapped wrap(std::span<const uint8_t> key) const;

private:
    std::shared_lock<std::shared_mutex> lock_;
    unsigned int version_{};
    std::shared_ptr<const crypto::secrets::KeyProvider> provider_;
};

// The switch, rollback and finalize hold this exclusively while they change which master wraps the rows.
[[nodiscard]] std::shared_mutex& gate();

// Drops the cached master of `version` (after its slot was deleted or replaced).
void forget(unsigned int version);
// Tests: drops every cached master (a test that deletes sealed slots, or swaps paths::backingPath).
void resetForTesting();

}
