#pragma once

#include "crypto/secrets/Versioned.hpp"

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <span>
#include <string>
#include <vector>

// The installation's vault master, by version (#352, design/sealing/master-secrets.md §6; migrations 121, 124): the
// vault_master slot of the versioned registry (crypto/secrets/Versioned.hpp), which the other data-wrapping masters
// share. It wraps every vault key version (vault_keys, vault_keys_trashed, vault_deletion_key); each row records the
// version that wraps it (master_version).
//
//   version 1   sealed slot "vault_master" ("test_vault_master" in test mode): the master every install started with
//   version N   sealed slot "vault_master.vN" (a rewrap stages it beside the current one)
//
// Unwrap a row with provider(row.master_version). Wrap new rows inside a Writer (see the registry).
namespace vh::vault::master {

inline constexpr auto kSlot = crypto::secrets::versioned::Slot::VaultMaster;

[[nodiscard]] inline std::string slotName(const unsigned int version) {
    return crypto::secrets::versioned::slotName(kSlot, version);
}
[[nodiscard]] inline unsigned int currentVersion() { return crypto::secrets::versioned::currentVersion(kSlot); }
[[nodiscard]] inline std::shared_ptr<const crypto::secrets::KeyProvider> provider(const unsigned int version) {
    return crypto::secrets::versioned::provider(kSlot, version);
}
// Unwraps a sealed vault key under master `masterVersion` (MasterSecretLost when it is gone, std::runtime_error when
// the bytes don't authenticate). The caller wipes the result (crypto::WipedKeyCopy).
[[nodiscard]] inline std::vector<uint8_t> unwrap(const std::vector<uint8_t>& encryptedKey,
                                                 const std::vector<uint8_t>& iv, const unsigned int masterVersion) {
    return crypto::secrets::versioned::unwrap(kSlot, encryptedKey, iv, masterVersion);
}

struct Wrapped {
    std::vector<uint8_t> encrypted_key{}, iv{};
    unsigned int master_version{};
};

// The registry's Writer for vault keys.
class Writer {
public:
    explicit Writer(const bool allowCreate = false) : writer_(kSlot, allowCreate) {}

    [[nodiscard]] unsigned int version() const noexcept { return writer_.version(); }
    [[nodiscard]] Wrapped wrap(const std::span<const uint8_t> key) const {
        auto w = writer_.wrap(key);
        return {.encrypted_key = std::move(w.ciphertext), .iv = std::move(w.iv), .master_version = w.master_version};
    }

private:
    crypto::secrets::versioned::Writer writer_;
};

[[nodiscard]] inline std::shared_mutex& gate() { return crypto::secrets::versioned::gate(kSlot); }
inline void forget(const unsigned int version) { crypto::secrets::versioned::forget(kSlot, version); }
// Tests: drops every cached master (of every slot).
inline void resetForTesting() { crypto::secrets::versioned::resetForTesting(); }

}
