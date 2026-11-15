#pragma once

#include "storage/RemoteAccess.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// The catalog side of the remote access gate (storage/RemoteAccess.hpp): vault_remote_access, migration 140.
namespace vh::db::query::vault {

class RemoteAccess {
public:
    using State = ::vh::storage::remote_access::State;
    using Mode = ::vh::storage::remote_access::Mode;

    // The vault's row; nullopt without one (full).
    [[nodiscard]] static std::optional<State> get(uint32_t vaultId);
    // Writes the row (the vault must be a live S3 vault: false, nothing written, otherwise) and returns it as stored.
    [[nodiscard]] static std::optional<State> set(uint32_t vaultId, Mode mode, const std::optional<std::string>& reason,
                                                  const std::string& setBy);
    // Rows whose access is not full, of live vaults, with the vault's name.
    struct Restricted {
        State state;
        std::string vault_name;
    };
    [[nodiscard]] static std::vector<Restricted> restricted();
};

}
