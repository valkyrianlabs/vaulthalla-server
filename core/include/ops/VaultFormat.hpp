#pragma once

#include "ops/Actor.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// The local format conversion's progress (#372, vault/FormatConversion.hpp): what is still legacy (gcm0) per vault,
// in items and bytes on disk, and what the background conversion last did. `vh vault format status`.
//
// Who: like `vh vault keys status`, super admins and holders of the encryption-key View permission. Nothing here is
// key material or content; counts, sizes and states only.
namespace vh::ops::vault_format {

struct Remaining {
    uint64_t items{}, bytes{};
};

struct LastPass {
    std::optional<std::time_t> started_at{}, finished_at{};
    uint64_t files{}, blobs{}, cleared{}, bytes{}, failed{}, deferred{}, conflicts{};
    std::optional<std::string> blocked{};
    std::optional<std::string> first_error{};
};

struct FormatStatus {
    unsigned int vault_id{};
    std::string vault_name{};
    // converted | pending | converting | blocked | disabled | not_loaded | awaiting_layout_migration
    std::string state{};
    std::optional<std::string> blocked_reason{};
    Remaining files{};               // live backing files still legacy on the current key version
    Remaining blobs{};               // recovery blobs (snapshots, local versions, backlog) still legacy
    Remaining total{};               // files + blobs this converter handles
    uint64_t files_other_key_versions{};  // legacy live files on another key version (a rotation or salvage owns them)
    // false for a cloud vault that encrypts upstream: its live files convert with the bucket layout migration
    // (design/encryption/01-provider-blind-storage.md §6), not here, and are not in total.
    bool converts_live_files{true};
    std::optional<LastPass> last_pass{};
};

[[nodiscard]] std::vector<FormatStatus> status(const Actor& actor, std::optional<unsigned int> vaultId = std::nullopt);
[[nodiscard]] nlohmann::json toJson(const FormatStatus& status);

}
