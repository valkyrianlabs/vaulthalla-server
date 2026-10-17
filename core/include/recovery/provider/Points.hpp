#pragma once

#include "recovery/Fwd.hpp"
#include "recovery/Model.hpp"
#include "storage/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

namespace vh::vault {
    class EncryptionManager;
}

// RecoveryPoints (pv-<upstream_object_version.id>) from the provider version index. Raw and unauthorized: every path
// returned is a vault path; ops::recovery filters by filesystem RBAC. Nothing here sends a request.
namespace vh::recovery::provider::points {

// What the bucket keeps noncurrent versions for, as far as Vaulthalla knows (ProviderVersioningState from the policy
// slice). Unknown unless the caller says otherwise: never a guessed default.
struct RetentionInfo {
    enum class Kind { Unknown, Days, Indefinite };
    Kind kind{Kind::Unknown};
    unsigned int days{};
    // Effective noncurrent days when known (incl. other applications' rules), else indefinite only when Vaulthalla
    // set indefinite retention and no lifecycle rule expires noncurrent versions; otherwise unknown.
    [[nodiscard]] static RetentionInfo from(const ProviderVersioningState& state);
};

// Storage classes whose bodies need a provider restore (archive retrieval) before they can be read or copied.
[[nodiscard]] bool isArchiveClass(const std::optional<std::string>& storageClass);

// One index row as a recovery point. `keys` decides key availability (nullptr: unknown → not available).
[[nodiscard]] RecoveryPoint fromRow(const db::query::recovery::ObjectVersionRow& row,
                                    const vault::EncryptionManager* keys, const RetentionInfo& retention = {});

// History of a file (newest first) or every version under a directory, from the index (refresh it first with
// versions::refresh for fresh data). Vaulthalla's own keys are never included. includeGone: also versions the
// provider no longer lists (restorable=false).
[[nodiscard]] std::vector<RecoveryPoint> forPath(const std::shared_ptr<storage::CloudEngine>& engine,
                                                 const std::filesystem::path& vaultPath, bool directory,
                                                 const RetentionInfo& retention = {}, unsigned int limit = 200,
                                                 bool includeGone = false);

// One pv- point by row id (nullopt: no such row, or it belongs to another vault than the engine's).
[[nodiscard]] std::optional<RecoveryPoint> byId(const std::shared_ptr<storage::CloudEngine>& engine, uint64_t id,
                                                const RetentionInfo& retention = {});

}
