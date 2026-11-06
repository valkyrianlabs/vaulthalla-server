#pragma once

#include "sync/manifest/Content.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <set>
#include <string>
#include <vector>

// The database side of manifest v2 (#368; design/encryption/03-metadata-recovery.md §3.4, §4.1; migration 125):
// the vault's chain position (remote_manifest_state, manifest_key '.vaulthalla/root'), the sids of its last three
// roots (remote_manifest_root, for garbage collection), and the collector that turns the vault's rows into manifest
// Content.
namespace vh::db::query::sync {

class Manifest {
public:
    struct State {
        std::optional<uint64_t> epoch;
        std::optional<std::string> root_sha256;
        std::optional<std::string> etag;
        std::optional<std::string> refused_reason;   // rollback | fork
        std::optional<uint64_t> refused_epoch;
        std::optional<std::string> refused_root_sha256;
        std::optional<std::time_t> refused_at;
        std::optional<std::time_t> gc_at;
    };

    // The roots this vault keeps the segments of, and how many.
    static constexpr std::size_t kRetainedRoots = 3;

    [[nodiscard]] static State state(uint32_t vaultId);

    // A root this vault published (or verified as the next one): its chain position and ETag, plus its sids in the
    // root history, which keeps the newest kRetainedRoots. Clears a recorded refusal (the chain moved on).
    static void recordRoot(uint32_t vaultId, uint64_t epoch, const std::string& rootSha256,
                           const std::optional<std::string>& etag, const std::vector<std::string>& sids);

    // A root the chain rules refused. True when it is not the root already recorded as refused: the caller alerts
    // the operator once per root, not once per pass.
    [[nodiscard]] static bool recordRefused(uint32_t vaultId, const std::string& reason, uint64_t epoch,
                                            const std::string& rootSha256);

    // Every sid the retained roots name.
    [[nodiscard]] static std::set<std::string> retainedSids(uint32_t vaultId);

    static void markCollected(uint32_t vaultId);

    // The vault as a manifest says it: the tree (directories, files, symlinks; files_trashed as trash entries; o/<uid>
    // provider versions as each file's versions, and as tombstones once the file is gone), the ready snapshots and
    // their members, the key history with key checks and attestations, the vault's settings and the producer
    // (this node, software version). Directories and symlinks without a uid get one here (libsodium) in the same
    // transaction. Throws std::runtime_error for a vault without a uid or a tree without one root.
    [[nodiscard]] static vh::sync::manifest::Content collect(uint32_t vaultId);
};

}
