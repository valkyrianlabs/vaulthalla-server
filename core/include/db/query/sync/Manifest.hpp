#pragma once

#include "sync/manifest/Session.hpp"

#include <pqxx/transaction>

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
    // The roots this vault keeps the segments of, and how many.
    static constexpr std::size_t kRetainedRoots = 3;

    // The state and root record types are the manifest's (sync/manifest/Session.hpp: ChainState, RootRecord); these
    // functions are what the server's StateStore (sync/vault_manifest/Service.cpp) calls for one vault.
    [[nodiscard]] static vh::sync::manifest::ChainState state(uint32_t vaultId);

    // A root this vault published (or verified as the next one): its chain position and ETag, plus its sids in the
    // root history, which keeps the newest kRetainedRoots. Clears a recorded refusal (the chain moved on), and the
    // applying marker when it names this root. In the same transaction the base copy (remote_manifest_state.base_root,
    // remote_manifest_base by sid) becomes this root's: its bytes, the named sids' bytes from the record or the ones
    // already stored, every other sid dropped; a record without one drops the copy.
    static void recordRoot(uint32_t vaultId, const vh::sync::manifest::RootRecord& record);
    // The same inside the caller's transaction (attach-remote's cutover records the root it verified with the rest).
    static void recordRoot(pqxx::work& txn, uint32_t vaultId, const vh::sync::manifest::RootRecord& record);

    // The local base copy of the recorded root (migration 145): the root's sealed bytes and those of the segments it
    // names, as recordRoot stored them; nullopt when none is stored.
    [[nodiscard]] static std::optional<vh::sync::manifest::BaseCopy> base(uint32_t vaultId);
    // This server is about to PUT the root of this hash (remote_manifest_state.publishing_root_sha256, migration 146).
    static void notePublishing(uint32_t vaultId, const std::string& rootSha256);
    // An apply of this root begins (remote_manifest_state.applying_*); recordRoot of the same root clears it.
    static void markApplying(uint32_t vaultId, uint64_t epoch, const std::string& rootSha256);

    // A root the chain rules refused. True when it is not the root already recorded as refused: the caller alerts
    // the operator once per root, not once per pass.
    [[nodiscard]] static bool recordRefused(uint32_t vaultId, const std::string& reason, uint64_t epoch,
                                            const std::string& rootSha256);

    // Every sid the retained roots name.
    [[nodiscard]] static std::set<std::string> retainedSids(uint32_t vaultId);

    static void markCollected(uint32_t vaultId);

    // version_log GC (spec 06 §5.4): when a segment became unreferenced by the canonical chain. first sets it (now) once
    // and returns it; forget drops it (referenced again, or collected).
    [[nodiscard]] static std::time_t firstUnreferenced(uint32_t vaultId, const std::string& sid);
    static void forgetUnreferenced(uint32_t vaultId, const std::string& sid);

    // The vault as a manifest says it: the tree (directories, files, symlinks; files_trashed as trash entries; o/<uid>
    // provider versions as each file's versions, and as tombstones once the file is gone), the ready snapshots and
    // their members, the key history with key checks and attestations, the vault's settings and the producer
    // (this node, software version). Directories and symlinks without a uid get one here (libsodium) in the same
    // transaction. Throws std::runtime_error for a vault without a uid or a tree without one root.
    [[nodiscard]] static vh::sync::manifest::Content collect(uint32_t vaultId);

    // Attach-remote (vault/RemoteAttach.hpp) publishes a still-local vault's manifest before its cutover: the objects
    // the bucket already holds, which the remote index doesn't name until the cutover commits, and the sync strategy
    // the vault will have then.
    struct StagedObject {
        std::string object_key;              // o/<uid>
        uint64_t plaintext_bytes{};
        std::string generation;              // files.encryption_iv form
        std::optional<std::string> etag, version_id, storage_class;
    };
    struct CollectOptions {
        std::vector<StagedObject> staged;
        std::optional<std::string> sync_strategy;
    };
    [[nodiscard]] static vh::sync::manifest::Content collect(uint32_t vaultId, const CollectOptions& options);
};

}
