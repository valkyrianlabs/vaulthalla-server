#pragma once

#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <pqxx/transaction>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace vh::fs::cache { class Registry; }

// The tree-apply module (design/peers/mirror.md "Following the core", "Shared executors"): what applying another
// server's tree to a vault on this server needs whoever the other writer is. Both appliers call it: the manifest
// applier (sync/vault_manifest/Applier.cpp: another writer of a shared bucket) and the mirror's log applier
// (mirror/apply/Applier.cpp: the vault's core server). It holds
//
//   * the uid lookup for local vaults: an entry is found by its permanent id alone (directories.uid, files.object_uid,
//     symlinks.uid, files_trashed.object_uid), with no remote_object_index (the manifest applier keeps its own lookup,
//     which also reads the bucket index its compare-and-set is about);
//   * the work after a commit that a local write does through the same calls: the FUSE cache takes the row as the apply
//     wrote it (never Registry::updateEntry, which writes the entry back and stamps it with the current time), a path
//     that no longer names its entry leaves the cache, the totals fs.dir.list reads are refreshed, and a folder gets its
//     backing directory as a local mkdir makes it.
//
// Row writers stay with each applier's queries (db::query::sync::ManifestApply, db::query::mirror::ApplyRows): their
// compare-and-sets differ (the bucket index's generation; the replication log's entry hashes), and so does their
// transaction (one per operation; one per group).
namespace vh::fs::tree_apply {

// Where a tree is applied: the vault's engine and the FUSE cache (none in some tests).
struct Target {
    uint32_t vaultId{};
    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<fs::cache::Registry> cache;

    // The process's engine and cache for `vaultId`; std::runtime_error when the vault has no engine.
    [[nodiscard]] static Target of(uint32_t vaultId);
    [[nodiscard]] std::filesystem::path fuse(const std::string& vaultPath) const;
};

// One entry of a vault found by its permanent id.
struct Located {
    enum class Kind { Directory, File, Symlink };
    Kind kind{Kind::File};
    bool trashed{false};
    uint32_t id{};                       // fs_entry id; the newest files_trashed id when trashed
    std::optional<uint32_t> parent_id{};
    std::optional<std::string> parent_uid{};   // uuid text
    std::string name{};
    std::string path{};                  // vault path (the trash row's path when trashed)
    std::string base32_alias{};
    std::optional<uint64_t> inode{};
    std::string generation{};            // files.encryption_iv as stored ('' for none)
    uint32_t key_version{};
};

// The live entry with this uid (uuid text), else its newest trash row that has not ended; nullopt when the vault holds
// neither.
[[nodiscard]] std::optional<Located> locate(pqxx::work& txn, uint32_t vaultId, const std::string& uuid);
[[nodiscard]] std::optional<Located> locate(uint32_t vaultId, const std::string& uuid);

// After a commit: the entry as the apply wrote it, into the cache (an inode assigned when the row has none), and its
// parent's totals.
void cacheFresh(const Target& target, unsigned int entryId);
// After a commit: a vault path that no longer names what it did leaves the cache; `parentId`'s totals are refreshed.
void evicted(const Target& target, const std::string& vaultPath, std::optional<unsigned int> parentId);
// A folder's backing directory, as a local mkdir makes it (files under it are linked or hydrated there).
void ensureBackingDirectory(const std::filesystem::path& backing);

}
