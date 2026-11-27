#pragma once

#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/Hash.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

// The rows of the server mirror's first copy and of following the core (migration 164; design/peers/mirror.md "As
// built: following the core"). Two sides:
//
//   * Baseline (core): the tree as of the baseline startCore took (mirror_baseline), read in pages for
//     peer.mirror.tree.
//   * ApplyRows (mirror): the statements mirror::apply runs inside one transaction per tree page or log group, under
//     Log::markMirrorApply: the vault's mirror row locked, the entry hashes it recorded (the compare-and-set), the
//     entry tables written with the core's uids, times, modes, owners and attribution, accounts named {node, id} mapped
//     to this server's rows, the digest and position moved. Entries are found by uid, never by path (tree_apply::locate).
//     Trusted primitives: the caller holds the transaction, checks the order and authorizes.
namespace vh::db::query::mirror {

struct BaselineItem {
    uint64_t ord{};
    std::string state{};   // the state document, as JSON text (served as it is)
};

struct BaselinePage {
    bool exists{false};            // the vault is this server's core and still holds its baseline
    Position position{};           // where the baseline was taken
    vh::mirror::Digest digest{};   // its digest and entry count
    uint64_t rows{};               // entries it serves
    nlohmann::json vault{};        // the vault's document then
    std::vector<BaselineItem> items{};
    bool more{false};
};

class Baseline {
public:
    // Up to `limit` baseline entries after `afterOrd`, in order (a folder before what is under it, trashed files last);
    // reading stops early once the states read add up to `maxBytes` (at least one entry is read).
    [[nodiscard]] static BaselinePage page(uint32_t vaultId, uint64_t afterOrd, std::size_t limit, std::size_t maxBytes);
};

// An entry's replicated fields as this server stores them (accounts already mapped to this server's rows).
struct EntryFields {
    std::optional<int64_t> mode{};
    bool hidden{false};
    std::optional<int64_t> owner_uid{}, owner_gid{};
    std::optional<int64_t> created_at_us{}, modified_at_us{};
    std::optional<uint32_t> created_by{}, modified_by{};
    // file (each as the core stores it, NULL included)
    std::optional<int64_t> size{};
    std::optional<std::string> content_hash{}, mime{};
    std::optional<std::string> generation{};
    std::optional<int64_t> key_version{};
    // symlink
    std::optional<std::string> target{};
};

struct NewEntry {
    uint32_t vault_id{};
    uint32_t parent_id{};
    std::string name{};
    std::string path{};
    std::string type{};   // file | directory | symlink
    std::string uid{};    // uuid text
    std::string alias{};
    std::optional<uint64_t> inode{};
    EntryFields fields{};
};

struct TrashFields {
    uint32_t vault_id{};
    std::string uid{};
    std::string path{};
    std::string backing_path{};
    std::string alias{};
    int64_t size{};
    std::optional<int64_t> trashed_at_us{};
    std::optional<uint32_t> trashed_by{};
};

class ApplyRows {
public:
    // Opens an apply in `txn`: the core's changes (Log::markMirrorApply: no log rows, no entry hashes moved by the
    // triggers), with the times it sent kept as they are (vh.keep_mtime).
    static void begin(pqxx::work& txn);
    // The vault's mirror row, FOR UPDATE (one apply of a vault at a time); nullopt without one.
    [[nodiscard]] static std::optional<MirrorVault> lock(pqxx::work& txn, uint32_t vaultId);

    // The entry hashes this server recorded for these uids (uuid text), FOR UPDATE.
    [[nodiscard]] static std::map<std::string, vh::mirror::Hash> recordedHashes(pqxx::work& txn, uint32_t vaultId,
                                                                               const std::vector<std::string>& uids);
    static void setRecordedHash(pqxx::work& txn, uint32_t vaultId, const std::string& uid,
                                const std::optional<vh::mirror::Hash>& hash);
    // The contents rows of these files, FOR UPDATE, before any entry row: the receive path's lock order (the pending
    // row, then the file's row).
    static void lockPending(pqxx::work& txn, uint32_t vaultId, const std::vector<std::string>& uids);

    // This server's row for the account {node, id}: when `node` is this server's own, the local account of that id
    // (nullopt when there is none); else the remote account (home node, id there), created the first time it is named
    // (migration 158: no credentials, attribution only). Never matched by name, never a local account for another
    // server's.
    [[nodiscard]] static std::optional<uint32_t> account(pqxx::work& txn, const std::string& ownNode,
                                                         const std::string& node, uint32_t id);

    [[nodiscard]] static bool keyHeld(pqxx::work& txn, uint32_t vaultId, uint32_t version);
    [[nodiscard]] static std::optional<uint32_t> rootOf(pqxx::work& txn, uint32_t vaultId);
    // The live entry named `name` in folder `parentId`.
    [[nodiscard]] static std::optional<uint32_t> named(pqxx::work& txn, uint32_t parentId, const std::string& name);
    [[nodiscard]] static uint64_t childCount(pqxx::work& txn, uint32_t dirId);
    // Whether a live entry holds this inode (one that stepped aside within the transaction keeps its own).
    [[nodiscard]] static bool inodeTaken(pqxx::work& txn, uint64_t inode);
    // The live entries directly in folder `dirId`.
    [[nodiscard]] static std::vector<uint32_t> children(pqxx::work& txn, uint32_t dirId);
    // `entryId` is `ancestorId` or somewhere under it.
    [[nodiscard]] static bool within(pqxx::work& txn, uint32_t entryId, uint32_t ancestorId);
    // Folders between the entry and the vault's root (0 directly under the root).
    [[nodiscard]] static uint32_t depthOf(pqxx::work& txn, uint32_t entryId);
    [[nodiscard]] static std::string pathOf(pqxx::work& txn, uint32_t entryId);

    // A live entry and its type row, its ancestors' totals moved. Returns its id.
    [[nodiscard]] static uint32_t insertEntry(pqxx::work& txn, const NewEntry& e);
    // Its parent and name (path is rewritten later: rewritePath), its subtree's totals moved between the two chains.
    static void moveEntry(pqxx::work& txn, uint32_t id, uint32_t newParentId, const std::string& newName);
    // Every replicated field but parent and name, the times as given (vh.keep_mtime), a file's size difference on
    // its ancestors' totals.
    static void updateEntry(pqxx::work& txn, uint32_t id, const std::string& type, const EntryFields& f);
    // A file, a symlink or an empty folder, off its ancestors' totals.
    static void removeEntry(pqxx::work& txn, uint32_t id);
    // The entry's path from its parent's, and every path under it.
    static void rewritePath(pqxx::work& txn, uint32_t id);

    static void insertTrash(pqxx::work& txn, const TrashFields& t);
    static void updateTrash(pqxx::work& txn, uint32_t trashId, const TrashFields& t);
    // A trash row ends (purged, or the file is live again).
    static void endTrash(pqxx::work& txn, uint32_t trashId);

    // The hash of what this server's tables hold for the entry now (vh_mirror_state_hash of its state document).
    [[nodiscard]] static std::optional<vh::mirror::Hash> liveHash(pqxx::work& txn, uint32_t entryId);
    [[nodiscard]] static std::optional<vh::mirror::Hash> trashHash(pqxx::work& txn, uint32_t vaultId,
                                                                   const std::string& uid);
    // The state document this server's tables hold for an entry (a mismatch's details).
    [[nodiscard]] static nlohmann::json liveState(pqxx::work& txn, uint32_t entryId);

    // The vault's settings from the core's vault document: name (unless another vault here holds it), description,
    // quota, owner (mapped); the document is recorded (mirror_vault.vault_state), its sync and recovery policies
    // never acted on (remote sync runs on the core only). Notes say what was not applied.
    [[nodiscard]] static std::vector<std::string> applyVault(pqxx::work& txn, uint32_t vaultId, const nlohmann::json& doc,
                                                             std::optional<uint32_t> owner);

    // The core's baseline as its first tree answer stated it (once; later answers must state the same).
    static void recordBaseline(pqxx::work& txn, uint32_t vaultId, Position at, const vh::mirror::Digest& digest,
                               uint64_t rows);
    // The first copy applied through baseline entry `cursor`, the digest as it now is; `finished`: complete, the
    // position becomes the baseline's.
    static void advanceCopy(pqxx::work& txn, uint32_t vaultId, uint64_t cursor, const vh::mirror::Digest& digest,
                            bool finished, Position baseline);
    // A group applied: the vault is at `at`, with `digest`.
    static void advance(pqxx::work& txn, uint32_t vaultId, Position at, const vh::mirror::Digest& digest);
};

}
