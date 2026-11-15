#pragma once

#include "sync/manifest/Content.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/transaction>

#include <cstdint>
#include <ctime>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

// The rows the manifest applier writes (design/sync/manifest-applier.md, work item 4; sync/vault_manifest/Applier.hpp
// runs it): what reconcile's plan does to one vault, in the row shapes db::query::vault::Recover::apply uses. Every
// update is a compare-and-set on what the plan's `ours` held: false (or nullopt) when the row moved since collect, and
// nothing changed. A row is found by uid only (directories.uid, files.object_uid, symlinks.uid,
// files_trashed.object_uid). Journaled by the entry tables' triggers (migration 115) like every writer.
namespace vh::db::query::sync {

struct ApplyRow {
    enum class Kind { Dir, File, Symlink };
    Kind kind{Kind::File};
    bool trashed{false};
    unsigned int id{};                             // fs_entry id; files_trashed id when trashed
    std::optional<unsigned int> parent_id;
    std::optional<std::string> parent_uid;         // base32
    std::string name;
    std::string path;                              // vault path (the trash row's path when trashed)
    std::optional<std::string> files_generation;   // hex of files.encryption_iv (the local copy's generation)
    std::optional<std::string> index_generation;   // hex of the o/<uid> index row's encryption_iv (the bucket's)
    std::optional<uint64_t> inode;
    std::optional<std::string> backing_path;
};

// An entry the applier could not take in yet because its file was open (migration 146).
struct DeferredEntry {
    std::string uid;                               // base32
    std::string op;                                // replace_content | delete | trash
    std::optional<vh::sync::manifest::Entry> target;
    std::optional<std::string> ours_generation;    // hex
    uint64_t root_epoch{};
    std::string root_sha256;
};

class ManifestApply {
public:
    // The live entry with this uid, else its newest trash row; nullopt when the vault holds neither.
    [[nodiscard]] static std::optional<ApplyRow> row(uint32_t vaultId, const std::string& uid);
    [[nodiscard]] static std::optional<ApplyRow> row(pqxx::work& txn, uint32_t vaultId, const std::string& uid);

    // Creates a live entry (fs_entry and its typed row with the uid, ancestors' totals) under parentId at `path`;
    // nullopt when the name is taken or the uid is live already (a local write since collect).
    [[nodiscard]] static std::optional<unsigned int> createEntry(pqxx::work& txn, uint32_t vaultId, unsigned int ownerId,
                                                                const vh::sync::manifest::Entry& e,
                                                                unsigned int parentId, const std::string& path,
                                                                std::optional<uint64_t> inode);
    // A trash row for a file this server never had live (theirs trashed it), as a restore writes it.
    static void createTrashed(pqxx::work& txn, uint32_t vaultId, unsigned int ownerId,
                              const vh::sync::manifest::Entry& e, const std::string& path);

    // The o/<uid> index row (source 'manifest') as the entry's object says; deleteIndex drops it.
    static void upsertIndex(pqxx::work& txn, uint32_t vaultId, const vh::sync::manifest::Entry& e);
    static void deleteIndex(pqxx::work& txn, uint32_t vaultId, const std::string& uid);

    // The files row takes the entry's generation, key version, size, hash and mime (ancestors' totals follow), only
    // while its generation is still `expectedHex` (the local copy is the one the index named).
    [[nodiscard]] static bool replaceContent(pqxx::work& txn, unsigned int fileId, const vh::sync::manifest::Entry& e,
                                             const std::optional<std::string>& expectedHex);
    // A file with no local bytes (remote-only under cache) moved or renamed in the rows alone, ancestors' totals
    // shifted, while it is still at (fromParentId, fromName): Filesystem::rename moves backing bytes it doesn't have.
    // `mtime`: the entry's in the applied root (the mover's), so both writers date the entry alike; nullopt: now.
    [[nodiscard]] static bool moveRow(pqxx::work& txn, unsigned int id, unsigned int fromParentId,
                                      const std::string& fromName, unsigned int toParentId, const std::string& toName,
                                      const std::string& toPath, const std::optional<std::string>& mtime = std::nullopt);

    // The entry's modification time from the applied root (after a rename through the filesystem, which stamps now).
    static void setMtime(pqxx::work& txn, unsigned int entryId, const std::string& mtime);

    // mode, owner (fs_entry) and a symlink's target, while they are still ours'; the entry takes target's mtime.
    [[nodiscard]] static bool setAttributes(pqxx::work& txn, unsigned int entryId, const vh::sync::manifest::Entry& ours,
                                            const vh::sync::manifest::Entry& target);

    // Provider versions of o/<uid> (upstream_object_version, insert only).
    static void addHistory(pqxx::work& txn, uint32_t vaultId, const vh::sync::manifest::Entry& e);

    // A snapshot record (recovery_snapshot with its uid, file_versions restorable only from the bucket), as a restore
    // writes one; the recovery_snapshot id of one by uid.
    static void createSnapshot(pqxx::work& txn, uint32_t vaultId, unsigned int ownerId,
                               const vh::sync::manifest::SnapshotRecord& s, const vh::sync::manifest::Content& result);
    [[nodiscard]] static std::optional<int64_t> snapshotId(uint32_t vaultId, const std::string& uid);

    // Vault settings the head changed (name unless another vault holds it, quota, sync strategy cache|sync); the
    // notes say what was not applied.
    [[nodiscard]] static std::vector<std::string> setVault(pqxx::work& txn, uint32_t vaultId,
                                                           const vh::sync::manifest::VaultInfo& ours,
                                                           const vh::sync::manifest::VaultInfo& target);

    // ---- other writers' envelopes (migration 147) ----
    // Every kid this vault knows: its own envelopes' and the other writers' it has read.
    [[nodiscard]] static std::set<std::string> knownKids(uint32_t vaultId);
    static void addForeignEnvelope(uint32_t vaultId, const std::string& kid, uint32_t keyVersion,
                                   const std::string& recipientIdHex);

    // ---- status (migration 147) ----
    struct Report {
        uint64_t epoch{};
        std::string root_sha256, producer;
        bool recorded{false}, union_base{false};
        std::size_t applied{}, skipped{}, deferred{}, kept{}, conflicts_decided{}, conflicts_open{};
        std::vector<std::string> notes;
    };
    // The vault's last apply (one row per vault, replaced); it clears a recorded stop.
    static void saveReport(uint32_t vaultId, const Report& report);
    // An apply stopped at this root for `reason`: true the first time for that root and reason (alert once).
    [[nodiscard]] static bool noteStopped(uint32_t vaultId, uint64_t epoch, const std::string& rootSha256,
                                          const std::string& producer, const std::string& reason);
    // What storage.vault.get and `vh vault sync info` show: the recorded root, the apply in progress, the writers and
    // the last apply (null members when unknown).
    [[nodiscard]] static nlohmann::json status(uint32_t vaultId);

    // ---- shared-vault trash purged locally only (migration 148) ----
    static void notePurgedLocally(uint32_t vaultId, const std::string& objectKey);
    // The objects purged here before `cutoff` (Unix time), oldest first.
    [[nodiscard]] static std::vector<std::string> purgedLocallyBefore(uint32_t vaultId, std::time_t cutoff);
    static void dropPurgedLocally(uint32_t vaultId, const std::string& objectKey);

    static void defer(pqxx::work& txn, uint32_t vaultId, const DeferredEntry& d);
    [[nodiscard]] static std::vector<DeferredEntry> deferred(uint32_t vaultId);
    static void dropDeferred(pqxx::work& txn, uint32_t vaultId, const std::string& uid);

    [[nodiscard]] static std::optional<std::string> hexOfB64(const std::optional<std::string>& b64);
    [[nodiscard]] static std::optional<std::string> b64OfHex(const std::optional<std::string>& hex);
};

}
