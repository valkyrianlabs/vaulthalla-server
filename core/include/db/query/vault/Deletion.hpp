#pragma once

#include "vault/Fwd.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Rows behind safe vault deletion (#162, migration 106): the vault's deleted_at mark, its vault_deletion record and
// the sealed key copies in vault_deletion_key. Trusted primitives: callers authorize. Every multi-step change runs in
// one transaction, so a crash leaves either the old state or the new one.
namespace vh::db::query::vault {

class Deletion {
public:
    using DeletionPtr = std::shared_ptr<vh::vault::model::Deletion>;
    using KeyPtr = std::shared_ptr<vh::vault::model::Key>;
    using Clock = std::chrono::system_clock;

    struct Schedule {
        unsigned int vault_id{};
        std::optional<unsigned int> deleted_by{};
        bool delete_upstream{false};
        std::chrono::seconds retention_window{};       // purge_after = deleted_at + this (0: "delete now")
        std::chrono::seconds key_retention_window{};   // key_retain_until = deleted_at + this (never before purge_after)
    };

    // Marks the vault deleted, detaches its root from the mount, forgets its inodes (nothing reaches it by inode),
    // copies its sealed key versions and records the schedule. Throws std::runtime_error when the vault does not
    // exist or is already deleted.
    static DeletionPtr schedule(const Schedule& s);

    // A pending deletion only: the vault is live again (root re-attached, inodes reassigned lazily) and the record
    // and its key copies go. False when there is nothing to restore (purge already started, or unknown).
    [[nodiscard]] static bool restore(unsigned int vaultId);

    [[nodiscard]] static DeletionPtr get(unsigned int vaultId);
    // Newest deletion first.
    [[nodiscard]] static std::vector<DeletionPtr> list();
    // The newest deletion of a vault with this name (owned by ownerId when given).
    [[nodiscard]] static DeletionPtr findByName(const std::string& name, std::optional<unsigned int> ownerId);

    // Pending or purging: purge on the next pass, and change delete_upstream when given. False when purged/unknown.
    [[nodiscard]] static bool expedite(unsigned int vaultId, std::optional<bool> deleteUpstream);

    // Claims the deletions due at `now` (pending past purge_after; purging ones whose retry is due, including those
    // a stopped daemon left mid-purge) and marks them purging.
    [[nodiscard]] static std::vector<DeletionPtr> claimDue(Clock::time_point now, unsigned int limit);
    static void markUpstreamPurged(unsigned int vaultId);
    static void recordFailure(unsigned int vaultId, const std::string& error, Clock::time_point retryAt);
    // Progress, not failure: a bounded upstream purge continues on a later pass.
    static void deferPurge(unsigned int vaultId, Clock::time_point retryAt);
    // Deletes the (deleted) vault row, which cascades its files, keys, roles, shares and sync state, and marks the
    // record purged (with `note`, e.g. why upstream data was kept, in last_error). Only for a deletion in the purging
    // state; never touches a live vault.
    static void finishPurge(unsigned int vaultId, const std::optional<std::string>& note = std::nullopt);

    // Drops the key copies of purged deletions whose key_retain_until passed; the tombstone rows stay. Returns the
    // vault ids whose keys were dropped.
    static std::vector<unsigned int> expireKeys(Clock::time_point now);
    // The retained sealed key versions, newest first (empty once expired).
    [[nodiscard]] static std::vector<KeyPtr> retainedKeys(unsigned int vaultId);
    static void markKeyExported(unsigned int vaultId);

    // The vault row of a deleted vault (with its S3 binding), or null when it is live or gone.
    [[nodiscard]] static std::shared_ptr<vh::vault::model::Vault> getDeletedVault(unsigned int vaultId);
    // Other vaults (live or deleted) bound to the same bucket on the same endpoint and region.
    [[nodiscard]] static std::vector<std::string> otherVaultsOnBucket(unsigned int vaultId);
    // Another vault row uses the same backing directory name.
    [[nodiscard]] static bool backingAliasShared(unsigned int vaultId, const std::string& alias);
};

}
