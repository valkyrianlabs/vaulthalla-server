#pragma once

#include "fs/Fwd.hpp"
#include "vault/LayoutMigration.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// The catalog side of the bucket layout migration (vault/LayoutMigration.hpp, #373): vault_layout_migration (one row
// per vault) and vault_layout_migration_item (the inventory), migration 133, plus the one cutover transaction.
namespace vh::db::query::vault {

class LayoutMigration {
public:
    using Row = ::vh::vault::layout::Row;
    using Item = ::vh::vault::layout::Item;
    using State = ::vh::vault::layout::State;

    [[nodiscard]] static std::optional<Row> get(uint32_t vaultId);
    [[nodiscard]] static std::vector<Row> list();

    // A new row (copying), or a failed one restarted (copying, attempts + 1, last_error cleared). nullopt when a row
    // exists in any other state: nothing changes then.
    [[nodiscard]] static std::optional<Row> start(uint32_t vaultId, std::optional<uint32_t> userId, unsigned int waitDays,
                                                  bool acceptUnpriced);
    // state (and last_error: nullopt clears it). Only states before the cutover go back and forth here.
    static void setState(uint32_t vaultId, State state, const std::optional<std::string>& error = std::nullopt);
    static void setVersioned(uint32_t vaultId, bool versioned);
    static void setEstimate(uint32_t vaultId, const nlohmann::json& estimate);
    static void setUsage(uint32_t vaultId, const nlohmann::json& usage);
    static void markVerified(uint32_t vaultId);
    static void markManifestVerified(uint32_t vaultId);
    static void setError(uint32_t vaultId, const std::optional<std::string>& error);
    // cleanup: confirmation recorded (state cleanup); a run recorded with its outcome state.
    static void confirmCleanup(uint32_t vaultId, uint32_t userId);
    static void finishCleanupRun(uint32_t vaultId, State state);

    // ---- items ----
    // Inserts a listed legacy version (kind version | marker | index) unless (key, version id) is known: then only the
    // listing fields of a pending item are refreshed. Returns the item as stored.
    static Item upsertLegacy(const Item& item);
    // The current-content item of a live file (one per file) or a backlog generation (one per generation), as stored.
    static Item upsertCurrent(const Item& item);
    static Item upsertBacklog(const Item& item);
    static void updateItem(const Item& item);
    // A restarted run re-evaluates what failed before (failed items become pending again, their reason cleared).
    static void resetFailed(uint32_t vaultId);
    [[nodiscard]] static std::vector<Item> items(uint32_t vaultId);

    // Every live file of the vault (rows as fs::model::File, with object uids), ascending id.
    [[nodiscard]] static std::vector<std::shared_ptr<::vh::fs::model::File>> liveFiles(uint32_t vaultId);
    // The sync baseline of a file (remote side), as the planner reads it.
    struct BaselineRemote {
        std::optional<std::string> remote_content_hash, remote_etag;
        std::optional<uint64_t> remote_size_bytes;
    };
    [[nodiscard]] static std::optional<BaselineRemote> baselineOf(uint32_t fileId);

    // ---- cutover ----
    struct CutoverFile {
        uint32_t file_id{};
        std::string path;                      // the vault path (the compare-and-set names the row by it)
        std::string object_key;                // o/<uid>
        // The files row moves from (from_generation, key_version) to (to_generation, key_version) when it still has
        // from_generation (index-only rows re-sealed from the bucket); equal for rows uploaded from a local copy.
        std::string from_generation, to_generation;
        unsigned int key_version{};
        uint64_t plaintext_bytes{};
        std::optional<std::string> content_hash;
        std::optional<std::string> etag, version_id;
        std::optional<std::string> storage_class;
        bool empty_object{false};               // an empty file: the row keeps "" (its object is 136 bytes)
    };
    struct VersionMove {
        std::string legacy_key, legacy_version_id;
        std::string object_key, version_id;
        std::optional<std::time_t> last_modified;   // the legacy version's own time (retention counts from it)
        std::optional<std::time_t> superseded_at;   // the next legacy version's time
    };
    struct CutoverInput {
        std::vector<CutoverFile> files;
        std::map<std::string, std::string> keyOf;   // legacy key -> o/<uid> (pending and migrated backlog rows)
        std::vector<VersionMove> versions;          // legacy version -> o/<uid> version (sent local versions, history times)
        unsigned int wait_days{7};
    };
    struct CutoverOutcome {
        bool done{false};
        std::vector<uint32_t> changed;      // files whose row moved meanwhile to a legacy generation (caught up first)
        uint64_t legacy_rows{};              // live gcm0 rows left (refused)
        uint64_t legacy_backlog{};           // pending backlog generations still gcm0 (refused)
        std::string refused;                 // why, when not done
    };
    // One transaction: refused (nothing changes) unless the vault is still path_v0 under a verifying row and no live
    // legacy row or pending legacy backlog blob is left once the index-only rows moved. Then: storage_layout
    // opaque_v1, the remote index replaced by the o/<uid> objects, sync baselines agreed on them, pending backlog keys
    // and sent local versions moved to o/<uid>, re-sealed versions' times set to the legacy ones, and the row
    // cut_over (cleanup_after = now + wait_days).
    [[nodiscard]] static CutoverOutcome cutover(uint32_t vaultId, const CutoverInput& input);

    // Cleanup bookkeeping: legacy upstream_object_version rows of deleted versions are gone.
    static void markLegacyVersionGone(uint32_t vaultId, const std::string& key, const std::optional<std::string>& versionId);

    // ---- #376 readiness: what legacy content remains on this host ----
    struct LegacySummary {
        std::vector<uint32_t> path_v0_vaults;          // encrypting S3 vaults still on path_v0
        std::vector<uint32_t> migrations_unfinished;   // cut over, legacy objects not all gone yet
        uint64_t legacy_files{}, legacy_blobs{}, legacy_upload_files{};
        [[nodiscard]] bool remaining() const {
            return !path_v0_vaults.empty() || !migrations_unfinished.empty() || legacy_files || legacy_blobs ||
                   legacy_upload_files;
        }
    };
    [[nodiscard]] static LegacySummary legacySummary();
};

}
