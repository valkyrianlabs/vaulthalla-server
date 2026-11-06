#pragma once

#include "crypto/id/ObjectUid.hpp"
#include "storage/Fwd.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The bucket layout migration path_v0 -> opaque_v1 (#373; design/encryption/01-provider-blind-storage.md §6 as
// simplified by the issue's consolidated scope of 2026-11-06): an encrypting S3/R2 vault's path-keyed legacy objects
// become VHF1 objects o/<file uid>, and every byte stays recoverable.
//
// Operator-started per vault (ops::vault_layout, `vh vault migrate-layout`), never on upgrade. Runs on the
// LayoutMigrationService thread and holds the vault's sync pass lease from the inventory to the cutover (the vault's
// sync waits; FUSE and every other local read and write keep working, and the changes upload after the cutover).
//
//   copying     inventory: a complete ListObjectVersions (R2: ListObjectsV2) of the bucket; every legacy version,
//               delete marker and the old index manifest becomes an item. One HEAD per legacy content version (its
//               generation), then the cost estimate (LayoutMigrationCost) and the price preflight ("layout_migration";
//               unpriced only with accept_unpriced). Then per object, oldest first: each retained legacy version (GET
//               ?versionId= with If-Match) and each pending backlog generation is authenticated in full and re-sealed
//               as VHF1 under the same key version, bound to the vault and the file's uid, verified (a full chunk walk
//               with matching plaintext digests), and PUT to o/<uid>; a delete marker between versions becomes a
//               DELETE of o/<uid>; the file's current content goes last: its local copy (a legacy one converted first
//               by the #372 protocol), or, without one, the legacy object it is indexed from. Never a write to a
//               legacy key. Catch-up: files changed meanwhile are copied again.
//   verifying   every PUT is proven held: its ETag equals the MD5 (or multipart MD5) of the exact bytes sent, else the
//               object is read back and authenticated end to end; a random sample (1 %, at least 100) is always read
//               back. A second complete listing must match the inventory.
//   cut_over    one transaction: storage_layout opaque_v1, index-only rows moved to their re-sealed generation, no
//               legacy (gcm0) live row left, the remote index and sync baselines rewritten to o/<uid>, the backlog
//               and the sent local versions pointed at o/<uid>. Then the manifest v2 is published and loaded back from
//               the bucket with only the key material (manifest_verified_at). The legacy objects stay untouched in
//               the bucket until cleanup_after (cutover + wait_days, default 7).
//   cleanup     only an operator, after cleanup_after, with the manifest verified, on a bucket without a protection
//               lock, after a dry run (`--cleanup`) and the typed vault name: each inventoried legacy version or
//               marker whose content is in o/ is deleted by its explicit version id (an unversioned bucket: its key,
//               after a HEAD shows the inventoried ETag). Object Lock retention and legal holds are read first and
//               respected (blocked with the date), never bypassed; a refused or failed delete is retried, never
//               reported done.
//   cleanup_blocked  legacy versions remain: each is named with its reason (and date). Retried daily.
//   complete    a complete listing shows no legacy key, version or delete marker. Never said before that.
//   failed      something failed before the cutover: the vault is still path_v0, nothing legacy was touched or deleted.
//               `vh vault migrate-layout` again resumes (verified items are kept).
//
// Kept from the inventory and never deleted: versions that can't be re-sealed now (`archived`: an archive storage
// class; `key_unavailable`: a key version this host doesn't hold; `unattributed`: not Vaulthalla's sealed content, e.g.
// another application's object or a plaintext one). They block `complete` and are listed in cleanup_blocked.
namespace vh::vault::layout {

enum class State { Copying, Verifying, Failed, CutOver, Cleanup, CleanupBlocked, Complete };
[[nodiscard]] std::string_view to_string(State state);
[[nodiscard]] State stateFromString(std::string_view text);   // std::invalid_argument
[[nodiscard]] bool beforeCutover(State state);                // copying | verifying | failed

enum class ItemKind { Version, Marker, Index, Current, Backlog };
[[nodiscard]] std::string_view to_string(ItemKind kind);
[[nodiscard]] ItemKind itemKindFromString(std::string_view text);

enum class ItemState { Pending, Verified, Superseded, Skipped, Failed };
[[nodiscard]] std::string_view to_string(ItemState state);
[[nodiscard]] ItemState itemStateFromString(std::string_view text);

// Skip and failure reasons an operator sees (items' `reason`).
inline constexpr const char* kArchived = "archived";              // GLACIER / DEEP_ARCHIVE: restore it first
inline constexpr const char* kKeyUnavailable = "key_unavailable"; // sealed under a key version this host doesn't hold
inline constexpr const char* kUnattributed = "unattributed";      // not Vaulthalla's sealed content
inline constexpr const char* kDiverged = "diverged";              // the bucket changed since the last sync
inline constexpr const char* kMissing = "missing";                // a file with neither a local copy nor an object
inline constexpr const char* kIntegrity = "integrity";            // didn't authenticate
inline constexpr const char* kNotInventoried = "not_inventoried"; // appeared after the inventory: never deleted

struct Item {
    int64_t id{};
    uint32_t vault_id{};
    ItemKind kind{ItemKind::Version};
    std::optional<std::string> legacy_key, legacy_version_id, legacy_etag;
    std::optional<uint64_t> legacy_size;
    std::optional<std::time_t> legacy_last_modified;
    std::optional<std::string> legacy_storage_class;
    bool legacy_latest{false};
    int seq{};
    std::optional<uint32_t> file_id;
    std::optional<int64_t> generation_id;
    std::optional<crypto::id::ObjectUid> object_uid;
    std::optional<std::string> source_generation;
    std::optional<unsigned int> key_version;
    std::optional<uint64_t> plaintext_bytes;
    std::optional<std::string> content_hash;
    std::optional<std::string> target_version_id, target_etag, target_generation;
    std::optional<uint64_t> target_size;
    ItemState state{ItemState::Pending};
    std::optional<std::string> reason, error;
    std::optional<std::string> cleanup_state;   // deleted | blocked
    std::optional<std::string> cleanup_reason;
    std::optional<std::time_t> retain_until;
    unsigned int cleanup_attempts{};

    [[nodiscard]] bool legacy() const { return legacy_key.has_value(); }
};

// LayoutMigrationCost: what the migration will send, computed after the inventory and the HEADs, before any write.
// Requests the migration's capture counts (the price preflight's input); the manifest v2 publish after the cutover is
// metadata (a root and the changed segments) and is listed separately.
struct Estimate {
    uint64_t list_requests{};       // the inventory's pages (sent) + the verification's second listing
    uint64_t head_requests{};       // one per legacy content version (sent)
    uint64_t get_requests{};        // legacy versions read (history, index-only content) + the sample read-back
    uint64_t put_requests{};        // re-sealed objects: 1 each, or initiate + parts + complete for multipart
    uint64_t delete_requests{};     // delete markers carried into o/<uid> history
    uint64_t download_bytes{};      // the legacy versions read + the sample read-back
    uint64_t upload_bytes{};        // the re-sealed objects
    uint64_t readback_worst_case_gets{};   // if the provider's ETags are not MD5s, every PUT is read back
    uint64_t readback_worst_case_bytes{};
    uint64_t metadata_puts{};       // manifest v2 after the cutover (root + segments; approximate)
    uint64_t objects{}, versions{}, delete_markers{}, backlog{}, current_files{}, sample{};
    std::optional<std::string> estimated_cost;   // price budget's estimate (decimal), when priced
    bool priced{false};
};

struct Row {
    uint32_t vault_id{};
    State state{State::Copying};
    std::optional<uint32_t> started_by;
    std::time_t started_at{};
    bool accept_unpriced{false};
    std::optional<bool> versioned;
    unsigned int wait_days{7};
    unsigned int attempts{};
    std::optional<std::time_t> verified_at, cutover_at, cleanup_after, manifest_verified_at;
    std::optional<std::time_t> cleanup_confirmed_at;
    std::optional<uint32_t> cleanup_confirmed_by;
    std::optional<std::time_t> cleanup_run_at, completed_at;
    std::optional<nlohmann::json> estimate, usage;
    std::optional<std::string> last_error;
    std::time_t updated_at{};
};

// ---- the run (copying -> verifying -> cut_over) ---------------------------------------------------------------------

struct RunDeps {
    // The vault's sync pass lease (sync::Controller in the daemon). Held from the inventory to the cutover.
    std::function<bool(uint32_t)> tryAcquirePass;
    std::function<void(uint32_t)> releasePass;
    // The price preflight of the estimate (throws a reason to refuse); default: the price budget ledger.
    std::function<void(const storage::CloudEngine&, Estimate&, bool acceptUnpriced)> pricePreflight;
    std::function<bool()> stop;                                   // optional: the service is stopping
    // Test seam, optional: called after each named step ("inventory", "heads", "item:<id>", "copied", "verified",
    // "cutover"); throwing from it leaves the state a crash there would.
    std::function<void(std::string_view step)> afterStep;
    unsigned int sampleMinimum{100};                               // read-back sample: max(1 %, this)
};

struct RunResult {
    State state{State::Copying};
    bool busy{false};                      // the pass lease was taken: retried later, nothing done
    bool stopped{false};
    std::optional<std::string> error;
};

// One run from wherever the vault's row stands (copying, verifying, or cut_over without a verified manifest).
// Never throws for a migration failure: the row goes to failed with last_error and the result says so.
RunResult run(const std::shared_ptr<storage::CloudEngine>& engine, const RunDeps& deps);

// Daemon seams: the sync controller's lease and the price budget ledger.
[[nodiscard]] RunDeps runtimeRunDeps();

// The preconditions an operator start checks (also re-checked by run): an S3 vault that encrypts upstream on
// path_v0, loaded with its keys, no key rotation or salvage, every key version its live files use held, and recovery
// material independent of this host (vault::envelopes::material). Throws std::runtime_error with the reason.
void requirePreconditions(const storage::CloudEngine& engine);

// ---- cleanup ----------------------------------------------------------------------------------------------------------

struct CleanupEntry {
    std::string key;
    std::optional<std::string> version_id;
    bool delete_marker{false};
    uint64_t size{};
    std::optional<std::time_t> last_modified;
    std::string reason;                     // why it stays (kept) or "" (deletable)
    std::optional<std::time_t> retain_until;
};

struct CleanupPlan {
    bool complete_listing{false};
    uint64_t deletable{}, deletable_bytes{}, deletable_markers{};
    std::optional<std::time_t> oldest, newest;
    std::vector<CleanupEntry> kept;          // stays in the bucket, with its reason
    uint64_t already_gone{};                 // inventoried, no longer listed
    std::vector<CleanupEntry> deletable_entries;
};

// Dry run: a complete listing matched against the inventory. Read-only (LIST requests only).
[[nodiscard]] CleanupPlan planCleanup(const storage::CloudEngine& engine, const Row& row);

struct CleanupDeps {
    std::function<bool()> stop;   // optional
};

struct CleanupResult {
    State state{State::CleanupBlocked};
    uint64_t deleted{}, blocked{}, failed{};
    std::vector<CleanupEntry> remaining;     // what still holds names: each with its reason
};

// Deletes exactly the deletable versions of a fresh plan (Object Lock read first), then lists again: complete only
// when nothing legacy is listed. The caller has checked who may and that the waiting period ended.
CleanupResult runCleanup(const storage::CloudEngine& engine, const CleanupDeps& deps);

// Whether the bucket's manifest v2 names every live file with the generation the database records (the bucket-only
// check before cleanup). Throws with the first difference.
void verifyManifestAgainstDatabase(const storage::CloudEngine& engine);

// ---- JSON -------------------------------------------------------------------------------------------------------------

[[nodiscard]] nlohmann::json toJson(const Estimate& estimate);
[[nodiscard]] Estimate estimateFromJson(const nlohmann::json& j);
[[nodiscard]] nlohmann::json toJson(const CleanupEntry& entry);

}
