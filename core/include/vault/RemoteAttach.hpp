#pragma once

#include "storage/Fwd.hpp"
#include "storage/s3/Capability.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Attaching a remote to a local vault (design/storage/attach-remote.md): an existing local vault becomes an encrypted,
// opaque_v1, bucket-backed vault in place. Its id, keys, RBAC, shares and files stay; its backing files are already the
// objects (VHF1), so the upload is a byte copy, never a re-seal.
//
// Operator-started per vault (ops::vault_remote, `vh vault remote attach`), never on upgrade. Runs on the
// RemoteAttachService thread through its own S3 controller for the reserved bucket; the vault's live engine stays the
// local one, so FUSE, the web console, shares and the gateway keep working throughout. Until the cutover transaction
// commits the vault is local and nothing of it changed.
//
//   preparing    the preconditions (below); a complete listing of the bucket, which must hold nothing but what an
//                earlier attempt of this attach recorded; the capability probe of spec 06 §7 (stored on the row);
//                every recovery recipient's KEV1 envelopes copied from the database to `.vaulthalla/key/<kid>` (missing
//                ones wrapped now); an item per live file with content; the estimate and the price preflight
//                ("remote_attach"; unpriced only with accept_unpriced).
//   uploading    per item: a hard link of the backing file (backing files are only ever replaced by rename), the
//                generation read from the bytes actually sent and authenticated against the vault and the file's uid,
//                one PUT to o/<uid> (multipart above the threshold), the ETag compared with the MD5 of what was sent.
//   catching_up  files whose generation changed are sent again (the earlier version is deleted by version id), new
//                files get items, a deleted file's versions are deleted; until a pass finds nothing or
//                vaults.remote_attach.max_passes passes ran. Correctness doesn't depend on it: whatever is newer
//                locally at the cutover is an ordinary pending upload.
//   verifying    a second complete listing equals the items (nothing foreign, nothing missing); a read-back sample
//                (1 %, at least 100) authenticated end to end, every object when the provider's ETags are not MD5s;
//                the manifest v2 published in the probed mode and loaded back from the bucket with only the key
//                material, compared with the database; every envelope inspected for its grant and key version.
//   cutover      one transaction under the vault's pass lease: vault.type s3, the s3 row (encrypting, opaque_v1, the
//                probe), fsync -> rsync with the operator's vaults.s3 defaults, the remote index and sync baselines at
//                the sent generation, the manifest's chain position, the gateway binding local -> remote_cache. Then the
//                engine swap, the orphan cleanup and the first sync pass.
//   done         the vault syncs as any S3 vault.
//   failed       something failed before the cutover: the vault is still local and untouched. Starting the attach
//                again resumes (verified items are kept).
//   aborted      an operator aborted before the cutover: every object the items list was deleted (by version id where
//                the bucket keeps versions) and the reservation released. Nothing the attach didn't record is deleted.
//
// Pre-attach history stays local (open question 1): local versions keep upstream_state 'none', provider history starts
// at the attach. A key rotation asked for during an attach is queued and starts once the attach ended.
namespace vh::vault::remote {

enum class State { Preparing, Uploading, CatchingUp, Verifying, Cutover, Done, Failed, Aborted };
[[nodiscard]] std::string_view to_string(State state);
[[nodiscard]] State stateFromString(std::string_view text);   // std::invalid_argument
[[nodiscard]] bool beforeCutover(State state);                // preparing | uploading | catching_up | verifying | failed
// Running or resumable by the service: every state before the cutover except failed, and cutover itself.
[[nodiscard]] bool running(State state);

enum class ItemKind { Content, Envelope, Metadata, Orphan };
[[nodiscard]] std::string_view to_string(ItemKind kind);
[[nodiscard]] ItemKind itemKindFromString(std::string_view text);

enum class ItemState { Pending, Sent, Verified, Stale, Deleted, Failed };
[[nodiscard]] std::string_view to_string(ItemState state);
[[nodiscard]] ItemState itemStateFromString(std::string_view text);

struct Item {
    int64_t id{};
    uint32_t vault_id{};
    ItemKind kind{ItemKind::Content};
    std::optional<uint32_t> file_id;
    std::string object_key;
    std::optional<std::string> generation;       // files.encryption_iv form (base64 of the header salt)
    std::optional<unsigned int> key_version;
    std::optional<uint64_t> plaintext_bytes;
    std::optional<std::string> content_hash;
    std::optional<uint64_t> size;                // bytes stored in the bucket
    std::optional<std::string> etag, version_id;
    ItemState state{ItemState::Pending};
    std::optional<std::string> error;
};

// RemoteAttachCost: what the attach will send, computed before the first content PUT.
struct Estimate {
    uint64_t list_requests{};       // the two complete listings (the pages the first one took, twice)
    uint64_t head_requests{};
    uint64_t get_requests{};        // the read-back sample and the manifest's load
    uint64_t put_requests{};        // content objects: 1 each, or initiate + parts + complete for multipart
    uint64_t delete_requests{};
    uint64_t download_bytes{};      // the read-back sample
    uint64_t upload_bytes{};        // the content objects
    uint64_t readback_worst_case_gets{};   // if the provider's ETags are not MD5s, every object is read back
    uint64_t readback_worst_case_bytes{};
    uint64_t metadata_puts{};       // envelopes, layout hint, segments and root
    uint64_t files{}, envelopes{}, sample{};
    std::optional<std::string> estimated_cost;   // the price budget's estimate (decimal), when priced
    bool priced{false};
};

struct Row {
    uint32_t vault_id{};
    std::string origin{"byos"};
    std::optional<uint32_t> api_key_id;          // nullopt: the key was deleted meanwhile
    std::string bucket;
    std::optional<std::string> storage_tier_id;
    std::optional<std::string> manifest_publish; // conditional | version_log, once probed
    std::optional<nlohmann::json> bucket_probe;
    std::optional<bool> versioned;
    State state{State::Preparing};
    std::optional<uint32_t> started_by;
    std::time_t started_at{};
    bool accept_unpriced{false};
    unsigned int attempts{}, passes{};
    std::optional<std::time_t> verified_at, cutover_at, done_at, aborted_at, abort_requested_at, rotation_queued_at;
    std::optional<uint32_t> abort_requested_by;
    std::optional<nlohmann::json> estimate, usage, manifest, first_pass;
    std::optional<std::string> last_error;
    std::time_t updated_at{};
};

// What Desktop and the console render as is (status's `progress`).
struct Progress {
    std::string phase;                      // the state
    uint64_t files_total{}, files_done{}, bytes_total{}, bytes_done{};
    std::optional<uint64_t> bytes_per_second;   // over the last minute; null while unknown
    std::optional<uint64_t> eta_seconds;        // null while unknown
    unsigned int passes{};
    std::time_t updated_at{};
};
[[nodiscard]] Progress progressOf(const Row& row, const std::vector<Item>& items);

// ---- the bucket ---------------------------------------------------------------------------------------------------------

// The controller an attach works through: the reserved bucket through the API key's credential, held to the opaque_v1
// request rules (spec 01 §4.3) from its first request and metered into the vault's usage ledger. Tests replace the
// factory (test mode only).
using ControllerFactory = std::function<std::shared_ptr<storage::s3::Controller>(uint32_t apiKeyId, const std::string& bucket)>;
void setControllerFactoryForTesting(ControllerFactory factory);
[[nodiscard]] std::shared_ptr<storage::s3::Controller> controllerFor(uint32_t vaultId, uint32_t apiKeyId,
                                                                    const std::string& bucket);

// ---- preconditions -----------------------------------------------------------------------------------------------------

// A refusal an operator sees: a stable code and a sentence. Nothing was written.
struct Refusal : std::runtime_error {
    Refusal(std::string code, const std::string& message) : std::runtime_error(message), code_(std::move(code)) {}
    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

// Preconditions 1-3 and 6 of the design, on the vault as it is now (checked at the start and again before the cutover):
// a live local vault whose engine is loaded with its keys; no key rotation or salvage running; no legacy content (no
// live file or recovery blob in gcm0, no non-empty plain file); every key version its files, blobs and snapshots use
// held; recovery material independent of this host (a recovery recipient, or a verified export of the current key
// version). Throws Refusal.
void requireVaultReady(const storage::Engine& engine);

// Precondition 4 (the reservation aside) and 7, on the bucket as it answers now: no protection lock; a complete listing
// that shows no version, delete marker or object except what this attach's items record; the capability probe (a bucket
// that can't take the manifest is refused as bucket_capability_insufficient). Read-only apart from the probe's own
// object, which it deletes. Returns the probe. Throws Refusal.
struct BucketCheck {
    storage::s3::ProbeResult probe;
    bool versioned{true};          // listings and deletes go by version id
    uint64_t list_pages{};
};
[[nodiscard]] BucketCheck requireBucketUsable(uint32_t vaultId, uint32_t apiKeyId, const std::string& bucket,
                                              const storage::s3::Controller& controller,
                                              const std::optional<storage::s3::ProbeResult>& storedProbe);

// ---- the run -----------------------------------------------------------------------------------------------------------

struct PricePreflight {
    uint32_t vault_id{};
    uint32_t api_key_id{};
    std::optional<std::string> storage_tier_id;
    bool accept_unpriced{false};
};

struct RunDeps {
    // The vault's sync pass lease (sync::Controller in the daemon), held for the cutover transaction.
    std::function<bool(uint32_t)> tryAcquirePass;
    std::function<void(uint32_t)> releasePass;
    // The price preflight of the estimate (throws a reason to refuse); default: the price budget ledger.
    std::function<void(const PricePreflight&, Estimate&)> pricePreflight;
    std::function<bool()> stop;                                   // optional: the service is stopping
    // Test seam, optional: called after each named step ("prepared", "item:<id>", "uploaded", "pass:<n>", "listed",
    // "sampled", "published", "verified", "staged", "cutover", "swapped"); throwing from it leaves the state a crash there would.
    std::function<void(std::string_view step)> afterStep;
    // After the cutover committed: the vault's engine rebuilt from its row (a CloudEngine now) and the sync task
    // replaced. Default: storage::Manager::reloadEngine + sync::Controller::refreshEngines.
    std::function<void(uint32_t)> swapEngine;
    // The first sync pass after the cutover: starts one when none ran since, and returns its result once it ended
    // (nullopt while it runs). Default: the sync controller and the vault's sync events.
    std::function<std::optional<nlohmann::json>(uint32_t vaultId, std::time_t cutoverAt)> firstPass;
    unsigned int sampleMinimum{100};                              // read-back sample: max(1 %, this)
    unsigned int maxPasses{3};                                    // vaults.remote_attach.max_passes
};

struct RunResult {
    State state{State::Preparing};
    bool busy{false};                      // the pass lease was taken at the cutover: retried later
    bool stopped{false};
    std::optional<std::string> error;
};

// One run from wherever the vault's row stands. Never throws for an attach failure: before the cutover the row goes to
// failed with last_error (the vault is local and untouched), after it the remaining steps are retried.
RunResult run(uint32_t vaultId, const RunDeps& deps);

// Daemon seams: the sync controller's lease, the price budget ledger, the storage manager's engine swap, the vault's
// sync events and vaults.remote_attach.max_passes.
[[nodiscard]] RunDeps runtimeRunDeps();

// ---- abort -------------------------------------------------------------------------------------------------------------

struct AbortResult {
    State state{State::Failed};
    uint64_t deleted{}, remaining{};
    std::vector<std::string> refused;      // "<key>[@<version>]: <reason>", the first 20
};

// Deletes what the items list (content objects, envelopes, hint, segments, root), each by its recorded version id, or
// on a bucket without versions its key once a HEAD shows the recorded ETag; then releases the reservation (aborted).
// A delete the provider refuses stays listed and is retried by the next call: never reported done. Only before the
// cutover. Never deletes anything the attach did not record.
AbortResult runAbort(uint32_t vaultId, const std::function<bool()>& stop = {});

// ---- key rotation waits ------------------------------------------------------------------------------------------------

// An attach of the vault is between its start and its end (not failed, aborted or done): a new key version must not
// seal content before its envelopes reach the bucket.
[[nodiscard]] bool attachInProgress(uint32_t vaultId);
// Records that a rotation was asked for meanwhile (true when one is in progress and it was queued): the service starts
// it once the attach is done, failed or aborted.
[[nodiscard]] bool queueRotation(uint32_t vaultId);

// ---- JSON --------------------------------------------------------------------------------------------------------------

[[nodiscard]] nlohmann::json toJson(const Estimate& estimate);
[[nodiscard]] Estimate estimateFromJson(const nlohmann::json& j);
[[nodiscard]] nlohmann::json toJson(const Progress& progress);

}
