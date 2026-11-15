#pragma once

#include "storage/Fwd.hpp"
#include "vault/RemoteAttach.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Detaching a remote from a vault (design/storage/attach-remote.md, "The reverse"; the attach is vault/RemoteAttach.hpp):
// an S3 vault becomes a local vault in place. Its id, keys, RBAC, shares and files stay; every file's current generation
// is held on this host and authenticated before the switch, so the local engine that takes over reads exactly what the
// bucket held. The bucket and everything in it are left in place: a detach never writes to or deletes from it.
//
// Operator-started per vault (ops::vault_remote::detach, `vh vault remote detach`), never on upgrade. Runs on the
// RemoteAttachService thread; the vault's live engine stays its CloudEngine until the cutover, so FUSE, the web console,
// shares, the gateway and sync keep working throughout.
//
//   preparing    the preconditions (below); an item per live file with content and per recovery envelope; the
//                estimate (what has to be fetched, how much history stays in the bucket only).
//   hydrating    per file: a remote-only file is fetched through CloudEngine::hydrate (price-preflighted, metered,
//                authenticated before it becomes visible); then the local copy is authenticated end to end (every
//                chunk, against the vault, the generation the catalog records, the key version and the file's uid).
//                Each recovery envelope whose bytes the database doesn't hold is read from the bucket, checked (its
//                name is its hash; it opens to this vault, its key version and its grant's recipient) and stored in
//                vault_key_envelope.envelope, where a local vault keeps them. Repeated while files change, up to
//                vaults.remote_attach.max_passes passes.
//   verifying    under the vault's sync pass lease (no sync pass can evict, index or fetch meanwhile): every live file
//                with content has a verified item at its current generation and its backing file has that generation's
//                sealed size; every envelope row holds its bytes. Anything that moved goes back to hydrating.
//   cutover      one transaction, still under the lease: vault.type local, the s3 row gone, rsync -> fsync (interval
//                and enabled kept), the remote index, sync baselines and manifest chain position gone, a gateway binding
//                remote_cache/remote_proxy -> local, the bucket row unbound (its ownership kept), pending upstream
//                backlog skipped, provider versioning -> local snapshots, the attach row gone. Then the engine swap
//                (a local Engine) before the lease is released.
//   done         the vault is a local vault.
//   failed       something failed before the cutover: the vault is still an S3 vault and syncs as before. Starting
//                the detach again resumes (verified items are kept while their generation holds).
//   aborted      an operator aborted before the cutover: nothing changed but the local copies it fetched, which stay
//                as cached copies; envelope bytes it copied are cleared again once the bucket's copy reads back equal.
//
// In place (Mode::InPlace, managed storage only: the bucket is gone or no longer this server's to use, design/cloud/
// managed-remotes.md "Entitlement states" and "Credentials and restores"): the same states without any request to the
// bucket. A file held here is verified and kept; a file held only in the bucket is recorded `lost` (path and size, in
// the row's `lost` list) and leaves the catalog at the cutover; nothing local is deleted. Recovery envelopes whose
// bytes only the bucket held are wrapped again into the database (every usable grant, every held version) before the
// switch, so recovery coverage is never smaller here than it was.
//
// Refusals (remote::Refusal codes): not_s3, vault_unavailable, attach_running, layout_migration_running,
// key_rotation_running, key_salvage_running, legacy_content, key_version_missing, event_sync_active,
// sync_conflicts_open.
namespace vh::vault::remote::detach {

enum class State { Preparing, Hydrating, Verifying, Cutover, Done, Failed, Aborted };
[[nodiscard]] std::string_view to_string(State state);
[[nodiscard]] State stateFromString(std::string_view text);   // std::invalid_argument
[[nodiscard]] bool beforeCutover(State state);                // preparing | hydrating | verifying | failed
// Running or resumable by the service: every state before the cutover except failed, and cutover itself.
[[nodiscard]] bool running(State state);

enum class ItemKind { Content, Envelope };
[[nodiscard]] std::string_view to_string(ItemKind kind);
[[nodiscard]] ItemKind itemKindFromString(std::string_view text);

enum class ItemState { Pending, Verified, Failed, Lost };

enum class Mode { Hydrate, InPlace };
[[nodiscard]] std::string_view to_string(Mode mode);
[[nodiscard]] Mode modeFromString(std::string_view text);
[[nodiscard]] std::string_view to_string(ItemState state);
[[nodiscard]] ItemState itemStateFromString(std::string_view text);

struct Item {
    int64_t id{};
    uint32_t vault_id{};
    ItemKind kind{ItemKind::Content};
    std::optional<uint32_t> file_id;
    std::optional<std::string> kid;
    std::optional<std::string> generation;   // files.encryption_iv form
    std::optional<unsigned int> key_version;
    std::optional<uint64_t> size;            // sealed bytes on disk
    bool hydrated{false};
    ItemState state{ItemState::Pending};
    std::optional<std::string> error;
};

// What the detach does, computed in preparing and refreshed each pass.
struct Estimate {
    uint64_t files{}, bytes{};                    // live files with content, their sealed bytes
    uint64_t files_remote_only{}, bytes_remote_only{};   // of those, fetched from the bucket (one GET each)
    uint64_t envelopes{}, envelopes_to_copy{};    // envelope rows; those whose bytes are read from the bucket
    // Local versions whose body the provider holds and this host released (smart cache): after the detach they are
    // history the bucket keeps, not restorable from this host.
    uint64_t history_in_bucket_only{};
    // Trashed files without a local copy: their objects stay in the bucket; restoring them locally is not possible.
    uint64_t trash_without_local_copy{};
};
[[nodiscard]] nlohmann::json toJson(const Estimate& estimate);
[[nodiscard]] Estimate estimateFromJson(const nlohmann::json& j);

struct Row {
    uint32_t vault_id{};
    std::optional<uint32_t> api_key_id;
    std::string bucket;
    Mode mode{Mode::Hydrate};
    // In place, from the cutover: the files that were held only in the bucket ([{file_id, path, size_bytes}]) and how
    // many envelope records only the bucket held (`envelopes_left_in_bucket`).
    std::optional<nlohmann::json> lost{};
    State state{State::Preparing};
    std::optional<uint32_t> started_by;
    std::time_t started_at{};
    unsigned int attempts{}, passes{};
    std::optional<std::time_t> verified_at, cutover_at, done_at, aborted_at, abort_requested_at;
    std::optional<uint32_t> abort_requested_by;
    std::optional<nlohmann::json> estimate;
    std::optional<std::string> last_error;
    std::time_t updated_at{};
};

// Progress as the attach renders it (phase "hydrating" while files are fetched and verified).
[[nodiscard]] Progress progressOf(const Row& row, const std::vector<Item>& items);

// Preconditions (checked at the start and again before the cutover): a live S3 vault whose engine is loaded with its
// keys; no remote attach, layout migration, key rotation or salvage running; no legacy content; every key version its
// live files use held; no active event-driven sync subscription; no open sync conflict. Throws Refusal.
void requireVaultReady(const storage::Engine& engine);

struct RunDeps {
    // The vault's sync pass lease (sync::Controller in the daemon), held for the final check, the cutover transaction
    // and the engine swap.
    std::function<bool(uint32_t)> tryAcquirePass;
    std::function<void(uint32_t)> releasePass;
    std::function<bool()> stop;                                   // optional: the service is stopping
    // Test seam, optional: called after each named step ("prepared", "item:<id>", "envelope:<kid>", "pass:<n>",
    // "hydrated", "checked", "cutover", "swapped"); throwing from it leaves the state a crash there would.
    std::function<void(std::string_view step)> afterStep;
    // After the cutover committed: the vault's engine rebuilt from its row (a local Engine now) and the sync task
    // replaced. Default: storage::Manager::reloadEngine + sync::Controller::refreshEngines.
    std::function<void(uint32_t)> swapEngine;
    unsigned int maxPasses{3};                                    // vaults.remote_attach.max_passes
};

struct RunResult {
    State state{State::Preparing};
    bool busy{false};                      // the pass lease was taken (or a rotation runs): retried later
    bool stopped{false};
    std::optional<std::string> error;
};

// One run from wherever the vault's row stands. Never throws for a detach failure: before the cutover the row goes to
// failed with last_error (the vault is an S3 vault and untouched), after it the engine swap is retried.
RunResult run(uint32_t vaultId, const RunDeps& deps);

// Daemon seams: the sync controller's lease, the storage manager's engine swap, vaults.remote_attach.max_passes.
[[nodiscard]] RunDeps runtimeRunDeps();

struct AbortResult {
    State state{State::Failed};
    uint64_t envelopes_cleared{}, envelopes_kept{};
};

// Before the cutover only. Nothing in the bucket is touched; the local copies fetched stay (cached copies of an S3
// vault). Envelope bytes this detach copied into the database are cleared again only where the bucket's copy reads back
// byte for byte (kept otherwise: an envelope is never dropped without a verified copy). Then the row is aborted.
AbortResult runAbort(uint32_t vaultId);

// A detach of the vault is between its start and its end (not failed, aborted or done).
[[nodiscard]] bool inProgress(uint32_t vaultId);

}
