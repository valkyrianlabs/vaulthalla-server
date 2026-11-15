#pragma once

#include "db/Fwd.hpp"
#include "vault/RemoteDetach.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// The catalog side of detaching a remote from a vault (vault/RemoteDetach.hpp, design/storage/attach-remote.md "The
// reverse"): vault_remote_detach (one row per vault), vault_remote_detach_item (what the detach verified locally),
// migration 139, plus the one cutover transaction.
namespace vh::db::query::vault {

class RemoteDetach {
public:
    using Row = ::vh::vault::remote::detach::Row;
    using Item = ::vh::vault::remote::detach::Item;
    using State = ::vh::vault::remote::detach::State;
    using ItemKind = ::vh::vault::remote::detach::ItemKind;
    using ItemState = ::vh::vault::remote::detach::ItemState;

    [[nodiscard]] static std::optional<Row> get(uint32_t vaultId);
    [[nodiscard]] static std::vector<Row> list();

    struct StartRequest {
        uint32_t vault_id{};
        std::optional<uint32_t> api_key_id;
        std::string bucket;
        std::optional<uint32_t> started_by;
    };
    enum class StartOutcome { Started, Resumed, Busy };
    struct Started {
        StartOutcome outcome{StartOutcome::Busy};
        std::optional<Row> row;
    };
    // A new row (preparing); a done or aborted one started afresh (its items go); a failed one resumed (preparing,
    // attempts + 1, last_error cleared, failed items pending again, verified ones kept); Busy for a row in any other
    // state.
    [[nodiscard]] static Started start(const StartRequest& request);

    // state (and last_error: nullopt clears it). Only states before the cutover move here.
    static void setState(uint32_t vaultId, State state, const std::optional<std::string>& error = std::nullopt);
    static void setEstimate(uint32_t vaultId, const nlohmann::json& estimate);
    static void setPasses(uint32_t vaultId, unsigned int passes);
    static void markVerified(uint32_t vaultId);
    static void clearVerified(uint32_t vaultId);
    static void setError(uint32_t vaultId, const std::optional<std::string>& error);

    // Abort: the request (false when the row is not before its cutover), and its end (aborted).
    [[nodiscard]] static bool requestAbort(uint32_t vaultId, std::optional<uint32_t> userId);
    static void finishAbort(uint32_t vaultId);
    // cutover -> done.
    static void markDone(uint32_t vaultId);

    // ---- items
    [[nodiscard]] static std::vector<Item> items(uint32_t vaultId);
    [[nodiscard]] static Item insertItem(const Item& item);
    static void updateItem(const Item& item);
    static void deleteItem(int64_t itemId);

    // ---- what the estimate and the preconditions read
    // Local versions of the vault whose body was released because the provider holds it (sent, no local blob).
    [[nodiscard]] static uint64_t historyInBucketOnly(uint32_t vaultId);
    // Trashed files (not purged) of the vault, with their backing paths.
    [[nodiscard]] static std::vector<std::string> trashedBackingPaths(uint32_t vaultId);
    // A live (not removed) event-driven sync subscription of the vault.
    [[nodiscard]] static bool eventSubscriptionActive(uint32_t vaultId);
    // Unresolved sync conflicts of the vault.
    [[nodiscard]] static uint64_t openConflicts(uint32_t vaultId);
    // A layout migration of the vault that has not completed and has not failed before its cutover.
    [[nodiscard]] static bool layoutMigrationRunning(uint32_t vaultId);

    // ---- the cutover
    struct CutoverOutcome {
        bool done{false};
        std::string refused;             // why not: nothing was changed
        bool gateway_flipped{false};
        bool bucket_unbound{false};
        uint64_t backlog_skipped{};
    };
    // One transaction, the vault's row locked: still a live S3 vault whose detach is verifying and verified with no
    // abort asked; every live file with content has a verified content item at its current generation; every
    // vault_key_envelope row of the vault holds its bytes. Then vault.type = 'local', the s3 row deleted, rsync ->
    // fsync (sync row kept: interval and enabled), the remote index, sync baselines, manifest rows and remote access row of
    // the vault deleted, a gateway binding remote_cache/remote_proxy -> local, the bucket row unbound (ownership kept), pending
    // upstream backlog -> skipped ('detached'), recovery mode provider_versioning -> local_snapshots, the attach row and
    // its items deleted, and the detach row cutover.
    [[nodiscard]] static CutoverOutcome cutover(uint32_t vaultId);

    // ---- health
    struct FailedDetach {
        uint32_t vault_id{};
        std::string vault_name;
        std::string detail;
    };
    struct Summary {
        std::vector<FailedDetach> failed;    // detaches that failed before their cutover (the vault is still S3)
        std::vector<uint32_t> unfinished;    // detaches still running
    };
    [[nodiscard]] static Summary summary();
    [[nodiscard]] static std::vector<std::pair<uint32_t, std::string>> states();
};

}
