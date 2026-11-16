#pragma once

#include "db/Fwd.hpp"
#include "db/query/sync/Manifest.hpp"
#include "fs/Fwd.hpp"
#include "vault/RemoteAttach.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// The catalog side of attaching a remote to a local vault (vault/RemoteAttach.hpp, design/storage/attach-remote.md):
// vault_remote_attach (one row per vault), vault_remote_attach_item (everything the attach wrote to the bucket) and
// the database-held recovery envelopes of local vaults (vault_key_envelope.envelope), migration 138, plus the one
// cutover transaction.
namespace vh::db::query::vault {

class RemoteAttach {
public:
    using Row = ::vh::vault::remote::Row;
    using Item = ::vh::vault::remote::Item;
    using State = ::vh::vault::remote::State;
    using ItemKind = ::vh::vault::remote::ItemKind;
    using ItemState = ::vh::vault::remote::ItemState;

    [[nodiscard]] static std::optional<Row> get(uint32_t vaultId);
    [[nodiscard]] static std::vector<Row> list();

    struct StartRequest {
        uint32_t vault_id{};
        std::string origin{"byos"};
        uint32_t api_key_id{};
        std::string bucket;
        std::optional<std::string> storage_tier_id;
        std::optional<uint32_t> started_by;
        bool accept_unpriced{false};
    };
    enum class StartOutcome { Started, Resumed, Busy, BucketReserved, BindingDiffers };
    struct Started {
        StartOutcome outcome{StartOutcome::Busy};
        std::optional<Row> row;
        std::optional<uint32_t> reserved_by;   // BucketReserved: the vault whose attach holds (key, bucket)
    };
    // A new row (preparing); an aborted one started afresh (its items, all deleted, go); a failed one resumed
    // (preparing, attempts + 1, last_error cleared, items kept) when it names the same key and bucket, BindingDiffers
    // otherwise; Busy for a row in any other state; BucketReserved when another vault's attach holds (key, bucket).
    [[nodiscard]] static Started start(const StartRequest& request);

    // state (and last_error: nullopt clears it). Only states before the cutover move here.
    static void setState(uint32_t vaultId, State state, const std::optional<std::string>& error = std::nullopt);
    static void setProbe(uint32_t vaultId, const std::optional<std::string>& manifestPublish,
                         const nlohmann::json& probe, bool versioned);
    static void setEstimate(uint32_t vaultId, const nlohmann::json& estimate);
    static void setUsage(uint32_t vaultId, const nlohmann::json& usage);
    static void setManifest(uint32_t vaultId, const nlohmann::json& manifest);
    static void setPasses(uint32_t vaultId, unsigned int passes);
    static void markVerified(uint32_t vaultId);
    static void clearVerified(uint32_t vaultId);
    static void setError(uint32_t vaultId, const std::optional<std::string>& error);
    static void touch(uint32_t vaultId);

    // Abort: the request (false when the row is not before its cutover), and its end (aborted; the reservation goes).
    [[nodiscard]] static bool requestAbort(uint32_t vaultId, std::optional<uint32_t> userId);
    static void finishAbort(uint32_t vaultId);
    // A rotation asked for while the attach runs (false when none runs), and taking it once it ended.
    [[nodiscard]] static bool queueRotation(uint32_t vaultId);
    [[nodiscard]] static bool takeQueuedRotation(uint32_t vaultId);
    // cutover -> done, with the first pass's result.
    static void markDone(uint32_t vaultId, const nlohmann::json& firstPass);

    // ---- items
    [[nodiscard]] static std::vector<Item> items(uint32_t vaultId);
    [[nodiscard]] static Item insertItem(const Item& item);
    static void updateItem(const Item& item);

    // ---- the vault's content
    [[nodiscard]] static std::vector<std::shared_ptr<::vh::fs::model::File>> liveFiles(uint32_t vaultId);
    struct LegacyContent {
        uint64_t gcm0_files{}, plain_files{}, gcm0_blobs{};
        [[nodiscard]] bool any() const { return gcm0_files || plain_files || gcm0_blobs; }
    };
    [[nodiscard]] static LegacyContent legacyContent(uint32_t vaultId);
    // Key versions of the vault (current and retired) without a recorded attestation.
    [[nodiscard]] static std::vector<unsigned int> unattestedKeyVersions(uint32_t vaultId);
    // Another live or deleted vault's s3 row, or another vault's unfinished attach, holds (key, bucket).
    [[nodiscard]] static std::optional<uint32_t> bucketHolder(uint32_t apiKeyId, const std::string& bucket,
                                                              uint32_t exceptVault);

    // ---- recovery envelopes a local vault keeps in the database (vault_key_envelope.envelope)
    struct StoredEnvelope {
        std::string grant_id;
        uint32_t key_version{};
        std::string kid;
        std::vector<uint8_t> bytes;    // empty: the row has none (an S3 vault's envelope lives in its bucket)
    };
    [[nodiscard]] static std::vector<StoredEnvelope> envelopes(uint32_t vaultId);
    [[nodiscard]] static std::optional<std::vector<uint8_t>> envelopeBytes(uint32_t vaultId, const std::string& kid);
    static void storeEnvelopeBytes(uint32_t vaultId, const std::string& kid, const std::vector<uint8_t>& bytes);
    static void clearEnvelopeBytes(uint32_t vaultId, const std::string& kid);

    // ---- the cutover
    struct CutoverFile {
        uint32_t file_id{};
        int64_t item_id{};
        std::string object_key;          // o/<uid>
        std::string generation;          // of the bytes the bucket holds
        unsigned int key_version{};
        uint64_t plaintext_bytes{};
        std::optional<std::string> content_hash;
        std::optional<std::string> etag, version_id, storage_class;
    };
    struct CutoverInput {
        std::string remote_strategy;          // freshPolicy(S3): the operator's vaults.s3 defaults
        std::string remote_conflict_policy;
        // The default request budgets of a new S3 vault (storage::s3::S3RequestBudget's members, same names).
        struct Budget {
            std::optional<uint64_t> max_list_requests, max_head_requests, max_get_requests, max_put_requests,
                max_copy_requests, max_delete_requests, max_downloaded_bytes;
        } budget;
        std::optional<int64_t> max_remote_index_age_seconds;
        std::vector<CutoverFile> files;       // every verified content item
        ::vl::vaultfmt::manifest::RootRecord root;   // the root the verification published
        std::optional<int64_t> upstream_bucket_id;   // a known, unbound bucket row to bind (control plane ownership kept)
    };
    struct CutoverOutcome {
        bool done{false};
        std::string refused;             // why not: nothing was changed
        uint64_t indexed{}, orphans{};
        bool gateway_flipped{false};
        // A recovery envelope the database still holds has no verified copy in the bucket (a recipient enrolled, or
        // a key version wrapped, after the envelopes were staged): the caller stages and verifies again.
        bool envelopes_unstaged{false};
    };
    // One transaction, the vault's row locked: still a live local vault whose attach is verifying and verified, the
    // (key, bucket) free; then vault.type = 's3', the s3 row (encrypting, opaque_v1, the probe), fsync -> rsync keeping
    // interval and enabled, the remote index and baselines of every verified item whose file still exists (the others
    // become orphans), the manifest's chain position, the bytes of every envelope with a verified copy in the bucket cleared (refused
    // while one has none), a
    // gateway binding local -> remote_cache, the bucket row bound, and the attach row cutover.
    [[nodiscard]] static CutoverOutcome cutover(uint32_t vaultId, const CutoverInput& input);

    // ---- health
    struct FailedAttach {
        uint32_t vault_id{};
        std::string vault_name;
        std::string detail;                  // last_error
    };
    struct Summary {
        std::vector<FailedAttach> failed;    // attaches that failed before their cutover (the vault is still local)
        std::vector<uint32_t> unfinished;    // attaches still running (any state before done, not failed or aborted)
    };
    [[nodiscard]] static Summary summary();
    // "none" | "attaching:<state>" | "attached" for storage.vault.get, by vault id (vaults without a row are absent).
    [[nodiscard]] static std::vector<std::pair<uint32_t, std::string>> states();
};

}
