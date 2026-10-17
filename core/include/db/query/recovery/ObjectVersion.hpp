#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// upstream_object_version (migration 111): metadata of provider object versions and delete markers, never bodies.
// Rows come from this daemon's own PUT/COPY responses (origin 'vaulthalla', with IV/key version/hash/sizes) or from a
// ListObjectVersions listing (origin 'observed', metadata only).
//
//   upsert         a version seen or written; never downgrades a 'vaulthalla' row to 'observed' and never drops
//                  IV/key/hash/size metadata an incoming row lacks; seeing a version again clears gone_at
//   markSuperseded a newer version became current for a key: older live ones are noncurrent (became_noncurrent_at)
//   markGoneUnder  after a complete listing of a prefix: live rows under it the listing didn't see are gone (gone_at)
namespace vh::db::query::recovery {

struct ObjectVersionRow {
    int64_t id{};
    uint32_t vault_id{};
    std::string object_key{};
    std::string version_id{};
    bool is_delete_marker{false};
    bool is_latest{false};
    std::optional<std::string> etag{};
    std::optional<uint64_t> size_bytes{};
    std::optional<std::string> storage_class{};
    std::optional<std::time_t> last_modified{};
    std::string origin{"observed"};               // vaulthalla | observed
    std::optional<bool> encrypted{};
    std::optional<std::string> encryption_iv{};
    std::optional<unsigned int> key_version{};
    std::optional<std::string> content_hash{};
    std::optional<uint64_t> plaintext_bytes{};
    std::optional<std::time_t> became_noncurrent_at{};
    std::optional<std::time_t> gone_at{};
    std::time_t first_seen_at{};
    std::time_t last_seen_at{};
};

struct NoncurrentSummary {
    uint64_t versions{};                           // live noncurrent versions (not delete markers)
    uint64_t bytes{};                              // their known sizes
    uint64_t unknown_size{};                       // noncurrent versions without a size
    uint64_t delete_markers{};                     // live delete markers (current or not)
    std::optional<std::time_t> oldest_noncurrent_at{};
    std::optional<std::time_t> oldest_last_modified{};
};

struct ByteHours {
    std::string byte_hours{"0"};                   // NUMERIC text: sum of size × hours noncurrent within the window
    uint64_t versions{};                           // versions that contributed
    uint64_t unknown_size{};                       // noncurrent within the window but without a size
};

class ObjectVersion {
public:
    using TimePoint = std::chrono::system_clock::time_point;

    // Inserts or refreshes (vault, key, version_id); last_seen_at = seenAt; returns the row id. id, first_seen_at,
    // last_seen_at and gone_at of `row` are ignored. A current version (is_latest) clears became_noncurrent_at.
    static int64_t upsert(const ObjectVersionRow& row, TimePoint seenAt = std::chrono::system_clock::now());
    // One transaction for a listing page.
    static void upsertMany(const std::vector<ObjectVersionRow>& rows, TimePoint seenAt = std::chrono::system_clock::now());

    // `currentVersionId` is now the key's current version: every other live version of the key stops being latest and
    // gets became_noncurrent_at = at (kept when already set). Returns how many rows changed.
    static uint64_t markSuperseded(uint32_t vaultId, const std::string& key, const std::string& currentVersionId,
                                   std::time_t at);

    // After a complete listing of `prefix` that started at listingStartedAt (every version seen was upserted with a
    // seenAt at or after it): live rows under the prefix last seen before it get gone_at = now. "" = the whole vault.
    static uint64_t markGoneUnder(uint32_t vaultId, const std::string& prefix, TimePoint listingStartedAt);

    [[nodiscard]] static std::optional<ObjectVersionRow> get(int64_t id);
    [[nodiscard]] static std::optional<ObjectVersionRow> find(uint32_t vaultId, const std::string& key,
                                                              const std::string& versionId);
    // History of one key, newest first (last_modified, then id). includeGone: also versions no longer listed.
    [[nodiscard]] static std::vector<ObjectVersionRow> listForKey(uint32_t vaultId, const std::string& key,
                                                                  bool includeGone, unsigned int limit);
    // Versions of every key under a prefix (byte prefix of object_key), key then newest first.
    [[nodiscard]] static std::vector<ObjectVersionRow> listUnderPrefix(uint32_t vaultId, const std::string& prefix,
                                                                       bool includeGone, unsigned int limit);
    // Per key under the prefix, the newest live version with last_modified <= at (a delete marker included: the
    // caller treats it as absent). Point-in-time reconstruction input.
    [[nodiscard]] static std::vector<ObjectVersionRow> listAsOf(uint32_t vaultId, const std::string& prefix,
                                                                std::time_t at, unsigned int limit);

    [[nodiscard]] static NoncurrentSummary noncurrentSummary(uint32_t vaultId);
    // Noncurrent byte-hours accrued in [from, to): per live-or-gone noncurrent version with a size, the overlap of
    // [became_noncurrent_at, gone_at or to) with the window. For "current month to date".
    [[nodiscard]] static ByteHours noncurrentByteHours(uint32_t vaultId, std::time_t from, std::time_t to);

    // Key versions referenced by live encrypted versions, ascending.
    [[nodiscard]] static std::vector<unsigned int> keyVersions(uint32_t vaultId);
};

}
