#pragma once

#include "fs/Fwd.hpp"

#include <cstdint>
#include <optional>
#include <string>

// What both sides of a remote vault file agreed on at its last sync (#187, table sync_file_baseline). A pass under
// the `ask` conflict policy compares each side against it to tell a change on one side (synced normally, in the
// direction of the change) from a change on both sides (a conflict someone has to decide).
//
// Written when a pass sees the two sides agree, and after every successful upload, download, index-only refresh and
// conflict resolution of the file. Each side is compared with its own recorded identity: files.content_hash is a
// hash of the sealed (ciphertext) bytes, so a download re-sealed under a fresh IV has a different hash from the
// object it came from even though the content is the same. The remote side is compared by its index row's content
// hash when it has one (rows Vaulthalla wrote itself, manifests), otherwise by ETag, otherwise by object size: rows
// that come from a LIST, an S3 Inventory or an event notification have no hash, and their size is the stored
// object's size.
namespace vh::sync::model {

struct Baseline {
    uint32_t file_id{};
    std::optional<std::string> content_hash;          // the local row's hash at the time
    uint64_t size_bytes{};
    std::optional<std::string> remote_content_hash;   // the remote index row's hash at the time
    std::optional<std::string> remote_etag;
    std::optional<uint64_t> remote_size_bytes;

    // Both sides as they are now (they agree).
    [[nodiscard]] static Baseline agreed(const fs::model::File& local, const fs::model::File& remote);
    // After this file's local content was uploaded: the remote object is now that content (no ETag known yet).
    [[nodiscard]] static Baseline afterUpload(const fs::model::File& local);
    // After the remote object was downloaded (or index-refreshed) into `local`.
    [[nodiscard]] static Baseline afterDownload(const fs::model::File& local, const fs::model::File& remote);

    // Local versioning's backlog replay (recovery/local/Backlog) PUT one of the file's earlier generations: the remote
    // object is now that generation (its hash, ETag, plaintext size), and the local side is the file's unpublished
    // history: kReplayMarker as the local hash never matches a file, so the local side reads as changed. While the
    // remote side still is what the replay put, the publication is in progress (publishing()): the next pass uploads the
    // rest under every conflict policy instead of reading Vaulthalla's own write as a remote change.
    static constexpr const char* kReplayMarker = "vh-replay";
    [[nodiscard]] static Baseline afterReplay(uint32_t fileId, const std::optional<std::string>& generationHash,
                                              uint64_t generationSize, const std::optional<std::string>& etag);
    [[nodiscard]] bool publishing() const;

    [[nodiscard]] bool sameAs(const Baseline& other) const;
};

[[nodiscard]] bool localChangedSince(const fs::model::File& local, const Baseline& base);
[[nodiscard]] bool remoteChangedSince(const fs::model::File& remote, const Baseline& base);

enum class Divergence {
    InSync,      // neither side changed since they last agreed (e.g. a hashless index row whose size is ciphertext)
    LocalOnly,   // only the local copy changed: upload it
    RemoteOnly,  // only the remote object changed: download it
    Both,        // both changed: a real conflict
    Unknown      // no baseline (never synced by this version, or first sight): treated as a conflict
};

[[nodiscard]] Divergence classify(const fs::model::File& local, const fs::model::File& remote, const Baseline* base);
[[nodiscard]] const char* toString(Divergence d);

}
