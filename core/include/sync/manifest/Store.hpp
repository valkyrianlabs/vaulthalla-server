#pragma once

#include "sync/manifest/WriteCapability.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// What the manifest needs from a bucket, and nothing else: conditional PUTs (If-None-Match: * for objects written
// once, If-Match for the root), plain PUTs (buckets without conditional writes, spec 06), GETs (whole, ranged, by
// provider version), a prefix listing, the versions of one key, DELETE and DELETE of one version. mode() is the
// bucket's write capability (WriteCapability.hpp): which of the PUTs its callers may use. Nothing here knows a
// provider: the server's implementation is storage::s3::ManifestStore (storage/s3/ManifestStore.hpp, over its metered
// controller).
//
// Manifest objects never carry x-amz-meta-* (spec 01: the provider learns nothing from metadata).
namespace vh::sync::manifest {

// 412: the condition (If-Match / If-None-Match) did not hold.
class PreconditionFailed : public std::runtime_error {
public:
    explicit PreconditionFailed(const std::string& message) : std::runtime_error(message) {}
};

// The bucket refused to evaluate a condition at all (501 / 400 NotImplemented). Nothing was written. On a bucket
// whose stored capability is Conditional (or Unknown) this means the capability changed: callers stall and ask for a
// re-probe, never fall back to a plain PUT on their own (spec 06 §7).
class ConditionsUnsupported : public std::runtime_error {
public:
    explicit ConditionsUnsupported(const std::string& message) : std::runtime_error(message) {}
};

// An unconditional PUT whose outcome is unknown: the request may or may not have been applied (a transport error after
// sending, a 5xx; Backblaze answered a PUT whose body stalled with 500 InternalError). The writer looks for its own
// version before deciding anything (spec 06 §5.2 step 2). Refusals before sending (budget, protection lock, the opaque
// request rules) are not this: nothing was sent.
class PutOutcomeUnknown : public std::runtime_error {
public:
    explicit PutOutcomeUnknown(const std::string& message) : std::runtime_error(message) {}
};

struct StoredObject {
    std::vector<uint8_t> bytes;
    std::optional<std::string> etag;
    std::optional<std::string> version_id;
};

struct ListedObject {
    std::string key;
    uint64_t size{};
    std::optional<std::time_t> last_modified;
    std::optional<std::string> etag;  // as listed (quoted); a restore compares it with the manifest's (#371)
};

struct StoredVersion {
    std::string key;         // set by versionsUnder()
    std::string version_id;
    uint64_t size{};
    std::optional<std::time_t> last_modified;
    bool delete_marker{false};
    std::string etag;        // as listed (quoted); empty for a delete marker
    bool is_latest{false};   // the key's current version (or marker)
};

// What an unconditional PUT produced: the ETag (quoted) and, on a versioned bucket, the new version's id.
struct PutResult {
    std::string etag;
    std::optional<std::string> version_id;
};

// No manifest object comes near this (a segment splits at 4 MiB of plaintext); a GET stops past it, so a hostile
// bucket can't make a reader buffer an arbitrarily large object.
inline constexpr uint64_t kMaxManifestObjectBytes = 256ull << 20;

class ObjectStore {
public:
    virtual ~ObjectStore() = default;

    // nullopt for 404 (and for a version that is a delete marker or doesn't exist). Throws past
    // kMaxManifestObjectBytes.
    [[nodiscard]] virtual std::optional<StoredObject> get(const std::string& key,
                                                         const std::optional<std::string>& versionId = std::nullopt) = 0;
    // Bytes [offset, offset + length) of the current object; nullopt for 404.
    [[nodiscard]] virtual std::optional<std::vector<uint8_t>> getRange(const std::string& key, uint64_t offset,
                                                                      uint64_t length) = 0;
    // The current ETag of `key` without its body (one HEAD): nullopt when the HEAD found nothing (or failed: callers
    // then fall back to get()). The default reads the object (stores that have no HEAD).
    [[nodiscard]] virtual std::optional<std::string> headEtag(const std::string& key) {
        const auto o = get(key);
        if (!o) return std::nullopt;
        return o->etag.value_or("");
    }
    // Returns the new object's ETag. Throws PreconditionFailed when the key exists.
    virtual std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) = 0;
    // Returns the new object's ETag. Throws PreconditionFailed when the current ETag is not `etag`.
    virtual std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) = 0;
    // A PUT without any condition (buckets whose mode() doesn't send preconditions; spec 06 §5.2). The default refuses:
    // a store that can't write plainly says so instead of pretending.
    virtual PutResult put(const std::string& key, const std::vector<uint8_t>& bytes);
    // An object written once under a name only its writer uses (a fresh random sid, a content-addressed kid, the
    // vault's identical layout hint): If-None-Match: * when mode() sends preconditions, else a plain PUT. A
    // PreconditionFailed means the name already holds an object.
    std::string putOnce(const std::string& key, const std::vector<uint8_t>& bytes);
    [[nodiscard]] virtual std::vector<ListedObject> list(const std::string& prefix) = 0;
    // The provider versions of exactly `key` in provider order, newest first: empty on an unversioned bucket. Throws
    // when the provider can't list versions (the caller treats that as "none retained").
    [[nodiscard]] virtual std::vector<StoredVersion> versions(const std::string& key) = 0;
    // The same, newest first, down to and including the version `stopAt` (spec 06 §7: a listing stops at the base it
    // needs); every version when stopAt is nullopt or not among them. The default lists everything and cuts.
    [[nodiscard]] virtual std::vector<StoredVersion> versionsSince(const std::string& key,
                                                                   const std::optional<std::string>& stopAt);
    // Every version and delete marker of every key under `prefix`, keys ascending, each key's newest first. The default
    // refuses.
    [[nodiscard]] virtual std::vector<StoredVersion> versionsUnder(const std::string& prefix);
    virtual void remove(const std::string& key) = 0;
    // DELETE ?versionId=: permanently removes exactly that version or delete marker (never adds a marker). The default
    // refuses.
    virtual void removeVersion(const std::string& key, const std::string& versionId);
    // The bucket's write capability. Unknown (never probed) behaves as Conditional: no silent downgrade.
    [[nodiscard]] virtual WriteCapability mode() const { return WriteCapability::Unknown; }
};

}
