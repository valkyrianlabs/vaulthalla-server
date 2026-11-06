#pragma once

#include "storage/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// What the manifest needs from a bucket, and nothing else: conditional PUTs (If-None-Match: * for objects written
// once, If-Match for the root), GETs (whole, ranged, by provider version), a prefix listing, the versions of one key
// and DELETE. S3Store maps it onto storage::s3::Controller, so every request is metered, budgeted and subject to the
// protection guard like any other upstream request; tests use the same adapter over the versioned fake bucket.
//
// Manifest objects never carry x-amz-meta-* (spec 01: the provider learns nothing from metadata).
namespace vh::sync::manifest {

// 412: the condition (If-Match / If-None-Match) did not hold.
class PreconditionFailed : public std::runtime_error {
public:
    explicit PreconditionFailed(const std::string& message) : std::runtime_error(message) {}
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
    std::string version_id;
    uint64_t size{};
    std::optional<std::time_t> last_modified;
    bool delete_marker{false};
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
    [[nodiscard]] virtual std::vector<ListedObject> list(const std::string& prefix) = 0;
    // The provider versions of exactly `key`, newest first: empty on an unversioned bucket. Throws when the provider
    // can't list versions (the caller treats that as "none retained").
    [[nodiscard]] virtual std::vector<StoredVersion> versions(const std::string& key) = 0;
    virtual void remove(const std::string& key) = 0;
};

class S3Store final : public ObjectStore {
public:
    explicit S3Store(std::shared_ptr<storage::s3::Controller> s3);

    [[nodiscard]] std::optional<StoredObject> get(const std::string& key,
                                                 const std::optional<std::string>& versionId) override;
    [[nodiscard]] std::optional<std::vector<uint8_t>> getRange(const std::string& key, uint64_t offset,
                                                              uint64_t length) override;
    [[nodiscard]] std::optional<std::string> headEtag(const std::string& key) override;
    std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) override;
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) override;
    [[nodiscard]] std::vector<ListedObject> list(const std::string& prefix) override;
    [[nodiscard]] std::vector<StoredVersion> versions(const std::string& key) override;
    void remove(const std::string& key) override;

private:
    std::string put(const std::string& key, const std::vector<uint8_t>& bytes, const std::optional<std::string>& ifMatch,
                    const std::optional<std::string>& ifNoneMatch);

    std::shared_ptr<storage::s3::Controller> s3_;
};

}
