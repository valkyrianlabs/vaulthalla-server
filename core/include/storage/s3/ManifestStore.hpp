#pragma once

#include "storage/Fwd.hpp"
#include "sync/manifest/Store.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// The manifest's ObjectStore (sync/manifest/Store.hpp) on an S3 bucket: every call goes through
// storage::s3::Controller, so each request is metered, budgeted and subject to the protection guard like any other
// upstream request. Tests use the same adapter over the versioned fake bucket (tests/helpers/versioned_bucket.hpp).
// The manifest's own files include nothing of the server; this is where the two meet.
namespace vh::storage::s3 {

class ManifestStore final : public sync::manifest::ObjectStore {
public:
    explicit ManifestStore(std::shared_ptr<Controller> s3,
                           sync::manifest::WriteCapability mode = sync::manifest::WriteCapability::Unknown);

    [[nodiscard]] std::optional<sync::manifest::StoredObject> get(const std::string& key,
                                                                  const std::optional<std::string>& versionId) override;
    [[nodiscard]] std::optional<std::vector<uint8_t>> getRange(const std::string& key, uint64_t offset,
                                                              uint64_t length) override;
    [[nodiscard]] std::optional<std::string> headEtag(const std::string& key) override;
    std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) override;
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) override;
    [[nodiscard]] std::vector<sync::manifest::ListedObject> list(const std::string& prefix) override;
    [[nodiscard]] std::vector<sync::manifest::StoredVersion> versions(const std::string& key) override;
    // Stops paging after the page that holds stopAt.
    [[nodiscard]] std::vector<sync::manifest::StoredVersion> versionsSince(
        const std::string& key, const std::optional<std::string>& stopAt) override;
    [[nodiscard]] std::vector<sync::manifest::StoredVersion> versionsUnder(const std::string& prefix) override;
    void remove(const std::string& key) override;
    sync::manifest::PutResult put(const std::string& key, const std::vector<uint8_t>& bytes) override;
    void removeVersion(const std::string& key, const std::string& versionId) override;
    [[nodiscard]] sync::manifest::WriteCapability mode() const override { return mode_; }

private:
    std::string put(const std::string& key, const std::vector<uint8_t>& bytes, const std::optional<std::string>& ifMatch,
                    const std::optional<std::string>& ifNoneMatch);

    std::shared_ptr<Controller> s3_;
    sync::manifest::WriteCapability mode_;
};

}
