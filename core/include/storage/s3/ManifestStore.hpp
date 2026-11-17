#pragma once

#include "storage/Fwd.hpp"
#include <vl/vaultfmt/manifest/Store.hpp>

#include <chrono>
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

// The deadline of one manifest root PUT, whole request (connect, body, reply). Roots are small (a few KiB; a large
// vault's, with thousands of segment references, well under a megabyte), so 60 s is ample on any link that can sync at
// all, and it bounds how long a root's body can be in flight: past it curl closes the connection, a body not sent in
// full can't be committed, and the publish treats the outcome as unknown (spec 06 §5.2 step 2). It can't bound a
// provider that received the whole body and commits later: Backblaze then orders that version by its start, below
// newer ones (spec 06 §4, measured 2026-11-16), which the publish and the session handle as this writer's own
// superseded attempt. Other manifest objects keep the stall bound only (segments can be large).
inline constexpr std::chrono::seconds kManifestRootPutDeadline{60};

class ManifestStore final : public vl::vaultfmt::manifest::ObjectStore {
public:
    explicit ManifestStore(std::shared_ptr<Controller> s3,
                           vl::vaultfmt::manifest::WriteCapability mode = vl::vaultfmt::manifest::WriteCapability::Unknown);

    [[nodiscard]] std::optional<vl::vaultfmt::manifest::StoredObject> get(const std::string& key,
                                                                  const std::optional<std::string>& versionId) override;
    [[nodiscard]] std::optional<std::vector<uint8_t>> getRange(const std::string& key, uint64_t offset,
                                                              uint64_t length) override;
    [[nodiscard]] std::optional<std::string> headEtag(const std::string& key) override;
    std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) override;
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) override;
    [[nodiscard]] std::vector<vl::vaultfmt::manifest::ListedObject> list(const std::string& prefix) override;
    [[nodiscard]] std::vector<vl::vaultfmt::manifest::StoredVersion> versions(const std::string& key) override;
    // Stops paging after the page that holds stopAt.
    [[nodiscard]] std::vector<vl::vaultfmt::manifest::StoredVersion> versionsSince(
        const std::string& key, const std::optional<std::string>& stopAt) override;
    [[nodiscard]] std::vector<vl::vaultfmt::manifest::StoredVersion> versionsUnder(const std::string& prefix) override;
    void remove(const std::string& key) override;
    vl::vaultfmt::manifest::PutResult put(const std::string& key, const std::vector<uint8_t>& bytes) override;
    void removeVersion(const std::string& key, const std::string& versionId) override;
    [[nodiscard]] vl::vaultfmt::manifest::WriteCapability mode() const override { return mode_; }

private:
    std::string put(const std::string& key, const std::vector<uint8_t>& bytes, const std::optional<std::string>& ifMatch,
                    const std::optional<std::string>& ifNoneMatch);

    std::shared_ptr<Controller> s3_;
    vl::vaultfmt::manifest::WriteCapability mode_;
};

}
