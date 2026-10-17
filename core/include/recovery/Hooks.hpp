#pragma once

#include "fs/Fwd.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

// Where recovery observes the storage engines. One seam per event, fired by the engine after the fact; the
// implementations (usage ledger, provider version index, …) live in their own recovery modules.
namespace vh::recovery::hooks {

// One successful upstream PUT or DELETE a CloudEngine sent for a vault (CloudEngine::OwnWrite::done()).
struct UpstreamWrite {
    uint32_t vault_id{};
    std::string key;                              // object key (no leading slash)
    bool is_delete{false};
    std::optional<uint64_t> object_size;          // bytes stored upstream (ciphertext incl. tag when encrypted)
    std::optional<std::string> etag;              // from the PUT response (s3::Controller::lastPutOutcome)
    std::optional<std::string> version_id;        // x-amz-version-id, when the bucket versions
    std::shared_ptr<fs::model::File> file;        // the local generation that was sent (PUTs; may be null)
};

// Never throws; failures are logged by the observers.
void afterUpstreamWrite(const UpstreamWrite& write) noexcept;

}
