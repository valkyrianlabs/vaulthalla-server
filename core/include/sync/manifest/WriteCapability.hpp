#pragma once

#include <optional>
#include <string_view>

// What a bucket can do for the writes that must never overwrite another writer's object
// (design/encryption/06-publish-without-preconditions.md §7): which PUTs an ObjectStore's callers may use
// (Store.hpp, mode()) and which publish protocol the root follows (Publisher.hpp). The server learns it by one probe
// per bucket and stores it per vault (storage/s3/Capability.hpp, storage/BucketCapability.hpp); nothing here probes.
//
//   Conditional   PUT honours If-None-Match: * and If-Match (AWS S3, Cloudflare R2): the manifest publishes as spec 03
//                 §3.4 says, every write-once object is PUT with If-None-Match: *.
//   VersionLog    conditional PUT is rejected (501 / 400 NotImplemented, Backblaze B2) or silently ignored, and the
//                 bucket keeps versions: write-once objects are PUT plainly (their names are random or
//                 content-addressed); the root is published as provider versions (spec 06 §5, version_log).
//   Insufficient  neither conditional PUT nor versions, or GET If-Match is not honoured: plain PUTs for write-once
//                 objects and the path_v0 index; no opaque_v1 manifest.
//   Unknown       never probed (or the probe could not run): today's behaviour, conditional writes. A bucket is never
//                 downgraded without a probe saying so.
namespace vh::sync::manifest {

enum class WriteCapability { Unknown, Conditional, VersionLog, Insufficient };

// "unknown", "conditional", "version_log", "insufficient".
[[nodiscard]] std::string_view to_string(WriteCapability capability);
// The stored s3.manifest_publish values: "conditional" | "version_log"; anything else is nullopt.
[[nodiscard]] std::optional<WriteCapability> publishModeFromString(std::string_view text);

// May a write carry If-None-Match / If-Match? Conditional, and Unknown (never a silent downgrade).
[[nodiscard]] bool sendsPreconditions(WriteCapability capability) noexcept;

}
