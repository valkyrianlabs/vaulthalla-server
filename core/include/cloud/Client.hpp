#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>

// The HTTPS client for Vaulthalla Cloud (cloud.endpoint in config.yaml): JSON in and out, bounded requests
// (storage::s3::curl::http), never redirects. Unsigned calls are the linking ceremony's; signed() calls carry this
// installation's VHC1-Ed25519 signature (cloud/Signing.hpp).
namespace vh::cloud {

struct Reply {
    long status = 0;          // 0 when the cloud couldn't be reached
    nlohmann::json body;      // null when the reply wasn't JSON
    std::string error;        // transport error, or the cloud's error.message
    [[nodiscard]] bool ok() const { return status / 100 == 2; }
};

struct Endpoint {
    std::string base;  // scheme://authority, no trailing slash
    std::string host;  // what the cloud sees as Host and what is signed: lower case, without :443
};

// cloud.endpoint, checked: https, or http only to a loopback host (development). Throws std::invalid_argument.
[[nodiscard]] Endpoint endpoint(const std::string& configured);

[[nodiscard]] Reply call(const Endpoint& at, const std::string& method, const std::string& path,
                         const std::optional<nlohmann::json>& body = std::nullopt);
[[nodiscard]] Reply signedCall(const Endpoint& at, const std::string& installation, std::span<const uint8_t> seed,
                               const std::string& method, const std::string& path,
                               const std::optional<nlohmann::json>& body = std::nullopt);

}
