#include "cloud/Client.hpp"

#include "cloud/Signing.hpp"
#include "storage/s3/curl/Http.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <stdexcept>

namespace vh::cloud {

// Named, not anonymous: the unity build joins this file with others.
namespace client_detail {

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool loopback(const std::string& host) {
    const auto name = host.starts_with('[') ? host.substr(0, host.find(']') + 1) : host.substr(0, host.find(':'));
    return name == "localhost" || name == "127.0.0.1" || name == "[::1]";
}

Reply perform(const Endpoint& at, const std::string& method, const std::string& path, const std::string& body,
              std::vector<std::pair<std::string, std::string>> headers) {
    storage::s3::curl::http::Request req;
    req.method = method;
    req.url = at.base + path;
    req.body = body;
    req.timeout = std::chrono::seconds(30);
    req.max_response_bytes = 4 * 1024 * 1024;
    headers.emplace_back("Accept", "application/json");
    if (!body.empty()) headers.emplace_back("Content-Type", "application/json");
    req.headers = std::move(headers);
    const auto res = storage::s3::curl::http::perform(req);
    Reply out;
    if (!res.transport_ok) {
        out.error = "Vaulthalla Cloud is unreachable (" + res.transport_error + ")";
        return out;
    }
    out.status = res.status;
    if (!res.body.empty() && !res.truncated) out.body = nlohmann::json::parse(res.body, nullptr, false);
    if (out.body.is_discarded()) out.body = nullptr;
    if (!out.ok()) {
        if (out.body.is_object() && out.body.contains("error") && out.body["error"].is_object() &&
            out.body["error"].contains("message") && out.body["error"]["message"].is_string())
            out.error = out.body["error"]["message"].get<std::string>();
        else
            out.error = "Vaulthalla Cloud answered HTTP " + std::to_string(res.status);
    }
    return out;
}

}

Endpoint endpoint(const std::string& configured) {
    auto url = configured;
    while (url.ends_with('/')) url.pop_back();
    const auto scheme = url.find("://");
    if (scheme == std::string::npos) throw std::invalid_argument("cloud.endpoint must be a URL, e.g. https://api.vaulthalla.cloud");
    const auto proto = client_detail::lower(url.substr(0, scheme));
    auto authority = url.substr(scheme + 3);
    if (authority.empty() || authority.find_first_of("/?#@ ") != std::string::npos)
        throw std::invalid_argument("cloud.endpoint is scheme://host[:port], with no path");
    authority = client_detail::lower(authority);
    if (proto == "https") {
        if (authority.ends_with(":443")) authority.resize(authority.size() - 4);
    } else if (proto != "http" || !client_detail::loopback(authority)) {
        throw std::invalid_argument("cloud.endpoint must use https (http only to localhost, for development)");
    }
    return {.base = proto + "://" + authority, .host = authority};
}

Reply call(const Endpoint& at, const std::string& method, const std::string& path, const std::optional<nlohmann::json>& body) {
    return client_detail::perform(at, method, path, body ? body->dump() : std::string(), {});
}

Reply signedCall(const Endpoint& at, const std::string& installation, const std::span<const uint8_t> seed,
                 const std::string& method, const std::string& path, const std::optional<nlohmann::json>& body) {
    const auto text = body ? body->dump() : std::string();
    const auto q = path.find('?');
    const SignedFields f{.method = method,
                         .path = path.substr(0, q),
                         .query = q == std::string::npos ? "" : path.substr(q + 1),
                         .host = at.host,
                         .installation = installation,
                         .timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch()).count(),
                         .nonce = newNonce(),
                         .body_sha256 = sha256Hex(text)};
    const auto h = sign(f, seed);
    return client_detail::perform(at, method, path, text,
                                  {{"Authorization", h.authorization}, {std::string(kContentHashHeader), h.content_sha256}});
}

}
