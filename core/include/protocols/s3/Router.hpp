#pragma once

#include "protocols/s3/Auth.hpp"
#include "protocols/s3/Error.hpp"
#include "protocols/s3/MultipartStore.hpp"
#include "protocols/s3/ObjectStore.hpp"

#include <boost/beast/http.hpp>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace vh::protocols::s3 {

namespace beast = boost::beast;
namespace http = beast::http;

class Router {
public:
    using Request = http::request<http::string_body>;
    using Response = http::response<http::string_body>;

    // Cache-Control on every gateway answer. Each one is per-credential, and a presigned GET is a bearer URL: no CDN or
    // shared cache in front of the gateway may store or replay one.
    static constexpr const char* kCacheControl = "private, no-store";

    struct ParsedTarget {
        std::string bucket;
        std::string key;
        std::map<std::string, std::string> query;
    };

    struct ParsedCopySource {
        std::string bucket;
        std::string key;
        std::map<std::string, std::string> query;
    };

    struct BodyPayload {
        std::optional<std::filesystem::path> temp_file;
        uint64_t size = 0;
        std::map<std::string, std::string> trailer_headers;
        std::optional<std::string> sha256_hex;
        std::optional<std::string> sha256_base64;
        std::optional<std::string> md5_base64;
        std::optional<std::string> md5_hex;
        std::optional<std::string> crc32_base64;
    };

    Router();
    Response route(Request&& request) const;
    Response route(Request&& request, BodyPayload payload) const;

    static Response errorResponse(const Request& request, const S3Error& error, const std::string& requestId);
    static ParsedTarget parseRequestTarget(const Request& request);
    static ParsedCopySource parseCopySource(std::string raw);
    static std::string checksumSha256Base64(const std::vector<uint8_t>& bytes);
    static std::string checksumCrc32Base64(const std::vector<uint8_t>& bytes);

private:
    Authenticator auth_;
    ObjectStore objects_;
    MultipartStore multipart_;

    Response routeAuthenticated(Request&& request, const AuthContext& auth, const std::string& requestId,
                                const BodyPayload& payload) const;
};

}
