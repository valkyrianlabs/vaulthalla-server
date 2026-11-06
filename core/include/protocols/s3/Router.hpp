#pragma once

#include "protocols/s3/Auth.hpp"
#include "protocols/s3/Error.hpp"
#include "protocols/s3/MultipartStore.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "crypto/Fwd.hpp"

#include <boost/beast/http.hpp>
#include <filesystem>
#include <map>
#include <memory>
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
        // A streamed body: ciphertext under the process key (crypto::ScratchFile, #345), unlinked with its last
        // reference. Unset for a buffered body (request.body()).
        std::shared_ptr<crypto::ScratchFile> file;
        uint64_t size = 0;
        std::map<std::string, std::string> trailer_headers;
        std::optional<std::string> sha256_hex;
        std::optional<std::string> sha256_base64;
        std::optional<std::string> md5_base64;
        std::optional<std::string> md5_hex;
        std::optional<std::string> crc32_base64;
        // Set when `file` still holds the aws-chunked encoding as received: route() decodes it into a new scratch file
        // at this path (after authenticating, for signed chunks) and acts only once every chunk verified. The digests
        // above are then those of the encoded body; route() replaces them (and `file`) with the decoded body's.
        std::optional<std::filesystem::path> aws_chunked_decode_to;
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
