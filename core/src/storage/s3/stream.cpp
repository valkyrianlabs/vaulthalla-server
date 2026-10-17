#include "storage/s3/Controller.hpp"
#include "recovery/usage/Ledger.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "storage/s3/curl/wrappers.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <optional>
#include <sstream>
#include <string_view>

namespace vh::storage::s3 {
namespace stream_detail {

constexpr std::size_t kMaxErrorBodyBytes = 4096;

struct CurlBodyContext {
    CURL* handle{};
    const std::function<bool(long, std::span<const uint8_t>)>* onBody{};
    bool aborted{};
};

size_t curlBodyCallback(char* ptr, const size_t size, const size_t nmemb, void* userdata) {
    auto* ctx = static_cast<CurlBodyContext*>(userdata);
    const auto bytes = size * nmemb;
    long status = 0;
    curl_easy_getinfo(ctx->handle, CURLINFO_RESPONSE_CODE, &status);
    try {
        if (!(*ctx->onBody)(status, {reinterpret_cast<const uint8_t*>(ptr), bytes})) {
            ctx->aborted = true;
            return bytes == 0 ? 1 : 0;  // any count other than `bytes` aborts the transfer
        }
    } catch (...) {
        ctx->aborted = true;
        return bytes == 0 ? 1 : 0;
    }
    return bytes;
}

}

Controller::TransportResponse Controller::transportGet(
    const fs::path& key,
    const std::optional<std::string>& versionId,
    const std::map<std::string, std::string>& extraHeaders,
    const TransportBodyFn& onBody) const {
    const CurlEasy easy;
    auto* handle = static_cast<CURL*>(easy);

    std::string url;
    SList headers;
    if (versionId) {
        // Version ids may carry '+', '/', '=': sigv4::sign encodes the query once for the URL and the signature.
        const auto request = signObjectRequest("GET", key.string(), {{"versionId", *versionId}}, extraHeaders);
        url = request.url;
        for (const auto& [name, value] : request.headers) headers.add(name + ": " + value);
    } else {
        const auto [canonicalPath, plainUrl] = constructPaths(handle, key);
        url = plainUrl;
        const std::string payloadHash = "UNSIGNED-PAYLOAD";
        auto hdrMap = buildHeaderMap(payloadHash);
        for (const auto& [name, value] : extraHeaders) hdrMap[name] = value;
        const auto authHeader = curl::buildAuthorizationHeader(apiKey_, "GET", canonicalPath, hdrMap, payloadHash);
        headers.add("Authorization: " + authHeader);
        for (const auto& [name, value] : hdrMap) headers.add(name + ": " + value);
    }

    TransportResponse response;
    stream_detail::CurlBodyContext ctx{handle, &onBody, false};
    curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, curl::writeToString);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, stream_detail::curlBodyCallback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ctx);
    // Callers sit on request threads: a stalled upstream must fail rather than hold one forever.
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(handle, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(handle, CURLOPT_LOW_SPEED_TIME, 60L);

    const auto res = curl_easy_perform(handle);
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response.http_status);
    if (ctx.aborted) {
        response.transport_ok = false;
        response.transport_error = "transfer aborted";
    } else if (res != CURLE_OK) {
        response.transport_ok = false;
        response.transport_error = curl_easy_strerror(res);
    }
    return response;
}

GetObjectResult Controller::streamObject(const fs::path& key, const GetObjectOptions& options,
                                         const BodySink& sink) const {
    if (options.range && options.range->first > options.range->second)
        throw std::invalid_argument("S3 GET range is inverted for " + key.string());
    if (options.version_id && options.version_id->empty())
        throw std::invalid_argument("S3 GET version id is empty for " + key.string());

    // A GET of a provider version is a restore transfer: its request and bytes count as such in the usage ledger.
    std::optional<vh::recovery::usage::ScopedRequestTag> versionTag;
    if (options.version_id) versionTag.emplace(vh::recovery::usage::RequestTag::VersionRestore);

    // Metered before anything is sent: a GET budget refusal costs nothing upstream.
    recordRequest(RequestKind::Get);

    std::map<std::string, std::string> extra;
    if (options.range) extra["range"] = fmt::format("bytes={}-{}", options.range->first, options.range->second);
    if (options.if_match) extra["if-match"] = *options.if_match;

    GetObjectResult result;
    std::string errorBody;
    std::exception_ptr failure;
    const TransportBodyFn onBody = [&](const long status, const std::span<const uint8_t> bytes) -> bool {
        try {
            // Every received byte is egress, error bodies included.
            recordRequest(RequestKind::DownloadBytes, bytes.size());
            if (status / 100 != 2) {
                const auto room = stream_detail::kMaxErrorBodyBytes - std::min(errorBody.size(), stream_detail::kMaxErrorBodyBytes);
                errorBody.append(reinterpret_cast<const char*>(bytes.data()), std::min(room, bytes.size()));
                return true;
            }
            if (options.range && status != 206)
                throw std::runtime_error(fmt::format("S3 ignored the Range request for {} (HTTP {})", key.string(), status));
            if (options.max_body_bytes && result.body_bytes + bytes.size() > *options.max_body_bytes)
                throw std::runtime_error(fmt::format("S3 object body for {} exceeds the expected {} bytes",
                                                     key.string(), *options.max_body_bytes));
            sink(bytes);
            result.body_bytes += bytes.size();
            return true;
        } catch (...) {
            failure = std::current_exception();
            return false;
        }
    };

    const auto response = transportGet(key, options.version_id, extra, onBody);
    if (failure) std::rethrow_exception(failure);

    result.http_status = response.http_status;
    if (response.http_status == 412)
        throw ConditionalRequestFailed(fmt::format("S3 object {} changed (If-Match failed)", key.string()));
    if (response.http_status == 404)
        throw ObjectNotFound(fmt::format("S3 object not found: {}", key.string()));
    // GET ?versionId= of a delete marker: 405 MethodNotAllowed (x-amz-delete-marker: true). There are no bytes.
    if (options.version_id && response.http_status == 405)
        throw ObjectNotFound(fmt::format("S3 version {} of {} is a delete marker", *options.version_id, key.string()));
    if (!response.transport_ok)
        throw std::runtime_error(fmt::format("S3 GET failed for {}: {}", key.string(), response.transport_error));
    if (response.http_status / 100 != 2)
        throw std::runtime_error(fmt::format("S3 GET failed for {} (HTTP {}): {}", key.string(), response.http_status, errorBody));
    if (options.range && response.http_status != 206)
        throw std::runtime_error(fmt::format("S3 ignored the Range request for {} (HTTP {})", key.string(), response.http_status));

    result.etag = curl::lastHeaderValue(response.headers, "etag");
    result.content_range = curl::lastHeaderValue(response.headers, "content-range");
    return result;
}

}
