#include "storage/s3/Controller.hpp"
#include "vault/model/APIKey.hpp"
#include "db/encoding/timestamp.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "log/Registry.hpp"

#include <algorithm>
#include <cctype>

using namespace vh::storage::s3;
using namespace vh::vault::model;
using namespace vh::storage::s3::curl;
using namespace vh::db::encoding;

std::map<std::string, std::string> Controller::buildHeaderMap(const std::string &payloadHash) const {
    return {
        {"host", apiKey_->endpoint.substr(apiKey_->endpoint.find("//") + 2)},
        {"x-amz-content-sha256", payloadHash},
        {"x-amz-date", getCurrentTimestamp()}
    };
}

void Controller::applyRequestOptions(
    std::map<std::string, std::string>& headers,
    const RequestOptions& options,
    const bool includeMetadata) {
    for (const auto& [key, value] : options.system_headers) {
        auto normalized = key;
        std::ranges::transform(normalized, normalized.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        headers[normalized] = value;
    }

    if (!includeMetadata) return;

    for (const auto& [key, value] : options.metadata) {
        headers[fmt::format("x-amz-meta-{}", key)] = value;
    }
}

SList Controller::makeSigHeaders(const std::string &method,
                                 const std::string &canonical,
                                 const std::string &payloadHash,
                                 const std::string &query) const {
    auto base = buildHeaderMap(payloadHash); // host + dates
    const auto auth = buildAuthorizationHeader(apiKey_, method, canonical, base, payloadHash, query);

    SList out;
    out.add("Authorization: " + auth);
    for (auto &[k, v]: base) out.add(k + ": " + v);
    return out; // RAII slist
}

namespace {
thread_local Controller::HeadOutcome lastHead;
}

void Controller::resetLastHeadOutcome() noexcept { lastHead = {}; }

Controller::HeadOutcome Controller::lastHeadOutcome() noexcept { return lastHead; }

void Controller::recordHeadOutcomeForTesting(const HeadOutcome outcome) noexcept { lastHead = outcome; }

std::optional<std::unordered_map<std::string, std::string> >
Controller::getHeadObject(const std::filesystem::path &key) const {
    recordRequest(RequestKind::Head);

    const auto [canonicalPath, url] = constructPaths(nullptr, key);
    const std::string payloadHash = "UNSIGNED-PAYLOAD";

    auto hdrMap = buildHeaderMap(payloadHash);
    const std::string authHeader = buildAuthorizationHeader(apiKey_, "HEAD", canonicalPath, hdrMap, payloadHash);

    SList headers;
    headers.add("Authorization: " + authHeader);
    for (const auto &[k, v]: hdrMap) headers.add(k + ": " + v);

    HttpResponse resp = performCurl([&](CURL *h) {
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(h, CURLOPT_NOBODY, 1L); // HEAD request
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers.get());
    });
    lastHead = {.performed = true, .transport_ok = resp.curl == CURLE_OK, .http_status = resp.http};

    if (!resp.ok()) {
        // 404 is an answer (the object is absent: a vault's first manifest HEAD, a removal check), not a failure.
        if (resp.curl == CURLE_OK && resp.http == 404)
            log::Registry::cloud()->debug("[S3Provider] getHeadObject: {} does not exist (HTTP 404)", key.string());
        else
            log::Registry::cloud()->error("[S3Provider] getHeadObject failed for {}: CURL={} HTTP={}",
                                          key.string(), resp.curl, resp.http);
        return std::nullopt;
    }

    // Parse response headers into key-value pairs
    std::unordered_map<std::string, std::string> metadata;
    std::istringstream headerStream(resp.hdr);
    std::string line;
    while (std::getline(headerStream, line)) {
        if (auto pos = line.find(':'); pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            trimInPlace(key);
            trimInPlace(value);
            metadata.emplace(std::move(key), std::move(value));
        }
    }

    return metadata;
}

void Controller::setObjectContentHash(const std::filesystem::path &key, const std::string &hash,
                                      const RequestOptions& options) const {
    recordRequest(RequestKind::Copy);

    CurlEasy curl;
    const auto [canonicalPath, url] = constructPaths(static_cast<CURL *>(curl), key);

    const std::string payloadHash = "UNSIGNED-PAYLOAD";

    std::ostringstream source;
    source << "/" << bucket_ << "/" << escapeKeyPreserveSlashes(static_cast<CURL *>(curl), key);

    auto hdrMap = buildHeaderMap(payloadHash);
    hdrMap["x-amz-copy-source"] = source.str();
    hdrMap["x-amz-metadata-directive"] = "REPLACE";
    hdrMap["x-amz-meta-content-hash"] = hash;
    applyRequestOptions(hdrMap, options, false);
    const std::string authHeader = buildAuthorizationHeader(apiKey_, "PUT", canonicalPath, hdrMap, payloadHash);

    SList headers;
    headers.add("Authorization: " + authHeader);
    for (const auto &[k, v]: hdrMap) headers.add(k + ": " + v);

    HttpResponse resp = performCurl([&](CURL *h) {
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers.get());
    });

    if (!resp.ok())
        log::Registry::cloud()->error("[S3Provider] setObjectContentHash failed for {}: CURL={} HTTP={}",
                                      key.string(), resp.curl, resp.http);

    if (!resp.ok())
        throw std::runtime_error(
            fmt::format("Failed to set content hash metadata on S3 object (HTTP {}): {}", resp.http, resp.body));
}

void Controller::setObjectEncryptionMetadata(const std::string &key, const std::string &iv_b64,
                                             unsigned int key_version,
                                             const RequestOptions& options) const {
    recordRequest(RequestKind::Copy);

    CurlEasy curl;
    const auto [canonicalPath, url] = constructPaths(static_cast<CURL *>(curl), key);
    const std::string payloadHash = "UNSIGNED-PAYLOAD";

    std::ostringstream source;
    source << "/" << bucket_ << "/" << escapeKeyPreserveSlashes(static_cast<CURL *>(curl), key);

    auto hdrMap = buildHeaderMap(payloadHash);
    hdrMap["x-amz-copy-source"] = source.str();
    hdrMap["x-amz-metadata-directive"] = "REPLACE";
    hdrMap["x-amz-meta-vh-encrypted"] = "true";
    hdrMap["x-amz-meta-vh-iv"] = iv_b64;
    hdrMap["x-amz-meta-vh-algo"] = "aes256gcm";
    hdrMap["x-amz-meta-vh-key-version"] = std::to_string(key_version);
    applyRequestOptions(hdrMap, options, false);
    const std::string authHeader = buildAuthorizationHeader(apiKey_, "PUT", canonicalPath, hdrMap, payloadHash);

    SList headers;
    headers.add("Authorization: " + authHeader);
    for (const auto &[k, v]: hdrMap) headers.add(k + ": " + v);

    HttpResponse resp = performCurl([&](CURL *h) {
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers.get());
    });

    if (!resp.ok())
        log::Registry::cloud()->error("[S3Provider] setObjectEncryptionMetadata failed for {}: CURL={} HTTP={}",
                                      key, resp.curl, resp.http);

    if (!resp.ok())
        throw std::runtime_error(
            fmt::format("Failed to set encryption metadata on S3 object (HTTP {}): {}", resp.http, resp.body));
}
