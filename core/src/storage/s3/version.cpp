// Version-aware data-plane operations for file recovery (.claude/context/recovery.md, "Provider versioning"):
// ListObjectVersions, HEAD/GET/COPY ?versionId=, and the per-thread PUT outcome (ETag + x-amz-version-id).
//
// These requests are signed with sigv4::sign, whose canonical query is RFC 3986 encoded and sorted and is also the
// query the URL carries: AWS version ids contain '+', '/' and '=', and any difference between what is signed and
// what is sent is a SignatureDoesNotMatch. They go through curl::http (bounded timeouts, the test transport).
// Every request is metered by recordRequest before it is sent, which also enforces the protection lock (#237).

#include "storage/s3/Controller.hpp"
#include "recovery/usage/Ledger.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "storage/s3/sigv4/Signer.hpp"
#include "vault/model/APIKey.hpp"
#include "log/Registry.hpp"

#include <fmt/format.h>
#include <pugixml.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <string_view>

namespace vh::storage::s3 {
namespace version_detail {

thread_local PutOutcome lastPut;

constexpr std::chrono::seconds kMetadataTimeout{60};
// A CopyObject of up to 5 GiB runs server-side; AWS keeps the connection open (sending whitespace) until it is done.
constexpr std::chrono::seconds kCopyTimeout{15 * 60};

std::string lowerAscii(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

struct EndpointParts {
    std::string scheme;
    std::string host;   // host[:port], as the endpoint has it
};

// "https://s3.us-east-2.amazonaws.com/" → {https, s3.us-east-2.amazonaws.com}. Same host the legacy signer uses.
EndpointParts endpointParts(const std::string& endpoint) {
    EndpointParts out{"https", endpoint};
    if (const auto sep = endpoint.find("://"); sep != std::string::npos) {
        out.scheme = endpoint.substr(0, sep);
        out.host = endpoint.substr(sep + 3);
    }
    if (const auto slash = out.host.find('/'); slash != std::string::npos) out.host.resize(slash);
    if (out.host.empty()) throw std::invalid_argument("S3 endpoint has no host");
    return out;
}

// "2009-10-12T17:50:30.000Z" (ListObjectVersions LastModified).
std::optional<std::time_t> parseIsoTime(const std::string& value) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (std::sscanf(value.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6) return std::nullopt;
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    return timegm(&tm);
}

// "Wed, 12 Oct 2009 17:50:00 GMT" (HTTP Last-Modified, RFC 7231 IMF-fixdate). Locale-independent.
std::optional<std::time_t> parseHttpDate(const std::string& value) {
    static constexpr std::string_view kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char month[4] = {};
    int d = 0, y = 0, h = 0, mi = 0, s = 0;
    const auto comma = value.find(',');
    const auto rest = comma == std::string::npos ? value : value.substr(comma + 1);
    if (std::sscanf(rest.c_str(), " %d %3s %d %d:%d:%d", &d, month, &y, &h, &mi, &s) != 6) return std::nullopt;
    int mon = -1;
    for (int i = 0; i < 12; ++i)
        if (kMonths[i] == month) mon = i;
    if (mon < 0) return std::nullopt;
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mon;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    return timegm(&tm);
}

struct S3ErrorBody {
    std::string code;
    std::string message;
};

// <Error><Code>…</Code><Message>…</Message></Error>, or empty when the body is something else.
S3ErrorBody parseErrorBody(const std::string& body) {
    S3ErrorBody out;
    pugi::xml_document doc;
    if (body.empty() || !doc.load_string(body.c_str())) return out;
    const auto error = doc.child("Error");
    if (!error) return out;
    out.code = error.child_value("Code");
    out.message = error.child_value("Message");
    if (out.code.empty()) out.code = "UnknownError";
    return out;
}

std::string describe(const curl::http::Response& response) {
    if (!response.transport_ok) return "transport: " + response.transport_error;
    const auto error = parseErrorBody(response.body);
    if (!error.code.empty()) return fmt::format("HTTP {} {}: {}", response.status, error.code, error.message);
    return fmt::format("HTTP {}", response.status);
}

// Request = Controller::SignedObjectRequest (deduced: the type is protected).
template <class Request>
curl::http::Response send(const Request& request, const std::chrono::seconds timeout) {
    curl::http::Request http;
    http.method = request.method;
    http.url = request.url;
    http.headers = request.headers;
    http.timeout = timeout;
    return curl::http::perform(http);
}

void requireVersionId(const std::string& versionId, const std::string& key) {
    if (versionId.empty()) throw std::invalid_argument("S3 version id is empty for " + key);
}

}

// ---- PUT outcome ---------------------------------------------------------------------------------------------------

PutOutcome Controller::lastPutOutcome() noexcept { return version_detail::lastPut; }

void Controller::resetLastPutOutcome() noexcept {
    version_detail::lastPut.etag.clear();
    version_detail::lastPut.version_id.reset();
}

void Controller::recordPutOutcomeForTesting(PutOutcome outcome) noexcept { version_detail::lastPut = std::move(outcome); }

void Controller::recordPutResponse(const std::string& rawHeaders, const std::optional<std::string>& bodyEtag) {
    PutOutcome outcome;
    if (bodyEtag) outcome.etag = *bodyEtag;
    else if (auto etag = curl::lastHeaderValue(rawHeaders, "etag")) outcome.etag = std::move(*etag);
    outcome.version_id = curl::lastHeaderValue(rawHeaders, "x-amz-version-id");
    version_detail::lastPut = std::move(outcome);
}

// ---- signing -------------------------------------------------------------------------------------------------------

Controller::SignedObjectRequest Controller::signObjectRequest(
    const std::string& method, const std::string& key,
    const std::vector<std::pair<std::string, std::string>>& query,
    const std::map<std::string, std::string>& headers,
    const std::string& payloadHash) const {
    const auto endpoint = version_detail::endpointParts(apiKey_->endpoint);
    const sigv4::Request request{
        .method = method,
        .host = endpoint.host,
        .path = "/" + bucket_ + (key.empty() ? std::string{} : "/" + key),
        .query = query,
        .headers = headers,
        .payload_hash = payloadHash,
    };
    const sigv4::Credentials credentials{
        .access_key = apiKey_->access_key,
        .secret_key = apiKey_->secret_access_key,
        .session_token = {},
    };
    const auto signedRequest = sigv4::sign(request, credentials, apiKey_->region, "s3", std::time(nullptr));

    SignedObjectRequest out;
    out.method = method;
    out.url = endpoint.scheme + "://" + endpoint.host + signedRequest.encoded_path +
              (signedRequest.query_string.empty() ? std::string{} : "?" + signedRequest.query_string);
    for (const auto& [name, value] : signedRequest.headers)
        if (name != "host") out.headers.emplace_back(name, value);   // curl derives Host from the URL
    out.canonical_request = signedRequest.canonical_request;
    return out;
}

// ---- ListObjectVersions --------------------------------------------------------------------------------------------

ObjectVersionPage Controller::listObjectVersionsPage(const std::string& prefix, const std::string& keyMarker,
                                                     const std::string& versionIdMarker,
                                                     const unsigned int maxKeys) const {
    if (!versionIdMarker.empty() && keyMarker.empty())
        throw std::invalid_argument("ListObjectVersions: a version-id-marker needs a key-marker");

    std::vector<std::pair<std::string, std::string>> query{
        {"versions", ""},
        {"max-keys", std::to_string(std::clamp(maxKeys, 1u, 1000u))},
    };
    if (!prefix.empty()) query.emplace_back("prefix", prefix);
    if (!keyMarker.empty()) query.emplace_back("key-marker", keyMarker);
    if (!versionIdMarker.empty()) query.emplace_back("version-id-marker", versionIdMarker);

    {
        const vh::recovery::usage::ScopedRequestTag tag(vh::recovery::usage::RequestTag::VersionList);
        recordRequest(RequestKind::List);
    }
    const auto response = version_detail::send(signObjectRequest("GET", {}, query, {}), version_detail::kMetadataTimeout);
    if (!response.ok() || response.truncated)
        throw std::runtime_error(fmt::format("ListObjectVersions failed for {} prefix '{}' ({})", bucket_, prefix,
                                             response.truncated ? "response too large" : version_detail::describe(response)));

    pugi::xml_document doc;
    if (!doc.load_string(response.body.c_str()))
        throw std::runtime_error("ListObjectVersions returned a response that is not XML");
    const auto root = doc.child("ListVersionsResult");
    if (!root) {
        const auto error = version_detail::parseErrorBody(response.body);
        throw std::runtime_error(error.code.empty()
                                     ? std::string("ListObjectVersions response has no ListVersionsResult")
                                     : fmt::format("ListObjectVersions failed ({}): {}", error.code, error.message));
    }

    ObjectVersionPage page;
    for (const auto node : root.children()) {
        const std::string_view name = node.name();
        const bool marker = name == "DeleteMarker";
        if (!marker && name != "Version") continue;
        ObjectVersionInfo info;
        info.key = node.child_value("Key");
        info.version_id = node.child_value("VersionId");
        info.is_latest = std::string_view(node.child_value("IsLatest")) == "true";
        info.last_modified = version_detail::parseIsoTime(node.child_value("LastModified"));
        info.delete_marker = marker;
        if (!marker) {
            info.etag = node.child_value("ETag");
            info.size = std::strtoull(node.child_value("Size"), nullptr, 10);
            if (const std::string storageClass = node.child_value("StorageClass"); !storageClass.empty())
                info.storage_class = storageClass;
        }
        if (info.key.empty() || info.version_id.empty())
            throw std::runtime_error("ListObjectVersions returned an entry without a key or version id");
        page.versions.push_back(std::move(info));
    }

    page.truncated = std::string_view(root.child_value("IsTruncated")) == "true";
    if (page.truncated) {
        page.next_key_marker = root.child_value("NextKeyMarker");
        page.next_version_id_marker = root.child_value("NextVersionIdMarker");
        // Never hand back a page the caller can't continue from: that would silently drop the rest of the listing.
        if (page.next_key_marker.empty())
            throw std::runtime_error("ListObjectVersions is truncated but names no NextKeyMarker");
    }
    return page;
}

// ---- HEAD ?versionId= ----------------------------------------------------------------------------------------------

std::optional<ObjectVersionHead> Controller::headObjectVersion(const std::string& key, const std::string& versionId) const {
    version_detail::requireVersionId(versionId, key);
    recordRequest(RequestKind::Head);

    const auto response = version_detail::send(signObjectRequest("HEAD", key, {{"versionId", versionId}}, {}),
                                                version_detail::kMetadataTimeout);
    // The same per-thread HEAD outcome getHeadObject sets (its storage lives in meta.cpp).
    recordHeadOutcomeForTesting({.performed = true, .transport_ok = response.transport_ok, .http_status = response.status});

    if (!response.transport_ok)
        throw std::runtime_error(fmt::format("S3 HEAD {}@{} failed: {}", key, versionId, response.transport_error));
    if (response.status == 404) return std::nullopt;

    const bool deleteMarker = version_detail::lowerAscii(response.header("x-amz-delete-marker").value_or("")) == "true";
    // AWS answers HEAD ?versionId= of a delete marker with 405 MethodNotAllowed + x-amz-delete-marker: true.
    if (!(response.ok() || (response.status == 405 && deleteMarker)))
        throw std::runtime_error(fmt::format("S3 HEAD {}@{} failed ({})", key, versionId, version_detail::describe(response)));

    ObjectVersionHead head;
    head.delete_marker = deleteMarker;
    head.version_id = response.header("x-amz-version-id").value_or(versionId);
    if (const auto lastModified = response.header("last-modified"))
        head.last_modified = version_detail::parseHttpDate(*lastModified);
    if (deleteMarker) return head;

    head.etag = response.header("etag").value_or("");
    head.content_length = std::strtoull(response.header("content-length").value_or("0").c_str(), nullptr, 10);
    head.storage_class = response.header("x-amz-storage-class");
    static constexpr std::string_view kMetaPrefix = "x-amz-meta-";
    for (const auto& [name, value] : response.headers) {
        auto lower = version_detail::lowerAscii(name);
        if (lower.starts_with(kMetaPrefix)) head.metadata[lower.substr(kMetaPrefix.size())] = value;
    }
    return head;
}

// ---- CopyObject ?versionId= ----------------------------------------------------------------------------------------

CopyResult Controller::copyObjectVersion(const std::string& sourceKey, const std::string& sourceVersionId,
                                         const std::string& destKey, const uint64_t sourceSize,
                                         const RequestOptions& options,
                                         const std::optional<std::string>& ifSourceMatchEtag) const {
    resetLastPutOutcome();
    version_detail::requireVersionId(sourceVersionId, sourceKey);
    if (sourceKey.empty() || destKey.empty()) throw std::invalid_argument("S3 copy needs a source and a destination key");
    if (sourceSize > MAX_SINGLE_COPY_BYTES)
        throw ObjectTooLargeForCopy(fmt::format(
            "S3 version {}@{} is {} bytes; a single CopyObject copies at most {} bytes", sourceKey, sourceVersionId,
            sourceSize, MAX_SINGLE_COPY_BYTES));

    std::map<std::string, std::string> headers;
    applyRequestOptions(headers, options, false);   // storage class etc.; never replacement metadata (COPY keeps it)
    headers["x-amz-copy-source"] = "/" + bucket_ + "/" + sigv4::uriEncode(sourceKey, false) +
                                   "?versionId=" + sigv4::uriEncode(sourceVersionId, true);
    headers["x-amz-metadata-directive"] = "COPY";
    if (ifSourceMatchEtag) headers["x-amz-copy-source-if-match"] = *ifSourceMatchEtag;

    {
        // Copying a version onto its key is how a provider version is restored.
        const vh::recovery::usage::ScopedRequestTag tag(vh::recovery::usage::RequestTag::VersionRestore);
        recordRequest(RequestKind::Copy);
    }
    const auto response = version_detail::send(signObjectRequest("PUT", destKey, {}, headers, sigv4::sha256Hex("")),
                                                version_detail::kCopyTimeout);

    const auto error = version_detail::parseErrorBody(response.body);
    if (response.transport_ok && response.status == 404)
        throw ObjectNotFound(fmt::format("S3 copy source {}@{} not found ({})", sourceKey, sourceVersionId,
                                         error.code.empty() ? "404" : error.code));
    if (response.transport_ok && response.status == 412)
        throw ConditionalRequestFailed(fmt::format("S3 copy source {}@{} no longer matches {}", sourceKey,
                                                   sourceVersionId, ifSourceMatchEtag.value_or("")));
    if (!response.ok() || response.truncated)
        throw std::runtime_error(fmt::format("S3 copy {}@{} → {} failed ({})", sourceKey, sourceVersionId, destKey,
                                             version_detail::describe(response)));
    // A copy can fail after S3 has answered 200: the error is then the body.
    if (!error.code.empty())
        throw std::runtime_error(fmt::format("S3 copy {}@{} → {} failed after HTTP 200 ({}): {}", sourceKey,
                                             sourceVersionId, destKey, error.code, error.message));

    pugi::xml_document doc;
    const auto result = doc.load_string(response.body.c_str()) ? doc.child("CopyObjectResult") : pugi::xml_node{};
    if (!result)
        throw std::runtime_error(fmt::format("S3 copy {}@{} → {} returned no CopyObjectResult", sourceKey,
                                             sourceVersionId, destKey));

    CopyResult out;
    out.etag = result.child_value("ETag");
    out.version_id = response.header("x-amz-version-id");
    version_detail::lastPut = {.etag = out.etag, .version_id = out.version_id};
    log::Registry::cloud()->debug("[S3Provider] copied {}@{} → {} (version {})", sourceKey, sourceVersionId, destKey,
                                  out.version_id.value_or("-"));
    return out;
}

}
