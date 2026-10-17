#include "storage/s3/Controller.hpp"
#include "recovery/usage/Ledger.hpp"
#include "log/Registry.hpp"

#include <pugixml.hpp>
#include <regex>

using namespace vh::storage::s3;
using namespace vh::storage::s3::curl;

std::string Controller::initiateMultipartUpload(
    const std::filesystem::path& key,
    const std::unordered_map<std::string, std::string>& metadata) const {
    RequestOptions options;
    options.metadata = metadata;
    return initiateMultipartUpload(key, options);
}

std::string Controller::initiateMultipartUpload(
    const std::filesystem::path& key,
    const RequestOptions& options) const {
    {
        const vh::recovery::usage::ScopedRequestTag tag(vh::recovery::usage::RequestTag::MultipartInitiate);
        recordRequest(RequestKind::Put);
    }

    CURL* curl = curl_easy_init();
    if (!curl) return "";

    const auto keyStr = key.u8string();
    const auto [canonicalPath, url] = constructPaths(curl, keyStr, "?uploads");
    const std::string payloadHash = "UNSIGNED-PAYLOAD";

    auto hdrMap = buildHeaderMap(payloadHash);
    applyRequestOptions(hdrMap, options);

    const std::string authHeader = buildAuthorizationHeader(apiKey_, "POST", canonicalPath, hdrMap, payloadHash);

    HeaderList headers;
    headers.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) headers.add(k + ": " + v);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(0));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || httpCode != 200) {
        log::Registry::cloud()->error("[S3Provider] initiateMultipartUpload failed: CURL={} HTTP={} Response:\n{}",
                                    res, httpCode, response);
        return "";
    }

    std::smatch m;
    std::regex re(R"(<UploadId>([^<]+)</UploadId>)");
    if (std::regex_search(response, m, re) && m.size() > 1)
        return m[1].str();

    log::Registry::cloud()->error("[S3Provider] initiateMultipartUpload failed to parse UploadId from response: {}", response);
    return "";
}

void Controller::uploadPart(const std::filesystem::path& key, const std::string& uploadId,
                             const int partNumber, const std::string& partData, std::string& etagOut) const {
    {
        const vh::recovery::usage::ScopedRequestTag tag(vh::recovery::usage::RequestTag::MultipartPart);
        recordRequest(RequestKind::Put);
    }
    recordUploadBytes(partData.size());

    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to init curl for S3 multipart upload");

    const auto keyStr = key.u8string();
    const std::string query = "?partNumber=" + std::to_string(partNumber) + "&uploadId=" + uploadId;
    const auto [canonicalPath, url] = constructPaths(curl, keyStr, query);

    const std::string payloadHash = sha256Hex(partData);
    const auto hdrMap = buildHeaderMap(payloadHash);
    const std::string authHeader = buildAuthorizationHeader(apiKey_, "PUT", canonicalPath, hdrMap, payloadHash);

    HeaderList headers;
    headers.add("Content-Type: application/octet-stream");
    headers.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) headers.add(k + ": " + v);

    std::string respHdr;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, partData.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(partData.size()));
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, writeToString);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &respHdr);

    const CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || httpCode != 200)
        throw std::runtime_error(fmt::format("Failed to upload part {}: CURL={} HTTP={}", partNumber, res, httpCode));

    if (!extractETag(respHdr, etagOut))
        throw std::runtime_error(fmt::format("Failed to extract ETag for uploaded part {}", partNumber));
}

void Controller::completeMultipartUpload(const std::filesystem::path& key, const std::string& uploadId,
                                         const std::vector<std::string>& etags) const {
    resetLastPutOutcome();
    if (etags.empty()) throw std::runtime_error("No ETags provided to completeMultipartUpload");
    recordRequest(RequestKind::Put);

    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to init curl for S3 complete multipart upload");

    std::u8string keyStr = key.u8string();
    const std::string query = "?uploadId=" + uploadId;
    const auto [canonicalPath, url] = constructPaths(curl, keyStr, query);

    const auto body = composeMultiPartUploadXMLBody(etags);
    const std::string payloadHash = sha256Hex(body);
    auto hdrMap = buildHeaderMap(payloadHash);
    const std::string authHeader = buildAuthorizationHeader(apiKey_, "POST", canonicalPath, hdrMap, payloadHash);

    HeaderList headers;
    headers.add("Content-Type: application/xml");
    headers.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) headers.add(k + ": " + v);

    std::string response;
    std::string responseHeaders;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, writeToString);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || httpCode != 200) {
        log::Registry::cloud()->error("[S3Provider] completeMultipartUpload failed: CURL={} HTTP={} Response:\n{}",
                                    res, httpCode, response);
        throw std::runtime_error(
            fmt::format("Failed to complete multipart upload to S3 (HTTP {}): {}", httpCode, response));
    }

    // S3 answers 200 before it finishes combining the parts and reports a later failure in the body (<Error>).
    pugi::xml_document doc;
    const auto parsed = doc.load_string(response.c_str());
    if (parsed && doc.child("Error")) {
        log::Registry::cloud()->error("[S3Provider] completeMultipartUpload failed after HTTP 200: {}", response);
        throw std::runtime_error(fmt::format("Failed to complete multipart upload to S3 ({}): {}",
                                             doc.child("Error").child_value("Code"),
                                             doc.child("Error").child_value("Message")));
    }
    std::optional<std::string> bodyEtag;
    if (parsed) {
        if (const std::string etag = doc.child("CompleteMultipartUploadResult").child_value("ETag"); !etag.empty())
            bodyEtag = etag;
    }
    recordPutResponse(responseHeaders, bodyEtag);
}

void Controller::abortMultipartUpload(const std::filesystem::path& key, const std::string& uploadId) const {
    recordRequest(RequestKind::Delete);

    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to init curl for S3 abort multipart upload");

    const auto keyStr = key.u8string();
    const std::string query = "?uploadId=" + uploadId;
    const auto [canonicalPath, url] = constructPaths(curl, keyStr, query);

    const std::string payloadHash = sha256Hex("");
    const auto hdrMap = buildHeaderMap(payloadHash);
    const std::string authHeader = buildAuthorizationHeader(apiKey_, "DELETE", canonicalPath, hdrMap, payloadHash);

    HeaderList headers;
    headers.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) headers.add(k + ": " + v);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);

    const CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        throw std::runtime_error("Failed to abort multipart upload to S3: CURL error " + std::to_string(res));
}
