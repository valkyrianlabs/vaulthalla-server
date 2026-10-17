#include "storage/s3/Controller.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "log/Registry.hpp"

using namespace vh::storage::s3;
using namespace vh::storage::s3::curl;

void Controller::uploadLargeObject(const std::filesystem::path& key,
                                     const std::vector<uint8_t>& buffer,
                                     const uintmax_t partSize,
                                     const std::unordered_map<std::string, std::string>& metadata) const {
    RequestOptions options;
    options.metadata = metadata;
    uploadLargeObject(key, buffer, partSize, options);
}

void Controller::uploadLargeObject(const std::filesystem::path& key,
                                     const std::vector<uint8_t>& buffer,
                                     const uintmax_t partSize,
                                     const RequestOptions& options) const {
    resetLastPutOutcome();   // set by completeMultipartUpload; an aborted upload leaves it empty
    if (buffer.empty())
        throw std::runtime_error("Buffer is empty, cannot perform multipart upload");

    const std::string uploadId = initiateMultipartUpload(key, options);
    if (uploadId.empty())
        throw std::runtime_error("Failed to initiate multipart upload for: " + key.string());

    std::vector<std::string> etags;
    int partNo = 1;
    bool success = true;

    size_t offset = 0;
    while (offset < buffer.size()) {
        const size_t chunkSize = std::min(partSize, buffer.size() - offset);
        std::string part(reinterpret_cast<const char*>(&buffer[offset]), chunkSize);

        std::string etag;
        try {
            uploadPart(key, uploadId, partNo++, part, etag);
        } catch (const std::exception& e) {
            log::Registry::cloud()->error("[S3Provider] uploadLargeObject (from buffer) failed to upload part {}: {}",
                                        partNo - 1, e.what());
            success = false;
            break;
        }

        etags.push_back(std::move(etag));
        offset += chunkSize;
    }

    if (!success || etags.empty()) {
        try {
            abortMultipartUpload(key, uploadId);
            return;
        } catch (const std::exception& e) {
            log::Registry::cloud()->error(
                "[S3Provider] uploadLargeObject (from buffer) failed to abort multipart upload for {}: uploadId={}",
                key.string(), uploadId);
            log::Registry::cloud()->error(e.what());
            throw std::runtime_error("Failed to abort multipart upload after part upload failure");
        }
    }

    completeMultipartUpload(key, uploadId, etags);
}

void Controller::uploadBufferWithMetadata(
    const std::filesystem::path& key,
    const std::vector<uint8_t>& buffer,
    const std::unordered_map<std::string, std::string>& metadata) const
{
    uploadBufferWithMetadataConditional(key, buffer, metadata, std::nullopt);
}

void Controller::uploadBufferWithMetadata(
    const std::filesystem::path& key,
    const std::vector<uint8_t>& buffer,
    const RequestOptions& options) const
{
    uploadBufferWithMetadataConditional(key, buffer, options, std::nullopt);
}

void Controller::uploadBufferWithMetadataConditional(
    const std::filesystem::path& key,
    const std::vector<uint8_t>& buffer,
    const std::unordered_map<std::string, std::string>& metadata,
    const std::optional<std::string>& ifMatch,
    const std::optional<std::string>& ifNoneMatch) const
{
    RequestOptions options;
    options.metadata = metadata;
    uploadBufferWithMetadataConditional(key, buffer, options, ifMatch, ifNoneMatch);
}

void Controller::uploadBufferWithMetadataConditional(
    const std::filesystem::path& key,
    const std::vector<uint8_t>& buffer,
    const RequestOptions& options,
    const std::optional<std::string>& ifMatch,
    const std::optional<std::string>& ifNoneMatch) const
{
    resetLastPutOutcome();
    recordRequest(RequestKind::Put);
    recordUploadBytes(buffer.size());

    log::Registry::cloud()->debug("[S3Provider] Uploading buffer to S3 key: {}, buffer_size: {}",
                               key.string(), buffer.size());

    // Hash the raw bytes for SigV4
    const std::string payloadHash = sha256Hex(std::string(buffer.begin(), buffer.end()));

    const CurlEasy tmpHandle;
    const auto [canonical, url] = constructPaths(static_cast<CURL*>(tmpHandle), key);

    auto hdrMap = buildHeaderMap(payloadHash);
    hdrMap["content-type"] = "application/octet-stream";
    if (ifMatch) hdrMap["if-match"] = *ifMatch;
    if (ifNoneMatch) hdrMap["if-none-match"] = *ifNoneMatch;
    applyRequestOptions(hdrMap, options);

    const std::string authHeader = buildAuthorizationHeader(apiKey_, "PUT", canonical, hdrMap, payloadHash);

    SList hdrs;
    hdrs.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) hdrs.add(k + ": " + v);
    // Avoid Expect: 100-continue stalls on small uploads. This header is not part of the signature.
    hdrs.add("Expect:");

    struct ReadCtx {
        const uint8_t* data{nullptr};
        size_t size{0};
        size_t off{0};
    } ctx{ buffer.data(), buffer.size(), 0 };

    const HttpResponse resp = performCurl([&](CURL* h) {
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(h, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs.get());
        curl_easy_setopt(h, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(ctx.size));
        curl_easy_setopt(h, CURLOPT_READDATA, &ctx);
        curl_easy_setopt(h, CURLOPT_READFUNCTION,
            +[](char* out, size_t size, size_t nmemb, void* userdata) -> size_t {
                auto* c = static_cast<ReadCtx*>(userdata);
                if (!c || !c->data) return 0;

                const size_t max_bytes = size * nmemb;
                const size_t remaining = (c->off < c->size) ? (c->size - c->off) : 0;
                const size_t to_copy = (remaining < max_bytes) ? remaining : max_bytes;

                if (to_copy) {
                    std::memcpy(out, c->data + c->off, to_copy);
                    c->off += to_copy;
                }
                return to_copy; // 0 signals EOF
            });

        // Support rewinds (auth retries, redirects)
        curl_easy_setopt(h, CURLOPT_SEEKDATA, &ctx);
        curl_easy_setopt(h, CURLOPT_SEEKFUNCTION,
            +[](void* userdata, curl_off_t offset, int origin) -> int {
                auto* c = static_cast<ReadCtx*>(userdata);
                if (!c || origin != SEEK_SET || offset < 0) return CURL_SEEKFUNC_CANTSEEK;
                const size_t off = static_cast<size_t>(offset);
                if (off > c->size) return CURL_SEEKFUNC_CANTSEEK;
                c->off = off;
                return CURL_SEEKFUNC_OK;
            });
    });

    if (resp.http == 409 || resp.http == 412) {
        throw ConditionalRequestFailed(
            fmt::format("Conditional S3 PUT failed for {} (HTTP {}): {}", key.string(), resp.http, resp.body));
    }

    if (!resp.ok()) throw std::runtime_error(
        fmt::format("Failed to upload buffer to S3 (HTTP {}): {}", resp.http, resp.body));
    recordPutResponse(resp.hdr);
}

void Controller::downloadToBuffer(const std::filesystem::path& key, std::vector<uint8_t>& outBuffer) const {
    recordRequest(RequestKind::Get);

    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to init curl for S3 download to buffer");

    const auto [canonicalPath, url] = constructPaths(curl, key);
    const std::string payloadHash = "UNSIGNED-PAYLOAD";
    const auto hdrMap = buildHeaderMap(payloadHash);
    const std::string authHeader = buildAuthorizationHeader(apiKey_, "GET", canonicalPath, hdrMap, payloadHash);

    HeaderList headers;
    headers.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) headers.add(k + ": " + v);

    struct WriteCtx {
        const Controller* controller;
        std::vector<uint8_t>* data;
        std::string budgetError;
        std::string budgetKind;
    } writeCtx{this, &outBuffer, {}, {}};

    outBuffer.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* ctx = static_cast<WriteCtx*>(userdata);
        const auto bytes = size * nmemb;
        try {
            ctx->controller->recordRequest(RequestKind::DownloadBytes, bytes);
        } catch (const RequestBudgetExceeded& e) {
            ctx->budgetError = e.what();
            ctx->budgetKind = e.kind();
            return 0;
        }
        ctx->data->insert(ctx->data->end(), ptr, ptr + bytes);
        return bytes;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeCtx);

    const CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (!writeCtx.budgetError.empty()) throw RequestBudgetExceeded(writeCtx.budgetError, writeCtx.budgetKind);

    if (res != CURLE_OK)
        log::Registry::cloud()->error("[S3Provider] downloadToBuffer failed for {}: CURL={} Response:\n{}",
                                        key.string(), res, curl_easy_strerror(res));

    if (res != CURLE_OK) throw std::runtime_error(
        fmt::format("Failed to download object from S3 to buffer: CURL error {}", res));
}
