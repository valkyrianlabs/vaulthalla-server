#include "storage/s3/Controller.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "log/Registry.hpp"

#include <fstream>

using namespace vh::storage::s3;
using namespace vh::storage::s3::curl;

void Controller::uploadLargeObject(const std::filesystem::path& key,
const std::filesystem::path& filePath,
const uintmax_t partSize,
const std::unordered_map<std::string, std::string>& metadata) const {
    RequestOptions options;
    options.metadata = metadata;
    uploadLargeObject(key, filePath, partSize, options);
}

void Controller::uploadLargeObject(const std::filesystem::path& key,
const std::filesystem::path& filePath,
const uintmax_t partSize,
const RequestOptions& options) const {
    resetLastPutOutcome();   // set by completeMultipartUpload; an aborted upload leaves it empty
    std::ifstream file(filePath, std::ios::binary);
    if (!file) throw std::runtime_error("Failed to open file for large upload: " + filePath.string());

    const std::string uploadId = initiateMultipartUpload(key, options);
    if (uploadId.empty()) throw std::runtime_error("Failed to initiate multipart upload for: " + key.string());

    std::vector<std::string> etags;
    int partNo = 1;
    bool success = true;

    while (file) {
        std::string part(partSize, '\0');
        file.read(&part[0], static_cast<std::streamsize>(partSize));
        std::streamsize bytesRead = file.gcount();
        if (bytesRead <= 0) break;

        part.resize(static_cast<size_t>(bytesRead));

        std::string etag;
        try { uploadPart(key, uploadId, partNo++, part, etag); }
        catch (const std::exception& e) {
            log::Registry::cloud()->error("[S3Provider] uploadLargeObject failed to upload part {}: {}", partNo - 1, e.what());
            success = false;
            break;
        }
        etags.push_back(std::move(etag));
    }

    if (!success || etags.empty()) {
        try {
            abortMultipartUpload(key, uploadId);
            return;
        }
        catch (const std::exception& e) {
            log::Registry::cloud()->error(
                "[S3Provider] uploadLargeObject failed to abort multipart upload for {}: uploadId={}",
                key.string(), uploadId);
            log::Registry::cloud()->error(e.what());
            throw std::runtime_error("Failed to abort multipart upload after part upload failure");
        }
    }

    return completeMultipartUpload(key, uploadId, etags);
}

void Controller::uploadObject(const std::filesystem::path& key, const std::filesystem::path& filePath) const {
    uploadObjectWithMetadata(key, filePath, RequestOptions{});
}

void Controller::uploadObjectWithMetadata(
    const std::filesystem::path& key,
    const std::filesystem::path& filePath,
    const std::unordered_map<std::string, std::string>& metadata) const {
    RequestOptions options;
    options.metadata = metadata;
    uploadObjectWithMetadata(key, filePath, options);
}

void Controller::uploadObjectWithMetadata(
    const std::filesystem::path& key,
    const std::filesystem::path& filePath,
    const RequestOptions& options) const {
    resetLastPutOutcome();
    recordRequest(RequestKind::Put);

    std::ifstream fin(filePath, std::ios::binary);
    if (!fin) throw std::runtime_error("Failed to open file for upload: " + filePath.string());

    fin.seekg(0, std::ios::end);
    const curl_off_t sz = fin.tellg();
    fin.seekg(0);
    if (sz > 0) recordUploadBytes(static_cast<uint64_t>(sz));

    const std::string fileContents = slurp(fin);
    const std::string payloadHash = sha256Hex(fileContents);

    fin.clear();
    fin.seekg(0);

    CurlEasy tmpHandle;
    const auto [canonical, url] = constructPaths(static_cast<CURL*>(tmpHandle), key);

    auto hdrMap = buildHeaderMap(payloadHash);
    hdrMap["content-type"] = "application/octet-stream";
    applyRequestOptions(hdrMap, options);

    const std::string authHeader = buildAuthorizationHeader(apiKey_, "PUT", canonical, hdrMap, payloadHash);

    SList hdrs;
    hdrs.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) hdrs.add(k + ": " + v);
    hdrs.add("Expect:");

    HttpResponse resp = performCurl([&](CURL* h) {
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(h, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs.get());
        curl_easy_setopt(h, CURLOPT_READDATA, &fin);
        curl_easy_setopt(h, CURLOPT_INFILESIZE_LARGE, sz);
        curl_easy_setopt(h, CURLOPT_READFUNCTION,
            +[](char* buf, const size_t sz, const size_t nm, void* ud) -> size_t {
                auto* fp = static_cast<std::ifstream*>(ud);
                fp->read(buf, static_cast<std::streamsize>(sz * nm));
                return static_cast<size_t>(fp->gcount());
            });
    });

    if (!resp.ok()) throw std::runtime_error(
        fmt::format("Failed to upload file to S3 (HTTP {}): {}", resp.http, resp.body));
    recordPutResponse(resp.hdr);
}

void Controller::downloadObject(const std::filesystem::path& key,
                                const std::filesystem::path& outputPath) const {
    recordRequest(RequestKind::Get);

    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to init curl for S3 download");

    std::ofstream file(outputPath, std::ios::binary);
    if (!file) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to open output file for S3 download: " + outputPath.string());
    }

    const auto [canonicalPath, url] = constructPaths(curl, key);

    const std::string payloadHash = "UNSIGNED-PAYLOAD";
    auto hdrMap = buildHeaderMap(payloadHash);
    const std::string authHeader =  buildAuthorizationHeader(apiKey_, "GET", canonicalPath, hdrMap, payloadHash);

    HeaderList headers;
    headers.add("Authorization: " + authHeader);
    for (const auto& [k, v] : hdrMap) headers.add(fmt::format("{}: {}", k, v));

    struct WriteCtx {
        const Controller* controller;
        std::ofstream* fout;
        uint64_t bytes{};
        std::string budgetError;
        std::string budgetKind;
    } writeCtx{this, &file, 0, {}, {}};

    auto writeFn = +[](const char* ptr, const size_t size, const size_t nmemb, void* userdata) -> size_t {
        auto* ctx = static_cast<WriteCtx*>(userdata);
        const auto bytes = size * nmemb;
        try {
            ctx->controller->recordRequest(RequestKind::DownloadBytes, bytes);
        } catch (const RequestBudgetExceeded& e) {
            ctx->budgetError = e.what();
            ctx->budgetKind = e.kind();
            return 0;
        }
        ctx->fout->write(ptr, bytes);
        ctx->bytes += bytes;
        return bytes;
    };

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeCtx);

    const CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    file.close();

    if (!writeCtx.budgetError.empty()) throw RequestBudgetExceeded(writeCtx.budgetError, writeCtx.budgetKind);

    if (res != CURLE_OK) throw std::runtime_error(
        fmt::format("Failed to download file from S3: CURL error {}", res));
}
