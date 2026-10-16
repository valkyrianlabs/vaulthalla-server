#include "storage/s3/Controller.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "vault/model/APIKey.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "log/Registry.hpp"

#include <algorithm>
#include <ctime>
#include <curl/curl.h>
#include <fmt/format.h>
#include <pugixml.hpp>
#include <sstream>
#include <utility>
#include <vector>

using namespace vh::vault::model;
using namespace vh::storage::s3::curl;

namespace vh::storage::s3 {
    namespace {
        thread_local std::vector<ScopedS3RequestUsageCapture*> requestUsageCaptures;

        bool isNoSuchKeyDeleteResponse(const HttpResponse& resp) {
            if (resp.curl != CURLE_OK || resp.http != 404) return false;
            return resp.body.find("NoSuchKey") != std::string::npos ||
                   resp.body.find("<Code>NotFound</Code>") != std::string::npos;
        }
    }

    Controller::Controller(const std::shared_ptr<APIKey>& apiKey, std::string bucket)
    : apiKey_(apiKey), bucket_(std::move(bucket)) {
        if (!apiKey_) throw std::runtime_error("S3Provider requires a valid S3APIKey");
        identity_ = upstream::identityFor(*apiKey_, bucket_);
        ensureCurlGlobalInit();
    }

    Controller::~Controller() = default;

    void Controller::setRequestBudget(const S3RequestBudget& budget) const {
        std::scoped_lock lock(metricsMutex_);
        requestBudget_ = budget;
    }

    void Controller::clearRequestBudget() const {
        std::scoped_lock lock(metricsMutex_);
        requestBudget_.reset();
    }

    void Controller::resetRequestMetrics() const {
        std::scoped_lock lock(metricsMutex_);
        metrics_ = {};
    }

    S3RequestMetrics Controller::requestMetrics() const {
        std::scoped_lock lock(metricsMutex_);
        return metrics_;
    }

    void Controller::pushRequestUsageCapture(ScopedS3RequestUsageCapture* capture) {
        if (capture) requestUsageCaptures.push_back(capture);
    }

    void Controller::popRequestUsageCapture(ScopedS3RequestUsageCapture* capture) noexcept {
        if (!capture || requestUsageCaptures.empty()) return;
        if (requestUsageCaptures.back() == capture) {
            requestUsageCaptures.pop_back();
            return;
        }
        const auto it = std::find(requestUsageCaptures.rbegin(), requestUsageCaptures.rend(), capture);
        if (it != requestUsageCaptures.rend())
            requestUsageCaptures.erase(std::next(it).base());
    }

    void Controller::recordRequest(const RequestKind kind, const uint64_t amount) const {
        // Hard protection (#237): every metered request of a bucket controller passes here before it is sent, so a
        // lock set while a sync pass, hydrate, purge or retry is in flight stops its next request. Bytes of a GET
        // already granted are not re-checked mid-stream.
        if (kind != RequestKind::DownloadBytes) upstream::guard::require(identity_);
        // Every capture active on this thread sees the request: a nested capture (a preview hydrate's own cap
        // inside an S3 gateway request) must not hide it from the outer one. All captures and the engine-wide
        // budget are checked before anything is recorded.
        const auto checkCapture = [&](const ScopedS3RequestUsageCapture* capture) {
            switch (kind) {
            case RequestKind::List:
                capture->checkList(amount);
                break;
            case RequestKind::Head:
                capture->checkHead(amount);
                break;
            case RequestKind::Get:
                capture->checkGet(amount);
                break;
            case RequestKind::Put:
                capture->checkPut(amount);
                break;
            case RequestKind::Copy:
                capture->checkCopy(amount);
                break;
            case RequestKind::Delete:
                capture->checkDelete(amount);
                break;
            case RequestKind::DownloadBytes:
                capture->checkDownloadBytes(amount);
                break;
            }
        };
        const auto recordCapture = [&](ScopedS3RequestUsageCapture* capture) {
            switch (kind) {
            case RequestKind::List:
                capture->recordList(amount);
                break;
            case RequestKind::Head:
                capture->recordHead(amount);
                break;
            case RequestKind::Get:
                capture->recordGet(amount);
                break;
            case RequestKind::Put:
                capture->recordPut(amount);
                break;
            case RequestKind::Copy:
                capture->recordCopy(amount);
                break;
            case RequestKind::Delete:
                capture->recordDelete(amount);
                break;
            case RequestKind::DownloadBytes:
                capture->recordDownloadBytes(amount);
                break;
            }
        };

        for (auto it = requestUsageCaptures.rbegin(); it != requestUsageCaptures.rend(); ++it) checkCapture(*it);

        std::scoped_lock lock(metricsMutex_);

        auto bump = [&](uint64_t& current, const std::optional<uint64_t>& limit, const char* label) {
            if (limit && current + amount > *limit) {
                metrics_.budget_exceeded = true;
                metrics_.budget_exceeded_reason = fmt::format("S3 request budget exceeded for {}", label);
                throw RequestBudgetExceeded(metrics_.budget_exceeded_reason, label);
            }
            current += amount;
        };

        switch (kind) {
        case RequestKind::List:
            bump(metrics_.list_requests, requestBudget_ ? requestBudget_->max_list_requests : std::optional<uint64_t>{}, "LIST");
            break;
        case RequestKind::Head:
            bump(metrics_.head_requests, requestBudget_ ? requestBudget_->max_head_requests : std::optional<uint64_t>{}, "HEAD");
            break;
        case RequestKind::Get:
            bump(metrics_.get_requests, requestBudget_ ? requestBudget_->max_get_requests : std::optional<uint64_t>{}, "GET");
            break;
        case RequestKind::Put:
            bump(metrics_.put_requests, requestBudget_ ? requestBudget_->max_put_requests : std::optional<uint64_t>{}, "PUT");
            break;
        case RequestKind::Copy:
            bump(metrics_.copy_requests, requestBudget_ ? requestBudget_->max_copy_requests : std::optional<uint64_t>{}, "COPY");
            break;
        case RequestKind::Delete:
            bump(metrics_.delete_requests, requestBudget_ ? requestBudget_->max_delete_requests : std::optional<uint64_t>{}, "DELETE");
            break;
        case RequestKind::DownloadBytes:
            bump(metrics_.downloaded_bytes, requestBudget_ ? requestBudget_->max_downloaded_bytes : std::optional<uint64_t>{}, "downloaded bytes");
            break;
        }

        for (auto* capture : requestUsageCaptures) recordCapture(capture);
    }

    void Controller::recordUploadBytes(const uint64_t amount) const {
        if (amount == 0) return;
        {
            std::scoped_lock lock(metricsMutex_);
            metrics_.uploaded_bytes += amount;
        }
        for (auto* capture : requestUsageCaptures) capture->recordUploadBytes(amount);
    }

    void Controller::deleteObject(const fs::path& key) const {
        recordRequest(RequestKind::Delete);

        const CurlEasy tmpHandle;
        const auto [canonical, url] = constructPaths(static_cast<CURL*>(tmpHandle), key);

        const std::string payloadHash = sha256Hex("");
        const SList hdrs = makeSigHeaders("DELETE", canonical, payloadHash);

        HttpResponse resp = performCurl([&](CURL* h){
            curl_easy_setopt(h, CURLOPT_URL, url.c_str());
            curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, "DELETE");
            curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs.get());
        });

        if (isNoSuchKeyDeleteResponse(resp)) {
            log::Registry::cloud()->warn(
                "[S3Provider] deleteObject confirmed object is already absent: key={} HTTP={} Response:\n{}",
                key.string(),
                resp.http,
                resp.body);
            throw ObjectNotFound(fmt::format("Object not found in upstream S3 during delete: {}", key.string()));
        }

        if (!resp.ok()) log::Registry::cloud()->error(
            "[S3Provider] deleteObject failed: CURL={} HTTP={} Response:\n{}",
            resp.curl, resp.http, resp.body
        );

        if (!resp.ok()) throw std::runtime_error(
            fmt::format("Failed to delete object from S3 (HTTP {}): {}", resp.http, resp.body));
    }

    ObjectKeyPage Controller::listObjectKeysPage(const std::string& continuationToken, const unsigned int maxKeys) const {
        recordRequest(RequestKind::List);

        const CurlEasy handle;
        auto* curl = static_cast<CURL*>(handle);
        if (!curl) throw std::runtime_error("listObjectKeysPage: curl_easy_init failed");

        std::ostringstream uri;
        uri << "/" << bucket_ << "?list-type=2&max-keys=" << std::clamp(maxKeys, 1u, 1000u);
        if (!continuationToken.empty()) {
            char* escaped = curl_easy_escape(curl, continuationToken.c_str(), static_cast<int>(continuationToken.size()));
            if (!escaped) throw std::runtime_error("listObjectKeysPage: cannot escape the continuation token");
            uri << "&continuation-token=" << escaped;
            curl_free(escaped);
        }

        const std::string uriStr = uri.str();
        const std::string url = apiKey_->endpoint + uriStr;
        const std::string payloadHash = "UNSIGNED-PAYLOAD";
        const auto hdrMap = buildHeaderMap(payloadHash);
        const std::string authHeader = buildAuthorizationHeader(apiKey_, "GET", uriStr, hdrMap, payloadHash);

        HeaderList headers;
        headers.add("Authorization: " + authHeader);
        for (const auto& [k, v] : hdrMap) headers.add(k + ": " + v);

        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        const CURLcode res = curl_easy_perform(curl);
        long http = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
        if (res != CURLE_OK || http != 200)
            throw std::runtime_error(fmt::format("ListObjectsV2 failed (CURL {}, HTTP {}): {}", static_cast<int>(res), http,
                                                 response.substr(0, 512)));

        pugi::xml_document doc;
        if (!doc.load_string(response.c_str()))
            throw std::runtime_error("ListObjectsV2 returned a response that is not XML");
        const auto result = doc.child("ListBucketResult");
        if (!result) throw std::runtime_error("ListObjectsV2 response has no ListBucketResult");

        ObjectKeyPage page;
        for (const auto contents : result.children("Contents"))
            if (const auto key = std::string(contents.child_value("Key")); !key.empty()) page.keys.push_back(key);
        if (std::string(result.child_value("IsTruncated")) == "true")
            page.next_continuation_token = result.child_value("NextContinuationToken");
        return page;
    }

    std::u8string Controller::listObjects(const fs::path& prefix) const {
        std::u8string fullXmlResponse;
        std::string continuationToken;
        bool moreResults = true;

        while (moreResults) {
            recordRequest(RequestKind::List);

            CURL* curl = curl_easy_init();
            if (!curl) break;

            std::string escapedPrefix;
            if (!prefix.empty()) escapedPrefix = escapeKeyPreserveSlashes(curl, prefix);

            std::ostringstream uri;
            uri << "/" << bucket_ << "?list-type=2";
            if (!escapedPrefix.empty()) uri << "&prefix=" << escapedPrefix;
            if (!continuationToken.empty()) {
                char* escapedToken = curl_easy_escape(curl, continuationToken.c_str(), static_cast<int>(continuationToken.size()));
                if (!escapedToken) {
                    curl_easy_cleanup(curl);
                    break;
                }
                uri << "&continuation-token=" << escapedToken;
                curl_free(escapedToken);
            }

            const std::string uriStr = uri.str();
            const std::string url = apiKey_->endpoint + uriStr;

            const std::string payloadHash = "UNSIGNED-PAYLOAD";
            const auto hdrMap = buildHeaderMap(payloadHash);
            const std::string authHeader =  buildAuthorizationHeader(apiKey_, "GET", uriStr, hdrMap, payloadHash);

            HeaderList headers;
            headers.add("Authorization: " + authHeader);
            for (const auto& [k, v] : hdrMap) headers.add(k + ": " + v);

            std::string response;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.list);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToString);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            const CURLcode res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            if (res != CURLE_OK) {
                log::Registry::cloud()->error("[S3Provider] listObjects failed: CURL={} Response:\n{}",
                                            res, response);
                break;
            }

            // Append raw XML as UTF-8
            fullXmlResponse += std::u8string(reinterpret_cast<const char8_t*>(response.data()), response.size());

            parsePagination(response, continuationToken, moreResults);
        }

        return fullXmlResponse;
    }

    std::pair<std::string, std::string> Controller::constructPaths(CURL* curl, const fs::path& p, const std::string& query) const {
        const auto escapedKey = escapeKeyPreserveSlashes(curl, p);
        const auto canonicalPath = "/" + bucket_ + "/" + escapedKey + query;
        const auto url = apiKey_->endpoint + canonicalPath;
        return {canonicalPath, url};
    }
}
