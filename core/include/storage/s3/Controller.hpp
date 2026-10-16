#pragma once

#include "curl/wrappers.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/Fwd.hpp"

#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <curl/curl.h>
#include <unordered_map>

namespace vh::storage {
    class ScopedS3RequestUsageCapture;
}

namespace vh::storage::s3 {
    namespace fs = std::filesystem;

    struct ValidateResult {
        bool ok;
        std::string msg;
    };

    struct S3RequestMetrics {
        uint64_t list_requests{};
        uint64_t head_requests{};
        uint64_t get_requests{};
        uint64_t put_requests{};
        uint64_t copy_requests{};
        uint64_t delete_requests{};
        uint64_t downloaded_bytes{};
        uint64_t uploaded_bytes{};
        bool budget_exceeded{};
        std::string budget_exceeded_reason;
    };

    struct S3RequestBudget {
        std::optional<uint64_t> max_list_requests;
        std::optional<uint64_t> max_head_requests;
        std::optional<uint64_t> max_get_requests;
        std::optional<uint64_t> max_put_requests;
        std::optional<uint64_t> max_copy_requests;
        std::optional<uint64_t> max_delete_requests;
        std::optional<uint64_t> max_downloaded_bytes;
    };

    struct RequestOptions {
        std::map<std::string, std::string> system_headers;
        std::unordered_map<std::string, std::string> metadata;
    };

    class RequestBudgetExceeded final : public std::runtime_error {
    public:
        explicit RequestBudgetExceeded(const std::string& message, std::string kind = {})
            : std::runtime_error(message), kind_(std::move(kind)) {}

        [[nodiscard]] const std::string& kind() const noexcept { return kind_; }

    private:
        std::string kind_;
    };

    class ConditionalRequestFailed final : public std::runtime_error {
    public:
        explicit ConditionalRequestFailed(const std::string& message) : std::runtime_error(message) {}
    };

    class ObjectNotFound final : public std::runtime_error {
    public:
        explicit ObjectNotFound(const std::string& message) : std::runtime_error(message) {}
    };

    // A streamed GET (Controller::streamObject).
    struct GetObjectOptions {
        std::optional<std::pair<uint64_t, uint64_t>> range;  // inclusive byte range, sent as a signed Range header
        std::optional<std::string> if_match;                 // signed If-Match: the bytes come from that version only
        std::optional<uint64_t> max_body_bytes;              // abort once the body would exceed this many bytes
    };

    struct GetObjectResult {
        long http_status{};
        uint64_t body_bytes{};
        std::optional<std::string> etag;
        std::optional<std::string> content_range;
    };

    // Receives the body in order; throwing aborts the transfer (the exception propagates from streamObject).
    using BodySink = std::function<void(std::span<const uint8_t>)>;

    // One ListObjectsV2 page (Controller::listObjectKeysPage).
    struct ObjectKeyPage {
        std::vector<std::string> keys;
        std::string next_continuation_token;   // empty on the last page
    };

    class Controller {
    public:
        static constexpr uintmax_t MIN_PART_SIZE = 5 * 1024 * 1024; // 5 MiB

        Controller(const std::shared_ptr<vault::model::APIKey> &apiKey, std::string bucket);

        virtual ~Controller();

        virtual void setRequestBudget(const S3RequestBudget& budget) const;
        virtual void clearRequestBudget() const;
        virtual void resetRequestMetrics() const;
        [[nodiscard]] virtual S3RequestMetrics requestMetrics() const;
        static void pushRequestUsageCapture(ScopedS3RequestUsageCapture* capture);
        static void popRequestUsageCapture(ScopedS3RequestUsageCapture* capture) noexcept;

        // #########################################################################
        // ########################### FILE OPS ####################################
        // #########################################################################

        virtual void uploadLargeObject(const fs::path &key, const fs::path &filePath,
                                       uintmax_t partSize = MIN_PART_SIZE,
                                       const std::unordered_map<std::string, std::string> &metadata = {}) const;

        virtual void uploadLargeObject(const fs::path &key, const fs::path &filePath,
                                       uintmax_t partSize,
                                       const RequestOptions &options) const;

        virtual void uploadObject(const fs::path &key, const fs::path &filePath) const;

        virtual void uploadObjectWithMetadata(
            const fs::path &key,
            const fs::path &filePath,
            const std::unordered_map<std::string, std::string> &metadata) const;

        virtual void uploadObjectWithMetadata(
            const fs::path &key,
            const fs::path &filePath,
            const RequestOptions &options) const;

        virtual void downloadObject(const fs::path &key, const fs::path &outputPath) const;

        // #########################################################################
        // ########################### BUFFER OPS ##################################
        // #########################################################################

        virtual void uploadLargeObject(const fs::path &key, const std::vector<uint8_t> &buffer,
                                       uintmax_t partSize = MIN_PART_SIZE,
                                       const std::unordered_map<std::string, std::string> &metadata = {}) const;

        virtual void uploadLargeObject(const fs::path &key, const std::vector<uint8_t> &buffer,
                                       uintmax_t partSize,
                                       const RequestOptions &options) const;

        virtual void uploadBufferWithMetadata(
            const fs::path &key,
            const std::vector<uint8_t> &buffer,
            const std::unordered_map<std::string, std::string> &metadata) const;

        virtual void uploadBufferWithMetadata(
            const fs::path &key,
            const std::vector<uint8_t> &buffer,
            const RequestOptions &options) const;

        virtual void uploadBufferWithMetadataConditional(
            const fs::path &key,
            const std::vector<uint8_t> &buffer,
            const std::unordered_map<std::string, std::string> &metadata,
            const std::optional<std::string> &ifMatch,
            const std::optional<std::string> &ifNoneMatch = std::nullopt) const;

        virtual void uploadBufferWithMetadataConditional(
            const fs::path &key,
            const std::vector<uint8_t> &buffer,
            const RequestOptions &options,
            const std::optional<std::string> &ifMatch,
            const std::optional<std::string> &ifNoneMatch = std::nullopt) const;

        virtual void downloadToBuffer(const fs::path &key, std::vector<uint8_t> &outBuffer) const;

        // Streams an object, or one byte range of it, into sink without buffering the body. One GET is metered
        // before the request is sent and every received body byte as it arrives (recordRequest: the engine-wide
        // budget plus every active per-thread usage capture), so a refusal happens before any body is fetched or
        // mid-stream. Throws ObjectNotFound (404), ConditionalRequestFailed (412: If-Match no longer matches),
        // RequestBudgetExceeded, or std::runtime_error (transport failure, other HTTP status, a Range the server
        // ignored, or a body over max_body_bytes).
        GetObjectResult streamObject(const fs::path &key, const GetObjectOptions &options, const BodySink &sink) const;

        // #########################################################################
        // ######################## MULTIPART UPLOADS ##############################
        // #########################################################################

        [[nodiscard]] virtual std::string initiateMultipartUpload(
            const fs::path &key,
            const std::unordered_map<std::string, std::string> &metadata = {}) const;

        [[nodiscard]] virtual std::string initiateMultipartUpload(
            const fs::path &key,
            const RequestOptions &options) const;

        virtual void uploadPart(const fs::path &key, const std::string &uploadId,
                        int partNumber, const std::string &partData, std::string &etagOut) const;

        virtual void completeMultipartUpload(const fs::path &key, const std::string &uploadId,
                                     const std::vector<std::string> &etags) const;

        virtual void abortMultipartUpload(const fs::path &key, const std::string &uploadId) const;

        // #########################################################################
        // ######################## METADATA & TAGS ################################
        // #########################################################################

        [[nodiscard]] virtual std::optional<std::unordered_map<std::string, std::string> > getHeadObject(
            const fs::path &key) const;

        // What the calling thread's last HEAD through this class's network path answered. getHeadObject returns
        // nullopt for a 404 and for every failure alike; callers that must not mistake an outage for a deletion
        // (event removals, #96) check this. Test fakes that override getHeadObject never set it (performed=false).
        struct HeadOutcome {
            bool performed = false;
            bool transport_ok = false;
            long http_status = 0;
        };
        static void resetLastHeadOutcome() noexcept;
        [[nodiscard]] static HeadOutcome lastHeadOutcome() noexcept;
        // Fakes that override getHeadObject report what their "network" answered (e.g. a 503).
        static void recordHeadOutcomeForTesting(HeadOutcome outcome) noexcept;

        virtual void setObjectContentHash(const fs::path &key, const std::string &hash,
                                          const RequestOptions &options = {}) const;

        virtual void setObjectEncryptionMetadata(const std::string &key, const std::string &iv_b64,
                                         unsigned int key_version,
                                         const RequestOptions &options = {}) const;

        // #########################################################################
        // ########################### VALIDATION ##################################
        // #########################################################################

        [[nodiscard]] virtual ValidateResult validateAPICredentials() const;

        [[nodiscard]] virtual bool isBucketEmpty() const;

        // #########################################################################
        // ############################### GENERAL #################################
        // #########################################################################

        virtual void deleteObject(const fs::path &key) const;

        [[nodiscard]] virtual std::u8string listObjects(const fs::path &prefix = {}) const;

        // One metered ListObjectsV2 request: up to maxKeys (1-1000) keys from the start of the bucket, or after
        // continuationToken. Unlike listObjects it never returns a partial listing: a transport or HTTP error throws.
        [[nodiscard]] virtual ObjectKeyPage listObjectKeysPage(const std::string &continuationToken = {},
                                                               unsigned int maxKeys = 1000) const;

    protected:
        struct TransportResponse {
            bool transport_ok{true};
            std::string transport_error;
            long http_status{};
            std::string headers;  // raw response header lines
        };

        // (HTTP status, body bytes) -> false aborts the transfer.
        using TransportBodyFn = std::function<bool(long, std::span<const uint8_t>)>;

        // The signed GET behind streamObject; extraHeaders are lower-case and included in the SigV4 signature.
        // Test seam: fakes override this and keep streamObject's metering and status handling.
        virtual TransportResponse transportGet(const fs::path &key,
                                               const std::map<std::string, std::string> &extraHeaders,
                                               const TransportBodyFn &onBody) const;

        enum class RequestKind { List, Head, Get, Put, Copy, Delete, DownloadBytes };
        void recordRequest(RequestKind kind, uint64_t amount = 1) const;
        void recordUploadBytes(uint64_t amount) const;
        [[nodiscard]] std::map<std::string, std::string> buildHeaderMap(const std::string &payloadHash) const;
        static void applyRequestOptions(std::map<std::string, std::string>& headers,
                                        const RequestOptions& options,
                                        bool includeMetadata = true);

    private:
        std::shared_ptr<vault::model::APIKey> apiKey_;
        std::string bucket_;
        // Who this controller talks to, for the protection guard (#237): checked before every metered request.
        upstream::BucketIdentity identity_;
        mutable std::mutex metricsMutex_;
        mutable S3RequestMetrics metrics_;
        mutable std::optional<S3RequestBudget> requestBudget_;

        std::pair<std::string, std::string> constructPaths(CURL *curl, const fs::path &p,
                                                           const std::string &query = "") const;

        [[nodiscard]] SList makeSigHeaders(const std::string &method,
                                           const std::string &canonical,
                                           const std::string &payloadHash,
                                           const std::string &query = "") const;

    };
}
