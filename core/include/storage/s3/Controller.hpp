#pragma once

#include "curl/wrappers.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/Fwd.hpp"

#include <atomic>
#include <cstdint>
#include <ctime>
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

    // A CopyObject whose source is larger than one request may copy (5 GiB). Thrown before anything is sent or
    // metered; the caller falls back to a bounded transfer (GET + PUT).
    class ObjectTooLargeForCopy final : public std::runtime_error {
    public:
        explicit ObjectTooLargeForCopy(const std::string& message) : std::runtime_error(message) {}
    };

    // A streamed GET (Controller::streamObject).
    struct GetObjectOptions {
        std::optional<std::pair<uint64_t, uint64_t>> range;  // inclusive byte range, sent as a signed Range header
        std::optional<std::string> if_match;                 // signed If-Match: the bytes come from that version only
        std::optional<uint64_t> max_body_bytes;              // abort once the body would exceed this many bytes
        // GET ?versionId= (signed, percent-encoded): that provider version instead of the current object. A version
        // that is a delete marker or doesn't exist throws ObjectNotFound.
        std::optional<std::string> version_id{};
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

    // ---- provider object versions (file recovery, .claude/context/recovery.md) ------------------------------------

    // One entry of ListObjectVersions: an object version or a delete marker. Values are as the provider reports
    // them: etag keeps its quotes, version_id is "null" for a version written while the bucket was unversioned or
    // suspended, storage_class is absent for delete markers (and where the provider omits it).
    struct ObjectVersionInfo {
        std::string key, version_id, etag;
        uint64_t size{};
        std::optional<std::time_t> last_modified;
        std::optional<std::string> storage_class;
        bool is_latest{};
        bool delete_marker{};
    };

    // One ListObjectVersions page: keys ascending, each key's versions newest first, in provider order. When
    // truncated, the next page starts after (next_key_marker, next_version_id_marker).
    struct ObjectVersionPage {
        std::vector<ObjectVersionInfo> versions;
        std::string next_key_marker, next_version_id_marker;
        bool truncated{};
    };

    // HEAD ?versionId= of one version (metadata only, no body).
    struct ObjectVersionHead {
        std::string version_id, etag;               // etag as sent (quoted)
        uint64_t content_length{};
        std::optional<std::time_t> last_modified;
        std::optional<std::string> storage_class;   // absent = the provider's default (STANDARD on AWS)
        bool delete_marker{};                       // the version is a delete marker (AWS: HTTP 405 + x-amz-delete-marker)
        // x-amz-meta-* user metadata: names lower-cased with the prefix stripped (vh-iv, vh-key-version,
        // vh-encrypted, content-hash, ...).
        std::unordered_map<std::string, std::string> metadata;
    };

    // What a CopyObject produced: the new object's ETag (quoted, from the CopyObjectResult body) and, on a versioned
    // bucket, its version id (x-amz-version-id).
    struct CopyResult {
        std::string etag;
        std::optional<std::string> version_id;
    };

    // What the calling thread's last successful PUT through a Controller produced (uploadObjectWithMetadata, every
    // buffer upload incl. conditional ones, completeMultipartUpload and so uploadLargeObject, copyObjectVersion):
    // the response ETag (as sent, quoted) and x-amz-version-id (absent on an unversioned bucket; "null" on a
    // suspended one where the provider sends it). Each of those calls resets it first, so a failed or aborted PUT
    // leaves it empty.
    struct PutOutcome {
        std::string etag;
        std::optional<std::string> version_id;
    };

    class Controller {
    public:
        static constexpr uintmax_t MIN_PART_SIZE = 5 * 1024 * 1024; // 5 MiB
        // The largest object a single CopyObject request may copy (AWS: 5 GiB); larger ones need UploadPartCopy or
        // a transfer.
        static constexpr uint64_t MAX_SINGLE_COPY_BYTES = 5ULL * 1024 * 1024 * 1024;

        Controller(const std::shared_ptr<vault::model::APIKey> &apiKey, std::string bucket);

        virtual ~Controller();

        virtual void setRequestBudget(const S3RequestBudget& budget) const;
        virtual void clearRequestBudget() const;
        virtual void resetRequestMetrics() const;
        [[nodiscard]] virtual S3RequestMetrics requestMetrics() const;
        // The vault this controller works for: its metered requests also feed that vault's local usage ledger
        // (recovery::usage, vault_upstream_usage_daily; nothing leaves the host). 0 (default) = none.
        void setUsageVault(uint32_t vaultId) noexcept { usageVaultId_.store(vaultId, std::memory_order_relaxed); }
        [[nodiscard]] uint32_t usageVault() const noexcept { return usageVaultId_.load(std::memory_order_relaxed); }

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
        // With options.version_id it GETs that provider version (a delete marker's 405 throws ObjectNotFound).
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

        // The thread's last PUT outcome (see PutOutcome). Fakes that override the PUT paths report theirs through
        // recordPutOutcomeForTesting.
        [[nodiscard]] static PutOutcome lastPutOutcome() noexcept;
        static void resetLastPutOutcome() noexcept;
        static void recordPutOutcomeForTesting(PutOutcome outcome) noexcept;

        // #########################################################################
        // ######################## OBJECT VERSIONS ################################
        // #########################################################################

        // One metered ListObjectVersions request (metadata only, never a body) for keys under prefix, starting after
        // (keyMarker, versionIdMarker); maxKeys is clamped to 1-1000. Never returns a partial page: a transport or
        // HTTP error, an unparsable body, or a truncated page without a next key marker throws. versionIdMarker
        // needs a keyMarker (std::invalid_argument, nothing sent or metered).
        [[nodiscard]] virtual ObjectVersionPage listObjectVersionsPage(const std::string &prefix,
                                                                       const std::string &keyMarker = {},
                                                                       const std::string &versionIdMarker = {},
                                                                       unsigned int maxKeys = 1000) const;

        // One metered HEAD ?versionId=. nullopt only for 404 (no such key/version); a delete marker answers a head
        // with delete_marker=true; anything else that is not a 2xx (400, 403, 5xx, transport) throws, so an outage is
        // never mistaken for absence. Sets lastHeadOutcome like getHeadObject.
        [[nodiscard]] virtual std::optional<ObjectVersionHead> headObjectVersion(const std::string &key,
                                                                                 const std::string &versionId) const;

        // One metered CopyObject of sourceKey@sourceVersionId onto destKey in this bucket, with directive COPY: the
        // source's user metadata (vh-iv, vh-key-version, vh-encrypted, content-hash) carries over unchanged; only
        // options.system_headers are applied (e.g. x-amz-storage-class from RequestOperation::CopyObjectRewrite),
        // never replacement metadata. ifSourceMatchEtag sends x-amz-copy-source-if-match. sourceSize is the
        // source's size (from a HEAD or the version listing): above MAX_SINGLE_COPY_BYTES it throws
        // ObjectTooLargeForCopy before anything is sent or metered. Copying the version that is already current onto
        // its own key is refused by AWS (400); restoring a noncurrent version onto its key is the documented use.
        // Throws ObjectNotFound (404), ConditionalRequestFailed (412), or std::runtime_error (other failures,
        // including an HTTP 200 whose body is an <Error>, which S3 sends when a copy fails after it started).
        // Records the PutOutcome.
        virtual CopyResult copyObjectVersion(const std::string &sourceKey, const std::string &sourceVersionId,
                                             const std::string &destKey, uint64_t sourceSize,
                                             const RequestOptions &options,
                                             const std::optional<std::string> &ifSourceMatchEtag = std::nullopt) const;

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

        // The signed GET behind streamObject; extraHeaders are lower-case and included in the SigV4 signature;
        // versionId (when set) travels as the signed, percent-encoded ?versionId= query.
        // Test seam: fakes override this and keep streamObject's metering and status handling.
        virtual TransportResponse transportGet(const fs::path &key,
                                               const std::optional<std::string> &versionId,
                                               const std::map<std::string, std::string> &extraHeaders,
                                               const TransportBodyFn &onBody) const;

        // A request signed with sigv4::sign: RFC 3986 encoded path, and a sorted, RFC 3986 encoded query that is
        // also exactly what the URL carries, so version ids with '+', '/', '=' sign and travel identically. key
        // empty = the bucket itself. The version-aware ops send these through curl::http (bounded timeouts).
        struct SignedObjectRequest {
            std::string method;
            std::string url;                                          // scheme://host/encoded-path[?canonical-query]
            std::vector<std::pair<std::string, std::string>> headers; // to send: authorization included, host not
            std::string canonical_request;                            // diagnostics and tests; contains no secret
        };
        [[nodiscard]] SignedObjectRequest signObjectRequest(
            const std::string &method, const std::string &key,
            const std::vector<std::pair<std::string, std::string>> &query,
            const std::map<std::string, std::string> &headers,
            const std::string &payloadHash = "UNSIGNED-PAYLOAD") const;

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
        std::atomic<uint32_t> usageVaultId_{0};

        std::pair<std::string, std::string> constructPaths(CURL *curl, const fs::path &p,
                                                           const std::string &query = "") const;

        [[nodiscard]] SList makeSigHeaders(const std::string &method,
                                           const std::string &canonical,
                                           const std::string &payloadHash,
                                           const std::string &query = "") const;

        // Sets the thread's PutOutcome from a successful PUT's raw response headers (ETag, x-amz-version-id);
        // bodyEtag (CompleteMultipartUpload / CopyObject results carry it in XML) wins over the header.
        static void recordPutResponse(const std::string &rawHeaders,
                                      const std::optional<std::string> &bodyEtag = std::nullopt);

    };
}
