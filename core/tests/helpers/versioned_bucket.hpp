#pragma once

// An in-memory S3 bucket with S3's versioning semantics, behind the real storage::s3::Controller (file recovery,
// .claude/context/recovery.md). Restore, backlog replay and smart-cache tests build on it, so it is meant to behave
// like AWS S3 where Vaulthalla can observe the difference, and it is DB-free.
//
// What is real: Controller::recordRequest (the protection guard, the engine-wide request budget, every
// ScopedS3RequestUsageCapture on the thread) runs for every request before the fake answers, exactly like the
// network paths, so budgets/captures/locks refuse a request before it "reaches" the bucket. streamObject is the
// production code (metering, status mapping, Range/If-Match) over the fake transportGet. uploadLargeObject is the
// production code over the fake multipart calls (so it meters initiate + parts + complete as Put).
//
// Semantics (as S3):
//   Versioning::Unversioned  every write replaces the key's only version, whose id is "null"; DeleteObject removes it.
//   Versioning::Enabled      every write (PUT, multipart complete, CopyObject, metadata REPLACE) pushes a new version
//                            with a fresh id; DeleteObject pushes a delete marker (even for a key that doesn't exist).
//                            Versions written before enabling keep the id "null".
//   Versioning::Suspended    a write replaces the "null" version (if any) and becomes the latest with id "null";
//                            DeleteObject replaces the "null" version with a delete marker whose id is "null".
//   A key whose latest version is a delete marker is absent: HEAD/GET 404, not in ListObjectsV2, but listed by
//   ListObjectVersions. HEAD/GET ?versionId= of a delete marker answer 405 (headObjectVersion: delete_marker=true;
//   streamObject: ObjectNotFound). Version ids look like AWS ids and contain '+', '/' and '=' ("null" aside).
//   ETags are quoted and content-derived (same bytes → same ETag; multipart: "<hash>-<parts>"); a CopyObject keeps
//   the source's ETag, body and user metadata (directive COPY) and takes x-amz-storage-class from the request.
//   Copying a key's current version onto itself without a storage-class change is refused (400) like AWS.
//
// Knobs:
//   setVersioning(mode)            switch modes at any time (existing versions are kept, as S3 does).
//   failNext(op, failure, n)       the next n requests of `op` (Op::Any = any kind) fail *after* being metered (a
//                                  failed request still costs a request): Failure::Transport (connection error),
//                                  Failure::Http503 (SlowDown), Failure::ErrorAfter200 (copy/complete only: a 200
//                                  whose body is an <Error>; other ops treat it as a 500).
//   setRequestBudget / ScopedS3RequestUsageCapture / upstream::guard::setForTesting
//                                  the real budget, capture and protection paths (refusal before any fake effect).
//   failHeads / blockHeads / failPuts   the sync_conflict_harness FakeBucket knobs, same behaviour.
//   setNow(t) / advance(s)         the clock writes stamp LastModified with; every mutation then ticks it by 1 s
//                                  (autoTick) so versions have strictly increasing timestamps.
// Seeding and inspection never meter: seed(), seedDeleteMarker(), purgeVersion(), history(), current(), version().
// Counters: counters() = what reached the bucket per kind, plus body_gets (GET requests that delivered object bytes)
// and bytes_served, so "listed/headed without downloading" is assertable as body_gets == 0.
// lastPutOutcome(): every PUT path (incl. copy and multipart complete) records {etag, version_id} like the real one
// (version_id absent while Unversioned, "null" while Suspended).

#include "storage/s3/Controller.hpp"
#include "storage/s3/curl/Http.hpp"
#include "vault/model/APIKey.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace vh::test_support::versioned {

enum class Versioning { Unversioned, Enabled, Suspended };

inline std::shared_ptr<vault::model::APIKey> versionedBucketKey() {
    return std::make_shared<vault::model::APIKey>(1, "versioned-fake", vault::model::S3Provider::AWS,
                                                  "AKIAVERSIONEDFAKE000", "versioned-fake-secret-0000000000000000",
                                                  "us-east-1", "https://s3.us-east-1.amazonaws.com");
}

class VersionedBucket : public storage::s3::Controller {
public:
    using RequestOptions = storage::s3::RequestOptions;
    // The metadata-map overloads stay the base's: they funnel into the RequestOptions overrides below.
    using Controller::initiateMultipartUpload;
    using Controller::uploadBufferWithMetadataConditional;
    using Controller::uploadObjectWithMetadata;

    struct Version {
        std::string version_id;
        std::vector<uint8_t> body;
        std::string etag;                                      // quoted
        std::unordered_map<std::string, std::string> meta;     // user metadata, bare names (vh-iv, content-hash)
        std::optional<std::string> storage_class;              // absent = STANDARD
        std::time_t last_modified{};
        bool delete_marker{};
        std::optional<uint64_t> reported_size;                 // pretend size (e.g. > 5 GiB) without holding bytes

        [[nodiscard]] uint64_t size() const { return reported_size.value_or(body.size()); }
    };

    enum class Op { Any, List, Head, Get, Put, Copy, Delete };
    enum class Failure { Transport, Http503, ErrorAfter200 };

    struct Counters {
        uint64_t list{}, head{}, get{}, put{}, copy{}, del{};
        uint64_t body_gets{};       // GETs that delivered object bytes (streamObject, downloadToBuffer, downloadObject)
        uint64_t bytes_served{};
    };

    explicit VersionedBucket(const Versioning mode = Versioning::Unversioned, std::string bucket = "vh-versioned-bucket",
                             const std::shared_ptr<vault::model::APIKey>& key = versionedBucketKey())
        : Controller(key, std::move(bucket)), mode_(mode) {}

    // ---- configuration -------------------------------------------------------------------------------------------

    void setVersioning(const Versioning mode) {
        std::scoped_lock lock(mutex_);
        mode_ = mode;
    }

    [[nodiscard]] Versioning versioning() const {
        std::scoped_lock lock(mutex_);
        return mode_;
    }

    void setNow(const std::time_t now) {
        std::scoped_lock lock(mutex_);
        now_ = now;
    }

    void advance(const std::time_t seconds) {
        std::scoped_lock lock(mutex_);
        now_ += seconds;
    }

    [[nodiscard]] std::time_t now() const {
        std::scoped_lock lock(mutex_);
        return now_;
    }

    std::atomic<bool> autoTick{true};

    void failNext(const Op op, const Failure failure, const unsigned times = 1) {
        std::scoped_lock lock(mutex_);
        for (unsigned i = 0; i < times; ++i) failures_.push_back({op, failure});
    }

    void clearFailures() {
        std::scoped_lock lock(mutex_);
        failures_.clear();
    }

    // sync_conflict_harness FakeBucket compatible knobs.
    std::atomic<bool> failHeads{false};    // getHeadObject answers like an outage (HTTP 503, nullopt)
    std::atomic<bool> blockHeads{false};   // getHeadObject blocks until released or the thread's HTTP cancellation
    mutable std::atomic<bool> headEntered{false};
    std::atomic<bool> failPuts{false};     // uploads throw before metering

    // ---- seeding and inspection (never metered) ------------------------------------------------------------------

    // Writes a version as a PUT would (mode semantics apply). Returns its version id.
    std::string seed(const std::string& key, std::vector<uint8_t> body,
                     const std::unordered_map<std::string, std::string>& meta = {},
                     std::optional<std::string> storageClass = std::nullopt,
                     std::optional<uint64_t> reportedSize = std::nullopt) {
        std::scoped_lock lock(mutex_);
        Version v;
        v.body = std::move(body);
        v.etag = etagFor(v.body);
        v.meta = meta;
        v.storage_class = std::move(storageClass);
        v.reported_size = reportedSize;
        return writeLocked(key, std::move(v)).version_id;
    }

    std::string seed(const std::string& key, const std::string& body,
                     const std::unordered_map<std::string, std::string>& meta = {}) {
        return seed(key, std::vector<uint8_t>(body.begin(), body.end()), meta);
    }

    // DeleteObject semantics without metering. Returns the delete marker's id (empty when Unversioned).
    std::string seedDeleteMarker(const std::string& key) {
        std::scoped_lock lock(mutex_);
        return deleteLocked(key);
    }

    // Permanently removes one version (DeleteObject ?versionId=; not a Controller operation).
    bool purgeVersion(const std::string& key, const std::string& versionId) {
        std::scoped_lock lock(mutex_);
        auto it = objects_.find(key);
        if (it == objects_.end()) return false;
        auto& stack = it->second;
        const auto before = stack.size();
        std::erase_if(stack, [&](const Version& v) { return v.version_id == versionId; });
        if (stack.empty()) objects_.erase(it);
        return stack.size() != before;
    }

    // Newest first; empty when the key has no versions.
    [[nodiscard]] std::vector<Version> history(const std::string& key) const {
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key);
        if (it == objects_.end()) return {};
        return {it->second.rbegin(), it->second.rend()};
    }

    // The latest version unless it is a delete marker.
    [[nodiscard]] std::optional<Version> current(const std::string& key) const {
        std::scoped_lock lock(mutex_);
        const auto* v = latestLocked(key);
        if (!v || v->delete_marker) return std::nullopt;
        return *v;
    }

    [[nodiscard]] std::optional<Version> version(const std::string& key, const std::string& versionId) const {
        std::scoped_lock lock(mutex_);
        const auto* v = findLocked(key, versionId);
        if (!v) return std::nullopt;
        return *v;
    }

    [[nodiscard]] std::vector<std::string> keys() const {
        std::scoped_lock lock(mutex_);
        std::vector<std::string> out;
        for (const auto& [key, stack] : objects_) out.push_back(key);
        return out;
    }

    [[nodiscard]] Counters counters() const {
        std::scoped_lock lock(mutex_);
        return counters_;
    }

    void resetCounters() {
        std::scoped_lock lock(mutex_);
        counters_ = {};
    }

    [[nodiscard]] unsigned puts() const { return static_cast<unsigned>(counters().put); }
    [[nodiscard]] unsigned heads() const { return static_cast<unsigned>(counters().head); }

    // ---- uploads ---------------------------------------------------------------------------------------------------

    void uploadObjectWithMetadata(const std::filesystem::path& key, const std::filesystem::path& file,
                                  const RequestOptions& options) const override {
        resetLastPutOutcome();
        if (failPuts.load()) throw std::runtime_error("upload refused (test)");
        std::ifstream in(file, std::ios::binary);
        if (!in) throw std::runtime_error("Failed to open file for upload: " + file.string());
        std::vector<uint8_t> body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        recordRequest(RequestKind::Put);
        recordUploadBytes(body.size());
        putVersion(key.string(), std::move(body), options, std::nullopt, std::nullopt);
    }

    void uploadBufferWithMetadataConditional(const std::filesystem::path& key, const std::vector<uint8_t>& buffer,
                                             const RequestOptions& options, const std::optional<std::string>& ifMatch,
                                             const std::optional<std::string>& ifNoneMatch) const override {
        resetLastPutOutcome();
        if (failPuts.load()) throw std::runtime_error("upload refused (test)");
        recordRequest(RequestKind::Put);
        recordUploadBytes(buffer.size());
        putVersion(key.string(), buffer, options, ifMatch, ifNoneMatch);
    }

    std::string initiateMultipartUpload(const std::filesystem::path& key, const RequestOptions& options) const override {
        if (failPuts.load()) throw std::runtime_error("upload refused (test)");
        recordRequest(RequestKind::Put);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Put);
        ++counters_.put;
        const auto id = fmt::format("upload-{}", ++uploadSeq_);
        uploads_[id] = Upload{key.string(), options, {}};
        return id;
    }

    void uploadPart(const std::filesystem::path& key, const std::string& uploadId, const int partNumber,
                    const std::string& partData, std::string& etagOut) const override {
        recordRequest(RequestKind::Put);
        recordUploadBytes(partData.size());
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Put);
        ++counters_.put;
        const auto it = uploads_.find(uploadId);
        if (it == uploads_.end() || it->second.key != key.string())
            throw std::runtime_error("NoSuchUpload " + uploadId);
        it->second.parts[partNumber] = std::vector<uint8_t>(partData.begin(), partData.end());
        etagOut = etagFor(it->second.parts[partNumber]);
    }

    void completeMultipartUpload(const std::filesystem::path& key, const std::string& uploadId,
                                 const std::vector<std::string>& etags) const override {
        resetLastPutOutcome();
        if (etags.empty()) throw std::runtime_error("No ETags provided to completeMultipartUpload");
        recordRequest(RequestKind::Put);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Put, true);
        ++counters_.put;
        const auto it = uploads_.find(uploadId);
        if (it == uploads_.end() || it->second.key != key.string())
            throw std::runtime_error("NoSuchUpload " + uploadId);
        Version v;
        for (const auto& [n, part] : it->second.parts) v.body.insert(v.body.end(), part.begin(), part.end());
        v.etag = etagFor(v.body, it->second.parts.size());
        v.meta = it->second.options.metadata;
        v.storage_class = storageClassOf(it->second.options);
        uploads_.erase(it);
        const auto& written = writeLocked(key.string(), std::move(v));
        recordPutOutcomeForTesting({.etag = written.etag, .version_id = outcomeIdLocked(written)});
    }

    void abortMultipartUpload(const std::filesystem::path&, const std::string& uploadId) const override {
        recordRequest(RequestKind::Delete);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Delete);
        ++counters_.del;
        uploads_.erase(uploadId);
    }

    // ---- reads -----------------------------------------------------------------------------------------------------

    void downloadToBuffer(const std::filesystem::path& key, std::vector<uint8_t>& out) const override {
        recordRequest(RequestKind::Get);
        std::vector<uint8_t> body;
        {
            std::scoped_lock lock(mutex_);
            failIfInjectedLocked(Op::Get);
            ++counters_.get;
            const auto* v = latestLocked(key.string());
            if (!v || v->delete_marker) throw storage::s3::ObjectNotFound("no such key: " + key.string());
            body = v->body;
        }
        recordRequest(RequestKind::DownloadBytes, body.size());
        {
            std::scoped_lock lock(mutex_);
            ++counters_.body_gets;
            counters_.bytes_served += body.size();
        }
        out = std::move(body);
    }

    void downloadObject(const std::filesystem::path& key, const std::filesystem::path& outputPath) const override {
        std::vector<uint8_t> body;
        downloadToBuffer(key, body);
        std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
    }

    std::optional<std::unordered_map<std::string, std::string>> getHeadObject(const std::filesystem::path& key) const override {
        if (blockHeads.load()) {
            headEntered = true;
            while (blockHeads.load() && !storage::s3::curl::http::cancellationRequested())
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            recordHeadOutcomeForTesting({.performed = true, .transport_ok = false, .http_status = 0});
            return std::nullopt;
        }
        if (failHeads.load()) {
            recordHeadOutcomeForTesting({.performed = true, .transport_ok = true, .http_status = 503});
            return std::nullopt;
        }
        recordRequest(RequestKind::Head);
        std::scoped_lock lock(mutex_);
        ++counters_.head;
        if (const auto failure = takeFailureLocked(Op::Head)) {
            recordHeadOutcomeForTesting({.performed = true, .transport_ok = *failure != Failure::Transport,
                                         .http_status = *failure == Failure::Transport ? 0L : 503L});
            return std::nullopt;
        }
        const auto* v = latestLocked(key.string());
        if (!v || v->delete_marker) {
            recordHeadOutcomeForTesting({.performed = true, .transport_ok = true, .http_status = 404});
            return std::nullopt;
        }
        recordHeadOutcomeForTesting({.performed = true, .transport_ok = true, .http_status = 200});
        std::unordered_map<std::string, std::string> headers{
            {"ETag", v->etag},
            {"Content-Length", std::to_string(v->size())},
            {"Last-Modified", httpDate(v->last_modified)},
        };
        if (mode_ != Versioning::Unversioned) headers["x-amz-version-id"] = v->version_id;
        if (v->storage_class) headers["x-amz-storage-class"] = *v->storage_class;
        for (const auto& [name, value] : v->meta) headers["x-amz-meta-" + name] = value;
        return headers;
    }

    std::optional<storage::s3::ObjectVersionHead> headObjectVersion(const std::string& key,
                                                                    const std::string& versionId) const override {
        if (versionId.empty()) throw std::invalid_argument("S3 version id is empty for " + key);
        recordRequest(RequestKind::Head);
        std::scoped_lock lock(mutex_);
        ++counters_.head;
        if (const auto failure = takeFailureLocked(Op::Head)) {
            const bool transport = *failure == Failure::Transport;
            recordHeadOutcomeForTesting({.performed = true, .transport_ok = !transport, .http_status = transport ? 0L : 503L});
            throw std::runtime_error(transport ? "S3 HEAD failed: transport (test)" : "S3 HEAD failed (HTTP 503 SlowDown)");
        }
        const auto* v = findLocked(key, versionId);
        if (!v) {
            recordHeadOutcomeForTesting({.performed = true, .transport_ok = true, .http_status = 404});
            return std::nullopt;
        }
        recordHeadOutcomeForTesting({.performed = true, .transport_ok = true, .http_status = v->delete_marker ? 405L : 200L});
        storage::s3::ObjectVersionHead head;
        head.version_id = v->version_id;
        head.last_modified = v->last_modified;
        head.delete_marker = v->delete_marker;
        if (v->delete_marker) return head;
        head.etag = v->etag;
        head.content_length = v->size();
        head.storage_class = v->storage_class;
        head.metadata = v->meta;
        return head;
    }

    // ---- listings --------------------------------------------------------------------------------------------------

    std::u8string listObjects(const std::filesystem::path& prefix) const override {
        const auto p = prefix.string();
        std::vector<std::pair<std::string, Version>> live;
        {
            std::scoped_lock lock(mutex_);
            for (const auto& [key, stack] : objects_)
                if (key.starts_with(p) && !stack.back().delete_marker) live.emplace_back(key, stack.back());
        }
        // ListObjectsV2 pages of 1000: one metered LIST per page, like the real loop.
        const auto pages = std::max<std::size_t>(1, (live.size() + 999) / 1000);
        for (std::size_t i = 0; i < pages; ++i) {
            recordRequest(RequestKind::List);
            std::scoped_lock lock(mutex_);
            failIfInjectedLocked(Op::List);
            ++counters_.list;
        }
        std::string xml = "<ListBucketResult>";
        for (const auto& [key, v] : live) {
            xml += "<Contents><Key>" + xmlEscape(key) + "</Key><LastModified>" + isoTime(v.last_modified) +
                   "</LastModified><ETag>" + xmlEscape(v.etag) + "</ETag><Size>" + std::to_string(v.size()) +
                   "</Size><StorageClass>" + v.storage_class.value_or("STANDARD") + "</StorageClass></Contents>";
        }
        xml += "</ListBucketResult>";
        return {reinterpret_cast<const char8_t*>(xml.data()), xml.size()};
    }

    storage::s3::ObjectKeyPage listObjectKeysPage(const std::string& continuationToken,
                                                  const unsigned int maxKeys) const override {
        recordRequest(RequestKind::List);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::List);
        ++counters_.list;
        storage::s3::ObjectKeyPage page;
        const auto limit = std::clamp(maxKeys, 1u, 1000u);
        auto it = continuationToken.empty() ? objects_.begin() : objects_.upper_bound(continuationToken);
        for (; it != objects_.end(); ++it) {
            if (it->second.back().delete_marker) continue;
            if (page.keys.size() == limit) {
                page.next_continuation_token = page.keys.back();
                break;
            }
            page.keys.push_back(it->first);
        }
        return page;
    }

    // Default arguments repeat the base's (they are not inherited by overrides).
    storage::s3::ObjectVersionPage listObjectVersionsPage(const std::string& prefix, const std::string& keyMarker = {},
                                                          const std::string& versionIdMarker = {},
                                                          const unsigned int maxKeys = 1000) const override {
        if (!versionIdMarker.empty() && keyMarker.empty())
            throw std::invalid_argument("ListObjectVersions: a version-id-marker needs a key-marker");
        recordRequest(RequestKind::List);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::List);
        ++counters_.list;

        storage::s3::ObjectVersionPage page;
        const auto limit = std::clamp(maxKeys, 1u, 1000u);
        // Without a version-id-marker the listing starts after every version of keyMarker; with one, after that
        // version of keyMarker (S3 semantics).
        auto it = keyMarker.empty() ? objects_.begin()
                                    : (versionIdMarker.empty() ? objects_.upper_bound(keyMarker)
                                                               : objects_.lower_bound(keyMarker));
        bool skipping = !versionIdMarker.empty();
        for (; it != objects_.end(); ++it) {
            if (!it->first.starts_with(prefix)) continue;
            const auto& stack = it->second;
            for (auto v = stack.rbegin(); v != stack.rend(); ++v) {
                if (skipping) {
                    if (it->first != keyMarker) skipping = false;
                    else {
                        if (v->version_id == versionIdMarker) skipping = false;
                        continue;
                    }
                }
                if (page.versions.size() == limit) {
                    const auto& last = page.versions.back();
                    page.truncated = true;
                    page.next_key_marker = last.key;
                    page.next_version_id_marker = last.version_id;
                    return page;
                }
                storage::s3::ObjectVersionInfo info;
                info.key = it->first;
                info.version_id = v->version_id;
                info.is_latest = v == stack.rbegin();
                info.last_modified = v->last_modified;
                info.delete_marker = v->delete_marker;
                if (!v->delete_marker) {
                    info.etag = v->etag;
                    info.size = v->size();
                    info.storage_class = v->storage_class.value_or("STANDARD");
                }
                page.versions.push_back(std::move(info));
            }
        }
        return page;
    }

    bool isBucketEmpty() const override {
        recordRequest(RequestKind::List);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::List);
        ++counters_.list;
        return std::ranges::none_of(objects_, [](const auto& kv) { return !kv.second.back().delete_marker; });
    }

    storage::s3::ValidateResult validateAPICredentials() const override { return {true, "fake"}; }

    // ---- copy and delete -------------------------------------------------------------------------------------------

    storage::s3::CopyResult copyObjectVersion(const std::string& sourceKey, const std::string& sourceVersionId,
                                              const std::string& destKey, const uint64_t sourceSize,
                                              const RequestOptions& options,
                                              const std::optional<std::string>& ifSourceMatchEtag = std::nullopt) const override {
        resetLastPutOutcome();
        if (sourceVersionId.empty()) throw std::invalid_argument("S3 version id is empty for " + sourceKey);
        if (sourceSize > MAX_SINGLE_COPY_BYTES)
            throw storage::s3::ObjectTooLargeForCopy(fmt::format("{}@{} is {} bytes", sourceKey, sourceVersionId, sourceSize));
        recordRequest(RequestKind::Copy);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Copy, true);
        ++counters_.copy;
        const auto* src = findLocked(sourceKey, sourceVersionId);
        if (!src) throw storage::s3::ObjectNotFound(fmt::format("NoSuchVersion {}@{}", sourceKey, sourceVersionId));
        if (src->delete_marker)
            throw std::runtime_error("S3 copy failed (HTTP 400 InvalidRequest): the source is a delete marker");
        if (ifSourceMatchEtag && *ifSourceMatchEtag != src->etag)
            throw storage::s3::ConditionalRequestFailed("S3 copy source no longer matches " + *ifSourceMatchEtag);
        const auto storageClass = storageClassOf(options);
        const auto* latest = latestLocked(destKey);
        if (sourceKey == destKey && latest == src && (!storageClass || storageClass == src->storage_class))
            throw std::runtime_error("S3 copy failed (HTTP 400 InvalidRequest): copying an object to itself without "
                                     "changing its metadata, storage class or encryption");
        Version v;
        v.body = src->body;
        v.etag = src->etag;
        v.meta = src->meta;
        v.storage_class = storageClass ? storageClass : src->storage_class;
        v.reported_size = src->reported_size;
        const auto& written = writeLocked(destKey, std::move(v));
        storage::s3::CopyResult result{.etag = written.etag, .version_id = outcomeIdLocked(written)};
        recordPutOutcomeForTesting({.etag = result.etag, .version_id = result.version_id});
        return result;
    }

    void setObjectContentHash(const std::filesystem::path& key, const std::string& hash,
                              const RequestOptions& options) const override {
        replaceMetadata(key.string(), {{"content-hash", hash}}, options);
    }

    void setObjectEncryptionMetadata(const std::string& key, const std::string& iv_b64, const unsigned int keyVersion,
                                     const RequestOptions& options) const override {
        replaceMetadata(key, {{"vh-encrypted", "true"}, {"vh-iv", iv_b64}, {"vh-algo", "aes256gcm"},
                              {"vh-key-version", std::to_string(keyVersion)}}, options);
    }

    void deleteObject(const std::filesystem::path& key) const override {
        recordRequest(RequestKind::Delete);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Delete);
        ++counters_.del;
        deleteLocked(key.string());
    }

protected:
    TransportResponse transportGet(const std::filesystem::path& key, const std::optional<std::string>& versionId,
                                   const std::map<std::string, std::string>& extraHeaders,
                                   const TransportBodyFn& onBody) const override {
        TransportResponse response;
        std::vector<uint8_t> bytes;
        std::string etag;
        long status = 200;
        {
            std::scoped_lock lock(mutex_);
            ++counters_.get;
            if (const auto failure = takeFailureLocked(Op::Get)) {
                if (*failure == Failure::Transport) {
                    response.transport_ok = false;
                    response.transport_error = "connection reset (test)";
                    return response;
                }
                return deliver(503, "<Error><Code>SlowDown</Code></Error>", onBody);
            }
            const auto* v = versionId ? findLocked(key.string(), *versionId) : latestLocked(key.string());
            if (!v) return deliver(404, versionId ? "<Error><Code>NoSuchVersion</Code></Error>"
                                                  : "<Error><Code>NoSuchKey</Code></Error>", onBody);
            if (v->delete_marker) {
                response = versionId ? deliver(405, "<Error><Code>MethodNotAllowed</Code></Error>", onBody)
                                     : deliver(404, "<Error><Code>NoSuchKey</Code></Error>", onBody);
                response.headers += "x-amz-delete-marker: true\r\n";
                return response;
            }
            if (const auto it = extraHeaders.find("if-match"); it != extraHeaders.end() && it->second != v->etag)
                return deliver(412, "<Error><Code>PreconditionFailed</Code></Error>", onBody);
            etag = v->etag;
            bytes = v->body;
            if (const auto it = extraHeaders.find("range"); it != extraHeaders.end()) {
                const auto spec = it->second.substr(std::string("bytes=").size());
                const auto dash = spec.find('-');
                const auto first = std::stoull(spec.substr(0, dash));
                auto last = std::stoull(spec.substr(dash + 1));
                if (first >= bytes.size()) return deliver(416, "", onBody);
                last = std::min<uint64_t>(last, bytes.size() - 1);
                bytes = {bytes.begin() + static_cast<std::ptrdiff_t>(first),
                         bytes.begin() + static_cast<std::ptrdiff_t>(last + 1)};
                status = 206;
            }
            if (mode_ != Versioning::Unversioned) response.headers += "x-amz-version-id: " + v->version_id + "\r\n";
            ++counters_.body_gets;
            counters_.bytes_served += bytes.size();
        }
        response.http_status = status;
        response.headers += "ETag: " + etag + "\r\n";
        constexpr std::size_t chunk = 16 * 1024;
        for (std::size_t off = 0; off < bytes.size(); off += chunk) {
            const auto n = std::min(chunk, bytes.size() - off);
            if (!onBody(status, {bytes.data() + off, n})) {
                response.transport_ok = false;
                response.transport_error = "aborted";
                break;
            }
        }
        return response;
    }

private:
    struct Upload {
        std::string key;
        RequestOptions options;
        std::map<int, std::vector<uint8_t>> parts;
    };

    struct InjectedFailure {
        Op op;
        Failure failure;
    };

    static TransportResponse deliver(const long status, const std::string& body, const TransportBodyFn& onBody) {
        TransportResponse response;
        response.http_status = status;
        if (!body.empty() && !onBody(status, {reinterpret_cast<const uint8_t*>(body.data()), body.size()})) {
            response.transport_ok = false;
            response.transport_error = "aborted";
        }
        return response;
    }

    static std::string etagFor(const std::vector<uint8_t>& body, const std::size_t parts = 0) {
        // Two FNV-1a passes: a 32-hex-digit content ETag shaped like S3's MD5.
        uint64_t a = 0xcbf29ce484222325ULL, b = 0x84222325cbf29ce4ULL;
        for (const auto byte : body) {
            a = (a ^ byte) * 0x100000001b3ULL;
            b = (b ^ static_cast<uint8_t>(byte + 0x5a)) * 0x100000001b3ULL;
        }
        auto tag = fmt::format("{:016x}{:016x}", a, b);
        if (parts) tag += "-" + std::to_string(parts);
        return "\"" + tag + "\"";
    }

    static std::optional<std::string> storageClassOf(const RequestOptions& options) {
        for (const auto& [name, value] : options.system_headers) {
            std::string lower = name;
            std::ranges::transform(lower, lower.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lower == "x-amz-storage-class" && value != "STANDARD") return value;
        }
        return std::nullopt;
    }

    static std::string isoTime(const std::time_t t) {
        std::tm tm{};
        gmtime_r(&t, &tm);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000Z", &tm);
        return buf;
    }

    static std::string httpDate(const std::time_t t) {
        static constexpr const char* kDays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        static constexpr const char* kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        std::tm tm{};
        gmtime_r(&t, &tm);
        return fmt::format("{}, {:02d} {} {} {:02d}:{:02d}:{:02d} GMT", kDays[tm.tm_wday], tm.tm_mday, kMonths[tm.tm_mon],
                           tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    }

    static std::string xmlEscape(const std::string& s) {
        std::string out;
        for (const char c : s) {
            switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out.push_back(c);
            }
        }
        return out;
    }

    std::string newVersionIdLocked() const {
        // Shaped like AWS ids, including the characters that need percent-encoding.
        const auto n = ++versionSeq_;
        return fmt::format("Vh{:06d}+fake/ver={:x}", n, static_cast<uint32_t>(n * 2654435761u));
    }

    std::time_t stampLocked() const {
        const auto t = now_;
        if (autoTick.load()) ++now_;
        return t;
    }

    const Version* latestLocked(const std::string& key) const {
        const auto it = objects_.find(key);
        if (it == objects_.end() || it->second.empty()) return nullptr;
        return &it->second.back();
    }

    const Version* findLocked(const std::string& key, const std::string& versionId) const {
        const auto it = objects_.find(key);
        if (it == objects_.end()) return nullptr;
        for (const auto& v : it->second)
            if (v.version_id == versionId) return &v;
        return nullptr;
    }

    std::optional<std::string> outcomeIdLocked(const Version& v) const {
        if (mode_ == Versioning::Unversioned) return std::nullopt;
        return v.version_id;
    }

    // Applies a write with the current mode's semantics; returns the stored version.
    const Version& writeLocked(const std::string& key, Version v) const {
        auto& stack = objects_[key];
        v.last_modified = stampLocked();
        v.delete_marker = false;
        switch (mode_) {
        case Versioning::Unversioned:
            stack.clear();
            v.version_id = "null";
            break;
        case Versioning::Suspended:
            std::erase_if(stack, [](const Version& old) { return old.version_id == "null"; });
            v.version_id = "null";
            break;
        case Versioning::Enabled:
            v.version_id = newVersionIdLocked();
            break;
        }
        stack.push_back(std::move(v));
        return stack.back();
    }

    std::string deleteLocked(const std::string& key) const {
        switch (mode_) {
        case Versioning::Unversioned:
            objects_.erase(key);
            return {};
        case Versioning::Suspended: {
            auto& stack = objects_[key];
            std::erase_if(stack, [](const Version& old) { return old.version_id == "null"; });
            Version marker;
            marker.version_id = "null";
            marker.delete_marker = true;
            marker.last_modified = stampLocked();
            stack.push_back(std::move(marker));
            return "null";
        }
        case Versioning::Enabled: {
            Version marker;
            marker.version_id = newVersionIdLocked();
            marker.delete_marker = true;
            marker.last_modified = stampLocked();
            objects_[key].push_back(marker);
            return marker.version_id;
        }
        }
        return {};
    }

    void putVersion(const std::string& key, std::vector<uint8_t> body, const RequestOptions& options,
                    const std::optional<std::string>& ifMatch, const std::optional<std::string>& ifNoneMatch) const {
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Put);
        ++counters_.put;
        const auto* latest = latestLocked(key);
        const bool exists = latest && !latest->delete_marker;
        if (ifMatch && (!exists || latest->etag != *ifMatch))
            throw storage::s3::ConditionalRequestFailed("Conditional S3 PUT failed (HTTP 412)");
        if (ifNoneMatch && *ifNoneMatch == "*" && exists)
            throw storage::s3::ConditionalRequestFailed("Conditional S3 PUT failed (HTTP 412)");
        Version v;
        v.body = std::move(body);
        v.etag = etagFor(v.body);
        v.meta = options.metadata;
        v.storage_class = storageClassOf(options);
        const auto& written = writeLocked(key, std::move(v));
        recordPutOutcomeForTesting({.etag = written.etag, .version_id = outcomeIdLocked(written)});
    }

    void replaceMetadata(const std::string& key, const std::unordered_map<std::string, std::string>& meta,
                         const RequestOptions& options) const {
        recordRequest(RequestKind::Copy);
        std::scoped_lock lock(mutex_);
        failIfInjectedLocked(Op::Copy);
        ++counters_.copy;
        const auto* latest = latestLocked(key);
        if (!latest || latest->delete_marker) throw storage::s3::ObjectNotFound("no such key: " + key);
        Version v = *latest;
        for (const auto& [name, value] : meta) v.meta[name] = value;
        if (const auto storageClass = storageClassOf(options)) v.storage_class = storageClass;
        writeLocked(key, std::move(v));
    }

    std::optional<Failure> takeFailureLocked(const Op op) const {
        for (auto it = failures_.begin(); it != failures_.end(); ++it) {
            if (it->op == Op::Any || it->op == op) {
                const auto failure = it->failure;
                failures_.erase(it);
                return failure;
            }
        }
        return std::nullopt;
    }

    // Throws the injected failure the way the network paths surface it.
    void failIfInjectedLocked(const Op op, const bool errorBodyAfter200 = false) const {
        const auto failure = takeFailureLocked(op);
        if (!failure) return;
        switch (*failure) {
        case Failure::Transport:
            throw std::runtime_error("S3 request failed: transport (test)");
        case Failure::Http503:
            throw std::runtime_error("S3 request failed (HTTP 503 SlowDown)");
        case Failure::ErrorAfter200:
            throw std::runtime_error(errorBodyAfter200 ? "S3 request failed after HTTP 200 (InternalError)"
                                                       : "S3 request failed (HTTP 500 InternalError)");
        }
    }

    mutable std::mutex mutex_;
    Versioning mode_;
    mutable std::map<std::string, std::vector<Version>> objects_;   // oldest → newest per key
    mutable std::map<std::string, Upload> uploads_;
    mutable std::vector<InjectedFailure> failures_;
    mutable Counters counters_;
    mutable std::time_t now_{1'760'000'000};   // 2025-10-09T08:53:20Z
    mutable uint64_t versionSeq_{0};
    mutable uint64_t uploadSeq_{0};
};

}
