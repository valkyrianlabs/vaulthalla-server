#pragma once

// An in-memory provider account for the upstream control-plane tests (#237): FakeAdmin implements the AdminClient
// interface over FakeCloud, which every client the admin factory hands out shares. Installed through
// storage::s3::provider::admin::setFactoryForTesting. Shared by test_upstream_ops.cpp and test_ops_parity_upstream.cpp.

#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace vh::test_support::upstream_admin {

namespace padmin = storage::s3::provider::admin;

constexpr const char* kAccount = "123456789012";

// One provider account in memory, shared by every client the factory hands out.
struct FakeCloud {
    struct Bucket {
        std::map<std::string, uint64_t> objects;
        // Non-current versions and delete markers (B2 hide markers): ListObjectVersions shows them, ListObjectsV2
        // doesn't, and a bucket that holds any of them isn't empty. Only on a provider with versioning.
        std::vector<padmin::ObjectSummary> history;
        std::vector<padmin::LifecycleRule> lifecycle;
        std::string region{"us-east-2"};
        std::set<std::string> locked;   // deletes of these fail (object lock)
        // Provider versioning: what the bucket is, what reads still say while a change propagates.
        padmin::Versioning versioning{padmin::Versioning::Unversioned};
        padmin::Versioning previousVersioning{padmin::Versioning::Unversioned};
        unsigned staleVersioningReads = 0;   // reads left that still answer previousVersioning
        bool objectLock = false;             // Object Lock: versioning Enabled and can't be suspended
        std::optional<bool> mfaDelete;       // MfaDelete as GetBucketVersioning reports it
    };

    std::mutex mutex;
    std::map<std::string, Bucket> buckets;
    std::set<std::string> otherAccount;   // HeadBucket 403
    std::set<std::string> takenElsewhere; // HeadBucket says absent, CreateBucket answers BucketAlreadyExists: another
                                          // account holds the name and this credential can't see its bucket
    std::set<std::string> hiddenFromHead; // HeadBucket says absent although it exists (race / us-east-1 create)
    bool silentCreate = false;            // CreateBucket on an existing bucket answers 200 (AWS us-east-1)
    std::set<std::string> headFails;      // HeadBucket fails transiently (503 SlowDown)
    int deleteObjectsFailAfter = -1;      // >= 0: DeleteObjects throws (503) once this many batches went through
    // Called (without the lock) before every DeleteObjects batch: lets a test act while a cleanup is running.
    std::function<void(const std::string&)> beforeDeleteObjects;
    std::map<std::string, unsigned> bucketCalls;
    unsigned calls = 0, deleteBucketCalls = 0;

    // Read-only keys for vault read grants (B2's b2_create_key / b2_delete_key in the real adapter).
    bool readKeysSupported = true;
    bool writeKeysMissing = false;           // the account key may not create keys (CapabilityMissing("writeKeys"))
    bool createReadKeyFails = false;         // b2_create_key answers 503
    bool deleteReadKeyFails = false;         // b2_delete_key answers 500
    std::map<std::string, padmin::ReadKeyRequest> readKeys;   // key id -> what it was created for (live keys)
    std::vector<padmin::ReadKeyRequest> readKeyRequests;      // every createReadKey, accepted or not
    std::vector<std::string> deleteReadKeyCalls;
    unsigned readKeySeq = 0;

    // Provider versioning. false = an R2-like provider (Unversioned, PutBucketVersioning refused locally).
    bool versioningSupported = true;
    std::set<std::string> putVersioningDenied;   // PutBucketVersioning answers 403 AccessDenied
    std::set<std::string> getVersioningDenied;   // GetBucketVersioning answers 403 AccessDenied
    // Eventual consistency: after a PutBucketVersioning, this many reads (versioning()/inspect) still see the old state.
    unsigned staleReadsAfterPut = 0;
    std::vector<std::pair<std::string, padmin::Versioning>> putVersioningCalls;   // (bucket, target), accepted or not
    unsigned getVersioningCalls = 0;

    // The status a read sees now (consumes one stale read). Caller holds the mutex.
    static padmin::Versioning readVersioning(Bucket& b) {
        if (b.staleVersioningReads > 0) {
            --b.staleVersioningReads;
            return b.previousVersioning;
        }
        return b.versioning;
    }

    void touch(const std::string& bucket) {
        ++calls;
        if (!bucket.empty()) ++bucketCalls[bucket];
    }
};

class FakeAdmin final : public padmin::AdminClient {
public:
    explicit FakeAdmin(std::shared_ptr<FakeCloud> cloud) : c_(std::move(cloud)) {}

    std::string providerId() const override { return "aws-s3"; }
    padmin::AccountIdentity identity() override {
        std::scoped_lock lock(c_->mutex);
        c_->touch({});
        return {.provider = "aws-s3", .account_ref = kAccount, .principal = "arn:aws:iam::123456789012:user/test"};
    }
    padmin::Capabilities probe() override {
        padmin::Capabilities caps;
        caps.identity = identity();
        caps.items = {{.name = "buckets.list", .ok = true, .probed = true, .detail = ""},
                      {.name = "events.queues", .ok = false, .probed = true, .detail = "sqs:CreateQueue denied"}};
        caps.checked_at = std::time(nullptr);
        return caps;
    }
    padmin::BucketPage listBuckets(const std::string&, unsigned int) override {
        std::scoped_lock lock(c_->mutex);
        c_->touch({});
        padmin::BucketPage page;
        for (const auto& [name, b] : c_->buckets) page.buckets.push_back({.name = name, .region = b.region, .created_at = {}});
        return page;
    }
    std::optional<std::string> headBucket(const std::string& bucket) override {
        guard(bucket);
        std::scoped_lock lock(c_->mutex);
        c_->touch(bucket);
        if (c_->otherAccount.contains(bucket)) throw padmin::ProviderError("forbidden", "AccessDenied", 403);
        if (c_->headFails.contains(bucket)) throw padmin::ProviderError("slow down", "SlowDown", 503);
        if (c_->hiddenFromHead.contains(bucket)) return std::nullopt;
        const auto it = c_->buckets.find(bucket);
        if (it == c_->buckets.end()) return std::nullopt;
        return it->second.region;
    }
    void createBucket(const padmin::CreateBucketRequest& request) override {
        guard(request.name);
        std::scoped_lock lock(c_->mutex);
        c_->touch(request.name);
        if (c_->takenElsewhere.contains(request.name)) throw padmin::ProviderError("taken", "BucketAlreadyExists", 409);
        if (c_->buckets.contains(request.name)) {
            if (c_->silentCreate) return;
            throw padmin::ProviderError("exists", "BucketAlreadyOwnedByYou", 409);
        }
        c_->buckets[request.name].region = request.region.value_or("us-east-1");
    }
    void deleteBucket(const std::string& bucket) override {
        guard(bucket);
        std::scoped_lock lock(c_->mutex);
        c_->touch(bucket);
        ++c_->deleteBucketCalls;
        const auto it = c_->buckets.find(bucket);
        if (it == c_->buckets.end()) throw padmin::ProviderError("no such bucket", "NoSuchBucket", 404);
        if (!it->second.objects.empty() || !it->second.history.empty())
            throw padmin::ProviderError("not empty", "BucketNotEmpty", 409);
        c_->buckets.erase(it);
    }
    padmin::BucketConfiguration inspect(const std::string& bucket) override {
        guard(bucket);
        std::scoped_lock lock(c_->mutex);
        c_->touch(bucket);
        padmin::BucketConfiguration config;
        config.bucket = bucket;
        auto& b = c_->buckets.at(bucket);
        config.region = b.region;
        config.versioning = c_->versioningSupported ? FakeCloud::readVersioning(b) : padmin::Versioning::Unversioned;
        config.object_lock = b.objectLock;
        config.mfa_delete = b.mfaDelete;
        config.lifecycle = b.lifecycle;
        return config;
    }
    void putLifecycle(const std::string& bucket, const std::vector<padmin::LifecycleRule>& rules) override {
        guard(bucket);
        std::scoped_lock lock(c_->mutex);
        c_->touch(bucket);
        c_->buckets.at(bucket).lifecycle = rules;
    }
    bool supportsVersioning() const override {
        std::scoped_lock lock(c_->mutex);
        return c_->versioningSupported;
    }
    padmin::VersioningState versioning(const std::string& bucket) override {
        guard(bucket);
        std::scoped_lock lock(c_->mutex);
        if (!c_->versioningSupported) return {.status = padmin::Versioning::Unversioned, .mfa_delete = std::nullopt};
        c_->touch(bucket);
        ++c_->getVersioningCalls;
        if (c_->getVersioningDenied.contains(bucket))
            throw padmin::ProviderError("GetBucketVersioning denied", "AccessDenied", 403);
        const auto it = c_->buckets.find(bucket);
        if (it == c_->buckets.end()) throw padmin::ProviderError("no such bucket", "NoSuchBucket", 404);
        return {.status = FakeCloud::readVersioning(it->second), .mfa_delete = it->second.mfaDelete};
    }
    void putVersioning(const std::string& bucket, const padmin::Versioning target) override {
        if (target != padmin::Versioning::Enabled && target != padmin::Versioning::Suspended)
            throw std::invalid_argument("bucket versioning can only be set to enabled or suspended");
        guard(bucket);
        std::scoped_lock lock(c_->mutex);
        if (!c_->versioningSupported) throw padmin::CapabilityMissing("versioning", padmin::kR2VersioningUnsupported);
        c_->touch(bucket);
        c_->putVersioningCalls.emplace_back(bucket, target);
        if (c_->putVersioningDenied.contains(bucket))
            throw padmin::ProviderError("PutBucketVersioning denied", "AccessDenied", 403);
        const auto it = c_->buckets.find(bucket);
        if (it == c_->buckets.end()) throw padmin::ProviderError("no such bucket", "NoSuchBucket", 404);
        auto& b = it->second;
        if (b.objectLock && target == padmin::Versioning::Suspended)
            throw padmin::ProviderError("An Object Lock configuration is present on this bucket, so the versioning "
                                        "state cannot be changed.", "InvalidBucketState", 409);
        if (b.staleVersioningReads == 0) b.previousVersioning = b.versioning;
        b.versioning = target;
        b.staleVersioningReads = c_->staleReadsAfterPut;
    }
    padmin::ObjectPage listObjects(const std::string& bucket, const std::string&, unsigned int max) override {
        guard(bucket);
        std::scoped_lock lock(c_->mutex);
        c_->touch(bucket);
        padmin::ObjectPage page;
        for (const auto& [key, size] : c_->buckets.at(bucket).objects) {
            if (page.objects.size() >= max) break;
            page.objects.push_back({.key = key, .size = size, .etag = "e", .last_modified = {}, .version_id = {},
                                    .delete_marker = false, .latest = true});
        }
        return page;
    }
    padmin::ObjectPage listObjectVersions(const std::string& bucket, const std::string& token, unsigned int max) override {
        auto page = listObjects(bucket, token, max);
        std::scoped_lock lock(c_->mutex);
        if (!c_->versioningSupported) return page;
        for (const auto& o : c_->buckets.at(bucket).history) {
            if (page.objects.size() >= max) break;
            page.objects.push_back(o);
        }
        return page;
    }
    std::vector<std::pair<std::string, std::string>> deleteObjects(const std::string& bucket,
                                                                   const std::vector<padmin::ObjectSummary>& objects) override {
        guard(bucket);
        std::function<void(const std::string&)> hook;
        {
            std::scoped_lock lock(c_->mutex);
            hook = c_->beforeDeleteObjects;
        }
        if (hook) hook(bucket);
        std::scoped_lock lock(c_->mutex);
        c_->touch(bucket);
        if (c_->deleteObjectsFailAfter == 0) throw padmin::ProviderError("service unavailable", "ServiceUnavailable", 503);
        if (c_->deleteObjectsFailAfter > 0) --c_->deleteObjectsFailAfter;
        std::vector<std::pair<std::string, std::string>> failed;
        auto& b = c_->buckets.at(bucket);
        for (const auto& o : objects) {
            if (b.locked.contains(o.key)) {
                failed.emplace_back(o.key, "AccessDenied");
                continue;
            }
            const auto version = [&](const padmin::ObjectSummary& h) {
                return o.version_id && h.key == o.key && h.version_id == o.version_id;
            };
            if (std::erase_if(b.history, version) == 0) b.objects.erase(o.key);
        }
        return failed;
    }
    padmin::Metrics metrics() const override { return {}; }

    bool supportsReadKeys() const override { return c_->readKeysSupported; }
    padmin::ReadKey createReadKey(const padmin::ReadKeyRequest& request) override {
        if (!c_->readKeysSupported) return AdminClient::createReadKey(request);
        guard(request.bucket);
        std::scoped_lock lock(c_->mutex);
        c_->touch(request.bucket);
        c_->readKeyRequests.push_back(request);
        if (c_->writeKeysMissing) throw padmin::CapabilityMissing("writeKeys", "the key may not create keys: it needs writeKeys");
        if (c_->createReadKeyFails) throw padmin::ProviderError("b2_create_key failed (HTTP 503)", "service_unavailable", 503);
        if (!c_->buckets.contains(request.bucket)) throw padmin::ProviderError("no such bucket", "NoSuchBucket", 404);
        const auto n = ++c_->readKeySeq;
        padmin::ReadKey key{.key_id = "004fakereadkey" + std::to_string(n),
                            .secret = "K004FakeReadSecret" + std::to_string(n) + "xyzzy",
                            .key_name = request.key_name,
                            .bucket = request.bucket,
                            .bucket_id = "bucketid-" + request.bucket,
                            .capabilities = padmin::kReadKeyCapabilities(),
                            .endpoint = "https://s3.us-west-004.backblazeb2.com",
                            .region = "us-west-004"};
        c_->readKeys[key.key_id] = request;
        return key;
    }
    void deleteReadKey(const std::string& keyId) override {
        if (!c_->readKeysSupported) return AdminClient::deleteReadKey(keyId);
        std::scoped_lock lock(c_->mutex);
        c_->deleteReadKeyCalls.push_back(keyId);
        if (c_->deleteReadKeyFails) throw padmin::ProviderError("b2_delete_key failed (HTTP 500)", "internal_error", 500);
        c_->readKeys.erase(keyId);
    }

private:
    // The real adapters check the guard before every bucket-scoped request; so does the fake.
    static void guard(const std::string& bucket) {
        storage::upstream::guard::require({.provider = "aws-s3", .account_ref = kAccount, .bucket = bucket});
    }
    std::shared_ptr<FakeCloud> c_;
};

}
