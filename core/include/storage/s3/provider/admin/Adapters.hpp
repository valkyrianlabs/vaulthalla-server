#pragma once

#include "storage/s3/provider/admin/Internal.hpp"
#include "storage/upstream/Guard.hpp"

#include <nlohmann/json.hpp>

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// The AWS S3 and Cloudflare R2 admin/events adapters (#237, #96). Construct them through admin::adminFor/eventsFor.
// Every bucket-scoped call checks storage::upstream::guard before anything is sent.
namespace vh::storage::s3::provider::admin {

// The S3 API both providers share: listings, bucket create/delete, lifecycle, batch delete.
class S3ApiAdmin : public AdminClient {
public:
    explicit S3ApiAdmin(std::shared_ptr<vault::model::APIKey> key);

    [[nodiscard]] BucketPage listBuckets(const std::string& token, unsigned int max) override;
    [[nodiscard]] std::optional<std::string> headBucket(const std::string& bucket) override;
    void createBucket(const CreateBucketRequest& request) override;
    void deleteBucket(const std::string& bucket) override;
    void putLifecycle(const std::string& bucket, const std::vector<LifecycleRule>& rules) override;
    // Versioning support follows allowNoncurrent(): a provider with noncurrent versions has versioning.
    [[nodiscard]] bool supportsVersioning() const override { return allowNoncurrent(); }
    // Unsupported: name + guard checked, then Unversioned without a request.
    [[nodiscard]] VersioningState versioning(const std::string& bucket) override;
    // Content-MD5 (AWS requires an integrity header on PutBucketVersioning) + x-amz-expected-bucket-owner when the
    // account is known. Unsupported: target, name and guard checked, then CapabilityMissing; nothing is sent.
    void putVersioning(const std::string& bucket, Versioning target) override;
    [[nodiscard]] ObjectPage listObjects(const std::string& bucket, const std::string& token, unsigned int max) override;
    [[nodiscard]] ObjectPage listObjectVersions(const std::string& bucket, const std::string& token,
                                                unsigned int max) override;
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> deleteObjects(
        const std::string& bucket, const std::vector<ObjectSummary>& objects) override;
    [[nodiscard]] Metrics metrics() const override;

    // The protection identity of a bucket in this account.
    [[nodiscard]] storage::upstream::BucketIdentity bucketIdentity(const std::string& bucket);

    // Bucket name validation + protection guard, nothing sent. Every bucket-scoped call runs it first.
    void requireBucket(const std::string& bucket);

    // A signed S3 call against the bucket's endpoint (guarded, metered). Public for the events adapter.
    [[nodiscard]] curl::http::Response bucketCall(const std::string& bucket, detail::SignedCall call, const char* kind);
    [[nodiscard]] std::vector<std::string> secrets() const;

protected:
    [[nodiscard]] virtual detail::Endpoint serviceEndpoint() = 0;
    [[nodiscard]] virtual detail::Endpoint bucketEndpoint(const std::string& bucket) = 0;
    [[nodiscard]] virtual bool allowNoncurrent() const = 0;
    // The CreateBucketConfiguration LocationConstraint for a region request; nullopt = no body.
    [[nodiscard]] virtual std::optional<std::string> locationConstraint(const CreateBucketRequest& request) const = 0;
    [[nodiscard]] virtual std::optional<std::string> accountForGuard() = 0;
    // ListBuckets max-buckets/continuation-token (AWS); providers without it get one unpaged listing.
    [[nodiscard]] virtual bool pagedListBuckets() const { return true; }

    curl::http::Response call(const detail::Endpoint& endpoint, const detail::SignedCall& call, const char* kind);
    void count(const char* kind);
    // GET ?lifecycle; NoSuchLifecycleConfiguration → empty; AccessDenied → nullopt.
    [[nodiscard]] std::optional<std::vector<LifecycleRule>> getLifecycle(const std::string& bucket);
    // GET ?versioning for inspect: NotImplemented → Unversioned; other failures → Unknown + a warning.
    [[nodiscard]] VersioningState getVersioning(const std::string& bucket, std::vector<std::string>& warnings);
    // The account that must own a bucket for a mutating call (x-amz-expected-bucket-owner); nullopt = not sent.
    [[nodiscard]] virtual std::optional<std::string> expectedBucketOwner() const { return std::nullopt; }

    std::shared_ptr<vault::model::APIKey> key_;
    sigv4::Credentials credentials_;
    mutable std::mutex metricsMutex_;
    Metrics metrics_;
};

class AwsAdmin final : public S3ApiAdmin {
public:
    explicit AwsAdmin(std::shared_ptr<vault::model::APIKey> key);

    [[nodiscard]] std::string providerId() const override { return "aws-s3"; }
    [[nodiscard]] AccountIdentity identity() override;
    [[nodiscard]] Capabilities probe() override;
    // 404 → nullopt; 200/301/400 with x-amz-bucket-region → the region; 403 → ProviderError(AccessDenied).
    // One HEAD when the region is known (cached, setKnownRegion, else the key's region) and right: it goes straight to
    // that regional endpoint. The global endpoint is probed only when no region is known, or when a known region
    // answers with a redirect that names no region; a region hint (x-amz-bucket-region) costs one more HEAD (#247).
    [[nodiscard]] std::optional<std::string> headBucket(const std::string& bucket) override;
    void setKnownRegion(const std::string& bucket, const std::string& region) override;
    // Sent to the requested region's endpoint (default: the key's region).
    void createBucket(const CreateBucketRequest& request) override;
    [[nodiscard]] BucketConfiguration inspect(const std::string& bucket) override;

    // The bucket's region (cached; resolved with one HEAD).
    [[nodiscard]] std::string regionOf(const std::string& bucket);
    [[nodiscard]] std::string defaultRegion() const;

protected:
    [[nodiscard]] detail::Endpoint serviceEndpoint() override;
    [[nodiscard]] detail::Endpoint bucketEndpoint(const std::string& bucket) override;
    [[nodiscard]] bool allowNoncurrent() const override { return true; }
    [[nodiscard]] std::optional<std::string> locationConstraint(const CreateBucketRequest& request) const override;
    [[nodiscard]] std::optional<std::string> accountForGuard() override;
    [[nodiscard]] std::optional<std::string> expectedBucketOwner() const override;

private:
    // Where headBucket sends its first HEAD (nullopt = the global endpoint).
    [[nodiscard]] std::optional<std::string> knownRegion(const std::string& bucket) const;

    std::optional<AccountIdentity> identity_;
    std::map<std::string, std::string> regions_;      // answered by the provider
    std::map<std::string, std::string> knownRegions_; // setKnownRegion hints
};

class R2Admin final : public S3ApiAdmin {
public:
    explicit R2Admin(std::shared_ptr<vault::model::APIKey> key);

    [[nodiscard]] std::string providerId() const override { return "cloudflare-r2"; }
    [[nodiscard]] AccountIdentity identity() override;
    [[nodiscard]] Capabilities probe() override;
    [[nodiscard]] BucketConfiguration inspect(const std::string& bucket) override;

protected:
    [[nodiscard]] detail::Endpoint serviceEndpoint() override;
    [[nodiscard]] detail::Endpoint bucketEndpoint(const std::string& bucket) override;
    [[nodiscard]] bool allowNoncurrent() const override { return false; }
    [[nodiscard]] std::optional<std::string> locationConstraint(const CreateBucketRequest& request) const override;
    [[nodiscard]] std::optional<std::string> accountForGuard() override;
    [[nodiscard]] bool pagedListBuckets() const override { return false; }
};

// S3 → SQS Standard. One queue (+ DLQ) per account and region.
class AwsEvents final : public EventsClient {
public:
    explicit AwsEvents(std::shared_ptr<vault::model::APIKey> key);

    [[nodiscard]] std::string providerId() const override { return "aws-s3"; }
    [[nodiscard]] ChannelRef ensureChannel(const ChannelSpec& spec) override;
    [[nodiscard]] std::vector<std::string> subscribe(const ChannelRef& channel, const SubscriptionSpec& spec) override;
    void unsubscribe(const ChannelRef& channel, const SubscriptionSpec& spec, const std::vector<std::string>& ruleIds) override;
    [[nodiscard]] std::vector<NotificationRule> rules(const std::string& bucket) override;
    void removeChannel(const ChannelRef& channel) override;
    [[nodiscard]] PollResult poll(const ChannelRef& channel, unsigned int max, std::chrono::seconds wait,
                                  std::chrono::seconds visibility) override;
    void ack(const ChannelRef& channel, const std::vector<std::string>& receipts) override;
    void retry(const ChannelRef& channel, const std::vector<std::string>& receipts, std::chrono::seconds delay) override;
    [[nodiscard]] std::optional<uint64_t> backlog(const ChannelRef& channel) override;
    [[nodiscard]] Metrics metrics() const override;

    // One SQS JSON-protocol action against the queue URL's region (metered). Throws ProviderError.
    [[nodiscard]] nlohmann::json sqs(const std::string& region, const std::string& action, const nlohmann::json& body,
                                     std::chrono::seconds timeout = std::chrono::seconds{30});
    [[nodiscard]] static std::string regionOfQueue(const ChannelRef& channel);

private:
    [[nodiscard]] std::string getNotificationXml(const std::string& bucket);
    void putNotificationXml(const std::string& bucket, const std::string& xml);
    [[nodiscard]] std::optional<std::string> queueUrl(const std::string& region, const std::string& name);
    [[nodiscard]] std::map<std::string, std::string> queueAttributes(const std::string& region, const std::string& url,
                                                                     const std::vector<std::string>& names);

    std::shared_ptr<vault::model::APIKey> key_;
    AwsAdmin s3_;
    mutable std::mutex metricsMutex_;
    Metrics metrics_;
};

// R2 → Cloudflare Queues (HTTP pull), through the Cloudflare REST API with the account API token.
class R2Events final : public EventsClient {
public:
    explicit R2Events(std::shared_ptr<vault::model::APIKey> key);

    [[nodiscard]] std::string providerId() const override { return "cloudflare-r2"; }
    [[nodiscard]] ChannelRef ensureChannel(const ChannelSpec& spec) override;
    [[nodiscard]] std::vector<std::string> subscribe(const ChannelRef& channel, const SubscriptionSpec& spec) override;
    void unsubscribe(const ChannelRef& channel, const SubscriptionSpec& spec, const std::vector<std::string>& ruleIds) override;
    [[nodiscard]] std::vector<NotificationRule> rules(const std::string& bucket) override;
    void removeChannel(const ChannelRef& channel) override;
    [[nodiscard]] PollResult poll(const ChannelRef& channel, unsigned int max, std::chrono::seconds wait,
                                  std::chrono::seconds visibility) override;
    void ack(const ChannelRef& channel, const std::vector<std::string>& receipts) override;
    void retry(const ChannelRef& channel, const std::vector<std::string>& receipts, std::chrono::seconds delay) override;
    [[nodiscard]] std::optional<uint64_t> backlog(const ChannelRef& channel) override;
    [[nodiscard]] Metrics metrics() const override;

    // One Cloudflare API call (metered); returns the envelope's `result` (and result_info via `info`). Throws
    // ProviderError; an authentication failure carries code "10000"/"10001" and accessDenied() is true.
    [[nodiscard]] nlohmann::json api(const std::string& method, const std::string& path, const nlohmann::json& body = nullptr,
                                     nlohmann::json* info = nullptr, bool bucketScoped = false);
    [[nodiscard]] const std::string& accountId() const { return account_; }

private:
    [[nodiscard]] std::optional<nlohmann::json> findQueue(const std::string& name);
    [[nodiscard]] nlohmann::json ensureQueue(const std::string& name, bool& created);
    [[nodiscard]] nlohmann::json bucketConfiguration(const std::string& bucket);
    // Our rule ids on the queue: the configuration listing names the queue by an id spelled differently from the Queues
    // API's queue_id (seen live), so the queue matches by its id with dashes and case ignored, or by its name (unique
    // per account).
    [[nodiscard]] std::vector<std::string> ourRuleIds(const nlohmann::json& config, const ChannelRef& channel,
                                                      const std::string& marker);
    [[nodiscard]] std::optional<std::string> jurisdiction() const;

    std::shared_ptr<vault::model::APIKey> key_;
    std::string account_;
    std::string token_;
    mutable std::mutex metricsMutex_;
    Metrics metrics_;
};

// Shared message for the IAM statement AWS event provisioning needs.
[[nodiscard]] std::string awsEventsPolicyHint(const std::string& accountRef);
inline constexpr const char* kCloudflareTokenHint =
    "a Cloudflare API token with Account > Queues: Edit and Account > Workers R2 Storage: Edit is required "
    "(R2 S3 credentials cannot call the Cloudflare API)";

}
