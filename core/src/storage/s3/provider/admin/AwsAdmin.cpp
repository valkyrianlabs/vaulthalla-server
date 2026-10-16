#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Names.hpp"

#include "vault/model/APIKey.hpp"

#include <pugixml.hpp>

#include <algorithm>
#include <stdexcept>

namespace vh::storage::s3::provider::admin {

namespace {

// The region becomes part of a host name: only a real region code may (a value like "evil.example/#" would send a
// signed request, access key id included, to someone else's server).
std::string s3Host(const std::string& region) {
    if (!storage::upstream::validAwsRegion(region)) throw std::invalid_argument("invalid AWS region '" + region + "'");
    return "s3." + region + ".amazonaws.com";
}

}

std::string awsEventsPolicyHint(const std::string& accountRef) {
    const auto account = accountRef.empty() ? std::string("<account>") : accountRef;
    return "grant the IAM identity sqs:CreateQueue, sqs:GetQueueUrl, sqs:GetQueueAttributes, sqs:SetQueueAttributes, "
           "sqs:ReceiveMessage, sqs:DeleteMessage, sqs:ChangeMessageVisibility and sqs:DeleteQueue on "
           "arn:aws:sqs:*:" + account + ":vaulthalla-*, sqs:ListQueues on *, and s3:GetBucketNotification + "
           "s3:PutBucketNotification on the vault buckets (one credential does it all; no extra IAM user is needed)";
}

AwsAdmin::AwsAdmin(std::shared_ptr<vault::model::APIKey> key) : S3ApiAdmin(std::move(key)) {}

std::string AwsAdmin::defaultRegion() const {
    if (key_->region.empty() || key_->region == "auto") return "us-east-1";
    return key_->region;
}

detail::Endpoint AwsAdmin::serviceEndpoint() { return {s3Host(defaultRegion()), defaultRegion(), "s3"}; }

detail::Endpoint AwsAdmin::bucketEndpoint(const std::string& bucket) {
    const auto region = regionOf(bucket);
    return {s3Host(region), region, "s3"};
}

std::optional<std::string> AwsAdmin::locationConstraint(const CreateBucketRequest& request) const {
    const auto region = request.region && !request.region->empty() ? *request.region : defaultRegion();
    if (!storage::upstream::validAwsRegion(region)) throw std::invalid_argument("invalid AWS region '" + region + "'");
    if (region == "us-east-1") return std::nullopt;
    return region;
}

AccountIdentity AwsAdmin::identity() {
    if (identity_) return *identity_;
    auto c = detail::call("GET", {{"Action", "GetCallerIdentity"}, {"Version", "2011-06-15"}});
    const auto response = call({"sts.amazonaws.com", "us-east-1", "sts"}, c, "get");
    if (!response.ok()) throw detail::makeError("STS GetCallerIdentity", response, detail::s3Error(response), secrets());
    pugi::xml_document doc;
    if (!doc.load_string(response.body.c_str())) throw ProviderError("STS GetCallerIdentity: response is not XML");
    const auto result = doc.child("GetCallerIdentityResponse").child("GetCallerIdentityResult");
    AccountIdentity id{.provider = "aws-s3", .account_ref = result.child_value("Account"), .principal = result.child_value("Arn")};
    if (id.account_ref.empty()) throw ProviderError("STS GetCallerIdentity returned no account");
    identity_ = id;
    return id;
}

std::optional<std::string> AwsAdmin::accountForGuard() {
    if (key_->provider_account_id && !key_->provider_account_id->empty()) return key_->provider_account_id;
    if (identity_) return identity_->account_ref;
    try {
        return identity().account_ref;
    } catch (const std::exception&) {
        return std::nullopt;   // unknown account: the guard then fails closed on any lock for the name
    }
}

std::string AwsAdmin::regionOf(const std::string& bucket) {
    if (const auto it = regions_.find(bucket); it != regions_.end()) return it->second;
    if (const auto region = headBucket(bucket)) return *region;
    return defaultRegion();
}

std::optional<std::string> AwsAdmin::headBucket(const std::string& bucket) {
    if (bucket.empty()) throw std::invalid_argument("bucket name is required");
    storage::upstream::requireValidBucketName(bucket);
    storage::upstream::guard::require(bucketIdentity(bucket));

    // The global endpoint answers for every bucket: 200 here, or a redirect/400 naming its region.
    const auto probe = [&](const std::string& region) {
        auto c = detail::call("HEAD", {}, "/" + bucket);
        return call({region == "us-east-1" ? std::string("s3.amazonaws.com") : s3Host(region), region, "s3"}, c, "head");
    };
    auto response = probe("us-east-1");
    if (response.transport_ok && response.status == 404) return std::nullopt;
    auto region = response.header("x-amz-bucket-region");
    if (region && !storage::upstream::validAwsRegion(*region)) region.reset();   // never route by a malformed header
    if (response.ok()) {
        regions_[bucket] = region.value_or("us-east-1");
        return regions_[bucket];
    }
    if (region && *region != "us-east-1") {
        response = probe(*region);
        if (response.ok()) {
            regions_[bucket] = *region;
            return region;
        }
        if (response.transport_ok && response.status == 404) return std::nullopt;
    }
    throw detail::makeError("HeadBucket " + bucket, response, detail::s3Error(response), secrets());
}

void AwsAdmin::createBucket(const CreateBucketRequest& request) {
    storage::upstream::requireValidBucketName(request.name);
    if (request.region && !request.region->empty() && !storage::upstream::validAwsRegion(*request.region))
        throw std::invalid_argument("invalid AWS region '" + *request.region + "'");
    regions_[request.name] = request.region && !request.region->empty() ? *request.region : defaultRegion();
    try {
        S3ApiAdmin::createBucket(request);
    } catch (...) {
        regions_.erase(request.name);   // a refused name may live in another region
        throw;
    }
}

BucketConfiguration AwsAdmin::inspect(const std::string& bucket) {
    BucketConfiguration config;
    config.bucket = bucket;
    config.region = headBucket(bucket);
    if (!config.region) throw ProviderError("bucket '" + bucket + "' does not exist", "NoSuchBucket", 404);

    config.versioning = getVersioning(bucket, config.warnings);

    const auto lock = bucketCall(bucket, detail::call("GET", {{"object-lock", ""}}), "get");
    if (lock.ok()) {
        pugi::xml_document doc;
        doc.load_string(lock.body.c_str());
        config.object_lock = std::string(doc.child("ObjectLockConfiguration").child_value("ObjectLockEnabled")) == "Enabled";
    } else if (detail::s3Error(lock).code == "ObjectLockConfigurationNotFoundError") {
        config.object_lock = false;
    } else {
        config.warnings.emplace_back("object lock configuration is not readable with this credential "
                                     "(s3:GetBucketObjectLockConfiguration); cleanup treats it as unknown");
    }

    if (auto rules = getLifecycle(bucket)) {
        config.lifecycle = std::move(*rules);
    } else {
        config.lifecycle_readable = false;
        config.warnings.emplace_back("lifecycle configuration is not readable with this credential (s3:GetLifecycleConfiguration)");
    }

    const auto notification = bucketCall(bucket, detail::call("GET", {{"notification", ""}}), "get");
    if (notification.ok()) {
        for (auto& e : detail::parseNotification(notification.body)) {
            if (e.kind == "EventBridgeConfiguration") {
                e.rule.id = "EventBridgeConfiguration";
                e.rule.destination = "eventbridge";
            }
            config.notifications.push_back(std::move(e.rule));
        }
    } else {
        config.notifications_readable = false;
        config.warnings.emplace_back("event notifications are not readable with this credential (s3:GetBucketNotification)");
    }
    return config;
}

Capabilities AwsAdmin::probe() {
    Capabilities caps;
    caps.identity = identity();
    caps.checked_at = std::time(nullptr);

    try {
        (void)listBuckets({}, 1);
        caps.items.push_back({"buckets.list", true, true, {}});
    } catch (const ProviderError& e) {
        caps.items.push_back({"buckets.list", false, true, e.what()});
    }
    caps.items.push_back({"buckets.create", true, false, "s3:CreateBucket is checked when a bucket is created"});
    caps.items.push_back({"lifecycle", true, false, "s3:Get/PutLifecycleConfiguration are checked on use"});
    caps.items.push_back({"events.notifications", true, false,
                          "s3:Get/PutBucketNotification are checked when events are enabled"});

    Capability queues{"events.queues", false, false, {}};
    try {
        AwsEvents events(key_);
        const auto region = defaultRegion();
        const auto name = defaultQueueName("aws-s3", region);
        try {
            const auto url = events.sqs(region, "GetQueueUrl", {{"QueueName", name}});
            (void)events.sqs(region, "GetQueueAttributes",
                             {{"QueueUrl", url.value("QueueUrl", "")}, {"AttributeNames", {"QueueArn"}}});
            queues = {"events.queues", true, true, "queue " + name + " is readable"};
        } catch (const ProviderError& e) {
            if (e.accessDenied()) {
                queues = {"events.queues", false, true, std::string(e.what()) + "; " + awsEventsPolicyHint(caps.identity.account_ref)};
            } else if (e.code == "NonExistentQueue") {
                try {
                    (void)events.sqs(region, "ListQueues", {{"QueueNamePrefix", kOwnedPrefix}, {"MaxResults", 1}});
                    queues = {"events.queues", true, false, "SQS is readable; queue creation is checked when events are enabled"};
                } catch (const ProviderError& listError) {
                    queues = {"events.queues", false, false,
                              "could not confirm SQS permissions (" + std::string(listError.what()) + "); " +
                                  awsEventsPolicyHint(caps.identity.account_ref)};
                }
            } else {
                queues.detail = e.what();
            }
        }
    } catch (const std::exception& e) {
        queues.detail = e.what();
    }
    caps.items.push_back(std::move(queues));
    return caps;
}

}
