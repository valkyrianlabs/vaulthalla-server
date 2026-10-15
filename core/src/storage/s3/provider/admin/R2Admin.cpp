#include "storage/s3/provider/admin/Adapters.hpp"

#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace vh::storage::s3::provider::admin {

namespace {

// R2 location hints accepted as CreateBucket LocationConstraint.
constexpr std::array<std::string_view, 6> kLocationHints{"wnam", "enam", "weur", "eeur", "apac", "oc"};

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

}

R2Admin::R2Admin(std::shared_ptr<vault::model::APIKey> key) : S3ApiAdmin(std::move(key)) {
    if (!staticAccountRef(*key_))
        throw std::invalid_argument("Cloudflare R2 endpoint must be https://<account id>.r2.cloudflarestorage.com");
}

detail::Endpoint R2Admin::serviceEndpoint() { return {detail::hostOf(key_->endpoint), "auto", "s3"}; }

detail::Endpoint R2Admin::bucketEndpoint(const std::string&) { return serviceEndpoint(); }

std::optional<std::string> R2Admin::accountForGuard() { return staticAccountRef(*key_); }

AccountIdentity R2Admin::identity() {
    return {.provider = "cloudflare-r2", .account_ref = *staticAccountRef(*key_), .principal = "r2-token"};
}

std::optional<std::string> R2Admin::locationConstraint(const CreateBucketRequest& request) const {
    auto hint = lower(request.region && !request.region->empty() ? *request.region : key_->region);
    if (hint.empty() || hint == "auto") return std::nullopt;
    if (std::ranges::find(kLocationHints, hint) == kLocationHints.end())
        throw std::invalid_argument("unknown R2 location hint '" + hint + "' (wnam, enam, weur, eeur, apac, oc or auto)");
    return hint;
}

BucketConfiguration R2Admin::inspect(const std::string& bucket) {
    BucketConfiguration config;
    config.bucket = bucket;
    if (!headBucket(bucket)) throw ProviderError("bucket '" + bucket + "' does not exist", "NoSuchBucket", 404);
    config.region = "auto";
    config.versioning = getVersioning(bucket, config.warnings);
    if (config.versioning == Versioning::Unknown) config.versioning = Versioning::Unversioned;   // R2 has no versioning
    config.object_lock = std::nullopt;   // R2 bucket locks live in the Cloudflare API; Vaulthalla does not manage them

    if (auto rules = getLifecycle(bucket)) {
        config.lifecycle = std::move(*rules);
    } else {
        config.lifecycle_readable = false;
        config.warnings.emplace_back("lifecycle configuration is not readable with this credential");
    }

    if (key_->provider_token.empty()) {
        config.notifications_readable = false;
        config.warnings.emplace_back(std::string("event notifications: ") + kCloudflareTokenHint);
    } else {
        try {
            R2Events events(key_);
            config.notifications = events.rules(bucket);
        } catch (const std::exception& e) {
            config.notifications_readable = false;
            config.warnings.emplace_back(std::string("event notifications are not readable: ") + e.what());
        }
    }
    return config;
}

Capabilities R2Admin::probe() {
    Capabilities caps;
    caps.identity = identity();
    caps.checked_at = std::time(nullptr);

    std::optional<std::string> firstBucket;
    try {
        const auto page = listBuckets({}, 1);
        if (!page.buckets.empty()) firstBucket = page.buckets.front().name;
        caps.items.push_back({"buckets.list", true, true, {}});
    } catch (const ProviderError& e) {
        caps.items.push_back({"buckets.list", false, true, e.what()});
    }
    caps.items.push_back({"buckets.create", true, false, "checked when a bucket is created (R2 token needs Object Read & Write + bucket admin)"});
    caps.items.push_back({"lifecycle", true, false, "checked on use"});

    if (key_->provider_token.empty()) {
        caps.items.push_back({"events.queues", false, true, kCloudflareTokenHint});
        caps.items.push_back({"events.notifications", false, true, kCloudflareTokenHint});
        return caps;
    }

    try {
        R2Events events(key_);
        try {
            (void)events.api("GET", "/accounts/" + events.accountId() + "/queues?per_page=1");
            caps.items.push_back({"events.queues", true, true, {}});
        } catch (const ProviderError& e) {
            caps.items.push_back({"events.queues", false, true, std::string(e.what()) + "; " + kCloudflareTokenHint});
        }
        if (firstBucket) {
            // Only a bucket that isn't protected may be probed.
            if (storage::upstream::guard::isProtected(bucketIdentity(*firstBucket))) {
                caps.items.push_back({"events.notifications", true, false, "not probed (first listed bucket is protected)"});
            } else {
                try {
                    (void)events.rules(*firstBucket);
                    caps.items.push_back({"events.notifications", true, true, {}});
                } catch (const ProviderError& e) {
                    caps.items.push_back({"events.notifications", !e.accessDenied(), true,
                                          e.accessDenied() ? std::string(e.what()) + "; " + kCloudflareTokenHint : e.what()});
                }
            }
        } else {
            caps.items.push_back({"events.notifications", true, false, "no bucket to probe; checked when events are enabled"});
        }
    } catch (const std::exception& e) {
        caps.items.push_back({"events.queues", false, true, e.what()});
    }
    return caps;
}

}
