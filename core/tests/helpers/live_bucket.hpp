#pragma once

// The ONE way a test reaches a real provider (.claude/context/testing.md, "Live provider tests"): Cloudflare R2 and
// Backblaze B2.
//
//  - Opt-in: nothing here runs unless VH_LIVE_TESTS=1, whatever credentials the environment holds. The credential is
//    the R2 admin key VH_R2_ADMIN_{ACCESS_KEY,SECRET_KEY,ENDPOINT} (+ optional VH_R2_ADMIN_REGION); events also need a
//    Cloudflare API token, VH_CF_API_TOKEN. Backblaze: an application key VH_B2_TEST_{KEY_ID,APP_KEY} (buckets
//    created and deleted, files listed, written and deleted); the S3 endpoint and region come from
//    b2_authorize_account (apiInfo.storageApi.s3ApiUrl). Bucket administration and version cleanup go through B2's
//    native API (GuardedB2): the product has no B2 admin adapter.
//  - Rule 1, names: every bucket a test creates is vh-test-<host>-<pid>-<run start> (kRunBucketPattern), or one of the
//    fixed tooling buckets (fixedTestBuckets(): vh-test-gateway-smoke). GuardedAdmin refuses to create, delete, empty,
//    inspect or reconfigure any other bucket, and GuardedEvents any other bucket or queue; production buckets are
//    unreachable by construction. Account listings (read-only)
//    are allowed: the orphan sweep needs them.
//  - Rule 2, cleanup: a live run creates exactly one bucket (RunBucket, on the first live test) and the global test
//    environment empties and deletes it after the last test, also when tests failed, then fails the run unless
//    HeadBucket says it is gone. Each test works under its own <Suite>.<Test>/ prefix, emptied (objects and unfinished
//    multipart uploads) in TearDown and checked empty. Before creating its bucket a run sweeps buckets matching
//    kRunBucketPattern whose run started more than kStaleAfter ago (crashed or killed runs), and nothing else.
//  - A guard violation is recorded as well as thrown, so it fails the test even when the code under test swallows it.
//  - tools/contracts/test_live_bucket_contract.py keeps provider administration in tests behind this helper.

#include "crypto/util/encrypt.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pugixml.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace vh::test_support::live {

namespace padmin = storage::s3::provider::admin;

inline constexpr std::string_view kBucketPrefix = "vh-test-";
// vh-test-<host>-<pid>-<run start>: what newRunBucketName() generates, and the only thing the sweep considers.
inline constexpr const char* kRunBucketPattern = R"(^vh-test-[a-z0-9]{1,24}-[0-9]{1,10}-[0-9]{10}$)";
// Fixed test buckets of tooling (tools/smoke), created and deleted by vh_live_bucket (live_bucket_tool.cpp). Never swept:
// their tool removes a leftover before it creates one.
inline const std::vector<std::string>& fixedTestBuckets() {
    static const std::vector<std::string> names{"vh-test-gateway-smoke", "vh-test-recover-drill"};
    return names;
}
// A run whose bucket is older than this crashed or was killed (a run takes minutes).
inline constexpr std::chrono::hours kStaleAfter{6};
inline constexpr int kMaxPages = 50;

inline std::string env(const char* name) {
    const auto* v = std::getenv(name);
    return v ? std::string(v) : std::string{};
}

inline bool optedIn() { return env("VH_LIVE_TESTS") == "1"; }

struct Target {
    std::string access, secret, endpoint, region, token;
    std::vector<std::string> missing;   // names of the unset required variables (never values)
    [[nodiscard]] bool configured() const { return missing.empty(); }
    [[nodiscard]] bool unset() const { return missing.size() == 3; }
};

inline Target target() {
    Target t;
    const auto read = [&](const char* name, std::string& out) {
        out = env(name);
        if (out.empty()) t.missing.emplace_back(name);
    };
    read("VH_R2_ADMIN_ACCESS_KEY", t.access);
    read("VH_R2_ADMIN_SECRET_KEY", t.secret);
    read("VH_R2_ADMIN_ENDPOINT", t.endpoint);
    t.region = env("VH_R2_ADMIN_REGION");
    if (t.region.empty()) t.region = "auto";
    t.token = env("VH_CF_API_TOKEN");
    return t;
}

inline std::shared_ptr<vault::model::APIKey> apiKey(const Target& t) {
    auto key = std::make_shared<vault::model::APIKey>(0, "live-r2", vault::model::S3Provider::CloudflareR2, t.access,
                                                      t.secret, t.region, t.endpoint);
    key->provider_token = t.token;
    return key;
}

// ---- names ------------------------------------------------------------------------------------------------------------

inline std::time_t runStarted() {
    static const std::time_t started = std::time(nullptr);
    return started;
}

inline std::string alnumLower(const std::string_view s, const std::size_t max) {
    std::string out;
    for (const char c : s)
        if (std::isalnum(static_cast<unsigned char>(c)) && out.size() < max)
            out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

inline bool isRunBucketName(const std::string& name) {
    static const std::regex re(kRunBucketPattern);
    return name.starts_with(kBucketPrefix) && name.size() <= 63 && std::regex_match(name, re);
}

inline bool isFixedTestBucket(const std::string& name) {
    return std::ranges::find(fixedTestBuckets(), name) != fixedTestBuckets().end();
}

// What the guarded clients may touch: a generated run bucket or one of the fixed tooling buckets.
inline bool isTestBucketName(const std::string& name) { return isRunBucketName(name) || isFixedTestBucket(name); }

// This run's bucket (and events queue) name.
inline const std::string& runBucketName() {
    static const std::string name = [] {
        char host[256] = {};
        if (gethostname(host, sizeof(host) - 1) != 0) host[0] = '\0';
        std::string h(host);
        h = alnumLower(h.substr(0, h.find('.')), 24);
        if (h.empty()) h = "host";
        auto n = std::string(kBucketPrefix) + h + "-" + std::to_string(getpid()) + "-" + std::to_string(runStarted());
        if (!isRunBucketName(n)) throw std::logic_error("generated a bucket name outside the pattern: " + n);
        return n;
    }();
    return name;
}

// The run start a run bucket's name carries.
inline std::optional<std::time_t> runStartOf(const std::string& name) {
    if (!isRunBucketName(name)) return std::nullopt;
    const auto digits = std::string_view(name).substr(name.rfind('-') + 1);
    long long value = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (ec != std::errc{} || end != digits.data() + digits.size()) return std::nullopt;
    return static_cast<std::time_t>(value);
}

// A run bucket of a run that started more than kStaleAfter ago. Never this run's, never anything else.
inline bool isOrphan(const std::string& name, const std::time_t now) {
    const auto start = runStartOf(name);
    return start && name != runBucketName() &&
           *start + std::chrono::duration_cast<std::chrono::seconds>(kStaleAfter).count() < now;
}

// <Suite>.<Test>/ of the running test, [A-Za-z0-9._-] only.
inline std::string testPrefix() {
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string out;
    for (const char c : info ? std::string(info->test_suite_name()) + "." + info->name() : std::string("no-test"))
        out += std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-' ? c : '-';
    return out + "/";
}

// ---- the runtime guard ------------------------------------------------------------------------------------------------

struct GuardViolation : std::logic_error {
    using std::logic_error::logic_error;
};

inline std::mutex& violationMutex() {
    static std::mutex m;
    return m;
}

inline std::vector<std::string>& violationLog() {
    static std::vector<std::string> log;
    return log;
}

[[noreturn]] inline void violate(const std::string& what) {
    {
        std::scoped_lock lock(violationMutex());
        violationLog().push_back(what);
    }
    throw GuardViolation("live bucket guard: " + what);
}

inline std::vector<std::string> takeViolations() {
    std::scoped_lock lock(violationMutex());
    return std::exchange(violationLog(), {});
}

// The run's events queues: <run bucket name> and <run bucket name>-dlq (R2Events names the dead-letter queue so).
inline bool isRunQueueName(const std::string& name) {
    return isRunBucketName(name) || (name.ends_with("-dlq") && isRunBucketName(name.substr(0, name.size() - 4)));
}

inline void requireTestQueue(const std::string& name) {
    if (!isRunQueueName(name)) violate("queue '" + name + "' is not a vh-test-<host>-<pid>-<start>[-dlq] test queue");
}

inline void requireTestBucket(const std::string& name, const char* what = "bucket") {
    if (!isTestBucketName(name))
        violate(std::string(what) + " '" + name + "' is not a vh-test-<host>-<pid>-<start> test bucket or a fixed tooling one");
}

struct Upload {
    std::string key, upload_id;
};

// An AdminClient that touches only test buckets (kRunBucketPattern); account-level reads pass through.
class GuardedAdmin final : public padmin::AdminClient {
public:
    explicit GuardedAdmin(std::unique_ptr<padmin::AdminClient> inner)
        : in_(std::move(inner)), api_(dynamic_cast<padmin::S3ApiAdmin*>(in_.get())) {}

    [[nodiscard]] std::string providerId() const override { return in_->providerId(); }
    [[nodiscard]] padmin::AccountIdentity identity() override { return in_->identity(); }
    [[nodiscard]] padmin::Capabilities probe() override { return in_->probe(); }
    [[nodiscard]] padmin::BucketPage listBuckets(const std::string& token, const unsigned int max) override {
        return in_->listBuckets(token, max);
    }
    [[nodiscard]] std::optional<std::string> headBucket(const std::string& bucket) override {
        requireTestBucket(bucket);
        return in_->headBucket(bucket);
    }
    void setKnownRegion(const std::string& bucket, const std::string& region) override { in_->setKnownRegion(bucket, region); }
    void createBucket(const padmin::CreateBucketRequest& request) override {
        requireTestBucket(request.name);
        in_->createBucket(request);
    }
    void deleteBucket(const std::string& bucket) override {
        requireTestBucket(bucket);
        in_->deleteBucket(bucket);
    }
    [[nodiscard]] padmin::BucketConfiguration inspect(const std::string& bucket) override {
        requireTestBucket(bucket);
        return in_->inspect(bucket);
    }
    void putLifecycle(const std::string& bucket, const std::vector<padmin::LifecycleRule>& rules) override {
        requireTestBucket(bucket);
        in_->putLifecycle(bucket, rules);
    }
    [[nodiscard]] bool supportsVersioning() const override { return in_->supportsVersioning(); }
    [[nodiscard]] padmin::VersioningState versioning(const std::string& bucket) override {
        requireTestBucket(bucket);
        return in_->versioning(bucket);
    }
    void putVersioning(const std::string& bucket, const padmin::Versioning target) override {
        requireTestBucket(bucket);
        in_->putVersioning(bucket, target);
    }
    [[nodiscard]] padmin::ObjectPage listObjects(const std::string& bucket, const std::string& token,
                                                 const unsigned int max) override {
        requireTestBucket(bucket);
        return in_->listObjects(bucket, token, max);
    }
    [[nodiscard]] padmin::ObjectPage listObjectVersions(const std::string& bucket, const std::string& token,
                                                        const unsigned int max) override {
        requireTestBucket(bucket);
        return in_->listObjectVersions(bucket, token, max);
    }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> deleteObjects(
        const std::string& bucket, const std::vector<padmin::ObjectSummary>& objects) override {
        requireTestBucket(bucket);
        return in_->deleteObjects(bucket, objects);
    }
    [[nodiscard]] padmin::Metrics metrics() const override { return in_->metrics(); }

    // Every object under prefix ("" = the whole bucket), all pages.
    [[nodiscard]] std::vector<padmin::ObjectSummary> objectsUnder(const std::string& bucket, const std::string& prefix) {
        requireTestBucket(bucket);
        std::vector<padmin::ObjectSummary> out;
        std::string token;
        for (int page = 0; page < kMaxPages; ++page) {
            padmin::ObjectPage p;
            if (!api_) {   // a fake inner client (the guard's self-tests)
                p = in_->listObjects(bucket, token, 1000);
                std::erase_if(p.objects, [&](const auto& o) { return !o.key.starts_with(prefix); });
            } else {
                auto c = padmin::detail::call("GET", {{"list-type", "2"}, {"prefix", prefix}, {"max-keys", "1000"}});
                if (!token.empty()) c.query.emplace_back("continuation-token", token);
                const auto r = api_->bucketCall(bucket, c, "list");
                if (!r.ok()) throw padmin::detail::makeError("ListObjectsV2 " + bucket, r, padmin::detail::s3Error(r), api_->secrets());
                p = padmin::detail::parseListObjectsV2(r.body);
            }
            out.insert(out.end(), p.objects.begin(), p.objects.end());
            token = p.next_token;
            if (token.empty()) return out;
        }
        throw std::runtime_error("more than " + std::to_string(kMaxPages) + " listing pages in " + bucket);
    }

    // Unfinished multipart uploads under prefix (none for a fake inner client).
    [[nodiscard]] std::vector<Upload> uploadsUnder(const std::string& bucket, const std::string& prefix) {
        requireTestBucket(bucket);
        std::vector<Upload> out;
        if (!api_) return out;
        std::string keyMarker, idMarker;
        for (int page = 0; page < kMaxPages; ++page) {
            auto c = padmin::detail::call("GET", {{"uploads", ""}, {"prefix", prefix}});
            if (!keyMarker.empty()) c.query.emplace_back("key-marker", keyMarker);
            if (!idMarker.empty()) c.query.emplace_back("upload-id-marker", idMarker);
            const auto r = api_->bucketCall(bucket, c, "list");
            if (!r.ok()) throw padmin::detail::makeError("ListMultipartUploads " + bucket, r, padmin::detail::s3Error(r), api_->secrets());
            pugi::xml_document doc;
            if (!doc.load_string(r.body.c_str())) throw std::runtime_error("ListMultipartUploads: not XML");
            const auto root = doc.child("ListMultipartUploadsResult");
            if (!root) throw std::runtime_error("ListMultipartUploads: no ListMultipartUploadsResult");
            for (const auto u : root.children("Upload")) out.push_back({u.child_value("Key"), u.child_value("UploadId")});
            if (std::string_view(root.child_value("IsTruncated")) != "true") return out;
            keyMarker = root.child_value("NextKeyMarker");
            idMarker = root.child_value("NextUploadIdMarker");
            if (keyMarker.empty()) throw std::runtime_error("ListMultipartUploads: truncated without NextKeyMarker");
        }
        throw std::runtime_error("more than " + std::to_string(kMaxPages) + " upload pages in " + bucket);
    }

private:
    std::unique_ptr<padmin::AdminClient> in_;
    padmin::S3ApiAdmin* api_;   // in_ when it is the real adapter
};

// An EventsClient that touches only test buckets and test queues (both kRunBucketPattern).
class GuardedEvents final : public padmin::EventsClient {
public:
    explicit GuardedEvents(std::unique_ptr<padmin::EventsClient> inner) : in_(std::move(inner)) {}

    [[nodiscard]] std::string providerId() const override { return in_->providerId(); }
    [[nodiscard]] padmin::ChannelRef ensureChannel(const padmin::ChannelSpec& spec) override {
        requireTestBucket(spec.queue_name, "queue");
        return in_->ensureChannel(spec);
    }
    [[nodiscard]] std::vector<std::string> subscribe(const padmin::ChannelRef& channel,
                                                     const padmin::SubscriptionSpec& spec) override {
        requireTestBucket(channel.queue_name, "queue");
        requireTestBucket(spec.bucket);
        return in_->subscribe(channel, spec);
    }
    void unsubscribe(const padmin::ChannelRef& channel, const padmin::SubscriptionSpec& spec,
                     const std::vector<std::string>& ruleIds) override {
        requireTestBucket(channel.queue_name, "queue");
        requireTestBucket(spec.bucket);
        in_->unsubscribe(channel, spec, ruleIds);
    }
    [[nodiscard]] std::vector<padmin::NotificationRule> rules(const std::string& bucket) override {
        requireTestBucket(bucket);
        return in_->rules(bucket);
    }
    void removeChannel(const padmin::ChannelRef& channel) override {
        requireTestBucket(channel.queue_name, "queue");
        in_->removeChannel(channel);
    }
    [[nodiscard]] padmin::PollResult poll(const padmin::ChannelRef& channel, const unsigned int max,
                                          const std::chrono::seconds wait, const std::chrono::seconds visibility) override {
        requireTestBucket(channel.queue_name, "queue");
        return in_->poll(channel, max, wait, visibility);
    }
    void ack(const padmin::ChannelRef& channel, const std::vector<std::string>& receipts) override {
        requireTestBucket(channel.queue_name, "queue");
        in_->ack(channel, receipts);
    }
    void retry(const padmin::ChannelRef& channel, const std::vector<std::string>& receipts,
               const std::chrono::seconds delay) override {
        requireTestBucket(channel.queue_name, "queue");
        in_->retry(channel, receipts, delay);
    }
    [[nodiscard]] std::optional<uint64_t> backlog(const padmin::ChannelRef& channel) override {
        requireTestBucket(channel.queue_name, "queue");
        return in_->backlog(channel);
    }
    [[nodiscard]] padmin::Metrics metrics() const override { return in_->metrics(); }

private:
    std::unique_ptr<padmin::EventsClient> in_;
};

// Cloudflare Queues by NAME, for cleanup and the orphan sweep only: test queues (isRunQueueName) are deleted by name,
// never through a ChannelRef from ensureChannel, because the Queues API is eventually consistent (seen live: a new
// queue missing from the listing and 404 for a few seconds), so a failed ensureChannel leaves queues it can't name.
class QueueAdmin final {
public:
    explicit QueueAdmin(const std::shared_ptr<vault::model::APIKey>& key)
        : token_(key->provider_token), secret_(key->secret_access_key) {
        const auto account = padmin::staticAccountRef(*key);
        if (!account) throw std::invalid_argument("R2 endpoint must be https://<account id>.r2.cloudflarestorage.com");
        account_ = *account;
        if (token_.empty()) throw padmin::CapabilityMissing("events.queues", padmin::kCloudflareTokenHint);
    }

    // Every queue of the account: (name, id). Read-only.
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> list() {
        std::vector<std::pair<std::string, std::string>> out;
        for (int page = 1; page <= kMaxPages; ++page) {
            const auto result = api("GET", "/queues?page=" + std::to_string(page) + "&per_page=100");
            if (!result.is_array() || result.empty()) break;
            for (const auto& q : result) out.emplace_back(q.value("queue_name", ""), q.value("queue_id", ""));
            if (result.size() < 100) break;
        }
        return out;
    }

    // Deletes the named test queue if it is listed. Returns whether it was listed.
    bool remove(const std::string& name) {
        requireTestQueue(name);
        for (const auto& [n, id] : list())
            if (n == name && !id.empty()) {
                (void)api("DELETE", "/queues/" + id);
                return true;
            }
        return false;
    }

    // Deletes the named test queues, retrying until the listing no longer shows them (it lags); throws if it still
    // does after about a minute.
    void removeUntilGone(const std::vector<std::string>& names) {
        for (const auto& n : names) requireTestQueue(n);
        std::string last;
        for (int attempt = 0; attempt < 15; ++attempt) {
            try {
                bool any = false;
                for (const auto& n : names) any = remove(n) || any;
                if (!any) return;
            } catch (const std::exception& e) {
                last = e.what();
            }
            std::this_thread::sleep_for(std::chrono::seconds{4});
        }
        throw std::runtime_error("test queues still listed after a minute" + (last.empty() ? "" : ": " + last));
    }

private:
    nlohmann::json api(const std::string& method, const std::string& path) {
        storage::s3::curl::http::Request request;
        request.method = method;
        request.url = "https://api.cloudflare.com/client/v4/accounts/" + account_ + path;
        request.timeout = std::chrono::seconds{30};
        request.headers.emplace_back("Authorization", "Bearer " + token_);
        const auto r = storage::s3::curl::http::perform(request);
        const auto what = "Cloudflare API " + method + " " + path.substr(0, path.find('?'));
        if (!r.transport_ok) throw std::runtime_error(what + ": " + r.transport_error);
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(r.body);
        } catch (const nlohmann::json::exception&) {
            throw std::runtime_error(what + ": HTTP " + std::to_string(r.status) + ", not JSON");
        }
        if (!r.ok() || !body.value("success", false)) {
            std::string message = body.dump();
            for (const auto* s : {&token_, &secret_})
                for (std::size_t p; !s->empty() && (p = message.find(*s)) != std::string::npos;)
                    message.replace(p, s->size(), "[REDACTED]");
            throw std::runtime_error(what + ": HTTP " + std::to_string(r.status) + " " + message.substr(0, 300));
        }
        return body.contains("result") ? body["result"] : nlohmann::json();
    }

    std::string token_, secret_, account_;
};

inline std::unique_ptr<GuardedAdmin> guardedAdmin(const std::shared_ptr<vault::model::APIKey>& key) {
    return std::make_unique<GuardedAdmin>(std::make_unique<padmin::R2Admin>(key));
}

// Throws CapabilityMissing without VH_CF_API_TOKEN (R2Events needs the Cloudflare REST API).
inline std::unique_ptr<GuardedEvents> guardedEvents(const std::shared_ptr<vault::model::APIKey>& key) {
    return std::make_unique<GuardedEvents>(std::make_unique<padmin::R2Events>(key));
}

// What admin::adminFor / eventsFor hand out while a live test runs: guarded clients for the live credential only.
inline padmin::Factory guardedFactory(const Target& t) {
    const auto same = [t](const std::shared_ptr<vault::model::APIKey>& key) {
        if (!key || key->access_key != t.access || key->endpoint != t.endpoint)
            violate("a provider client for a credential other than the live test credential");
    };
    return padmin::Factory{
        .admin = [same](const std::shared_ptr<vault::model::APIKey>& key) -> std::unique_ptr<padmin::AdminClient> {
            same(key);
            return guardedAdmin(key);
        },
        .events = [same](const std::shared_ptr<vault::model::APIKey>& key) -> std::unique_ptr<padmin::EventsClient> {
            same(key);
            return guardedEvents(key);
        }};
}

// ---- cleanup ----------------------------------------------------------------------------------------------------------

// Removes everything under prefix in a test bucket: unfinished multipart uploads are aborted, objects deleted (R2 has
// no versions). Returns how many objects + uploads it removed; throws if anything is left.
inline std::size_t emptyUnder(GuardedAdmin& admin, const std::shared_ptr<vault::model::APIKey>& key,
                              const std::string& bucket, const std::string& prefix) {
    requireTestBucket(bucket);
    std::size_t removed = 0;
    for (int round = 0; round < 5; ++round) {
        const auto uploads = admin.uploadsUnder(bucket, prefix);
        const auto objects = admin.objectsUnder(bucket, prefix);
        if (uploads.empty() && objects.empty()) return removed;
        if (!uploads.empty()) {
            const storage::s3::Controller data(key, bucket);
            for (const auto& u : uploads) data.abortMultipartUpload(u.key, u.upload_id);
        }
        if (!objects.empty()) {
            const auto failed = admin.deleteObjects(bucket, objects);
            if (!failed.empty())
                throw std::runtime_error("could not delete " + std::to_string(failed.size()) + " object(s) in " + bucket +
                                         ", first: " + failed.front().first + " (" + failed.front().second + ")");
        }
        removed += uploads.size() + objects.size();
    }
    throw std::runtime_error("objects keep appearing under '" + prefix + "' in " + bucket);
}

// Empties and deletes a test bucket (retried: a provider can briefly still report it non-empty), then waits until
// HeadBucket says it is gone. Throws on failure. The only place a test deletes a bucket.
inline void emptyAndDeleteBucket(GuardedAdmin& admin, const std::shared_ptr<vault::model::APIKey>& key,
                                 const std::string& bucket) {
    requireTestBucket(bucket);
    if (!admin.headBucket(bucket)) return;
    for (int attempt = 1;; ++attempt) {
        try {
            (void)emptyUnder(admin, key, bucket, "");
            admin.deleteBucket(bucket);
            break;
        } catch (const GuardViolation&) {
            throw;
        } catch (const std::exception& e) {
            if (attempt >= 5) throw;
            std::cerr << "[live] deleting " << bucket << ", attempt " << attempt << ": " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds{2 * attempt});
        }
    }
    for (int i = 0; i < 15 && admin.headBucket(bucket); ++i) std::this_thread::sleep_for(std::chrono::seconds{1});
    if (admin.headBucket(bucket)) throw std::runtime_error("bucket " + bucket + " still exists after DeleteBucket");
}

// Removes every event-notification rule on a test bucket, by rule id (the bucket is test-owned, so all of them are the
// test's; GuardedEvents still refuses a queue outside the pattern). A rule left behind makes R2 refuse DeleteBucket
// (409 "still has a notification configuration") and the queue's deletion. Retries while R2's listing catches up.
inline void removeEventRules(GuardedEvents& events, const std::string& bucket) {
    requireTestBucket(bucket);
    for (int attempt = 1;; ++attempt) {
        try {
            std::vector<std::pair<padmin::ChannelRef, std::vector<std::string>>> byQueue;
            for (const auto& r : events.rules(bucket)) {
                auto it = std::ranges::find_if(byQueue, [&](const auto& q) { return q.first.queue_ref == r.destination; });
                if (it == byQueue.end()) {
                    padmin::ChannelRef c;
                    c.queue_ref = r.destination;
                    c.queue_name = r.destination_name;
                    byQueue.push_back({c, {}});
                    it = std::prev(byQueue.end());
                }
                it->second.push_back(r.id);
            }
            if (byQueue.empty()) return;
            for (const auto& [channel, ids] : byQueue)
                events.unsubscribe(channel, {.bucket = bucket, .rule_id = "vaulthalla-live", .prefix = ""}, ids);
            std::cout << "[live] removed the event rules of " << bucket << std::endl;
        } catch (const GuardViolation&) {
            throw;
        } catch (const std::exception& e) {
            if (attempt >= 6) throw;
            std::cerr << "[live] event rules of " << bucket << ", attempt " << attempt << ": " << e.what() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds{3});
        if (attempt >= 6) throw std::runtime_error("event rules keep being listed on " + bucket);
    }
}

// ---- the run's one bucket ---------------------------------------------------------------------------------------------

// Created on the first live test (after the orphan sweep), deleted by finish() from the global test environment.
class RunBucket {
public:
    static RunBucket& get() {
        static RunBucket instance;
        return instance;
    }

    // The bucket name, creating it first if needed. Throws (with the reason) when the account isn't usable.
    const std::string& ensure() {
        std::scoped_lock lock(mutex_);
        if (!error_.empty()) throw std::runtime_error(error_);
        if (created_) return runBucketName();
        try {
            const auto t = target();
            key_ = apiKey(t);
            admin_ = guardedAdmin(key_);
            sweep();
            if (admin_->headBucket(runBucketName())) throw std::runtime_error(runBucketName() + " already exists");
            attempted_ = true;
            admin_->createBucket({.name = runBucketName(), .region = std::nullopt});
            if (!admin_->headBucket(runBucketName())) throw std::runtime_error("HeadBucket can't see the new bucket");
            created_ = true;
            std::cout << "[live] created " << runBucketName() << std::endl;
        } catch (const std::exception& e) {
            error_ = std::string("VH_R2_ADMIN_* are set, but the live run can't start: ") + e.what();
            throw std::runtime_error(error_);
        }
        return runBucketName();
    }

    [[nodiscard]] GuardedAdmin& admin() { return *admin_; }
    [[nodiscard]] const std::shared_ptr<vault::model::APIKey>& key() const { return key_; }

    // Empties and deletes the bucket if this run created (or tried to create) it. Returns an error, empty if gone.
    std::string finish() {
        std::scoped_lock lock(mutex_);
        if (!attempted_ || finished_) return {};
        finished_ = true;
        try {
            if (!key_->provider_token.empty()) {
                removeEventRules(*guardedEvents(key_), runBucketName());
                QueueAdmin(key_).removeUntilGone({runBucketName(), runBucketName() + "-dlq"});
            }
            emptyAndDeleteBucket(*admin_, key_, runBucketName());
            std::cout << "[live] deleted " << runBucketName() << " (HeadBucket: gone)" << std::endl;
            return {};
        } catch (const std::exception& e) {
            return "deleting the run bucket " + runBucketName() + " failed: " + e.what();
        }
    }

    // Exactly what the sweep would delete now, from a list of names.
    [[nodiscard]] static std::vector<std::string> orphans(const std::vector<std::string>& names, const std::time_t now) {
        std::vector<std::string> out;
        for (const auto& n : names)
            if (isOrphan(n, now)) out.push_back(n);
        return out;
    }

private:
    void sweep() {
        std::vector<std::string> names;
        std::string token;
        for (int page = 0; page < kMaxPages; ++page) {
            const auto p = admin_->listBuckets(token, 1000);
            for (const auto& b : p.buckets) names.push_back(b.name);
            token = p.next_token;
            if (token.empty()) break;
        }
        const auto now = std::time(nullptr);
        const auto stale = orphans(names, now);
        const bool events = !key_->provider_token.empty();
        for (const auto& name : stale) {
            if (events) removeEventRules(*guardedEvents(key_), name);   // R2 refuses to delete a bucket with rules
            emptyAndDeleteBucket(*admin_, key_, name);
            std::cout << "[live] swept orphaned test bucket " << name << std::endl;
        }
        std::size_t queues = 0;
        if (events) {
            QueueAdmin q(key_);
            std::vector<std::string> staleQueues;
            for (const auto& [name, id] : q.list()) {
                const auto base = name.ends_with("-dlq") ? name.substr(0, name.size() - 4) : name;
                if (isRunQueueName(name) && isOrphan(base, now)) staleQueues.push_back(name);
            }
            if (!staleQueues.empty()) q.removeUntilGone(staleQueues);
            queues = staleQueues.size();
        }
        std::cout << "[live] orphan sweep: " << stale.size() << " bucket(s), " << queues << " queue(s) removed" << std::endl;
    }

    std::mutex mutex_;
    std::shared_ptr<vault::model::APIKey> key_;
    std::unique_ptr<GuardedAdmin> admin_;
    std::string error_;
    bool attempted_ = false, created_ = false, finished_ = false;
};

// Deletes the run bucket after the last test, whatever happened; a bucket that is still there fails the run.
class RunBucketEnvironment final : public ::testing::Environment {
public:
    void TearDown() override {
        if (const auto error = RunBucket::get().finish(); !error.empty()) ADD_FAILURE() << "[live] " << error;
    }
};

// ---- the fixture ------------------------------------------------------------------------------------------------------

// A live test: skipped unless VH_LIVE_TESTS=1 and VH_R2_ADMIN_* are set; fails if they are only partly set or the
// account isn't usable. It works in bucket() under prefix(), which TearDown empties and checks.
class LiveR2Test : public ::testing::Test {
protected:
    void SetUp() override {
        if (!optedIn()) GTEST_SKIP() << "live R2 tests are opt-in: set VH_LIVE_TESTS=1 (and VH_R2_ADMIN_*)";
        t_ = target();
        if (t_.unset()) GTEST_SKIP() << "VH_LIVE_TESTS=1 but VH_R2_ADMIN_* are not set";
        if (!t_.configured()) {
            std::string names;
            for (const auto& m : t_.missing) names += (names.empty() ? "" : ", ") + m;
            FAIL() << "VH_R2_ADMIN_* partially set; missing: " << names;
        }
        try {
            bucket_ = RunBucket::get().ensure();
        } catch (const std::exception& e) {
            FAIL() << e.what();
        }
        (void)takeViolations();
        padmin::setFactoryForTesting(guardedFactory(t_));
        active_ = true;
        prefix_ = testPrefix();
        data_ = std::make_shared<storage::s3::Controller>(RunBucket::get().key(), bucket_);
    }

    void TearDown() override {
        if (!active_) return;
        data_.reset();
        try {
            const auto removed = emptyUnder(admin(), RunBucket::get().key(), bucket_, prefix_);
            if (removed) std::cout << "[live] removed " << removed << " object(s)/upload(s) under " << prefix_ << std::endl;
            EXPECT_TRUE(admin().objectsUnder(bucket_, prefix_).empty() && admin().uploadsUnder(bucket_, prefix_).empty())
                << "[live] " << prefix_ << " not empty after cleanup";
        } catch (const std::exception& e) {
            ADD_FAILURE() << "[live] cleanup of " << prefix_ << " failed: " << e.what();
        }
        padmin::setFactoryForTesting(std::nullopt);
        storage::upstream::guard::clearForTesting();
        for (const auto& v : takeViolations()) ADD_FAILURE() << "live bucket guard: " << v;
    }

    [[nodiscard]] const std::string& bucket() const { return bucket_; }
    [[nodiscard]] const std::string& prefix() const { return prefix_; }
    [[nodiscard]] std::string key(const std::string_view relative) const { return prefix_ + std::string(relative); }
    [[nodiscard]] storage::s3::Controller& controller() { return *data_; }
    // The same controller, shared (a CloudEngine under test holds it; the opaque_v1 data plane, #369).
    [[nodiscard]] const std::shared_ptr<storage::s3::Controller>& sharedController() const { return data_; }
    [[nodiscard]] GuardedAdmin& admin() { return RunBucket::get().admin(); }
    [[nodiscard]] const std::shared_ptr<vault::model::APIKey>& apiKey() const { return RunBucket::get().key(); }
    [[nodiscard]] const Target& liveTarget() const { return t_; }

private:
    Target t_;
    std::string bucket_, prefix_;
    std::shared_ptr<storage::s3::Controller> data_;
    bool active_ = false;
};


// ---- Backblaze B2 (spec 06 §8.3; test_live_b2.cpp) ----------------------------------------------------------------

struct B2Target {
    std::string key_id, app_key;
    std::vector<std::string> missing;   // names of the unset variables (never values)
    [[nodiscard]] bool configured() const { return missing.empty(); }
    [[nodiscard]] bool unset() const { return missing.size() == 2; }
};

inline B2Target b2Target() {
    B2Target t;
    const auto read = [&](const char* name, std::string& out) {
        out = env(name);
        if (out.empty()) t.missing.emplace_back(name);
    };
    read("VH_B2_TEST_KEY_ID", t.key_id);
    read("VH_B2_TEST_APP_KEY", t.app_key);
    return t;
}

// The account as b2_authorize_account describes it.
struct B2Account {
    std::string account_id, api_url, token, s3_url, region;
};

// The region of a B2 S3 endpoint: https://s3.<region>.backblazeb2.com.
inline std::string b2RegionOf(const std::string& s3Url) {
    static const std::regex re(R"(^https://s3\.([a-z0-9-]+)\.backblazeb2\.com/?$)");
    std::smatch m;
    if (!std::regex_match(s3Url, m, re)) throw std::runtime_error("unexpected B2 S3 endpoint: " + s3Url);
    return m[1];
}

struct B2FileVersion {
    std::string name, id, action;   // action: upload | hide | start (an unfinished large file) | folder
};

// B2's native API for a test bucket's administration: every bucket-scoped call checks the name first (refusing every
// bucket that isn't a vh-test-* test bucket before anything is sent); the account listing is a read. The secrets are
// redacted from every error.
class GuardedB2 final {
public:
    // Authorizes (one b2_authorize_account).
    explicit GuardedB2(const B2Target& t, storage::s3::curl::http::Transport transport = {})
        : transport_(std::move(transport)), keyId_(t.key_id), appKey_(t.app_key) {
        storage::s3::curl::http::Request request;
        request.url = "https://api.backblazeb2.com/b2api/v3/b2_authorize_account";
        request.timeout = std::chrono::seconds{30};
        const auto basic = t.key_id + ":" + t.app_key;
        request.headers.emplace_back("Authorization",
                                     "Basic " + crypto::util::b64_encode(std::vector<uint8_t>(basic.begin(), basic.end())));
        const auto body = parse(send(request), "b2_authorize_account");
        account_.account_id = body.value("accountId", "");
        account_.token = body.value("authorizationToken", "");
        const auto storage = body.at("apiInfo").at("storageApi");
        account_.api_url = storage.value("apiUrl", "");
        account_.s3_url = storage.value("s3ApiUrl", "");
        account_.region = b2RegionOf(account_.s3_url);
        if (storage.contains("allowed") && storage["allowed"].contains("buckets") && storage["allowed"]["buckets"].is_array() &&
            !storage["allowed"]["buckets"].empty())
            throw std::runtime_error("the B2 key is restricted to buckets: live tests create and delete their own");
    }
    // For the guard's self-tests: a given account, a recording transport.
    GuardedB2(B2Account account, storage::s3::curl::http::Transport transport)
        : transport_(std::move(transport)), account_(std::move(account)) {}

    [[nodiscard]] const B2Account& account() const { return account_; }

    // The data plane's credential: the same application key over the S3 API.
    [[nodiscard]] std::shared_ptr<vault::model::APIKey> s3Key() const {
        return std::make_shared<vault::model::APIKey>(0, "live-b2", vault::model::S3Provider::BackblazeB2, keyId_, appKey_,
                                                      account_.region, account_.s3_url);
    }

    // Every bucket of the account (read-only).
    [[nodiscard]] std::vector<std::string> listBucketNames() {
        std::vector<std::string> out;
        for (const auto& b : api("b2_list_buckets", {{"accountId", account_.account_id}}).value("buckets", nlohmann::json::array()))
            out.push_back(b.value("bucketName", ""));
        return out;
    }
    [[nodiscard]] std::optional<std::string> bucketId(const std::string& bucket) {
        requireTestBucket(bucket);
        const auto r = api("b2_list_buckets", {{"accountId", account_.account_id}, {"bucketName", bucket}});
        for (const auto& b : r.value("buckets", nlohmann::json::array()))
            if (b.value("bucketName", "") == bucket) return b.value("bucketId", "");
        return std::nullopt;
    }
    // A private bucket whose default lifecycle keeps every version (B2's default).
    void createBucket(const std::string& bucket) {
        requireTestBucket(bucket);
        (void)api("b2_create_bucket", {{"accountId", account_.account_id}, {"bucketName", bucket}, {"bucketType", "allPrivate"}});
    }
    // Every version, hide marker and unfinished large file under prefix, all pages.
    [[nodiscard]] std::vector<B2FileVersion> versionsUnder(const std::string& bucket, const std::string& prefix) {
        requireTestBucket(bucket);
        const auto id = bucketId(bucket);
        if (!id) return {};
        std::vector<B2FileVersion> out;
        nlohmann::json start = nullptr, startId = nullptr;
        for (int page = 0; page < kMaxPages; ++page) {
            nlohmann::json q{{"bucketId", *id}, {"prefix", prefix}, {"maxFileCount", 1000}};
            if (!start.is_null()) q["startFileName"] = start;
            if (!startId.is_null()) q["startFileId"] = startId;
            const auto r = api("b2_list_file_versions", q);
            for (const auto& f : r.value("files", nlohmann::json::array()))
                out.push_back({f.value("fileName", ""), f.value("fileId", ""), f.value("action", "")});
            start = r.contains("nextFileName") ? r["nextFileName"] : nlohmann::json(nullptr);
            startId = r.contains("nextFileId") ? r["nextFileId"] : nlohmann::json(nullptr);
            if (start.is_null()) return out;
        }
        throw std::runtime_error("more than " + std::to_string(kMaxPages) + " version pages in " + bucket);
    }
    void deleteVersion(const std::string& bucket, const B2FileVersion& v) {
        requireTestBucket(bucket);
        if (v.action == "start") (void)api("b2_cancel_large_file", {{"fileId", v.id}});
        else (void)api("b2_delete_file_version", {{"fileName", v.name}, {"fileId", v.id}});
    }
    void removeBucket(const std::string& bucket) {
        requireTestBucket(bucket);
        const auto id = bucketId(bucket);
        if (!id) return;
        (void)api("b2_delete_bucket", {{"accountId", account_.account_id}, {"bucketId", *id}});
    }

private:
    storage::s3::curl::http::Response send(const storage::s3::curl::http::Request& request) const {
        return transport_ ? transport_(request) : storage::s3::curl::http::perform(request);
    }

    nlohmann::json parse(const storage::s3::curl::http::Response& r, const std::string& what) const {
        if (!r.transport_ok) throw std::runtime_error(what + ": " + r.transport_error);
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(r.body);
        } catch (const nlohmann::json::exception&) {
            throw std::runtime_error(what + ": HTTP " + std::to_string(r.status) + ", not JSON");
        }
        if (!r.ok()) {
            std::string message = body.dump();
            for (const auto* secret : {&appKey_, &account_.token})
                for (std::size_t p; !secret->empty() && (p = message.find(*secret)) != std::string::npos;)
                    message.replace(p, secret->size(), "[REDACTED]");
            throw std::runtime_error(what + ": HTTP " + std::to_string(r.status) + " " + message.substr(0, 300));
        }
        return body;
    }

    nlohmann::json api(const std::string& op, const nlohmann::json& body) {
        storage::s3::curl::http::Request request;
        request.method = "POST";
        request.url = account_.api_url + "/b2api/v3/" + op;
        request.timeout = std::chrono::seconds{30};
        request.headers.emplace_back("Authorization", account_.token);
        request.headers.emplace_back("Content-Type", "application/json");
        request.body = body.dump();
        return parse(send(request), op);
    }

    storage::s3::curl::http::Transport transport_;
    std::string keyId_, appKey_;
    B2Account account_;
};

// Deletes every version, hide marker and unfinished large file under prefix of a test bucket. Returns how many; throws
// if anything is left after a few rounds.
inline std::size_t emptyB2Under(GuardedB2& b2, const std::string& bucket, const std::string& prefix) {
    requireTestBucket(bucket);
    std::size_t removed = 0;
    for (int round = 0; round < 5; ++round) {
        const auto versions = b2.versionsUnder(bucket, prefix);
        if (versions.empty()) return removed;
        for (const auto& v : versions) b2.deleteVersion(bucket, v);
        removed += versions.size();
    }
    throw std::runtime_error("versions keep appearing under '" + prefix + "' in " + bucket);
}

// Empties a test bucket of every version and deletes it, then checks it is gone. The only place a B2 bucket is deleted.
inline void emptyAndDeleteB2Bucket(GuardedB2& b2, const std::string& bucket) {
    requireTestBucket(bucket);
    if (!b2.bucketId(bucket)) return;
    for (int attempt = 1;; ++attempt) {
        try {
            (void)emptyB2Under(b2, bucket, "");
            b2.removeBucket(bucket);
            break;
        } catch (const GuardViolation&) {
            throw;
        } catch (const std::exception& e) {
            if (attempt >= 5) throw;
            std::cerr << "[live] deleting " << bucket << ", attempt " << attempt << ": " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds{2 * attempt});
        }
    }
    for (int i = 0; i < 15 && b2.bucketId(bucket); ++i) std::this_thread::sleep_for(std::chrono::seconds{1});
    if (b2.bucketId(bucket)) throw std::runtime_error("bucket " + bucket + " still exists after b2_delete_bucket");
}

// The run's one B2 bucket (named like the R2 one: B2 names are global, the pattern carries host, pid and start).
class RunB2Bucket {
public:
    static RunB2Bucket& get() {
        static RunB2Bucket instance;
        return instance;
    }

    const std::string& ensure() {
        std::scoped_lock lock(mutex_);
        if (!error_.empty()) throw std::runtime_error(error_);
        if (created_) return runBucketName();
        try {
            b2_ = std::make_unique<GuardedB2>(b2Target());
            const auto now = std::time(nullptr);
            std::size_t swept = 0;
            for (const auto& name : b2_->listBucketNames())
                if (isOrphan(name, now)) {
                    emptyAndDeleteB2Bucket(*b2_, name);
                    std::cout << "[live] swept orphaned test bucket " << name << std::endl;
                    ++swept;
                }
            std::cout << "[live] orphan sweep: " << swept << " bucket(s) removed" << std::endl;
            if (b2_->bucketId(runBucketName())) throw std::runtime_error(runBucketName() + " already exists");
            attempted_ = true;
            b2_->createBucket(runBucketName());
            if (!b2_->bucketId(runBucketName())) throw std::runtime_error("b2_list_buckets can't see the new bucket");
            created_ = true;
            std::cout << "[live] created " << runBucketName() << " (" << b2_->account().region << ")" << std::endl;
        } catch (const std::exception& e) {
            error_ = std::string("VH_B2_TEST_* are set, but the live run can't start: ") + e.what();
            throw std::runtime_error(error_);
        }
        return runBucketName();
    }

    [[nodiscard]] GuardedB2& b2() { return *b2_; }

    std::string finish() {
        std::scoped_lock lock(mutex_);
        if (!attempted_ || finished_) return {};
        finished_ = true;
        try {
            emptyAndDeleteB2Bucket(*b2_, runBucketName());
            std::cout << "[live] deleted " << runBucketName() << " and every version in it (gone)" << std::endl;
            return {};
        } catch (const std::exception& e) {
            return "deleting the run bucket " + runBucketName() + " failed: " + e.what();
        }
    }

private:
    std::mutex mutex_;
    std::unique_ptr<GuardedB2> b2_;
    std::string error_;
    bool attempted_ = false, created_ = false, finished_ = false;
};

class RunB2BucketEnvironment final : public ::testing::Environment {
public:
    void TearDown() override {
        if (const auto error = RunB2Bucket::get().finish(); !error.empty()) ADD_FAILURE() << "[live] " << error;
    }
};

// A live B2 test: skipped unless VH_LIVE_TESTS=1 and VH_B2_TEST_* are set; fails if they are only partly set or the
// account isn't usable. TearDown deletes every version under the test's prefix and checks.
class LiveB2Test : public ::testing::Test {
protected:
    void SetUp() override {
        if (!optedIn()) GTEST_SKIP() << "live B2 tests are opt-in: set VH_LIVE_TESTS=1 (and VH_B2_TEST_*)";
        const auto t = b2Target();
        if (t.unset()) GTEST_SKIP() << "VH_LIVE_TESTS=1 but VH_B2_TEST_* are not set";
        if (!t.configured()) {
            std::string names;
            for (const auto& m : t.missing) names += (names.empty() ? "" : ", ") + m;
            FAIL() << "VH_B2_TEST_* partially set; missing: " << names;
        }
        try {
            bucket_ = RunB2Bucket::get().ensure();
        } catch (const std::exception& e) {
            FAIL() << e.what();
        }
        (void)takeViolations();
        active_ = true;
        prefix_ = testPrefix();
        data_ = std::make_shared<storage::s3::Controller>(b2().s3Key(), bucket_);
    }

    void TearDown() override {
        if (!active_) return;
        data_.reset();
        try {
            const auto removed = emptyB2Under(b2(), bucket_, prefix_);
            if (removed) std::cout << "[live] removed " << removed << " version(s) under " << prefix_ << std::endl;
            EXPECT_TRUE(b2().versionsUnder(bucket_, prefix_).empty()) << "[live] " << prefix_ << " not empty after cleanup";
        } catch (const std::exception& e) {
            ADD_FAILURE() << "[live] cleanup of " << prefix_ << " failed: " << e.what();
        }
        for (const auto& v : takeViolations()) ADD_FAILURE() << "live bucket guard: " << v;
    }

    [[nodiscard]] const std::string& bucket() const { return bucket_; }
    [[nodiscard]] const std::string& prefix() const { return prefix_; }
    [[nodiscard]] storage::s3::Controller& controller() { return *data_; }
    [[nodiscard]] const std::shared_ptr<storage::s3::Controller>& sharedController() const { return data_; }
    [[nodiscard]] GuardedB2& b2() { return RunB2Bucket::get().b2(); }

private:
    std::string bucket_, prefix_;
    std::shared_ptr<storage::s3::Controller> data_;
    bool active_ = false;
};

}
