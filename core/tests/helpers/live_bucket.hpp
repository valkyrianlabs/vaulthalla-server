#pragma once

// The ONE way a test reaches a real S3/R2 provider (.claude/context/testing.md, "Live provider tests").
//
//  - One shared bucket per provider, provisioned by the maintainer and never by a test. No test creates, deletes or
//    reconfigures a bucket (versioning, lifecycle, locks, notifications, CORS); bucket administration is covered by the
//    fakes (upstream_admin_fakes.hpp, upstream_event_fakes.hpp, the transport seam in test_upstream_providers.cpp).
//      Cloudflare R2: VAULTHALLA_TEST_R2_{ACCESS_KEY,SECRET_ACCESS_KEY,ENDPOINT,REGION,BUCKET} (a bucket-scoped token)
//      AWS S3:        VAULTHALLA_TEST_S3_{ACCESS_KEY,SECRET_ACCESS_KEY,ENDPOINT,REGION,BUCKET} (one dedicated bucket;
//                     unversioned or versioning Enabled, never Suspended)
//    None of a provider's five set: its tests skip. Some set: they fail naming the missing ones. All set but the
//    bucket unreachable: they fail saying so (never a silent skip).
//  - Each test works only under its own prefix vh-test-runs/<host>-<pid>-<start>/<Suite>.<Test>/. The fixture's
//    TearDown removes everything under it (objects; every version and delete marker where the provider has versions;
//    unfinished multipart uploads), also when the test failed or threw, and fails unless the prefix is empty
//    afterwards. R2 has no versions: ListObjectVersions answers 501 NotImplemented, so plain listings are complete.
//  - The first live test of a process sweeps vh-test-runs/ runs older than kStaleAfter (crashed or killed runs).
//    Nothing outside vh-test-runs/ is ever deleted: deleteObjects refuses such keys before anything is sent.
//  - Runtime guard: the admin client a live test gets, and the one Vaulthalla code gets from adminFor() while a live
//    test runs, refuses bucket creation, deletion and configuration, account listings and any other bucket; events
//    clients (queues, notifications) are refused outright. A violation fails the test even when the code under test
//    swallows the exception, and TearDown fails a test that left a key outside vh-test-runs/.
//  - tools/contracts/test_live_bucket_contract.py keeps bucket-provisioning code and credentials out of test code.

#include "storage/s3/Controller.hpp"
#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <pugixml.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

namespace vh::test_support::live {

namespace padmin = storage::s3::provider::admin;

// Every key a live test writes lives under here; the sweep and every delete are confined to it.
inline constexpr std::string_view kRunsRoot = "vh-test-runs/";
// A run prefix whose newest timestamp is older than this belongs to a crashed or killed run.
inline constexpr std::chrono::hours kStaleAfter{6};
// Listing bounds: a test prefix holds a handful of objects; the shared bucket is expected to stay small.
inline constexpr int kMaxPrefixPages = 50;
inline constexpr int kMaxBucketPages = 20;

enum class Provider { R2, Aws };

struct Target {
    Provider provider{Provider::R2};
    std::string label;                              // "r2" | "aws"
    std::string access, secret, endpoint, region, bucket;
    std::vector<std::string> missing;               // names of the unset variables (never values)

    [[nodiscard]] bool configured() const { return missing.empty(); }
    [[nodiscard]] bool unset() const { return missing.size() == 5; }
    [[nodiscard]] std::string variables() const {
        return provider == Provider::R2 ? "VAULTHALLA_TEST_R2_*" : "VAULTHALLA_TEST_S3_*";
    }
};

inline std::string env(const std::string& name) {
    const auto* v = std::getenv(name.c_str());
    return v ? std::string(v) : std::string{};
}

inline Target target(const Provider provider) {
    const std::string base = provider == Provider::R2 ? "VAULTHALLA_TEST_R2_" : "VAULTHALLA_TEST_S3_";
    Target t;
    t.provider = provider;
    t.label = provider == Provider::R2 ? "r2" : "aws";
    const auto read = [&](const char* suffix, std::string& out) {
        out = env(base + suffix);
        if (out.empty()) t.missing.push_back(base + suffix);
    };
    read("ACCESS_KEY", t.access);
    read("SECRET_ACCESS_KEY", t.secret);
    read("ENDPOINT", t.endpoint);
    read("REGION", t.region);
    read("BUCKET", t.bucket);
    return t;
}

inline std::shared_ptr<vault::model::APIKey> apiKey(const Target& t) {
    return std::make_shared<vault::model::APIKey>(
        0, "live-" + t.label,
        t.provider == Provider::R2 ? vault::model::S3Provider::CloudflareR2 : vault::model::S3Provider::AWS, t.access,
        t.secret, t.region, t.endpoint);
}

// ---- prefixes ---------------------------------------------------------------------------------------------------------

inline std::time_t runStarted() {
    static const std::time_t started = std::time(nullptr);
    return started;
}

// [A-Za-z0-9._-] kept, anything else becomes '-'.
inline std::string sanitize(const std::string_view s) {
    std::string out;
    for (const char c : s)
        out += std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-' ? c : '-';
    return out;
}

// <host>-<pid>-<start>: one per test process.
inline const std::string& runId() {
    static const std::string id = [] {
        char host[256] = {};
        if (gethostname(host, sizeof(host) - 1) != 0) host[0] = '\0';
        std::string name(host);
        name = name.substr(0, name.find('.'));
        std::ranges::transform(name, name.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (name.empty()) name = "host";
        return sanitize(name) + "-" + std::to_string(getpid()) + "-" + std::to_string(runStarted());
    }();
    return id;
}

// vh-test-runs/<run>/<Suite>.<Test>/ for the running test.
inline std::string testPrefix() {
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    const std::string test = info ? sanitize(std::string(info->test_suite_name()) + "." + info->name()) : "no-test";
    return std::string(kRunsRoot) + runId() + "/" + test + "/";
}

// The start time in a vh-test-runs/<host>-<pid>-<start>/… key, or nullopt.
inline std::optional<std::time_t> runStartOf(std::string_view key) {
    if (!key.starts_with(kRunsRoot)) return std::nullopt;
    key.remove_prefix(kRunsRoot.size());
    const auto slash = key.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    const auto run = key.substr(0, slash);
    const auto dash = run.rfind('-');
    if (dash == std::string_view::npos || dash + 1 == run.size()) return std::nullopt;
    const auto digits = run.substr(dash + 1);
    long long value = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (ec != std::errc{} || end != digits.data() + digits.size()) return std::nullopt;
    return static_cast<std::time_t>(value);
}

// A key under vh-test-runs/ of a run that started more than kStaleAfter ago (a test process runs minutes, never hours),
// or, for a name without a start time, last modified that long ago. Keys outside vh-test-runs/ are never stale, and a
// key with no known time is kept.
inline bool isStale(const std::string& key, const std::optional<std::time_t> lastModified, const std::time_t now) {
    if (!key.starts_with(kRunsRoot)) return false;
    const auto when = runStartOf(key) ? runStartOf(key) : lastModified;
    return when && *when + std::chrono::duration_cast<std::chrono::seconds>(kStaleAfter).count() < now;
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

// Records the violation (so a caller that swallows the exception still fails the test) and throws.
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

// An unfinished multipart upload (ListMultipartUploads).
struct Upload {
    std::string key, upload_id;
    std::optional<std::time_t> initiated;
};

// An AdminClient that only does object-level work in the one configured bucket, and deletes only under its prefix.
class GuardedAdmin final : public padmin::AdminClient {
public:
    GuardedAdmin(std::unique_ptr<padmin::AdminClient> inner, std::string bucket, std::string deletablePrefix)
        : in_(std::move(inner)), api_(dynamic_cast<padmin::S3ApiAdmin*>(in_.get())), bucket_(std::move(bucket)),
          deletable_(std::move(deletablePrefix)) {
        if (!deletable_.starts_with(kRunsRoot)) throw std::logic_error("a live prefix must be under vh-test-runs/");
    }

    [[nodiscard]] const std::string& bucket() const { return bucket_; }
    [[nodiscard]] const std::string& deletablePrefix() const { return deletable_; }

    [[nodiscard]] std::string providerId() const override { return in_->providerId(); }
    [[nodiscard]] padmin::AccountIdentity identity() override { return in_->identity(); }
    [[nodiscard]] padmin::Capabilities probe() override { violate("probe (lists the account's buckets)"); }
    [[nodiscard]] padmin::BucketPage listBuckets(const std::string&, unsigned int) override {
        violate("ListBuckets (account-level listing)");
    }
    [[nodiscard]] std::optional<std::string> headBucket(const std::string& bucket) override {
        check(bucket);
        return in_->headBucket(bucket);
    }
    void setKnownRegion(const std::string& bucket, const std::string& region) override { in_->setKnownRegion(bucket, region); }
    void createBucket(const padmin::CreateBucketRequest& request) override { violate("CreateBucket " + request.name); }
    void deleteBucket(const std::string& bucket) override { violate("DeleteBucket " + bucket); }
    [[nodiscard]] padmin::BucketConfiguration inspect(const std::string& bucket) override {
        check(bucket);
        return in_->inspect(bucket);
    }
    void putLifecycle(const std::string& bucket, const std::vector<padmin::LifecycleRule>&) override {
        violate("PutBucketLifecycleConfiguration " + bucket);
    }
    [[nodiscard]] bool supportsVersioning() const override { return in_->supportsVersioning(); }
    [[nodiscard]] padmin::VersioningState versioning(const std::string& bucket) override {
        check(bucket);
        return in_->versioning(bucket);
    }
    void putVersioning(const std::string& bucket, padmin::Versioning) override {
        violate("PutBucketVersioning " + bucket);
    }
    [[nodiscard]] padmin::ObjectPage listObjects(const std::string& bucket, const std::string& token,
                                                 const unsigned int max) override {
        check(bucket);
        return in_->listObjects(bucket, token, max);
    }
    [[nodiscard]] padmin::ObjectPage listObjectVersions(const std::string& bucket, const std::string& token,
                                                        const unsigned int max) override {
        check(bucket);
        return in_->listObjectVersions(bucket, token, max);
    }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> deleteObjects(
        const std::string& bucket, const std::vector<padmin::ObjectSummary>& objects) override {
        check(bucket);
        for (const auto& o : objects) requireDeletable(o.key);
        return in_->deleteObjects(bucket, objects);
    }
    [[nodiscard]] padmin::Metrics metrics() const override { return in_->metrics(); }

    void requireDeletable(const std::string& key) const {
        if (!key.starts_with(kRunsRoot) || !key.starts_with(deletable_))
            violate("delete of '" + key + "' outside " + deletable_);
    }

    // Every object (versions and delete markers too where the provider has versions) under prefix.
    [[nodiscard]] std::vector<padmin::ObjectSummary> listUnder(const std::string& prefix) {
        std::vector<padmin::ObjectSummary> out;
        const bool versions = in_->supportsVersioning();
        std::string token;
        for (int page = 0; page < kMaxPrefixPages; ++page) {
            padmin::ObjectPage p;
            if (!api_) {   // a fake inner client (the guard's self-tests): whole listing, filtered
                p = versions ? in_->listObjectVersions(bucket_, token, 1000) : in_->listObjects(bucket_, token, 1000);
                std::erase_if(p.objects, [&](const auto& o) { return !o.key.starts_with(prefix); });
            } else {
                auto c = versions ? padmin::detail::call("GET", {{"versions", ""}, {"prefix", prefix}, {"max-keys", "1000"}})
                                  : padmin::detail::call("GET", {{"list-type", "2"}, {"prefix", prefix}, {"max-keys", "1000"}});
                if (!token.empty() && versions) {
                    const auto nl = token.find('\n');
                    c.query.emplace_back("key-marker", token.substr(0, nl));
                    if (nl != std::string::npos && nl + 1 < token.size())
                        c.query.emplace_back("version-id-marker", token.substr(nl + 1));
                } else if (!token.empty()) {
                    c.query.emplace_back("continuation-token", token);
                }
                const auto r = api_->bucketCall(bucket_, c, "list");
                if (!r.ok())
                    throw padmin::detail::makeError("List " + prefix, r, padmin::detail::s3Error(r), api_->secrets());
                p = versions ? padmin::detail::parseListObjectVersions(r.body) : padmin::detail::parseListObjectsV2(r.body);
            }
            out.insert(out.end(), p.objects.begin(), p.objects.end());
            token = p.next_token;
            if (token.empty()) return out;
        }
        throw std::runtime_error("more than " + std::to_string(kMaxPrefixPages) + " listing pages under " + prefix);
    }

    // Unfinished multipart uploads under prefix (none for a fake inner client).
    [[nodiscard]] std::vector<Upload> uploadsUnder(const std::string& prefix) {
        std::vector<Upload> out;
        if (!api_) return out;
        std::string keyMarker, idMarker;
        for (int page = 0; page < kMaxPrefixPages; ++page) {
            auto c = padmin::detail::call("GET", {{"uploads", ""}, {"prefix", prefix}});
            if (!keyMarker.empty()) c.query.emplace_back("key-marker", keyMarker);
            if (!idMarker.empty()) c.query.emplace_back("upload-id-marker", idMarker);
            const auto r = api_->bucketCall(bucket_, c, "list");
            if (!r.ok())
                throw padmin::detail::makeError("ListMultipartUploads " + prefix, r, padmin::detail::s3Error(r),
                                                api_->secrets());
            pugi::xml_document doc;
            if (!doc.load_string(r.body.c_str())) throw std::runtime_error("ListMultipartUploads: not XML");
            const auto root = doc.child("ListMultipartUploadsResult");
            if (!root) throw std::runtime_error("ListMultipartUploads: no ListMultipartUploadsResult");
            for (const auto u : root.children("Upload"))
                out.push_back({.key = u.child_value("Key"), .upload_id = u.child_value("UploadId"),
                               .initiated = padmin::detail::parseIsoTime(u.child_value("Initiated"))});
            if (std::string_view(root.child_value("IsTruncated")) != "true") return out;
            keyMarker = root.child_value("NextKeyMarker");
            idMarker = root.child_value("NextUploadIdMarker");
            if (keyMarker.empty()) throw std::runtime_error("ListMultipartUploads: truncated without NextKeyMarker");
        }
        throw std::runtime_error("more than " + std::to_string(kMaxPrefixPages) + " upload pages under " + prefix);
    }

private:
    void check(const std::string& bucket) const {
        if (bucket != bucket_) violate("names bucket '" + bucket + "', not the configured test bucket");
    }

    std::unique_ptr<padmin::AdminClient> in_;
    padmin::S3ApiAdmin* api_;   // in_ when it is a real adapter
    std::string bucket_;
    std::string deletable_;
};

inline std::unique_ptr<GuardedAdmin> guardedAdmin(const Target& t, const std::shared_ptr<vault::model::APIKey>& key,
                                                  const std::string& deletablePrefix) {
    std::unique_ptr<padmin::AdminClient> inner;
    if (t.provider == Provider::R2) inner = std::make_unique<padmin::R2Admin>(key);
    else inner = std::make_unique<padmin::AwsAdmin>(key);
    return std::make_unique<GuardedAdmin>(std::move(inner), t.bucket, deletablePrefix);
}

// What admin::adminFor/eventsFor hand out while a live test runs: the guarded admin client for the test's own
// credential, nothing for any other credential, and never an events client.
inline padmin::Factory guardedFactory(const Target& t, const std::string& deletablePrefix) {
    return padmin::Factory{
        .admin = [t, deletablePrefix](const std::shared_ptr<vault::model::APIKey>& key) -> std::unique_ptr<padmin::AdminClient> {
            if (!key || key->endpoint != t.endpoint || key->access_key != t.access)
                violate("an admin client for a credential other than the live test credential");
            return guardedAdmin(t, key, deletablePrefix);
        },
        .events = [](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::EventsClient> {
            violate("an events client (queues, bucket notifications)");
        }};
}

// ---- removal ----------------------------------------------------------------------------------------------------------

struct Contents {
    std::vector<padmin::ObjectSummary> objects;
    std::vector<Upload> uploads;
    [[nodiscard]] bool empty() const { return objects.empty() && uploads.empty(); }
    [[nodiscard]] std::size_t size() const { return objects.size() + uploads.size(); }
};

inline Contents contentsUnder(GuardedAdmin& admin, const std::string& prefix) {
    return {.objects = admin.listUnder(prefix), .uploads = admin.uploadsUnder(prefix)};
}

// Deletes what `keep` rejects under prefix (every version and marker, unfinished uploads aborted) in bounded rounds.
// Returns what was removed; throws when something could not be removed.
template <typename Select>
Contents removeUnder(GuardedAdmin& admin, const storage::s3::Controller& data, const std::string& prefix, Select select) {
    Contents removed;
    for (int round = 0; round < 5; ++round) {
        auto now = contentsUnder(admin, prefix);
        std::erase_if(now.objects, [&](const auto& o) { return !select(o.key, o.last_modified); });
        std::erase_if(now.uploads, [&](const auto& u) { return !select(u.key, u.initiated); });
        if (now.empty()) return removed;
        for (const auto& u : now.uploads) {
            admin.requireDeletable(u.key);
            data.abortMultipartUpload(u.key, u.upload_id);
        }
        if (!now.objects.empty()) {
            const auto failed = admin.deleteObjects(admin.bucket(), now.objects);
            if (!failed.empty())
                throw std::runtime_error("could not delete " + std::to_string(failed.size()) + " object(s) under " +
                                         prefix + ", first: " + failed.front().first + " (" + failed.front().second + ")");
        }
        removed.objects.insert(removed.objects.end(), now.objects.begin(), now.objects.end());
        removed.uploads.insert(removed.uploads.end(), now.uploads.begin(), now.uploads.end());
    }
    throw std::runtime_error("objects keep appearing under " + prefix + " after 5 removal rounds");
}

// Everything one test writes, removed when it goes out of scope (also during unwinding) and checked to be gone.
class LivePrefix {
public:
    LivePrefix(Target t, std::string prefix)
        : t_(std::move(t)), prefix_(checked(std::move(prefix))), key_(live::apiKey(t_)), admin_(guardedAdmin(t_, key_, prefix_)),
          data_(std::make_unique<storage::s3::Controller>(key_, t_.bucket)) {}
    ~LivePrefix() {
        try {
            (void)cleanup();
        } catch (const std::exception& e) {
            ADD_FAILURE() << "[live] cleanup of " << prefix_ << " failed: " << e.what();
        }
    }
    LivePrefix(const LivePrefix&) = delete;
    LivePrefix& operator=(const LivePrefix&) = delete;

    [[nodiscard]] const Target& target() const { return t_; }
    [[nodiscard]] const std::string& prefix() const { return prefix_; }
    [[nodiscard]] std::string key(const std::string_view relative) const { return prefix_ + std::string(relative); }
    [[nodiscard]] const std::shared_ptr<vault::model::APIKey>& apiKey() const { return key_; }
    [[nodiscard]] GuardedAdmin& admin() { return *admin_; }
    [[nodiscard]] storage::s3::Controller& controller() { return *data_; }

    [[nodiscard]] Contents contents() { return contentsUnder(*admin_, prefix_); }

    // Removes everything under the prefix and fails the test unless it is empty afterwards. Idempotent.
    Contents cleanup() {
        if (cleaned_) return {};
        cleaned_ = true;
        auto removed = removeUnder(*admin_, *data_, prefix_, [](const auto&, const auto&) { return true; });
        const auto left = contents();
        EXPECT_TRUE(left.empty()) << "[live] " << left.size() << " object(s)/upload(s) left under " << prefix_
                                  << (left.objects.empty() ? std::string{} : ", first: " + left.objects.front().key);
        if (!removed.empty())
            std::cout << "[live] removed " << removed.objects.size() << " object(s)/version(s) and "
                      << removed.uploads.size() << " unfinished upload(s) under " << prefix_ << std::endl;
        return removed;
    }

private:
    static std::string checked(std::string prefix) {
        if (!prefix.starts_with(kRunsRoot) || !prefix.ends_with('/') || prefix.size() <= kRunsRoot.size())
            throw std::logic_error("a live prefix is vh-test-runs/<run>/<test>/");
        return prefix;
    }

    Target t_;
    std::string prefix_;
    std::shared_ptr<vault::model::APIKey> key_;
    std::unique_ptr<GuardedAdmin> admin_;
    std::unique_ptr<storage::s3::Controller> data_;
    bool cleaned_ = false;
};

// ---- the session: reachability, sweep, baseline -----------------------------------------------------------------------

struct Session {
    bool ready = false;
    std::string error;
    std::set<std::string> outside;   // keys outside vh-test-runs/ when the first live test started
    bool outsideComplete = false;    // the whole bucket fit in kMaxBucketPages
};

// Keys outside vh-test-runs/ (current objects), and whether the listing was complete.
inline std::pair<std::set<std::string>, bool> keysOutsideRuns(GuardedAdmin& admin) {
    std::set<std::string> out;
    std::string token;
    for (int page = 0; page < kMaxBucketPages; ++page) {
        const auto p = admin.listObjects(admin.bucket(), token, 1000);
        for (const auto& o : p.objects)
            if (!o.key.starts_with(kRunsRoot)) out.insert(o.key);
        token = p.next_token;
        if (token.empty()) return {out, true};
    }
    return {out, false};
}

// Once per provider per process: the bucket answers, stale runs are swept, the keys outside vh-test-runs/ recorded.
inline const Session& session(const Target& t) {
    static std::mutex mutex;
    static std::map<Provider, Session> sessions;
    std::scoped_lock lock(mutex);
    if (const auto it = sessions.find(t.provider); it != sessions.end()) return it->second;
    auto& s = sessions[t.provider];
    try {
        const auto key = apiKey(t);
        const auto admin = guardedAdmin(t, key, std::string(kRunsRoot));
        if (!admin->headBucket(t.bucket)) throw std::runtime_error("HeadBucket says it does not exist");
        const storage::s3::Controller data(key, t.bucket);
        const auto now = std::time(nullptr);
        const auto swept = removeUnder(*admin, data, std::string(kRunsRoot), [&](const std::string& k, const auto& when) {
            return isStale(k, when, now);
        });
        std::set<std::string> runs;
        for (const auto& o : swept.objects) runs.insert(o.key.substr(0, o.key.find('/', kRunsRoot.size()) + 1));
        for (const auto& u : swept.uploads) runs.insert(u.key.substr(0, u.key.find('/', kRunsRoot.size()) + 1));
        std::cout << "[live] " << t.label << ": swept " << swept.size() << " stale object(s)/upload(s) from "
                  << runs.size() << " run(s) older than " << kStaleAfter.count() << " h" << std::endl;
        std::tie(s.outside, s.outsideComplete) = keysOutsideRuns(*admin);
        s.ready = true;
    } catch (const std::exception& e) {
        s.error = t.variables() + " are set, but bucket '" + t.bucket + "' is not usable: " + e.what();
    }
    return s;
}

// ---- the fixture ------------------------------------------------------------------------------------------------------

// Parameterized by provider: INSTANTIATE_TEST_SUITE_P(Live, Suite, ::testing::Values(Provider::R2, Provider::Aws),
// providerName). Tests use live().key(...), live().controller() and live().admin(); nothing else.
class LiveBucketTest : public ::testing::TestWithParam<Provider> {
protected:
    void SetUp() override {
        t_ = target(GetParam());
        if (t_.unset()) GTEST_SKIP() << t_.variables() << " not set: no live " << t_.label << " bucket configured";
        if (!t_.configured()) {
            std::string names;
            for (const auto& m : t_.missing) names += (names.empty() ? "" : ", ") + m;
            FAIL() << t_.variables() << " partially set; missing: " << names;
        }
        const auto& s = session(t_);
        if (!s.ready) FAIL() << s.error;
        (void)takeViolations();
        const auto prefix = testPrefix();
        padmin::setFactoryForTesting(guardedFactory(t_, prefix));
        factoryInstalled_ = true;
        live_ = std::make_unique<LivePrefix>(t_, prefix);
    }

    void TearDown() override {
        live_.reset();   // removes the prefix and checks it is empty, also after a failure
        if (factoryInstalled_) {
            padmin::setFactoryForTesting(std::nullopt);
            storage::upstream::guard::clearForTesting();
            checkNothingOutside();
        }
        for (const auto& v : takeViolations()) ADD_FAILURE() << "live bucket guard: " << v;
    }

    [[nodiscard]] LivePrefix& live() { return *live_; }
    [[nodiscard]] const Target& liveTarget() const { return t_; }

private:
    void checkNothingOutside() {
        const auto& s = session(t_);
        try {
            const auto admin = guardedAdmin(t_, apiKey(t_), std::string(kRunsRoot));
            const auto [now, complete] = keysOutsideRuns(*admin);
            if (!complete || !s.outsideComplete) {
                std::cout << "[live] bucket too large to check for writes outside vh-test-runs/" << std::endl;
                return;
            }
            for (const auto& k : now)
                if (!s.outside.contains(k)) ADD_FAILURE() << "[live] a key appeared outside vh-test-runs/: " << k;
        } catch (const std::exception& e) {
            ADD_FAILURE() << "[live] listing the bucket after the test failed: " << e.what();
        }
    }

    Target t_;
    std::unique_ptr<LivePrefix> live_;
    bool factoryInstalled_ = false;
};

inline std::string providerName(const ::testing::TestParamInfo<Provider>& info) {
    return info.param == Provider::R2 ? "r2" : "aws";
}

}
