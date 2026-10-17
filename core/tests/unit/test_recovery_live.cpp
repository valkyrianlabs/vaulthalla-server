// File recovery, release-blocking acceptance scenario against REAL providers (.claude/context/recovery.md, "Smart
// cache" and "Provider versioning"). The fake-bucket version is RecoverySmartCacheTest; this one runs the same steps
// with a real CloudEngine over a real AWS S3 bucket. Never part of CI: skips unless VH_LIVE_UPSTREAM=1, the provider
// credentials (tests/helpers/upstream_live.hpp) and the test DB (VH_TEST_DB_*) are present. Run it through the
// per-run database runner, which hands exactly the live variables through (testing.md, "Live provider tests"):
//
//   (set -a; . ./.bashrc; set +a; VH_LIVE_UPSTREAM=1 bash bin/tests/run_unit.sh --build-dir build
//        -- --gtest_filter='UpstreamLive.AwsRecovery*:UpstreamLive.R2VersioningRefused')
//
// Buckets: only NEW ones named vaulthalla-test-<unix time>-<random>, created by the admin client and deleted again
// with every version, even on failure. Every admin call goes through a tally that fails the test if it names any other
// bucket or lists the account's buckets.

#include "../helpers/recovery_pricing.hpp"
#include "../helpers/recovery_provider_harness.hpp"
#include "../helpers/upstream_live.hpp"

#include "config/Registry.hpp"

#include "db/query/recovery/ObjectVersion.hpp"
#include "ops/Error.hpp"
#include "ops/Recovery.hpp"
#include "recovery/cost/Report.hpp"
#include "recovery/provider/Policy.hpp"
#include "recovery/usage/Ledger.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/APIKeyManager.hpp"

#include <gtest/gtest.h>

#include <mutex>
#include <numeric>
#include <set>

namespace vh::test_recovery_live {

using namespace test_support::recovery_provider;
namespace live = test_support::live;
namespace padmin = storage::s3::provider::admin;
namespace rec = ops::recovery;
namespace rp = recovery::provider;
using recovery::ItemAction;
using recovery::Mode;
using recovery::ProviderRetention;

// What the admin clients Vaulthalla created during a test did: requests sent, buckets named, account listings.
struct AdminTally {
    std::mutex mutex;
    uint64_t clients = 0, requests = 0, list_buckets = 0;
    padmin::Metrics byKind{};   // list/head/get/put/del of every closed client
    std::set<std::string> buckets;
};

// Forwards to a real adapter and records what it was asked to touch.
class TallyAdmin final : public padmin::AdminClient {
public:
    TallyAdmin(std::unique_ptr<padmin::AdminClient> inner, std::shared_ptr<AdminTally> tally)
        : in_(std::move(inner)), t_(std::move(tally)) {
        std::scoped_lock lock(t_->mutex);
        ++t_->clients;
    }
    ~TallyAdmin() override {
        std::scoped_lock lock(t_->mutex);
        const auto m = in_->metrics();
        t_->requests += m.requests;
        t_->byKind.list += m.list;
        t_->byKind.head += m.head;
        t_->byKind.get += m.get;
        t_->byKind.put += m.put;
        t_->byKind.del += m.del;
    }

    [[nodiscard]] std::string providerId() const override { return in_->providerId(); }
    [[nodiscard]] padmin::AccountIdentity identity() override { return in_->identity(); }
    [[nodiscard]] padmin::Capabilities probe() override {
        listed();
        return in_->probe();
    }
    [[nodiscard]] padmin::BucketPage listBuckets(const std::string& token, const unsigned int max) override {
        listed();
        return in_->listBuckets(token, max);
    }
    [[nodiscard]] std::optional<std::string> headBucket(const std::string& bucket) override {
        touch(bucket);
        return in_->headBucket(bucket);
    }
    void setKnownRegion(const std::string& bucket, const std::string& region) override {
        in_->setKnownRegion(bucket, region);
    }
    void createBucket(const padmin::CreateBucketRequest& request) override {
        touch(request.name);
        in_->createBucket(request);
    }
    void deleteBucket(const std::string& bucket) override {
        touch(bucket);
        in_->deleteBucket(bucket);
    }
    [[nodiscard]] padmin::BucketConfiguration inspect(const std::string& bucket) override {
        touch(bucket);
        return in_->inspect(bucket);
    }
    void putLifecycle(const std::string& bucket, const std::vector<padmin::LifecycleRule>& rules) override {
        touch(bucket);
        in_->putLifecycle(bucket, rules);
    }
    [[nodiscard]] bool supportsVersioning() const override { return in_->supportsVersioning(); }
    [[nodiscard]] padmin::VersioningState versioning(const std::string& bucket) override {
        touch(bucket);
        return in_->versioning(bucket);
    }
    void putVersioning(const std::string& bucket, const padmin::Versioning target) override {
        touch(bucket);
        in_->putVersioning(bucket, target);
    }
    [[nodiscard]] padmin::ObjectPage listObjects(const std::string& bucket, const std::string& token,
                                                 const unsigned int max) override {
        touch(bucket);
        return in_->listObjects(bucket, token, max);
    }
    [[nodiscard]] padmin::ObjectPage listObjectVersions(const std::string& bucket, const std::string& token,
                                                        const unsigned int max) override {
        touch(bucket);
        return in_->listObjectVersions(bucket, token, max);
    }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> deleteObjects(
        const std::string& bucket, const std::vector<padmin::ObjectSummary>& objects) override {
        touch(bucket);
        return in_->deleteObjects(bucket, objects);
    }
    [[nodiscard]] padmin::Metrics metrics() const override { return in_->metrics(); }

private:
    void touch(const std::string& bucket) {
        std::scoped_lock lock(t_->mutex);
        t_->buckets.insert(bucket);
    }
    void listed() {
        std::scoped_lock lock(t_->mutex);
        ++t_->list_buckets;
    }

    std::unique_ptr<padmin::AdminClient> in_;
    std::shared_ptr<AdminTally> t_;
};

// The real adapters behind the tally (setFactoryForTesting is honoured in test mode only).
inline std::shared_ptr<AdminTally> installTallyFactory() {
    auto tally = std::make_shared<AdminTally>();
    padmin::setFactoryForTesting(padmin::Factory{
        .admin = [tally](const std::shared_ptr<vault::model::APIKey>& key) -> std::unique_ptr<padmin::AdminClient> {
            if (padmin::providerIdentity(*key) == "cloudflare-r2")
                return std::make_unique<TallyAdmin>(std::make_unique<padmin::R2Admin>(key), tally);
            return std::make_unique<TallyAdmin>(std::make_unique<padmin::AwsAdmin>(key), tally);
        },
        .events = nullptr});
    return tally;
}

struct Requests {
    uint64_t list = 0, head = 0, get = 0, put = 0, copy = 0, del = 0, down = 0, up = 0;
    [[nodiscard]] std::string str() const {
        return "LIST " + std::to_string(list) + ", HEAD " + std::to_string(head) + ", GET " + std::to_string(get) +
               ", PUT " + std::to_string(put) + ", COPY " + std::to_string(copy) + ", DELETE " + std::to_string(del) +
               ", down " + std::to_string(down) + " B, up " + std::to_string(up) + " B";
    }
};

// Every data-plane request any s3::Controller sent on this thread while it was alive (ops and sync tasks run inline).
class Meter {
public:
    explicit Meter(const std::shared_ptr<storage::CloudEngine>& engine) : capture_(engine) {}
    [[nodiscard]] Requests read() const {
        const auto u = capture_.usage();
        return {u.list_requests, u.head_requests, u.get_requests, u.put_requests, u.copy_requests,
                u.delete_requests, u.downloaded_bytes, u.uploaded_bytes};
    }

private:
    storage::ScopedS3RequestUsageCapture capture_;
};

class LiveRecovery : public ProviderHarness {
public:
    static bool dbReady() {
        static const bool ready = [] {
            SetUpTestSuite();
            return !skipTests;
        }();
        return ready;
    }

    struct AwsVault {
        VFixture f;
        std::string bucket;
        std::string account;
        unsigned keyId = 0;
        std::shared_ptr<vault::model::APIKey> key;
    };

    static std::shared_ptr<storage::CloudEngine> engineOf(const uint32_t vaultId) {
        return std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(vaultId));
    }

    static VFixture refresh(const VFixture& f) {
        auto g = f;
        g.engine = engineOf(f.vault->id);
        return g;
    }

    static unsigned recoveryBlobRows(const uint32_t vaultId) {
        return db::Transactions::exec("LiveRecovery::blobs", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM recovery_blob WHERE vault_id = $1", pqxx::params{vaultId})
                .one_field_ref().as<unsigned>();
        });
    }

    static std::vector<std::filesystem::path> regularFilesUnder(const std::filesystem::path& dir) {
        std::vector<std::filesystem::path> out;
        std::error_code ec;
        for (auto it = std::filesystem::recursive_directory_iterator(dir, ec);
             !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
            if (it->is_regular_file()) out.push_back(it->path());
        return out;
    }

    // Every version/marker of `key` in the bucket, newest first (one admin ListObjectVersions; small test buckets).
    static std::vector<padmin::ObjectSummary> bucketHistory(padmin::AdminClient& admin, const std::string& bucket,
                                                            const std::string& key) {
        std::vector<padmin::ObjectSummary> out;
        for (const auto& o : admin.listObjectVersions(bucket, {}, 1000).objects)
            if (o.key == key) out.push_back(o);
        std::ranges::stable_sort(out, [](const auto& a, const auto& b) {
            if (a.latest != b.latest) return a.latest;
            return a.last_modified.value_or(0) > b.last_modified.value_or(0);
        });
        return out;
    }

    // The real AWS key as an admin-enabled key of the test DB. The account comes from one STS GetCallerIdentity;
    // no capability probe (it would list the account's buckets).
    static unsigned addAwsAdminKey(const std::string& account) {
        auto key = live::liveAwsKey(superUser->id);
        key->name = "live_aws_" + test_support::sync_conflicts::tag();
        const auto& manager = runtime::Deps::get().apiKeyManager;
        const auto id = manager->addAPIKey(key);
        manager->setAdmin(id, true, account, std::nullopt, std::time(nullptr));
        return id;
    }

    // Steps shared by the AWS scenarios: a cache-strategy, encrypt_upstream S3 vault bound to the new test bucket, and
    // provider versioning enabled through ops::recovery (disclosure priced from the signed fixture catalog → update
    // with its token, adopting the vault's own bucket). The 15-minute propagation window is then moved to now (test
    // mode): AWS reads Enabled back at once on a new bucket, and a version id on every PUT is asserted below.
    static void setUpAwsVault(AwsVault& v, padmin::AdminClient& admin, const std::shared_ptr<AdminTally>& tally) {
        v.keyId = addAwsAdminKey(v.account);
        v.key = runtime::Deps::get().apiKeyManager->getAPIKey(v.keyId);
        v.f.vault = ops::vaults::create(superUser, {.name = "live_vault_" + test_support::sync_conflicts::tag(),
                                                    .type = vault::model::VaultType::S3, .owner_id = superUser->id,
                                                    .s3 = ops::vaults::S3Spec{.api_key_id = v.keyId, .bucket = v.bucket,
                                                                              .encrypt_upstream = true}});
        v.f.engine = engineOf(v.f.vault->id);
        const auto policy = v.f.engine->remote_policy();
        policy->strategy = Strategy::Cache;
        policy->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::Ask;
        storage::upstream::guard::reload();

        const ProviderRetention retention{.indefinite = false, .days = 30};
        struct Snap {
            uint64_t clients, requests;
            padmin::Metrics m;
        };
        const auto snap = [&] {
            std::scoped_lock lock(tally->mutex);
            return Snap{tally->clients, tally->requests, tally->byKind};
        };
        const auto delta = [](const Snap& a, const Snap& b) {
            return std::to_string(b.requests - a.requests) + " request(s) over " + std::to_string(b.clients - a.clients) +
                   " client(s) (LIST " + std::to_string(b.m.list - a.m.list) + ", HEAD " +
                   std::to_string(b.m.head - a.m.head) + ", GET " + std::to_string(b.m.get - a.m.get) + ", PUT " +
                   std::to_string(b.m.put - a.m.put) + ", DELETE " + std::to_string(b.m.del - a.m.del) + ")";
        };
        const auto s0 = snap();
        const auto disclosure = rec::versioningDisclosure(superUser, v.f.vault->id, retention);
        const auto s1 = snap();
        std::cout << "[live] disclosure: priced=" << disclosure.report.priced << " phase=" << disclosure.report.phase
                  << " pre_activation_monthly="
                  << (disclosure.report.pre_activation_monthly.expected
                          ? disclosure.report.pre_activation_monthly.expected->amount : std::string("null"))
                  << " acknowledgements=" << disclosure.required_acknowledgements.size() << "; admin "
                  << delta(s0, s1) << std::endl;
        EXPECT_TRUE(disclosure.report.priced) << disclosure.report.unpriced_reason.value_or("");
        rec::Update u;
        u.mode = Mode::ProviderVersioning;
        u.provider_retention = retention;
        u.disclosure_token = disclosure.token;
        u.accept_adoption = true;
        const auto st = rec::update(superUser, v.f.vault->id, u);
        std::cout << "[live] enable: status=" << st.provider.status << " bucket_state=" << st.provider.bucket_state
                  << " enabled_by_vaulthalla=" << st.provider.enabled_by_vaulthalla << "; admin " << delta(s1, snap())
                  << std::endl;
        for (const auto& w : st.warnings) std::cout << "[live] status warning: " << w << std::endl;
        for (const auto& w : st.provider.warnings) std::cout << "[live] provider warning: " << w << std::endl;
        ASSERT_EQ(st.provider.status, "enabled");
        EXPECT_EQ(st.provider.bucket_state, "adopted");
        EXPECT_TRUE(st.provider.enabled_by_vaulthalla);
        EXPECT_FALSE(st.provider.settled) << "AWS asks for 15 minutes";
        EXPECT_EQ(admin.versioning(v.bucket).status, padmin::Versioning::Enabled);

        db::Transactions::exec("LiveRecovery::settle", [&](pqxx::work& txn) {
            txn.exec("UPDATE upstream_bucket SET versioning_settles_at = now() - interval '1 second' "
                     "WHERE provider = 'aws-s3' AND bucket = $1", pqxx::params{v.bucket});
        });
        EXPECT_TRUE(rec::status(superUser, v.f.vault->id).provider.settled);
        v.f = refresh(v.f);
    }

    // Plans one provider version through ops and restores it with the plan's token.
    static recovery::RestoreResult opsRestore(const VFixture& f, const VersionRow& version, const std::string& method,
                                              recovery::Plan* planOut = nullptr) {
        const auto plan = rec::plan(superUser, {.recovery_id = pv(version)});
        EXPECT_EQ(plan.items.size(), 1u);
        EXPECT_TRUE(plan.blockers.empty());
        if (!plan.items.empty()) {
            EXPECT_EQ(plan.items[0].action, ItemAction::Overwrite);
            EXPECT_EQ(plan.items[0].method, method);
        }
        std::cout << "[live] plan " << plan.id << ": " << plan.items.size() << " item(s), method "
                  << (plan.items.empty() ? std::string("-") : plan.items[0].method) << ", estimate GET "
                  << plan.estimate.get_requests << " HEAD " << plan.estimate.head_requests << " PUT "
                  << plan.estimate.put_requests << " COPY " << plan.estimate.copy_requests << ", cost "
                  << (plan.estimate.cost ? plan.estimate.cost->amount + " " + plan.estimate.cost->currency
                                         : "unpriced (" + plan.estimate.unpriced_reason.value_or("?") + ")")
                  << std::endl;
        if (planOut) *planOut = plan;
        (void)f;
        return rec::restore(superUser, {.plan_id = plan.id, .token = plan.token});
    }

    static void smartCache(AwsVault& v, padmin::AdminClient& admin);
    static void acrossKeyRotation(AwsVault& v, padmin::AdminClient& admin);
    static void r2Refused(const std::shared_ptr<AdminTally>& tally);
};

void LiveRecovery::smartCache(AwsVault& v, padmin::AdminClient& admin) {
    auto& f = v.f;
    const std::string path = "/smart/report.txt";
    const std::string key = "smart/report.txt";
    const std::vector<std::string> contents = {"generation zero: the draft", "generation one: the reviewed text",
                                               "generation two: an accidental overwrite", "generation three: worse"};

    // 1. Upload a file (sync pass) and 2. replace it several times, each followed by a pass.
    std::vector<std::string> ivs;
    for (size_t i = 0; i < contents.size(); ++i) {
        put(f, path, contents[i]);
        Meter m(f.engine);
        const auto plan = runPass(f);
        const auto r = m.read();
        std::cout << "[live] step " << (i == 0 ? "1" : "2") << " pass " << i << ": " << r.str() << std::endl;
        ASSERT_EQ(transfers(plan), 1u) << contents[i];
        EXPECT_EQ(r.get, 0u) << "an upload pass downloads nothing";
        EXPECT_EQ(r.copy, 0u);
        ivs.push_back(db::query::fs::File::getFileByPath(f.vault->id, path)->encryption_iv);
    }
    const auto upstream = bucketHistory(admin, v.bucket, key);
    ASSERT_EQ(upstream.size(), contents.size()) << "one provider version per generation";
    for (const auto& o : upstream) EXPECT_TRUE(o.version_id && *o.version_id != "null") << "versioned PUT";
    auto rows = history(f, path);
    ASSERT_EQ(rows.size(), contents.size());
    std::ranges::reverse(rows);   // oldest first
    for (size_t i = 0; i < rows.size(); ++i) {
        EXPECT_EQ(rows[i].origin, "vaulthalla");
        EXPECT_EQ(rows[i].encryption_iv, ivs[i]) << "generation " << i << " indexed with its own IV";
        EXPECT_EQ(rows[i].is_latest, i + 1 == rows.size());
        EXPECT_TRUE(std::ranges::any_of(upstream, [&](const auto& o) { return o.version_id == rows[i].version_id; }))
            << "the index's version id is the provider's: " << rows[i].version_id;
    }

    // 3. Evict the local cached content: the row is index-only.
    evict(f, path);
    const auto backing = backingOf(f, path);
    ASSERT_FALSE(std::filesystem::exists(backing));

    // 4. Enumerate the historical versions (ops list with a provider refresh) without downloading a single body.
    {
        Meter m(f.engine);
        const auto points = rec::list(superUser, f.vault->id, {.path = path, .refresh_provider = true,
                                                               .include_snapshots = false, .include_versions = false});
        const auto r = m.read();
        std::cout << "[live] step 4 list (" << points.size() << " points): " << r.str() << std::endl;
        ASSERT_EQ(points.size(), contents.size());
        EXPECT_EQ(std::ranges::count_if(points, [](const auto& p) { return p.is_current; }), 1);
        EXPECT_EQ(std::ranges::count_if(points, [](const auto& p) { return !p.is_current && p.restorable; }),
                  static_cast<long>(contents.size() - 1));
        EXPECT_GE(r.list, 1u);
        EXPECT_EQ(r.get, 0u) << "no body GET";
        EXPECT_EQ(r.down, 0u);
        EXPECT_EQ(r.head, 0u);
        EXPECT_EQ(r.put + r.copy + r.del, 0u);
    }

    // 5. Restore a selected historical generation (generation one) through ops plan + restore: one provider copy.
    rows = history(f, path);
    std::ranges::reverse(rows);
    const auto chosen = rows[1];
    {
        const auto manifestBefore = bucketHistory(admin, v.bucket, sync::model::remote_manifest::INDEX_V1_KEY).size();
        Meter m(f.engine);
        const auto out = opsRestore(f, chosen, "provider_copy");
        const auto r = m.read();
        const auto manifestPuts = bucketHistory(admin, v.bucket, sync::model::remote_manifest::INDEX_V1_KEY).size() -
                                  manifestBefore;
        std::cout << "[live] step 5 restore: state=" << out.state << " restored=" << out.restored << "; " << r.str()
                  << "; manifest versions written " << manifestPuts << std::endl;
        for (const auto& item : out.items)
            if (item.error) std::cout << "[live] item " << item.destination_path << ": " << *item.error << std::endl;
        ASSERT_EQ(out.state, "done");
        ASSERT_EQ(out.restored, 1u);
        EXPECT_EQ(r.copy, 1u);
        EXPECT_EQ(r.get, 0u);
        EXPECT_EQ(r.down, 0u);
        EXPECT_EQ(r.put, manifestPuts) << "the only PUTs were Vaulthalla's index manifest";
        EXPECT_FALSE(std::filesystem::exists(backing)) << "a cache vault adopts the generation index-only";
    }

    // 6. The restored current file decrypts through the normal read path (hydrate) and is that generation.
    f = refresh(f);
    {
        Meter m(f.engine);
        EXPECT_EQ(readVia(f, path), contents[1]);
        const auto r = m.read();
        std::cout << "[live] step 6 read: " << r.str() << std::endl;
        EXPECT_EQ(r.get, 1u);
        EXPECT_EQ(r.put + r.copy, 0u);
    }

    // 7. Upstream history is all still there, plus one new current version carrying generation one's IV.
    const auto after = bucketHistory(admin, v.bucket, key);
    std::cout << "[live] step 7 ListObjectVersions: " << after.size() << " versions of " << key << std::endl;
    ASSERT_EQ(after.size(), contents.size() + 1);
    for (const auto& r : rows)
        EXPECT_TRUE(std::ranges::any_of(after, [&](const auto& o) { return o.version_id == r.version_id; }))
            << r.version_id;
    const auto indexed = history(f, path);
    ASSERT_EQ(indexed.size(), contents.size() + 1);
    EXPECT_TRUE(indexed.front().is_latest);
    EXPECT_EQ(indexed.front().encryption_iv, ivs[1]);
    EXPECT_TRUE(after.front().latest);
    EXPECT_EQ(after.front().version_id, std::optional<std::string>(indexed.front().version_id));
    EXPECT_EQ(std::ranges::count_if(indexed, [](const auto& r) { return r.is_latest; }), 1);
    {
        storage::s3::Controller data(v.key, v.bucket);
        const auto head = data.headObjectVersion(key, indexed.front().version_id);
        ASSERT_TRUE(head.has_value());
        EXPECT_EQ(head->metadata.at("vh-iv"), ivs[1]) << "the provider copy kept the generation's metadata";
    }

    // 8. No duplicate upload: the next full sync pass transfers nothing and PUTs nothing...
    {
        Meter m(f.engine);
        const auto next = runPass(f);
        const auto r = m.read();
        std::cout << "[live] step 8 pass: " << transfers(next) << " transfer(s); " << r.str() << std::endl;
        EXPECT_EQ(transfers(next), 0u);
        EXPECT_EQ(r.put, 0u);
        EXPECT_EQ(r.copy, 0u);
        EXPECT_EQ(bucketHistory(admin, v.bucket, key).size(), contents.size() + 1);
    }
    // ...and no retained local historical copy: no recovery blobs, only the hydrated current copy on disk.
    EXPECT_EQ(recoveryBlobRows(f.vault->id), 0u);
    const auto files = regularFilesUnder(backing.parent_path());
    std::cout << "[live] step 8 local files under " << backing.parent_path().filename() << ": " << files.size()
              << ", recovery blobs: " << recoveryBlobRows(f.vault->id) << std::endl;
    EXPECT_EQ(files.size(), 1u);
    if (!files.empty()) {
        EXPECT_EQ(files.front(), backing);
    }

    // 9. Cost inputs see the extra historical objects: every superseded version and its bytes; the active cost panel
    // prices the month to date from them.
    const auto summary = db::query::recovery::ObjectVersion::noncurrentSummary(f.vault->id);
    const uint64_t expectedBytes = std::accumulate(contents.begin(), contents.end(), uint64_t{0},
                                                   [](const uint64_t acc, const std::string& c) { return acc + c.size() + 16; });
    std::cout << "[live] step 9 noncurrent: " << summary.versions << " versions, " << summary.bytes << " bytes (expected "
              << contents.size() << ", " << expectedBytes << ")" << std::endl;
    EXPECT_EQ(summary.versions, contents.size());
    EXPECT_EQ(summary.bytes, expectedBytes);
    EXPECT_EQ(summary.unknown_size, 0u);
    EXPECT_EQ(summary.delete_markers, 0u);
    EXPECT_TRUE(summary.oldest_noncurrent_at.has_value());
    (void)recovery::usage::flush();
    const auto costs = rec::costs(superUser, f.vault->id);
    const auto money = [](const recovery::CostFigure& c) {
        return c.expected ? c.expected->amount + " " + c.expected->currency : "null (" + c.reason.value_or("") + ")";
    };
    std::cout << "[live] step 9 costs: phase=" << costs.phase << " priced=" << costs.priced
              << " month_to_date=" << money(costs.current_month_to_date)
              << " month_projected=" << money(costs.current_month_projected)
              << " projected_monthly=" << money(costs.projected_monthly)
              << " history=" << costs.history.known_noncurrent_versions << "/" << costs.history.known_noncurrent_bytes
              << " B; observed put=" << costs.observation.put_requests << " copy=" << costs.observation.copy_requests
              << " overwrite_objects=" << costs.observation.overwrite_objects << std::endl;
    EXPECT_EQ(costs.phase, "active");
    EXPECT_TRUE(costs.priced) << costs.unpriced_reason.value_or("");
    EXPECT_TRUE(costs.current_month_to_date.expected.has_value()) << costs.current_month_to_date.reason.value_or("");
    EXPECT_EQ(costs.history.known_noncurrent_versions, contents.size());
    EXPECT_EQ(costs.history.known_noncurrent_bytes, expectedBytes);
}

void LiveRecovery::acrossKeyRotation(AwsVault& v, padmin::AdminClient& admin) {
    auto& f = v.f;
    const std::string path = "/rot/a.txt";
    const std::string key = "rot/a.txt";
    const std::string first = "sealed under the first key";
    const std::string second = "sealed under the second key";

    put(f, path, first);
    ASSERT_EQ(transfers(runPass(f)), 1u);
    const auto oldKey = f.engine->encryptionManager->get_key_version();
    const auto oldRow = history(f, path).front();
    f.engine->encryptionManager->prepare_key_rotation();
    f.engine->encryptionManager->finish_key_rotation();
    const auto newKey = f.engine->encryptionManager->get_key_version();
    ASSERT_GT(newKey, oldKey);
    put(f, path, second);
    ASSERT_EQ(transfers(runPass(f)), 1u);
    ASSERT_EQ(bucketHistory(admin, v.bucket, key).size(), 2u);
    const auto old = *rowFor(f, path, oldRow.version_id);
    EXPECT_EQ(old.key_version, oldKey);
    evict(f, path);

    {
        const auto manifestBefore = bucketHistory(admin, v.bucket, sync::model::remote_manifest::INDEX_V1_KEY).size();
        Meter m(f.engine);
        const auto out = opsRestore(f, old, "provider_transfer");
        const auto r = m.read();
        const auto manifestPuts = bucketHistory(admin, v.bucket, sync::model::remote_manifest::INDEX_V1_KEY).size() -
                                  manifestBefore;
        std::cout << "[live] rotation restore: state=" << out.state << "; " << r.str() << "; manifest versions written "
                  << manifestPuts << std::endl;
        for (const auto& item : out.items)
            if (item.error) std::cout << "[live] item " << item.destination_path << ": " << *item.error << std::endl;
        ASSERT_EQ(out.state, "done");
        EXPECT_EQ(r.copy, 0u);
        EXPECT_EQ(r.get, 1u);
        EXPECT_EQ(r.put, 1u + manifestPuts) << "one object PUT (re-sealed) + the index manifest";
    }
    f = refresh(f);
    const auto local = db::query::fs::File::getFileByPath(f.vault->id, path);
    EXPECT_EQ(local->encrypted_with_key_version, newKey);
    EXPECT_NE(local->encryption_iv, *old.encryption_iv);
    EXPECT_EQ(readVia(f, path), first);
    const auto after = bucketHistory(admin, v.bucket, key);
    std::cout << "[live] rotation ListObjectVersions: " << after.size() << " versions of " << key << std::endl;
    ASSERT_EQ(after.size(), 3u);
    {
        storage::s3::Controller data(v.key, v.bucket);
        const auto head = data.headObjectVersion(key, *after.front().version_id);
        ASSERT_TRUE(head.has_value());
        EXPECT_EQ(head->metadata.at("vh-key-version"), std::to_string(newKey));
        EXPECT_EQ(head->metadata.at("vh-iv"), local->encryption_iv);
    }
    Meter m(f.engine);
    EXPECT_EQ(transfers(runPass(f)), 0u);
    const auto r = m.read();
    std::cout << "[live] rotation next pass: " << r.str() << std::endl;
    EXPECT_EQ(r.put, 0u);
}

void LiveRecovery::r2Refused(const std::shared_ptr<AdminTally>& tally) {
    // A Cloudflare R2 vault on a fresh test name that is never created: the refusal needs no bucket, and the local
    // snapshot works entirely locally. If anything were sent it would name only this nonexistent test bucket.
    const auto bucket = live::liveTestName();
    auto key = live::liveR2Key(superUser->id);
    key->name = "live_r2_" + test_support::sync_conflicts::tag();
    const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
    runtime::Deps::get().apiKeyManager->setAdmin(keyId, true, std::nullopt, std::nullopt, std::time(nullptr));
    const auto vault = ops::vaults::create(superUser, {.name = "live_r2_vault_" + test_support::sync_conflicts::tag(),
                                                       .type = vault::model::VaultType::S3, .owner_id = superUser->id,
                                                       .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = bucket,
                                                                                 .encrypt_upstream = true}});
    VFixture f{.vault = vault, .engine = engineOf(vault->id), .bucket = nullptr};
    f.engine->remote_policy()->strategy = Strategy::Cache;

    Meter m(f.engine);
    const auto st = rec::status(superUser, vault->id);
    EXPECT_FALSE(st.provider.supported);
    EXPECT_EQ(st.provider.unsupported_reason, padmin::kR2VersioningUnsupported);
    rec::Update u;
    u.mode = Mode::ProviderVersioning;
    u.provider_retention = ProviderRetention{.indefinite = false, .days = 30};
    u.disclosure_token = "v1.0.00";
    u.accept_adoption = true;
    try {
        (void)rec::update(superUser, vault->id, u);
        ADD_FAILURE() << "provider versioning enabled on R2";
    } catch (const ops::Invalid& e) {
        std::cout << "[live] R2 refusal: " << e.what() << std::endl;
        EXPECT_EQ(std::string(e.what()), padmin::kR2VersioningUnsupported);
    }
    EXPECT_THROW((void)rec::versioningDisclosure(superUser, vault->id, ProviderRetention{.indefinite = false, .days = 30}),
                 ops::Invalid);

    // Local snapshots of the same vault still work: snapshot → overwrite → restore the snapshot.
    rec::Update local;
    local.mode = Mode::LocalSnapshots;
    EXPECT_EQ(rec::update(superUser, vault->id, local).mode, Mode::LocalSnapshots);
    put(f, "/notes/today.txt", "before the mistake");
    const auto snap = rec::createSnapshot(superUser, vault->id, {.path = "/notes", .name = std::string("live")});
    std::cout << "[live] R2 snapshot " << snap.point.id << ": restorable=" << snap.point.restorable
              << " files=" << snap.point.file_count.value_or(0) << std::endl;
    EXPECT_TRUE(snap.point.restorable);
    put(f, "/notes/today.txt", "after the mistake");
    const auto plan = rec::plan(superUser, {.recovery_id = snap.point.id});
    EXPECT_TRUE(plan.blockers.empty());
    const auto out = rec::restore(superUser, {.plan_id = plan.id, .token = plan.token});
    EXPECT_EQ(out.state, "done");
    EXPECT_EQ(readVia(f, "/notes/today.txt"), "before the mistake");

    const auto r = m.read();
    std::uint64_t adminRequests = 0, clients = 0;
    {
        std::scoped_lock lock(tally->mutex);
        adminRequests = tally->requests;
        clients = tally->clients;
    }
    std::cout << "[live] R2 data plane: " << r.str() << "; admin clients " << clients << ", admin requests "
              << adminRequests << std::endl;
    EXPECT_EQ(r.list + r.head + r.get + r.put + r.copy + r.del, 0u) << "nothing sent to R2";
    EXPECT_EQ(adminRequests, 0u) << "no admin request sent to R2";
}

namespace {

bool awsGate() {
    if (!live::liveEnabled()) {
        std::cout << "[live] set VH_LIVE_UPSTREAM=1 to run live provider tests" << std::endl;
        return false;
    }
    return !live::liveEnv("VH_AWS_ADMIN_API_KEY").empty();
}

// One AWS scenario on its own new test bucket, with cleanup of every version even on failure.
void runAws(const std::function<void(LiveRecovery::AwsVault&, padmin::AdminClient&)>& scenario) {
    const auto tally = installTallyFactory();
    const auto savedConfig = config::Registry::get();
    struct Restore {
        const config::Config& saved;
        ~Restore() {
            padmin::setFactoryForTesting(std::nullopt);
            vh::recovery::cost::setCatalogStoreForTesting(nullptr);
            config::Registry::set(saved);
        }
    } restoreSeams{savedConfig};
    // Prices from the signed fixture catalog (aws-s3 us-east-2 standard) everywhere: the recovery cost panel and, through
    // the daemon's own on-disk catalog cache, plan estimates and the price preflights of listing and restore.
    vh::recovery::cost::setCatalogStoreForTesting(test_support::recovery_pricing::catalogStore());
    {
        const auto cache = paths::getBackingPath() / "price-cache" / "artifacts";
        std::filesystem::remove_all(cache);
        std::filesystem::create_directories(cache.parent_path());
        std::filesystem::copy(test_support::recovery_pricing::copyFixture(), cache, std::filesystem::copy_options::recursive);
        auto cfg = savedConfig;
        cfg.pricing.enabled = true;
        cfg.pricing.storage_rates_api.remote_refresh_enabled = false;
        cfg.pricing.storage_rates_api.cache_ttl_seconds = 365u * 24 * 3600;
        cfg.pricing.storage_rates_api.refresh_interval_seconds = 365u * 24 * 3600;
        cfg.pricing.storage_rates_api.signature_warning_only = false;
        cfg.pricing.storage_rates_api.signature_public_key_path = cache / "public-key.pem";
        config::Registry::set(cfg);
    }

    LiveRecovery::AwsVault v;
    auto adminKey = live::liveAwsKey();
    padmin::AwsAdmin direct(adminKey);
    v.account = direct.identity().account_ref;
    adminKey->provider_account_id = v.account;
    TallyAdmin admin(std::make_unique<padmin::AwsAdmin>(adminKey), tally);
    v.bucket = live::liveTestName();
    std::cout << "[live] aws-s3 recovery test bucket " << v.bucket << std::endl;
    live::LiveCleanup cleanup{[&] { live::liveDestroyTestBucket(admin, v.bucket); }};
    ASSERT_EQ(admin.headBucket(v.bucket), std::nullopt);
    admin.createBucket({.name = v.bucket, .region = std::string("us-east-2")});

    LiveRecovery::setUpAwsVault(v, admin, tally);
    if (::testing::Test::HasFatalFailure()) return;
    scenario(v, admin);

    std::scoped_lock lock(tally->mutex);
    EXPECT_EQ(tally->list_buckets, 0u) << "the account's buckets were listed";
    for (const auto& b : tally->buckets) EXPECT_EQ(b, v.bucket) << "an admin call named another bucket";
}

}

}

using vh::test_recovery_live::LiveRecovery;

TEST(UpstreamLive, AwsRecoverySmartCache) {
    if (!vh::test_recovery_live::awsGate()) GTEST_SKIP() << "VH_LIVE_UPSTREAM=1 and VH_AWS_ADMIN_* required";
    if (!LiveRecovery::dbReady()) GTEST_SKIP() << "VH_TEST_DB_* not set (run through bin/tests/run_unit.sh)";
    vh::test_recovery_live::runAws([](auto& v, auto& admin) { LiveRecovery::smartCache(v, admin); });
}

TEST(UpstreamLive, AwsRecoveryAcrossKeyRotation) {
    if (!vh::test_recovery_live::awsGate()) GTEST_SKIP() << "VH_LIVE_UPSTREAM=1 and VH_AWS_ADMIN_* required";
    if (!LiveRecovery::dbReady()) GTEST_SKIP() << "VH_TEST_DB_* not set (run through bin/tests/run_unit.sh)";
    vh::test_recovery_live::runAws([](auto& v, auto& admin) { LiveRecovery::acrossKeyRotation(v, admin); });
}

TEST(UpstreamLive, R2VersioningRefused) {
    if (!vh::test_support::live::liveEnabled()) GTEST_SKIP() << "set VH_LIVE_UPSTREAM=1 to run live provider tests";
    if (vh::test_support::live::liveEnv("VH_R2_ADMIN_ACCESS_KEY").empty()) GTEST_SKIP() << "VH_R2_ADMIN_* not set";
    if (!LiveRecovery::dbReady()) GTEST_SKIP() << "VH_TEST_DB_* not set (run through bin/tests/run_unit.sh)";
    const auto tally = vh::test_recovery_live::installTallyFactory();
    LiveRecovery::r2Refused(tally);
    vh::storage::s3::provider::admin::setFactoryForTesting(std::nullopt);
}
