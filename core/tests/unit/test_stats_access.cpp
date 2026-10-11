// Who may read stats (#166) and what the stats payloads promise (#160).
//
// #166: system stats used to be gated on User::isAdmin() ("can delete admins AND remove admin vaults"), which the
// built-in `admin` role lacks, so it could not see Health. They now need admin.stats.view, and a vault's own stats
// are open to its owner (or an admin with view + view_stats on it), never to anyone else.
// #160: 24 h trends read the same rollups as 7 d (never more points), unknown amounts are null rather than fake
// zeros, counts carry numeric_value, money carries numeric_value + currency, and hrefs are console routes.

#include "../helpers/identities.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/stats/MetricSamples.hpp"
#include "db/query/stats/Snapshot.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Stats.hpp"
#include "ops/Vaults.hpp"
#include "preview/cache/Maintenance.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Stats.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "stats/model/CacheStats.hpp"
#include "stats/model/DashboardOverview.hpp"
#include "stats/model/StatsTrends.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <regex>
#include <set>
#include <string>

namespace vh::test_stats_access {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using rbac::role::Admin;

std::string statsTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

std::shared_ptr<protocols::ws::Session> sessionFor(const UserPtr& user) {
    auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    s->user = user;
    return s;
}

// A user that exists only in memory, holding `role` (the system gate needs no DB).
UserPtr inMemoryUser(const Admin& role) {
    return test::identities::detachedUser(4343, "stats_access_" + role.name, std::make_shared<Admin>(role));
}

bool granted(const Admin& role, const std::string& qualified) {
    for (const auto& p : role.toPermissions())
        if (p.qualified_name == qualified) return p.value.value_or(false);
    ADD_FAILURE() << qualified << " is not exported";
    return false;
}

// ---------------------------------------------------------------------------------------------------------------
// The permission itself (no DB)
// ---------------------------------------------------------------------------------------------------------------

TEST(StatsPermission, IsExportedAsAdminStatsViewAtAStableBit) {
    bool found = false;
    for (const auto& p : Admin::None().toPermissions()) {
        if (p.qualified_name != "admin.stats.view") continue;
        found = true;
        // Persisted in admin_role.stats_permissions bit 0 (migration 105): never renumber.
        EXPECT_EQ(p.bit_position, 0u);
        EXPECT_FALSE(p.value.value_or(false));
        EXPECT_NE(std::ranges::find(p.flags, "--allow-stats-view"), p.flags.end());
    }
    EXPECT_TRUE(found);
    EXPECT_EQ(Admin::SuperAdmin().stats.toBitString(), "00000001");
}

TEST(StatsPermission, BuiltInRolesThatWatchHealthHoldIt) {
    const std::set<std::string> watchers{"admin", "auditor", "platform_operator", "super_admin"};
    for (const auto& role : {Admin::None(), Admin::Auditor(), Admin::Support(), Admin::IdentityAdmin(),
                             Admin::SecurityAdmin(), Admin::PlatformOperator(), Admin::VaultAdmin(), Admin::OrgAdmin(),
                             Admin::SuperAdmin(), Admin::KeyCustodian()}) {
        SCOPED_TRACE(role.name);
        EXPECT_EQ(granted(role, "admin.stats.view"), watchers.contains(role.name));
        EXPECT_EQ(ops::stats::canViewSystem(inMemoryUser(role)), watchers.contains(role.name));
    }
}

// The bug: the built-in admin role fails isAdmin() (it cannot delete admins), so it could not see Health. The gate
// no longer asks isAdmin(), and isAdmin() itself is unchanged (S3 policy bypass and the resolvers still use it).
TEST(StatsPermission, TheBuiltInAdminRolePassesTheGateWithoutBeingAFullAdmin) {
    const auto admin = inMemoryUser(Admin::OrgAdmin());
    EXPECT_FALSE(admin->isAdmin());
    EXPECT_TRUE(ops::stats::canViewSystem(admin));
    EXPECT_NO_THROW(ops::stats::requireSystem(admin, "system health"));

    const auto support = inMemoryUser(Admin::Support());
    EXPECT_FALSE(ops::stats::canViewSystem(support));
    EXPECT_THROW(ops::stats::requireSystem(support, "system health"), ops::Denied);
    EXPECT_THROW(ops::stats::requireSystem(nullptr, "system health"), ops::Denied);

    // Granting just the stats bit is enough; nothing else of the old gate is needed.
    auto custom = Admin::None();
    custom.stats = rbac::permission::admin::Stats::ViewOnly();
    EXPECT_TRUE(ops::stats::canViewSystem(inMemoryUser(custom)));
}

TEST(StatsPermission, WsSystemGatesRefuseWithDeniedWithoutTheBit) {
    const auto s = sessionFor(inMemoryUser(Admin::Support()));
    EXPECT_THROW((void)protocols::ws::handler::Stats::dashboardOverview(json::object(), s), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::Stats::dashboardSeverity(s), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::Stats::systemHealth(s), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::Stats::systemTrends(json::object(), s), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::Stats::systemPricing(s), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::Stats::pricingBudget(json::object(), s), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::Stats::fsCache(s), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::Stats::httpCache(s), ops::Denied);
}

// #160: a cache without a byte cap (the FS metadata cache) reports capacity/free as null, never "0 B of 0 B".
TEST(StatsPayloads, CacheCapacityIsNullWhenTheCacheHasNoCap) {
    stats::model::CacheStatsSnapshot unbounded;
    unbounded.used_bytes = 17;
    const json a = unbounded;
    EXPECT_TRUE(a.at("capacity_bytes").is_null());
    EXPECT_TRUE(a.at("free_bytes").is_null());
    EXPECT_EQ(a.at("used_bytes"), 17);

    stats::model::CacheStatsSnapshot bounded;
    bounded.used_bytes = 1024;
    bounded.capacity_bytes = 10ull << 30;
    const json b = bounded;
    EXPECT_EQ(b.at("capacity_bytes"), 10ull << 30);
    EXPECT_EQ(b.at("free_bytes"), (10ull << 30) - 1024);
}

// ---------------------------------------------------------------------------------------------------------------
// DB-backed: real users, roles and vaults
// ---------------------------------------------------------------------------------------------------------------

class StatsAccessTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser, orgAdmin, auditor, vaultAdmin, support, alice, bob;
    inline static uint32_t aliceVault = 0, bobVault = 0;

    static UserPtr createUser(const std::string& prefix, const std::string& roleName) {
        const auto name = prefix + "_" + statsTag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test");
    }

    static uint32_t vaultFor(const UserPtr& owner) {
        return ops::vaults::create(superUser, {.name = "sa_" + statsTag(), .type = vault::model::VaultType::Local,
                                               .owner_id = owner->id})->id;
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_stats_access] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_stats_access_" + statsTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);

        superUser = createUser("sa_super", "super_admin");
        orgAdmin = createUser("sa_admin", "admin");
        auditor = createUser("sa_auditor", "auditor");
        vaultAdmin = createUser("sa_vault_admin", "vault_admin");
        support = createUser("sa_support", "support");
        alice = createUser("sa_alice", "unprivileged");
        bob = createUser("sa_bob", "unprivileged");
        aliceVault = vaultFor(alice);
        bobVault = vaultFor(bob);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static bool allowed(const std::function<void()>& fn) {
        try {
            fn();
            return true;
        } catch (const ops::Denied&) {
            return false;
        }
    }

    // Every vault-scoped stats command, by name, for one vault.
    static std::vector<std::pair<std::string, std::function<void(const std::shared_ptr<protocols::ws::Session>&)>>>
    vaultCommands(const uint32_t vaultId) {
        using H = protocols::ws::handler::Stats;
        const json p{{"vault_id", vaultId}};
        return {
            {"stats.vault.sync", [p](const auto& s) { (void)H::vaultSync(p, s); }},
            {"stats.vault.activity", [p](const auto& s) { (void)H::vaultActivity(p, s); }},
            {"stats.vault.shares", [p](const auto& s) { (void)H::vaultShares(p, s); }},
            {"stats.vault.recovery", [p](const auto& s) { (void)H::vaultRecovery(p, s); }},
            {"stats.vault.operations", [p](const auto& s) { (void)H::vaultOperations(p, s); }},
            {"stats.vault.storage", [p](const auto& s) { (void)H::vaultStorage(p, s); }},
            {"stats.vault.retention", [p](const auto& s) { (void)H::vaultRetention(p, s); }},
            {"stats.vault.trends", [p](const auto& s) { (void)H::vaultTrends(p, s); }},
            {"stats.vault.security", [p](const auto& s) { (void)H::vaultSecurity(p, s); }},
            {"stats.vault.pricing", [p](const auto& s) { (void)H::vaultPricing(p, s); }},
            {"stats.pricing.budget{vault_id}", [p](const auto& s) { (void)H::pricingBudget(p, s); }},
        };
    }

    static bool systemAllowed(const UserPtr& user) {
        const auto s = sessionFor(user);
        using H = protocols::ws::handler::Stats;
        const std::vector<std::function<void()>> calls{
            [&] { (void)H::dashboardSeverity(s); },
            [&] { (void)H::systemHealth(s); },
            [&] { (void)H::systemTrends(json{{"window_hours", 24}}, s); },
            [&] { (void)H::systemRetention(s); },
            [&] { (void)H::fsCache(s); },
            [&] { (void)H::httpCache(s); },
            [&] { (void)H::pricingBudget(json::object(), s); },
        };
        std::size_t passed = 0;
        for (const auto& call : calls) passed += allowed(call) ? 1 : 0;
        EXPECT_TRUE(passed == 0 || passed == calls.size()) << user->name() << ": system stats gates disagree";
        return passed == calls.size();
    }
};

TEST_F(StatsAccessTest, TheBuiltInAdminRoleNowSeesSystemStats) {
    ASSERT_FALSE(orgAdmin->isAdmin()) << "the admin role is still not a full admin; only the stats gate moved";
    EXPECT_TRUE(systemAllowed(orgAdmin));
    EXPECT_TRUE(systemAllowed(auditor));
    EXPECT_TRUE(systemAllowed(superUser));
}

TEST_F(StatsAccessTest, RolesWithoutStatsViewAreRefusedSystemStats) {
    EXPECT_FALSE(systemAllowed(support));
    EXPECT_FALSE(systemAllowed(vaultAdmin));
    EXPECT_FALSE(systemAllowed(alice));
}

TEST_F(StatsAccessTest, APlainUserSeesTheirOwnVaultStatsAndNoOneElses) {
    const auto s = sessionFor(alice);
    for (const auto& [name, call] : vaultCommands(aliceVault)) {
        SCOPED_TRACE(name + " own vault");
        EXPECT_TRUE(allowed([&] { call(s); }));
    }
    for (const auto& [name, call] : vaultCommands(bobVault)) {
        SCOPED_TRACE(name + " someone else's vault");
        EXPECT_FALSE(allowed([&] { call(s); }));
    }
    // A vault that does not exist is refused the same way (no existence oracle).
    for (const auto& [name, call] : vaultCommands(987654)) {
        SCOPED_TRACE(name + " missing vault");
        EXPECT_FALSE(allowed([&] { call(s); }));
    }
}

TEST_F(StatsAccessTest, VaultStatsFollowTheAdminVaultPermissionsNotStatsView) {
    // vault_admin: admin.vaults.*.view + view_stats, no admin.stats.view.
    for (const auto& [name, call] : vaultCommands(bobVault)) {
        SCOPED_TRACE(name);
        EXPECT_TRUE(allowed([&] { call(sessionFor(vaultAdmin)); }));
        // support has view + view_stats on every vault scope too (Vaults::ViewOnly).
        EXPECT_TRUE(allowed([&] { call(sessionFor(support)); }));
    }
    EXPECT_TRUE(ops::stats::canViewVault(orgAdmin, aliceVault));
    EXPECT_FALSE(ops::stats::canViewVault(bob, aliceVault));
    EXPECT_FALSE(ops::stats::canViewVault(nullptr, aliceVault));
}

// #160 payload shapes against a live (idle) test database.
TEST_F(StatsAccessTest, OverviewPayloadUsesConsoleRoutesNumericValuesAndNoFakeMoney) {
    const auto overview = stats::model::DashboardOverview::snapshot();
    const json payload = overview;
    ASSERT_FALSE(overview.cards.empty());

    const std::regex consoleRoute{R"(^/(health(/(runtime|filesystem|storage|activity))?|cost)(#[a-z-]+)?$)"};
    const std::regex plainCount{R"(^\d+$)"};
    const std::regex currency{R"(^[A-Z]{3}$)"};
    for (const auto& section : payload.at("sections")) EXPECT_TRUE(std::regex_match(section.at("href").get<std::string>(), consoleRoute)) << section.dump();
    for (const auto& card : payload.at("cards")) {
        SCOPED_TRACE(card.at("id").get<std::string>());
        EXPECT_TRUE(std::regex_match(card.at("href").get<std::string>(), consoleRoute)) << card.at("href");
        EXPECT_LE(card.at("series").size(), stats::model::kDashboardOverviewMaxSeriesPerCard);
        for (const auto& series : card.at("series"))
            EXPECT_LE(series.at("points").size(), stats::model::kDashboardOverviewMaxPointsPerSeries);
        for (const auto& metric : card.at("metrics")) {
            SCOPED_TRACE(metric.dump());
            const auto value = metric.at("value").get<std::string>();
            if (std::regex_match(value, plainCount)) {
                ASSERT_TRUE(metric.at("numeric_value").is_number());
                EXPECT_EQ(metric.at("numeric_value").get<double>(), std::stod(value));
            }
            const auto& unit = metric.at("unit");
            if (unit.is_string() && std::regex_match(unit.get<std::string>(), currency)) {
                // Money: a number plus its currency, or unknown with a null number. Never "0.00000000 USD".
                if (value == "unknown") EXPECT_TRUE(metric.at("numeric_value").is_null());
                else EXPECT_TRUE(metric.at("numeric_value").is_number());
                EXPECT_EQ(value.find("0.00000000"), std::string::npos);
            }
        }
        for (const auto& issue : card.at("warnings")) EXPECT_TRUE(std::regex_match(issue.at("href").get<std::string>(), consoleRoute));
    }
    for (const auto& item : payload.at("attention")) EXPECT_TRUE(std::regex_match(item.at("href").get<std::string>(), consoleRoute));
}

TEST_F(StatsAccessTest, MonthlySpendIsUnknownWithoutAMonthlyBudget) {
    // No price budget policies in this database: spend is not measured.
    const auto stats = protocols::ws::handler::Stats::pricingBudget(json::object(), sessionFor(superUser)).at("stats");
    EXPECT_TRUE(stats.at("current_monthly_spend").is_null());
    EXPECT_TRUE(stats.at("projected_monthly_spend").is_null());

    stats::model::DashboardOverviewRequest request;
    request.cards.push_back({.id = "system.pricing_budget", .variant = "tiles", .size = "2x1"});
    const json card = stats::model::DashboardOverview::snapshot(request).cards.at(0);
    for (const auto& metric : card.at("metrics")) {
        const auto key = metric.at("key").get<std::string>();
        if (key != "monthly_spend" && key != "projected_monthly") continue;
        EXPECT_EQ(metric.at("value"), "unknown") << metric.dump();
        EXPECT_EQ(metric.at("tone"), "unknown") << metric.dump();
        EXPECT_TRUE(metric.at("numeric_value").is_null()) << metric.dump();
        EXPECT_EQ(metric.at("unit"), "USD") << metric.dump();
    }
}

TEST_F(StatsAccessTest, FsCacheCapacityIsUnknownAndThePreviewCacheCapIsReported) {
    const auto fs = protocols::ws::handler::Stats::fsCache(sessionFor(superUser)).at("stats");
    EXPECT_TRUE(fs.at("capacity_bytes").is_null()) << fs.dump();
    EXPECT_TRUE(fs.at("free_bytes").is_null()) << fs.dump();

    stats::model::DashboardOverviewRequest request;
    request.cards.push_back({.id = "system.fs_cache", .variant = "tiles", .size = "2x1"});
    const json card = stats::model::DashboardOverview::snapshot(request).cards.at(0);
    for (const auto& metric : card.at("metrics")) {
        const auto key = metric.at("key").get<std::string>();
        if (key != "capacity" && key != "free" && key != "occupancy") continue;
        EXPECT_EQ(metric.at("value"), "unknown") << metric.dump();
        EXPECT_TRUE(metric.at("numeric_value").is_null()) << metric.dump();
    }

    // caching.max_size_mb caps the preview (derived artifact) cache, reported from boot rather than only after the
    // first 15-minute eviction pass.
    preview::cache::applyConfig();
    const auto http = protocols::ws::handler::Stats::httpCache(sessionFor(superUser)).at("stats");
    EXPECT_EQ(http.at("capacity_bytes"), static_cast<std::uint64_t>(config::Registry::get().caching.max_size_mb) << 20)
        << http.dump();
}

// #160: 24 h trends read the same 5-minute rollups as 7 d, so the shorter window can never return more points.
TEST_F(StatsAccessTest, ShortTrendWindowsAreRolledUpLikeTheSevenDayWindow) {
    const auto key = "claude_test_rollup_" + statsTag();
    const auto now = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    // Three hours of samples ten seconds apart: what the 24 h window used to return one point for each.
    db::query::stats::SampleBatch batch;
    for (std::uint64_t t = now - 3 * 3600; t <= now; t += 10) {
        db::query::stats::MetricSample sample;
        sample.metricKey = key;
        sample.seriesLabel = "Rollup test";
        sample.unit = "count";
        sample.snapshotType = "system.test";
        sample.windowStart = t - 10;
        sample.windowEnd = t;
        sample.windowSeconds = 10;
        sample.valueAvg = static_cast<double>(t % 97);
        sample.valueLast = sample.valueAvg;
        batch.metrics.push_back(std::move(sample));
    }
    const auto raw = batch.metrics.size();
    db::query::stats::MetricSamples::insertBatch(batch);

    const auto pointsFor = [&](const std::uint32_t hours) -> std::vector<stats::model::StatsTrendPoint> {
        const auto trends = db::query::stats::Snapshot::systemTrends(hours);
        if (!trends) return {};
        for (const auto& series : trends->series)
            if (series.key == key) return series.points;
        return {};
    };
    const auto day = pointsFor(24);
    const auto week = pointsFor(168);

    ASSERT_FALSE(day.empty());
    EXPECT_LE(day.size(), week.size());
    EXPECT_LE(day.size(), 3u * 3600u / 300u + 2u) << "the 24 h window is not rolled up (" << raw << " raw samples)";
    for (std::size_t i = 1; i < day.size(); ++i) EXPECT_GE(day[i].createdAt - day[i - 1].createdAt, 300u);

    // Same data, shorter window: never the bigger payload (it was 642 KB vs 166 KB on the lab).
    EXPECT_LE(json(*db::query::stats::Snapshot::systemTrends(24)).dump().size(),
              json(*db::query::stats::Snapshot::systemTrends(168)).dump().size());
}

}
