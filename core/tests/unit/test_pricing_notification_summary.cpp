// pricing.notifications.list carries a `summary` of the OPEN alerts (unacknowledged, not expired) the caller can
// see: open_count and worst_severity, from one aggregate query (#172). The console bell used to fetch 50 rows every
// minute and compute its badge from them, so it couldn't shrink the page without a short page hiding an older,
// worse alert. These tests hold the summary to the list's scoping and keep it independent of `limit`.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Pricing.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace vh::test_pricing_notification_summary {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
namespace budget = storage::s3::pricing;

std::string pnTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

TEST(PricingNotificationSummaryRank, RanksTheSeveritiesTheTableAccepts) {
    EXPECT_GT(budget::priceBudgetNotificationSeverityRank("critical"), budget::priceBudgetNotificationSeverityRank("error"));
    EXPECT_GT(budget::priceBudgetNotificationSeverityRank("error"), budget::priceBudgetNotificationSeverityRank("warning"));
    EXPECT_GT(budget::priceBudgetNotificationSeverityRank("warning"), budget::priceBudgetNotificationSeverityRank("info"));
    EXPECT_GT(budget::priceBudgetNotificationSeverityRank("info"), 0);
    EXPECT_EQ(budget::priceBudgetNotificationSeverityRank("bogus"), 0);

    budget::PriceBudgetNotificationSummary total;
    budget::mergePriceBudgetNotificationSummary(total, {.open_count = 0, .worst_severity = std::nullopt});
    EXPECT_EQ(total.open_count, 0u);
    EXPECT_FALSE(total.worst_severity);
    budget::mergePriceBudgetNotificationSummary(total, {.open_count = 2, .worst_severity = "warning"});
    budget::mergePriceBudgetNotificationSummary(total, {.open_count = 1, .worst_severity = "critical"});
    budget::mergePriceBudgetNotificationSummary(total, {.open_count = 4, .worst_severity = "error"});
    EXPECT_EQ(total.open_count, 7u);
    EXPECT_EQ(total.worst_severity, std::optional<std::string>{"critical"});
    EXPECT_EQ(json(total), (json{{"open_count", 7}, {"worst_severity", "critical"}}));
    EXPECT_EQ(json(budget::PriceBudgetNotificationSummary{}), (json{{"open_count", 0}, {"worst_severity", nullptr}}));
}

class PricingNotificationSummaryTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;

    static UserPtr seedUser(const std::string& prefix, const std::string& roleName = "unprivileged") {
        const auto name = prefix + "_" + pnTag();
        auto user = vh::test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test", "x", std::nullopt);
        return vh::identities::manager().user(user->id);
    }

    static uint32_t vaultFor(const UserPtr& owner) {
        return ops::vaults::create(superUser, {.name = "pn_" + pnTag(), .type = vault::model::VaultType::Local,
                                               .owner_id = owner->id})->id;
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_pricing_notification_summary] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_pn_summary_" + pnTag());
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

        superUser = seedUser("pn_super", "super_admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        db::Transactions::exec("test_pricing_notification_summary::reset", [](pqxx::work& txn) {
            txn.exec("DELETE FROM operator_notification");
        });
    }

    static budget::PriceBudgetNotification notify(const std::optional<uint32_t> vaultId, const std::string& severity,
                                                  const std::optional<std::string>& expiresAt = std::nullopt) {
        budget::PriceBudgetNotification n;
        n.type = "budget.summary_test";
        n.severity = severity;
        n.title = "summary test " + severity;
        n.message = "summary test";
        n.vault_id = vaultId;
        n.expires_at = expiresAt;
        return budget::PriceBudgetService{}.createNotification(std::move(n));
    }

    static json list(const UserPtr& user, json payload) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return protocols::ws::handler::Pricing::notificationsList(payload, s);
    }

    static json summary(uint32_t count, const std::optional<std::string>& worst) {
        return {{"open_count", count}, {"worst_severity", worst ? json(*worst) : json(nullptr)}};
    }
};

TEST_F(PricingNotificationSummaryTest, CountsOpenAlertsIndependentOfLimitAndKeepsTheOldestWorst) {
    const auto vault = vaultFor(superUser);
    // The worst open alert is the OLDEST one: a page of the newest rows would never contain it.
    (void)notify(vault, "error");
    for (int i = 0; i < 11; ++i) (void)notify(vault, i % 2 ? "warning" : "info");
    // Worse, but not open: acknowledged or expired rows never count and never set the tone.
    const auto acked = notify(vault, "critical");
    (void)budget::PriceBudgetService{}.acknowledgeNotification(acked.id, superUser->id);
    (void)notify(vault, "critical", std::string{"2000-01-01 00:00:00+00"});

    const auto page = list(superUser, {{"limit", 3}});
    EXPECT_EQ(page.at("notifications").size(), 3u);
    EXPECT_EQ(page.at("summary"), summary(12, "error"));

    // The summary describes open alerts even when the page includes acknowledged rows.
    const auto withAcked = list(superUser, {{"limit", 500}, {"include_acknowledged", true}});
    EXPECT_EQ(withAcked.at("notifications").size(), 13u);
    EXPECT_EQ(withAcked.at("summary"), summary(12, "error"));

    EXPECT_EQ(list(superUser, {{"vault_id", vault}, {"limit", 1}}).at("summary"), summary(12, "error"));
}

TEST_F(PricingNotificationSummaryTest, NothingOpenIsZeroAndNull) {
    const auto vault = vaultFor(superUser);
    EXPECT_EQ(list(superUser, json::object()).at("summary"), summary(0, std::nullopt));
    EXPECT_EQ(list(superUser, nullptr).at("summary"), summary(0, std::nullopt));

    const auto acked = notify(vault, "critical");
    (void)budget::PriceBudgetService{}.acknowledgeNotification(acked.id, superUser->id);
    (void)notify(vault, "warning", std::string{"2000-01-01 00:00:00+00"});
    EXPECT_EQ(list(superUser, json::object()).at("summary"), summary(0, std::nullopt));
    EXPECT_EQ(list(superUser, {{"vault_id", vault}}).at("summary"), summary(0, std::nullopt));
}

TEST_F(PricingNotificationSummaryTest, VaultFilterScopesTheSummary) {
    const auto a = vaultFor(superUser);
    const auto b = vaultFor(superUser);
    (void)notify(a, "critical");
    (void)notify(b, "warning");
    (void)notify(b, "info");
    (void)notify(std::nullopt, "error");  // system-wide: only in the unfiltered super-admin view

    EXPECT_EQ(list(superUser, {{"vault_id", b}}).at("summary"), summary(2, "warning"));
    EXPECT_EQ(list(superUser, {{"vault_id", a}}).at("summary"), summary(1, "critical"));
    EXPECT_EQ(list(superUser, json::object()).at("summary"), summary(4, "critical"));
}

TEST_F(PricingNotificationSummaryTest, NonSuperAdminsSummarizeOnlyVaultsTheyCanView) {
    const auto owner = seedUser("pn_owner");
    const auto hidden = vaultFor(superUser);
    const auto mine = vaultFor(owner);
    (void)notify(hidden, "critical");
    (void)notify(std::nullopt, "critical");
    (void)notify(mine, "warning");
    (void)notify(mine, "info");

    const auto all = list(owner, {{"limit", 1}});
    EXPECT_EQ(all.at("notifications").size(), 1u);
    EXPECT_EQ(all.at("summary"), summary(2, "warning")) << "a hidden vault or a system-wide alert leaked into the summary";
    EXPECT_EQ(list(owner, {{"vault_id", mine}}).at("summary"), summary(2, "warning"));
    EXPECT_THROW((void)list(owner, {{"vault_id", hidden}}), ops::Denied);
}

}
