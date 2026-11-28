// Health findings (design/health/findings.md): the catalog covers what the cards raise, the rules for acknowledged
// and silenced marks, who may set them, what the audit trail records, that no agent path can, and the push
// (health.subscribe, health.changed; protocols::ws::HealthNotifier).

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "Mcp.hpp"
#include "audit/Trail.hpp"
#include "db/query/health/FindingState.hpp"
#include "health/Catalog.hpp"
#include "health/Findings.hpp"
#include "identities/User.hpp"
#include "ops/Audit.hpp"
#include "ops/Error.hpp"
#include "ops/Health.hpp"
#include "protocols/ws/HealthNotifier.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Health.hpp"
#include "protocols/ws/handler/Stats.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace vh::test_health_findings {

using json = nlohmann::json;
using health::Active;
using health::Mark;

Active raised(const std::string& code, const std::string& severity) {
    return {.code = code, .subject = "", .cardId = "system.card", .severity = severity, .title = "Card",
            .message = code + " happened"};
}

Mark mark(const std::string& cls, const std::string& state, const std::string& severity,
          const std::optional<std::uint64_t> expiresAt = std::nullopt) {
    return {.cls = cls, .subject = "", .state = state, .severity = severity, .setBy = 1, .setByName = "admin",
            .setAt = 100, .expiresAt = expiresAt};
}

std::string stateOf(const health::Resolution& r, const std::string& code) {
    for (const auto& f : r.findings)
        if (f.raised.code == code) return f.state;
    return "absent";
}

bool stale(const health::Resolution& r, const std::string& code) {
    return std::ranges::find(r.stale, health::Key{code, ""}) != r.stale.end();
}

// ---------------------------------------------------------------------------------------------------------------
// The catalog (no DB)
// ---------------------------------------------------------------------------------------------------------------

// Every code a dashboard card raises is a class in the catalog, and the catalog names no code nothing raises: a new
// finding can't ship without saying whether it notifies and what can be done about it.
TEST(HealthCatalog, CoversEveryCodeTheCardsRaise) {
    // VH_PSQL_TEST_SCHEMAS_PATH is <repository>/deploy/psql.
    const auto source = std::filesystem::path(VH_PSQL_TEST_SCHEMAS_PATH).parent_path().parent_path() /
                        "core/src/stats/model/DashboardOverview.cpp";
    std::ifstream in(source);
    ASSERT_TRUE(in) << source;
    std::stringstream text;
    text << in.rdbuf();
    const auto body = text.str();

    std::set<std::string> raisedCodes;
    const std::regex call(R"re(dashboardOverviewAddIssue\(card, "([a-z_.]+)")re");
    for (auto it = std::sregex_iterator(body.begin(), body.end(), call); it != std::sregex_iterator(); ++it)
        raisedCodes.insert((*it)[1].str());
    ASSERT_GE(raisedCodes.size(), 27u);

    std::set<std::string> known;
    for (const auto& cls : health::catalog()) {
        EXPECT_TRUE(known.insert(cls.code).second) << cls.code << " is declared twice";
        EXPECT_TRUE(cls.maxSeverity == "warning" || cls.maxSeverity == "error") << cls.code;
        EXPECT_FALSE(cls.title.empty()) << cls.code;
        EXPECT_FALSE(cls.remedies.empty()) << cls.code << " offers nothing to do";
        // Every error interrupts; only a warning may be marked as normal work.
        if (cls.maxSeverity == "error") {
            EXPECT_TRUE(cls.notifies) << cls.code;
        }
        for (const auto& remedy : cls.remedies) {
            EXPECT_TRUE(remedy.kind == "open" || remedy.kind == "command") << cls.code;
            if (remedy.kind == "open") {
                EXPECT_TRUE(remedy.href && remedy.href->starts_with("/")) << cls.code;
            }
            if (remedy.kind == "command") {
                EXPECT_TRUE(remedy.command && remedy.effect) << cls.code;
            }
        }
    }
    for (const auto& code : raisedCodes) EXPECT_TRUE(known.contains(code)) << code << " is raised but not in the catalog";
    for (const auto& code : known) EXPECT_TRUE(raisedCodes.contains(code)) << code << " is in the catalog but never raised";

    EXPECT_FALSE(health::findClass("system.operations.active_work")->notifies) << "raised by every upload";
    EXPECT_EQ(health::findClass("system.nothing"), nullptr);
}

// ---------------------------------------------------------------------------------------------------------------
// The rules (no DB)
// ---------------------------------------------------------------------------------------------------------------

TEST(HealthFindingRules, AnAcknowledgementLastsAsLongAsItsOccurrence) {
    const std::vector<Mark> marks{mark("a.warn", "acknowledged", "warning")};

    auto r = health::resolve({raised("a.warn", "warning")}, marks, 1000);
    EXPECT_EQ(stateOf(r, "a.warn"), "acknowledged");
    EXPECT_EQ(r.unattendedWarnings, 0u);
    EXPECT_TRUE(r.stale.empty());

    // It cleared: the acknowledgement is over, so the next occurrence is new.
    r = health::resolve({}, marks, 1000);
    EXPECT_TRUE(stale(r, "a.warn"));
    EXPECT_TRUE(r.silences.empty());

    // It got worse than what was acknowledged: news again.
    r = health::resolve({raised("a.warn", "error")}, marks, 1000);
    EXPECT_EQ(stateOf(r, "a.warn"), "active");
    EXPECT_EQ(r.unattendedErrors, 1u);
    EXPECT_TRUE(stale(r, "a.warn"));
}

TEST(HealthFindingRules, ASilenceSurvivesAClearExpiresAndDoesNotCoverWorse) {
    const std::vector<Mark> marks{mark("a.warn", "silenced", "warning", 2000)};

    auto r = health::resolve({raised("a.warn", "warning"), raised("b.err", "error")}, marks, 1000);
    EXPECT_EQ(stateOf(r, "a.warn"), "silenced");
    EXPECT_EQ(stateOf(r, "b.err"), "active");
    EXPECT_EQ(r.unattendedWarnings, 0u);
    EXPECT_EQ(r.unattendedErrors, 1u);

    // Not active: the silence stays and is listed.
    r = health::resolve({}, marks, 1000);
    ASSERT_EQ(r.silences.size(), 1u);
    EXPECT_EQ(r.silences.front().cls, "a.warn");
    EXPECT_TRUE(r.stale.empty());

    // Worse than what was silenced: it speaks again, and the silence still stands for the warning.
    r = health::resolve({raised("a.warn", "error")}, marks, 1000);
    EXPECT_EQ(stateOf(r, "a.warn"), "active");
    EXPECT_FALSE(stale(r, "a.warn"));

    // Past its expiry it no longer exists.
    r = health::resolve({raised("a.warn", "warning")}, marks, 2000);
    EXPECT_EQ(stateOf(r, "a.warn"), "active");
    EXPECT_TRUE(stale(r, "a.warn"));
    EXPECT_EQ(r.unattendedWarnings, 1u);

    // A silence set for errors covers the warning too.
    r = health::resolve({raised("a.warn", "warning")}, {mark("a.warn", "silenced", "error")}, 1000);
    EXPECT_EQ(stateOf(r, "a.warn"), "silenced");
}

TEST(HealthFindingRules, TheDigestChangesWithWhatAClientWouldShow) {
    health::Snapshot a{.overallStatus = "warning", .findings = {{.raised = raised("a.warn", "warning")}}};
    auto b = a;
    b.checkedAt = 99;  // a later check of the same state
    EXPECT_EQ(health::digest(a), health::digest(b));
    b.findings.front().state = "acknowledged";
    EXPECT_NE(health::digest(a), health::digest(b));
    auto c = a;
    c.silences.push_back(mark("z.other", "silenced", "warning"));
    EXPECT_NE(health::digest(a), health::digest(c));
}

// ---------------------------------------------------------------------------------------------------------------
// Agents (no DB)
// ---------------------------------------------------------------------------------------------------------------

// Whether a warning has been dealt with is decided by a human: an AI app's own pairing is refused the three commands
// whatever its scope, and may read.
TEST(HealthFindingAgents, AScopedDeviceMayReadAndNeverChange) {
    using protocols::ws::Router;
    for (const auto* cmd : {"health.finding.acknowledge", "health.finding.silence", "health.finding.unsilence"}) {
        EXPECT_TRUE(Router::isScopedDeviceForbidden(cmd)) << cmd;
        EXPECT_FALSE(Router::scopedDeviceMayRun(cmd, "destructive")) << cmd;
    }
    EXPECT_FALSE(Router::isScopedDeviceForbidden("health.findings.list"));
    EXPECT_TRUE(Router::scopedDeviceMayRun("health.findings.list", "read"));
}

// No MCP transport lists or runs them: the local `vh mcp`, the device listener's /mcp and connector grants all use
// this catalog.
TEST(HealthFindingAgents, TheMcpCatalogExcludesTheThreeCommandsAtEveryCeiling) {
    const mcp::Catalog catalog;
    std::set<std::string> excluded;
    bool listIsRead = false;
    for (const auto& leaf : catalog.leaves()) {
        if (!leaf.command.starts_with("health")) continue;
        if (leaf.excluded) excluded.insert(leaf.command);
        if (leaf.command == "health list")
            listIsRead = !leaf.excluded && leaf.effect == protocols::shell::CommandEffect::Read;
    }
    EXPECT_EQ(excluded, (std::set<std::string>{"health ack", "health silence", "health unsilence"}));
    EXPECT_TRUE(listIsRead);
    for (const auto* line : {"health ack system.db.warning", "health silence system.db.warning --for 1h",
                             "health unsilence system.db.warning"}) {
        const auto prepared = catalog.prepare("vh_run", json{{"command", line}});
        ASSERT_TRUE(std::holds_alternative<json>(prepared)) << line;
        EXPECT_TRUE(std::get<json>(prepared).value("isError", false)) << line;
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Operations (DB)
// ---------------------------------------------------------------------------------------------------------------

class HealthFindingsDb : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() { setUpDbSuite("health_findings", {.seed = true, .runtime = true}); }
    static void TearDownTestSuite() {
        health::setActiveSourceForTesting({});
        tearDownDbSuite();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP();
        for (const auto& m : db::query::health::FindingState::list()) db::query::health::FindingState::remove(m.cls, m.subject);
        active = {raised("system.fuse.error_rate_elevated", "warning"), raised("system.db.disconnected", "error")};
        health::setActiveSourceForTesting([this] { return active; });
        viewer = test::identities::detachedUser(9101, "health_viewer", std::make_shared<rbac::role::Admin>(
                                                                           rbac::role::Admin::OrgAdmin()));
    }

    static std::shared_ptr<protocols::ws::Session> sessionFor(const std::shared_ptr<identities::User>& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static std::string state(const json& health, const std::string& cls) {
        for (const auto& f : health.at("findings"))
            if (f.at("class") == cls) return f.at("state").get<std::string>();
        return "absent";
    }

    std::vector<Active> active;
    std::shared_ptr<identities::User> viewer;
};

TEST_F(HealthFindingsDb, AcknowledgeAndSilenceChangeWhatAsksForAPersonAndNeverTheSeverity) {
    auto health = ops::health::list(superUser);
    EXPECT_TRUE(health.at("can_manage").get<bool>());
    EXPECT_EQ(health.at("overall_status"), "error");
    EXPECT_EQ(health.at("error_count"), 1);
    EXPECT_EQ(health.at("unattended_error_count"), 1);
    EXPECT_EQ(health.at("unattended_warning_count"), 1);

    health = ops::health::acknowledge(superUser, "system.db.disconnected", "", std::string("  on it  "));
    EXPECT_EQ(state(health, "system.db.disconnected"), "acknowledged");
    EXPECT_EQ(health.at("overall_status"), "error") << "an acknowledged error is still an error";
    EXPECT_EQ(health.at("error_count"), 1);
    EXPECT_EQ(health.at("unattended_error_count"), 0);
    for (const auto& f : health.at("findings"))
        if (f.at("class") == "system.db.disconnected") {
            EXPECT_EQ(f.at("mark").at("note"), "on it");
            EXPECT_EQ(f.at("mark").at("set_by_name"), superUser->name());
            EXPECT_TRUE(f.at("mark").at("expires_at").is_null());
        }

    health = ops::health::silence(superUser, {.cls = "system.fuse.error_rate_elevated", .forSeconds = 3600});
    EXPECT_EQ(state(health, "system.fuse.error_rate_elevated"), "silenced");
    EXPECT_EQ(health.at("warning_count"), 1);
    EXPECT_EQ(health.at("unattended_warning_count"), 0);

    // The finding clears: the acknowledgement goes with it, the silence stays and is listed.
    active.clear();
    health = ops::health::list(superUser);
    EXPECT_TRUE(health.at("findings").empty());
    ASSERT_EQ(health.at("silences").size(), 1u);
    EXPECT_EQ(health.at("silences")[0].at("class"), "system.fuse.error_rate_elevated");
    const auto stored = db::query::health::FindingState::list();
    ASSERT_EQ(stored.size(), 1u);
    EXPECT_EQ(stored.front().state, "silenced");

    // Back, and now an error: the silence set for a warning does not cover it.
    active = {raised("system.fuse.error_rate_elevated", "error")};
    health = ops::health::list(superUser);
    EXPECT_EQ(state(health, "system.fuse.error_rate_elevated"), "active");
    EXPECT_EQ(health.at("unattended_error_count"), 1);

    health = ops::health::unsilence(superUser, "system.fuse.error_rate_elevated", "");
    EXPECT_TRUE(health.at("silences").empty());
    EXPECT_TRUE(db::query::health::FindingState::list().empty());
}

TEST_F(HealthFindingsDb, RefusesWhatMakesNoSense) {
    EXPECT_THROW(ops::health::acknowledge(superUser, "system.nothing", "", {}), ops::NotFound);
    EXPECT_THROW(ops::health::acknowledge(superUser, "system.retention.overdue", "", {}), ops::Conflict)
        << "not active: nothing to acknowledge";
    EXPECT_THROW(ops::health::acknowledge(superUser, "system.db.disconnected", "vault:1", {}), ops::Invalid);
    EXPECT_THROW(ops::health::acknowledge(superUser, "system.db.disconnected", "", std::string(501, 'x')), ops::Invalid);
    EXPECT_THROW(ops::health::silence(superUser, {.cls = "system.db.disconnected", .forSeconds = 10}), ops::Invalid);
    EXPECT_THROW(ops::health::silence(superUser, {.cls = "system.db.disconnected", .forSeconds = 3600, .until = 99}),
                 ops::Invalid);
    EXPECT_THROW(ops::health::silence(superUser, {.cls = "system.db.disconnected", .severity = "info"}), ops::Invalid);
    EXPECT_THROW(ops::health::unsilence(superUser, "system.db.disconnected", ""), ops::NotFound);

    (void)ops::health::silence(superUser, {.cls = "system.db.disconnected"});
    EXPECT_THROW(ops::health::acknowledge(superUser, "system.db.disconnected", "", {}), ops::Conflict)
        << "silenced already";
    // A class that is not active can be silenced, at the worst severity it can have.
    const auto health = ops::health::silence(superUser, {.cls = "system.retention.overdue"});
    bool found = false;
    for (const auto& s : health.at("silences"))
        if (s.at("class") == "system.retention.overdue") {
            found = true;
            EXPECT_EQ(s.at("severity"), "error");
            EXPECT_TRUE(s.at("expires_at").is_null());
        }
    EXPECT_TRUE(found);
}

// Seeing the dashboard is not enough to change what every operator is told.
TEST_F(HealthFindingsDb, ViewingIsNotManaging) {
    ASSERT_TRUE(viewer->statsPerms().canView());
    ASSERT_FALSE(viewer->statsPerms().canManage());
    const auto health = ops::health::list(viewer);
    EXPECT_FALSE(health.at("can_manage").get<bool>());
    EXPECT_THROW(ops::health::acknowledge(viewer, "system.db.disconnected", "", {}), ops::Denied);
    EXPECT_THROW(ops::health::silence(viewer, {.cls = "system.db.disconnected"}), ops::Denied);
    EXPECT_THROW(ops::health::unsilence(viewer, "system.db.disconnected", ""), ops::Denied);
    EXPECT_TRUE(db::query::health::FindingState::list().empty());

    const auto none = test::identities::detachedUser(9102, "health_none",
                                                     std::make_shared<rbac::role::Admin>(rbac::role::Admin::None()));
    EXPECT_THROW((void)ops::health::list(none), ops::Denied);
    EXPECT_THROW((void)ops::health::list(nullptr), ops::Denied);
}

TEST_F(HealthFindingsDb, TheWsCommandsAnswerTheWholeStateAndTheDashboardCarriesIt) {
    using protocols::ws::handler::Health;
    const auto admin = sessionFor(superUser);
    auto answer = Health::findingAcknowledge(json{{"class", "system.db.disconnected"}}, admin);
    EXPECT_EQ(state(answer.at("health"), "system.db.disconnected"), "acknowledged");
    answer = Health::findingSilence(json{{"class", "system.fuse.error_rate_elevated"}, {"for_seconds", 600}}, admin);
    EXPECT_EQ(answer.at("health").at("unattended_warning_count"), 0);
    answer = Health::findingsList(json{{"include_catalog", true}}, admin);
    EXPECT_EQ(answer.at("health").at("catalog").size(), health::catalog().size());
    answer = Health::findingUnsilence(json{{"class", "system.fuse.error_rate_elevated"}}, admin);
    EXPECT_EQ(state(answer.at("health"), "system.fuse.error_rate_elevated"), "active");

    EXPECT_THROW(Health::findingSilence(json{{"for_seconds", 600}}, admin), ops::Invalid);
    EXPECT_THROW(Health::findingSilence(json{{"class", 3}}, admin), ops::Invalid);
    EXPECT_THROW(Health::findingAcknowledge(json{{"class", "system.db.disconnected"}}, sessionFor(viewer)), ops::Denied);
}

TEST_F(HealthFindingsDb, EachChangeIsInTheAuditTrailWithoutTheNote) {
    (void)ops::health::acknowledge(superUser, "system.db.disconnected", "", std::string("customer name here"));
    (void)ops::health::silence(superUser, {.cls = "system.fuse.error_rate_elevated", .forSeconds = 3600});
    (void)ops::health::unsilence(superUser, "system.fuse.error_rate_elevated", "");
    (void)vh::audit::Trail::instance()->flushNow();

    // The three newest: earlier tests of this suite recorded their own.
    const auto page = ops::audit::list(superUser, {.action_prefix = std::string("health.finding.")}, 3);
    std::vector<std::string> actions;
    for (const auto& event : page.events) {
        actions.push_back(event.action);
        const auto j = ops::audit::toJson(event);
        EXPECT_EQ(j.dump().find("customer name here"), std::string::npos) << "a note is free text: never in the trail";
    }
    std::ranges::sort(actions);
    EXPECT_EQ(actions, (std::vector<std::string>{"health.finding.acknowledge", "health.finding.silence",
                                                "health.finding.unsilence"}));
}

// ---------------------------------------------------------------------------------------------------------------
// The push (DB): health.subscribe and health.changed
// ---------------------------------------------------------------------------------------------------------------

// Events are captured through the notifier's delivery seam (a test session has no socket); the default delivery
// holds them the same way while Session::queuedFrames() is at HealthNotifier::kMaxQueuedFrames. Each test drives
// its own notifier's passes with explicit times, and points health::stateChanged() at it.
class HealthPushDb : public HealthFindingsDb {
protected:
    using HealthNotifier = protocols::ws::HealthNotifier;
    using Clock = HealthNotifier::Clock;
    using SessionPtr = std::shared_ptr<protocols::ws::Session>;

    static void SetUpTestSuite() { setUpDbSuite("health_push", {.seed = true, .runtime = true}); }
    static void TearDownTestSuite() {
        health::setActiveSourceForTesting({});
        tearDownDbSuite();
    }

    void SetUp() override {
        HealthFindingsDb::SetUp();
        if (IsSkipped()) return;
        notifier = std::make_shared<HealthNotifier>();
        notifier->setDeliveryForTesting([this](const SessionPtr& session, const json& event) {
            if (full) return false;
            delivered[session->uuid].push_back(event);
            return true;
        });
        HealthNotifier::listenForStateChanges(notifier);
        t0 = Clock::now();
    }

    void TearDown() override { HealthNotifier::listenForStateChanges(HealthNotifier::instance()); }

    [[nodiscard]] std::vector<json> take(const SessionPtr& session) {
        auto out = std::move(delivered[session->uuid]);
        delivered.erase(session->uuid);
        return out;
    }

    // Later than t0 by `seconds`: subscribe() evaluates on the real clock, so a pass is due 15 s after it.
    [[nodiscard]] Clock::time_point at(const int seconds) const { return t0 + std::chrono::seconds(seconds); }

    std::shared_ptr<HealthNotifier> notifier;
    std::map<std::string, std::vector<json>> delivered;  // by session uuid
    bool full = false;                                   // the consumer is not reading
    Clock::time_point t0{};
};

TEST_F(HealthPushDb, NoSubscriberNoEvaluation) {
    notifier->tick(at(0));
    notifier->stateChanged();
    notifier->tick(at(60));
    notifier->tick(at(120));
    EXPECT_EQ(notifier->evaluations(), 0u);

    const auto admin = sessionFor(superUser);
    const auto revision = notifier->subscribe(admin);
    EXPECT_EQ(notifier->evaluations(), 1u) << "the first subscriber after none looks now";
    EXPECT_GE(revision, 1u);
    EXPECT_TRUE(notifier->subscribed(*admin));
    EXPECT_EQ(notifier->subscribe(admin), revision) << "subscribing again changes nothing";
    EXPECT_EQ(notifier->evaluations(), 1u);
    EXPECT_EQ(notifier->sessionCount(), 1u);

    notifier->unsubscribe(admin);
    EXPECT_FALSE(notifier->subscribed(*admin));
    active.push_back(raised("system.retention.overdue", "error"));
    notifier->tick(at(200));
    EXPECT_EQ(notifier->evaluations(), 1u);
    EXPECT_TRUE(delivered.empty());

    // The ws commands are the same notifier's (the process's), refused without admin.stats.view.
    using protocols::ws::handler::Health;
    const auto none = test::identities::detachedUser(9103, "health_push_none",
                                                     std::make_shared<rbac::role::Admin>(rbac::role::Admin::None()));
    EXPECT_THROW((void)Health::subscribe(sessionFor(none)), ops::Denied);
    EXPECT_THROW((void)Health::subscribe(sessionFor(nullptr)), ops::Denied);
    const auto viaWs = sessionFor(viewer);
    EXPECT_TRUE(Health::subscribe(viaWs).at("revision").is_number_unsigned());
    EXPECT_TRUE(HealthNotifier::instance()->subscribed(*viaWs));
    EXPECT_EQ(Health::unsubscribe(viaWs), (json{{"subscribed", false}}));
    EXPECT_FALSE(HealthNotifier::instance()->subscribed(*viaWs));
}

TEST_F(HealthPushDb, ADigestChangePushesOnce) {
    const auto admin = sessionFor(superUser);
    const auto r0 = notifier->subscribe(admin);
    notifier->tick(at(1));
    EXPECT_TRUE(take(admin).empty()) << "nothing changed, nothing due";
    EXPECT_EQ(notifier->evaluations(), 1u);

    notifier->tick(at(20));
    EXPECT_EQ(notifier->evaluations(), 2u) << "evaluated every 15 seconds while subscribed";
    EXPECT_TRUE(take(admin).empty()) << "the same findings: no event";

    active.push_back(raised("system.retention.overdue", "error"));
    notifier->tick(at(40));
    const auto events = take(admin);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].at("command"), "health.changed");
    EXPECT_FALSE(events[0].contains("requestId"));
    EXPECT_EQ(events[0].at("data"), (json{{"revision", r0 + 1},
                                          {"overall_status", "error"},
                                          {"error_count", 2},
                                          {"warning_count", 1},
                                          {"unattended_error_count", 2},
                                          {"unattended_warning_count", 1}}))
        << "the summary only: no findings";

    notifier->tick(at(60));
    notifier->tick(at(80));
    EXPECT_TRUE(take(admin).empty()) << "pushed once";
    EXPECT_EQ(notifier->revision(), r0 + 1);
}

TEST_F(HealthPushDb, ASlowConsumerGetsOneEventTheNewest) {
    const auto admin = sessionFor(superUser);
    const auto r0 = notifier->subscribe(admin);
    full = true;
    active.push_back(raised("system.retention.overdue", "error"));
    notifier->tick(at(20));
    active.clear();
    notifier->tick(at(40));
    EXPECT_EQ(notifier->revision(), r0 + 2);
    EXPECT_TRUE(delivered.empty());

    full = false;
    notifier->tick(at(45));  // no evaluation due: what was held goes out
    const auto events = take(admin);
    ASSERT_EQ(events.size(), 1u) << "coalesced";
    EXPECT_EQ(events[0].at("data").at("revision"), r0 + 2);
    EXPECT_EQ(events[0].at("data").at("overall_status"), "healthy");
    EXPECT_EQ(events[0].at("data").at("error_count"), 0);
    notifier->tick(at(50));
    EXPECT_TRUE(take(admin).empty());
}

TEST_F(HealthPushDb, ASessionThatLostThePermissionGetsOneLastEvent) {
    const auto admin = sessionFor(superUser);
    const auto watcher = sessionFor(viewer);
    (void)notifier->subscribe(admin);
    (void)notifier->subscribe(watcher);
    notifier->tick(at(1));  // the first revalidation: both may
    EXPECT_EQ(notifier->sessionCount(), 2u);

    // Its role lost admin.stats.view (a signed-out session reads the same: no user).
    watcher->user = test::identities::detachedUser(9104, "health_push_demoted",
                                                   std::make_shared<rbac::role::Admin>(rbac::role::Admin::None()));
    notifier->tick(at(10));
    EXPECT_TRUE(take(watcher).empty()) << "re-checked every 30 seconds, not every pass";

    active.push_back(raised("system.retention.overdue", "error"));
    notifier->tick(at(32));
    const auto last = take(watcher);
    ASSERT_EQ(last.size(), 1u);
    EXPECT_EQ(last[0].at("command"), "health.changed");
    EXPECT_EQ(last[0].at("data").at("subscribed"), false);
    EXPECT_TRUE(last[0].at("data").contains("revision"));
    EXPECT_FALSE(last[0].at("data").contains("overall_status")) << "nothing about findings it may not see";
    EXPECT_FALSE(notifier->subscribed(*watcher));
    EXPECT_EQ(notifier->sessionCount(), 1u);
    EXPECT_EQ(take(admin).size(), 1u) << "the others are told as usual";

    active.clear();
    notifier->tick(at(64));
    EXPECT_TRUE(take(watcher).empty());
    EXPECT_EQ(take(admin).size(), 1u);
}

TEST_F(HealthPushDb, AnAcknowledgeSilenceOrUnsilencePushesAtOnce) {
    const auto admin = sessionFor(superUser);
    const auto r0 = notifier->subscribe(admin);
    notifier->tick(at(1));
    ASSERT_TRUE(take(admin).empty());

    (void)ops::health::silence(superUser, {.cls = "system.fuse.error_rate_elevated", .forSeconds = 3600});
    notifier->tick(at(2));  // well before the next evaluation is due
    auto events = take(admin);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].at("data").at("revision"), r0 + 1);
    EXPECT_EQ(events[0].at("data").at("warning_count"), 1) << "a silenced warning is still a warning";
    EXPECT_EQ(events[0].at("data").at("unattended_warning_count"), 0);

    (void)ops::health::acknowledge(superUser, "system.db.disconnected", "", {});
    notifier->tick(at(3));
    events = take(admin);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].at("data").at("unattended_error_count"), 0);
    EXPECT_EQ(events[0].at("data").at("overall_status"), "error");

    (void)ops::health::unsilence(superUser, "system.fuse.error_rate_elevated", "");
    notifier->tick(at(4));
    events = take(admin);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].at("data").at("revision"), r0 + 3);
    EXPECT_EQ(events[0].at("data").at("unattended_warning_count"), 1);

    notifier->tick(at(5));
    EXPECT_TRUE(take(admin).empty());
    EXPECT_EQ(notifier->evaluations(), 4u) << "one on subscribe, one per change";
}

// A closed session is forgotten at the next pass, with nothing sent.
TEST_F(HealthPushDb, AClosedSessionIsForgotten) {
    auto gone = sessionFor(superUser);
    (void)notifier->subscribe(gone);
    gone.reset();
    active.push_back(raised("system.retention.overdue", "error"));
    notifier->tick(at(20));
    EXPECT_EQ(notifier->sessionCount(), 0u);
    EXPECT_TRUE(delivered.empty());
}

}
