#include "audit/Chain.hpp"
#include "audit/Trail.hpp"
#include "config/Config.hpp"
#include "db/Transactions.hpp"
#include "db/query/audit/Trail.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Audit.hpp"
#include "ops/Error.hpp"
#include "ops/Users.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <paths.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <cstdlib>
#include <string>
#include <unistd.h>

// #323: the hash-chained audit trail.

namespace {

using vh::audit::Hash;
using vh::audit::Record;

Hash bytes0to31() {
    Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i) h[i] = static_cast<uint8_t>(i);
    return h;
}

Record vectorRecord() {
    Record r;
    r.seq = 7;
    r.prev_hash = bytes0to31();
    r.occurred_us = 1762300800123456ULL;
    r.level = "info";
    r.action = "auth.login.success";
    r.outcome = "success";
    r.actor_id = 9;
    r.actor = "alice";
    r.origin = "web";
    r.message = "[auth] alice signed in";
    r.details = R"({"method":"password"})";
    return r;
}

std::vector<Record> chainOf(const std::size_t n) {
    std::vector<Record> out;
    Hash prev{};
    for (std::size_t i = 1; i <= n; ++i) {
        Record r;
        r.seq = i;
        r.prev_hash = prev;
        r.occurred_us = 1000 + i;
        r.level = "info";
        r.action = "test.event";
        r.outcome = "info";
        r.message = "event " + std::to_string(i);
        r.hash = vh::audit::computeHash(r);
        prev = r.hash;
        out.push_back(r);
    }
    return out;
}

vh::audit::ChainCheck verifyAll(const std::vector<Record>& records, std::optional<vh::audit::Checkpoint> anchor = {}) {
    vh::audit::ChainVerifier v(anchor);
    for (const auto& r : records)
        if (!v.feed(r)) break;
    return v.result();
}

}

// Pinned against an independent implementation (Python hashlib/struct) of the layout in audit/Chain.hpp.
TEST(AuditChain, MatchesTheDocumentedVector) {
    EXPECT_EQ(vh::audit::toHex(vh::audit::computeHash(vectorRecord())),
              "d533d9d58a09ec57c4c6edc5ddc77f48379663f032a8f154646d0cc9f754549e");

    Record sparse;
    sparse.seq = 1;
    sparse.vault_id = 42;
    sparse.entry_id = 123;
    EXPECT_EQ(vh::audit::toHex(vh::audit::computeHash(sparse)),
              "9279043903ff5f0ad884edb8dfbe620e58e836efb24ecc987391398afb8c2ba2");
}

TEST(AuditChain, EveryFieldIsCovered) {
    const auto base = vh::audit::computeHash(vectorRecord());
    const std::vector<std::function<void(Record&)>> edits = {
        [](Record& r) { r.seq++; },
        [](Record& r) { r.prev_hash[0] ^= 1; },
        [](Record& r) { r.occurred_us++; },
        [](Record& r) { r.level = "warning"; },
        [](Record& r) { r.action = "auth.login.failure"; },
        [](Record& r) { r.outcome = "failure"; },
        [](Record& r) { r.actor_id = 10; },
        [](Record& r) { r.actor_id.reset(); },
        [](Record& r) { r.actor = "mallory"; },
        [](Record& r) { r.origin = "cli"; },
        [](Record& r) { r.vault_id = 0; },
        [](Record& r) { r.entry_id = 0; },
        [](Record& r) { r.message += " "; },
        [](Record& r) { r.details = R"({"method":"passkey"})"; },
        // Length prefixes keep field boundaries: moving bytes between fields changes the hash.
        [](Record& r) { r.actor = "alic"; r.origin = "eweb"; },
    };
    for (std::size_t i = 0; i < edits.size(); ++i) {
        auto r = vectorRecord();
        edits[i](r);
        EXPECT_NE(vh::audit::computeHash(r), base) << "edit " << i;
    }
}

TEST(AuditChain, VerifierAcceptsAnIntactChainAndFindsTheFirstBadEvent) {
    auto chain = chainOf(6);
    auto ok = verifyAll(chain);
    EXPECT_FALSE(ok.broken_at);
    EXPECT_EQ(ok.checked, 6u);
    EXPECT_EQ(ok.last_seq, 6u);

    auto altered = chain;
    altered[3].message = "edited";
    EXPECT_EQ(verifyAll(altered).broken_at, 4u);

    auto rehashed = altered;  // re-hashing the edited event still breaks the next link
    rehashed[3].hash = vh::audit::computeHash(rehashed[3]);
    EXPECT_EQ(verifyAll(rehashed).broken_at, 5u);

    auto missing = chain;
    missing.erase(missing.begin() + 2);
    const auto m = verifyAll(missing);
    EXPECT_EQ(m.broken_at, 4u);
    EXPECT_NE(m.problem.find("missing"), std::string::npos);

    auto swapped = chain;
    std::swap(swapped[1], swapped[2]);
    EXPECT_EQ(verifyAll(swapped).broken_at, 3u);
}

TEST(AuditChain, VerificationStartsFromARetentionCheckpoint) {
    const auto chain = chainOf(5);
    const std::vector<Record> retained(chain.begin() + 2, chain.end());
    EXPECT_EQ(verifyAll(retained).broken_at, 3u);  // without the anchor the first retained event looks orphaned
    const auto anchored = verifyAll(retained, vh::audit::Checkpoint{.seq = 2, .hash = chain[1].hash, .purged = 2});
    EXPECT_FALSE(anchored.broken_at);
    EXPECT_EQ(anchored.checked, 3u);
}

TEST(AuditChain, HeadMessageIsDomainSeparatedAndUnambiguous) {
    const auto msg = vh::audit::headMessage("node-1", 5, bytes0to31(), 99);
    const std::string_view domain = vh::audit::kHeadDomain;
    ASSERT_GE(msg.size(), domain.size());
    EXPECT_TRUE(std::equal(domain.begin(), domain.end(), msg.begin()));
    EXPECT_EQ(msg.size(), domain.size() + 4 + 6 + 8 + 32 + 8);
    EXPECT_NE(msg, vh::audit::headMessage("node-15", 5, bytes0to31(), 99));
    EXPECT_THROW((void)vh::audit::headMessage("", 5, bytes0to31(), 99), std::invalid_argument);
}

TEST(AuditChain, HexRoundTrip) {
    const auto h = bytes0to31();
    EXPECT_EQ(vh::audit::hashFromHex(vh::audit::toHex(h)), h);
    EXPECT_FALSE(vh::audit::hashFromHex("00"));
    EXPECT_FALSE(vh::audit::hashFromHex(std::string(64, 'g')));
}

TEST(AuditTrailAction, LegacyLinesGetTheirTagAsAction) {
    EXPECT_EQ(vh::audit::actionFromMessage("[ops::users] admin created user bob with role x"), "ops.users");
    EXPECT_EQ(vh::audit::actionFromMessage("[http] fs.read user=1"), "http");
    EXPECT_EQ(vh::audit::actionFromMessage("vh fs get: admin read vault 3 entry 4"), "vh.fs.get");
    EXPECT_EQ(vh::audit::actionFromMessage("PUT /upload/content: admin created vault 3"), "put.upload.content");
    EXPECT_EQ(vh::audit::actionFromMessage("no tag here at all, just words"), "log");
    EXPECT_EQ(vh::audit::actionFromMessage("[]"), "log");
}

TEST(AuditTrailConfig, ValidatesRetentionIntervalAndFacility) {
    vh::config::AuditTrailConfig c;
    EXPECT_NO_THROW(vh::config::validateAuditTrail(c));
    EXPECT_EQ(c.retention_days.count(), 2190);
    c.retention_days = std::chrono::days(29);
    EXPECT_THROW(vh::config::validateAuditTrail(c), std::invalid_argument);
    c = {};
    c.head_interval_minutes = 0;
    EXPECT_THROW(vh::config::validateAuditTrail(c), std::invalid_argument);
    c = {};
    c.syslog_facility = "daemon";
    EXPECT_THROW(vh::config::validateAuditTrail(c), std::invalid_argument);
}

// ---- against the database ----------------------------------------------------------------------------------------

class AuditTrailDbTest : public ::testing::Test {
protected:
    inline static bool skip = false;
    inline static std::shared_ptr<vh::identities::User> admin, plain;
    inline static std::filesystem::path root;

    static void TearDownTestSuite() {
        std::error_code ec;
        if (!root.empty()) std::filesystem::remove_all(root, ec);
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skip = true;
            return;
        }
        vh::paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_audit_trail_" + std::to_string(::getpid()));
        vh::paths::backingPath = root / "backing";
        vh::paths::mountPath = root / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);
        vh::db::Transactions::init();
        vh::db::seed::nuke_and_recreate_schema_public();
        vh::db::Transactions::dbPool_->initPreparedStatements();
        vh::seed::seed_database();
        vh::runtime::Deps::init();
        vh::fs::Filesystem::init(vh::runtime::Deps::get().storageManager);
        admin = vh::identities::manager().userByName("admin");
        const auto created = vh::ops::users::create(
            admin, {.name = "audit_plain_" + std::to_string(::getpid()), .role = "unprivileged",
                    .password = std::string("Audit-Trail-Pass-123")});
        plain = vh::identities::manager().user(created.user->id);
        vh::audit::Trail::instance()->resetForTesting();
    }

    void SetUp() override {
        if (skip) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
    }

    static void exec(const std::string& sql) {
        vh::db::Transactions::exec("audit test", [&](pqxx::work& txn) { txn.exec(sql); });
    }
};

TEST_F(AuditTrailDbTest, EveryAuditLineLandsInTheChainWithItsFields) {
    vh::audit::record({.action = "test.structured", .outcome = vh::audit::Outcome::Denied, .actor_id = admin->id,
                       .actor = admin->name(), .vault_id = 4, .entry_id = 77, .details = {{"reason", "x"}}},
                      "[test] structured event");
    vh::log::Registry::audit()->warn("[ops::test] a plain audit line");
    ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());

    const auto events = vh::ops::audit::list(admin, {.action_prefix = std::string("test.")}, 10).events;
    ASSERT_FALSE(events.empty());
    const auto& e = events.front();
    EXPECT_EQ(e.action, "test.structured");
    EXPECT_EQ(e.outcome, "denied");
    EXPECT_EQ(e.actor_id, admin->id);
    EXPECT_EQ(e.vault_id, 4u);
    EXPECT_EQ(e.entry_id, 77u);
    EXPECT_EQ(e.details, R"({"reason":"x"})");

    const auto plainLines = vh::ops::audit::list(admin, {.action_prefix = std::string("ops.test")}, 10).events;
    ASSERT_EQ(plainLines.size(), 1u);
    EXPECT_EQ(plainLines.front().level, "warning");
    EXPECT_EQ(plainLines.front().message, "[ops::test] a plain audit line");
}

TEST_F(AuditTrailDbTest, ReadingNeedsTheAuditsPermissionAndIsItselfRecorded) {
    EXPECT_THROW((void)vh::ops::audit::list(plain, {}, 10), vh::ops::Denied);
    EXPECT_THROW((void)vh::ops::audit::verify(plain), vh::ops::Denied);
    EXPECT_THROW((void)vh::ops::audit::exportNdjson(plain, {}, {}, [](std::string_view) {}), vh::ops::Denied);
    EXPECT_THROW((void)vh::ops::audit::list(admin, {}, 0), vh::ops::Invalid);

    (void)vh::ops::audit::list(admin, {}, 5);
    ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
    const auto views = vh::ops::audit::list(admin, {.action_prefix = std::string("audit.view")}, 5).events;
    ASSERT_FALSE(views.empty());
    EXPECT_EQ(views.front().actor_id, admin->id);
}

TEST_F(AuditTrailDbTest, AppendOnly) {
    vh::audit::record({.action = "test.append_only"}, "[test] something to sign");
    ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
    ASSERT_TRUE(vh::audit::Trail::instance()->signHead());
    EXPECT_ANY_THROW(exec("UPDATE audit_event SET message = 'edited'"));
    EXPECT_ANY_THROW(exec("DELETE FROM audit_event"));
    EXPECT_ANY_THROW(exec("UPDATE audit_head SET seq = seq + 1"));
}

TEST_F(AuditTrailDbTest, SignedHeadsVerifyAndExportCarriesThem) {
    vh::audit::record({.action = "test.head"}, "[test] before the head");
    ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
    const auto head = vh::audit::Trail::instance()->signHead();
    ASSERT_TRUE(head);
    EXPECT_FALSE(vh::audit::Trail::instance()->signHead()) << "nothing new to sign";

    const auto v = vh::ops::audit::verify(admin);
    EXPECT_TRUE(v.ok) << v.problem;
    EXPECT_GE(v.heads_valid, 1u);
    EXPECT_EQ(v.last_signed_seq, head->seq);
    EXPECT_TRUE(v.head_problems.empty());

    std::vector<nlohmann::json> lines;
    const auto n = vh::ops::audit::exportNdjson(admin, {}, {}, [&](std::string_view l) {
        lines.push_back(nlohmann::json::parse(l));
    });
    ASSERT_GE(lines.size(), n + 2);
    EXPECT_EQ(lines.front().at("format"), "vh-audit-export-v1");
    EXPECT_EQ(lines.back().at("type"), "head");
    // The exported events re-verify on their own.
    vh::audit::ChainVerifier chain(std::nullopt);
    for (const auto& l : lines) {
        if (l.at("type") != "event") continue;
        Record r;
        r.seq = l.at("seq");
        r.occurred_us = l.at("occurred_us");
        r.level = l.at("level");
        r.action = l.at("action");
        r.outcome = l.at("outcome");
        if (!l.at("actor_id").is_null()) r.actor_id = l.at("actor_id").get<uint32_t>();
        r.actor = l.at("actor");
        r.origin = l.at("origin");
        if (!l.at("vault_id").is_null()) r.vault_id = l.at("vault_id").get<uint32_t>();
        if (!l.at("entry_id").is_null()) r.entry_id = l.at("entry_id").get<uint64_t>();
        r.message = l.at("message");
        r.details = l.at("details");
        r.prev_hash = *vh::audit::hashFromHex(l.at("prev_hash").get<std::string>());
        r.hash = *vh::audit::hashFromHex(l.at("hash").get<std::string>());
        ASSERT_TRUE(chain.feed(r)) << chain.result().problem;
    }
}

TEST_F(AuditTrailDbTest, RetentionPurgeKeepsTheChainVerifiable) {
    for (int i = 0; i < 3; ++i) vh::audit::record({.action = "test.purge"}, "[test] old event");
    ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
    ASSERT_TRUE(vh::audit::Trail::instance()->signHead());
    vh::audit::record({.action = "test.purge"}, "[test] after the head");
    ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());

    const auto lastHead = vh::db::query::audit::Trail::lastHead();
    const auto removed = vh::db::query::audit::Trail::purgeBefore(UINT64_C(1) << 62);  // everything it may remove
    EXPECT_GT(removed, 0u);
    const auto checkpoint = vh::db::query::audit::Trail::checkpoint();
    ASSERT_TRUE(checkpoint);
    EXPECT_EQ(checkpoint->seq + 1, lastHead->seq) << "the newest signed head's event is kept";

    const auto v = vh::ops::audit::verify(admin);
    EXPECT_TRUE(v.ok) << v.problem;
    EXPECT_EQ(v.anchor_seq, checkpoint->seq);
    EXPECT_EQ(v.first_seq, checkpoint->seq + 1);
}

// Last: these tests tamper with the database, the way an attacker with table-owner rights could.
TEST_F(AuditTrailDbTest, ZZTamperingIsDetected) {
    for (int i = 0; i < 3; ++i) vh::audit::record({.action = "test.tamper"}, "[test] event " + std::to_string(i));
    ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
    const auto head = vh::audit::Trail::instance()->signHead();
    ASSERT_TRUE(head);
    const auto target = head->seq - 1;

    exec("ALTER TABLE audit_event DISABLE TRIGGER audit_event_append_only");
    exec("UPDATE audit_event SET message = message || ' (edited)' WHERE seq = " + std::to_string(target));
    auto v = vh::ops::audit::verify(admin);
    EXPECT_FALSE(v.ok);
    EXPECT_EQ(v.broken_at, target);

    exec("UPDATE audit_event SET message = replace(message, ' (edited)', '') WHERE seq = " + std::to_string(target));
    ASSERT_TRUE(vh::ops::audit::verify(admin).ok);

    // Removing the newest events (including what the verification itself recorded) leaves the signed head pointing
    // at an event that no longer exists.
    exec("DELETE FROM audit_event WHERE seq >= " + std::to_string(head->seq));
    exec("ALTER TABLE audit_event ENABLE TRIGGER audit_event_append_only");
    vh::audit::Trail::instance()->resetForTesting();
    v = vh::ops::audit::verify(admin);
    EXPECT_FALSE(v.ok);
    EXPECT_GE(v.heads_invalid, 1u);
    ASSERT_FALSE(v.head_problems.empty());
    EXPECT_NE(v.head_problems.front().find("missing"), std::string::npos) << v.head_problems.front();
}
