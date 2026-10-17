// File recovery persistence (migration 111): the shared model's text forms and JSON, and every db::query::recovery
// query against a migrated database. The model/JSON suites are DB-free; the DB suite skips without VH_TEST_DB_*.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/recovery/Blob.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/recovery/Plan.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/recovery/Snapshot.hpp"
#include "db/query/recovery/Usage.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/RecoveryJson.hpp"
#include "ops/Vaults.hpp"
#include "recovery/Model.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_recovery_db {

namespace rq = db::query::recovery;
namespace rm = vh::recovery;
namespace orec = vh::ops::recovery;
using nlohmann::json;

// ---- model text forms (no DB) --------------------------------------------------------------------------------------

TEST(RecoveryModel, RecoveryIdsRoundTripAndParseStrictly) {
    EXPECT_EQ(rm::RecoveryId::parse("snap-12").str(), "snap-12");
    EXPECT_EQ(rm::RecoveryId::parse("lv-1").type, rm::RecoveryId::Type::LocalGeneration);
    EXPECT_EQ(rm::RecoveryId::parse("pv-9223372036854775807").id, 9223372036854775807ull);
    for (const auto* bad : {"", "snap-", "snap-0", "snap-01", "snap--1", "snap-+1", "snap-1x", "SNAP-1", "lv-1 ", " lv-1",
                            "pv-9223372036854775808", "pv-99999999999999999999", "xv-1", "snap1", "lv-1.0"})
        EXPECT_THROW(static_cast<void>(rm::RecoveryId::parse(bad)), std::invalid_argument) << bad;
}

TEST(RecoveryModel, ModesBackendsAndActionsHaveStableText) {
    EXPECT_EQ(rm::to_string(rm::Mode::LocalSnapshots), "local_snapshots");
    EXPECT_EQ(rm::modeFromString("provider-versioning"), rm::Mode::ProviderVersioning);
    EXPECT_EQ(rm::modeFromString("local-snapshots"), rm::Mode::LocalSnapshots);
    EXPECT_EQ(rm::modeFromString("off"), rm::Mode::Off);
    EXPECT_THROW(static_cast<void>(rm::modeFromString("Off")), std::invalid_argument);
    EXPECT_EQ(rm::to_string(rm::Backend::ProviderVersion), "provider_version");
    EXPECT_EQ(rm::to_string(rm::PointKind::Directory), "directory");
    for (const auto a : {rm::ItemAction::Create, rm::ItemAction::Overwrite, rm::ItemAction::Skip, rm::ItemAction::Conflict,
                         rm::ItemAction::Remove, rm::ItemAction::Unavailable})
        EXPECT_EQ(rm::itemActionFromString(rm::to_string(a)), a);
}

TEST(RecoveryModel, ProviderRetentionParsesDaysAndIndefinite) {
    EXPECT_EQ(rm::ProviderRetention::parse("30").days, 30u);
    EXPECT_EQ(rm::ProviderRetention::parse("90d").str(), "90d");
    EXPECT_TRUE(rm::ProviderRetention::parse("indefinite").indefinite);
    EXPECT_EQ(rm::ProviderRetention::parse("36500d").days, 36500u);
    for (const auto* bad : {"0", "0d", "36501", "-1", "d", "", "30 d", "30dd", "1.5", "forever", "030"})
        EXPECT_THROW(static_cast<void>(rm::ProviderRetention::parse(bad)), std::invalid_argument) << bad;
}

// ---- JSON (no DB) --------------------------------------------------------------------------------------------------

TEST(RecoveryJson, PointsUseMemberNamesNullOptionalsIsoTimesAndStringMoney) {
    rm::RecoveryPoint p;
    p.id = "lv-4";
    p.backend = rm::Backend::LocalVersion;
    p.vault_id = 3;
    p.path = "/a.txt";
    p.created_at = 1760000000;
    p.estimated_monthly_cost = rm::Money{.amount = "0.0042", .currency = "USD"};
    p.reason = "overwrite";
    const json j = p;
    EXPECT_EQ(j.at("id"), "lv-4");
    EXPECT_EQ(j.at("backend"), "local_version");
    EXPECT_EQ(j.at("kind"), "file");
    EXPECT_EQ(j.at("created_at"), "2025-10-09T08:53:20Z");
    EXPECT_TRUE(j.at("valid_from").is_null());
    EXPECT_TRUE(j.at("name").is_null());
    EXPECT_TRUE(j.at("estimated_monthly_cost").at("amount").is_string());
    EXPECT_EQ(j.at("estimated_monthly_cost").at("currency"), "USD");
    EXPECT_EQ(j.at("encryption").at("key_version"), 0);
    EXPECT_EQ(j.at("retention").at("policy"), "");

    rm::CostReport report;
    report.priced = false;
    report.unpriced_reason = "no catalog profile";
    report.pre_activation_monthly.basis = "illustrative";
    report.scenarios.push_back({.retention = "30d", .steady_noncurrent_bytes = 10, .monthly_cost = {}, .notes = {}});
    const json r = report;
    EXPECT_TRUE(r.at("pre_activation_monthly").at("expected").is_null()) << "unknown money is null, never 0";
    EXPECT_EQ(r.at("scenarios").at(0).at("retention"), "30d");
    EXPECT_TRUE(r.at("computed_at").is_null()) << "a time never set is null";
    EXPECT_EQ(r.at("observation").at("overwritten_bytes_per_day"), "0");
    EXPECT_TRUE(r.at("catalog").contains("verified"));

    rm::Status st;
    st.mode = rm::Mode::ProviderVersioning;
    st.cost_alert_monthly = rm::Money{.amount = "25.00", .currency = "USD"};
    st.retained_key_versions = {1, 2};
    const json s = st;
    EXPECT_EQ(s.at("mode"), "provider_versioning");
    EXPECT_EQ(s.at("cost_alert_monthly").at("amount"), "25.00");
    EXPECT_EQ(s.at("provider").at("status"), "unknown");
    EXPECT_EQ(s.at("retained_key_versions"), json::array({1, 2}));

    const json ret = rm::ProviderRetention{.indefinite = false, .days = 30};
    EXPECT_EQ(ret.at("value"), "30d");
    EXPECT_EQ(ret.at("days"), 30);
}

TEST(RecoveryJson, PlansAndResultsRoundTripThroughStoredJson) {
    rm::Plan plan;
    plan.id = 7;
    plan.items.push_back({.source_id = "lv-3", .source_path = "/a", .destination_path = "/b",
                          .action = rm::ItemAction::Overwrite, .size_bytes = 12, .destination_source_id = "f:9:iv",
                          .method = "local_copy", .notes = {"n"}});
    const json pj = plan;
    EXPECT_EQ(pj.at("items").at(0).at("action"), "overwrite");
    const auto items = orec::planItemsFromJson(pj.at("items"));
    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0].action, rm::ItemAction::Overwrite);
    EXPECT_EQ(items[0].size_bytes, 12u);
    EXPECT_EQ(items[0].destination_source_id, "f:9:iv");
    EXPECT_EQ(items[0].notes, std::vector<std::string>{"n"});

    rm::RestoreResult result{.plan_id = 7, .state = "partial",
                             .items = {{.destination_path = "/b", .outcome = "failed", .error = "boom"}},
                             .restored = 1, .skipped = 0, .conflicts = 0, .failed = 1, .removed = 0};
    const auto back = orec::restoreResultFromJson(json(result));
    EXPECT_EQ(back.state, "partial");
    ASSERT_EQ(back.items.size(), 1u);
    EXPECT_EQ(back.items[0].error, "boom");
    EXPECT_EQ(back.failed, 1u);
}

TEST(RecoveryJson, RequestReadersKeepDefaultsIgnoreUnknownAndRefuseWrongTypes) {
    const auto u = orec::updateFromJson(json{{"mode", "local-snapshots"}, {"provider_retention", "90d"},
                                             {"snapshot_quota_bytes", 1024}, {"cost_alert_monthly", "12.50"},
                                             {"local_versioning", {{"enabled", true}, {"keep_last", 5}}},
                                             {"accept_unpriced", true}, {"unknown", {1, 2}}});
    EXPECT_EQ(u.mode, rm::Mode::LocalSnapshots);
    EXPECT_EQ(u.provider_retention->days, 90u);
    EXPECT_EQ(u.snapshot_quota_bytes, 1024u);
    EXPECT_EQ(u.cost_alert_monthly, "12.50");
    EXPECT_TRUE(u.local_versioning->enabled);
    EXPECT_EQ(u.local_versioning->keep_last, 5u);
    EXPECT_FALSE(u.local_versioning->max_age_days);
    EXPECT_TRUE(u.accept_unpriced);
    EXPECT_FALSE(u.accept_adoption);

    EXPECT_EQ(orec::updateFromJson(json{{"provider_retention", 30}}).provider_retention->days, 30u);
    EXPECT_TRUE(orec::updateFromJson(json{{"provider_retention", "indefinite"}}).provider_retention->indefinite);
    EXPECT_TRUE(orec::updateFromJson(json{{"provider_retention", {{"indefinite", true}}}}).provider_retention->indefinite);
    EXPECT_EQ(orec::updateFromJson(json{{"cost_alert_monthly", ""}}).cost_alert_monthly, "");
    EXPECT_FALSE(orec::updateFromJson(json::object()).mode);

    for (const auto& bad : {json{{"mode", 1}}, json{{"mode", "sometimes"}}, json{{"cost_alert_monthly", 12.5}},
                            json{{"cost_alert_monthly", "-1"}}, json{{"cost_alert_monthly", "1e3"}},
                            json{{"cost_alert_monthly", "1.123456789"}}, json{{"snapshot_quota_bytes", -1}},
                            json{{"snapshot_quota_bytes", "10"}}, json{{"provider_retention", 0}},
                            json{{"provider_retention", "0d"}}, json{{"provider_retention", true}},
                            json{{"local_versioning", {{"keep_last", 0}}}},
                            json{{"local_versioning", {{"max_age_days", 36501}}}},
                            json{{"local_versioning", true}}, json{{"accept_unpriced", "yes"}}, json::array()})
        EXPECT_THROW(static_cast<void>(orec::updateFromJson(bad)), ops::Invalid) << bad.dump();

    const auto q = orec::listQueryFromJson(json{{"path", "/docs"}, {"include_provider", false}, {"extra", 1}});
    EXPECT_EQ(q.path, "/docs");
    EXPECT_FALSE(q.include_provider);
    EXPECT_TRUE(q.include_snapshots);
    EXPECT_EQ(q.limit, 200u);
    EXPECT_THROW(static_cast<void>(orec::listQueryFromJson(json{{"limit", 0}})), ops::Invalid);
    EXPECT_THROW(static_cast<void>(orec::listQueryFromJson(json{{"path", 3}})), ops::Invalid);

    EXPECT_EQ(orec::snapshotRequestFromJson(json{{"path", "/a"}, {"name", "before"}}).name, "before");
    EXPECT_THROW(static_cast<void>(orec::snapshotRequestFromJson(json{{"name", "x"}})), ops::Invalid);
    EXPECT_THROW(static_cast<void>(orec::snapshotRequestFromJson(json{{"path", "/a"}, {"name", ""}})), ops::Invalid);

    const auto p = orec::planRequestFromJson(json{{"vault_id", 4}, {"path", "/d"}, {"at", "2026-10-01T12:00:00Z"},
                                                  {"prune", true}});
    EXPECT_EQ(p.vault_id, 4u);
    EXPECT_EQ(p.at, 1790856000);
    EXPECT_TRUE(p.prune);
    EXPECT_TRUE(p.refresh_provider);
    EXPECT_EQ(orec::planRequestFromJson(json{{"at", 1790856000}}).at, 1790856000);
    EXPECT_THROW(static_cast<void>(orec::planRequestFromJson(json{{"at", "yesterday"}})), ops::Invalid);
    EXPECT_THROW(static_cast<void>(orec::planRequestFromJson(json{{"vault_id", "4"}})), ops::Invalid);

    const auto r = orec::restoreRequestFromJson(json{{"plan_id", 9}, {"token", "t"}, {"accept_unverified", true}});
    EXPECT_EQ(r.plan_id, 9u);
    EXPECT_EQ(r.token, "t");
    EXPECT_TRUE(r.accept_unverified);
    EXPECT_THROW(static_cast<void>(orec::restoreRequestFromJson(json::object())), ops::Invalid);
    EXPECT_THROW(static_cast<void>(orec::restoreRequestFromJson(json{{"plan_id", 0}})), ops::Invalid);
}

// ---- DB-backed -----------------------------------------------------------------------------------------------------

std::string recoveryDbTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

// A unique 32-character [a-z0-9] storage name for blob rows inserted without a file.
std::string blobName() {
    static std::atomic<uint64_t> n{0};
    auto v = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) * 1000 + n.fetch_add(1);
    std::string out;
    while (out.size() < 32) {
        out += "abcdefghijklmnopqrstuvwxyz0123456789"[v % 36];
        v = v / 36 + 7919 * out.size();
    }
    return out;
}

class RecoveryDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_recovery_db] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_recovery_db_" + recoveryDbTag());
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

        const auto user = vh::test::identities::createUser("rdb_super_" + recoveryDbTag(),
                                                           db::query::rbac::role::Admin::get("super_admin"),
                                                           "rdb_super@vaulthalla.test", "x", std::nullopt);
        superUser = vh::identities::manager().user(user->id);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static uint32_t addVault() {
        return ops::vaults::create(superUser, {.name = "rdb_vault_" + recoveryDbTag(), .type = vault::model::VaultType::Local})
            ->id;
    }

    // A file row (fs_entry + files) directly under the vault, without content.
    static uint32_t addFile(const uint32_t vaultId, const std::string& path) {
        return db::Transactions::exec("test::addFile", [&](pqxx::work& txn) {
            const auto name = std::filesystem::path(path).filename().string();
            const auto res = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, $2, $3) RETURNING id",
                                      pqxx::params{vaultId, name + "_" + recoveryDbTag(), path});
            const auto id = res.one_field_ref().as<uint32_t>();
            txn.exec("INSERT INTO files (fs_entry_id, size_bytes) VALUES ($1, 1)", pqxx::params{id});
            return id;
        });
    }

    static void sql(const std::string& statement, const pqxx::params& params = {}) {
        db::Transactions::exec("test::sql", [&](pqxx::work& txn) { txn.exec(statement, params); });
    }

    static int64_t addBlob(const uint32_t vaultId, const std::string& iv, const unsigned int keyVersion = 1,
                           const uint64_t bytes = 100) {
        return db::Transactions::exec("test::addBlob", [&](pqxx::work& txn) {
            return rq::Blob::insert(txn, {.id = 0, .vault_id = vaultId, .storage_name = blobName(),
                                          .encryption_iv = iv, .key_version = keyVersion, .cipher_bytes = bytes,
                                          .plaintext_bytes = bytes > 16 ? bytes - 16 : 0,
                                          .content_hash = std::nullopt, .created_at = 0})
                .id;
        });
    }

    static rq::NewGeneration version(const uint32_t vaultId, const std::optional<uint32_t> fileId, const std::string& path,
                                     const std::optional<int64_t> blobId = std::nullopt,
                                     const rq::UpstreamState state = rq::UpstreamState::None) {
        return {.vault_id = vaultId, .file_id = fileId, .blob_id = blobId, .content_hash = "h", .size_bytes = 10,
                .mime_type = std::nullopt, .path = path, .mode = 0644, .source_updated_at = 1700000000,
                .created_by = superUser->id, .snapshot_id = std::nullopt, .rel_path = std::nullopt,
                .reason = "overwrite", .upstream_state = state, .upstream_key = std::nullopt};
    }
};

}

namespace vh::test_recovery_db {

TEST_F(RecoveryDbTest, PolicyDefaultsWithoutARowAndUpsertRoundTrips) {
    const auto vaultId = addVault();
    const auto none = rq::Policy::get(vaultId);
    EXPECT_FALSE(none.stored);
    EXPECT_EQ(none.mode, rm::Mode::Off);
    EXPECT_FALSE(none.local_versioning.enabled);
    EXPECT_FALSE(none.snapshot_quota_bytes);

    rq::PolicyRow p = none;
    p.mode = rm::Mode::LocalSnapshots;
    p.snapshot_quota_bytes = 1 << 20;
    p.cost_alert_monthly = "12.50";
    p.cost_alert_currency = "USD";
    p.local_versioning = {.enabled = true, .keep_last = 5, .max_age_days = 30, .quota_bytes = 4096};
    p.updated_by = superUser->id;
    rq::Policy::upsert(p);

    const auto got = rq::Policy::get(vaultId);
    EXPECT_TRUE(got.stored);
    EXPECT_EQ(got.mode, rm::Mode::LocalSnapshots);
    EXPECT_EQ(got.snapshot_quota_bytes, 1u << 20);
    EXPECT_EQ(got.cost_alert_monthly, "12.5") << "NUMERIC text, trailing zeros trimmed";
    EXPECT_EQ(got.cost_alert_currency, "USD");
    EXPECT_EQ(got.local_versioning.keep_last, 5u);
    EXPECT_EQ(got.local_versioning.max_age_days, 30u);
    EXPECT_EQ(got.local_versioning.quota_bytes, 4096u);
    EXPECT_EQ(got.updated_by, superUser->id);
    EXPECT_TRUE(got.updated_at);
    const auto vaults = rq::Policy::listLocalVersioningVaults();
    EXPECT_NE(std::ranges::find(vaults, vaultId), vaults.end());

    p.local_versioning.enabled = false;
    p.cost_alert_monthly.reset();
    rq::Policy::upsert(p);
    EXPECT_FALSE(rq::Policy::get(vaultId).cost_alert_monthly);
    const auto after = rq::Policy::listLocalVersioningVaults();
    EXPECT_EQ(std::ranges::find(after, vaultId), after.end());

    p.local_versioning.keep_last = 0;
    EXPECT_THROW(rq::Policy::upsert(p), pqxx::check_violation);
}

TEST_F(RecoveryDbTest, BlobsDeduplicatePerGenerationAndDeleteOnlyWhenUnreferenced) {
    const auto vaultId = addVault();
    const auto other = addVault();
    const auto first = db::Transactions::exec("t", [&](pqxx::work& txn) {
        return rq::Blob::insert(txn, {.vault_id = vaultId, .storage_name = blobName(),
                                      .encryption_iv = "ivA", .key_version = 1, .cipher_bytes = 116,
                                      .plaintext_bytes = 100});
    });
    EXPECT_TRUE(first.inserted);
    const auto again = db::Transactions::exec("t", [&](pqxx::work& txn) {
        return rq::Blob::insert(txn, {.vault_id = vaultId, .storage_name = blobName(),
                                      .encryption_iv = "ivA", .key_version = 1, .cipher_bytes = 116,
                                      .plaintext_bytes = 100});
    });
    EXPECT_FALSE(again.inserted);
    EXPECT_EQ(again.id, first.id);
    EXPECT_EQ(again.storage_name, first.storage_name);

    // Another key version, another vault, or an empty IV are different generations.
    EXPECT_NE(addBlob(vaultId, "ivA", 2), first.id);
    EXPECT_NE(addBlob(other, "ivA", 1), first.id);
    const auto empty1 = addBlob(vaultId, "");
    const auto empty2 = addBlob(vaultId, "");
    EXPECT_NE(empty1, empty2) << "an empty IV is never deduplicated";

    ASSERT_TRUE(rq::Blob::findByGeneration(vaultId, "ivA", 1));
    EXPECT_FALSE(rq::Blob::findByGeneration(vaultId, "", 0));
    EXPECT_EQ(rq::Blob::keyVersions(vaultId), (std::vector<unsigned int>{1, 2}));

    const auto fileId = addFile(vaultId, "/blob.txt");
    static_cast<void>(rq::Generation::insertLocalVersion(version(vaultId, fileId, "/blob.txt", first.id)));
    EXPECT_EQ(rq::Blob::refCount(first.id), 1u);
    EXPECT_FALSE(rq::Blob::deleteIfUnreferenced(first.id)) << "referenced";
    EXPECT_TRUE(rq::Blob::get(first.id));

    const auto usage = rq::Blob::usage(vaultId);
    EXPECT_EQ(usage.blobs, 4u);
    EXPECT_EQ(usage.version_blobs, 1u);
    EXPECT_EQ(usage.version_bytes, 116u);
    EXPECT_EQ(usage.unreferenced_blobs, 3u);
    EXPECT_EQ(rq::Blob::physicalBytes(vaultId), usage.bytes);

    const auto deleted = rq::Blob::deleteIfUnreferenced(empty1);
    ASSERT_TRUE(deleted);
    EXPECT_EQ(deleted->id, empty1);
    EXPECT_FALSE(rq::Blob::get(empty1));
    EXPECT_FALSE(rq::Blob::deleteIfUnreferenced(empty1)) << "already gone";

    const auto orphans = rq::Blob::listUnreferenced(vaultId, 0, 10);
    EXPECT_EQ(orphans.size(), 2u);
    EXPECT_TRUE(rq::Blob::listUnreferenced(vaultId, 3600, 10).empty()) << "younger than the minimum age";
    const auto byName = rq::Blob::existingStorageNames(vaultId, {first.storage_name, "nope", blobName()});
    EXPECT_EQ(byName, std::vector<std::string>{first.storage_name});
    EXPECT_TRUE(rq::Blob::existingStorageNames(other, {first.storage_name}).empty());
}

TEST_F(RecoveryDbTest, SnapshotLifecycleNameConflictAndRemoval) {
    const auto vaultId = addVault();
    const auto fileA = addFile(vaultId, "/docs/a.txt");
    const auto fileB = addFile(vaultId, "/docs/sub/b.txt");
    const auto blobA = addBlob(vaultId, "ivSA");
    const auto blobB = addBlob(vaultId, "ivSB");

    const auto snapId = rq::Snapshot::create({.vault_id = vaultId, .name = "before-cleanup", .root_path = "/docs",
                                              .root_type = rm::PointKind::Directory, .root_entry_id = std::nullopt,
                                              .created_by = superUser->id, .created_by_name = "super"});
    EXPECT_EQ(rq::Snapshot::get(snapId)->state, "creating");

    db::Transactions::exec("t", [&](pqxx::work& txn) {
        auto a = version(vaultId, fileA, "/docs/a.txt", blobA);
        a.snapshot_id = snapId;
        a.rel_path = "a.txt";
        auto b = version(vaultId, fileB, "/docs/sub/b.txt", blobB);
        b.snapshot_id = snapId;
        b.rel_path = "sub/b.txt";
        EXPECT_EQ(rq::Generation::insertSnapshotMember(txn, a).version_number, 1);
        static_cast<void>(rq::Generation::insertSnapshotMember(txn, b));
        EXPECT_TRUE(rq::Snapshot::finish(txn, snapId, {.file_count = 2, .directory_count = 2, .plaintext_bytes = 20,
                                                       .empty_directories = {"/docs/empty"},
                                                       .skipped_json = R"([{"path":"/docs/l","reason":"symlink"}])"}));
    });
    const auto snap = rq::Snapshot::get(snapId);
    ASSERT_TRUE(snap);
    EXPECT_EQ(snap->state, "ready");
    EXPECT_EQ(snap->file_count, 2u);
    EXPECT_EQ(snap->root_type, rm::PointKind::Directory);
    EXPECT_EQ(snap->empty_directories, std::vector<std::string>{"/docs/empty"});
    EXPECT_EQ(json::parse(snap->skipped_json).at(0).at("reason"), "symlink");
    EXPECT_TRUE(snap->completed_at);
    EXPECT_EQ(snap->created_by_name, "super");
    EXPECT_FALSE(rq::Snapshot::finish(snapId, {})) << "only a creating snapshot finishes";

    // Members: origin snapshot, never part of the upstream backlog.
    const auto members = rq::Generation::listSnapshotMembers(snapId, "", 10);
    ASSERT_EQ(members.size(), 2u);
    EXPECT_EQ(members[0].rel_path, "a.txt");
    EXPECT_EQ(members[0].origin, rq::Origin::Snapshot);
    EXPECT_EQ(members[0].upstream_state, rq::UpstreamState::None);
    EXPECT_FALSE(members[0].reason) << "a member has no change reason";
    EXPECT_EQ(members[0].storage_name, rq::Blob::get(blobA)->storage_name);
    EXPECT_EQ(rq::Generation::listSnapshotMembers(snapId, "a.txt", 10).size(), 1u);
    EXPECT_EQ(rq::Generation::countSnapshotMembers(snapId), 2u);

    // Name taken in this vault (not in another one); the caller's transaction survives the refusal.
    EXPECT_THROW(static_cast<void>(rq::Snapshot::create({.vault_id = vaultId, .name = "before-cleanup",
                                                         .root_path = "/docs/a.txt"})),
                 rq::SnapshotNameTaken);
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        EXPECT_THROW(static_cast<void>(rq::Snapshot::create(txn, {.vault_id = vaultId, .name = "before-cleanup",
                                                                  .root_path = "/docs"})),
                     ops::Conflict);
        EXPECT_GT(rq::Snapshot::create(txn, {.vault_id = vaultId, .name = "other", .root_path = "/docs/a.txt"}), 0);
    });
    EXPECT_GT(rq::Snapshot::create({.vault_id = addVault(), .name = "before-cleanup", .root_path = "/"}), 0);
    EXPECT_TRUE(rq::Snapshot::getByName(vaultId, "before-cleanup"));

    // Listing.
    EXPECT_EQ(rq::Snapshot::listByVault(vaultId, 10).size(), 2u);
    EXPECT_EQ(rq::Snapshot::listByVault(vaultId, 10, snapId).size(), 0u);
    EXPECT_EQ(rq::Snapshot::listUnderPath(vaultId, "/docs", 10).size(), 2u);
    EXPECT_EQ(rq::Snapshot::listUnderPath(vaultId, "/", 10).size(), 2u);
    EXPECT_EQ(rq::Snapshot::listUnderPath(vaultId, "/doc", 10).size(), 0u) << "a prefix is not a parent directory";
    const auto holding = [&](const std::string& path) {
        std::vector<int64_t> ids;
        for (const auto& s : rq::Snapshot::listContainingPath(vaultId, path, 10)) ids.push_back(s.id);
        return ids;
    };
    EXPECT_EQ(holding("/docs/sub/b.txt"), std::vector<int64_t>{snapId});
    EXPECT_EQ(holding("/docs/sub"), std::vector<int64_t>{snapId});
    EXPECT_EQ(holding("/docs/empty"), std::vector<int64_t>{snapId});
    EXPECT_TRUE(holding("/docs/none.txt").empty());
    EXPECT_TRUE(holding("/docs/sub_").empty()) << "LIKE metacharacters are escaped";

    // Fail path.
    const auto failing = rq::Snapshot::create({.vault_id = vaultId, .root_path = "/x"});
    EXPECT_TRUE(rq::Snapshot::fail(failing, "disk full"));
    EXPECT_EQ(rq::Snapshot::get(failing)->state, "failed");
    EXPECT_EQ(rq::Snapshot::get(failing)->error, "disk full");

    // blobB is also a local version: removing the snapshot frees only blobA.
    static_cast<void>(rq::Generation::insertLocalVersion(version(vaultId, fileB, "/docs/sub/b.txt", blobB)));
    EXPECT_TRUE(rq::Snapshot::markDeleting(snapId));
    EXPECT_FALSE(rq::Snapshot::markDeleting(snapId));
    EXPECT_FALSE(rq::Snapshot::getByName(vaultId, "before-cleanup")) << "a deleting snapshot frees its name";
    EXPECT_GT(rq::Snapshot::create({.vault_id = vaultId, .name = "before-cleanup", .root_path = "/docs"}), 0);
    EXPECT_EQ(rq::Snapshot::remove(snapId), std::vector<int64_t>{blobA});
    EXPECT_FALSE(rq::Snapshot::get(snapId));
    EXPECT_EQ(rq::Generation::countSnapshotMembers(snapId), 0u) << "members cascade";
    EXPECT_TRUE(rq::Blob::get(blobA)) << "the row stays until the store removes it";
}

TEST_F(RecoveryDbTest, VersionNumbersStayUniqueUnderConcurrentCaptures) {
    const auto vaultId = addVault();
    const auto fileId = addFile(vaultId, "/hot.txt");
    constexpr int kThreads = 6, kEach = 8;
    std::vector<std::future<std::vector<int>>> futures;
    for (int t = 0; t < kThreads; ++t)
        futures.push_back(std::async(std::launch::async, [&] {
            std::vector<int> numbers;
            for (int i = 0; i < kEach; ++i)
                numbers.push_back(rq::Generation::insertLocalVersion(version(vaultId, fileId, "/hot.txt")).version_number);
            return numbers;
        }));
    std::set<int> all;
    for (auto& f : futures)
        for (const auto n : f.get()) EXPECT_TRUE(all.insert(n).second) << "duplicate version number " << n;
    EXPECT_EQ(all.size(), static_cast<size_t>(kThreads * kEach));
    EXPECT_EQ(*all.begin(), 1);
    EXPECT_EQ(*all.rbegin(), kThreads * kEach);
    const auto history = rq::Generation::listByFile(fileId, 1000);
    ASSERT_EQ(history.size(), static_cast<size_t>(kThreads * kEach));
    EXPECT_EQ(history.front().version_number, kThreads * kEach) << "newest first";
}

TEST_F(RecoveryDbTest, GenerationsOutliveTheLiveFile) {
    const auto vaultId = addVault();
    const auto fileId = addFile(vaultId, "/gone.txt");
    const auto blob = addBlob(vaultId, "ivGone");
    const auto v1 = rq::Generation::insertLocalVersion(version(vaultId, fileId, "/gone.txt", blob));
    const auto v2 = rq::Generation::insertLocalVersion(version(vaultId, fileId, "/gone.txt"));
    EXPECT_EQ(v2.version_number, 2);

    sql("DELETE FROM fs_entry WHERE id = $1", pqxx::params{fileId});   // cascades files; file_versions SET NULL
    const auto kept = rq::Generation::get(v1.id);
    ASSERT_TRUE(kept) << "deleting the live file keeps its generations";
    EXPECT_FALSE(kept->file_id);
    EXPECT_EQ(kept->blob_id, blob);
    EXPECT_EQ(kept->encryption_iv, "ivGone");
    EXPECT_EQ(rq::Generation::listByPath(vaultId, "/gone.txt", std::nullopt, 10).size(), 2u);
    EXPECT_EQ(rq::Generation::listByPath(vaultId, "/gone.txt", rq::Origin::Snapshot, 10).size(), 0u);
    EXPECT_EQ(rq::Generation::listVersionsUnder(vaultId, "/", 10).size(), 2u);

    // A capture by path after the file is gone continues that path's numbering.
    const auto v3 = rq::Generation::insertLocalVersion(version(vaultId, std::nullopt, "/gone.txt"));
    EXPECT_EQ(v3.version_number, 3);
    EXPECT_FALSE(rq::Generation::get(v3.id)->file_id);

    EXPECT_FALSE(rq::Generation::remove(v2.id)) << "no blob";
    EXPECT_EQ(rq::Generation::remove(v1.id), blob) << "its blob is now unreferenced";
}

TEST_F(RecoveryDbTest, BacklogReplaysInFileAndVersionOrderAndTracksTransitions) {
    const auto vaultId = addVault();
    const auto f1 = addFile(vaultId, "/q1.txt");
    const auto f2 = addFile(vaultId, "/q2.txt");
    std::vector<int64_t> f1ids, f2ids;
    for (int i = 0; i < 3; ++i) {
        f2ids.push_back(rq::Generation::insertLocalVersion(version(vaultId, f2, "/q2.txt", std::nullopt,
                                                                   rq::UpstreamState::Pending)).id);
        f1ids.push_back(rq::Generation::insertLocalVersion(version(vaultId, f1, "/q1.txt", std::nullopt,
                                                                   rq::UpstreamState::Pending)).id);
    }
    static_cast<void>(rq::Generation::insertLocalVersion(version(vaultId, f1, "/q1.txt")));   // not part of the backlog

    const auto pending = rq::Generation::listPending(vaultId, 100);
    ASSERT_EQ(pending.size(), 6u);
    for (size_t i = 1; i < pending.size(); ++i) {
        const auto& a = pending[i - 1];
        const auto& b = pending[i];
        EXPECT_TRUE(*a.file_id < *b.file_id || (*a.file_id == *b.file_id && a.version_number < b.version_number));
    }
    EXPECT_EQ(rq::Generation::listPendingForFile(f2).size(), 3u);
    EXPECT_EQ(rq::Generation::listPendingForFile(f2).front().id, f2ids[0]);

    auto summary = rq::Generation::backlog(vaultId);
    EXPECT_EQ(summary.pending, 6u);
    EXPECT_EQ(summary.pending_bytes, 60u);
    EXPECT_TRUE(summary.oldest_pending_at);
    EXPECT_EQ(summary.failing, 0u);

    rq::Generation::recordFailure(f1ids[0], "503 SlowDown");
    rq::Generation::recordFailure(f1ids[0], "timeout");
    summary = rq::Generation::backlog(vaultId);
    EXPECT_EQ(summary.failing, 1u);
    EXPECT_EQ(summary.last_error, "timeout");
    EXPECT_EQ(rq::Generation::get(f1ids[0])->upstream_attempts, 2u);

    EXPECT_TRUE(rq::Generation::markSent(f1ids[0], "v-abc"));
    EXPECT_FALSE(rq::Generation::markSent(f1ids[0], "v-def")) << "only pending → sent";
    const auto sent = rq::Generation::get(f1ids[0]);
    EXPECT_EQ(sent->upstream_state, rq::UpstreamState::Sent);
    EXPECT_EQ(sent->upstream_version_id, "v-abc");
    EXPECT_TRUE(sent->upstream_sent_at);
    EXPECT_FALSE(sent->upstream_error);
    EXPECT_EQ(rq::Generation::markSkipped(f2ids), 3u);
    EXPECT_EQ(rq::Generation::backlog(vaultId).pending, 2u);
    EXPECT_EQ(rq::Generation::listPending(vaultId, 100).front().id, f1ids[1]);
}

TEST_F(RecoveryDbTest, RetentionNeverPrunesPendingVersionsOrSnapshotMembers) {
    const auto vaultId = addVault();
    const auto fileId = addFile(vaultId, "/r.txt");
    std::vector<int64_t> ids, blobs;
    for (int i = 0; i < 5; ++i) {
        blobs.push_back(addBlob(vaultId, "ivR" + std::to_string(i), 1, 1000));
        ids.push_back(rq::Generation::insertLocalVersion(
            version(vaultId, fileId, "/r.txt", blobs.back(),
                    i == 0 ? rq::UpstreamState::Pending : rq::UpstreamState::Sent)).id);
    }
    // Spread created_at over days: oldest first.
    for (int i = 0; i < 5; ++i)
        sql("UPDATE file_versions SET created_at = CURRENT_TIMESTAMP - make_interval(days => $2) WHERE id = $1",
            pqxx::params{ids[i], 50 - i * 10});
    // A snapshot member of the same file shares the oldest-but-one blob.
    const auto snapId = rq::Snapshot::create({.vault_id = vaultId, .root_path = "/r.txt"});
    const auto member = db::Transactions::exec("t", [&](pqxx::work& txn) {
        auto m = version(vaultId, fileId, "/r.txt", blobs[1]);
        m.snapshot_id = snapId;
        m.rel_path = "r.txt";
        return rq::Generation::insertSnapshotMember(txn, m).id;
    });
    sql("UPDATE file_versions SET created_at = CURRENT_TIMESTAMP - make_interval(days => 100) WHERE id = $1",
        pqxx::params{member});

    const auto now = std::time(nullptr);
    const auto pruned = [&](const rq::RetentionRule& rule) {
        std::vector<int64_t> out;
        for (const auto& g : rq::Generation::listPrunable(vaultId, rule, now)) out.push_back(g.id);
        return out;
    };
    EXPECT_TRUE(pruned({}).empty()) << "no limits, nothing pruned";
    EXPECT_EQ(pruned({.keep_last = 2}), (std::vector<int64_t>{ids[1], ids[2]})) << "pending ids[0] kept";
    EXPECT_EQ(pruned({.max_age_days = 25}), (std::vector<int64_t>{ids[1], ids[2]}));
    EXPECT_TRUE(pruned({.keep_last = 10, .max_age_days = 365}).empty());
    // Quota over 5000 version bytes, oldest prunable first. Blob 1 is shared with the snapshot member, but pruning
    // ids[1] still takes it out of the version bytes (no other version row references it).
    EXPECT_EQ(pruned({.quota_bytes = 4000}), std::vector<int64_t>{ids[1]});
    EXPECT_EQ(pruned({.quota_bytes = 2500}), (std::vector<int64_t>{ids[1], ids[2], ids[3]}));
    EXPECT_EQ(pruned({.quota_bytes = 0}), (std::vector<int64_t>{ids[1], ids[2], ids[3], ids[4]}));

    const auto freed = rq::Generation::removeVersions(vaultId, {ids[0], ids[1], ids[2], member});
    EXPECT_EQ(freed, std::vector<int64_t>{blobs[2]}) << "blob 1 still has the snapshot member";
    EXPECT_TRUE(rq::Generation::get(ids[0])) << "pending is never removed";
    EXPECT_TRUE(rq::Generation::get(member)) << "a snapshot member is never removed as a version";
    EXPECT_FALSE(rq::Generation::get(ids[1]));

    // Releasing a sent version's body.
    const auto released = db::Transactions::exec("t", [&](pqxx::work& txn) { return rq::Generation::releaseBlob(txn, ids[3]); });
    EXPECT_EQ(released, blobs[3]);
    EXPECT_FALSE(rq::Generation::get(ids[3])->blob_id);
    const auto memberRelease = db::Transactions::exec("t", [&](pqxx::work& txn) { return rq::Generation::releaseBlob(txn, member); });
    EXPECT_FALSE(memberRelease);
    EXPECT_EQ(rq::Generation::get(member)->blob_id, blobs[1]);

    const auto usage = rq::Generation::usage(vaultId);
    EXPECT_EQ(usage.snapshots.count, 1u);
    EXPECT_EQ(usage.snapshots.stored_bytes, 1000u);
    EXPECT_EQ(usage.versions.count, 3u);
    EXPECT_EQ(usage.versions.stored_bytes, 2000u) << "ids[0] and ids[4] still hold blobs";
}

TEST_F(RecoveryDbTest, ObjectVersionsKeepOriginAndMetadataAndTrackNoncurrentAndGone) {
    const auto vaultId = addVault();
    using clock = std::chrono::system_clock;
    const auto t0 = clock::now();
    rq::ObjectVersionRow ours{.vault_id = vaultId, .object_key = "docs/a.txt", .version_id = "v1", .is_latest = true,
                              .etag = "\"e1\"", .size_bytes = 116, .last_modified = 1760000000,
                              .origin = "vaulthalla", .encrypted = true, .encryption_iv = "ivO", .key_version = 3,
                              .content_hash = "h1", .plaintext_bytes = 100};
    const auto id1 = rq::ObjectVersion::upsert(ours, t0);

    // The same version observed in a listing: metadata kept, origin not downgraded.
    rq::ObjectVersionRow observed{.vault_id = vaultId, .object_key = "docs/a.txt", .version_id = "v1",
                                  .is_latest = true, .size_bytes = 116, .storage_class = "STANDARD",
                                  .last_modified = 1760000000, .origin = "observed"};
    EXPECT_EQ(rq::ObjectVersion::upsert(observed, t0), id1);
    auto row = rq::ObjectVersion::get(id1);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->origin, "vaulthalla");
    EXPECT_EQ(row->encryption_iv, "ivO");
    EXPECT_EQ(row->key_version, 3u);
    EXPECT_EQ(row->storage_class, "STANDARD");
    EXPECT_EQ(row->etag, "\"e1\"");
    EXPECT_EQ(rq::ObjectVersion::keyVersions(vaultId), std::vector<unsigned int>{3});

    // A newer version arrives: v1 becomes noncurrent.
    auto v2 = ours;
    v2.version_id = "v2";
    v2.size_bytes = 200;
    v2.last_modified = 1760003600;
    static_cast<void>(rq::ObjectVersion::upsert(v2, t0));
    EXPECT_EQ(rq::ObjectVersion::markSuperseded(vaultId, "docs/a.txt", "v2", 1760003600), 1u);
    row = rq::ObjectVersion::get(id1);
    EXPECT_FALSE(row->is_latest);
    EXPECT_EQ(row->became_noncurrent_at, 1760003600);
    static_cast<void>(rq::ObjectVersion::markSuperseded(vaultId, "docs/a.txt", "v2", 1760009999));
    EXPECT_EQ(rq::ObjectVersion::get(id1)->became_noncurrent_at, 1760003600) << "kept when already set";
    // Seeing the noncurrent version again in a listing doesn't reset when it became noncurrent.
    observed.is_latest = false;
    static_cast<void>(rq::ObjectVersion::upsert(observed, t0));
    EXPECT_EQ(rq::ObjectVersion::get(id1)->became_noncurrent_at, 1760003600);

    // A delete marker and an observed version of another key under the prefix.
    static_cast<void>(rq::ObjectVersion::upsert({.vault_id = vaultId, .object_key = "docs/b.txt", .version_id = "m1",
                                                 .is_delete_marker = true, .is_latest = true,
                                                 .last_modified = 1760007200, .origin = "observed"}, t0));
    static_cast<void>(rq::ObjectVersion::upsert({.vault_id = vaultId, .object_key = "docs/b.txt", .version_id = "b0",
                                                 .is_latest = false, .last_modified = 1760000000, .origin = "observed",
                                                 .became_noncurrent_at = 1760007200}, t0));
    static_cast<void>(rq::ObjectVersion::upsert({.vault_id = vaultId, .object_key = "other/c.txt", .version_id = "c1",
                                                 .is_latest = true, .size_bytes = 5, .last_modified = 1760000000,
                                                 .origin = "observed"}, t0));

    auto summary = rq::ObjectVersion::noncurrentSummary(vaultId);
    EXPECT_EQ(summary.versions, 2u);
    EXPECT_EQ(summary.bytes, 116u);
    EXPECT_EQ(summary.unknown_size, 1u);
    EXPECT_EQ(summary.delete_markers, 1u);
    EXPECT_EQ(summary.oldest_noncurrent_at, 1760003600);

    EXPECT_EQ(rq::ObjectVersion::listForKey(vaultId, "docs/a.txt", false, 10).front().version_id, "v2");
    EXPECT_EQ(rq::ObjectVersion::listUnderPrefix(vaultId, "docs/", false, 10).size(), 4u);
    const auto asOf = rq::ObjectVersion::listAsOf(vaultId, "docs/", 1760005000, 10);
    ASSERT_EQ(asOf.size(), 2u);
    EXPECT_EQ(asOf[0].version_id, "v2");
    EXPECT_EQ(asOf[1].version_id, "b0");
    EXPECT_EQ(rq::ObjectVersion::listAsOf(vaultId, "docs/", 1760010000, 10)[1].version_id, "m1") << "deleted by then";

    // Byte-hours: v1 (116 B) noncurrent from 1760003600; window of 2 h from there.
    const auto bh = rq::ObjectVersion::noncurrentByteHours(vaultId, 1760003600, 1760003600 + 7200);
    EXPECT_EQ(std::stod(bh.byte_hours), 232.0);
    EXPECT_EQ(bh.versions, 1u);
    EXPECT_EQ(bh.unknown_size, 1u) << "b0 (no size) is noncurrent for the window's last hour";
    EXPECT_EQ(rq::ObjectVersion::noncurrentByteHours(vaultId, 1760003600, 1760007200).unknown_size, 0u)
        << "b0 became noncurrent after this window";
    EXPECT_EQ(rq::ObjectVersion::noncurrentByteHours(vaultId, 10, 10).byte_hours, "0");

    // A complete listing of docs/ that no longer shows v1: gone (only under the prefix, only rows not seen since).
    const auto listing = t0 + std::chrono::seconds(5);
    for (const auto& [key, ver] : std::vector<std::pair<std::string, std::string>>{{"docs/a.txt", "v2"},
                                                                                   {"docs/b.txt", "m1"},
                                                                                   {"docs/b.txt", "b0"}}) {
        auto seen = *rq::ObjectVersion::find(vaultId, key, ver);
        static_cast<void>(rq::ObjectVersion::upsert(seen, listing + std::chrono::milliseconds(10)));
    }
    EXPECT_EQ(rq::ObjectVersion::markGoneUnder(vaultId, "docs/", listing), 1u);
    EXPECT_TRUE(rq::ObjectVersion::get(id1)->gone_at);
    EXPECT_FALSE(rq::ObjectVersion::find(vaultId, "other/c.txt", "c1")->gone_at) << "outside the prefix";
    EXPECT_EQ(rq::ObjectVersion::listForKey(vaultId, "docs/a.txt", false, 10).size(), 1u);
    EXPECT_EQ(rq::ObjectVersion::listForKey(vaultId, "docs/a.txt", true, 10).size(), 2u);
    EXPECT_EQ(rq::ObjectVersion::noncurrentSummary(vaultId).versions, 1u);
    // Gone versions still accrued while they existed.
    EXPECT_GT(std::stod(rq::ObjectVersion::noncurrentByteHours(vaultId, 1760003600, 1760003600 + 7200).byte_hours), 0.0);
    // Seen again: no longer gone.
    static_cast<void>(rq::ObjectVersion::upsert(observed, listing + std::chrono::seconds(1)));
    EXPECT_FALSE(rq::ObjectVersion::get(id1)->gone_at);

    EXPECT_THROW(static_cast<void>(rq::ObjectVersion::upsert({.vault_id = vaultId, .object_key = "k",
                                                              .version_id = "x", .origin = "guess"})),
                 std::invalid_argument);
}

TEST_F(RecoveryDbTest, UsageCountersAddUpPerVaultAndDay) {
    const auto vaultId = addVault();
    rq::UsageCounters delta;
    delta.put_requests = 3;
    delta.overwritten_bytes = 1000;
    rq::Usage::add(vaultId, "2026-10-01", delta);
    rq::Usage::add(vaultId, "2026-10-01", delta);
    delta.version_restore_requests = 1;
    rq::Usage::addMany({{.vault_id = vaultId, .day = "2026-10-03", .counters = delta},
                        {.vault_id = vaultId, .day = "2026-10-01", .counters = delta}});
    rq::Usage::add(vaultId, "2026-10-02", {});   // empty: nothing written

    const auto days = rq::Usage::range(vaultId, "2026-09-01", "2026-10-31");
    ASSERT_EQ(days.size(), 2u);
    EXPECT_EQ(days[0].day, "2026-10-01");
    EXPECT_EQ(days[0].counters.put_requests, 9u);
    EXPECT_EQ(days[0].counters.overwritten_bytes, 3000u);
    EXPECT_EQ(days[0].counters.version_restore_requests, 1u);
    EXPECT_EQ(days[1].day, "2026-10-03");

    const auto totals = rq::Usage::totals(vaultId);
    EXPECT_EQ(totals.days, 2u);
    EXPECT_EQ(totals.first_day, "2026-10-01");
    EXPECT_EQ(totals.last_day, "2026-10-03");
    EXPECT_EQ(totals.counters.put_requests, 12u);
    EXPECT_EQ(rq::Usage::totals(vaultId, "2026-10-02", "2026-10-31").counters.put_requests, 3u);
    EXPECT_EQ(rq::Usage::totals(addVault()).days, 0u);

    rq::Usage::add(vaultId, db::Transactions::read("today", [](pqxx::transaction_base& txn) {
                       return txn.exec("SELECT to_char(CURRENT_DATE, 'YYYY-MM-DD')").one_field_ref().as<std::string>();
                   }), delta);
    EXPECT_EQ(rq::Usage::lastDays(vaultId, 7).size(), 1u);

    rq::UsageCounters sum;
    sum += delta;
    sum += delta;
    EXPECT_EQ(sum.put_requests, 6u);
    EXPECT_FALSE(sum.empty());
}

TEST_F(RecoveryDbTest, PlansMoveThroughTheirStates) {
    const auto vaultId = addVault();
    const auto now = std::time(nullptr);
    const auto id = rq::Plan::insert({.vault_id = vaultId, .token = "tok", .source_json = R"({"id":"snap-1"})",
                                      .destination = "/restored", .items_json = R"([{"source_id":"lv-1"}])",
                                      .summary_json = R"({"creates":1})", .expires_at = now + 1800,
                                      .created_by = superUser->id});
    auto plan = rq::Plan::get(id);
    ASSERT_TRUE(plan);
    EXPECT_EQ(plan->state, "planned");
    EXPECT_EQ(json::parse(plan->source_json).at("id"), "snap-1");
    EXPECT_EQ(plan->destination, "/restored");
    EXPECT_EQ(plan->expires_at, now + 1800);

    EXPECT_FALSE(rq::Plan::finish(id, "done", "{}")) << "not running";
    EXPECT_TRUE(rq::Plan::start(id, now));
    const auto started = rq::Plan::get(id)->started_at;
    EXPECT_TRUE(started);
    rq::Plan::saveResult(id, R"({"restored":1})");
    rq::Plan::saveItems(id, R"([{"source_id":"lv-1","outcome":"restored"}])");
    EXPECT_TRUE(rq::Plan::finish(id, "partial", R"({"restored":1,"failed":1})"));
    EXPECT_TRUE(rq::Plan::start(id, now)) << "a partial plan resumes";
    EXPECT_EQ(rq::Plan::get(id)->started_at, started);
    EXPECT_TRUE(rq::Plan::finish(id, "done", R"({"restored":2})"));
    plan = rq::Plan::get(id);
    EXPECT_EQ(plan->state, "done");
    EXPECT_EQ(json::parse(*plan->result_json).at("restored"), 2);
    EXPECT_TRUE(plan->completed_at);
    EXPECT_FALSE(rq::Plan::start(id, now)) << "done is final";
    EXPECT_THROW(static_cast<void>(rq::Plan::finish(id, "planned", "{}")), std::invalid_argument);

    const auto stale = rq::Plan::insert({.vault_id = vaultId, .token = "old", .expires_at = now - 10});
    EXPECT_FALSE(rq::Plan::start(stale, now)) << "expired plans don't start";
    EXPECT_GE(rq::Plan::expire(now), 1u);
    EXPECT_EQ(rq::Plan::get(stale)->state, "expired");
    EXPECT_EQ(rq::Plan::listByVault(vaultId, 10).size(), 2u);
    EXPECT_GE(rq::Plan::purgeOlderThan(now + 3600), 2u);
    EXPECT_FALSE(rq::Plan::get(id));
}

}
