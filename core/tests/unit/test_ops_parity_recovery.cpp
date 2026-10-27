// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// File recovery through both surfaces: `vh vault recovery …` / `vh snapshot …` / `vh recovery …`
// (shell::Router::executeLine) and the ws vault.recovery.* / recovery.* handlers, against the test DB and local vaults.
// Verdicts are compared between the surfaces (and pinned for the super admin and an unprivileged account), outcomes
// by the state ops::recovery reports and the vault's files, never by text. See .claude/context/recovery.md.

#include "../helpers/sync_conflict_harness.hpp"

#include "db/query/fs/File.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Recovery.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "UsageManager.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_ops_parity_recovery {

using namespace test_support::sync_conflicts;
namespace rec = ops::recovery;
using json = nlohmann::json;
using WsRec = protocols::ws::handler::Recovery;

class RecoveryParityTest : public Harness {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;

    static void SetUpTestSuite() {
        Harness::SetUpTestSuite();
        if (skipTests) return;
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerRecoveryCommands(router);
        protocols::shell::commands::registerSnapshotCommands(router);
        protocols::shell::commands::vault::registerCommands(router);
    }

    // Non-interactive (no terminal): what a script sees.
    static int cli(const std::string& line, const UserPtr& user) {
        try {
            return router->executeLine(line, user, nullptr).exit_code;
        } catch (const std::exception&) {
            return 1;
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    // ws verdict: true = the op ran; false = refused (any ops::Error, NeedsConfirmation included).
    template <class Fn>
    static bool wsOk(Fn&& fn) {
        try {
            fn();
            return true;
        } catch (const ops::Error&) {
            return false;
        }
    }

    static uint32_t localVault(const std::string& prefix = "rcp") {
        return ops::vaults::create(superUser, {.name = prefix + "_" + tag(), .type = vault::model::VaultType::Local})->id;
    }

    static std::shared_ptr<storage::Engine> engineOf(const uint32_t vaultId) {
        return runtime::Deps::get().storageManager->getEngine(vaultId);
    }

    static void write(const uint32_t vaultId, const std::string& path, const std::string& content) {
        const auto engine = engineOf(vaultId);
        const auto parent = std::filesystem::path(path).parent_path();
        if (parent != "/" && !runtime::Deps::get().fsCache->entryExists(engine->vaultPathToFusePath(parent)))
            engine->mkdir(parent, superUser);
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine, .user = superUser, .overwrite = true}));
    }

    static std::string read(const uint32_t vaultId, const std::string& path) {
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        if (!file) return "<missing>";
        const auto reader = engineOf(vaultId)->openPlaintextReader(file);
        const auto data = storage::readAll(*reader, 1 << 20);
        return {data.begin(), data.end()};
    }

    // The settings both surfaces write, as the shared JSON (provider state and usage left out).
    static json settings(const uint32_t vaultId) {
        const json s = rec::status(superUser, vaultId);
        return {{"mode", s.at("mode")},
                {"snapshot_quota_bytes", s.at("snapshot_quota_bytes")},
                {"cost_alert_monthly", s.at("cost_alert_monthly")},
                {"local_versioning", s.at("local_versioning")}};
    }

    static std::vector<vh::recovery::RecoveryPoint> snapshots(const uint32_t vaultId, const std::string& path) {
        return rec::list(superUser, vaultId,
                         {.path = path, .include_snapshots = true, .include_versions = false, .include_provider = false});
    }

    static void allowSnapshots(const uint32_t vaultId) {
        (void)rec::update(superUser, vaultId, {.mode = vh::recovery::Mode::LocalSnapshots});
    }
};

// Reads and local-settings writes, for every seeded admin role on a vault the account doesn't own: the CLI and the ws
// handler agree; the super admin may, an unprivileged account may not.
TEST_F(RecoveryParityTest, EverySeededRoleGetsTheSameVerdictOnBothSurfaces) {
    const auto cliVault = localVault(), wsVault = localVault();
    for (const auto id : {cliVault, wsVault}) {
        allowSnapshots(id);
        write(id, "/docs/a.txt", "alpha");
    }

    for (const auto* role : {"unprivileged", "auditor", "support", "identity_admin", "security_admin", "platform_operator",
                             "vault_admin", "admin", "key_custodian", "super_admin"}) {
        const bool super = std::string(role) == "super_admin";
        const auto user = super ? superUser : createUser(std::string("rcp_") + role, role);
        const auto session = ws(user);
        // pinDenied: an unprivileged account is refused outright (a list instead leaves out what it can't read).
        const auto check = [&](const std::string& what, const std::string& line, auto&& wsCall, const bool pinDenied) {
            const bool viaCli = cli(line, user) == 0;
            const bool viaWs = wsOk(wsCall);
            EXPECT_EQ(viaCli, viaWs) << role << " " << what;
            if (super) {
                EXPECT_TRUE(viaCli) << role << " " << what;
            }
            if (pinDenied && std::string(role) == "unprivileged") {
                EXPECT_FALSE(viaCli || viaWs) << role << " " << what;
            }
        };
        const auto c = std::to_string(cliVault);

        check("status", "vault recovery status " + c,
              [&] { (void)WsRec::vaultStatus(json{{"vault_id", cliVault}}, session); }, true);
        check("costs", "recovery costs " + c, [&] { (void)WsRec::costs(json{{"vault_id", cliVault}}, session); }, true);
        check("list", "recovery list " + c + " /docs",
              [&] { (void)WsRec::list(json{{"vault_id", cliVault}, {"path", "/docs"}}, session); }, false);

        // A local-settings write on each surface (its own vault), then the same resulting state.
        const auto quota = std::to_string((1 + (std::string(role).size() % 7)) * 1048576);
        const bool cliWrote = cli("vault recovery set " + c + " --snapshot-quota " + quota, user) == 0;
        const bool wsWrote = wsOk([&] {
            (void)WsRec::vaultUpdate(json{{"vault_id", wsVault}, {"snapshot_quota_bytes", std::stoull(quota)}}, session);
        });
        EXPECT_EQ(cliWrote, wsWrote) << role << " update";
        if (super) {
            EXPECT_TRUE(cliWrote) << role << " update";
        }
        if (std::string(role) == "unprivileged") {
            EXPECT_FALSE(cliWrote || wsWrote) << role << " update";
        }
        EXPECT_EQ(settings(cliVault), settings(wsVault)) << role << " update state";
    }
}

TEST_F(RecoveryParityTest, LocalSettingsLeaveTheSameStateOnBothSurfaces) {
    const auto cliVault = localVault(), wsVault = localVault();
    ASSERT_EQ(cli("vault recovery set " + std::to_string(cliVault) + " --mode local-snapshots --snapshot-quota 50M "
                  "--cost-alert 12.50 --local-versioning on --keep-last 5 --max-age-days 30 --version-quota 1G",
                  superUser), 0);
    (void)WsRec::vaultUpdate(json{{"vault_id", wsVault},
                                  {"mode", "local_snapshots"},
                                  {"snapshot_quota_bytes", 50ull * 1024 * 1024},
                                  {"cost_alert_monthly", "12.50"},
                                  {"local_versioning", {{"enabled", true}, {"keep_last", 5}, {"max_age_days", 30},
                                                        {"quota_bytes", 1024ull * 1024 * 1024}}}},
                             ws(superUser));
    const auto viaCli = settings(cliVault);
    EXPECT_EQ(viaCli, settings(wsVault));
    EXPECT_EQ(viaCli.at("mode"), "local_snapshots");
    EXPECT_EQ(viaCli.at("local_versioning").at("keep_last"), 5);

    // Changing one local-versioning field keeps the others on both surfaces (the CLI merges into the stored policy).
    ASSERT_EQ(cli("vault recovery set " + std::to_string(cliVault) + " --keep-last 0", superUser), 0);
    (void)WsRec::vaultUpdate(json{{"vault_id", wsVault},
                                  {"local_versioning", {{"enabled", true}, {"keep_last", nullptr}, {"max_age_days", 30},
                                                        {"quota_bytes", 1024ull * 1024 * 1024}}}},
                             ws(superUser));
    EXPECT_EQ(settings(cliVault), settings(wsVault));
    EXPECT_TRUE(settings(cliVault).at("local_versioning").at("keep_last").is_null());
    EXPECT_EQ(settings(cliVault).at("local_versioning").at("max_age_days"), 30);

    // The same refusal for a malformed alert amount, and nothing changes.
    EXPECT_NE(cli("vault recovery set " + std::to_string(cliVault) + " --cost-alert 1e3", superUser), 0);
    EXPECT_THROW((void)WsRec::vaultUpdate(json{{"vault_id", wsVault}, {"cost_alert_monthly", 1000}}, ws(superUser)),
                 ops::Invalid);
    EXPECT_EQ(settings(cliVault), settings(wsVault));
}

TEST_F(RecoveryParityTest, ProviderVersioningIsNeverEnabledWithoutTheDisclosureOnEitherSurface) {
    // A local vault has no bucket: both surfaces refuse, and neither changes the mode. Without a terminal the CLI
    // refuses even with --yes when the op does; the ws refuses without a disclosure token.
    const auto cliVault = localVault(), wsVault = localVault();
    EXPECT_NE(cli("vault recovery set " + std::to_string(cliVault) + " --mode provider-versioning --retention 30d",
                  superUser), 0);
    EXPECT_NE(cli("vault recovery set " + std::to_string(cliVault) + " --mode provider-versioning --retention 30d --yes "
                  "--accept-unpriced", superUser), 0);
    EXPECT_FALSE(wsOk([&] {
        (void)WsRec::vaultUpdate(json{{"vault_id", wsVault}, {"mode", "provider_versioning"},
                                      {"provider_retention", "30d"}}, ws(superUser));
    }));
    EXPECT_EQ(settings(cliVault).at("mode"), "off");
    EXPECT_EQ(settings(wsVault).at("mode"), "off");
    EXPECT_EQ(cli("vault recovery disclosure " + std::to_string(cliVault), superUser) == 0,
              wsOk([&] { (void)WsRec::vaultDisclosure(json{{"vault_id", wsVault}}, ws(superUser)); }));
}

TEST_F(RecoveryParityTest, SnapshotsAreCreatedAndListedAlikeOnBothSurfaces) {
    const auto cliVault = localVault(), wsVault = localVault();
    const auto session = ws(superUser);

    // Mode off: refused on both surfaces, nothing taken.
    for (const auto id : {cliVault, wsVault}) {
        write(id, "/docs/a.txt", "alpha");
        write(id, "/docs/b.txt", "bravo");
    }
    EXPECT_NE(cli("snapshot create " + std::to_string(cliVault) + " /docs --name parity", superUser), 0);
    EXPECT_FALSE(wsOk([&] {
        (void)WsRec::snapshotCreate(json{{"vault_id", wsVault}, {"path", "/docs"}, {"name", "parity"}}, session);
    }));
    EXPECT_TRUE(snapshots(cliVault, "/docs").empty());
    EXPECT_TRUE(snapshots(wsVault, "/docs").empty());

    allowSnapshots(cliVault);
    allowSnapshots(wsVault);
    ASSERT_EQ(cli("snapshot create " + std::to_string(cliVault) + " /docs --name parity", superUser), 0);
    const auto created = WsRec::snapshotCreate(json{{"vault_id", wsVault}, {"path", "/docs"}, {"name", "parity"}}, session);
    EXPECT_TRUE(created.at("detail").at("point").at("id").get<std::string>().starts_with("snap-"));

    for (const auto id : {cliVault, wsVault}) {
        const auto points = snapshots(id, "/docs");
        ASSERT_EQ(points.size(), 1u) << id;
        EXPECT_EQ(points[0].name.value_or(""), "parity");
        EXPECT_EQ(points[0].kind, vh::recovery::PointKind::Directory);
        EXPECT_EQ(points[0].file_count.value_or(0), 2u);
        EXPECT_EQ(points[0].backend, vh::recovery::Backend::LocalSnapshot);
    }
    EXPECT_EQ(cli("snapshot list " + std::to_string(cliVault) + " /docs", superUser), 0);
    EXPECT_EQ(WsRec::list(json{{"vault_id", wsVault}, {"path", "/docs"}, {"include_versions", false},
                               {"include_provider", false}}, session).at("points").size(), 1u);
}

TEST_F(RecoveryParityTest, DeletingAPointNeedsTheSameConfirmationOnBothSurfaces) {
    const auto cliVault = localVault(), wsVault = localVault();
    std::string cliSnap, wsSnap;
    for (const auto id : {cliVault, wsVault}) {
        allowSnapshots(id);
        write(id, "/a.txt", "alpha");
    }
    cliSnap = rec::createSnapshot(superUser, cliVault, {.path = "/a.txt"}).point.id;
    wsSnap = rec::createSnapshot(superUser, wsVault, {.path = "/a.txt"}).point.id;
    const auto session = ws(superUser);

    // Unconfirmed: the CLI (no terminal, no --yes) and ws (no confirm) both refuse and keep the snapshot.
    EXPECT_NE(cli("snapshot delete " + cliSnap, superUser), 0);
    try {
        (void)WsRec::pointDelete(json{{"recovery_id", wsSnap}}, session);
        ADD_FAILURE() << "ws deleted a snapshot without confirmation";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, rec::POINT_DELETE);
    }
    EXPECT_EQ(snapshots(cliVault, "/a.txt").size(), 1u);
    EXPECT_EQ(snapshots(wsVault, "/a.txt").size(), 1u);

    EXPECT_EQ(cli("snapshot delete " + cliSnap + " --yes", superUser), 0);
    EXPECT_EQ(WsRec::pointDelete(json{{"recovery_id", wsSnap}, {"confirm", true}}, session).at("recovery_id"), wsSnap);
    EXPECT_TRUE(snapshots(cliVault, "/a.txt").empty());
    EXPECT_TRUE(snapshots(wsVault, "/a.txt").empty());

    // Someone who can't read the vault gets the same answer as for a point that doesn't exist (no oracle).
    const auto nobody = createUser("rcp_nobody", "unprivileged");
    const auto other = rec::createSnapshot(superUser, cliVault, {.path = "/a.txt"}).point.id;
    EXPECT_NE(cli("recovery inspect " + other, nobody), 0);
    EXPECT_THROW((void)WsRec::inspect(json{{"recovery_id", other}}, ws(nobody)), ops::NotFound);
    EXPECT_THROW((void)WsRec::inspect(json{{"recovery_id", "snap-999999999"}}, ws(nobody)), ops::NotFound);
}

TEST_F(RecoveryParityTest, RestoringASnapshotNeedsConsentAndRestoresTheSameContent) {
    const auto cliVault = localVault(), wsVault = localVault();
    std::string cliSnap, wsSnap;
    for (const auto id : {cliVault, wsVault}) {
        allowSnapshots(id);
        write(id, "/report.txt", "version one");
    }
    cliSnap = rec::createSnapshot(superUser, cliVault, {.path = "/report.txt"}).point.id;
    wsSnap = rec::createSnapshot(superUser, wsVault, {.path = "/report.txt"}).point.id;
    for (const auto id : {cliVault, wsVault}) write(id, "/report.txt", "version two");
    const auto session = ws(superUser);

    // Without consent: the CLI (no terminal, no --yes) refuses; ws restore without the plan's token refuses.
    EXPECT_NE(cli("recovery restore " + cliSnap, superUser), 0);
    const auto plan = WsRec::plan(json{{"recovery_id", wsSnap}}, session).at("plan");
    EXPECT_EQ(plan.at("overwrites"), 1);
    EXPECT_TRUE(plan.at("atomic").get<bool>()) << "a local snapshot is the one atomic source";
    try {
        (void)WsRec::restore(json{{"plan_id", plan.at("id")}}, session);
        ADD_FAILURE() << "ws restored without the plan's token";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, rec::RESTORE_CONFIRM);
    }
    EXPECT_EQ(read(cliVault, "/report.txt"), "version two");
    EXPECT_EQ(read(wsVault, "/report.txt"), "version two");

    // With consent: the same content on both surfaces, and the plan reads back done.
    EXPECT_EQ(cli("recovery restore " + cliSnap + " --yes", superUser), 0);
    const auto result = WsRec::restore(json{{"plan_id", plan.at("id")}, {"token", plan.at("token")}}, session).at("result");
    EXPECT_EQ(result.at("state"), "done");
    EXPECT_EQ(result.at("restored"), 1);
    EXPECT_EQ(read(cliVault, "/report.txt"), "version one");
    EXPECT_EQ(read(wsVault, "/report.txt"), "version one");
    EXPECT_EQ(WsRec::planGet(json{{"plan_id", plan.at("id")}}, session).at("plan").at("state"), "done");
}

}
