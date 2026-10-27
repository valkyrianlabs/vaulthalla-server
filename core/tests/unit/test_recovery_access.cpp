// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Recovery authorization (ops::recovery + ops/RecoveryAccess): the review findings that history must not loosen
// filesystem RBAC. A deleted or renamed folder keeps its deny overrides for its history; nothing is revealed or sent
// before the source is authorized; restoring elsewhere is a copy.

#include "../helpers/recovery_local.hpp"
#include "ops/Error.hpp"
#include "ops/Recovery.hpp"
#include "ops/Roles.hpp"

#include <algorithm>

namespace vh::test_recovery_access {

using namespace vh::test_support::recovery_local;
namespace orec = vh::ops::recovery;

class RecoveryAccessTest : public LocalRecoveryFixture {
protected:
    static void SetUpTestSuite() { setUpSuite("recovery_access"); }
    static void TearDownTestSuite() { tearDownSuite(); }

    void deny(const UserPtr& user, const std::string& permission, const std::string& pattern) const {
        (void)ops::roles::addVaultRoleOverrides(superUser, {
            .target = {.vault_id = vaultId(), .subject = {.type = "user", .id = user->id}},
            .permissions = {.changes = {{permission, false}}},
            .pattern = pattern});
    }

    [[nodiscard]] static UserPtr fresh(const UserPtr& user) { return vh::identities::manager().user(user->id); }

    [[nodiscard]] static bool mentions(const std::vector<vh::recovery::RecoveryPoint>& points, const std::string& prefix) {
        return std::ranges::any_of(points, [&](const auto& p) { return p.path.starts_with(prefix); });
    }
};

TEST_F(RecoveryAccessTest, ADeletedFolderKeepsItsDenyOverridesForItsHistory) {
    mkdir("/hr");
    write("/hr/pay.txt", "salaries");
    write("/notes.txt", "public");
    const auto snap = orec::createSnapshot(superUser, vaultId(), {.path = "/hr", .name = "hr"}).point.id;
    (void)orec::createSnapshot(superUser, vaultId(), {.path = "/notes.txt"});

    // The folder is hidden from this reader entirely.
    const auto reader = userWithVaultRole("reader");
    for (const auto* pattern : {"/hr", "/hr/**"}) {
        deny(reader, "vault.fs.directories.list", pattern);
        deny(reader, "vault.fs.directories.download", pattern);
        deny(reader, "vault.fs.files.download", pattern);
    }
    const auto who = fresh(reader);
    EXPECT_FALSE(mentions(orec::list(who, vaultId(), {}), "/hr"));

    // Gone (deleted): its history is still judged at /hr, so the overrides still apply.
    remove("/hr/pay.txt");
    remove("/hr");
    const auto all = orec::list(who, vaultId(), {});
    EXPECT_FALSE(mentions(all, "/hr")) << "a deleted folder must not lift its deny overrides for its history";
    EXPECT_TRUE(mentions(all, "/notes.txt")) << "the rest stays visible";
    EXPECT_THROW((void)orec::list(who, vaultId(), {.path = "/hr/pay.txt"}), ops::Denied);
    EXPECT_THROW((void)orec::inspect(who, snap), ops::NotFound);
    EXPECT_THROW((void)orec::plan(who, {.recovery_id = snap}), ops::NotFound);
    EXPECT_THROW((void)orec::plan(who, {.recovery_id = snap, .destination = "/mine"}), ops::NotFound);
    EXPECT_THROW(orec::deletePoint(who, snap, true), ops::NotFound);

    // Someone without the overrides sees and restores it.
    const auto other = fresh(userWithVaultRole("reader"));
    EXPECT_TRUE(mentions(orec::list(other, vaultId(), {}), "/hr"));
    EXPECT_NO_THROW((void)orec::inspect(other, snap));
}

TEST_F(RecoveryAccessTest, AFileDenyInsideASnapshotKeepsThatFileOutOfItsHistoryAndPlans) {
    mkdir("/team");
    write("/team/a.txt", "a");
    write("/team/pay.txt", "secret");
    const auto snap = orec::createSnapshot(superUser, vaultId(), {.path = "/team", .name = "team"}).point.id;
    remove("/team/pay.txt");

    const auto reader = userWithVaultRole("editor");
    deny(reader, "vault.fs.files.download", "/team/pay.txt");
    const auto who = fresh(reader);

    const auto detail = orec::inspect(who, snap);
    EXPECT_TRUE(std::ranges::none_of(detail.members, [](const auto& m) { return m.path == "/team/pay.txt"; }))
        << "the deleted file is still judged by its own override";
    EXPECT_THROW((void)orec::list(who, vaultId(), {.path = "/team/pay.txt"}), ops::Denied);
    const auto plan = orec::plan(who, {.recovery_id = snap});
    EXPECT_TRUE(std::ranges::none_of(plan.items, [](const auto& i) { return i.source_path == "/team/pay.txt"; }));
    EXPECT_TRUE(std::ranges::none_of(plan.warnings, [](const auto& w) { return w.find("can't read") != std::string::npos; }))
        << "not even a count of what was left out";
    EXPECT_THROW(orec::deletePoint(who, snap, true), ops::Denied) << "Delete on everything the snapshot holds";
}

TEST_F(RecoveryAccessTest, RestoringElsewhereNeedsCopyOnTheSource) {
    mkdir("/team");
    write("/team/a.txt", "a1");
    const auto snap = orec::createSnapshot(superUser, vaultId(), {.path = "/team/a.txt"}).point.id;
    write("/team/a.txt", "a2");

    const auto editor = userWithVaultRole("editor");
    deny(editor, "vault.fs.files.copy", "/**");
    const auto who = fresh(editor);

    // Elsewhere: a copy, refused as one.
    const auto elsewhere = orec::plan(who, {.recovery_id = snap, .destination = "/team/restored"});
    ASSERT_FALSE(elsewhere.blockers.empty());
    EXPECT_NE(elsewhere.blockers.front().find("Copy"), std::string::npos) << elsewhere.blockers.front();
    EXPECT_THROW((void)orec::restore(who, {.plan_id = elsewhere.id, .token = elsewhere.token}), ops::Denied);

    // In place it is an overwrite, not a copy: allowed.
    const auto inPlace = orec::plan(who, {.recovery_id = snap});
    EXPECT_TRUE(inPlace.blockers.empty()) << (inPlace.blockers.empty() ? "" : inPlace.blockers.front());
    const auto done = orec::restore(who, {.plan_id = inPlace.id, .token = inPlace.token});
    EXPECT_EQ(done.restored, 1u);
    EXPECT_EQ(plaintext("/team/a.txt"), "a1");
}

TEST_F(RecoveryAccessTest, NothingIsRevealedBeforeTheSourceIsAuthorized) {
    write("/a.txt", "a");
    const auto snap = orec::createSnapshot(superUser, vaultId(), {.path = "/a.txt"}).point.id;
    const auto stranger = fresh(userWithVaultRole("reader"));
    deny(stranger, "vault.fs.files.download", "/**");
    deny(stranger, "vault.fs.directories.list", "/**");
    const auto who = fresh(stranger);

    // A local vault, a missing vault and an unreadable path all answer alike (no vault-type or existence oracle).
    try {
        (void)orec::plan(who, {.vault_id = vaultId(), .path = "/", .at = std::time(nullptr)});
        ADD_FAILURE() << "planned without read access";
    } catch (const ops::NotFound&) {
    }
    EXPECT_THROW((void)orec::plan(who, {.vault_id = 999999, .path = "/", .at = std::time(nullptr)}), ops::NotFound);
    EXPECT_THROW((void)orec::plan(who, {.recovery_id = "snap-999999999"}), ops::NotFound);
    EXPECT_THROW((void)orec::plan(who, {.recovery_id = snap}), ops::NotFound);

    // Snapshot creation says "no such path" only to someone who could see there.
    EXPECT_THROW((void)orec::createSnapshot(who, vaultId(), {.path = "/does-not-exist"}), ops::Denied);
    EXPECT_THROW((void)orec::createSnapshot(superUser, vaultId(), {.path = "/does-not-exist"}), ops::NotFound);
}

TEST_F(RecoveryAccessTest, PlansArePersonalButCarryTheirTokenForTheirCreator) {
    write("/p.txt", "p1");
    const auto snap = orec::createSnapshot(superUser, vaultId(), {.path = "/p.txt"}).point.id;
    write("/p.txt", "p2");
    const auto made = orec::plan(superUser, {.recovery_id = snap});
    EXPECT_EQ(orec::getPlan(superUser, made.id).token, made.token) << "vh recovery restore <plan-id> needs it";
    const auto other = fresh(userWithVaultRole("editor"));
    EXPECT_THROW((void)orec::getPlan(other, made.id), ops::NotFound);
    EXPECT_THROW((void)orec::restore(other, {.plan_id = made.id, .token = made.token}), ops::NotFound);
    EXPECT_EQ(orec::restore(superUser, {.plan_id = made.id, .token = made.token}).restored, 1u);
}

}
