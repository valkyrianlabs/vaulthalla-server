// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Resync and the scrub (wave 5 piece B; migration 168; design/peers/mirror.md "Parity", "As built: moving the core and
// resync"; mirror::resync), with the two servers of test_mirror_submit_db.cpp (helpers/mirror_pair.hpp).
//
// Covered: a copy started over from each stopped state (diverged, expired, stopped), reusing the bytes it holds of every
// file whose generation is the core's (nothing fetched for them, the same entry rows), with a pending change and a held
// one present (the pending one held, the held one kept), this server's version of a file the core replaced kept as a
// held change with its bytes, an entry the core's tree does not hold kept as a held change and out of the tree, a
// name this server's entry took that the core's needs set aside; the digests equal at the end; the core's side (a new
// term, the log and submissions started again); refusals (a live copy, the link down, the core gone); the scrub
// catching a planted difference on each side; who may resync.

#include "../helpers/mirror_pair.hpp"

#include "../helpers/identities.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/mirror/Resync.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Peer.hpp"
#include "protocols/ws/Session.hpp"

#include <algorithm>

namespace vh::test_mirror_resync {

using namespace vh::test_mirror_pair;   // the fixture and its aliases (json, mq, mf, ap, ms)

class MirrorResyncDbTest : public MirrorPairDb {
protected:
    static void SetUpTestSuite() { setUpPair("test_mirror_resync"); }

    static int count(const std::string& statement) { return one<int>(statement); }

    static std::string where(const Scenario& s) { return " WHERE vault_id = " + std::to_string(s.mirrorId); }

    // The vault's entries changed behind the triggers' backs (the apply switch on: nothing logged, no hash moves).
    static void plant(const uint32_t vaultId, const std::string& path) {
        db::Transactions::exec("mr plant", [&](pqxx::work& txn) {
            txn.exec("SELECT set_config('vh.mirror_apply', 'on', true)");
            txn.exec("UPDATE fs_entry SET mode = (COALESCE(mode, 420) # 1) WHERE vault_id = $1 AND path = $2",
                     pqxx::params{vaultId, path});
        });
    }
};

// ---- resync ------------------------------------------------------------------------------------------------------------

TEST_F(MirrorResyncDbTest, ADivergedCopyStartsOverReusingItsBytesAndKeepingWhatThePersonWroteAsHeldChanges) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/same.txt", "bytes both servers hold");
        write(e, "/docs/changed.txt", "the first version");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    const auto sameId = entryId(s.mirrorId, "/docs/same.txt");
    const auto changedUid = uidOf(s.mirrorId, "/docs/changed.txt");

    // A change the core refused (held), one still pending, and this server's own folder in the way of the core's.
    write(s.mirror, "/docs/held.txt", "refused for its bytes");
    wire.contentRefusal = "invalid_contents";
    followAll(wire, s);
    wire.contentRefusal.reset();
    ASSERT_EQ(mq::Pending::heldChanges(s.mirrorId).size(), 1u);
    write(s.mirror, "/docs/pending.txt", "never confirmed");
    ASSERT_EQ(mq::Pending::list(s.mirrorId).size(), 1u);
    const auto pendingUid = uidOf(s.mirrorId, "/docs/pending.txt");

    // Then the copy stops as diverged while the core moves on: a file replaced, a folder made.
    ASSERT_TRUE(mq::MirrorVaults::stop(s.mirrorId, "diverged", "mirror_digest_mismatch", {{"why", "a test"}}));
    coreChange(s, [](const EnginePtr& e) {
        write(e, "/docs/changed.txt", "the core's second version, which replaces it");
        e->mkdir("/docs/new", superUser);
    });

    const auto termBefore = coreCount(s, "SELECT term FROM mirror_vault WHERE vault_id = " + std::to_string(s.coreId));
    const auto answer = vh::mirror::resync::start(s.mirrorId, superUser->id, std::string("admin"), wire);
    EXPECT_EQ(answer.value("held", uint64_t{0}), 1u) << answer.dump();
    EXPECT_EQ(answer.value("state", ""), "live");
    EXPECT_EQ(coreCount(s, "SELECT term FROM mirror_vault WHERE vault_id = " + std::to_string(s.coreId)), termBefore + 1)
        << "the core's log starts again in the next term";
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(s.coreId)), 0);
    auto row = mirrorRow(s);
    EXPECT_EQ(row.state, "live");
    EXPECT_FALSE(row.copy_finished);
    EXPECT_EQ(row.resync_by.value_or(0), superUser->id);
    EXPECT_EQ(row.resync_count, 1u);
    EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty()) << "pending: held";

    followAll(wire, s);
    expectSettled(s);
    row = mirrorRow(s);
    EXPECT_TRUE(row.copy_finished);
    EXPECT_EQ(row.term, static_cast<uint64_t>(termBefore + 1));
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s)) << "the core's tree, nothing more";
    EXPECT_EQ(entryId(s.mirrorId, "/docs/same.txt"), sameId) << "taken in place";
    EXPECT_EQ(count("SELECT count(*) FROM mirror_content_pending" + where(s) + " AND object_uid = '" +
                    uidOf(s.mirrorId, "/docs/same.txt") + "'"),
              0)
        << "the bytes it holds of the core's generation are not fetched";
    EXPECT_EQ(count("SELECT count(*) FROM mirror_content_pending" + where(s) + " AND object_uid = '" + changedUid + "'"),
              1)
        << "the core's new generation is";

    std::map<std::string, mq::HeldChange> byCode;
    for (const auto& h : mq::Pending::heldChanges(s.mirrorId)) byCode[h.reason_code + ":" + h.entry_uid.value_or("")] = h;
    ASSERT_TRUE(byCode.contains("mirror_resync:" + pendingUid)) << "the pending change, held with its bytes";
    EXPECT_TRUE(std::filesystem::exists(ms::contents::heldBlob(s.mirrorId, byCode["mirror_resync:" + pendingUid].id)));
    ASSERT_TRUE(byCode.contains("mirror_resync_replaced:" + changedUid)) << "this server's version of the replaced file";
    const auto& replaced = byCode["mirror_resync_replaced:" + changedUid];
    EXPECT_TRUE(std::filesystem::exists(ms::contents::heldBlob(s.mirrorId, replaced.id))) << "with its bytes";
    EXPECT_EQ(replaced.op, "write");
    EXPECT_FALSE(replaced.args.value("generation", std::string{}).empty());
    std::size_t refused = 0;
    for (const auto& [k, h] : byCode) refused += h.reason_code == "invalid_contents" ? 1 : 0;
    EXPECT_EQ(refused, 1u) << "the held change from before is still there";
    EXPECT_EQ(count("SELECT count(*) FROM mirror_held" + where(s) + " AND entry_uid = '" + pendingUid + "'"), 1)
        << "kept once, not again as an entry the core's tree lacks";

    // It follows the core's new log from there.
    coreChange(s, [](const EnginePtr& e) { e->mkdir("/docs/after", superUser); });
    followAll(wire, s);
    expectSettled(s);
    EXPECT_TRUE(pathsOf(s.mirrorId).contains("/docs/after"));
}

TEST_F(MirrorResyncDbTest, AnExpiredOrStoppedCopyStartsOverAndAnEntryOnlyThisServerHeldIsKeptAsAHeldChange) {
    for (const auto* state : {"expired", "stopped"}) {
        auto s = begin([](const EnginePtr& e) {
            e->mkdir("/docs", superUser);
            write(e, "/docs/a.txt", "a");
        });
        Wire wire(s);
        followAll(wire, s);
        receiveAll(s);
        // An entry this server holds that the core never had (a bug, an operator's hand): the evidence, kept.
        {
            const vh::mirror::submit::Scratch scratch(s.mirrorId);   // past the backstop
            const vh::mirror::submit::Local::Suppress quiet(s.mirrorId);   // and nothing pending
            ASSERT_TRUE(scratch.active());
            write(s.mirror, "/docs/only-here.txt", "this server's alone");
        }
        const auto extraUid = uidOf(s.mirrorId, "/docs/only-here.txt");
        ASSERT_FALSE(extraUid.empty());
        ASSERT_TRUE(mq::MirrorVaults::stop(s.mirrorId, state, "mirror_log_expired", {{"why", "a test"}}));
        const auto answer = vh::mirror::resync::start(s.mirrorId, superUser->id, std::string("admin"), wire);
        EXPECT_EQ(answer.value("state", ""), "live") << state;
        followAll(wire, s);
        expectSettled(s);
        EXPECT_FALSE(pathsOf(s.mirrorId).contains("/docs/only-here.txt")) << state << ": out of the tree";
        const auto held = mq::Pending::heldChanges(s.mirrorId);
        ASSERT_EQ(held.size(), 1u) << state;
        EXPECT_EQ(held[0].reason_code, "mirror_resync_extra");
        EXPECT_EQ(held[0].entry_uid.value_or(""), extraUid);
        EXPECT_EQ(held[0].args.value("name", ""), "only-here.txt");
        EXPECT_TRUE(std::filesystem::exists(ms::contents::heldBlob(s.mirrorId, held[0].id))) << "its bytes kept";
        EXPECT_EQ(mq::Digests::recompute(s.mirrorId), mirrorRow(s).digest);
    }
}

TEST_F(MirrorResyncDbTest, ResyncIsRefusedForALiveCopyWithTheLinkDownOrWhenTheCoreNoLongerMirrorsIt) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    const auto refusedWith = [&](const std::string& code) {
        try {
            (void)vh::mirror::resync::start(s.mirrorId, superUser->id, std::string("admin"), wire);
        } catch (const ops::Refused& e) {
            return e.code == code ? std::string() : e.code;
        }
        return std::string("not refused");
    };
    EXPECT_EQ(refusedWith("mirror_not_stopped"), "") << "a live copy needs nothing";
    ASSERT_TRUE(mq::MirrorVaults::stop(s.mirrorId, "diverged", "test", json::object()));
    struct Down final : mf::Transport {
        bool connected(uint32_t) override { return false; }
        std::optional<Answer> request(uint32_t, const std::string&, const json&) override { return std::nullopt; }
        bool notify(uint32_t, const std::string&, const json&) override { return false; }
    } down;
    EXPECT_THROW((void)vh::mirror::resync::start(s.mirrorId, superUser->id, std::string("admin"), down), ops::Refused);
    EXPECT_EQ(mirrorRow(s).state, "diverged") << "nothing changed here";
    toCore(s);
    {
        AsCore as;
        ASSERT_TRUE(mq::MirrorVaults::remove(s.coreId));
    }
    toMirror(s);
    EXPECT_EQ(refusedWith("mirror_core_gone"), "");
    EXPECT_EQ(mirrorRow(s).state, "diverged");
}

// ---- the scrub ---------------------------------------------------------------------------------------------------------

TEST_F(MirrorResyncDbTest, TheScrubCatchesAPlantedDifferenceOnEitherSideAndResyncBringsTheCopyBack) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "a");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    EXPECT_TRUE(vh::mirror::resync::scrub(s.mirrorId)) << "a clean copy";

    // A change made here and still pending is this server's own until it settles: not a difference.
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/mine");
    EXPECT_TRUE(vh::mirror::resync::scrub(s.mirrorId));
    followAll(wire, s);
    expectSettled(s);

    plant(s.mirrorId, "/docs/a.txt");
    EXPECT_FALSE(vh::mirror::resync::scrub(s.mirrorId));
    auto row = mirrorRow(s);
    EXPECT_EQ(row.state, "diverged");
    EXPECT_EQ(row.stop_reason.value_or(""), "mirror_scrub_mismatch");
    EXPECT_EQ(row.stop_detail.value("differences", 0), 1) << row.stop_detail.dump();
    EXPECT_EQ(row.stop_detail.at("first").at(0).value("uid", ""), uidOf(s.mirrorId, "/docs/a.txt"));

    // The core's side, through the schedule (never scrubbed: due).
    toCore(s);
    {
        AsCore as;
        plant(s.coreId, "/docs");
        EXPECT_GE(vh::mirror::resync::scrubDue(), 1u);
        EXPECT_EQ(mq::MirrorVaults::get(s.coreId)->state, "diverged");
        const auto due = mq::Resync::scrubDue(vh::mirror::resync::kScrubEvery);
        EXPECT_EQ(std::ranges::find(due, s.coreId), due.end()) << "scrubbed: not due again within the day";
    }
    toMirror(s);

    // Resync takes the core's tree again on both sides (the core's planted change is in its new baseline).
    (void)vh::mirror::resync::start(s.mirrorId, superUser->id, std::string("admin"), wire);
    followAll(wire, s);
    expectSettled(s);
    EXPECT_TRUE(vh::mirror::resync::scrub(s.mirrorId));
    toCore(s);
    {
        AsCore as;
        EXPECT_EQ(mq::MirrorVaults::get(s.coreId)->state, "live") << "the core's new baseline is its tree";
        EXPECT_TRUE(vh::mirror::resync::scrub(s.coreId));
    }
    toMirror(s);
}

// ---- who may ------------------------------------------------------------------------------------------------------------

TEST_F(MirrorResyncDbTest, OnlyASuperAdminPersonMayResyncNeverAnAgentOrARelayedDevice) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    ASSERT_TRUE(mq::MirrorVaults::stop(s.mirrorId, "diverged", "test", json::object()));
    const auto name = "mr_user_" + msTag();
    const auto plain = test::identities::createUser(name, db::query::rbac::role::Admin::get("unprivileged"),
                                                    name + "@vaulthalla.test");
    EXPECT_THROW((void)ops::mirrors::resync(plain, s.mirrorId), ops::Denied);
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        try {
            (void)ops::mirrors::resync(superUser, s.mirrorId);
            ADD_FAILURE() << "an agent resynced";
        } catch (const ops::Refused& e) {
            EXPECT_EQ(e.code, "peer_forbidden");
        }
    }
    auto p = std::make_shared<vh::device::Peer>();
    p->spki.fill(0x31);
    p->spkiHex = std::string(64, '3');
    p->address = "10.0.0.7";
    p->deviceRowId = 9;
    p->relayed = true;
    const auto relayed = protocols::ws::Session::devicePrincipal(std::move(p), superUser, [] {});
    {
        const auth::stepup::Scope scope(relayed);
        try {
            (void)ops::mirrors::resync(superUser, s.mirrorId);
            ADD_FAILURE() << "a relayed device resynced";
        } catch (const ops::Refused& e) {
            EXPECT_EQ(e.code, "peer_forbidden");
        }
    }
    relayed->close();
    EXPECT_EQ(mirrorRow(s).state, "diverged") << "nothing changed";
    EXPECT_EQ(mirrorRow(s).resync_count, 0u);
}

}
