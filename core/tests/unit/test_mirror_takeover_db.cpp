// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Take over (forced promotion; wave 5 piece B; migration 168 mirror_takeover, mirror_fork_base; design/peers/mirror.md
// "Forced promotion", "As built: take over"; mirror::takeover), with the two servers of test_mirror_submit_db.cpp
// (helpers/mirror_pair.hpp).
//
// Covered: a mirror whose core is gone takes over with a pending change and a held one present (the pending change an
// ordinary change of the vault now, its sealed copy dropped, the held one still listed; the fork point the position it
// applied, the fork base the tree as the core last confirmed it, its digest the fork point's; the new term, the gate
// lifted, the log from (term + 1, 1)); files whose contents never arrived counted; refused while the core answers, for
// a name not typed exactly, an orphaned copy, an unfinished first copy, a diverged copy; the way out of a planned switch
// whose core never came back (from prepared), and the old core's later decision: switched (the two agree: settled, the
// old core follows) or abandoned; an unlink ending a switch's telling on both sides; a detach on either side of a take
// over (it settles, nothing is told again); a take over while the core deletes the vault; who may (super admins and holders of
// admin.mirror.takeover, people only), and the console's step-up.

#include "../helpers/mirror_pair.hpp"

#include "../helpers/identities.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/mirror/Switch.hpp"
#include "db/query/mirror/Takeover.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Peer.hpp"
#include "db/query/mirror/Rejoin.hpp"
#include "db/query/mirror/Detach.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Vault.hpp"
#include "mirror/leave/Leave.hpp"
#include "audit/Trail.hpp"
#include "mirror/resync/Resync.hpp"
#include "mirror/switching/Switch.hpp"
#include "mirror/takeover/Takeover.hpp"
#include "ops/PeerPolicy.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/permission/admin/Mirror.hpp"
#include "rbac/role/Admin.hpp"

#include <filesystem>

namespace vh::test_mirror_takeover {

using namespace vh::test_mirror_pair;   // the fixture and its aliases (json, mq, mf, ap, ms)
namespace sw = vh::mirror::switching;
namespace tk = vh::mirror::takeover;

class MirrorTakeoverDbTest : public MirrorPairDb {
protected:
    static void SetUpTestSuite() {
        setUpPair("test_mirror_takeover");
        sw::setTellPauseForTesting(true);
    }

    static void TearDownTestSuite() {
        sw::setTellPauseForTesting(false);
        vh::mirror::access::linkChanged(mirrorPeer, false);
        MirrorPairDb::TearDownTestSuite();
    }

    void SetUp() override {
        MirrorPairDb::SetUp();
        if (IsSkipped()) return;
        vh::mirror::access::linkChanged(mirrorPeer, true);
        sql("UPDATE peer SET revoked_at = NULL WHERE id IN (" + std::to_string(mirrorPeer) + ", " +
            std::to_string(corePeer) + ")");
        sql("UPDATE mirror_switch SET notify = FALSE, phase = CASE WHEN ended_at IS NULL THEN 'abandoned' ELSE phase END, "
            "  ended_at = COALESCE(ended_at, CURRENT_TIMESTAMP) WHERE ended_at IS NULL OR notify");
        (void)ops::peer_policy::set(superUser, std::to_string(corePeer), ops::roles::Ref{std::string("power_user")});
        // Earlier tests' take overs and rejoins are no pass's business here (one database holds every test's servers).
        sql("UPDATE mirror_takeover SET settled_at = CURRENT_TIMESTAMP, settled_how = 'ended' WHERE settled_at IS NULL");
        sql("UPDATE mirror_rejoin SET phase = 'resynced' WHERE phase IN ('draining', 'rejoining', 'forked')");
    }

    static void node(const std::string& id) { sql("UPDATE device_node SET node_id = '" + id + "' WHERE singleton"); }

    template <class F>
    static auto onCore(Scenario& s, F&& f) {
        const bool wasMirror = !s.coreActive;
        toCore(s);
        node(coreNode);
        struct Back {
            Scenario& s;
            bool wasMirror;
            ~Back() {
                node(ownNode);
                if (wasMirror) toMirror(s);
            }
        } back{s, wasMirror};
        return f();
    }

    template <class F>
    static auto onMirror(Scenario& s, F&& f) {
        const bool wasCore = s.coreActive;
        toMirror(s);
        node(ownNode);
        struct Back {
            Scenario& s;
            bool wasCore;
            ~Back() {
                if (wasCore) {
                    toCore(s);
                    node(coreNode);
                }
            }
        } back{s, wasCore};
        return f();
    }

    static mf::Transport::Answer answerOf(const std::function<json()>& serve) {
        try {
            return {.ok = true, .data = serve()};
        } catch (const ops::Refused& e) {
            return {.ok = false, .code = e.code, .error = e.what()};
        } catch (const ops::NotFound& e) {
            return {.ok = false, .code = "not_found", .error = e.what()};
        } catch (const ops::Error& e) {
            return {.ok = false, .code = "invalid", .error = e.what()};
        }
    }

    // The planned switch's messages between the turns (test_mirror_switch_db.cpp's wire); `dropCommit` loses the core's
    // decision on its way.
    class SwitchWire final : public mf::Transport {
    public:
        SwitchWire(Scenario& s, Wire& follow) : s_(s), follow_(follow) {}
        bool up{true};
        bool dropCommit{false};
        std::vector<json> promoted;
        bool loseAnswer{false};
        bool connected(uint32_t) override { return up; }
        std::optional<Answer> request(const uint32_t peer, const std::string& command, const json& payload) override {
            if (!up) return std::nullopt;
            if (command == "peer.mirror.switch.prepare") {
                auto out = onMirror(s_, [&] { return answerOf([&] { return sw::servePrepare(corePeer, payload); }); });
                if (loseAnswer) return std::nullopt;
                return out;
            }
            if (command == "peer.mirror.switch.commit") {
                if (dropCommit) return std::nullopt;
                return onMirror(s_, [&] { return answerOf([&] { return sw::serveCommit(corePeer, payload); }); });
            }
            // The new core tells its old core: the mirror's row names the core as corePeer, the core's names the mirror
            // as mirrorPeer (both forced: the core tells the mirror).
            if (command == "peer.mirror.promoted") {
                promoted.push_back(payload);
                if (peer == mirrorPeer)
                    return onMirror(s_, [&] { return answerOf([&] { return tk::servePromoted(corePeer, payload); }); });
                return onCore(s_, [&] { return answerOf([&] { return tk::servePromoted(mirrorPeer, payload); }); });
            }
            if (command == "peer.mirror.resync")
                return onMirror(s_, [&] {
                    return answerOf([&] { return vh::mirror::resync::serveResync(corePeer, payload); });
                });
            return follow_.request(peer, command, payload);
        }
        bool notify(uint32_t, const std::string&, const json&) override { return true; }

    private:
        Scenario& s_;
        Wire& follow_;
    };

    // The core gone: no connection, no answer.
    struct Down final : mf::Transport {
        bool connected(uint32_t) override { return false; }
        std::optional<Answer> request(uint32_t, const std::string&, const json&) override { return std::nullopt; }
        bool notify(uint32_t, const std::string&, const json&) override { return false; }
    };

    static std::string refusalOf(const std::function<void()>& f) {
        try {
            f();
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::Error& e) {
            return std::string("error: ") + e.what();
        }
        return "not refused";
    }

    static std::string vaultName(const Scenario& s) { return s.mirror->vault->name; }

    static mq::MirrorVault coreRow(Scenario& s) {
        return onCore(s, [&] { return mq::MirrorVaults::get(s.coreId).value_or(mq::MirrorVault{}); });
    }

    static Scenario settledPair(const bool contents = true) {
        auto s = begin([](const EnginePtr& e) {
            e->mkdir("/docs", superUser);
            write(e, "/docs/a.txt", "the first file");
        });
        Wire wire(s);
        followAll(wire, s);
        if (contents) {
            receiveAll(s);
            expectSettled(s);
        }
        return s;
    }
};

// ---- take over -----------------------------------------------------------------------------------------------------------

TEST_F(MirrorTakeoverDbTest, AMirrorWhoseCoreIsGoneTakesOverWithItsPendingChangesMadeOrdinaryAndHeldOnesKept) {
    auto s = settledPair();
    Wire wire(s);
    // A change the core refused (held), then one still pending when the core goes.
    write(s.mirror, "/docs/held.txt", "refused for its bytes");
    wire.contentRefusal = "invalid_contents";
    followAll(wire, s);
    wire.contentRefusal.reset();
    ASSERT_EQ(mq::Pending::heldChanges(s.mirrorId).size(), 1u);
    write(s.mirror, "/docs/pending.txt", "never confirmed by the core");
    ASSERT_EQ(mq::Pending::list(s.mirrorId).size(), 1u);
    const auto pendingId = mq::Pending::list(s.mirrorId).front().id;
    ASSERT_TRUE(std::filesystem::exists(ms::contents::pendingBlob(s.mirrorId, pendingId)));
    const auto before = mirrorRow(s);
    vh::mirror::access::linkChanged(corePeer, false);

    Down down;
    const auto answer = tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    EXPECT_EQ(answer.value("term", uint64_t{0}), before.term + 1);
    EXPECT_EQ(answer.at("fork").value("term", uint64_t{0}), before.term);
    EXPECT_EQ(answer.at("fork").value("seq", uint64_t{0}), before.last_seq);
    EXPECT_EQ(answer.at("fork").value("digest", ""), before.digest.hex());
    EXPECT_TRUE(answer.value("fork_base_matches", false)) << "the fork base is the tree the core last confirmed";
    EXPECT_EQ(answer.value("pending_made_local", 0u), 1u);
    EXPECT_EQ(answer.value("held", 0u), 1u);
    EXPECT_EQ(answer.value("contents_missing", 0u), 0u);
    EXPECT_NE(answer.value("warning", "").find("may hold changes"), std::string::npos);

    // The core in term + 1: live, the gate lifted, the grant gone, the tree as it is here (the person's file in it).
    const auto now = mirrorRow(s);
    EXPECT_EQ(now.role, "core");
    EXPECT_EQ(now.state, "live");
    EXPECT_EQ(now.term, before.term + 1);
    EXPECT_EQ(now.last_seq, 0u);
    EXPECT_FALSE(now.grant);
    EXPECT_EQ(now.digest, mq::Digests::recompute(s.mirrorId)) << "its digest is its tables'";
    EXPECT_EQ(now.digest, mq::Digests::stored(s.mirrorId));
    EXPECT_NE(now.digest, before.digest) << "the pending file is in the tree now";
    EXPECT_EQ(vh::mirror::access::state(s.mirrorId), vh::mirror::access::State::NotMirrored);
    EXPECT_FALSE(uidOf(s.mirrorId, "/docs/pending.txt").empty());
    EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty());
    EXPECT_TRUE(mq::Pending::dirtyUids(s.mirrorId).empty());
    EXPECT_FALSE(std::filesystem::exists(ms::contents::pendingBlob(s.mirrorId, pendingId)))
        << "its sealed copy goes: the file holds the bytes";
    EXPECT_EQ(mq::Pending::heldChanges(s.mirrorId).size(), 1u) << "the held change stays listed";

    // The fork base: the core's tree at the fork point, entry for entry (the pending file is not in it).
    const auto t = mq::Takeovers::openOf(s.mirrorId);
    ASSERT_TRUE(t);
    EXPECT_EQ(t->fork_rows, static_cast<uint64_t>(before.digest.entries));
    const auto base = mq::Takeovers::forkBase(t->id, 0, 1000);
    EXPECT_EQ(base.size(), static_cast<std::size_t>(before.digest.entries));
    const auto pendingUid = uidOf(s.mirrorId, "/docs/pending.txt");
    EXPECT_TRUE(std::ranges::none_of(base, [&](const json& b) { return b.value("uid", "") == pendingUid; }));

    // A change here is the core's own now, logged in the new term from seq 1.
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/after");
    const auto numbered = mq::Log::sequence(s.mirrorId);
    ASSERT_TRUE(numbered);
    EXPECT_EQ(numbered->last.term, before.term + 1);
    EXPECT_EQ(one<int>("SELECT min(seq)::int FROM vault_replication_log WHERE vault_id = " + std::to_string(s.mirrorId)),
              1);
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_EQ(one<int>("SELECT count(*)::int FROM audit_event WHERE action = 'mirror.takeover' AND vault_id = " +
                       std::to_string(s.mirrorId)),
              1);
    vh::mirror::access::linkChanged(corePeer, true);
}

TEST_F(MirrorTakeoverDbTest, FilesWhoseContentsNeverArrivedAreCountedAndTheirRowsKept) {
    auto s = settledPair(false);
    vh::mirror::access::linkChanged(corePeer, false);
    Down down;
    const auto answer = tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    EXPECT_EQ(answer.value("contents_missing", 0u), 1u);
    EXPECT_EQ(one<int>("SELECT count(*)::int FROM mirror_content_pending WHERE vault_id = " + std::to_string(s.mirrorId)),
              1)
        << "the list of what is missing stays (the old core can serve them when it returns)";
    vh::mirror::access::linkChanged(corePeer, true);
}

TEST_F(MirrorTakeoverDbTest, TakeOverIsRefusedWhileTheCoreAnswersAndForAWrongNameAnOrphanedUnfinishedOrDivergedCopy) {
    auto s = settledPair();
    Wire wire(s);
    const auto before = mirrorRow(s);
    EXPECT_EQ(refusalOf([&] { (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", wire); }),
              "mirror_core_reachable")
        << "the core answers: the planned switch";
    Down down;
    EXPECT_EQ(refusalOf([&] { (void)tk::take(s.mirrorId, vaultName(s) + "x", superUser->id, "admin", down); }),
              "mirror_name_mismatch");
    ASSERT_TRUE(mq::MirrorVaults::stop(s.mirrorId, "diverged", "mirror_digest_mismatch", {{"why", "a test"}}));
    EXPECT_EQ(refusalOf([&] { (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down); }),
              "mirror_diverged");
    ASSERT_TRUE(mq::MirrorVaults::setState(s.mirrorId, "live"));
    sql("UPDATE mirror_vault SET copy_finished = FALSE WHERE vault_id = " + std::to_string(s.mirrorId));
    EXPECT_EQ(refusalOf([&] { (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down); }),
              "mirror_first_copy");
    sql("UPDATE mirror_vault SET copy_finished = TRUE WHERE vault_id = " + std::to_string(s.mirrorId));
    ASSERT_TRUE(mq::MirrorVaults::orphan(s.mirrorId));
    EXPECT_EQ(refusalOf([&] { (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down); }),
              "mirror_orphaned");
    const auto after = mirrorRow(s);
    EXPECT_EQ(after.term, before.term) << "no refusal changed the term";
    EXPECT_FALSE(mq::Takeovers::latestOf(s.mirrorId));
}

// ---- the way out of a planned switch whose core never came back ----------------------------------------------------

TEST_F(MirrorTakeoverDbTest, APreparedMirrorTakesOverAndTheOldCoresLaterSwitchedDecisionAgreesWithIt) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto digest = mirrorRow(s).digest;
    const auto begun = onCore(s, [&] {
        return sw::begin(s.coreId, {.on = "core", .by = mq::Account{.node = coreNode, .id = superUser->id},
                                    .name = "admin"},
                         wire);
    });
    // The core decides switched and its decision never arrives: the mirror is prepared and waits.
    wire.dropCommit = true;
    (void)onCore(s, [&] { return sw::advance(begun.id, wire); });
    ASSERT_EQ(mq::Switches::bySwitchId(begun.switch_id, "mirror")->phase, "prepared");
    ASSERT_EQ(mirrorRow(s).state, "switching");
    // `vh mirror info` says what to do.
    const auto info = ops::mirrors::toJson(ops::mirrors::get(superUser, s.mirrorId));
    EXPECT_NE(info.value("advice", "").find("vh mirror takeover"), std::string::npos) << info.dump();

    // The core never comes back (as far as this server can tell): take over from prepared.
    Down down;
    vh::mirror::access::linkChanged(corePeer, false);
    const auto answer = tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    EXPECT_EQ(answer.value("term", uint64_t{0}), 2u);
    EXPECT_EQ(mq::Switches::bySwitchId(begun.switch_id, "mirror")->reason.value_or(""), "mirror_taken_over");
    EXPECT_EQ(mirrorRow(s).role, "core");
    EXPECT_EQ(mirrorRow(s).state, "live");
    vh::mirror::access::linkChanged(corePeer, true);

    // The old core comes back and tells its decision: the same fork point and next term, so they agree; told again,
    // the same answer; the take over settles and the old core is a live mirror of the new one.
    wire.dropCommit = false;
    for (int i = 0; i < 3; ++i) (void)onCore(s, [&] { return sw::advance(begun.id, wire); });
    const auto a = coreRow(s);
    EXPECT_EQ(a.role, "mirror");
    EXPECT_EQ(a.state, "live");
    EXPECT_EQ(a.term, 2u);
    EXPECT_EQ(a.digest, digest);
    EXPECT_FALSE(onCore(s, [&] { return mq::Switches::get(begun.id); })->notify) << "told";
    const auto t = mq::Takeovers::latestOf(s.mirrorId);
    ASSERT_TRUE(t);
    EXPECT_EQ(t->settled_how.value_or(""), "switched");
    EXPECT_TRUE(mq::Takeovers::forkBase(t->id, 0, 10).empty()) << "nothing left to merge";
    const auto b = mirrorRow(s);
    EXPECT_EQ(b.baseline.value_or(mq::Position{}), (mq::Position{2, 0}));
    EXPECT_EQ(b.baseline_digest.value_or(vh::mirror::Digest{}), digest) << "the old core's first acknowledgement compares";
    const auto told = answerOf([&] {
        return sw::serveCommit(corePeer, {{"vault_uid", s.vaultUid}, {"switch_id", begun.switch_id},
                                          {"outcome", "switched"}});
    });
    EXPECT_TRUE(told.ok) << told.code;
    EXPECT_EQ(told.data.value("outcome", ""), "switched");
}

TEST_F(MirrorTakeoverDbTest, APreparedMirrorTakesOverAndTheOldCoresAbandonedDecisionIsAnsweredWithoutUndoingIt) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto begun = onCore(s, [&] {
        return sw::begin(s.coreId, {.on = "core", .by = mq::Account{.node = coreNode, .id = superUser->id},
                                    .name = "admin"},
                         wire);
    });
    wire.loseAnswer = true;   // prepared, and the core never heard it
    (void)onCore(s, [&] { return sw::advance(begun.id, wire); });
    ASSERT_EQ(mq::Switches::bySwitchId(begun.switch_id, "mirror")->phase, "prepared");
    Down down;
    vh::mirror::access::linkChanged(corePeer, false);
    (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    vh::mirror::access::linkChanged(corePeer, true);
    // The core abandons by its deadline and tells it: answered, nothing undone here (this server stays the core of the
    // next term; the old core's return is the next piece).
    onCore(s, [&] {
        sql("UPDATE mirror_switch SET deadline = CURRENT_TIMESTAMP - interval '1 minute' WHERE id = " +
            std::to_string(begun.id));
        return 0;
    });
    wire.loseAnswer = false;
    for (int i = 0; i < 3; ++i) (void)onCore(s, [&] { return sw::advance(begun.id, wire); });
    const auto ended = onCore(s, [&] { return mq::Switches::get(begun.id); });
    EXPECT_EQ(ended->phase, "abandoned");
    EXPECT_FALSE(ended->notify) << "told, and the telling ended";
    EXPECT_EQ(mirrorRow(s).role, "core");
    EXPECT_EQ(mirrorRow(s).term, 2u);
    EXPECT_TRUE(mq::Takeovers::openOf(s.mirrorId)) << "still waiting for the old core's return";
    EXPECT_EQ(coreRow(s).role, "core");
    EXPECT_EQ(coreRow(s).term, 1u) << "two cores, never in one term (invariant 12)";
}

TEST_F(MirrorTakeoverDbTest, AnUnlinkEndsASwitchsTellingOnBothSides) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto begun = onCore(s, [&] {
        return sw::begin(s.coreId, {.on = "core", .by = mq::Account{.node = coreNode, .id = superUser->id},
                                    .name = "admin"},
                         wire);
    });
    wire.dropCommit = true;
    (void)onCore(s, [&] { return sw::advance(begun.id, wire); });
    ASSERT_TRUE(onCore(s, [&] { return mq::Switches::get(begun.id); })->notify);
    ASSERT_EQ(coreRow(s).state, "switching");
    ASSERT_EQ(mq::Switches::bySwitchId(begun.switch_id, "mirror")->phase, "prepared");

    // Both servers unlink (the core's row for the mirror, the mirror's for the core).
    sql("UPDATE peer SET revoked_at = CURRENT_TIMESTAMP WHERE id IN (" + std::to_string(mirrorPeer) + ", " +
        std::to_string(corePeer) + ")");
    // One pass ends both (in one database both servers' switches are this pass's).
    EXPECT_EQ(onCore(s, [&] { return sw::tick(wire); }), 2u);
    const auto core = onCore(s, [&] { return mq::Switches::get(begun.id); });
    EXPECT_FALSE(core->notify) << "nothing left to tell";
    EXPECT_TRUE(core->detail.value("unlinked", false));
    EXPECT_EQ(coreRow(s).state, "live") << "not held switching any more";
    const auto mine = mq::Switches::bySwitchId(begun.switch_id, "mirror");
    EXPECT_EQ(mine->phase, "abandoned");
    EXPECT_EQ(mine->reason.value_or(""), "mirror_unlinked");
    EXPECT_EQ(mirrorRow(s).state, "live");
    EXPECT_EQ(sw::tick(wire), 0u) << "nothing is active any more";
    sql("UPDATE peer SET revoked_at = NULL WHERE id IN (" + std::to_string(mirrorPeer) + ", " +
        std::to_string(corePeer) + ")");
}

// ---- who may -----------------------------------------------------------------------------------------------------------

TEST_F(MirrorTakeoverDbTest, OnlyASuperAdminOrAHolderOfTheTakeoverPermissionMayNeverAnAgentOrARelayedDevice) {
    auto s = settledPair();
    vh::mirror::access::linkChanged(corePeer, false);
    const auto name = "mto_user_" + msTag();
    const auto plain = test::identities::createUser(name, db::query::rbac::role::Admin::get("unprivileged"),
                                                    name + "@vaulthalla.test");
    EXPECT_THROW((void)ops::mirrors::takeover(plain, s.mirrorId, vaultName(s)), ops::Denied);
    // admin.mirror.takeover (bit 1) lets a person take over; admin.mirror.detach (bit 0) alone does not.
    const auto holderOf = [&](const rbac::permission::admin::MirrorPermissions bit, const std::string& tag) {
        auto role = std::make_shared<rbac::role::Admin>(rbac::role::Admin::None());
        role->name = "mto_" + tag + "_" + msTag();
        role->description = "mirror permission " + tag;
        role->mirror.grant(bit);
        (void)db::query::rbac::role::Admin::insert(role);
        return test::identities::createUser(role->name, db::query::rbac::role::Admin::get(role->name),
                                            role->name + "@vaulthalla.test");
    };
    const auto taker = holderOf(rbac::permission::admin::MirrorPermissions::Takeover, "taker");
    const auto detacher = holderOf(rbac::permission::admin::MirrorPermissions::Detach, "detacher");
    ASSERT_TRUE(taker->mirrorPerms().canTakeover());
    EXPECT_FALSE(detacher->mirrorPerms().canTakeover());
    EXPECT_NO_THROW(ops::mirrors::requireTakeover(taker, "take over"));
    EXPECT_THROW(ops::mirrors::requireTakeover(detacher, "take over"), ops::Denied);
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        EXPECT_EQ(refusalOf([&] { ops::mirrors::requireTakeover(taker, "take over"); }), "peer_forbidden");
    }
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        EXPECT_EQ(refusalOf([&] { (void)ops::mirrors::takeover(superUser, s.mirrorId, vaultName(s)); }),
                  "peer_forbidden");
    }
    auto p = std::make_shared<vh::device::Peer>();
    p->spki.fill(0x33);
    p->spkiHex = std::string(64, '3');
    p->address = "10.0.0.9";
    p->deviceRowId = 9;
    p->relayed = true;
    const auto relayed = protocols::ws::Session::devicePrincipal(std::move(p), superUser, [] {});
    {
        const auth::stepup::Scope scope(relayed);
        EXPECT_EQ(refusalOf([&] { (void)ops::mirrors::takeover(superUser, s.mirrorId, vaultName(s)); }),
                  "peer_forbidden");
    }
    relayed->close();
    EXPECT_EQ(mirrorRow(s).role, "mirror") << "nothing changed";
    vh::mirror::access::linkChanged(corePeer, true);
}

TEST_F(MirrorTakeoverDbTest, TheConsoleStepsUpBoundToTheVaultBeforeTakingOver) {
    auto s = settledPair();
    vh::mirror::access::linkChanged(corePeer, false);
    auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = superUser;
    web->tokens->refreshToken = std::make_shared<auth::model::RefreshToken>();
    web->tokens->refreshToken->jti = "takeover-stepup-jti-" + msTag();
    web->tokens->refreshToken->aal = 1;
    web->tokens->refreshToken->amr = {"pwd"};
    web->tokens->refreshToken->authTime = std::chrono::system_clock::now() - std::chrono::hours(1);
    const auth::stepup::Scope scope(web);
    const auto target = "mirror.takeover:" + std::to_string(s.mirrorId);
    try {
        (void)ops::mirrors::takeover(superUser, s.mirrorId, vaultName(s));
        ADD_FAILURE() << "taken over without the step-up";
    } catch (const ops::StepUpRequired& e) {
        EXPECT_EQ(e.family, "data.destroy");
        EXPECT_EQ(e.target.value_or(""), target);
    }
    EXPECT_EQ(mirrorRow(s).role, "mirror") << "nothing changed without the step-up";
    web->stepUp().addGrant({.user_id = superUser->id, .refresh_jti = web->tokens->refreshToken->jti,
                            .family = auth::stepup::Family::DataDestroy, .target = target, .method = "test",
                            .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5)});
    // With the grant it goes on to the take over itself (here the core still answers the link service: no link in
    // this process, so it is taken over).
    const auto answer = ops::mirrors::takeover(superUser, s.mirrorId, vaultName(s));
    EXPECT_EQ(answer.value("term", uint64_t{0}), 2u);
    EXPECT_EQ(mirrorRow(s).role, "core");
    vh::mirror::access::linkChanged(corePeer, true);
}

// ---- the old core learns (step 4a) ---------------------------------------------------------------------------------------

TEST_F(MirrorTakeoverDbTest, AnOldCoreWithNothingNewStopsWhenToldAndFollowsTheNewCore) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto digest = mirrorRow(s).digest;
    Down down;
    vh::mirror::access::linkChanged(corePeer, false);
    (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    vh::mirror::access::linkChanged(corePeer, true);
    EXPECT_EQ(coreRow(s).role, "core") << "the old core does not know yet";

    // The new core tells it (the link is up; captured here, then served as the old core's handler would): it stops at
    // once, before anything is decided.
    struct Capture final : mf::Transport {
        std::vector<json> payloads;
        bool connected(uint32_t) override { return true; }
        std::optional<Answer> request(uint32_t, const std::string& c, const json& p) override {
            if (c == "peer.mirror.promoted") payloads.push_back(p);
            return std::nullopt;
        }
        bool notify(uint32_t, const std::string&, const json&) override { return true; }
    } capture;
    EXPECT_EQ(tk::tick(capture), 0u);
    ASSERT_EQ(capture.payloads.size(), 1u);
    EXPECT_EQ(capture.payloads.front().value("term", uint64_t{0}), 2u);
    const auto first = onCore(s, [&] { return tk::servePromoted(mirrorPeer, capture.payloads.front()); });
    EXPECT_EQ(first.value("outcome", ""), "pending");
    EXPECT_EQ(coreRow(s).state, "rejoining");
    onCore(s, [&] {
        EXPECT_EQ(vh::mirror::access::reason(s.coreId), vh::mirror::access::kRejoining);
        EXPECT_EQ(refusalOf([&] { ops::fs::mkdir(superUser, s.coreId, "/docs/told"); }), "read_only");
        EXPECT_ANY_THROW(sql("UPDATE fs_entry SET mode = (COALESCE(mode, 420) # 1) WHERE vault_id = " +
                             std::to_string(s.coreId) + " AND path = '/docs'"))
            << "the backstop";
        return 0;
    });
    EXPECT_TRUE(mq::Takeovers::openOf(s.mirrorId)) << "still waiting for the answer";

    // A pass decides (in one database either server's pass does): nothing past the fork point, the new core's tree is
    // the fork point's: it follows.
    EXPECT_GE(onCore(s, [&] { return tk::tick(capture); }), 1u);
    const auto a = coreRow(s);
    EXPECT_EQ(a.role, "mirror");
    EXPECT_EQ(a.state, "live");
    EXPECT_EQ(a.position(), (mq::Position{2, 0}));
    EXPECT_TRUE(a.copy_finished) << "no copy, nothing fetched";
    EXPECT_EQ(a.digest, digest);
    // Told again, it answers following; the take over settles and its fork base goes.
    EXPECT_EQ(tk::tick(wire), 1u);
    const auto t = mq::Takeovers::latestOf(s.mirrorId);
    EXPECT_EQ(t->settled_how.value_or(""), "returned");
    EXPECT_EQ(t->old_core_outcome.value_or(""), "following");
    EXPECT_TRUE(mq::Takeovers::forkBase(t->id, 0, 10).empty());
    EXPECT_EQ(tk::tick(wire), 0u) << "nothing more to tell";
    EXPECT_FALSE(a.role == "core" && mirrorRow(s).role == "core");
}

TEST_F(MirrorTakeoverDbTest, AnOldCoreThatCommittedAfterTheForkPointStopsReadOnlyKeepingItsChanges) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    Down down;
    vh::mirror::access::linkChanged(corePeer, false);
    (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    vh::mirror::access::linkChanged(corePeer, true);
    // Cut off, the old core went on: a change the new core never received.
    onCore(s, [&] {
        write(s.core, "/docs/only-on-the-old-core.txt", "never sent");
        (void)mq::Log::sequence(s.coreId);
        return 0;
    });

    // Told on the new core's pass, which (one database) also decides the old core's rejoin: rejoining.
    (void)tk::tick(wire);
    const auto a = coreRow(s);
    EXPECT_EQ(a.role, "core") << "its log past the fork point is the list of its changes";
    EXPECT_EQ(a.state, "rejoining");
    const auto r = onCore(s, [&] { return mq::Rejoins::openOf(s.coreId); });
    ASSERT_TRUE(r);
    EXPECT_EQ(r->phase, "rejoining");
    EXPECT_GE(r->changes, 1u);
    EXPECT_TRUE(onCore(s, [&] { return !uidOf(s.coreId, "/docs/only-on-the-old-core.txt").empty(); }))
        << "nothing dropped: its tree stays as it is";
    onCore(s, [&] {
        EXPECT_EQ(vh::mirror::access::reason(s.coreId), vh::mirror::access::kRejoining);
        const auto info = ops::mirrors::toJson(ops::mirrors::get(superUser, s.coreId));
        EXPECT_NE(info.value("advice", "").find("vh mirror resync"), std::string::npos) << info.dump();
        return 0;
    });
    // The new core learns how many, and says so; it is unaffected (live, taking changes).
    EXPECT_EQ(tk::tick(wire), 1u);
    const auto t = mq::Takeovers::openOf(s.mirrorId);
    ASSERT_TRUE(t) << "the fork base stays for the merge";
    EXPECT_EQ(t->old_core_outcome.value_or(""), "rejoining");
    EXPECT_EQ(t->old_core_changes.value_or(0), r->changes);
    EXPECT_FALSE(mq::Takeovers::forkBase(t->id, 0, 10).empty());
    EXPECT_NE(ops::mirrors::toJson(ops::mirrors::get(superUser, s.mirrorId)).value("advice", "").find("never received"),
              std::string::npos);
    EXPECT_EQ(mirrorRow(s).state, "live");
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/new-core-goes-on");

    // The way out today: start the old core's copy over from the new core (its change will be kept as held).
    const auto started = onCore(s, [&] { return vh::mirror::resync::start(s.coreId, superUser->id, "admin", wire); });
    EXPECT_EQ(started.value("state", ""), "live");
    const auto now = coreRow(s);
    EXPECT_EQ(now.role, "mirror");
    EXPECT_FALSE(now.copy_finished) << "its copy starts over from the new core's tree";
    EXPECT_EQ(onCore(s, [&] { return mq::Rejoins::latestOf(s.coreId)->phase; }), "resynced");
    EXPECT_EQ(mq::Takeovers::latestOf(s.mirrorId)->settled_how.value_or(""), "returned");
    EXPECT_EQ(mirrorRow(s).term, 3u) << "the new core's baseline again, in the next term";
}

TEST_F(MirrorTakeoverDbTest, BothServersTookOverAndNeitherFollowsTheOther) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto begun = onCore(s, [&] {
        return sw::begin(s.coreId, {.on = "core", .by = mq::Account{.node = coreNode, .id = superUser->id},
                                    .name = "admin"},
                         wire);
    });
    // The core decides switched; its decision never arrives; cut off, each side takes over.
    wire.dropCommit = true;
    (void)onCore(s, [&] { return sw::advance(begun.id, wire); });
    Down down;
    vh::mirror::access::linkChanged(corePeer, false);
    vh::mirror::access::linkChanged(mirrorPeer, false);
    (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    onCore(s, [&] { return tk::take(s.coreId, s.core->vault->name, superUser->id, "admin", down); });
    EXPECT_EQ(coreRow(s).term, 3u);
    EXPECT_EQ(mirrorRow(s).term, 2u);
    vh::mirror::access::linkChanged(corePeer, true);
    vh::mirror::access::linkChanged(mirrorPeer, true);

    // Each tells the other: each finds a take over of its own open: both forced, read-only, neither follows.
    (void)tk::tick(wire);
    (void)onCore(s, [&] { return tk::tick(wire); });
    EXPECT_EQ(mirrorRow(s).state, "forked");
    EXPECT_EQ(coreRow(s).state, "forked");
    EXPECT_EQ(mirrorRow(s).role, "core");
    EXPECT_EQ(coreRow(s).role, "core");
    EXPECT_EQ(vh::mirror::access::reason(s.mirrorId), vh::mirror::access::kForked);
    onCore(s, [&] {
        EXPECT_EQ(vh::mirror::access::reason(s.coreId), vh::mirror::access::kForked);
        EXPECT_NE(ops::mirrors::toJson(ops::mirrors::get(superUser, s.coreId)).value("advice", "").find("Pick the server"),
                  std::string::npos);
        return 0;
    });
    EXPECT_EQ(refusalOf([&] { ops::fs::mkdir(superUser, s.mirrorId, "/docs/neither"); }), "read_only");
}

TEST_F(MirrorTakeoverDbTest, ANewCoreTellsNothingAfterAnUnlinkAndAServerNotBehindRefusesTheTelling) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    Down down;
    vh::mirror::access::linkChanged(corePeer, false);
    (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    vh::mirror::access::linkChanged(corePeer, true);
    sql("UPDATE peer SET revoked_at = CURRENT_TIMESTAMP WHERE id = " + std::to_string(corePeer));
    EXPECT_EQ(tk::tick(wire), 0u);
    EXPECT_TRUE(wire.promoted.empty()) << "unlinked: nothing is told";
    sql("UPDATE peer SET revoked_at = NULL WHERE id = " + std::to_string(corePeer));
    // A server that is not behind (here: the new core told by a stale claim of a lower term) refuses.
    const auto stale = answerOf([&] {
        return tk::servePromoted(corePeer, {{"vault_uid", s.vaultUid}, {"term", 1},
                                            {"fork", {{"term", 1}, {"seq", 0}, {"digest", std::string(64, '0')},
                                                      {"entries", 0}}}});
    });
    EXPECT_EQ(stale.code, "mirror_term_stale");
    EXPECT_EQ(mirrorRow(s).state, "live");
}

// ---- detach and the core's deletion --------------------------------------------------------------------------------------

// A detach completes on either side of a take over: the old core that stopped rejoining, then the new core with its
// take over still open. Each settles what it holds (the rejoin and the take over `ended`, the fork base gone, the gate
// lifted), and the other server, told as a mirror's detach, ends its side: nothing tells anyone again.
TEST_F(MirrorTakeoverDbTest, ADetachOnEitherSideOfATakeOverSettlesItAndNothingIsToldAgain) {
    namespace leave = vh::mirror::leave;
    const auto corePeerRecord = *db::query::peer::Peers::byId(corePeer);
    const auto mirrorPeerRecord = *db::query::peer::Peers::byId(mirrorPeer);
    Down down;
    {
        // The old core, rejoining (it committed after the fork point), detaches.
        auto s = settledPair();
        Wire follow(s);
        SwitchWire wire(s, follow);
        vh::mirror::access::linkChanged(corePeer, false);
        (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
        vh::mirror::access::linkChanged(corePeer, true);
        onCore(s, [&] {
            write(s.core, "/docs/old-core-only.txt", "never sent");
            (void)mq::Log::sequence(s.coreId);
            return 0;
        });
        (void)tk::tick(wire);
        ASSERT_EQ(coreRow(s).state, "rejoining");
        const auto rejoin = onCore(s, [&] { return mq::Rejoins::openOf(s.coreId); });
        ASSERT_TRUE(rejoin);

        const auto gone = onCore(s, [&] { return leave::detach(s.coreId, superUser->id, superUser->id, "admin"); });
        EXPECT_EQ(gone.before.role, "core");
        EXPECT_EQ(gone.before.state, "rejoining");
        EXPECT_TRUE(gone.core_told_later) << "the new core is told as a mirror's detach";
        onCore(s, [&] {
            EXPECT_FALSE(mq::MirrorVaults::get(s.coreId));
            EXPECT_FALSE(mq::Rejoins::openOf(s.coreId));
            EXPECT_EQ(mq::Rejoins::get(rejoin->id)->phase, "ended");
            EXPECT_EQ(vh::db::query::vault::Vault::getVault(s.coreId)->owner_id, s.core->vault->owner_id)
                << "a core row keeps its owner";
            EXPECT_NO_THROW(ops::fs::mkdir(superUser, s.coreId, "/docs/its-own-again"));
            return 0;
        });
        // The new core is told: its side ends, the take over settles, the fork base goes, nothing is told again.
        const auto t = mq::Takeovers::openOf(s.mirrorId);
        ASSERT_TRUE(t);
        EXPECT_TRUE(leave::detachedReceived(corePeerRecord, {{"vault_uid", s.vaultUid},
                                                             {"at", {{"term", 1}, {"seq", 0}}}, {"missing", 0}})
                        .at("recorded").get<bool>());
        EXPECT_FALSE(mq::MirrorVaults::get(s.mirrorId));
        EXPECT_EQ(mq::Takeovers::latestOf(s.mirrorId)->settled_how.value_or(""), "ended");
        EXPECT_TRUE(mq::Takeovers::forkBase(t->id, 0, 10).empty());
        const auto told = wire.promoted.size();
        EXPECT_EQ(tk::tick(wire), 0u);
        EXPECT_EQ(onCore(s, [&] { return tk::tick(wire); }), 0u);
        EXPECT_EQ(wire.promoted.size(), told) << "nothing is told any more";
    }
    {
        // The new core detaches while its take over is open (its old core never came back).
        auto s = settledPair();
        Wire follow(s);
        SwitchWire wire(s, follow);
        vh::mirror::access::linkChanged(corePeer, false);
        (void)tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
        const auto t = mq::Takeovers::openOf(s.mirrorId);
        ASSERT_TRUE(t);
        ASSERT_FALSE(mq::Takeovers::forkBase(t->id, 0, 10).empty());

        const auto gone = leave::detach(s.mirrorId, superUser->id, superUser->id, "admin");
        EXPECT_EQ(gone.before.role, "core");
        EXPECT_FALSE(mq::MirrorVaults::get(s.mirrorId));
        EXPECT_FALSE(mq::Takeovers::openOf(s.mirrorId));
        EXPECT_EQ(mq::Takeovers::latestOf(s.mirrorId)->settled_how.value_or(""), "ended");
        EXPECT_TRUE(mq::Takeovers::forkBase(t->id, 0, 10).empty());
        EXPECT_TRUE(mq::MirrorDetach::forVault(s.mirrorId)) << "recorded as a detach";
        vh::mirror::access::linkChanged(corePeer, true);
        EXPECT_EQ(tk::tick(wire), 0u);
        EXPECT_TRUE(wire.promoted.empty()) << "the old core is not told it was taken over";
        // The old core, still the core, learns of the detach instead: its mirror ends, its vault stays.
        EXPECT_TRUE(onCore(s, [&] {
                        return leave::detachedReceived(mirrorPeerRecord, {{"vault_uid", s.vaultUid},
                                                                          {"at", {{"term", 2}, {"seq", 0}}},
                                                                          {"missing", 0}});
                    }).at("recorded").get<bool>());
        EXPECT_FALSE(onCore(s, [&] { return mq::MirrorVaults::get(s.coreId); }));
    }
}

// The core scheduled the vault's deletion, so the copy is paused (mirror_core_deleting); the core then went away. A take
// over is allowed: the vault is this server's from then on, live, and the record says the old core was deleting it.
TEST_F(MirrorTakeoverDbTest, ATakeOverWhileTheCoreDeletesTheVaultIsAllowedAndAuditedAsSuch) {
    auto s = settledPair();
    ASSERT_TRUE(mq::MirrorDetach::pauseForCore(s.mirrorId, std::string(vh::mirror::leave::kCoreDeletingReason),
                                               {{"purge_after", std::time(nullptr) + 86400}, {"copy", "leave"}}));
    ASSERT_EQ(mirrorRow(s).state, "paused");
    Down down;
    vh::mirror::access::linkChanged(corePeer, false);
    const auto answer = tk::take(s.mirrorId, vaultName(s), superUser->id, "admin", down);
    vh::mirror::access::linkChanged(corePeer, true);
    EXPECT_NE(answer.value("warning", "").find("deleting the vault"), std::string::npos) << answer.dump();
    const auto row = mirrorRow(s);
    EXPECT_EQ(row.role, "core");
    EXPECT_EQ(row.state, "live");
    EXPECT_FALSE(row.stop_reason);
    EXPECT_TRUE(vh::mirror::leave::deletionOf(s.mirrorId).is_null()) << "nothing deletes it here";
    EXPECT_NO_THROW(ops::fs::mkdir(superUser, s.mirrorId, "/docs/kept"));
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_EQ(one<int>("SELECT count(*) FROM audit_event WHERE action = 'mirror.takeover' AND vault_id = " +
                       std::to_string(s.mirrorId) + " AND details::jsonb->>'core_deleting' = 'true' "
                       "AND details::jsonb->'core_deletion'->>'copy' = 'leave'"),
              1);
}

}
