// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The planned switch of the core role (wave 5 piece B; migration 168; design/peers/mirror.md "Planned switch", "As
// built: the planned switch"; mirror::switching, db::query::mirror::Switches), with the two servers of
// test_mirror_submit_db.cpp (helpers/mirror_pair.hpp): the core's steps run on its turn (AsCore), and the switch's wire
// carries prepare and commit to the mirror's turn and the mirror's request to the core's.
//
// Covered: a switch end to end (both read-only with the reason while it runs, the database refusing a write that
// missed the gate, the roles swapped in term + 1, the new core's log from (term + 1, 1) with the baseline at the digest
// both hold, the old core a mirror that takes changes as pending once told); asked on the mirror; the mirror catching
// up under the freeze; every interruption point (the prepare lost before it arrived, its answer lost, the mirror
// prepared and the core's deadline passing, the decision taken and not told, the new core's answer lost, a stop of
// either side between steps), each ending switched or with nothing changed on both, and never both accepting changes
// as core (invariant 12); refusals (pending changes, contents not yet here, submissions queued on the core, a switch
// running, an orphaned copy, a vault with a remote, the link down) and a switch granted once the pending change
// confirmed; the wire's not_found for another server; who may switch.

#include "../helpers/mirror_pair.hpp"

#include "../helpers/identities.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/mirror/Switch.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Peer.hpp"
#include "mirror/switching/Switch.hpp"
#include "ops/PeerPolicy.hpp"
#include "protocols/ws/Session.hpp"

#include <algorithm>

namespace vh::test_mirror_switch {

using namespace vh::test_mirror_pair;   // the fixture and its aliases (json, mq, mf, ap, ms)
namespace sw = vh::mirror::switching;

class MirrorSwitchDbTest : public MirrorPairDb {
protected:
    static void SetUpTestSuite() {
        setUpPair("test_mirror_switch");
        sw::setTellPauseForTesting(true);
    }

    static void TearDownTestSuite() {
        sw::setTellPauseForTesting(false);
        sw::setTimeoutForTesting(std::chrono::seconds(0));
        vh::mirror::access::linkChanged(mirrorPeer, false);
        MirrorPairDb::TearDownTestSuite();
    }

    void SetUp() override {
        MirrorPairDb::SetUp();
        if (IsSkipped()) return;
        vh::mirror::access::linkChanged(mirrorPeer, true);
        // One database holds every test's servers: a switch an earlier test left active is no pass's business here.
        sql("UPDATE mirror_switch SET notify = FALSE, phase = CASE WHEN ended_at IS NULL THEN 'abandoned' ELSE phase END, "
            "  ended_at = COALESCE(ended_at, CURRENT_TIMESTAMP) WHERE ended_at IS NULL OR notify");
        // The mirror's role for the core once it is the core (its link default for that server): read-write.
        policy("power_user");
    }

    // The mirror's link default for its core (corePeer): the role the old core holds after a switch. nullopt: none.
    static void policy(const std::optional<std::string>& role) {
        (void)ops::peer_policy::set(superUser, std::to_string(corePeer),
                                    role ? std::optional<ops::roles::Ref>(ops::roles::Ref{*role}) : std::nullopt);
    }

    static void node(const std::string& id) { sql("UPDATE device_node SET node_id = '" + id + "' WHERE singleton"); }

    // The core's turn (its uids unparked, this server under the core's node id), then back to the mirror's.
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

    // The mirror's turn, from wherever the caller is, and back.
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
        } catch (const ops::Conflict& e) {
            return {.ok = false, .code = "conflict", .error = e.what()};
        } catch (const ops::Error& e) {
            return {.ok = false, .code = "invalid", .error = e.what()};
        }
    }

    // The switch's messages between the two turns; everything else is the pair's wire (the log, acknowledgements).
    class SwitchWire final : public mf::Transport {
    public:
        SwitchWire(Scenario& s, Wire& follow) : s_(s), follow_(follow) {}
        bool up{true};
        bool dropRequest{false};   // the message never arrives
        bool loseAnswer{false};    // it arrives and is served; its answer is lost
        std::vector<std::string> sent;

        bool connected(uint32_t) override { return up; }
        std::optional<Answer> request(const uint32_t peer, const std::string& command, const json& payload) override {
            sent.push_back(command);
            if (!up || dropRequest) return std::nullopt;
            std::optional<Answer> out;
            if (command == "peer.mirror.switch.prepare")
                out = onMirror(s_, [&] { return answerOf([&] { return sw::servePrepare(corePeer, payload); }); });
            else if (command == "peer.mirror.switch.commit")
                out = onMirror(s_, [&] { return answerOf([&] { return sw::serveCommit(corePeer, payload); }); });
            else if (command == "peer.mirror.switch.request")
                out = onCore(s_, [&] { return answerOf([&] { return sw::serveRequest(mirrorPeer, payload); }); });
            else
                return follow_.request(peer, command, payload);
            if (loseAnswer) return std::nullopt;
            return out;
        }
        bool notify(uint32_t, const std::string&, const json&) override { return true; }

    private:
        Scenario& s_;
        Wire& follow_;
    };

    // ---- the two rows

    static mq::MirrorVault coreRow(Scenario& s) {
        return onCore(s, [&] { return mq::MirrorVaults::get(s.coreId).value_or(mq::MirrorVault{}); });
    }

    // A server accepts changes as the vault's core: its row is a live core (its writes are logged in its term).
    static bool acceptsAsCore(const mq::MirrorVault& mv) { return mv.role == "core" && mv.state == "live"; }

    // Invariant 12, at the point the test stands: the two servers never both accept changes as core, and a server that
    // accepts as core in a term is the only one with that term as core.
    static void expectOneCore(Scenario& s, const std::string& where) {
        const auto a = coreRow(s);
        const auto b = mirrorRow(s);
        EXPECT_FALSE(acceptsAsCore(a) && acceptsAsCore(b)) << where << ": both accept changes as core";
        if (a.role == "core" && b.role == "core") {
            EXPECT_NE(a.term, b.term) << where << ": two cores in one term";
        }
    }

    // The switch was abandoned with nothing changed: the core is the live core in term 1, the mirror a live mirror
    // in term 1, at the same position and digest as before.
    static void expectNothingChanged(Scenario& s, const mq::Position at, const vh::mirror::Digest& digest,
                                     const std::string& where) {
        const auto a = coreRow(s);
        const auto b = mirrorRow(s);
        EXPECT_EQ(a.role, "core") << where;
        EXPECT_EQ(a.state, "live") << where;
        EXPECT_EQ(a.term, 1u) << where;
        EXPECT_EQ(b.role, "mirror") << where;
        EXPECT_EQ(b.state, "live") << where;
        EXPECT_EQ(b.position(), at) << where;
        EXPECT_EQ(b.digest, digest) << where;
        EXPECT_EQ(a.digest, digest) << where;
    }

    // Both switched: the old core the mirror in term 2 at (2, 0), the old mirror the core in term 2 with its baseline
    // at (2, 0) and the digest both hold.
    static void expectSwitched(Scenario& s, const vh::mirror::Digest& digest, const std::string& where) {
        const auto a = coreRow(s);
        const auto b = mirrorRow(s);
        EXPECT_EQ(b.role, "core") << where;
        EXPECT_EQ(b.state, "live") << where;
        EXPECT_EQ(b.term, 2u) << where;
        EXPECT_EQ(b.last_seq, 0u) << where;
        ASSERT_TRUE(b.baseline) << where;
        EXPECT_EQ(*b.baseline, (mq::Position{2, 0})) << where;
        EXPECT_EQ(b.baseline_digest.value_or(vh::mirror::Digest{}), digest) << where;
        EXPECT_FALSE(b.grant) << where << ": a core holds no grant";
        EXPECT_EQ(a.role, "mirror") << where;
        EXPECT_EQ(a.state, "live") << where;
        EXPECT_EQ(a.position(), (mq::Position{2, 0})) << where;
        EXPECT_TRUE(a.copy_finished) << where;
        EXPECT_EQ(a.digest, digest) << where;
        EXPECT_EQ(b.digest, digest) << where;
    }

    static mq::Switch beginOnCore(Scenario& s, SwitchWire& wire) {
        return onCore(s, [&] {
            return sw::begin(s.coreId, {.on = "core", .by = mq::Account{.node = coreNode, .id = superUser->id},
                                        .name = "admin"},
                             wire);
        });
    }

    static bool advance(Scenario& s, const uint64_t id, SwitchWire& wire) {
        return onCore(s, [&] { return sw::advance(id, wire); });
    }

    // Steps the core's switch until it ended and was told (bounded).
    static void drive(Scenario& s, const uint64_t id, SwitchWire& wire) {
        for (int i = 0; i < 20; ++i) {
            (void)advance(s, id, wire);
            const auto now = onCore(s, [&] { return mq::Switches::get(id); });
            ASSERT_TRUE(now);
            if (!now->open() && !now->notify) return;
        }
        FAIL() << "the switch never ended";
    }

    static void pastDeadline(Scenario& s, const uint64_t id) {
        onCore(s, [&] {
            sql("UPDATE mirror_switch SET deadline = CURRENT_TIMESTAMP - interval '1 minute' WHERE id = " +
                std::to_string(id));
            return 0;
        });
    }

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

    // A mirror that holds its core's tree (contents included) and nothing pending.
    static Scenario settledPair() {
        auto s = begin([](const EnginePtr& e) {
            e->mkdir("/docs", superUser);
            write(e, "/docs/a.txt", "the first file");
        });
        Wire wire(s);
        followAll(wire, s);
        receiveAll(s);
        expectSettled(s);
        return s;
    }
};

// ---- end to end ------------------------------------------------------------------------------------------------------------

TEST_F(MirrorSwitchDbTest, ASwitchSwapsTheRolesInTheNextTermWithBothReadOnlyWhileItRuns) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto digest = mirrorRow(s).digest;

    const auto begun = beginOnCore(s, wire);
    EXPECT_EQ(begun.phase, "draining");
    EXPECT_EQ(coreRow(s).state, "switching");
    // The core is read-only with the reason a person can act on; the database refuses a write that missed the gate.
    onCore(s, [&] {
        EXPECT_EQ(vh::mirror::access::reason(s.coreId), vh::mirror::access::kSwitching);
        EXPECT_FALSE(vh::mirror::access::held(s.coreId)) << "a switching core is gated, not held";
        try {
            ops::fs::mkdir(superUser, s.coreId, "/docs/during");
            ADD_FAILURE() << "a write on the switching core was accepted";
        } catch (const ops::ReadOnly& e) {
            EXPECT_EQ(e.reason, vh::mirror::access::kSwitching);
        }
        EXPECT_ANY_THROW(sql("UPDATE fs_entry SET mode = (COALESCE(mode, 420) # 1) WHERE vault_id = " +
                             std::to_string(s.coreId) + " AND path = '/docs'"));
        return 0;
    });

    // Drained, prepared (the mirror read-only too, ready at once: it holds the core's last change), decided, told.
    ASSERT_TRUE(advance(s, begun.id, wire));
    expectOneCore(s, "after the first step");
    const auto after = onCore(s, [&] { return mq::Switches::get(begun.id); });
    ASSERT_TRUE(after);
    EXPECT_EQ(after->phase, "switched");
    EXPECT_FALSE(after->notify) << "told in the same step";
    const auto mirrorSide = mq::Switches::bySwitchId(begun.switch_id, "mirror");
    ASSERT_TRUE(mirrorSide);
    EXPECT_EQ(mirrorSide->phase, "switched");
    expectSwitched(s, digest, "switched");
    EXPECT_EQ(wire.sent, (std::vector<std::string>{"peer.mirror.switch.prepare", "peer.mirror.switch.commit"}));

    // The new core logs its own changes from (2, 1), one group per change.
    write(s.mirror, "/docs/b.txt", "written on the new core");
    const auto numbered = mq::Log::sequence(s.mirrorId);
    ASSERT_TRUE(numbered);
    EXPECT_EQ(numbered->last.term, 2u);
    EXPECT_EQ(one<int>("SELECT min(seq)::int FROM vault_replication_log WHERE vault_id = " + std::to_string(s.mirrorId)),
              1);
    EXPECT_TRUE(mq::MirrorVaults::digestAt(s.mirrorId, {2, 0})) << "the new mirror's first acknowledgement is known";
    EXPECT_EQ(*mq::MirrorVaults::digestAt(s.mirrorId, {2, 0}), digest);
    expectOneCore(s, "after the new core wrote");

    // The old core is a mirror now: a change there is a pending change for the new core (its grant recorded first).
    onCore(s, [&] {
        EXPECT_TRUE(vh::mirror::access::held(s.coreId));
        EXPECT_TRUE(mq::MirrorVaults::recordGrant(s.coreId, grantOf(rbac::role::Vault::Full(), ownNode)));
        EXPECT_EQ(vh::mirror::access::state(s.coreId), vh::mirror::access::State::Live);
        ops::fs::mkdir(superUser, s.coreId, "/docs/from-the-old-core");
        EXPECT_EQ(mq::Pending::list(s.coreId).size(), 1u) << "taken as pending, submitted to the new core";
        EXPECT_EQ(one<int>("SELECT count(*)::int FROM vault_replication_log WHERE vault_id = " + std::to_string(s.coreId)),
                  0)
            << "nothing logged on the old core";
        return 0;
    });
    // Both servers audited it.
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_GE(one<int>("SELECT count(*)::int FROM audit_event WHERE action = 'mirror.switch' AND vault_id = " +
                       std::to_string(s.mirrorId)),
              1);
}

TEST_F(MirrorSwitchDbTest, AskedOnTheMirrorTheCoreBeginsAndTheMirrorLearnsTheOutcome) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto digest = mirrorRow(s).digest;

    const auto asked = sw::request(s.mirrorId, superUser->id, "admin", wire, std::chrono::milliseconds(0));
    EXPECT_EQ(asked.value("outcome", ""), "running");
    EXPECT_EQ(asked.value("side", ""), "mirror");
    EXPECT_EQ(asked.value("phase", ""), "requested");
    const auto switchId = asked.value("switch_id", "");
    const auto onTheCore = onCore(s, [&] { return mq::Switches::bySwitchId(switchId, "core"); });
    ASSERT_TRUE(onTheCore);
    EXPECT_EQ(onTheCore->asked_on, "mirror");
    ASSERT_TRUE(onTheCore->asked_by);
    EXPECT_EQ(onTheCore->asked_by->node, ownNode) << "the mirror's person, named by the mirror's node id";
    EXPECT_EQ(onTheCore->asked_by->id, superUser->id);

    drive(s, onTheCore->id, wire);
    expectSwitched(s, digest, "asked on the mirror");
    const auto here = mq::Switches::bySwitchId(switchId, "mirror");
    ASSERT_TRUE(here);
    EXPECT_EQ(here->phase, "switched");
    expectOneCore(s, "asked on the mirror");
}

TEST_F(MirrorSwitchDbTest, TheMirrorCatchesUpToTheCoresLastChangeUnderTheFreeze) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    coreChange(s, [](const EnginePtr& e) { e->mkdir("/docs/late", superUser); });
    const auto last = s.at;
    const auto begun = beginOnCore(s, wire);

    EXPECT_FALSE(advance(s, begun.id, wire)) << "the mirror has not applied the core's last change yet";
    const auto waiting = onCore(s, [&] { return mq::Switches::get(begun.id); });
    EXPECT_EQ(waiting->phase, "preparing");
    EXPECT_EQ(waiting->seq.value_or(0), last.seq);
    EXPECT_EQ(waiting->detail.value("waiting", ""), "applying");
    EXPECT_EQ(mirrorRow(s).state, "switching");
    EXPECT_EQ(vh::mirror::access::reason(s.mirrorId), vh::mirror::access::kSwitching);
    EXPECT_TRUE(sw::following(s.mirrorId));
    expectOneCore(s, "preparing");

    followAll(follow, s);   // the follower applies the log up to the core's position while switching
    EXPECT_EQ(mirrorRow(s).position(), last);
    drive(s, begun.id, wire);
    expectSwitched(s, s.digests.at(last), "after catching up");
}

// ---- interrupted: each point ends switched or with nothing changed --------------------------------------------------------

TEST_F(MirrorSwitchDbTest, InterruptedBeforeThePrepareIsAnsweredNothingChangesOnEitherServer) {
    sw::setTimeoutForTesting(std::chrono::seconds(30));
    for (const bool reached : {false, true}) {
        SCOPED_TRACE(reached ? "the prepare arrived, its answer was lost" : "the prepare never arrived");
        auto s = settledPair();
        Wire follow(s);
        SwitchWire wire(s, follow);
        const auto at = mirrorRow(s).position();
        const auto digest = mirrorRow(s).digest;
        const auto begun = beginOnCore(s, wire);
        (reached ? wire.loseAnswer : wire.dropRequest) = true;
        EXPECT_FALSE(advance(s, begun.id, wire));
        EXPECT_EQ(mirrorRow(s).state, reached ? "switching" : "live");
        expectOneCore(s, "prepare unanswered");

        // The core's deadline passes: abandoned, then told (the mirror goes live again where it had frozen).
        pastDeadline(s, begun.id);
        wire.loseAnswer = wire.dropRequest = false;
        drive(s, begun.id, wire);
        const auto ended = onCore(s, [&] { return mq::Switches::get(begun.id); });
        EXPECT_EQ(ended->phase, "abandoned");
        EXPECT_EQ(ended->reason.value_or(""), "mirror_switch_timeout");
        expectNothingChanged(s, at, digest, "abandoned by the deadline");
        if (reached) {
            const auto mine = mq::Switches::bySwitchId(begun.switch_id, "mirror");
            ASSERT_TRUE(mine);
            EXPECT_EQ(mine->phase, "abandoned");
        }
        EXPECT_EQ(vh::mirror::access::state(s.mirrorId), vh::mirror::access::State::Live);
        onCore(s, [&] {
            EXPECT_EQ(vh::mirror::access::state(s.coreId), vh::mirror::access::State::NotMirrored);
            ops::fs::mkdir(superUser, s.coreId, "/docs/after-the-abandon");
            return 0;
        });
    }
    sw::setTimeoutForTesting(std::chrono::seconds(0));
}

TEST_F(MirrorSwitchDbTest, APreparedMirrorNeverDecidesTheCoresDeadlineAbandonsAndARestartChangesNothing) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto at = mirrorRow(s).position();
    const auto digest = mirrorRow(s).digest;
    const auto begun = beginOnCore(s, wire);

    // Prepared (the answer reached the core's process but the decision is not taken: a stop of the core right there,
    // simulated by losing the answer).
    wire.loseAnswer = true;
    EXPECT_FALSE(advance(s, begun.id, wire));
    const auto prepared = mq::Switches::bySwitchId(begun.switch_id, "mirror");
    ASSERT_TRUE(prepared);
    EXPECT_EQ(prepared->phase, "prepared");
    EXPECT_FALSE(sw::following(s.mirrorId)) << "prepared: the follower asks nothing";
    EXPECT_EQ(mf::Follower::instance()->step(s.mirrorId, follow).step, mf::Step::Stopped);
    expectOneCore(s, "prepared, undecided");
    // The mirror restarts: its rows say the same; its step decides nothing.
    EXPECT_FALSE(sw::advance(prepared->id, wire));
    EXPECT_EQ(mirrorRow(s).state, "switching");
    EXPECT_EQ(mq::Switches::bySwitchId(begun.switch_id, "mirror")->phase, "prepared");

    pastDeadline(s, begun.id);
    wire.loseAnswer = false;
    drive(s, begun.id, wire);
    expectNothingChanged(s, at, digest, "the core abandoned a prepared switch");
    EXPECT_EQ(mq::Switches::bySwitchId(begun.switch_id, "mirror")->phase, "abandoned");
}

TEST_F(MirrorSwitchDbTest, DecidedAndNotToldNeitherServerAcceptsChangesUntilTheNewCoreHearsIt) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto digest = mirrorRow(s).digest;
    const auto begun = beginOnCore(s, wire);

    // The core decides; the link drops before the commit reaches the mirror.
    struct DropCommit final : mf::Transport {
        SwitchWire& inner;
        explicit DropCommit(SwitchWire& w) : inner(w) {}
        bool connected(uint32_t p) override { return inner.connected(p); }
        std::optional<Answer> request(uint32_t p, const std::string& c, const json& payload) override {
            if (c == "peer.mirror.switch.commit") return std::nullopt;
            return inner.request(p, c, payload);
        }
        bool notify(uint32_t, const std::string&, const json&) override { return true; }
    } drop(wire);
    (void)onCore(s, [&] { return sw::advance(begun.id, drop); });
    auto a = coreRow(s);
    EXPECT_EQ(a.role, "mirror") << "the decision is durable on the core";
    EXPECT_EQ(a.state, "switching") << "and it accepts nothing until the new core confirms";
    EXPECT_EQ(mirrorRow(s).role, "mirror");
    EXPECT_EQ(mirrorRow(s).state, "switching");
    expectOneCore(s, "decided, not told");
    onCore(s, [&] {
        EXPECT_EQ(vh::mirror::access::reason(s.coreId), vh::mirror::access::kSwitching);
        return 0;
    });
    EXPECT_EQ(vh::mirror::access::reason(s.mirrorId), vh::mirror::access::kSwitching);
    // The old core's follower asks the new one nothing yet (it would not be the core).
    onCore(s, [&] {
        EXPECT_EQ(mf::Follower::instance()->step(s.coreId, follow).step, mf::Step::Stopped);
        return 0;
    });

    // The new core takes the role, and its answer is lost: told again, it answers the same.
    wire.loseAnswer = true;
    (void)advance(s, begun.id, wire);
    EXPECT_EQ(mirrorRow(s).role, "core");
    EXPECT_EQ(coreRow(s).state, "switching");
    expectOneCore(s, "the new core's answer lost");
    wire.loseAnswer = false;
    drive(s, begun.id, wire);
    expectSwitched(s, digest, "told again");
}

TEST_F(MirrorSwitchDbTest, AStopOfEitherServerBetweenStepsResumesFromItsRows) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto digest = mirrorRow(s).digest;
    const auto begun = beginOnCore(s, wire);
    // The core stops right after the freeze: nothing is in memory that the next pass needs (the writers it waits for
    // are recorded; after a restart none of them runs).
    EXPECT_EQ(onCore(s, [&] { return mq::Switches::get(begun.id); })->phase, "draining");
    // Its pass after the restart takes the switch on from its row.
    EXPECT_GE(onCore(s, [&] { return sw::tick(wire); }), 1u);
    expectSwitched(s, digest, "resumed from the rows");
    // Nothing is left for a pass to do.
    EXPECT_EQ(onCore(s, [&] { return sw::tick(wire); }), 0u);
    EXPECT_EQ(sw::tick(wire), 0u);
}

TEST_F(MirrorSwitchDbTest, AVaultThatStopsWhileSwitchingAbandonsTheSwitchAndKeepsItsStop) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto begun = beginOnCore(s, wire);
    onCore(s, [&] {
        EXPECT_TRUE(mq::MirrorVaults::stop(s.coreId, "diverged", "mirror_digest_mismatch", {{"why", "a test"}}));
        return 0;
    });
    drive(s, begun.id, wire);
    const auto ended = onCore(s, [&] { return mq::Switches::get(begun.id); });
    EXPECT_EQ(ended->phase, "abandoned");
    EXPECT_EQ(ended->reason.value_or(""), "mirror_switch_interrupted");
    EXPECT_EQ(coreRow(s).state, "diverged") << "the stop stands; the switch does not make the vault live";
    EXPECT_EQ(coreRow(s).role, "core");
    EXPECT_EQ(mirrorRow(s).role, "mirror");
    expectOneCore(s, "stopped while switching");
}

// ---- refused, and granted once the obstacle is gone ----------------------------------------------------------------------

TEST_F(MirrorSwitchDbTest, ASwitchIsRefusedWithPendingChangesAndGrantedOnceTheyConfirm) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/pending");
    ASSERT_EQ(mq::Pending::list(s.mirrorId).size(), 1u);
    const auto at = mirrorRow(s).position();
    const auto digest = mirrorRow(s).digest;

    // Asked on the mirror: refused at once, the core never asked.
    EXPECT_EQ(refusalOf([&] { (void)sw::request(s.mirrorId, superUser->id, "admin", wire, std::chrono::milliseconds(0)); }),
              "mirror_pending_changes");
    EXPECT_TRUE(wire.sent.empty());
    // Asked on the core: the mirror refuses its prepare and the switch is abandoned with that reason.
    const auto begun = beginOnCore(s, wire);
    drive(s, begun.id, wire);
    const auto ended = onCore(s, [&] { return mq::Switches::get(begun.id); });
    EXPECT_EQ(ended->phase, "abandoned");
    EXPECT_EQ(ended->reason.value_or(""), "mirror_pending_changes");
    expectNothingChanged(s, at, digest, "refused for a pending change");
    EXPECT_EQ(mq::Pending::list(s.mirrorId).size(), 1u) << "the person's change is still pending, untouched";

    // The change confirms (the core took it), then the switch is granted.
    followAll(follow, s);
    expectSettled(s);
    const auto again = beginOnCore(s, wire);
    drive(s, again.id, wire);
    expectSwitched(s, s.digests.at(s.at), "granted once the change confirmed");
    EXPECT_TRUE(onMirror(s, [&] { return !uidOf(s.mirrorId, "/docs/pending").empty(); }));
}

TEST_F(MirrorSwitchDbTest, ASwitchIsRefusedForContentsNotYetHereQueuedSubmissionsARunningSwitchAndAnOrphanedCopy) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "contents the mirror has not fetched yet");
    });
    Wire follow(s);
    followAll(follow, s);
    SwitchWire wire(s, follow);

    // Contents not yet here: refused at the mirror's prepare, abandoned.
    {
        const auto begun = beginOnCore(s, wire);
        drive(s, begun.id, wire);
        EXPECT_EQ(onCore(s, [&] { return mq::Switches::get(begun.id); })->reason.value_or(""),
                  "mirror_contents_missing");
        EXPECT_EQ(mirrorRow(s).state, "live");
    }
    receiveAll(s);

    // A submission queued on the core: the freeze refuses.
    sql("INSERT INTO mirror_submission (vault_id, request_id, peer_id, payload) VALUES (" + std::to_string(s.coreId) +
        ", 'queued-request-1', " + std::to_string(mirrorPeer) + ", '{}'::jsonb)");
    EXPECT_EQ(refusalOf([&] { (void)beginOnCore(s, wire); }), "mirror_submissions_queued");
    sql("DELETE FROM mirror_submission WHERE vault_id = " + std::to_string(s.coreId));
    // A switch running already.
    const auto first = beginOnCore(s, wire);
    EXPECT_EQ(refusalOf([&] { (void)beginOnCore(s, wire); }), "mirror_switch_running");
    EXPECT_TRUE(mq::Switches::abandonCore(first.id, "test", json::object()));
    // The link down.
    wire.up = false;
    EXPECT_EQ(refusalOf([&] { (void)beginOnCore(s, wire); }), "peer_link_down");
    wire.up = true;
    // A vault with a remote keeps its core (phase 3).
    const auto type = [&](const std::string& t) {
        sql("ALTER TABLE vault DISABLE TRIGGER USER");
        sql("UPDATE vault SET type = '" + t + "' WHERE id = " + std::to_string(s.coreId));
        sql("ALTER TABLE vault ENABLE TRIGGER USER");
    };
    type("s3");
    EXPECT_EQ(refusalOf([&] { (void)beginOnCore(s, wire); }), "mirror_has_remote");
    type("local");
    EXPECT_EQ(mq::MirrorVaults::get(s.coreId)->state, "live") << "no refusal froze anything";
    // Told of the abandoned switch (the mirror never heard of it): nothing to undo there.
    (void)onCore(s, [&] { return sw::tick(wire); });

    // An orphaned copy has no core to switch with.
    ASSERT_TRUE(mq::MirrorVaults::orphan(s.mirrorId));
    EXPECT_EQ(refusalOf([&] { (void)sw::request(s.mirrorId, superUser->id, "admin", wire, std::chrono::milliseconds(0)); }),
              "mirror_orphaned");
}

TEST_F(MirrorSwitchDbTest, TheWireAnswersNotFoundToAServerThatIsNotTheVaultsOtherSide) {
    auto s = settledPair();
    Wire follow(s);
    SwitchWire wire(s, follow);
    const auto begun = beginOnCore(s, wire);
    const json prepare{{"vault_uid", s.vaultUid}, {"switch_id", begun.switch_id}, {"term", 1}, {"seq", 0},
                       {"digest", mirrorRow(s).digest.hex()}, {"entries", mirrorRow(s).digest.entries}};
    // The mirror's own link row (it names this server) is not its core.
    EXPECT_THROW((void)sw::servePrepare(mirrorPeer, prepare), ops::NotFound);
    EXPECT_THROW((void)sw::serveCommit(mirrorPeer, {{"vault_uid", s.vaultUid}, {"switch_id", begun.switch_id},
                                                    {"outcome", "switched"}}),
                 ops::NotFound);
    EXPECT_EQ(mirrorRow(s).state, "live") << "nothing frozen for another server";
    // A commit for a switch this mirror never prepared is refused (the core never decides before it is ready).
    const auto refused = answerOf([&] {
        return sw::serveCommit(corePeer, {{"vault_uid", s.vaultUid}, {"switch_id", begun.switch_id},
                                          {"outcome", "switched"}});
    });
    EXPECT_EQ(refused.code, "mirror_not_prepared");
    EXPECT_EQ(mirrorRow(s).role, "mirror");
    // The core's request handler: only the vault's mirror may ask.
    onCore(s, [&] {
        EXPECT_THROW((void)sw::serveRequest(corePeer, {{"vault_uid", s.vaultUid}}), ops::NotFound);
        return 0;
    });
    drive(s, begun.id, wire);
}

// ---- the old core's role on the new core -------------------------------------------------------------------------------

TEST_F(MirrorSwitchDbTest, ASwitchThatWouldLeaveTheOldCoreNoRoleIsRefusedUnlessThePersonAcceptsIt) {
    {
        SCOPED_TRACE("no policy for the old core on the mirror, asked on the core");
        auto s = settledPair();
        Wire follow(s);
        SwitchWire wire(s, follow);
        policy(std::nullopt);
        const auto at = mirrorRow(s).position();
        const auto digest = mirrorRow(s).digest;
        const auto begun = beginOnCore(s, wire);
        drive(s, begun.id, wire);
        const auto answer = onCore(s, [&] { return sw::outcome(s.coreId, begun.switch_id, "core"); });
        EXPECT_EQ(answer.value("outcome", ""), "abandoned");
        EXPECT_EQ(answer.value("reason", ""), "mirror_switch_no_role");
        EXPECT_NE(answer.at("detail").value("why", "").find("--accept-no-access"), std::string::npos)
            << answer.dump();
        EXPECT_EQ(answer.value("peer_access", ""), "none");
        expectNothingChanged(s, at, digest, "refused for no role");
        EXPECT_EQ(mq::Switches::bySwitchId(begun.switch_id, "mirror")->phase, "abandoned");

        // Asked on the mirror: refused there before the core is asked.
        EXPECT_EQ(refusalOf([&] {
                      (void)sw::request(s.mirrorId, superUser->id, "admin", wire, std::chrono::milliseconds(0));
                  }),
                  "mirror_switch_no_role");
        EXPECT_EQ(std::count(wire.sent.begin(), wire.sent.end(), "peer.mirror.switch.request"), 0);
        expectNothingChanged(s, at, digest, "refused on the mirror");

        // With the person's word it goes ahead, and the answer says the old core holds no role.
        const auto accepted = onCore(s, [&] {
            return sw::begin(s.coreId, {.on = "core", .by = mq::Account{.node = coreNode, .id = superUser->id},
                                        .name = "admin"},
                             wire, true);
        });
        drive(s, accepted.id, wire);
        expectSwitched(s, digest, "accepted with no role");
        const auto done = onCore(s, [&] { return sw::outcome(s.coreId, accepted.switch_id, "core"); });
        EXPECT_EQ(done.value("outcome", ""), "switched");
        EXPECT_TRUE(done.at("peer_role").is_null());
        EXPECT_EQ(done.value("peer_access", ""), "none");
        EXPECT_TRUE(done.at("detail").value("accepted_no_access", false));
    }
    {
        SCOPED_TRACE("no policy, asked on the mirror with the person's word");
        auto s = settledPair();
        Wire follow(s);
        SwitchWire wire(s, follow);
        policy(std::nullopt);
        const auto digest = mirrorRow(s).digest;
        const auto asked = sw::request(s.mirrorId, superUser->id, "admin", wire, std::chrono::milliseconds(0), true);
        const auto onTheCore = onCore(s, [&] { return mq::Switches::bySwitchId(asked.value("switch_id", ""), "core"); });
        ASSERT_TRUE(onTheCore);
        EXPECT_TRUE(onTheCore->accept_no_access) << "carried in peer.mirror.switch.request";
        drive(s, onTheCore->id, wire);
        expectSwitched(s, digest, "accepted, asked on the mirror");
        EXPECT_EQ(sw::outcome(s.mirrorId, asked.value("switch_id", ""), "mirror").value("peer_access", ""), "none");
    }
    {
        SCOPED_TRACE("a link default: the answer names it");
        policy("power_user");
        auto s = settledPair();
        Wire follow(s);
        SwitchWire wire(s, follow);
        const auto begun = beginOnCore(s, wire);
        drive(s, begun.id, wire);
        const auto answer = onCore(s, [&] { return sw::outcome(s.coreId, begun.switch_id, "core"); });
        EXPECT_EQ(answer.value("outcome", ""), "switched");
        EXPECT_EQ(answer.at("peer_role").value("role_name", ""), "power_user");
        EXPECT_EQ(answer.value("peer_access", ""), "read-write");
    }
    {
        SCOPED_TRACE("a per-vault role (set while the mirror was a core), no link default: the answer names it");
        auto s = settledPair();
        Wire follow(s);
        SwitchWire wire(s, follow);
        policy(std::nullopt);
        sql("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) SELECT " +
            std::to_string(s.mirrorId) + ", 'peer', " + std::to_string(corePeer) +
            ", id FROM vault_role WHERE name = 'reader'");
        const auto begun = beginOnCore(s, wire);
        drive(s, begun.id, wire);
        const auto answer = onCore(s, [&] { return sw::outcome(s.coreId, begun.switch_id, "core"); });
        EXPECT_EQ(answer.value("outcome", ""), "switched") << answer.dump();
        EXPECT_EQ(answer.at("peer_role").value("role_name", ""), "reader");
        EXPECT_EQ(answer.value("peer_access", ""), "read-only");
        const auto mine = sw::outcome(s.mirrorId, begun.switch_id, "mirror");
        EXPECT_EQ(mine.at("peer_role").value("role_name", ""), "reader") << "the new core says the same";
    }
}

// ---- who may ------------------------------------------------------------------------------------------------------------

TEST_F(MirrorSwitchDbTest, OnlyASuperAdminPersonMaySwitchNeverAnAgentOrARelayedDevice) {
    auto s = settledPair();
    const auto name = "msw_user_" + msTag();
    const auto plain = test::identities::createUser(name, db::query::rbac::role::Admin::get("unprivileged"),
                                                    name + "@vaulthalla.test");
    EXPECT_THROW((void)ops::mirrors::switchRole(plain, s.mirrorId), ops::Denied);
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        EXPECT_EQ(refusalOf([&] { (void)ops::mirrors::switchRole(superUser, s.mirrorId); }), "peer_forbidden");
    }
    auto p = std::make_shared<vh::device::Peer>();
    p->spki.fill(0x32);
    p->spkiHex = std::string(64, '3');
    p->address = "10.0.0.8";
    p->deviceRowId = 9;
    p->relayed = true;
    const auto relayed = protocols::ws::Session::devicePrincipal(std::move(p), superUser, [] {});
    {
        const auth::stepup::Scope scope(relayed);
        EXPECT_EQ(refusalOf([&] { (void)ops::mirrors::switchRole(superUser, s.mirrorId); }), "peer_forbidden");
    }
    relayed->close();
    EXPECT_EQ(mirrorRow(s).state, "live") << "nothing changed";
    EXPECT_FALSE(mq::Switches::openOf(s.mirrorId));
}

}
