// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Relink (migration 171; design/peers/mirror.md "As built: relink"; mirror::relink), with the two servers of
// helpers/mirror_pair.hpp. Every request between them is served live on the other server's turn (RelinkWire), so the
// follower, the submits, the resync and the relink's own wire all meet the real other side.
//
// Covered: the comparison by entry uid (only here, only there, changed here, there, on both, with the bases kept when
// the mirror ended), the paths and the counts; the hard override in each direction from each starting state
// (detached, orphaned, forked), ending with both servers live, equal digests, and what the losing side had kept as
// held changes; a step-through plan mixing all three choices (the future mirror's versions brought onto the core as its
// changes, a conflict copy, the core's version kept) ending equal with nothing lost; the invalidated plan; the
// refusals (a live mirror pair, keys that differ, a wrong name, no relationship); who may (super admins, people only)
// and the console's keys step-up.

#include "../helpers/mirror_pair.hpp"

#include "../helpers/identities.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/stepup/StepUp.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/mirror/Detach.hpp"
#include "db/query/mirror/Relink.hpp"
#include "db/query/mirror/Rejoin.hpp"
#include "db/query/mirror/Switch.hpp"
#include "db/query/mirror/Takeover.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Peer.hpp"
#include "fs/tree_apply/TreeApply.hpp"
#include "mirror/leave/Leave.hpp"
#include "mirror/relink/Relink.hpp"
#include "mirror/switching/Switch.hpp"
#include "mirror/takeover/Takeover.hpp"
#include "ops/PeerPolicy.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"

#include <vl/keykit/uid.hpp>

#include <filesystem>

namespace vh::test_mirror_relink {

using namespace vh::test_mirror_pair;   // the fixture and its aliases (json, mq, mf, ap, ms)
namespace rl = vh::mirror::relink;
namespace sw = vh::mirror::switching;
namespace tk = vh::mirror::takeover;

class MirrorRelinkDbTest : public MirrorPairDb {
protected:
    static void SetUpTestSuite() {
        setUpPair("test_mirror_relink");
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
        vh::mirror::access::linkChanged(corePeer, true);
        rl::resetForTesting();
        sql("UPDATE peer SET revoked_at = NULL WHERE id IN (" + std::to_string(mirrorPeer) + ", " +
            std::to_string(corePeer) + ")");
        sql("UPDATE mirror_switch SET notify = FALSE, phase = CASE WHEN ended_at IS NULL THEN 'abandoned' ELSE phase END, "
            "  ended_at = COALESCE(ended_at, CURRENT_TIMESTAMP) WHERE ended_at IS NULL OR notify");
        sql("UPDATE mirror_takeover SET settled_at = CURRENT_TIMESTAMP, settled_how = 'ended' WHERE settled_at IS NULL");
        sql("UPDATE mirror_rejoin SET phase = 'resynced' WHERE phase IN ('draining', 'rejoining', 'forked')");
        sql("UPDATE mirror_relink SET phase = 'cancelled' WHERE phase IN ('open', 'prepared', 'bring', 'copying')");
        // Either server may become the other's core: each holds a role on the vault there (its link's default).
        (void)ops::peer_policy::set(superUser, std::to_string(corePeer), ops::roles::Ref{std::string("power_user")});
        (void)ops::peer_policy::set(superUser, std::to_string(mirrorPeer), ops::roles::Ref{std::string("power_user")});
    }

    static void node(const std::string& id) { sql("UPDATE device_node SET node_id = '" + id + "' WHERE singleton"); }

    // The server holding `core` (the fixture's core vault) or the other, for the call; then back to whoever acted.
    template <class F>
    static auto on(Scenario& s, const bool core, F&& f) {
        const bool wasCore = s.coreActive;
        if (core) {
            toCore(s);
            node(coreNode);
        } else {
            toMirror(s);
            node(ownNode);
        }
        struct Back {
            Scenario& s;
            bool wasCore;
            ~Back() {
                if (wasCore) {
                    toCore(s);
                    node(coreNode);
                } else {
                    toMirror(s);
                    node(ownNode);
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

    // Every request served live by the server it names: corePeer is the fixture's core server (asked by the other as
    // mirrorPeer), mirrorPeer the other.
    class RelinkWire final : public mf::Transport {
    public:
        explicit RelinkWire(Scenario& s) : s_(s) {}
        bool up{true};
        std::set<std::string> drop;
        std::vector<std::string> asked;

        bool connected(uint32_t) override { return up; }
        std::optional<Answer> request(const uint32_t peer, const std::string& command, const json& payload) override {
            if (!up || drop.contains(command)) return std::nullopt;
            asked.push_back(command);
            const bool toCoreSide = peer == corePeer;
            const auto caller = toCoreSide ? mirrorPeer : corePeer;
            const auto serve = [&]() -> json {
                if (command == "peer.mirror.tree") return mf::serveTree(caller, payload);
                if (command == "peer.mirror.log") return mf::serveLog(caller, payload);
                if (command == "peer.mirror.ack") return mf::serveAck(caller, payload);
                if (command == "peer.mirror.submit") return ms::serveSubmit(caller, payload);
                if (command == "peer.mirror.resync") return vh::mirror::resync::serveResync(caller, payload);
                if (command == "peer.mirror.switch.prepare") return sw::servePrepare(caller, payload);
                if (command == "peer.mirror.switch.commit") return sw::serveCommit(caller, payload);
                if (command == "peer.mirror.switch.request") return sw::serveRequest(caller, payload);
                if (command == "peer.mirror.promoted") return tk::servePromoted(caller, payload);
                if (command == "peer.mirror.relink.state") return rl::serveState(caller, payload);
                if (command == "peer.mirror.relink.tree") return rl::serveTree(caller, payload);
                if (command == "peer.mirror.relink.prepare") return rl::servePrepare(caller, payload);
                if (command == "peer.mirror.relink.go") return rl::serveGo(caller, payload);
                if (command == "peer.mirror.relink.abort") return rl::serveAbort(caller, payload);
                throw ops::Invalid("unknown command " + command);
            };
            return on(s_, toCoreSide, [&] { return answerOf(serve); });
        }
        bool notify(uint32_t, const std::string&, const json&) override { return true; }
        Sent sendContent(const uint32_t peer, const Content& c) override {
            const bool toCoreSide = peer == corePeer;
            const auto target = toCoreSide ? s_.coreId : s_.mirrorId;
            return on(s_, toCoreSide, [&] {
                const auto received = ms::contents::receivingPath(target);
                std::filesystem::copy_file(c.path, received);
                const auto kept = ms::contents::keepVerified(
                    target, c.object_uid,
                    {.generation = c.generation, .key_version = c.key_version, .size = c.size,
                     .content_hash = c.content_hash},
                    received);
                if (!kept.ok) return Sent{.ok = false, .retry = false, .code = kept.code, .error = kept.error};
                return Sent{.ok = true};
            });
        }

    private:
        Scenario& s_;
    };

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

    // The same keys on both, as a mirror holds them: its key rows came from the core (vault_key_origin). In one
    // database the vaults' keys differ, so the core's check is what the mirror recorded as its origin's.
    static void sameKeys(Scenario& s) {
        const auto core = std::to_string(s.coreId);
        sql("UPDATE vault_keys SET key_check = '0123456789abcdef0123456789abcdef' WHERE vault_id = " + core +
            " AND key_check IS NULL");
        sql("INSERT INTO vault_key_origin (vault_id, version, origin_node_id, origin_vault_id, origin_key_check, "
            "  attestation_key_id, attestation_public_key, attestation, anchor) "
            "SELECT " + std::to_string(s.mirrorId) + ", k.version, '" + coreNode + "', " + core + ", k.key_check, 1, "
            "  decode(repeat('00', 32), 'hex'), decode(repeat('00', 64), 'hex'), 'peer' "
            "FROM vault_keys k WHERE k.vault_id = " + core +
            " ON CONFLICT (vault_id, version) DO UPDATE SET origin_key_check = EXCLUDED.origin_key_check");
    }

    // Follows on `core`'s side (the server now holding the vault as a mirror) until it has nothing more.
    static void follow(Scenario& s, const bool core, RelinkWire& wire) {
        const auto vaultId = core ? s.coreId : s.mirrorId;
        on(s, core, [&] {
            for (int i = 0; i < 300; ++i) {
                (void)rl::tick(wire);
                const auto r = mf::Follower::instance()->step(vaultId, wire);
                if (r.step == mf::Step::Idle || r.step == mf::Step::Gone) break;
                EXPECT_TRUE(r.step == mf::Step::Progress || r.step == mf::Step::CopyFinished ||
                            r.step == mf::Step::Stopped || r.step == mf::Step::Waiting)
                    << mf::toString(r.step) << " " << r.detail;
                if (r.step == mf::Step::Stopped) {
                    const auto mv = mq::MirrorVaults::get(vaultId);
                    if (!mv || mv->stop_reason.value_or("") != "mirror_relinking") break;
                }
            }
            (void)rl::tick(wire);
            return 0;
        });
        // The core's side learns its pair completed too.
        on(s, !core, [&] { return rl::tick(wire); });
    }

    static mq::MirrorVault rowOf(Scenario& s, const bool core) {
        return on(s, core, [&] { return mq::MirrorVaults::get(core ? s.coreId : s.mirrorId).value_or(mq::MirrorVault{}); });
    }

    static vh::mirror::Digest treeDigest(Scenario& s, const bool core) {
        return on(s, core, [&] { return mq::Digests::recompute(core ? s.coreId : s.mirrorId); });
    }

    static std::vector<mq::HeldChange> heldOn(Scenario& s, const bool core) {
        return on(s, core, [&] { return mq::Pending::heldChanges(core ? s.coreId : s.mirrorId); });
    }

    static std::string uidAt(Scenario& s, const bool core, const std::string& path) {
        return on(s, core, [&] { return uidOf(core ? s.coreId : s.mirrorId, path); });
    }

    static std::string pathOfUid(Scenario& s, const bool core, const std::string& uid) {
        return on(s, core, [&] {
            const auto at = vh::fs::tree_apply::locate(core ? s.coreId : s.mirrorId, uid);
            return at ? (at->trashed ? "trash:" : "") + at->path : std::string{};
        });
    }

    // Both servers live, the pair's digests equal, each side's relink done.
    static void expectRelinked(Scenario& s, const bool coreIsCoreSide) {
        const auto core = rowOf(s, coreIsCoreSide);
        const auto mirror = rowOf(s, !coreIsCoreSide);
        EXPECT_EQ(core.role, "core");
        EXPECT_EQ(core.state, "live") << core.stop_detail.dump();
        EXPECT_EQ(mirror.role, "mirror");
        EXPECT_EQ(mirror.state, "live") << mirror.stop_reason.value_or("") << " " << mirror.stop_detail.dump();
        EXPECT_TRUE(mirror.copy_finished);
        EXPECT_TRUE(core.acked) << "the mirror acknowledged the core's baseline with an equal digest";
        EXPECT_EQ(treeDigest(s, coreIsCoreSide), treeDigest(s, !coreIsCoreSide)) << "both trees are the same";
        EXPECT_EQ(mirror.digest, treeDigest(s, !coreIsCoreSide));
        for (const bool side : {true, false}) {
            const auto r = on(s, side, [&] { return mq::Relinks::latestOf(side ? s.coreId : s.mirrorId); });
            ASSERT_TRUE(r);
            EXPECT_EQ(r->phase, "done") << (side ? "core side: " : "other side: ") << r->error.value_or("");
        }
    }

    static void followPair(Scenario& s, RelinkWire& wire) {
        for (int i = 0; i < 200; ++i) {
            const auto r = mf::Follower::instance()->step(s.mirrorId, wire);
            if (r.step == mf::Step::Idle) break;
            ASSERT_TRUE(r.step == mf::Step::Progress || r.step == mf::Step::CopyFinished)
                << mf::toString(r.step) << " " << r.detail;
        }
        ASSERT_TRUE(mirrorRow(s).copy_finished);
    }

    // The fixture's pair, its first copy applied and acknowledged for real, the keys the same.
    static Scenario pair() {
        auto s = begin([](const EnginePtr& e) {
            e->mkdir("/docs", superUser);
            for (const auto* n : {"a", "b", "c", "d", "e"})
                write(e, std::string("/docs/") + n + ".txt", std::string("file ") + n);
        });
        RelinkWire wire(s);
        followPair(s, wire);
        receiveAll(s);
        sameKeys(s);
        return s;
    }

    static std::string wireUid(const Scenario& s) { return vl::keykit::toBase32(crypto::id::fromUuid(s.vaultUid)); }

    // The mirror detaches its copy; the core is told: both hold the vault, standalone, with the base each agreed.
    static void detachBoth(Scenario& s) {
        on(s, false, [&] { return vh::mirror::leave::detach(s.mirrorId, superUser->id, superUser->id, "admin"); });
        const auto mirrorPeerRecord = *db::query::peer::Peers::byId(mirrorPeer);
        on(s, true, [&] {
            return vh::mirror::leave::detachedReceived(mirrorPeerRecord, {{"vault_uid", wireUid(s)},
                                                                         {"at", {{"term", 1}, {"seq", 0}}},
                                                                         {"missing", 0}});
        });
        EXPECT_FALSE(rowOf(s, true).vault_id) << "the core's side ended";
        EXPECT_FALSE(rowOf(s, false).vault_id) << "the copy is standalone";
    }

    // The core ends the mirror, the copy kept (orphaned): only the core's side can change since.
    static void orphanCopy(Scenario& s) {
        on(s, true, [&] { return vh::mirror::start::cancelOnCore(s.coreId, "cancelled", false, false, superUser->id, "admin"); });
        on(s, false, [&] {
            EXPECT_TRUE(mq::MirrorVaults::orphan(s.mirrorId));
            (void)ms::orphaned(s.mirrorId);
            return 0;
        });
        EXPECT_EQ(rowOf(s, false).role, "orphaned");
    }

    // Both servers took over (a switch decided and never told, then cut off): forked, read-only on both.
    static void forkBoth(Scenario& s, RelinkWire& wire) {
        const auto begun = on(s, true, [&] {
            return sw::begin(s.coreId, {.on = "core", .by = mq::Account{.node = coreNode, .id = superUser->id},
                                        .name = "admin"},
                             wire);
        });
        wire.drop.insert("peer.mirror.switch.commit");
        (void)on(s, true, [&] { return sw::advance(begun.id, wire); });
        Down down;
        vh::mirror::access::linkChanged(corePeer, false);
        vh::mirror::access::linkChanged(mirrorPeer, false);
        on(s, false, [&] { return tk::take(s.mirrorId, s.mirror->vault->name, superUser->id, "admin", down); });
        on(s, true, [&] { return tk::take(s.coreId, s.core->vault->name, superUser->id, "admin", down); });
        vh::mirror::access::linkChanged(corePeer, true);
        vh::mirror::access::linkChanged(mirrorPeer, true);
        wire.drop.clear();
        (void)on(s, false, [&] { return tk::tick(wire); });
        (void)on(s, true, [&] { return tk::tick(wire); });
        ASSERT_EQ(rowOf(s, false).state, "forked");
        ASSERT_EQ(rowOf(s, true).state, "forked");
    }

    // The relink, started on `here` (true: the fixture's core server) keeping `keep`'s tree.
    static json overrideFrom(Scenario& s, const bool here, const std::string& keep, RelinkWire& wire) {
        const auto vaultId = here ? s.coreId : s.mirrorId;
        const auto peer = here ? mirrorPeer : corePeer;
        const auto name = here ? s.core->vault->name : s.mirror->vault->name;
        return on(s, here, [&] {
            return rl::override(vaultId, peer, keep, name, {.id = superUser->id, .name = "admin"}, wire);
        });
    }

    static uint64_t count(const json& status, const char* kind) {
        return status.at("counts").value(kind, uint64_t{0});
    }
};

// ---- compare ---------------------------------------------------------------------------------------------------------------

// After a detach both servers changed the vault. The comparison names every drifted entry by uid with its path, and
// tells which side changed it from the bases both kept when the mirror ended; nothing is changed by it.
TEST_F(MirrorRelinkDbTest, CompareReportsWhatDriftedOnWhichSideByUidWithPaths) {
    auto s = pair();
    RelinkWire wire(s);
    detachBoth(s);
    on(s, false, [&] {
        write(s.mirror, "/docs/only-here.txt", "made on the detached copy");
        write(s.mirror, "/docs/a.txt", "changed on the detached copy");
        return 0;
    });
    on(s, true, [&] {
        write(s.core, "/docs/only-there.txt", "made on the old core");
        write(s.core, "/docs/b.txt", "changed on the old core");
        write(s.core, "/docs/c.txt", "changed on the old core too");
        return 0;
    });
    on(s, false, [&] {
        write(s.mirror, "/docs/c.txt", "and on the copy");
        return 0;
    });
    const auto before = treeDigest(s, false);
    const auto st = on(s, false, [&] { return rl::compare(s.mirrorId, corePeer, {.id = superUser->id, .name = "admin"}, wire); });
    EXPECT_EQ(st.at("this").value("status", ""), "detached");
    EXPECT_EQ(st.at("theirs").value("status", ""), "detached");
    EXPECT_TRUE(st.at("base").value("both", false)) << st.at("base").dump();
    EXPECT_EQ(count(st, "only_this"), 1u) << st.at("counts").dump();
    EXPECT_EQ(count(st, "only_theirs"), 1u);
    EXPECT_EQ(count(st, "changed_this"), 1u);
    EXPECT_EQ(count(st, "changed_theirs"), 1u);
    EXPECT_EQ(count(st, "changed_both"), 1u);
    EXPECT_EQ(count(st, "differs"), 0u);
    EXPECT_EQ(count(st, "total"), 5u);
    EXPECT_TRUE(st.at("keys").value("match", false)) << st.at("keys").dump();
    EXPECT_TRUE(st.at("blockers").empty()) << st.at("blockers").dump();
    // The list, by path; a kind narrows it.
    const auto page = on(s, false, [&] { return rl::entries(s.mirrorId, "", 0, 100); });
    std::map<std::string, std::string> kinds;
    for (const auto& e : page.at("entries")) kinds[e.value("path", "")] = e.value("kind", "");
    EXPECT_EQ(kinds["/docs/only-here.txt"], "only_this");
    EXPECT_EQ(kinds["/docs/only-there.txt"], "only_theirs");
    EXPECT_EQ(kinds["/docs/a.txt"], "changed_this");
    EXPECT_EQ(kinds["/docs/b.txt"], "changed_theirs");
    EXPECT_EQ(kinds["/docs/c.txt"], "changed_both");
    const auto narrowed = on(s, false, [&] { return rl::entries(s.mirrorId, "only_theirs", 0, 100); });
    ASSERT_EQ(narrowed.value("total", 0), 1);
    const auto& e = narrowed.at("entries")[0];
    EXPECT_TRUE(e.at("this").is_null());
    EXPECT_EQ(e.at("theirs").value("path", ""), "/docs/only-there.txt");
    EXPECT_NE(std::ranges::find(e.at("aspects"), json("created")), e.at("aspects").end()) << e.dump();
    EXPECT_EQ(e.value("resolution", ""), "core") << "the default: the core's (this server's) version";
    EXPECT_EQ(treeDigest(s, false), before) << "comparing changes nothing";
    EXPECT_FALSE(rowOf(s, false).vault_id);
}

// ---- the hard override, each direction, from each starting state -----------------------------------------------------------

// Detached, run on the copy, keeping its tree: it becomes the core, the old core its mirror; what the old core had that
// differs is kept there as held changes, with its bytes; both end live with equal digests; the detach records settle.
TEST_F(MirrorRelinkDbTest, ADetachedPairRelinksKeepingThisServersTree) {
    auto s = pair();
    RelinkWire wire(s);
    detachBoth(s);
    on(s, false, [&] { write(s.mirror, "/docs/copy-only.txt", "copy"); return 0; });
    on(s, true, [&] {
        write(s.core, "/docs/old-core-only.txt", "old core");
        write(s.core, "/docs/a.txt", "the old core's version of a");
        return 0;
    });
    const auto aUid = uidAt(s, true, "/docs/a.txt");
    const auto extraUid = uidAt(s, true, "/docs/old-core-only.txt");
    const auto st = overrideFrom(s, false, "this", wire);
    EXPECT_EQ(st.at("relink").value("role", ""), "core");
    follow(s, true, wire);
    expectRelinked(s, false);
    EXPECT_FALSE(uidAt(s, true, "/docs/copy-only.txt").empty()) << "the old core took the copy's entry";
    EXPECT_TRUE(uidAt(s, true, "/docs/old-core-only.txt").empty()) << "its own entry left its tree";
    const auto held = heldOn(s, true);
    const auto keeps = [&](const std::string& uid) {
        return std::ranges::any_of(held, [&](const mq::HeldChange& h) { return h.entry_uid.value_or("") == uid && h.op == "write"; });
    };
    EXPECT_TRUE(keeps(aUid)) << "its version of a.txt is kept";
    EXPECT_TRUE(keeps(extraUid)) << "and the file only it had";
    for (const auto& h : held) {
        if (h.op != "write") continue;
        EXPECT_TRUE(std::filesystem::exists(ms::contents::heldBlob(s.coreId, h.id))) << "with its bytes: " << h.path.value_or("");
    }
    for (const bool side : {true, false})
        EXPECT_FALSE(on(s, side, [&] { return mq::MirrorDetach::forVault(side ? s.coreId : s.mirrorId); }))
            << "the detach records settled";
}

// Detached, run on the copy, keeping the other's tree: the old core is the core again, the copy its mirror.
TEST_F(MirrorRelinkDbTest, ADetachedPairRelinksKeepingTheOtherServersTree) {
    auto s = pair();
    RelinkWire wire(s);
    detachBoth(s);
    on(s, false, [&] { write(s.mirror, "/docs/copy-only.txt", "copy"); return 0; });
    on(s, true, [&] { write(s.core, "/docs/old-core-only.txt", "old core"); return 0; });
    const auto extraUid = uidAt(s, false, "/docs/copy-only.txt");
    (void)overrideFrom(s, false, "theirs", wire);
    follow(s, false, wire);
    expectRelinked(s, true);
    EXPECT_FALSE(uidAt(s, false, "/docs/old-core-only.txt").empty());
    EXPECT_TRUE(std::ranges::any_of(heldOn(s, false), [&](const mq::HeldChange& h) {
        return h.entry_uid.value_or("") == extraUid;
    })) << "the copy's own file is kept as a held change";
}

// Orphaned (the core ended the mirror, the copy kept read-only), run on the old core keeping its tree, then the other
// way on a second pair: the copy's tree wins.
TEST_F(MirrorRelinkDbTest, AnOrphanedCopyRelinksInEitherDirection) {
    {
        auto s = pair();
        RelinkWire wire(s);
        orphanCopy(s);
        on(s, true, [&] { write(s.core, "/docs/after-the-end.txt", "core"); return 0; });
        const auto st = overrideFrom(s, true, "this", wire);
        EXPECT_EQ(st.at("theirs").value("status", ""), "orphaned");
        follow(s, false, wire);
        expectRelinked(s, true);
        EXPECT_FALSE(uidAt(s, false, "/docs/after-the-end.txt").empty());
    }
    {
        auto s = pair();
        RelinkWire wire(s);
        orphanCopy(s);
        on(s, true, [&] { write(s.core, "/docs/after-the-end.txt", "core"); return 0; });
        const auto uid = uidAt(s, true, "/docs/after-the-end.txt");
        (void)overrideFrom(s, true, "theirs", wire);
        follow(s, true, wire);
        expectRelinked(s, false);
        EXPECT_TRUE(uidAt(s, true, "/docs/after-the-end.txt").empty());
        EXPECT_TRUE(std::ranges::any_of(heldOn(s, true), [&](const mq::HeldChange& h) {
            return h.entry_uid.value_or("") == uid;
        })) << "the old core's later file is kept as a held change";
    }
}

// Forked (both took over), each direction: the take overs and rejoins settle 'relinked'.
TEST_F(MirrorRelinkDbTest, AForkedPairRelinksInEitherDirection) {
    for (const bool keepCoreSide : {true, false}) {
        auto s = pair();
        RelinkWire wire(s);
        forkBoth(s, wire);
        const auto st = overrideFrom(s, false, keepCoreSide ? "theirs" : "this", wire);
        EXPECT_EQ(st.at("this").value("status", ""), "forked");
        follow(s, !keepCoreSide, wire);
        expectRelinked(s, keepCoreSide);
        for (const bool side : {true, false}) {
            const auto id = side ? s.coreId : s.mirrorId;
            const auto t = on(s, side, [&] { return mq::Takeovers::latestOf(id); });
            ASSERT_TRUE(t);
            EXPECT_EQ(t->settled_how.value_or(""), "relinked");
            const auto rejoin = on(s, side, [&] { return mq::Rejoins::latestOf(id); });
            if (rejoin) {
                EXPECT_EQ(rejoin->phase, "relinked");
            }
            EXPECT_FALSE(on(s, side, [&] { return mq::Rejoins::openOf(id); }));
        }
        EXPECT_GT(rowOf(s, keepCoreSide).term, 3u) << "a term above any either used";
    }
}

// ---- the step-through ------------------------------------------------------------------------------------------------------

// A plan mixing every choice, run on the copy, which stays the core: the old core's versions chosen are brought onto it
// as the old core's changes (a file only it had, its contents of a file both changed, a removal), a file changed on the
// old core keeps both (its version a conflict copy beside the core's), a rename keeps the core's place (the old core's
// kept as a held place), and an entry only the core has reaches the old core. Both end equal; nothing is lost.
TEST_F(MirrorRelinkDbTest, AStepThroughPlanMixingEveryChoiceEndsEqualWithNothingLost) {
    auto s = pair();
    RelinkWire wire(s);
    detachBoth(s);
    on(s, false, [&] {
        write(s.mirror, "/docs/core-only.txt", "the core's own");
        write(s.mirror, "/docs/a.txt", "a on the core");
        return 0;
    });
    on(s, true, [&] {
        write(s.core, "/docs/brought.txt", "made on the old core");
        write(s.core, "/docs/a.txt", "a on the old core");
        write(s.core, "/docs/b.txt", "b on the old core");
        ops::fs::rename(superUser, s.coreId, "/docs/c.txt", "/docs/c-renamed.txt");
        ops::fs::remove(superUser, s.coreId, "/docs/d.txt");
        return 0;
    });
    const auto uid = [&](const std::string& p) { return uidAt(s, false, p).empty() ? uidAt(s, true, p) : uidAt(s, false, p); };
    const auto brought = uidAt(s, true, "/docs/brought.txt");
    const auto a = uid("/docs/a.txt"), b = uid("/docs/b.txt"), c = uid("/docs/c.txt"), d = uid("/docs/d.txt");
    const auto coreOnly = uidAt(s, false, "/docs/core-only.txt");
    const rl::Who admin{.id = superUser->id, .name = "admin"};
    auto st = on(s, false, [&] { return rl::compare(s.mirrorId, corePeer, admin, wire); });
    ASSERT_TRUE(st.at("blockers").empty()) << st.at("blockers").dump();
    rl::PlanEdit edit;
    edit.set = {{.uid = brought, .choice = "theirs"}, {.uid = a, .choice = "theirs"}, {.uid = b, .choice = "both"},
                {.uid = c, .choice = "this"}, {.uid = d, .choice = "theirs"}};
    st = on(s, false, [&] { return rl::plan(s.mirrorId, edit); });
    EXPECT_EQ(st.at("plan").at("chosen").value("mirror", 0), 3) << st.at("plan").dump();
    EXPECT_EQ(st.at("plan").at("chosen").value("both", 0), 1);
    EXPECT_EQ(st.at("plan").at("this").value("conflict_copies", 0), 1);
    // A folder keeps one place or the other.
    rl::PlanEdit folder;
    folder.set = {{.uid = uid("/docs"), .choice = "both"}};
    EXPECT_NE(refusalOf([&] { (void)on(s, false, [&] { return rl::plan(s.mirrorId, folder); }); }), "not refused");

    st = on(s, false, [&] { return rl::apply(s.mirrorId, s.mirror->vault->name, admin, wire); });
    EXPECT_EQ(st.at("relink").value("phase", ""), "copying");
    follow(s, true, wire);
    expectRelinked(s, false);

    // The core holds the old core's choices, as the old core's changes.
    EXPECT_EQ(pathOfUid(s, false, brought), "/docs/brought.txt");
    EXPECT_EQ(pathOfUid(s, false, d).rfind("trash:", 0), 0u) << "the removal brought over: in the core's trash";
    EXPECT_EQ(pathOfUid(s, false, c), "/docs/c.txt") << "the core's place kept";
    const auto copyName = ms::conflictName("b.txt", b, false);
    EXPECT_FALSE(uidAt(s, false, "/docs/" + copyName).empty()) << "the conflict copy beside the core's b.txt";
    EXPECT_FALSE(uidAt(s, true, "/docs/" + copyName).empty()) << "on both servers";
    EXPECT_EQ(pathOfUid(s, true, coreOnly), "/docs/core-only.txt") << "the core's own entry reached the old core";
    // Nothing lost: the core's replaced a.txt and the old core's place for c are held changes.
    const auto coreHeld = heldOn(s, false);
    EXPECT_TRUE(std::ranges::any_of(coreHeld, [&](const mq::HeldChange& h) {
        return h.entry_uid.value_or("") == a && h.op == "write" && h.reason_code == "mirror_relink_replaced";
    })) << "the core's own a.txt is kept";
    const auto oldHeld = heldOn(s, true);
    EXPECT_TRUE(std::ranges::any_of(oldHeld, [&](const mq::HeldChange& h) {
        return h.entry_uid.value_or("") == c && h.op == "move";
    })) << "the old core's name for c is kept";
    const auto relink = on(s, true, [&] { return mq::Relinks::latestOf(s.coreId); });
    ASSERT_TRUE(relink);
    EXPECT_EQ(on(s, true, [&] { return mq::Relinks::entry(relink->id, brought)->outcome.value_or(""); }), "executed");
}

// ---- the invalidated plan and the refusals ---------------------------------------------------------------------------------

TEST_F(MirrorRelinkDbTest, APlanIsInvalidatedWhenEitherTreeChangesUnderIt) {
    auto s = pair();
    RelinkWire wire(s);
    detachBoth(s);
    const rl::Who admin{.id = superUser->id, .name = "admin"};
    (void)on(s, false, [&] { return rl::compare(s.mirrorId, corePeer, admin, wire); });
    on(s, true, [&] { write(s.core, "/docs/late.txt", "after the comparison"); return 0; });
    EXPECT_EQ(refusalOf([&] { (void)on(s, false, [&] { return rl::apply(s.mirrorId, s.mirror->vault->name, admin, wire); }); }),
              "mirror_relink_stale");
    const auto st = on(s, false, [&] { return rl::status(s.mirrorId); });
    EXPECT_EQ(st.at("relink").value("phase", ""), "stale");
    EXPECT_NE(st.at("relink").value("error", "").find("compare again"), std::string::npos);
    EXPECT_FALSE(rowOf(s, false).vault_id) << "nothing changed";
    EXPECT_FALSE(rowOf(s, true).vault_id);
    // Compared again, it goes.
    (void)on(s, false, [&] { return rl::compare(s.mirrorId, corePeer, admin, wire); });
    (void)on(s, false, [&] { return rl::apply(s.mirrorId, s.mirror->vault->name, admin, wire); });
    follow(s, true, wire);
    expectRelinked(s, false);
}

TEST_F(MirrorRelinkDbTest, RefusedForALivePairKeysThatDifferAWrongNameOrAVaultNeverMirroredWithThatServer) {
    const rl::Who admin{.id = superUser->id, .name = "admin"};
    {
        auto s = pair();
        RelinkWire wire(s);
        const auto st = on(s, false, [&] { return rl::compare(s.mirrorId, corePeer, admin, wire); });
        ASSERT_FALSE(st.at("blockers").empty());
        EXPECT_EQ(st.at("blockers")[0].value("code", ""), "mirror_relink_mirrored");
        EXPECT_EQ(refusalOf([&] { (void)overrideFrom(s, false, "this", wire); }), "mirror_relink_mirrored");
        EXPECT_EQ(mirrorRow(s).role, "mirror") << "the live pair is untouched";
        detachBoth(s);
        EXPECT_EQ(refusalOf([&] {
                      (void)on(s, false, [&] { return rl::override(s.mirrorId, corePeer, "this", "wrong", admin, wire); });
                  }),
                  "mirror_name_mismatch");
        // The keys rotated on one side since: refused, nothing moves.
        sql("UPDATE vault_key_origin SET origin_key_check = repeat('f', 32) WHERE vault_id = " + std::to_string(s.mirrorId));
        EXPECT_EQ(refusalOf([&] { (void)overrideFrom(s, false, "this", wire); }), "mirror_relink_keys");
        EXPECT_FALSE(rowOf(s, false).vault_id);
    }
    {
        // A vault with the same uid on the other server that was never mirrored with this one... here: a vault this
        // server never mirrored at all.
        auto s = pair();
        RelinkWire wire(s);
        const auto other = localVault("mr_plain_");
        EXPECT_EQ(refusalOf([&] { (void)rl::compare(vid(other), corePeer, admin, wire); }), "mirror_relink_unrelated");
    }
}

// ---- who may ---------------------------------------------------------------------------------------------------------------

TEST_F(MirrorRelinkDbTest, OnlyASuperAdminPersonMayRelinkAndTheConsoleStepsUpBoundToTheVault) {
    auto s = pair();
    detachBoth(s);
    const auto name = "mr_user_" + msTag();
    const auto plain = test::identities::createUser(name, db::query::rbac::role::Admin::get("unprivileged"),
                                                    name + "@vaulthalla.test");
    const auto peerRef = std::to_string(corePeer);
    EXPECT_THROW((void)ops::mirrors::relinkCompare(plain, s.mirrorId, peerRef), ops::Denied);
    EXPECT_THROW((void)ops::mirrors::relinkApply(plain, s.mirrorId, s.mirror->vault->name, "this", peerRef), ops::Denied);
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        EXPECT_EQ(refusalOf([&] { (void)ops::mirrors::relinkCompare(superUser, s.mirrorId, peerRef); }), "peer_forbidden");
        EXPECT_EQ(refusalOf([&] { (void)ops::mirrors::relinkStatus(superUser, s.mirrorId); }), "peer_forbidden");
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
        EXPECT_EQ(refusalOf([&] {
                      (void)ops::mirrors::relinkApply(superUser, s.mirrorId, s.mirror->vault->name, "this", peerRef);
                  }),
                  "peer_forbidden");
    }
    relayed->close();
    // The console: the keys step-up, bound to the vault, before anything changes.
    auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = superUser;
    web->tokens->refreshToken = std::make_shared<auth::model::RefreshToken>();
    web->tokens->refreshToken->jti = "relink-stepup-jti-" + msTag();
    web->tokens->refreshToken->aal = 1;
    web->tokens->refreshToken->amr = {"pwd"};
    web->tokens->refreshToken->authTime = std::chrono::system_clock::now() - std::chrono::hours(1);
    const auth::stepup::Scope scope(web);
    try {
        (void)ops::mirrors::relinkApply(superUser, s.mirrorId, s.mirror->vault->name, "this", peerRef);
        ADD_FAILURE() << "relinked without the step-up";
    } catch (const ops::StepUpRequired& e) {
        EXPECT_EQ(e.family, "keys");
        EXPECT_EQ(e.target.value_or(""), "mirror.relink:" + std::to_string(s.mirrorId));
    }
    EXPECT_FALSE(rowOf(s, false).vault_id) << "nothing changed without the step-up";
}

}
