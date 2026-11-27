// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// A change made on the mirror (wave 4 piece B; migration 166; design/peers/mirror.md "As built: a change made on the
// mirror"; mirror::submit, db::query::mirror::Pending, the applier's confirmation). One database holds one vault of a
// given uid, and every entry uid once, so the two servers take turns: the side that is not acting is parked (its vault
// uid and every entry uid replaced, the originals kept in a table, triggers off) and unparked when it acts again. The
// core is this server under another node id (AsCore), so the mirror's people arrive there as remote accounts and the
// core's as remote accounts here. The follower drives everything through a transport that, for peer.mirror.submit,
// turns the core on, serves the request (drained inline), captures the log it wrote and turns the mirror back on; the
// log and the acknowledgements are answered from what was captured.
//
// Covered: each operation applied here at once as pending (the digest and the entry hashes unmoved), submitted,
// executed on the core as the person under the linked server's ceiling with the mirror's uid, logged with the request
// id in origin and the person as actor, audited with the peer, confirmed by the applier without a second apply (same
// entry row, digests equal, nothing left pending or dirty); an unrelated core change to a pending entry arriving first;
// the core's entry taking a name a pending folder holds (set aside, refused for the name, resubmitted under its conflict
// name); a refusal by the ceiling held with the entry back at the core's state; a repeated submit answered from the
// first time; pending rows surviving a restart and going in order; the gate refusing while the link is down; the wire's
// refusals.

#include "../helpers/db_suite.hpp"

#include "audit/Trail.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/Entry.hpp"
#include "fs/model/Entry.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Pending.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "identities/User.hpp"
#include "mirror/Hash.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/apply/Applier.hpp"
#include "mirror/follow/Follower.hpp"
#include "mirror/follow/Protocol.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/submit/Submit.hpp"
#include "mirror/versions/Versions.hpp"
#include "recovery/local/Versions.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"
#include "ops/MirrorLeave.hpp"
#include "ops/Mirrors.hpp"
#include "ops/Roles.hpp"
#include "ops/Vaults.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace vh::test_mirror_submit {

using json = nlohmann::json;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace mq = vh::db::query::mirror;
namespace mf = vh::mirror::follow;
namespace ap = vh::mirror::apply;
namespace ms = vh::mirror::submit;
using namespace std::chrono_literals;

std::string msTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "s" + std::to_string(n.fetch_add(1));
}

class MirrorSubmitDbTest : public vh::test::db::Suite {
protected:
    // The core's row for its mirror (node id: this server's own, as the mirror is) and the mirror's row for its core.
    inline static uint32_t mirrorPeer{};
    inline static uint32_t corePeer{};
    inline static std::string ownNode{};
    inline static std::string coreNode{};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_mirror_submit")) return;
        ownNode = vh::db::query::device::Devices::nodeId();
        coreNode = "core-node-" + msTag();
        for (auto* id : {&mirrorPeer, &corePeer}) {
            vh::db::query::peer::NewPeer p;
            p.node_id = id == &mirrorPeer ? ownNode : coreNode;
            p.name = id == &mirrorPeer ? "the mirror" : "the core";
            p.spki_sha256 = std::string(64, id == &mirrorPeer ? 'c' : 'd');
            p.wrap_public_key.fill(9);
            *id = vh::db::query::peer::Peers::insert(p).id;
        }
        ms::setInlineForTesting(true);
        ms::setPollPauseForTesting(0ms);
    }

    static void TearDownTestSuite() {
        if (!skipTests)
            for (const auto& m : mq::MirrorVaults::list()) (void)mq::MirrorVaults::remove(m.vault_id);
        ms::setInlineForTesting(false);
        ms::setPollPauseForTesting(100ms);
        vh::mirror::access::linkChanged(corePeer, false);
        setExperimental(false);
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        ownNode = vh::db::query::device::Devices::nodeId();
        setExperimental(true);
    }

    static void setExperimental(const bool on) {
        auto cfg = config::Registry::get();
        cfg.peers.experimental = on;
        config::Registry::set(cfg);
    }

    // ---- helpers

    static void sql(const std::string& statement) {
        db::Transactions::exec("ms sql", [&](pqxx::work& txn) { txn.exec(statement); });
    }
    template <class T>
    static T one(const std::string& statement) {
        return db::Transactions::exec("ms one", [&](pqxx::work& txn) { return txn.exec(statement).one_field().as<T>(); });
    }

    static EnginePtr localVault(const std::string& prefix) {
        const auto v = ops::vaults::create(superUser, {.name = prefix + msTag(), .type = vault::model::VaultType::Local});
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    static uint32_t vid(const EnginePtr& e) { return e->vault->id; }

    static void write(const EnginePtr& engine, const std::string& path, const std::string& content) {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    static uint32_t entryId(const uint32_t vaultId, const std::string& path) {
        return db::Transactions::exec("ms entry id", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = $2", pqxx::params{vaultId, path});
            return r.empty() ? 0u : r[0][0].as<uint32_t>();
        });
    }

    static std::string uidOf(const uint32_t vaultId, const std::string& path) {
        return db::Transactions::exec("ms uid", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT COALESCE(f.object_uid, d.uid, s.uid)::text FROM fs_entry e "
                                    "LEFT JOIN files f ON f.fs_entry_id = e.id LEFT JOIN directories d ON d.fs_entry_id = e.id "
                                    "LEFT JOIN symlinks s ON s.fs_entry_id = e.id WHERE e.vault_id = $1 AND e.path = $2",
                                    pqxx::params{vaultId, path});
            return r.empty() || r[0][0].is_null() ? std::string{} : r[0][0].as<std::string>();
        });
    }

    static std::set<std::string> pathsOf(const uint32_t vaultId) {
        return db::Transactions::exec("ms paths", [&](pqxx::work& txn) {
            std::set<std::string> out;
            for (const auto row : txn.exec("SELECT path FROM fs_entry WHERE vault_id = $1 AND path <> '/'",
                                           pqxx::params{vaultId}))
                out.insert(row[0].as<std::string>());
            return out;
        });
    }

    static mq::Grant grantOf(const rbac::role::Vault& role, const std::string& node) {
        return {.role_name = role.name, .files = role.fs.files.toMask(), .directories = role.fs.directories.toMask(),
                .sync = role.sync.toMask(), .roles = role.roles.toMask(), .granted_by_node = node, .granted_at = 0};
    }

    // ---- the two servers in one database

    // This server acts as the core: its node id is the core's, so the mirror's people are remote accounts here.
    struct AsCore {
        explicit AsCore() { sql("UPDATE device_node SET node_id = '" + coreNode + "' WHERE singleton"); }
        ~AsCore() { sql("UPDATE device_node SET node_id = '" + ownNode + "' WHERE singleton"); }
    };

    // A vault's uid and every entry uid out of the way (kept), triggers off: the other server's turn.
    static void park(const uint32_t vaultId) {
        db::Transactions::exec("ms park", [&](pqxx::work& txn) {
            txn.exec("CREATE TABLE IF NOT EXISTS ms_parked (vault_id INTEGER, kind TEXT, row_id BIGINT, uid UUID)");
            for (const auto* t : {"vault", "directories", "files", "symlinks", "files_trashed"})
                txn.exec(std::string("ALTER TABLE ") + t + " DISABLE TRIGGER USER");
            const pqxx::params v{vaultId};
            txn.exec("INSERT INTO ms_parked SELECT $1, 'd', d.fs_entry_id, d.uid FROM directories d "
                     "JOIN fs_entry e ON e.id = d.fs_entry_id WHERE e.vault_id = $1", v);
            txn.exec("UPDATE directories d SET uid = gen_random_uuid() FROM fs_entry e "
                     "WHERE e.id = d.fs_entry_id AND e.vault_id = $1", v);
            txn.exec("INSERT INTO ms_parked SELECT $1, 'f', f.fs_entry_id, f.object_uid FROM files f "
                     "JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1", v);
            txn.exec("UPDATE files f SET object_uid = gen_random_uuid() FROM fs_entry e "
                     "WHERE e.id = f.fs_entry_id AND e.vault_id = $1", v);
            txn.exec("INSERT INTO ms_parked SELECT $1, 's', s.fs_entry_id, s.uid FROM symlinks s "
                     "JOIN fs_entry e ON e.id = s.fs_entry_id WHERE e.vault_id = $1", v);
            txn.exec("UPDATE symlinks s SET uid = gen_random_uuid() FROM fs_entry e "
                     "WHERE e.id = s.fs_entry_id AND e.vault_id = $1", v);
            txn.exec("INSERT INTO ms_parked SELECT $1, 't', id, object_uid FROM files_trashed "
                     "WHERE vault_id = $1 AND object_uid IS NOT NULL", v);
            txn.exec("UPDATE files_trashed SET object_uid = gen_random_uuid() WHERE vault_id = $1 AND object_uid IS NOT NULL", v);
            txn.exec("INSERT INTO ms_parked SELECT $1, 'v', id, uid FROM vault WHERE id = $1", v);
            txn.exec("UPDATE vault SET uid = gen_random_uuid() WHERE id = $1", v);
            for (const auto* t : {"vault", "directories", "files", "symlinks", "files_trashed"})
                txn.exec(std::string("ALTER TABLE ") + t + " ENABLE TRIGGER USER");
        });
    }

    static void unpark(const uint32_t vaultId) {
        db::Transactions::exec("ms unpark", [&](pqxx::work& txn) {
            for (const auto* t : {"vault", "directories", "files", "symlinks", "files_trashed"})
                txn.exec(std::string("ALTER TABLE ") + t + " DISABLE TRIGGER USER");
            const pqxx::params v{vaultId};
            txn.exec("UPDATE directories d SET uid = p.uid FROM ms_parked p WHERE p.vault_id = $1 AND p.kind = 'd' "
                     "AND p.row_id = d.fs_entry_id", v);
            txn.exec("UPDATE files f SET object_uid = p.uid FROM ms_parked p WHERE p.vault_id = $1 AND p.kind = 'f' "
                     "AND p.row_id = f.fs_entry_id", v);
            txn.exec("UPDATE symlinks s SET uid = p.uid FROM ms_parked p WHERE p.vault_id = $1 AND p.kind = 's' "
                     "AND p.row_id = s.fs_entry_id", v);
            txn.exec("UPDATE files_trashed t SET object_uid = p.uid FROM ms_parked p WHERE p.vault_id = $1 AND p.kind = 't' "
                     "AND p.row_id = t.id", v);
            txn.exec("UPDATE vault t SET uid = p.uid FROM ms_parked p WHERE p.vault_id = $1 AND p.kind = 'v' AND p.row_id = t.id", v);
            txn.exec("DELETE FROM ms_parked WHERE vault_id = $1", v);
            for (const auto* t : {"vault", "directories", "files", "symlinks", "files_trashed"})
                txn.exec(std::string("ALTER TABLE ") + t + " ENABLE TRIGGER USER");
        });
    }

    struct Scenario {
        EnginePtr core;
        uint32_t coreId{};
        EnginePtr mirror;
        uint32_t mirrorId{};
        std::string vaultUid;
        std::map<std::string, json> answers;            // what the core answered, by request
        std::map<mq::Position, vh::mirror::Digest> digests;
        mq::Position at{1, 0};                          // the core's log position captured so far
        bool coreActive{true};
    };

    static std::string key(const std::string& command, const json& payload) { return command + " " + payload.dump(); }

    // ---- the turns

    static void toCore(Scenario& s) {
        if (s.coreActive) return;
        park(s.mirrorId);
        unpark(s.coreId);
        s.coreActive = true;
    }

    static void toMirror(Scenario& s) {
        if (!s.coreActive) return;
        park(s.coreId);
        unpark(s.mirrorId);
        s.coreActive = false;
    }

    // The core's log after what was captured, paged as the follower asks for it; each group's end's digest. The core
    // is active and this server acts as it.
    static void captureLog(Scenario& s) {
        (void)mq::Log::sequence(s.coreId);
        for (int guard = 0; guard < 10'000; ++guard) {
            const json payload{{"vault_uid", s.vaultUid}, {"term", s.at.term}, {"seq", s.at.seq}};
            const auto answer = mf::serveLog(mirrorPeer, payload);
            s.answers[key("peer.mirror.log", payload)] = answer;
            ASSERT_FALSE(answer.contains("part")) << "no group here is larger than an answer";
            const auto groups = answer.value("groups", json::array());
            for (const auto& g : groups) {
                const auto group = mf::groupFromJson(g);
                s.at = {group.term, group.last_seq};
                const auto d = mq::MirrorVaults::digestAt(s.coreId, s.at);
                ASSERT_TRUE(d);
                s.digests[s.at] = *d;
            }
            if (groups.empty() || !answer.value("more", false)) break;
        }
        // What the core answers at the position the mirror is at next (nothing new).
        const json peek{{"vault_uid", s.vaultUid}, {"term", s.at.term}, {"seq", s.at.seq}};
        s.answers[key("peer.mirror.log", peek)] = mf::serveLog(mirrorPeer, peek);
    }

    // A change on the core by its own person (another of the core's accounts would do as well), captured.
    static void coreChange(Scenario& s, const std::function<void(const EnginePtr&)>& change) {
        toCore(s);
        {
            AsCore as;
            change(s.core);
            captureLog(s);
        }
        toMirror(s);
    }

    // The two servers: the core built and started (its link's role for the mirror is `peerRole`), its baseline captured;
    // the mirror's vault made with the same uid and following, its first copy applied, its grant full, its link up.
    static Scenario begin(const std::function<void(const EnginePtr&)>& build, const std::string& peerRole = "power_user") {
        Scenario s;
        {
            AsCore as;
            s.core = localVault("ms_core_");
            s.coreId = vid(s.core);
            build(s.core);
            (void)mq::MirrorVaults::startCore(s.coreId, mirrorPeer);
            (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = s.coreId,
                                                                     .subject = {.type = "peer", .id = mirrorPeer}},
                                                          .role = peerRole});
            s.vaultUid = *mq::MirrorVaults::vaultUidOf(s.coreId);
            uint64_t after = 0;
            for (int guard = 0; guard < 1000; ++guard) {
                const json payload{{"vault_uid", s.vaultUid}, {"after", after}};
                const auto answer = mf::serveTree(mirrorPeer, payload);
                s.answers[key("peer.mirror.tree", payload)] = answer;
                if (!answer.at("items").empty()) after = answer.at("items").back().at("ord").get<uint64_t>();
                if (!answer.value("more", false)) break;
            }
            const auto mv = mq::MirrorVaults::get(s.coreId);
            s.at = *mv->baseline;
            s.digests[s.at] = *mv->baseline_digest;
            const json peek{{"vault_uid", s.vaultUid}, {"term", s.at.term}, {"seq", s.at.seq}};
            s.answers[key("peer.mirror.log", peek)] = mf::serveLog(mirrorPeer, peek);
        }
        park(s.coreId);
        s.coreActive = false;
        s.mirror = localVault("ms_mirror_");
        s.mirrorId = vid(s.mirror);
        db::Transactions::exec("ms mirror uid", [&](pqxx::work& txn) {
            txn.exec("ALTER TABLE vault DISABLE TRIGGER vh_uid_immutable");
            txn.exec("UPDATE vault SET uid = $2::uuid WHERE id = $1", pqxx::params{s.mirrorId, s.vaultUid});
            txn.exec("ALTER TABLE vault ENABLE TRIGGER vh_uid_immutable");
        });
        (void)mq::MirrorVaults::startMirror(s.mirrorId, corePeer);
        EXPECT_TRUE(mq::MirrorVaults::recordGrant(s.mirrorId, grantOf(rbac::role::Vault::Full(), coreNode)));
        vh::mirror::access::linkChanged(corePeer, true);
        return s;
    }

    // The core as the follower meets it: peer.mirror.submit is served for real (the core's turn, drained inline, its
    // log captured); the log and acknowledgements answer from what was captured.
    class Wire final : public mf::Transport {
    public:
        explicit Wire(Scenario& s) : s_(s) {}
        std::vector<json> submits;
        std::vector<json> answersGiven;
        std::vector<std::string> misses;
        std::function<void()> beforeServing;   // runs on the core's turn, before the submit is served
        std::function<void(json&)> rewrite;    // what the submit claims, changed on its way (a lying mirror)

        bool connected(uint32_t) override { return true; }
        std::optional<Answer> request(uint32_t, const std::string& command, const json& payload) override {
            if (command == "peer.mirror.submit") {
                submits.push_back(payload);
                toCore(s_);
                json answer;
                std::string code, error;
                bool ok = true;
                {
                    AsCore as;
                    if (beforeServing) beforeServing();
                    try {
                        auto served = payload;
                        if (rewrite) rewrite(served);
                        answer = ms::serveSubmit(mirrorPeer, served);
                    } catch (const ops::Refused& e) {
                        ok = false;
                        code = e.code;
                        error = e.what();
                    } catch (const ops::Error& e) {
                        ok = false;
                        code = dynamic_cast<const ops::NotFound*>(&e) ? "not_found" : "invalid";
                        error = e.what();
                    }
                    captureLog(s_);
                }
                toMirror(s_);
                answersGiven.push_back(answer);
                return Answer{.ok = ok, .data = answer, .code = code, .error = error};
            }
            if (command == "peer.mirror.ack") {
                const mq::Position at{payload.at("term").get<uint64_t>(), payload.at("seq").get<uint64_t>()};
                const auto theirs = vh::mirror::Digest::fromBytes(
                    vh::mirror::hashFromHex(payload.at("digest").get<std::string>()), payload.at("entries").get<int64_t>());
                const auto it = s_.digests.find(at);
                const bool known = it != s_.digests.end();
                const bool match = known && it->second == theirs;
                return Answer{.ok = true, .data = {{"known", known}, {"match", match}, {"recorded", match},
                                                   {"core_digest", known ? json(it->second.hex()) : json(nullptr)},
                                                   {"core_entries", known ? json(it->second.entries) : json(nullptr)}}};
            }
            const auto it = s_.answers.find(key(command, payload));
            if (it == s_.answers.end()) {
                misses.push_back(key(command, payload));
                return std::nullopt;
            }
            return Answer{.ok = true, .data = it->second};
        }
        bool notify(uint32_t, const std::string&, const json&) override { return true; }

        // The sealed lane's PUT, short-circuited: the bytes land where the core's staging keeps verified ones. (In one
        // database the two vaults have different keys, so the core's verification is proven on its own bytes:
        // TheCoreStagesOnlyVerifiedBytes; two daemons with delivered keys prove the whole path: vhh drill peers.)
        std::size_t contentsSent{0};
        std::optional<std::string> contentRefusal;
        Sent sendContent(uint32_t, const Content& c) override {
            ++contentsSent;
            if (contentRefusal) return {.ok = false, .retry = false, .code = *contentRefusal, .error = "refused in a test"};
            // Kept as the core keeps bytes it verified, with the facts the PUT announced.
            const auto received = ms::contents::receivingPath(s_.coreId);
            std::filesystem::copy_file(c.path, received);
            const auto kept = ms::contents::keepVerified(
                s_.coreId, c.object_uid,
                {.generation = c.generation, .key_version = c.key_version, .size = c.size, .content_hash = c.content_hash},
                received);
            if (!kept.ok) return {.ok = false, .retry = false, .code = kept.code, .error = kept.error};
            return {.ok = true};
        }

    private:
        Scenario& s_;
    };

    // The contents the first copy expects, received as the sealed lane would deliver them: the core's sealed bytes at
    // the same vault path (the same generation), and the pending rows settled.
    static void receiveAll(const Scenario& s) {
        for (const auto& path : pathsOf(s.mirrorId)) {
            const auto mine = db::query::fs::Entry::getFSEntryById(entryId(s.mirrorId, path));
            const auto theirs = db::query::fs::Entry::getFSEntryById(entryId(s.coreId, path));
            if (!mine || !theirs || mine->isDirectory() || mine->isSymlink()) continue;
            std::error_code ec;
            if (!std::filesystem::exists(theirs->backing_path, ec)) continue;
            std::filesystem::create_directories(mine->backing_path.parent_path(), ec);
            std::filesystem::copy_file(theirs->backing_path, mine->backing_path,
                                       std::filesystem::copy_options::overwrite_existing, ec);
            ASSERT_FALSE(ec) << ec.message();
        }
        sql("DELETE FROM mirror_content_pending WHERE vault_id = " + std::to_string(s.mirrorId));
    }

    static mq::MirrorVault mirrorRow(const Scenario& s) {
        const auto mv = mq::MirrorVaults::get(s.mirrorId);
        EXPECT_TRUE(mv);
        return mv.value_or(mq::MirrorVault{});
    }

    // Visits until the follower has nothing more (bounded).
    static void followAll(Wire& wire, const Scenario& s) {
        for (int i = 0; i < 200; ++i) {
            const auto r = mf::Follower::instance()->step(s.mirrorId, wire);
            if (r.step == mf::Step::Idle) return;
            ASSERT_TRUE(r.step == mf::Step::Progress || r.step == mf::Step::CopyFinished)
                << mf::toString(r.step) << " " << r.detail << " " << mirrorRow(s).stop_detail.dump();
        }
        FAIL() << "the follower never settled";
    }

    // The mirror holds the core's tree as of its last captured position: the digest, recomputed from its tables too;
    // nothing pending or dirty.
    static void expectSettled(const Scenario& s) {
        const auto mv = mirrorRow(s);
        EXPECT_EQ(mv.state, "live") << mv.stop_detail.dump();
        EXPECT_EQ(mv.position(), s.at);
        ASSERT_TRUE(s.digests.contains(s.at));
        EXPECT_EQ(mv.digest, s.digests.at(s.at)) << "the mirror's digest is the core's";
        EXPECT_EQ(mq::Digests::recompute(s.mirrorId), mv.digest) << "its tables are the core's tree";
        EXPECT_EQ(mq::Digests::stored(s.mirrorId), mv.digest);
        EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty()) << "nothing left pending";
        EXPECT_TRUE(mq::Pending::dirtyUids(s.mirrorId).empty()) << "nothing left dirty";
    }

    static std::set<std::string> corePaths(Scenario& s) {
        toCore(s);
        auto out = pathsOf(s.coreId);
        toMirror(s);
        return out;
    }

    static int coreCount(Scenario& s, const std::string& statement) {
        toCore(s);
        const auto n = one<int>(statement);
        toMirror(s);
        return n;
    }
};

// ---- each operation, round trip ------------------------------------------------------------------------------------------

TEST_F(MirrorSubmitDbTest, AFolderMadeHereIsSubmittedExecutedAsThePersonAndConfirmedWithoutASecondApply) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    expectSettled(s);
    const auto digestBefore = mirrorRow(s).digest;

    // Applied here at once: the person sees the folder; the digest and the entry hashes are still the core's.
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/new");
    const auto uid = uidOf(s.mirrorId, "/docs/new");
    ASSERT_FALSE(uid.empty()) << "seen at once";
    const auto rowId = entryId(s.mirrorId, "/docs/new");
    auto pending = mq::Pending::list(s.mirrorId);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].op, "mkdir");
    EXPECT_EQ(pending[0].state, "pending");
    EXPECT_EQ(pending[0].entry_uid, uid);
    EXPECT_EQ(pending[0].actor.node, ownNode);
    EXPECT_EQ(pending[0].actor.id, superUser->id);
    EXPECT_EQ(pending[0].args.value("name", ""), "new");
    EXPECT_EQ(pending[0].args.value("parent_uid", ""), uidOf(s.mirrorId, "/docs"));
    EXPECT_EQ(mirrorRow(s).digest, digestBefore) << "a pending change never moves the digest";
    EXPECT_EQ(mq::Digests::stored(s.mirrorId), digestBefore);
    EXPECT_NE(mq::Digests::recompute(s.mirrorId), digestBefore) << "the tables hold the person's change";
    EXPECT_GE(one<int>("SELECT count(*) FROM fs_change_log WHERE vault_id = " + std::to_string(s.mirrorId) +
                       " AND path = '/docs/new' AND kind = 'create'"),
              1)
        << "the journal fired for this server's clients";

    followAll(wire, s);
    ASSERT_EQ(wire.submits.size(), 1u);
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed") << wire.answersGiven.back().dump();
    EXPECT_TRUE(wire.misses.empty()) << ::testing::PrintToString(wire.misses);
    expectSettled(s);
    EXPECT_EQ(entryId(s.mirrorId, "/docs/new"), rowId) << "confirmed, not applied a second time: the same row";
    EXPECT_EQ(uidOf(s.mirrorId, "/docs/new"), uid);

    // The core made it under the mirror's uid, as the person (a remote account), logged with the request's origin.
    const auto rid = wire.submits[0].at("request_id").get<std::string>();
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM directories d JOIN fs_entry e ON e.id = d.fs_entry_id WHERE e.vault_id = " +
                               std::to_string(s.coreId) + " AND d.uid = '" + uid + "'"),
              1);
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM fs_entry e JOIN users u ON u.id = e.created_by WHERE e.vault_id = " +
                               std::to_string(s.coreId) + " AND e.path = '/docs/new' AND u.remote AND u.home_node = '" +
                               ownNode + "' AND u.home_id = " + std::to_string(superUser->id)),
              1)
        << "the person, as the core names an account of the mirror";
    EXPECT_GE(coreCount(s, "SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(s.coreId) +
                               " AND origin = '" + rid + "' AND actor_node = '" + ownNode + "' AND actor_id = " +
                               std::to_string(superUser->id)),
              1);
    ASSERT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_EQ(one<int>("SELECT count(*) FROM audit_event WHERE action = 'fs.mkdir' AND details::jsonb ->> 'origin' = '" + rid +
                       "' AND (details::jsonb ->> 'peer_id')::int = " + std::to_string(mirrorPeer)),
              1)
        << "the core's audit names the person and the peer";
    EXPECT_EQ(corePaths(s), pathsOf(s.mirrorId));
}

TEST_F(MirrorSubmitDbTest, RenameMoveTrashAndDeleteEachConfirmWithTheCoresDigest) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/a", superUser);
        e->mkdir("/a/sub", superUser);
        e->mkdir("/b", superUser);
        write(e, "/a/one.txt", "one");
        write(e, "/a/sub/two.txt", "two");
        write(e, "/b/three.txt", "three");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);

    ops::fs::rename(superUser, s.mirrorId, "/a/one.txt", "/a/uno.txt");
    ops::fs::move(superUser, s.mirrorId, "/a/sub", "/b/sub");           // a folder with a file in it
    ops::fs::remove(superUser, s.mirrorId, "/b/three.txt");             // a file: the trash
    EXPECT_EQ(mq::Pending::list(s.mirrorId).size(), 3u);
    followAll(wire, s);
    EXPECT_EQ(wire.submits.size(), 3u);
    for (const auto& a : wire.answersGiven) EXPECT_EQ(a.value("status", ""), "executed") << a.dump();
    expectSettled(s);
    EXPECT_EQ(corePaths(s), pathsOf(s.mirrorId));
    EXPECT_TRUE(pathsOf(s.mirrorId).contains("/b/sub/two.txt"));

    ops::fs::remove(superUser, s.mirrorId, "/b");                       // a folder with files: trashed, then deleted
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(corePaths(s), pathsOf(s.mirrorId));
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/b"));
}

// ---- the compare-and-set with a pending change in the way ------------------------------------------------------------------

TEST_F(MirrorSubmitDbTest, AnUnrelatedCoreChangeToAPendingEntryArrivesFirst) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "first");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    const auto uid = uidOf(s.mirrorId, "/docs/a.txt");

    // Renamed here, not yet submitted.
    ops::fs::rename(superUser, s.mirrorId, "/docs/a.txt", "/docs/b.txt");
    ASSERT_EQ(mq::Pending::list(s.mirrorId).size(), 1u);

    // Meanwhile on the core: the same file's mode changes (an unrelated change), and it reaches the mirror first.
    coreChange(s, [&](const EnginePtr& e) {
        sql("UPDATE fs_entry SET mode = 384 WHERE id = " + std::to_string(entryId(s.coreId, "/docs/a.txt")));
        (void)e;
    });
    // The compare-and-set is against what the core last confirmed, not the pending state: no divergence.
    const json logAt{{"vault_uid", s.vaultUid}, {"term", mirrorRow(s).term}, {"seq", mirrorRow(s).last_seq}};
    const auto page = s.answers.at(key("peer.mirror.log", logAt));
    ASSERT_FALSE(page.at("groups").empty());
    const auto r = ap::applyGroup(s.mirrorId, mf::groupFromJson(page.at("groups")[0]));
    ASSERT_EQ(r.status, ap::Status::Applied) << r.reason << " " << r.detail.dump();
    EXPECT_EQ(mirrorRow(s).digest, r.digest);
    EXPECT_EQ(mirrorRow(s).digest, s.digests.at(r.at)) << "the core's digest at that group";
    EXPECT_EQ(one<int>("SELECT mode FROM fs_entry WHERE vault_id = " + std::to_string(s.mirrorId) + " AND path IN "
                       "('/docs/a.txt', '/docs/b.txt')"),
              384)
        << "the core's change is here";
    EXPECT_EQ(mq::Pending::list(s.mirrorId).size(), 1u) << "the person's change is still pending";

    // Then the person's rename goes to the core, which executes it on top; its confirmation settles everything.
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
    EXPECT_TRUE(pathsOf(s.mirrorId).contains("/docs/b.txt"));
    EXPECT_EQ(uidOf(s.mirrorId, "/docs/b.txt"), uid);
    const auto coreMode = coreCount(s, "SELECT mode FROM fs_entry WHERE vault_id = " + std::to_string(s.coreId) +
                                           " AND path = '/docs/b.txt'");
    EXPECT_EQ(one<int>("SELECT mode FROM fs_entry WHERE vault_id = " + std::to_string(s.mirrorId) +
                       " AND path = '/docs/b.txt'"),
              coreMode)
        << "the core's state, field for field";
}

TEST_F(MirrorSubmitDbTest, TheCoresEntryTakingAPendingFoldersNameSetsItAsideAndItGoesAgainAsItsConflictCopy) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);

    ops::fs::mkdir(superUser, s.mirrorId, "/docs/plans");
    const auto mine = uidOf(s.mirrorId, "/docs/plans");
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/plans/inside");          // and something in it, pending too
    coreChange(s, [](const EnginePtr& e) { e->mkdir("/docs/plans", superUser); });   // the core's own, first
    const auto copy = ms::conflictName("plans", mine, true);

    // The core's folder arrives before the person's is submitted: the pending one steps aside to its conflict name,
    // with what is in it, and the core's takes the name (no divergence).
    const json logAt{{"vault_uid", s.vaultUid}, {"term", mirrorRow(s).term}, {"seq", mirrorRow(s).last_seq}};
    const auto page = s.answers.at(key("peer.mirror.log", logAt));
    ASSERT_FALSE(page.at("groups").empty());
    const auto r = ap::applyGroup(s.mirrorId, mf::groupFromJson(page.at("groups")[0]));
    ASSERT_EQ(r.status, ap::Status::Applied) << r.reason << " " << r.detail.dump();
    EXPECT_EQ(uidOf(s.mirrorId, "/docs/" + copy), mine);
    EXPECT_FALSE(uidOf(s.mirrorId, "/docs/" + copy + "/inside").empty());
    EXPECT_EQ(mirrorRow(s).digest, s.digests.at(r.at));

    followAll(wire, s);
    expectSettled(s);
    EXPECT_FALSE(uidOf(s.mirrorId, "/docs/" + copy + "/inside").empty());
    EXPECT_EQ(uidOf(s.mirrorId, "/docs/" + copy), mine) << "the person's folder is its conflict copy, same entry";
    EXPECT_FALSE(uidOf(s.mirrorId, "/docs/plans").empty());
    EXPECT_NE(uidOf(s.mirrorId, "/docs/plans"), mine) << "the core's folder has the name";
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
    ASSERT_GE(wire.answersGiven.size(), 2u);
    EXPECT_EQ(wire.answersGiven[0].value("code", ""), "conflict");
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed");
    const auto held = mq::Pending::heldChanges(s.mirrorId);
    ASSERT_EQ(held.size(), 1u);
    EXPECT_EQ(held[0].kind, "conflict");
    EXPECT_EQ(held[0].copy_name.value_or(""), copy);
}

TEST_F(MirrorSubmitDbTest, TheCoreRemovingAFolderAPendingFolderWasMadeInTakesItBackAndTheChangeIsHeld) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/gone", superUser); });
    Wire wire(s);
    followAll(wire, s);

    ops::fs::mkdir(superUser, s.mirrorId, "/gone/mine");                       // pending here
    coreChange(s, [](const EnginePtr& e) { e->remove("/gone", superUser->id); });   // the core removes the folder
    // The core's removal arrives first: the pending folder in it goes back to what the core has (nothing), the folder
    // goes, and nothing diverges.
    const json logAt{{"vault_uid", s.vaultUid}, {"term", mirrorRow(s).term}, {"seq", mirrorRow(s).last_seq}};
    for (const auto& g : s.answers.at(key("peer.mirror.log", logAt)).at("groups")) {
        const auto r = ap::applyGroup(s.mirrorId, mf::groupFromJson(g));
        ASSERT_EQ(r.status, ap::Status::Applied) << r.reason << " " << r.detail.dump();
        EXPECT_EQ(r.digest, s.digests.at(r.at));
    }
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/gone"));
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/gone/mine"));
    ASSERT_EQ(mq::Pending::list(s.mirrorId).size(), 1u) << "the person's change is still to be told to the core";

    // The core refuses it (its folder is gone): kept as a held change, never dropped.
    followAll(wire, s);
    expectSettled(s);
    ASSERT_EQ(wire.answersGiven.size(), 1u);
    EXPECT_EQ(wire.answersGiven[0].value("code", ""), "not_found");
    const auto held = mq::Pending::heldChanges(s.mirrorId);
    ASSERT_EQ(held.size(), 1u);
    EXPECT_EQ(held[0].kind, "held");
    EXPECT_EQ(held[0].op, "mkdir");
    EXPECT_EQ(held[0].args.value("name", ""), "mine");
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
}

TEST_F(MirrorSubmitDbTest, TheCoresEntryInAFolderRemovedHereBringsTheFolderBackUntilTheRemovalIsConfirmed) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/box", superUser); });
    Wire wire(s);
    followAll(wire, s);
    const auto box = uidOf(s.mirrorId, "/box");

    ops::fs::remove(superUser, s.mirrorId, "/box");                             // pending here
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/box"));
    coreChange(s, [](const EnginePtr& e) { e->mkdir("/box/theirs", superUser); });   // meanwhile in it, on the core
    const json logAt{{"vault_uid", s.vaultUid}, {"term", mirrorRow(s).term}, {"seq", mirrorRow(s).last_seq}};
    for (const auto& g : s.answers.at(key("peer.mirror.log", logAt)).at("groups")) {
        const auto r = ap::applyGroup(s.mirrorId, mf::groupFromJson(g));
        ASSERT_EQ(r.status, ap::Status::Applied) << r.reason << " " << r.detail.dump();
        EXPECT_EQ(r.digest, s.digests.at(r.at));
    }
    EXPECT_EQ(uidOf(s.mirrorId, "/box"), box) << "the folder came back as the core has it, under its uid";
    EXPECT_TRUE(pathsOf(s.mirrorId).contains("/box/theirs"));

    // The person's removal then reaches the core, which removes the folder with what the core put in it.
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed");
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/box"));
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
}

// ---- contents ------------------------------------------------------------------------------------------------------------

TEST_F(MirrorSubmitDbTest, AFileWrittenHereGoesToTheCoreWithItsSealedBytesAndIsConfirmedWithoutAFetch) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);

    // An upload lane's commit, a share upload, the S3 gateway, `vh fs put`: all write through Filesystem::createFile.
    write(s.mirror, "/docs/new.txt", "the person's bytes");
    const auto uid = uidOf(s.mirrorId, "/docs/new.txt");
    ASSERT_FALSE(uid.empty()) << "seen here at once";
    const auto pending = mq::Pending::list(s.mirrorId);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].op, "write");
    EXPECT_EQ(pending[0].entry_uid, uid);
    EXPECT_FALSE(pending[0].args.contains("base")) << "a create";
    const auto generation = pending[0].args.value("generation", std::string{});
    EXPECT_FALSE(generation.empty());
    EXPECT_EQ(pending[0].new_generation.value_or(""), generation);
    const auto blob = ms::contents::pendingBlob(s.mirrorId, pending[0].id);
    EXPECT_TRUE(std::filesystem::exists(blob)) << "the sealed bytes are kept apart until the core has them";

    followAll(wire, s);
    EXPECT_EQ(wire.contentsSent, 1u) << "the bytes go before the change";
    ASSERT_FALSE(wire.answersGiven.empty());
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed") << wire.answersGiven.back().dump();
    expectSettled(s);
    EXPECT_FALSE(std::filesystem::exists(blob)) << "confirmed: the pending store lets them go";
    EXPECT_EQ(one<int>("SELECT count(*) FROM mirror_content_pending WHERE vault_id = " + std::to_string(s.mirrorId)), 0)
        << "the same generation is here: nothing is fetched";
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = " +
                               std::to_string(s.coreId) + " AND f.object_uid = '" + uid + "' AND f.encryption_iv = '" +
                               generation + "'"),
              1)
        << "the core holds the same bytes under the same generation and uid";
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));

    // A replacement: based on the generation it replaced, committed as a compare-and-swap.
    write(s.mirror, "/docs/new.txt", "the person's second version, longer");
    const auto again = mq::Pending::list(s.mirrorId);
    ASSERT_EQ(again.size(), 1u);
    EXPECT_EQ(again[0].args.value("base", ""), generation);
    followAll(wire, s);
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed");
    expectSettled(s);
}

TEST_F(MirrorSubmitDbTest, AReplacementTheCoreOutranBecomesAConflictCopyWithThePersonsBytes) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "first");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    const auto uid = uidOf(s.mirrorId, "/docs/a.txt");

    write(s.mirror, "/docs/a.txt", "the person's version");
    const auto mine = mq::Pending::list(s.mirrorId).at(0).args.value("generation", std::string{});
    coreChange(s, [](const EnginePtr& e) { write(e, "/docs/a.txt", "the core's version, first"); });

    followAll(wire, s);
    expectSettled(s);
    ASSERT_FALSE(wire.answersGiven.empty());
    EXPECT_EQ(wire.answersGiven.front().value("code", ""), "content_conflict");
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed");
    EXPECT_EQ(uidOf(s.mirrorId, "/docs/a.txt"), uid);
    const auto held = mq::Pending::heldChanges(s.mirrorId);
    ASSERT_EQ(held.size(), 1u);
    EXPECT_EQ(held[0].kind, "conflict");
    const auto copyName = held[0].copy_name.value_or("");
    ASSERT_FALSE(copyName.empty());
    EXPECT_NE(copyName.find(" (conflict "), std::string::npos);
    EXPECT_TRUE(copyName.ends_with(".txt")) << copyName;
    const auto copy = "/docs/" + copyName;
    EXPECT_FALSE(uidOf(s.mirrorId, copy).empty()) << "the person's version is beside it, never dropped";
    EXPECT_EQ(one<std::string>("SELECT f.encryption_iv FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE "
                               "e.vault_id = " + std::to_string(s.mirrorId) + " AND e.path = '" + copy + "'"),
              mine)
        << "with the person's bytes as they were sealed";
    EXPECT_NE(one<std::string>("SELECT f.encryption_iv FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE "
                               "e.vault_id = " + std::to_string(s.mirrorId) + " AND e.path = '/docs/a.txt'"),
              mine)
        << "the file itself is the core's version";
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
}

TEST_F(MirrorSubmitDbTest, BytesTheCoreRefusesAreHeldWithTheChangeAndNothingIsLost) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    write(s.mirror, "/docs/kept.txt", "keep me");
    wire.contentRefusal = "invalid_contents";
    followAll(wire, s);
    expectSettled(s);
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/docs/kept.txt")) << "back to the core's state";
    const auto held = mq::Pending::heldChanges(s.mirrorId);
    ASSERT_EQ(held.size(), 1u);
    EXPECT_EQ(held[0].kind, "held");
    EXPECT_EQ(held[0].op, "write");
    EXPECT_EQ(held[0].reason_code, "invalid_contents");
    EXPECT_TRUE(std::filesystem::exists(ms::contents::heldBlob(s.mirrorId, held[0].id)))
        << "the person's sealed bytes stay with the held change";
}

TEST_F(MirrorSubmitDbTest, AHeldWriteRetriedGoesWithItsBytesAndADiscardedOneTakesThemAway) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    write(s.mirror, "/docs/again.txt", "sent again once the core takes it");
    write(s.mirror, "/docs/dropped.txt", "let go by a super admin");
    const auto uid = uidOf(s.mirrorId, "/docs/again.txt");
    wire.contentRefusal = "over_quota";
    followAll(wire, s);
    expectSettled(s);
    auto held = ops::mirrors::held(superUser, s.mirrorId, false);
    ASSERT_EQ(held.size(), 2u);
    const auto& again = held[0].args.value("name", "") == "again.txt" ? held[0] : held[1];
    const auto& dropped = held[0].args.value("name", "") == "again.txt" ? held[1] : held[0];
    const auto againBlob = ms::contents::heldBlob(s.mirrorId, again.id);
    const auto droppedBlob = ms::contents::heldBlob(s.mirrorId, dropped.id);
    ASSERT_TRUE(std::filesystem::exists(againBlob));
    ASSERT_TRUE(std::filesystem::exists(droppedBlob));

    // Discarded: the person's bytes go with it.
    EXPECT_EQ(ops::mirrors::discardHeld(superUser, dropped.id).state, "discarded");
    EXPECT_FALSE(std::filesystem::exists(droppedBlob)) << "a discarded change keeps nothing on disk";

    // Retried once the core has room: the bytes move to the new change, are sent, and the write is executed.
    wire.contentRefusal.reset();
    const auto sentBefore = wire.contentsSent;
    EXPECT_EQ(ops::mirrors::retryHeld(superUser, again.id).state, "retried");
    EXPECT_FALSE(std::filesystem::exists(againBlob)) << "moved, not copied";
    const auto row = mq::Pending::list(s.mirrorId);
    ASSERT_EQ(row.size(), 1u);
    EXPECT_TRUE(std::filesystem::exists(ms::contents::pendingBlob(s.mirrorId, row[0].id)));
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(wire.contentsSent, sentBefore + 1) << "the same bytes, sent again";
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed") << wire.answersGiven.back().dump();
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = " +
                               std::to_string(s.coreId) + " AND f.object_uid = '" + uid + "'"),
              1)
        << "the core holds the person's file";
    EXPECT_FALSE(std::filesystem::exists(ms::contents::pendingBlob(s.mirrorId, row[0].id))) << "confirmed: let go";
    EXPECT_TRUE(ops::mirrors::held(superUser, s.mirrorId, false).empty());
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
}

TEST_F(MirrorSubmitDbTest, WhenACopyEndsItsRowsAndSealedBytesAreHandledAndNothingIsLeftForAVaultThatIsGone) {
    // ---- a copy whose core ended the mirror and kept it (orphaned): what was applied here stays as content; each
    // pending change is kept as a held one with its bytes, listed until discarded; nothing is dirty any more.
    {
        auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
        Wire wire(s);
        followAll(wire, s);
        ops::fs::mkdir(superUser, s.mirrorId, "/docs/sent");   // the core keeps what it did with this one
        followAll(wire, s);
        expectSettled(s);
        write(s.mirror, "/docs/unsent.txt", "made here, never submitted");
        const auto pending = mq::Pending::list(s.mirrorId);
        ASSERT_EQ(pending.size(), 1u);
        const auto blob = ms::contents::pendingBlob(s.mirrorId, pending[0].id);
        ASSERT_TRUE(std::filesystem::exists(blob));
        ASSERT_FALSE(mq::Pending::dirtyUids(s.mirrorId).empty());
        const auto core = db::query::peer::Peers::byId(corePeer);
        ASSERT_TRUE(core);
        const auto answer = vh::mirror::start::cancelReceived(*core, {{"vault_uid", vl::keykit::toBase32(vh::crypto::id::fromUuid(s.vaultUid))}, {"remove_copy", false},
                                                                      {"reason", "cancelled"}});
        EXPECT_EQ(answer.value("copy", ""), "kept") << answer.dump();
        EXPECT_EQ(mirrorRow(s).role, "orphaned");
        EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty());
        EXPECT_TRUE(mq::Pending::dirtyUids(s.mirrorId).empty());
        EXPECT_TRUE(pathsOf(s.mirrorId).contains("/docs/unsent.txt")) << "the applied change stays as content";
        const auto held = ops::mirrors::held(superUser, s.mirrorId, false);
        ASSERT_EQ(held.size(), 1u) << "listed until discarded";
        EXPECT_EQ(held[0].reason_code, "mirror_orphaned");
        EXPECT_FALSE(std::filesystem::exists(blob));
        const auto heldBlob = ms::contents::heldBlob(s.mirrorId, held[0].id);
        EXPECT_TRUE(std::filesystem::exists(heldBlob)) << "with its bytes";
        EXPECT_EQ(ops::mirrors::discardHeld(superUser, held[0].id).state, "discarded");
        EXPECT_FALSE(std::filesystem::exists(heldBlob));

        // ---- the core's side when the mirror ends: what the mirror submitted is forgotten, staged bytes go.
        toCore(s);
        {
            AsCore as;
            const auto stagedDir = ms::contents::stagedPath(s.coreId, "u", "g").parent_path();
            {
                const auto received = ms::contents::receivingPath(s.coreId);
                vh::fs::ops::writeFileExclusive(received, {}, 0600);
                ASSERT_TRUE(ms::contents::keepVerified(s.coreId, "00000000-0000-4000-8000-0000000000b1",
                                                       {.generation = "x", .size = 0}, received).ok);
            }
            ASSERT_GT(one<int>("SELECT count(*) FROM mirror_submission WHERE vault_id = " + std::to_string(s.coreId)), 0);
            EXPECT_TRUE(vh::mirror::start::cancelOnCore(s.coreId, "test", false, false, std::nullopt, ""));
            EXPECT_EQ(one<int>("SELECT count(*) FROM mirror_submission WHERE vault_id = " + std::to_string(s.coreId)), 0);
            EXPECT_FALSE(std::filesystem::exists(stagedDir)) << "what the mirror sent and never committed";
        }
        toMirror(s);
    }

    // ---- a copy removed (the core asked, or its first copy never finished): the vault, its rows and its three
    // directories go.
    {
        auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
        Wire wire(s);
        followAll(wire, s);
        write(s.mirror, "/docs/a.txt", "pending");
        write(s.mirror, "/docs/b.txt", "held");
        wire.contentRefusal = "invalid_contents";
        (void)mf::Follower::instance()->step(s.mirrorId, wire);   // one goes, is refused and held
        wire.contentRefusal.reset();
        const auto v = s.mirrorId;
        const auto pendingDir = ms::contents::pendingBlob(v, 1).parent_path();
        const auto heldDir = ms::contents::heldBlob(v, 1).parent_path();
        std::filesystem::create_directories(heldDir);
        ASSERT_TRUE(std::filesystem::exists(pendingDir));
        vh::mirror::start::removeCopy(v);
        EXPECT_FALSE(std::filesystem::exists(pendingDir));
        EXPECT_FALSE(std::filesystem::exists(heldDir));
        EXPECT_FALSE(std::filesystem::exists(ms::contents::stagedPath(v, "u", "g").parent_path()));
        for (const auto* t : {"mirror_pending", "mirror_dirty", "mirror_held", "mirror_vault"})
            EXPECT_EQ(one<int>(std::string("SELECT count(*) FROM ") + t + " WHERE vault_id = " + std::to_string(v)), 0)
                << t;
    }
}

TEST_F(MirrorSubmitDbTest, AFileWhoseContentsHaveNotArrivedIsRenamedAndTrashedAsMetadata) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/far.txt", "not here yet");
        write(e, "/docs/gone.txt", "not here either");
    });
    Wire wire(s);
    followAll(wire, s);
    ASSERT_GE(one<int>("SELECT count(*) FROM mirror_content_pending WHERE vault_id = " + std::to_string(s.mirrorId)), 2);
    ops::fs::rename(superUser, s.mirrorId, "/docs/far.txt", "/docs/near.txt");
    ops::fs::move(superUser, s.mirrorId, "/docs/near.txt", "/near.txt");
    ops::fs::remove(superUser, s.mirrorId, "/docs/gone.txt");
    followAll(wire, s);
    expectSettled(s);
    EXPECT_TRUE(pathsOf(s.mirrorId).contains("/near.txt"));
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
    EXPECT_EQ(one<int>("SELECT count(*) FROM mirror_content_pending WHERE vault_id = " + std::to_string(s.mirrorId)), 1)
        << "the moved file's contents are still expected (fetched to where it is now); the trashed one's are not";
}

TEST_F(MirrorSubmitDbTest, AModeOrTimeChangeIsAPendingChangeAndAnOwnerChangeIsRefused) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "first");
    });
    Wire wire(s);
    followAll(wire, s);
    ops::fs::setAttributes(superUser, s.mirrorId, "/docs/a.txt", {.mode = 0600, .mtime_us = int64_t{1'700'000'000'000'000}});
    const auto pending = mq::Pending::list(s.mirrorId);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].op, "setattr");
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(coreCount(s, "SELECT mode FROM fs_entry WHERE vault_id = " + std::to_string(s.coreId) +
                               " AND path = '/docs/a.txt'") & 0777,
              0600);
    EXPECT_THROW(ops::fs::setAttributes(superUser, s.mirrorId, "/docs/a.txt", {.owner_uid = 4242}), ops::Denied);
    EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty());
}

TEST_F(MirrorSubmitDbTest, ASealIsKeptAsPendingWhenTheLinkIsDownAndNothingElseIs) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    vh::mirror::access::linkChanged(corePeer, false);
    {
        ms::Local seal(superUser, s.mirrorId, "write", ms::Local::Mode::Seal);
        EXPECT_TRUE(seal.active()) << "a file open for writing when the link dropped is sealed and kept as pending";
    }
    {
        ms::Local change(superUser, s.mirrorId, "write");
        EXPECT_FALSE(change.active()) << "any new change is refused by the gate";
    }
    ASSERT_TRUE(mq::MirrorVaults::setState(s.mirrorId, "paused"));
    {
        ms::Local seal(superUser, s.mirrorId, "write", ms::Local::Mode::Seal);
        EXPECT_FALSE(seal.active()) << "paused: the seal is refused and the copy kept unsaved (the gate's rule)";
    }
    ASSERT_TRUE(mq::MirrorVaults::setState(s.mirrorId, "live"));
    vh::mirror::access::linkChanged(corePeer, true);
}

TEST_F(MirrorSubmitDbTest, TheCoreStagesOnlyVerifiedBytes) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/real.txt", "sealed under the core's own key");
    });
    toCore(s);
    const auto entry = db::query::fs::Entry::getFSEntryById(entryId(s.coreId, "/docs/real.txt"));
    ASSERT_TRUE(entry);
    const auto file = std::dynamic_pointer_cast<fs::model::File>(entry);
    ASSERT_TRUE(file);
    const auto uid = uidOf(s.coreId, "/docs/real.txt");
    const ms::contents::Facts facts{.generation = file->encryption_iv, .key_version = file->encrypted_with_key_version,
                                    .size = file->size_bytes, .content_hash = file->content_hash.value_or("")};
    const auto copyIn = [&](const bool tamper) {
        const auto received = ms::contents::receivingPath(s.coreId);
        std::filesystem::copy_file(file->backing_path, received);
        if (tamper) {
            std::fstream f(received, std::ios::in | std::ios::out | std::ios::binary);
            f.seekp(-1, std::ios::end);
            f.put('\x5a');
        }
        return received;
    };
    auto bad = facts;
    bad.content_hash = std::string(64, '0');
    EXPECT_EQ(ms::contents::stage(s.coreId, uid, bad, copyIn(false)).code, "invalid_contents") << "another hash";
    EXPECT_EQ(ms::contents::stage(s.coreId, uid, facts, copyIn(true)).code, "invalid_contents") << "a changed byte";
    EXPECT_FALSE(ms::contents::staged(s.coreId, uid, facts.generation)) << "nothing refused is kept";
    const auto ok = ms::contents::stage(s.coreId, uid, facts, copyIn(false));
    EXPECT_TRUE(ok.ok) << ok.code << " " << ok.error;
    EXPECT_TRUE(ms::contents::staged(s.coreId, uid, facts.generation));
    EXPECT_GE(ms::contents::sweep(std::chrono::hours(0)), 1u) << "staged and never committed: swept";
    EXPECT_FALSE(ms::contents::staged(s.coreId, uid, facts.generation));
    toMirror(s);
}

TEST_F(MirrorSubmitDbTest, TheCoreCommitsAWriteWithTheFactsItVerifiedAndRefusesAChangeThatClaimsOthers) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    const auto coreFile = [&](const std::string& uid, const std::string& column) {
        toCore(s);
        const auto r = db::Transactions::exec("ms core file", [&](pqxx::work& txn) {
            const auto rows = txn.exec("SELECT f." + column + "::text FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                       "WHERE e.vault_id = $1 AND f.object_uid = $2::uuid",
                                       pqxx::params{s.coreId, uid});
            return rows.empty() ? std::string("<none>") : rows[0][0].as<std::string>();
        });
        toMirror(s);
        return r;
    };

    // Bytes sent and verified, then a submit that claims another key version for them (or another hash, size): the
    // core never describes bytes with what a submit says of them. Refused for the bytes, held, never sent again.
    write(s.mirror, "/docs/claimed.txt", "the bytes the core verified");
    const auto uid = uidOf(s.mirrorId, "/docs/claimed.txt");
    wire.rewrite = [](json& p) { p["args"]["key_version"] = p["args"].value("key_version", 0u) + 7; };
    followAll(wire, s);
    expectSettled(s);
    ASSERT_EQ(wire.submits.size(), 1u) << "refused for its bytes: not retried";
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "refused") << wire.answersGiven.back().dump();
    EXPECT_EQ(wire.answersGiven.back().value("code", ""), "invalid_contents");
    EXPECT_EQ(coreFile(uid, "encrypted_with_key_version"), "<none>") << "nothing committed on the core";
    auto held = mq::Pending::heldChanges(s.mirrorId);
    ASSERT_EQ(held.size(), 1u);
    EXPECT_EQ(held[0].reason_code, "invalid_contents");
    EXPECT_TRUE(std::filesystem::exists(ms::contents::heldBlob(s.mirrorId, held[0].id)));
    wire.rewrite = [](json& p) { p["args"]["content_hash"] = std::string(64, 'e'); };
    write(s.mirror, "/docs/hashed.txt", "bytes with another hash claimed");
    followAll(wire, s);
    EXPECT_EQ(wire.answersGiven.back().value("code", ""), "invalid_contents");
    EXPECT_EQ(mq::Pending::heldChanges(s.mirrorId).size(), 2u);

    // Told the truth: committed, and the core's row is the verified facts.
    wire.rewrite = nullptr;
    write(s.mirror, "/docs/true.txt", "and these are described as they are");
    const auto args = mq::Pending::list(s.mirrorId).at(0).args;
    const auto trueUid = uidOf(s.mirrorId, "/docs/true.txt");
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(wire.answersGiven.back().value("status", ""), "executed");
    EXPECT_EQ(coreFile(trueUid, "encrypted_with_key_version"), std::to_string(args.value("key_version", 0u)));
    EXPECT_EQ(coreFile(trueUid, "content_hash"), args.value("content_hash", std::string{}));
    EXPECT_EQ(coreFile(trueUid, "size_bytes"), std::to_string(args.value("size", uint64_t{0})));
    EXPECT_EQ(coreFile(trueUid, "encryption_iv"), args.value("generation", std::string{}));

    // A write's generation is a VHF1 salt, and an empty file has none: anything else is not a write.
    toCore(s);
    {
        AsCore as;
        const json base{{"vault_uid", s.vaultUid},
                        {"request_id", ms::newRequestId()},
                        {"person", {{"node", ownNode}, {"id", superUser->id}}},
                        {"at", {{"term", 1}, {"seq", 0}}},
                        {"op", "write"},
                        {"entry_uid", "00000000-0000-4000-8000-0000000000a1"},
                        {"args", {{"parent_uid", s.vaultUid}, {"name", "w.txt"}, {"size", 5}, {"key_version", 1},
                                  {"content_hash", std::string(64, 'a')}, {"generation", "not-a-salt"}}}};
        EXPECT_THROW((void)ms::serveSubmit(mirrorPeer, base), ops::Invalid) << "bytes under no VHF1 generation";
        auto empty = base;
        empty["args"]["size"] = 0;
        empty["args"]["generation"] = args.value("generation", std::string{});
        EXPECT_THROW((void)ms::serveSubmit(mirrorPeer, empty), ops::Invalid) << "an empty file names no generation";
    }
    toMirror(s);
}

TEST_F(MirrorSubmitDbTest, HousekeepingSweepsWhatAStopLeftAndWhatNothingNamesAndRunsFromTheFollowersLoop) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    toCore(s);
    const auto put = [&](const std::string& uid, const std::string& generation) {
        const auto received = ms::contents::receivingPath(s.coreId);
        vh::fs::ops::writeFileExclusive(received, {}, 0600);
        EXPECT_TRUE(ms::contents::keepVerified(s.coreId, uid, {.generation = generation}, received).ok);
        return ms::contents::stagedPath(s.coreId, uid, generation);
    };
    const auto fresh = put("00000000-0000-4000-8000-0000000000c1", "fresh");
    const auto old = put("00000000-0000-4000-8000-0000000000c2", "old");
    const auto twoDaysAgo = std::filesystem::file_time_type::clock::now() - std::chrono::hours(48);
    for (const auto& p : {old, std::filesystem::path(old.string() + ".facts")}) std::filesystem::last_write_time(p, twoDaysAgo);
    // A vault that is not a core here (any more), with bytes still staged.
    const auto notCore = ms::contents::stagedPath(s.mirrorId + 100000, "00000000-0000-4000-8000-0000000000c3", "g");
    std::filesystem::create_directories(notCore.parent_path());
    vh::fs::ops::writeFileExclusive(notCore, {}, 0600);
    // A pending blob of a change that is gone, and a held one of a vault that is gone.
    toMirror(s);
    const auto strayPending = ms::contents::pendingBlob(s.mirrorId, 999'999'999);
    std::filesystem::create_directories(strayPending.parent_path());
    vh::fs::ops::writeFileExclusive(strayPending, {}, 0600);
    const auto goneVault = ms::contents::heldBlob(999'999'000, 1);
    std::filesystem::create_directories(goneVault.parent_path());
    vh::fs::ops::writeFileExclusive(goneVault, {}, 0600);
    write(s.mirror, "/docs/kept.txt", "a pending change's bytes are named: kept");
    const auto named = ms::contents::pendingBlob(s.mirrorId, mq::Pending::list(s.mirrorId).at(0).id);

    // The loop runs it at its first pass and every hour after (whatever ran before in this process).
    const auto at = std::chrono::steady_clock::now() + std::chrono::hours(10'000);
    EXPECT_GT(mf::Follower::instance()->housekeep(at), 0u);
    EXPECT_EQ(mf::Follower::instance()->housekeep(at + std::chrono::minutes(59)), 0u) << "not again within the hour";
    EXPECT_FALSE(std::filesystem::exists(old)) << "staged a day ago and never committed";
    EXPECT_FALSE(std::filesystem::exists(old.string() + ".facts"));
    EXPECT_TRUE(std::filesystem::exists(fresh)) << "a change may still name it";
    EXPECT_FALSE(std::filesystem::exists(notCore.parent_path())) << "not this server's core: nothing will commit it";
    EXPECT_FALSE(std::filesystem::exists(strayPending)) << "no change names it";
    EXPECT_FALSE(std::filesystem::exists(goneVault.parent_path())) << "the vault is gone";
    EXPECT_TRUE(std::filesystem::exists(named));
    // A partial reception is swept at startup (nothing resumes one: the mirror sends the bytes again).
    toCore(s);
    const auto interrupted = ms::contents::receivingPath(s.coreId);   // a PUT a stop broke off
    vh::fs::ops::writeFileExclusive(interrupted, {}, 0600);
    toMirror(s);
    EXPECT_GE(ms::contents::housekeeping(true), 1u);
    EXPECT_FALSE(std::filesystem::exists(interrupted));
    EXPECT_TRUE(std::filesystem::exists(fresh));
    followAll(wire, s);
    expectSettled(s);
}

// ---- an HTTP upload's staging file (.upload-http-*.part): never content, in either direction ---------------------------------

TEST_F(MirrorSubmitDbTest, AnUploadOnTheMirrorIsOneWriteAndItsStagingFileIsScratchThatIsNeverSubmittedOrHashed) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    // The upload coordinator stages next to the target (through the mount on Linux), then commits the real file.
    const std::string staging = "/docs/.upload-http-0f1e2d3c-77.part";
    write(s.mirror, staging, "the upload's bytes, staged");
    EXPECT_TRUE(pathsOf(s.mirrorId).contains(staging)) << "written past the backstop";
    EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty()) << "scratch: nothing pending";
    EXPECT_TRUE(mq::Pending::dirtyUids(s.mirrorId).empty()) << "nothing dirty";
    write(s.mirror, "/docs/uploaded.txt", "the upload's bytes, staged");
    ASSERT_EQ(mq::Pending::list(s.mirrorId).size(), 1u) << "the commit is the one change";

    followAll(wire, s);
    EXPECT_EQ(wire.submits.size(), 1u) << "exactly one pending write";
    EXPECT_EQ(wire.contentsSent, 1u) << "and one PUT";
    EXPECT_EQ(wire.submits.at(0).at("args").value("name", ""), "uploaded.txt");
    expectSettled(s);   // the staging file is still here, outside the digest
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM fs_entry WHERE vault_id = " + std::to_string(s.coreId) +
                               " AND name LIKE '.upload-http-%'"),
              0)
        << "never on the core";

    // The coordinator's discard (or a share upload's): scratch again, nothing pending.
    ops::fs::remove(superUser, s.mirrorId, staging);
    EXPECT_FALSE(pathsOf(s.mirrorId).contains(staging));
    EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty());
    followAll(wire, s);
    EXPECT_EQ(wire.submits.size(), 1u);
    expectSettled(s);
}

TEST_F(MirrorSubmitDbTest, AnUploadOnTheCoreLogsOnlyItsFileAndAFileRenamedToAStagingNameLeavesTheTree) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/old.txt", "a file that will take a staging name");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    const std::string staging = "/docs/.upload-http-aa55-1.part";
    const auto logged = [&](const std::string& uid) {
        return coreCount(s, "SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(s.coreId) +
                                " AND entry_uid = '" + uid + "'");
    };
    std::string stagingUid;
    coreChange(s, [&](const EnginePtr& e) {
        write(e, staging, "staged on the core");
        stagingUid = uidOf(s.coreId, staging);
        write(e, "/docs/up.txt", "staged on the core");
    });
    ASSERT_FALSE(stagingUid.empty());
    EXPECT_EQ(logged(stagingUid), 0) << "the core never logs its staging file";
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM vh_mirror_tree_states(" + std::to_string(s.coreId) + ") WHERE entry_uid = '" +
                               stagingUid + "'"),
              0)
        << "nor counts it in its tree";
    coreChange(s, [&](const EnginePtr&) { ops::fs::remove(superUser, s.coreId, staging); });
    EXPECT_EQ(logged(stagingUid), 0) << "nor its trash or purge";
    followAll(wire, s);
    expectSettled(s);
    EXPECT_TRUE(pathsOf(s.mirrorId).contains("/docs/up.txt"));
    EXPECT_FALSE(pathsOf(s.mirrorId).contains(staging)) << "never fetched";

    // A file renamed to a staging name leaves the replicated tree (a delete); the mirror follows.
    const auto oldUid = uidOf(s.mirrorId, "/docs/old.txt");
    coreChange(s, [&](const EnginePtr&) { ops::fs::rename(superUser, s.coreId, "/docs/old.txt", "/docs/.upload-http-x.part"); });
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(s.coreId) +
                               " AND entry_uid = '" + oldUid + "' AND op = 'delete'"),
              1);
    followAll(wire, s);
    expectSettled(s);
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/docs/old.txt"));
}

// ---- refusals ------------------------------------------------------------------------------------------------------------

TEST_F(MirrorSubmitDbTest, ARefusalByTheCeilingIsHeldAndTheEntryComesBackToTheCoresState) {
    // The core lets the mirror server read only; this server's grant (its own business) allows more.
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "first");
    }, "reader");
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    const auto uid = uidOf(s.mirrorId, "/docs/a.txt");

    ops::fs::rename(superUser, s.mirrorId, "/docs/a.txt", "/docs/b.txt");
    ASSERT_TRUE(pathsOf(s.mirrorId).contains("/docs/b.txt")) << "applied here at once";
    followAll(wire, s);
    ASSERT_EQ(wire.answersGiven.size(), 1u);
    EXPECT_EQ(wire.answersGiven[0].value("status", ""), "refused");
    EXPECT_EQ(wire.answersGiven[0].value("code", ""), "denied");
    expectSettled(s);
    EXPECT_TRUE(pathsOf(s.mirrorId).contains("/docs/a.txt")) << "back to the core's state";
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/docs/b.txt"));
    EXPECT_EQ(uidOf(s.mirrorId, "/docs/a.txt"), uid);
    const auto held = mq::Pending::heldChanges(s.mirrorId);
    ASSERT_EQ(held.size(), 1u) << "never dropped: kept as a held change";
    EXPECT_EQ(held[0].kind, "held");
    EXPECT_EQ(held[0].op, "rename");
    EXPECT_EQ(held[0].reason_code, "denied");
    EXPECT_EQ(held[0].args.value("name", ""), "b.txt");
    EXPECT_EQ(held[0].actor.id, superUser->id);
    EXPECT_EQ(corePaths(s), pathsOf(s.mirrorId));
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(s.coreId) +
                               " AND origin IS NOT NULL"),
              0)
        << "nothing was executed on the core";

    // A held folder made here (refused for Touch) goes too, and the entry it made is gone again.
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/new");
    followAll(wire, s);
    expectSettled(s);
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/docs/new"));
    EXPECT_EQ(mq::Pending::heldChanges(s.mirrorId).size(), 2u);

    // A super admin here retries one (the core still refuses: held again) and discards the other.
    const auto open = ops::mirrors::held(superUser, s.mirrorId, false);
    ASSERT_EQ(open.size(), 2u);
    EXPECT_EQ(ops::mirrors::retryHeld(superUser, open[0].id).state, "retried");
    EXPECT_THROW((void)ops::mirrors::retryHeld(superUser, open[0].id), ops::Conflict) << "once";
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(wire.answersGiven.back().value("code", ""), "denied");
    EXPECT_EQ(ops::mirrors::held(superUser, s.mirrorId, false).size(), 2u) << "refused again: held again";
    EXPECT_EQ(ops::mirrors::held(superUser, s.mirrorId, true).size(), 3u);
    EXPECT_EQ(ops::mirrors::discardHeld(superUser, open[1].id).state, "discarded");
    EXPECT_THROW((void)ops::mirrors::discardHeld(superUser, open[1].id), ops::Conflict);
    EXPECT_EQ(ops::mirrors::held(superUser, s.mirrorId, false).size(), 1u);
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s)) << "neither touched the vault";
}

TEST_F(MirrorSubmitDbTest, ARepeatedSubmitIsAnsweredWithWhatTheCoreDidTheFirstTime) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);

    ops::fs::mkdir(superUser, s.mirrorId, "/docs/once");
    followAll(wire, s);
    expectSettled(s);
    ASSERT_EQ(wire.submits.size(), 1u);
    const auto first = wire.answersGiven[0];
    const auto groupsLogged = coreCount(s, "SELECT count(DISTINCT txid) FROM vault_replication_log WHERE vault_id = " +
                                               std::to_string(s.coreId));

    // The same request again (a lost answer, a restart): answered from the first time, never executed twice.
    const auto repeated = wire.submits[0];
    const auto again = wire.request(corePeer, "peer.mirror.submit", repeated);
    ASSERT_TRUE(again && again->ok);
    EXPECT_EQ(again->data.value("status", ""), "executed");
    EXPECT_EQ(again->data.value("groups", 0u), first.value("groups", 0u));
    EXPECT_EQ(coreCount(s, "SELECT count(DISTINCT txid) FROM vault_replication_log WHERE vault_id = " +
                               std::to_string(s.coreId)),
              groupsLogged);
    EXPECT_EQ(coreCount(s, "SELECT count(*) FROM fs_entry WHERE vault_id = " + std::to_string(s.coreId) +
                               " AND path = '/docs/once'"),
              1);
}

TEST_F(MirrorSubmitDbTest, PendingChangesSurviveARestartAndGoInOrder) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);

    ops::fs::mkdir(superUser, s.mirrorId, "/docs/first");
    ops::fs::mkdir(superUser, s.mirrorId, "/docs/first/second");   // depends on the first
    // A stop while the second was being applied: its row is still local (nothing in memory survives).
    sql("UPDATE mirror_pending SET state = 'local' WHERE vault_id = " + std::to_string(s.mirrorId) +
        " AND op = 'mkdir' AND args ->> 'name' = 'second'");
    // And the first one's answer was lost: submitted, no outcome.
    sql("UPDATE mirror_pending SET state = 'submitted' WHERE vault_id = " + std::to_string(s.mirrorId) +
        " AND args ->> 'name' = 'first'");

    followAll(wire, s);
    expectSettled(s);
    ASSERT_EQ(wire.submits.size(), 2u);
    EXPECT_EQ(wire.submits[0].at("args").value("name", ""), "first") << "in order";
    EXPECT_EQ(wire.submits[1].at("args").value("name", ""), "second");
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths(s));
}

// ---- the gate, and the wire ------------------------------------------------------------------------------------------------

TEST_F(MirrorSubmitDbTest, WithTheLinkDownNothingIsAcceptedAndNothingIsPending) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    // An upload on a Live mirror is let through (its commit is a pending write); with the link down it is refused.
    EXPECT_NO_THROW((void)ops::fs::authorizeUpload(superUser, s.mirrorId, "/docs/u.txt"));
    vh::mirror::access::linkChanged(corePeer, false);
    EXPECT_THROW(ops::fs::mkdir(superUser, s.mirrorId, "/docs/no"), vh::mirror::access::MirrorReadOnly);
    EXPECT_THROW((void)ops::fs::authorizeUpload(superUser, s.mirrorId, "/docs/u.txt"), vh::mirror::access::MirrorReadOnly);
    EXPECT_FALSE(pathsOf(s.mirrorId).contains("/docs/no"));
    EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty());
    vh::mirror::access::linkChanged(corePeer, true);
}

TEST_F(MirrorSubmitDbTest, TheWireAnswersNotFoundToAnyoneButTheVaultsMirrorAndRefusesAnotherServersPerson) {
    auto s = begin([](const EnginePtr& e) { e->mkdir("/docs", superUser); });
    Wire wire(s);
    followAll(wire, s);
    toCore(s);
    {
        AsCore as;
        const json payload{{"vault_uid", s.vaultUid},
                           {"request_id", ms::newRequestId()},
                           {"person", {{"node", ownNode}, {"id", superUser->id}}},
                           {"at", {{"term", 1}, {"seq", 0}}},
                           {"op", "mkdir"},
                           {"entry_uid", "00000000-0000-4000-8000-000000000001"},
                           {"args", {{"parent_uid", s.vaultUid}, {"name", "x"}}}};
        EXPECT_THROW((void)ms::serveSubmit(corePeer, payload), ops::NotFound) << "not the vault's mirror";
        auto other = payload;
        other["vault_uid"] = "00000000-0000-4000-8000-0000000000ff";
        EXPECT_THROW((void)ms::serveSubmit(mirrorPeer, other), ops::NotFound) << "no such vault";
        auto stranger = payload;
        stranger["person"]["node"] = coreNode;
        EXPECT_THROW((void)ms::serveSubmit(mirrorPeer, stranger), ops::Invalid) << "only the mirror's own accounts";
        auto badOp = payload;
        badOp["op"] = "chmod";
        EXPECT_THROW((void)ms::serveSubmit(mirrorPeer, badOp), ops::Invalid);
    }
    toMirror(s);
}

// ---- versions on the mirror (wave 5 piece A) -------------------------------------------------------------------------

// The applier keeps the prior generation of what the core replaces, trashes or deletes, only while the mirror's setting
// is on, bounded by it; the digest never moves for them and nothing of them is logged or submitted.
TEST_F(MirrorSubmitDbTest, VersionsOnTheMirrorKeepWhatTheCoreReplacesOrDeletesOnlyWhenOnAndNeverMoveTheDigest) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "first");
        write(e, "/docs/b.txt", "bee");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    const auto versions = [&](const std::string& reason) {
        return one<int>("SELECT count(*) FROM file_versions WHERE origin = 'version' AND vault_id = " +
                        std::to_string(s.mirrorId) + (reason.empty() ? std::string() : " AND reason = '" + reason + "'"));
    };

    // Off (the default): the core's replacement keeps nothing here.
    coreChange(s, [](const EnginePtr& e) { write(e, "/docs/a.txt", "second"); });
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    EXPECT_EQ(versions(""), 0);

    (void)ops::mirrors::setVersions(superUser, {.vault_id = s.mirrorId, .enabled = true, .keep_last = 2});
    for (const auto* text : {"third", "fourth", "fifth"}) {
        coreChange(s, [text](const EnginePtr& e) { write(e, "/docs/a.txt", text); });
        followAll(wire, s);
        expectSettled(s);   // the digest is the core's: versions are never part of it
        receiveAll(s);
    }
    EXPECT_EQ(versions("overwrite"), 2) << "the prior generations, bounded by keep_last";

    coreChange(s, [](const EnginePtr& e) { ops::fs::remove(superUser, e->vault->id, "/docs/b.txt"); });
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(versions("delete"), 1) << "what the core trashed or deleted is kept here";
    EXPECT_TRUE(mq::Pending::list(s.mirrorId).empty()) << "nothing of them is submitted";
    EXPECT_EQ(one<int>("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(s.mirrorId)), 0);

    // Off again: nothing more is kept.
    (void)ops::mirrors::setVersions(superUser, {.vault_id = s.mirrorId, .enabled = false});
    coreChange(s, [](const EnginePtr& e) { write(e, "/docs/a.txt", "sixth"); });
    followAll(wire, s);
    expectSettled(s);
    EXPECT_EQ(versions(""), 3);
}

// Cost (run by hand: --gtest_also_run_disabled_tests): the applier's time per replacing group with versions off and on.
TEST_F(MirrorSubmitDbTest, DISABLED_VersionsOnTheMirrorCostPerGroup) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        for (int i = 0; i < 20; ++i) write(e, "/docs/f" + std::to_string(i) + ".txt", "zero");
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    const auto measure = [&](const char* label) {
        std::chrono::nanoseconds spent{};
        for (int round = 0; round < 5; ++round) {
            coreChange(s, [round](const EnginePtr& e) {
                for (int i = 0; i < 20; ++i) write(e, "/docs/f" + std::to_string(i) + ".txt", "round " + std::to_string(round));
            });
            const auto t0 = std::chrono::steady_clock::now();
            followAll(wire, s);
            spent += std::chrono::steady_clock::now() - t0;
            receiveAll(s);
        }
        std::printf("[versions cost] %s: %.3f ms per group (100 groups of one replacement)\n", label,
                    std::chrono::duration<double, std::milli>(spent).count() / 100.0);
    };
    measure("off");
    (void)ops::mirrors::setVersions(superUser, {.vault_id = s.mirrorId, .enabled = true, .keep_last = 3});
    measure("on");
}

}
