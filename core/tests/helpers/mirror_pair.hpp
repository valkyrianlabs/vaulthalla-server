#pragma once

// Two servers of one mirrored vault in one process and one database (the capture-and-replay setup of
// test_mirror_submit_db.cpp, shared by the mirror's DB suites): the side that is not acting is parked (its vault uid
// and every entry uid replaced, the originals kept in a table, triggers off) and unparked when it acts again. The core
// is this server under another node id (AsCore). The follower drives everything through a transport (Wire) that, for
// peer.mirror.submit and peer.mirror.resync, turns the core on, serves the request, captures what the core then
// answers and turns the mirror back on; the log and the acknowledgements are answered from what was captured. A
// derived fixture names its database: `static void SetUpTestSuite() { setUpPair("..."); }`.

#include "db_suite.hpp"

#include "audit/Trail.hpp"
#include "crypto/id/ObjectUid.hpp"
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
#include "mirror/resync/Resync.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/submit/Submit.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"
#include "ops/Mirrors.hpp"
#include "ops/Roles.hpp"
#include "ops/Vaults.hpp"
#include "peer/Keys.hpp"
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
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace vh::test_mirror_pair {

using json = nlohmann::json;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace mq = vh::db::query::mirror;
namespace mf = vh::mirror::follow;
namespace ap = vh::mirror::apply;
namespace ms = vh::mirror::submit;
using namespace std::chrono_literals;

inline std::string msTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "s" + std::to_string(n.fetch_add(1));
}

class MirrorPairDb : public vh::test::db::Suite {
protected:
    // The core's row for its mirror (node id: this server's own, as the mirror is) and the mirror's row for its core.
    inline static uint32_t mirrorPeer{};
    inline static uint32_t corePeer{};
    inline static std::string ownNode{};
    inline static std::string coreNode{};

    // The derived fixture's SetUpTestSuite calls this with its suite's database name.
    static void setUpPair(const char* suite) {
        if (!setUpDbSuite(suite)) return;
        // This server's peer wrap key, made before any linked server pins it (as the first pairing does): a suite
        // that delivers keys over the link wraps them to it.
        (void)vh::peer::keys::wrapPublicKey();
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
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        ownNode = vh::db::query::device::Devices::nodeId();
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
            captureBaseline(s);
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

    // The core's baseline as the first copy reads it (every tree page), its position and digest, and the log's answer
    // there. The core is active and this server acts as it.
    static void captureBaseline(Scenario& s) {
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
            if (command == "peer.mirror.resync") {
                toCore(s_);
                std::optional<Answer> out;
                {
                    AsCore as;
                    try {
                        const auto answer = vh::mirror::resync::serveResync(mirrorPeer, payload);
                        captureBaseline(s_);
                        out = Answer{.ok = true, .data = answer};
                    } catch (const ops::Refused& e) {
                        out = Answer{.ok = false, .code = e.code, .error = e.what()};
                    } catch (const ops::NotFound& e) {
                        out = Answer{.ok = false, .code = "not_found", .error = e.what()};
                    }
                }
                toMirror(s_);
                return out;
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

}
