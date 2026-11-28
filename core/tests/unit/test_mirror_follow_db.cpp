// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The server mirror's first copy and following the core (wave 3 piece B; migration 164; design/peers/mirror.md "As
// built: following the core"; db::query::mirror, mirror::apply, mirror::follow). One database holds only one vault of
// a given uid, so the appliers are proven by capture and replay: a vault is built as core (this server under another
// node id, so its accounts arrive on the mirror as another server's), the baseline pages and the log groups are
// captured exactly as peer.mirror.tree and peer.mirror.log answer them, the core vault is retired (its entries gone,
// its uid changed), an empty vault with the same uid becomes this server's mirror, and the follower applies what was
// captured through a transport that replays it.
//
// Covered: a mixed tree with a trash row; every op; a swap and a three-way rename chain in one group; a folder move
// with many descendants served in parts; a cascade delete; a compare-and-set mismatch (diverged, entry named, nothing
// applied); a first copy interrupted after each page and resumed; a group applied twice; a deferred open file; an
// unknown key version; expired; the digest equal to the core's after each step and to a recompute. Serving: another
// peer and a vault not mirrored with it answer not_found; pages never split a group; answers stay within their byte
// bound. The per-vault baseline (no server-wide lock); the trigger deadlock reproduced and fixed; retention moving with
// acknowledgements and held by a mirror that stops acknowledging.

#include "../helpers/db_suite.hpp"

#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/mirror/Apply.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "fs/model/file/Trashed.hpp"
#include "identities/User.hpp"
#include "mirror/Hash.hpp"
#include "mirror/apply/Applier.hpp"
#include "mirror/follow/Follower.hpp"
#include "mirror/follow/Protocol.hpp"
#include "ops/Error.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_mirror_follow {

using json = nlohmann::json;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace mq = vh::db::query::mirror;
namespace mf = vh::mirror::follow;
namespace ap = vh::mirror::apply;
using namespace std::chrono_literals;

std::string mfTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "f" + std::to_string(n.fetch_add(1));
}

// What the core answered, keyed by the request, and its digest at every position it can be acknowledged at.
struct Recorded {
    std::string vaultUid;
    std::map<std::string, json> answers;
    std::map<mq::Position, vh::mirror::Digest> digests;
    std::vector<std::vector<ap::LogGroup>> steps;   // each step's groups, in order
    std::vector<mq::Position> stepEnds;
    mq::Position at{1, 0};

    static std::string key(const std::string& command, const json& payload) { return command + " " + payload.dump(); }
};

// The core, replayed: answers what was recorded, acknowledges against the recorded digests.
class Replay final : public mf::Transport {
public:
    explicit Replay(Recorded& rec) : rec_(rec) {}
    bool up{true};
    std::function<bool(const std::string&, const json&)> drop;   // true: no answer (the link broke)
    std::function<std::optional<Answer>(const std::string&, const json&)> override_;
    std::vector<std::string> misses;
    std::size_t requests{0};

    bool connected(uint32_t) override { return up; }
    std::optional<Answer> request(uint32_t, const std::string& command, const json& payload) override {
        ++requests;
        if (drop && drop(command, payload)) return std::nullopt;
        if (override_)
            if (auto a = override_(command, payload)) return a;
        if (command == "peer.mirror.ack") {
            const mq::Position at{payload.at("term").get<uint64_t>(), payload.at("seq").get<uint64_t>()};
            const auto theirs = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(payload.at("digest").get<std::string>()),
                                                              payload.at("entries").get<int64_t>());
            const auto it = rec_.digests.find(at);
            const bool known = it != rec_.digests.end();
            const bool match = known && it->second == theirs;
            acks.push_back(at);
            return Answer{.ok = true,
                          .data = {{"known", known}, {"match", match}, {"recorded", match},
                                   {"core_digest", known ? json(it->second.hex()) : json(nullptr)},
                                   {"core_entries", known ? json(it->second.entries) : json(nullptr)}}};
        }
        const auto it = rec_.answers.find(Recorded::key(command, payload));
        if (it == rec_.answers.end()) {
            misses.push_back(Recorded::key(command, payload));
            return std::nullopt;
        }
        return Answer{.ok = true, .data = it->second};
    }
    bool notify(uint32_t, const std::string&, const json&) override { return true; }

    std::vector<mq::Position> acks;

private:
    Recorded& rec_;
};

class MirrorFollowDbTest : public vh::test::db::Suite {
protected:
    inline static uint32_t peerId{};
    inline static uint32_t otherPeerId{};
    inline static std::string ownNode{};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_mirror_follow")) return;
        for (auto* id : {&peerId, &otherPeerId}) {
            vh::db::query::peer::NewPeer p;
            p.node_id = "peer-node-" + mfTag();
            p.name = "mirror peer";
            p.spki_sha256 = std::string(64, id == &peerId ? 'a' : 'b');
            p.wrap_public_key.fill(7);
            *id = vh::db::query::peer::Peers::insert(p).id;
        }
    }

    static void TearDownTestSuite() {
        if (!skipTests)
            for (const auto& m : mq::MirrorVaults::list()) (void)mq::MirrorVaults::remove(m.vault_id);
        mf::setAnswerBytesForTesting(0);
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        ownNode = vh::db::query::device::Devices::nodeId();
        mf::setAnswerBytesForTesting(0);
    }

    // ---- helpers

    static void sql(const std::string& statement) {
        db::Transactions::exec("mf sql", [&](pqxx::work& txn) { txn.exec(statement); });
    }
    template <class T>
    static T one(const std::string& statement) {
        return db::Transactions::exec("mf one", [&](pqxx::work& txn) { return txn.exec(statement).one_field().as<T>(); });
    }

    static EnginePtr localVault(const std::string& prefix) {
        const auto v = ops::vaults::create(superUser, {.name = prefix + mfTag(), .type = vault::model::VaultType::Local});
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
        return db::Transactions::exec("mf entry id", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = $2", pqxx::params{vaultId, path});
            return r.empty() ? 0u : r[0][0].as<uint32_t>();
        });
    }

    static std::string uidOf(const uint32_t vaultId, const std::string& path) {
        return db::Transactions::exec("mf uid", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT COALESCE(f.object_uid, d.uid, s.uid)::text FROM fs_entry e "
                                    "LEFT JOIN files f ON f.fs_entry_id = e.id LEFT JOIN directories d ON d.fs_entry_id = e.id "
                                    "LEFT JOIN symlinks s ON s.fs_entry_id = e.id WHERE e.vault_id = $1 AND e.path = $2",
                                    pqxx::params{vaultId, path});
            return r.empty() || r[0][0].is_null() ? std::string{} : r[0][0].as<std::string>();
        });
    }

    static uint32_t symlink(const EnginePtr& engine, const std::string& dir, const std::string& name,
                            const std::string& target) {
        auto link = std::make_shared<fs::model::Symlink>();
        link->vault_id = static_cast<int32_t>(vid(engine));
        link->parent_id = static_cast<int32_t>(entryId(vid(engine), dir));
        link->name = name;
        link->path = (dir == "/" ? "" : dir) + "/" + name;
        link->fuse_path = engine->vaultPathToFusePath(link->path);
        link->base32_alias = "mf" + mfTag();
        link->target = target;
        link->created_by = link->last_modified_by = static_cast<int32_t>(superUser->id);
        return db::query::fs::Symlink::upsertSymlink(link);
    }

    static void trash(const EnginePtr& engine, const std::string& path) {
        fs::Filesystem::remove(engine->vaultPathToFusePath(path), superUser->id);
    }

    static uint32_t trashId(const uint32_t vaultId, const std::string& path) {
        for (const auto& t : db::query::fs::File::listTrashedFiles(vaultId))
            if (t && t->path == path) return t->id;
        return 0;
    }

    // As the manifest applier restores: the file live again under its trashed uid, its trash row ended, one
    // transaction.
    static void restore(const EnginePtr& engine, const std::string& trashedPath, const std::string& to) {
        db::Transactions::exec("mf restore", [&](pqxx::work& txn) {
            const auto t = txn.exec("SELECT id, object_uid::text, size_bytes FROM files_trashed "
                                    "WHERE vault_id = $1 AND path = $2 AND deleted_at IS NULL ORDER BY id DESC LIMIT 1",
                                    pqxx::params{vid(engine), trashedPath}).one_row();
            const auto parent = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = '/'",
                                         pqxx::params{vid(engine)}).one_field().as<uint32_t>();
            const auto id = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, created_by, last_modified_by, path, "
                                     "  mode, base32_alias) VALUES ($1, $2, $3, $4, $4, $5, 420, "
                                     "  substr(md5(random()::text) || md5(random()::text), 1, 33)) RETURNING id",
                                     pqxx::params{vid(engine), parent, to.substr(1), superUser->id, to})
                                .one_field().as<uint32_t>();
            txn.exec("INSERT INTO files (fs_entry_id, size_bytes, content_hash, encryption_iv, "
                     "  encrypted_with_key_version, object_uid) VALUES ($1, $2, $3, '', 0, $4::uuid)",
                     pqxx::params{id, t["size_bytes"].as<int64_t>(), std::string(64, '0'), t["object_uid"].as<std::string>()});
            txn.exec("UPDATE files_trashed SET deleted_at = NOW() WHERE id = $1", pqxx::params{t["id"].as<uint32_t>()});
            db::query::fs::Directory::addToAncestorStats(txn, parent, t["size_bytes"].as<int64_t>(), 1, 0);
        });
    }

    // ---- the core, captured

    // This server acts as another node while it is the core, so its accounts arrive on the mirror as another
    // server's (remote accounts), never as local ones.
    struct AsCore {
        std::string coreNode;
        explicit AsCore(std::string node) : coreNode(std::move(node)) {
            sql("UPDATE device_node SET node_id = '" + coreNode + "' WHERE singleton");
        }
        ~AsCore() { sql("UPDATE device_node SET node_id = '" + ownNode + "' WHERE singleton"); }
    };

    struct Scenario {
        EnginePtr core;
        uint32_t coreId{};
        std::string coreNode{"core-node-" + mfTag()};
        Recorded rec;
        uint32_t mirrorId{};
        EnginePtr mirror;
    };

    static void captureTree(Scenario& s) {
        uint64_t after = 0;
        for (int guard = 0; guard < 10'000; ++guard) {
            const json payload{{"vault_uid", s.rec.vaultUid}, {"after", after}};
            const auto answer = mf::serveTree(peerId, payload);
            s.rec.answers[Recorded::key("peer.mirror.tree", payload)] = answer;
            ASSERT_FALSE(answer.value("expired", false));
            ASSERT_LE(answer.dump().size(), mf::answerBytes()) << "a tree page stays within its byte bound";
            if (!answer.at("items").empty()) after = answer.at("items").back().at("ord").get<uint64_t>();
            if (!answer.value("more", false)) break;
        }
        const auto mv = mq::MirrorVaults::get(s.coreId);
        ASSERT_TRUE(mv && mv->baseline && mv->baseline_digest);
        s.rec.digests[*mv->baseline] = *mv->baseline_digest;
        s.rec.at = *mv->baseline;
    }

    // What the core answers at the position the mirror will be at next (nothing new yet): the follower asks it.
    static void peek(Scenario& s) {
        const json payload{{"vault_uid", s.rec.vaultUid}, {"term", s.rec.at.term}, {"seq", s.rec.at.seq}};
        s.rec.answers[Recorded::key("peer.mirror.log", payload)] = mf::serveLog(peerId, payload);
    }

    // The log from where the last capture stopped, paged as the follower asks for it; each group's end's digest.
    static void captureLog(Scenario& s) {
        (void)mq::Log::sequence(s.coreId);
        std::vector<ap::LogGroup> groups;
        std::optional<ap::LogGroup> partial;
        for (int guard = 0; guard < 100'000; ++guard) {
            json payload{{"vault_uid", s.rec.vaultUid}, {"term", s.rec.at.term}, {"seq", s.rec.at.seq}};
            if (partial) payload["part"] = {{"txid", partial->txid}, {"after_seq", partial->rows.back().seq}};
            const auto answer = mf::serveLog(peerId, payload);
            s.rec.answers[Recorded::key("peer.mirror.log", payload)] = answer;
            ASSERT_FALSE(answer.value("expired", false)) << answer.dump();
            if (answer.contains("part")) {
                auto piece = mf::groupFromJson(answer["part"]);
                if (!partial) partial = piece;
                else
                    for (auto& r : piece.rows) partial->rows.push_back(std::move(r));
                if (!answer["part"].value("complete", false)) continue;
                groups.push_back(*partial);
                s.rec.at = {partial->term, partial->last_seq};
                partial.reset();
                continue;
            }
            EXPECT_LE(answer.dump().size(), mf::answerBytes()) << "a log page stays within its byte bound";
            for (const auto& g : answer.at("groups")) {
                auto group = mf::groupFromJson(g);
                EXPECT_EQ(group.rows.size(), group.last_seq - group.first_seq + 1) << "a page never splits a group";
                EXPECT_EQ(group.first_seq, s.rec.at.seq + 1) << "groups follow each other without a gap";
                s.rec.at = {group.term, group.last_seq};
                groups.push_back(std::move(group));
            }
            if (!answer.value("more", false)) break;
        }
        for (const auto& g : groups) {
            const mq::Position end{g.term, g.last_seq};
            const auto d = mq::MirrorVaults::digestAt(s.coreId, end);
            ASSERT_TRUE(d) << "the core can say its digest at every group's end";
            s.rec.digests[end] = *d;
        }
        const auto mv = mq::MirrorVaults::get(s.coreId);
        ASSERT_TRUE(mv);
        EXPECT_EQ(mv->digest, mq::Digests::recompute(s.coreId)) << "the core's running digest is its tree's";
        s.rec.steps.push_back(std::move(groups));
        s.rec.stepEnds.push_back(s.rec.at);
        peek(s);
    }

    static Scenario begin(const std::function<void(const EnginePtr&)>& build) {
        Scenario s;
        AsCore as(s.coreNode);
        s.core = localVault("mf_core_");
        s.coreId = vid(s.core);
        build(s.core);
        (void)mq::MirrorVaults::startCore(s.coreId, peerId);
        s.rec.vaultUid = *mq::MirrorVaults::vaultUidOf(s.coreId);
        captureTree(s);
        peek(s);
        return s;
    }

    static void step(Scenario& s, const std::function<void(const EnginePtr&)>& change) {
        AsCore as(s.coreNode);
        change(s.core);
        captureLog(s);
    }

    // The core's vault leaves this database (its entries go, its uid changes); an empty vault with its uid becomes
    // this server's mirror of it.
    static void retireAndMirror(Scenario& s) {
        (void)mq::MirrorVaults::remove(s.coreId);
        db::Transactions::exec("mf retire", [&](pqxx::work& txn) {
            txn.exec("DELETE FROM mirror_content_pending WHERE vault_id = $1", pqxx::params{s.coreId});
            txn.exec("DELETE FROM files_trashed WHERE vault_id = $1", pqxx::params{s.coreId});
            txn.exec("DELETE FROM fs_entry WHERE vault_id = $1 AND path <> '/'", pqxx::params{s.coreId});
            txn.exec("ALTER TABLE vault DISABLE TRIGGER vh_uid_immutable");
            txn.exec("UPDATE vault SET uid = gen_random_uuid() WHERE id = $1", pqxx::params{s.coreId});
            txn.exec("ALTER TABLE vault ENABLE TRIGGER vh_uid_immutable");
        });
        s.mirror = localVault("mf_mirror_");
        s.mirrorId = vid(s.mirror);
        db::Transactions::exec("mf mirror uid", [&](pqxx::work& txn) {
            txn.exec("ALTER TABLE vault DISABLE TRIGGER vh_uid_immutable");
            txn.exec("UPDATE vault SET uid = $2::uuid WHERE id = $1", pqxx::params{s.mirrorId, s.rec.vaultUid});
            txn.exec("ALTER TABLE vault ENABLE TRIGGER vh_uid_immutable");
        });
        (void)mq::MirrorVaults::startMirror(s.mirrorId, peerId);
    }

    static mq::MirrorVault mirrorRow(const Scenario& s) {
        const auto mv = mq::MirrorVaults::get(s.mirrorId);
        EXPECT_TRUE(mv);
        return mv.value_or(mq::MirrorVault{});
    }

    // The mirror holds the core's tree as of `at`: its digest, recomputed from its tables too.
    static void expectAt(const Scenario& s, const mq::Position at) {
        const auto mv = mirrorRow(s);
        EXPECT_EQ(mv.position(), at);
        ASSERT_TRUE(s.rec.digests.contains(at));
        EXPECT_EQ(mv.digest, s.rec.digests.at(at)) << "the mirror's digest is the core's at (" << at.term << ", "
                                                   << at.seq << ")";
        EXPECT_EQ(mq::Digests::recompute(s.mirrorId), mv.digest) << "a scrub agrees with the running digest";
        EXPECT_EQ(mq::Digests::stored(s.mirrorId), mv.digest);
    }

    static mf::StepResult follow(Replay& replay, const uint32_t vaultId, const ap::Options& options = {}) {
        return mf::Follower::instance()->step(vaultId, replay, options);
    }

    // Steps until the first copy is finished (bounded).
    static void copyOnly(Replay& replay, const Scenario& s) {
        for (int i = 0; i < 1000 && !mirrorRow(s).copy_finished; ++i) {
            const auto r = follow(replay, s.mirrorId);
            ASSERT_TRUE(r.step == mf::Step::Progress || r.step == mf::Step::CopyFinished)
                << mf::toString(r.step) << " " << r.detail << " " << mirrorRow(s).stop_detail.dump();
        }
        ASSERT_TRUE(mirrorRow(s).copy_finished);
    }

    // Steps until the follower has nothing more (bounded).
    static void followAll(Replay& replay, const Scenario& s) {
        for (int i = 0; i < 1000; ++i) {
            const auto r = follow(replay, s.mirrorId);
            if (r.step == mf::Step::Idle) return;
            ASSERT_TRUE(r.step == mf::Step::Progress || r.step == mf::Step::CopyFinished)
                << mf::toString(r.step) << " " << r.detail << " " << mirrorRow(s).stop_detail.dump();
        }
        FAIL() << "the follower never settled";
    }

    static std::string pathOn(const uint32_t vaultId, const std::string& uid) {
        return db::Transactions::exec("mf path of", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT e.path FROM fs_entry e LEFT JOIN files f ON f.fs_entry_id = e.id "
                                    "LEFT JOIN directories d ON d.fs_entry_id = e.id LEFT JOIN symlinks s ON s.fs_entry_id = e.id "
                                    "WHERE e.vault_id = $1 AND (f.object_uid = $2::uuid OR d.uid = $2::uuid OR s.uid = $2::uuid)",
                                    pqxx::params{vaultId, uid});
            return r.empty() ? std::string{} : r[0][0].as<std::string>();
        });
    }

    static std::set<std::string> pathsOf(const uint32_t vaultId) {
        return db::Transactions::exec("mf paths", [&](pqxx::work& txn) {
            std::set<std::string> out;
            for (const auto row : txn.exec("SELECT path FROM fs_entry WHERE vault_id = $1 AND path <> '/'",
                                           pqxx::params{vaultId}))
                out.insert(row[0].as<std::string>());
            return out;
        });
    }
};

// ---- the first copy ----------------------------------------------------------------------------------------------------

TEST_F(MirrorFollowDbTest, FirstCopyOfAMixedTreeIsTheCoresBaseline) {
    std::set<std::string> corePaths;
    std::string trashedUid;
    mf::setAnswerBytesForTesting(4096);   // several pages
    auto s = begin([&](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        e->mkdir("/docs/sub", superUser);
        e->mkdir("/empty", superUser);
        for (int i = 0; i < 12; ++i) write(e, "/docs/sub/f" + std::to_string(i) + ".txt", "file " + std::to_string(i));
        write(e, "/top.txt", "top");
        write(e, "/gone.txt", "to the trash");
        trashedUid = uidOf(vid(e), "/gone.txt");
        trash(e, "/gone.txt");
        (void)symlink(e, "/docs", "latest", "sub/f1.txt");
        corePaths = pathsOf(vid(e));
    });
    EXPECT_GT(s.rec.answers.size(), 2u) << "the baseline came in several pages";
    retireAndMirror(s);

    Replay replay(s.rec);
    followAll(replay, s);
    EXPECT_TRUE(replay.misses.empty()) << ::testing::PrintToString(replay.misses);
    const auto mv = mirrorRow(s);
    EXPECT_TRUE(mv.copy_finished);
    EXPECT_EQ(mv.state, "live") << mv.stop_detail.dump();
    expectAt(s, s.rec.at);
    EXPECT_EQ(pathsOf(s.mirrorId), corePaths) << "entry for entry";
    EXPECT_EQ(mq::Digests::recompute(s.mirrorId).entries, static_cast<int64_t>(corePaths.size()) + 1)
        << "every live entry and the trashed file";
    EXPECT_EQ(one<int>("SELECT count(*) FROM files_trashed WHERE vault_id = " + std::to_string(s.mirrorId) +
                       " AND deleted_at IS NULL AND object_uid = '" + trashedUid + "'"),
              1);
    ASSERT_FALSE(replay.acks.empty());
    EXPECT_EQ(replay.acks.back(), s.rec.at) << "the first copy is acknowledged at the baseline";
    EXPECT_EQ(mv.acked, std::optional<mq::Position>(s.rec.at));

    // Accounts arrive as {node, id}: the core's are another server's here, remote accounts, never local ones.
    const auto remote = one<int>("SELECT count(*) FROM users WHERE remote AND home_node = '" + s.coreNode +
                                 "' AND home_id = " + std::to_string(superUser->id));
    EXPECT_EQ(remote, 1);
    EXPECT_EQ(one<int>("SELECT count(*) FROM fs_entry e JOIN users u ON u.id = e.created_by WHERE e.vault_id = " +
                       std::to_string(s.mirrorId) + " AND e.path <> '/' AND NOT u.remote"),
              0)
        << "no entry is attributed to a local account";

    // Every file's contents are expected (wave 2's lane fetches them), none fetched here.
    EXPECT_EQ(mq::PendingContents::countOutstanding(s.mirrorId), 13u) << "every live file (not the trashed one)";
}

// A folder's modification time is outside its entry hash (a totals stamp, moved by every write below it), so a change
// of it alone is never logged. It still travels in the folder's state (migration 173, folder_modified_at): the first
// copy gives every folder the core's time and keeps it while it adds what is below (in later pages too), and a folder
// the log creates arrives with its time. Listings on the mirror show the core's times, not when the mirror made them.
TEST_F(MirrorFollowDbTest, FolderTimesAreTheCoresAndAFolderTimeAloneIsNeverLogged) {
    const auto folderTimes = [](const uint32_t vaultId) {
        return db::Transactions::exec("mf folder times", [&](pqxx::work& txn) {
            std::map<std::string, int64_t> out;
            for (const auto row : txn.exec("SELECT e.path, vh_mirror_micros(e.updated_at) FROM fs_entry e "
                                           "JOIN directories d ON d.fs_entry_id = e.id "
                                           "WHERE e.vault_id = $1 AND e.path <> '/'",
                                           pqxx::params{vaultId}))
                out[row[0].as<std::string>()] = row[1].as<int64_t>();
            return out;
        });
    };
    // As a dated write sets it (vh.keep_mtime): a time the mirror could not have made itself.
    const auto setFolderTime = [](const uint32_t vaultId, const std::string& path, const std::string& at) {
        db::Transactions::exec("mf folder time", [&](pqxx::work& txn) {
            txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
            txn.exec("UPDATE fs_entry SET updated_at = $3::timestamptz WHERE vault_id = $1 AND path = $2",
                     pqxx::params{vaultId, path, at});
        });
    };

    mf::setAnswerBytesForTesting(2048);   // several pages: folders and what is below them in different ones
    std::map<std::string, int64_t> core;
    auto s = begin([&](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        e->mkdir("/docs/sub", superUser);
        e->mkdir("/empty", superUser);
        for (int i = 0; i < 8; ++i) write(e, "/docs/sub/f" + std::to_string(i) + ".txt", "file " + std::to_string(i));
        write(e, "/docs/top.txt", "top");
        setFolderTime(vid(e), "/docs", "2021-03-04 05:06:07.123456+00");
        setFolderTime(vid(e), "/docs/sub", "2022-04-05 06:07:08.234567+00");
        setFolderTime(vid(e), "/empty", "2023-05-06 07:08:09.345678+00");
        core = folderTimes(vid(e));
    });
    EXPECT_GT(s.rec.answers.size(), 2u) << "the baseline came in several pages";
    // Only a folder's time: no row, so nothing to apply and no digest change.
    step(s, [&](const EnginePtr& e) { setFolderTime(vid(e), "/docs", "2024-06-07 08:09:10+00"); });
    EXPECT_TRUE(s.rec.steps.back().empty()) << "a folder-time-only change writes no log row";
    // A folder the log creates carries its time.
    step(s, [&](const EnginePtr& e) {
        e->mkdir("/later", superUser);
        core["/later"] = folderTimes(vid(e)).at("/later");
    });
    EXPECT_FALSE(s.rec.steps.back().empty());

    retireAndMirror(s);
    Replay replay(s.rec);
    copyOnly(replay, s);
    auto mirror = folderTimes(s.mirrorId);
    for (const auto* path : {"/docs", "/docs/sub", "/empty"})
        EXPECT_EQ(mirror.at(path), core.at(path)) << path << " has the core's time after the copy";
    followAll(replay, s);
    EXPECT_TRUE(replay.misses.empty()) << ::testing::PrintToString(replay.misses);
    expectAt(s, s.rec.at);
    mirror = folderTimes(s.mirrorId);
    EXPECT_EQ(mirror.at("/later"), core.at("/later")) << "a folder the log created has the core's time";
    EXPECT_EQ(mirror.at("/docs"), core.at("/docs")) << "the core's later folder-time-only change never traveled";
}

TEST_F(MirrorFollowDbTest, FirstCopyInterruptedAfterEachPageResumesExactly) {
    mf::setAnswerBytesForTesting(2048);
    auto s = begin([&](const EnginePtr& e) {
        e->mkdir("/a", superUser);
        for (int i = 0; i < 20; ++i) write(e, "/a/n" + std::to_string(i), std::to_string(i));
    });
    retireAndMirror(s);
    Replay replay(s.rec);
    // Every other tree request breaks the link: the follower waits, then resumes after the page it applied.
    int n = 0;
    replay.drop = [&](const std::string& command, const json&) { return command == "peer.mirror.tree" && n++ % 2 == 1; };
    std::vector<uint64_t> cursors;
    for (int i = 0; i < 200 && !mirrorRow(s).copy_finished; ++i) {
        const auto r = follow(replay, s.mirrorId);
        ASSERT_TRUE(r.step == mf::Step::Waiting || r.step == mf::Step::Progress || r.step == mf::Step::CopyFinished)
            << mf::toString(r.step) << " " << r.detail;
        cursors.push_back(mirrorRow(s).copy_cursor);
    }
    EXPECT_TRUE(mirrorRow(s).copy_finished);
    EXPECT_GT(cursors.size(), 3u);
    EXPECT_TRUE(std::ranges::is_sorted(cursors)) << "the cursor never moves back";
    EXPECT_TRUE(replay.misses.empty()) << ::testing::PrintToString(replay.misses);
    expectAt(s, s.rec.at);

    // A page applied twice is applied once.
    const auto first = mf::treePageFromJson(
        s.rec.answers.at(Recorded::key("peer.mirror.tree", {{"vault_uid", s.rec.vaultUid}, {"after", 0}})));
    const auto again = ap::applyTreePage(s.mirrorId, first);
    EXPECT_EQ(again.status, ap::Status::AlreadyApplied);
    expectAt(s, s.rec.at);
}

// ---- following the log -----------------------------------------------------------------------------------------------

TEST_F(MirrorFollowDbTest, EveryOperationFollowsWithTheCoresDigestAtEachStep) {
    std::map<std::string, std::string> uid;
    auto s = begin([&](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        write(e, "/docs/a.txt", "first");
        uid["a"] = uidOf(vid(e), "/docs/a.txt");
    });
    step(s, [&](const EnginePtr& e) { write(e, "/docs/a.txt", "second, longer"); });            // upsert (content)
    step(s, [&](const EnginePtr& e) {                                                            // move, rename
        e->mkdir("/box", superUser);
        e->rename("/docs/a.txt", "/docs/b.txt", superUser);
        e->move("/docs/b.txt", "/box/b.txt", superUser);
        e->copy("/box/b.txt", "/docs/c.txt", superUser->id, {});
        uid["c"] = uidOf(vid(e), "/docs/c.txt");
    });
    step(s, [&](const EnginePtr& e) {                                                            // attributes
        (void)symlink(e, "/docs", "latest", "c.txt");
        sql("UPDATE fs_entry SET mode = 384 WHERE id = " + std::to_string(entryId(vid(e), "/docs/c.txt")));
        db::Transactions::exec("mf owner", [&](pqxx::work& txn) {
            txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
            txn.exec("UPDATE fs_entry SET owner_uid = 4242, group_gid = 4343, is_hidden = true WHERE id = $1",
                     pqxx::params{entryId(vid(e), "/docs/c.txt")});
        });
        sql("UPDATE symlinks SET target = 'b.txt' WHERE fs_entry_id = " + std::to_string(entryId(vid(e), "/docs/latest")));
    });
    step(s, [&](const EnginePtr& e) { trash(e, "/docs/c.txt"); });                              // trash
    step(s, [&](const EnginePtr& e) { restore(e, "/docs/c.txt", "/c.txt"); });                  // restore
    step(s, [&](const EnginePtr& e) {                                                            // trash, purge
        write(e, "/p.txt", "to purge");
        trash(e, "/p.txt");
        db::query::fs::File::markTrashedFileDeleted(trashId(vid(e), "/p.txt"));
    });
    step(s, [&](const EnginePtr& e) {                                                            // delete
        // Removed without the trash, by hand (as psql would; the log records it like any delete).
        sql("DELETE FROM fs_entry WHERE id = " + std::to_string(entryId(vid(e), "/docs/latest")));
    });
    step(s, [&](const EnginePtr& e) {                                                            // vault
        (void)ops::vaults::update(superUser, {.id = vid(e), .description = std::string("mirrored ") + mfTag(),
                                              .quota = uintmax_t{987654321}});
    });
    const auto finalPaths = [&] {
        AsCore as(s.coreNode);
        return pathsOf(s.coreId);
    }();
    std::set<std::string> ops;
    for (const auto& st : s.rec.steps)
        for (const auto& g : st)
            for (const auto& r : g.rows) ops.insert(r.op);
    for (const auto* op : {"upsert", "move", "trash", "restore", "purge", "delete", "vault"})
        EXPECT_TRUE(ops.contains(op)) << op << " is driven: " << ::testing::PrintToString(ops);

    retireAndMirror(s);
    Replay replay(s.rec);
    copyOnly(replay, s);
    expectAt(s, s.rec.digests.begin()->first);
    for (std::size_t i = 0; i < s.rec.steps.size(); ++i) {
        SCOPED_TRACE("step " + std::to_string(i));
        for (const auto& g : s.rec.steps[i]) {
            const auto r = ap::applyGroup(s.mirrorId, g);
            ASSERT_EQ(r.status, ap::Status::Applied) << r.reason << " " << r.detail.dump();
        }
        expectAt(s, s.rec.stepEnds[i]);
        // A group applied twice is applied once.
        if (!s.rec.steps[i].empty()) {
            const auto again = ap::applyGroup(s.mirrorId, s.rec.steps[i].back());
            EXPECT_EQ(again.status, ap::Status::AlreadyApplied);
            expectAt(s, s.rec.stepEnds[i]);
        }
    }
    EXPECT_EQ(pathsOf(s.mirrorId), finalPaths);
    EXPECT_EQ(pathOn(s.mirrorId, uid["a"]), "/box/b.txt") << "found by uid, moved";
    EXPECT_EQ(pathOn(s.mirrorId, uid["c"]), "/c.txt") << "restored under its uid";
    EXPECT_EQ(one<std::string>("SELECT description FROM vault WHERE id = " + std::to_string(s.mirrorId)).rfind("mirrored ", 0),
              0u);
    EXPECT_EQ(one<int64_t>("SELECT quota FROM vault WHERE id = " + std::to_string(s.mirrorId)), 987654321);
    EXPECT_EQ(one<int>("SELECT count(*) FROM mirror_vault WHERE vault_id = " + std::to_string(s.mirrorId) +
                       " AND vault_state ->> 'quota' = '987654321'"),
              1)
        << "the vault document is recorded";
    EXPECT_EQ(mirrorRow(s).state, "live");

    // The fs_change_log fired for this server's own clients.
    EXPECT_GT(one<int>("SELECT count(*) FROM fs_change_log WHERE vault_id = " + std::to_string(s.mirrorId)), 0);
}

TEST_F(MirrorFollowDbTest, SwapsAndRenameChainsInOneGroupGoThroughTemporaryNames) {
    std::map<std::string, std::string> uid;
    auto s = begin([&](const EnginePtr& e) {
        for (const auto* n : {"x", "y", "p", "q", "r"}) {
            write(e, std::string("/") + n, n);
            uid[n] = uidOf(vid(e), std::string("/") + n);
        }
    });
    step(s, [&](const EnginePtr& e) {
        // One transaction: x <-> y swapped, and p -> q -> r -> p (a three-way chain), through names of the core's own.
        db::Transactions::exec("mf swap", [&](pqxx::work& txn) {
            const auto rename = [&](const std::string& from, const std::string& to) {
                txn.exec("UPDATE fs_entry SET name = $3::text, path = '/' || $3::text "
                         "WHERE vault_id = $1 AND path = '/' || $2::text",
                         pqxx::params{vid(e), from, to});
            };
            rename("x", "tmp1");
            rename("y", "x");
            rename("tmp1", "y");
            rename("p", "tmp2");
            rename("r", "p");
            rename("q", "r");
            rename("tmp2", "q");
        });
    });
    ASSERT_EQ(s.rec.steps.back().size(), 1u) << "one transaction, one group";
    retireAndMirror(s);
    Replay replay(s.rec);
    followAll(replay, s);
    EXPECT_TRUE(replay.misses.empty()) << ::testing::PrintToString(replay.misses);
    expectAt(s, s.rec.stepEnds.back());
    EXPECT_EQ(pathOn(s.mirrorId, uid["x"]), "/y");
    EXPECT_EQ(pathOn(s.mirrorId, uid["y"]), "/x");
    EXPECT_EQ(pathOn(s.mirrorId, uid["p"]), "/q");
    EXPECT_EQ(pathOn(s.mirrorId, uid["q"]), "/r");
    EXPECT_EQ(pathOn(s.mirrorId, uid["r"]), "/p");
    EXPECT_EQ(one<int>("SELECT count(*) FROM fs_entry WHERE vault_id = " + std::to_string(s.mirrorId) +
                       " AND name LIKE '.vh-mirror-%'"),
              0)
        << "no temporary name is left";
}

TEST_F(MirrorFollowDbTest, AFolderMoveWithManyDescendantsComesInPartsAndAppliesWhole) {
    mf::setAnswerBytesForTesting(16 * 1024);
    std::string big;
    auto s = begin([&](const EnginePtr& e) {
        e->mkdir("/big", superUser);
        e->mkdir("/big/deep", superUser);
        e->mkdir("/box", superUser);
        for (int i = 0; i < 60; ++i) write(e, "/big/deep/f" + std::to_string(i), std::to_string(i));
        big = uidOf(vid(e), "/big");
    });
    step(s, [&](const EnginePtr& e) { e->move("/big", "/box/big", superUser); });
    std::size_t parts = 0;
    for (const auto& [k, a] : s.rec.answers)
        if (a.contains("part")) ++parts;
    EXPECT_GE(parts, 2u) << "the group was larger than an answer";
    ASSERT_EQ(s.rec.steps.back().size(), 1u);
    EXPECT_GT(s.rec.steps.back().front().rows.size(), 60u);
    retireAndMirror(s);
    Replay replay(s.rec);
    followAll(replay, s);
    EXPECT_TRUE(replay.misses.empty()) << ::testing::PrintToString(replay.misses);
    expectAt(s, s.rec.stepEnds.back());
    EXPECT_EQ(pathOn(s.mirrorId, big), "/box/big");
    EXPECT_EQ(entryId(s.mirrorId, "/big/deep/f7"), 0u);
    EXPECT_NE(entryId(s.mirrorId, "/box/big/deep/f7"), 0u) << "every path under the folder moved with it";
}

TEST_F(MirrorFollowDbTest, ACascadeDeleteRemovesTheWholeFolder) {
    auto s = begin([&](const EnginePtr& e) {
        e->mkdir("/tree", superUser);
        e->mkdir("/tree/a", superUser);
        e->mkdir("/tree/a/b", superUser);
        (void)symlink(e, "/tree/a/b", "l", "x");
        e->mkdir("/keep", superUser);
    });
    step(s, [&](const EnginePtr& e) { db::query::fs::Directory::deleteDirectoryTree(entryId(vid(e), "/tree")); });
    retireAndMirror(s);
    Replay replay(s.rec);
    followAll(replay, s);
    expectAt(s, s.rec.stepEnds.back());
    EXPECT_EQ(pathsOf(s.mirrorId), (std::set<std::string>{"/keep"}));
}

// ---- refusals ----------------------------------------------------------------------------------------------------------

TEST_F(MirrorFollowDbTest, ACompareAndSetMismatchDivergesNamingTheEntryAndAppliesNothing) {
    std::map<std::string, std::string> uid;
    auto s = begin([&](const EnginePtr& e) {
        write(e, "/one", "1");
        write(e, "/two", "2");
        uid["one"] = uidOf(vid(e), "/one");
        uid["two"] = uidOf(vid(e), "/two");
    });
    step(s, [&](const EnginePtr& e) {
        db::Transactions::exec("mf both", [&](pqxx::work& txn) {
            txn.exec("UPDATE fs_entry SET name = 'one-renamed', path = '/one-renamed' "
                     "WHERE vault_id = $1 AND path = '/one'",
                     pqxx::params{vid(e)});
            txn.exec("UPDATE fs_entry SET name = 'two-renamed', path = '/two-renamed' WHERE vault_id = $1 AND path = '/two'",
                     pqxx::params{vid(e)});
        });
    });
    retireAndMirror(s);
    Replay replay(s.rec);
    copyOnly(replay, s);
    const auto before = mirrorRow(s);
    // This server's copy of /two is not the one the core changed.
    sql("UPDATE mirror_entry_hash SET entry_hash = decode(repeat('ab', 32), 'hex') WHERE vault_id = " +
        std::to_string(s.mirrorId) + " AND entry_uid = '" + uid["two"] + "'");
    const auto r = ap::applyGroup(s.mirrorId, s.rec.steps.back().front());
    EXPECT_EQ(r.status, ap::Status::Diverged);
    const auto after = mirrorRow(s);
    EXPECT_EQ(after.state, "diverged");
    EXPECT_EQ(after.stop_reason.value_or(""), "mirror_compare_mismatch");
    EXPECT_EQ(after.stop_detail.value("uid", std::string{}), uid["two"]) << after.stop_detail.dump();
    std::string tampered;
    for (int i = 0; i < 32; ++i) tampered += "ab";
    EXPECT_EQ(after.stop_detail.value("found", std::string{}), tampered) << "both hashes are recorded";
    EXPECT_TRUE(after.stop_detail.contains("expected"));
    EXPECT_EQ(after.position(), before.position()) << "nothing of the group applied";
    EXPECT_EQ(pathOn(s.mirrorId, uid["one"]), "/one") << "not half applied";
    // Stopped: the follower leaves it alone.
    EXPECT_EQ(follow(replay, s.mirrorId).step, mf::Step::Stopped);
}

TEST_F(MirrorFollowDbTest, AFileOpenHereMakesTheWholeGroupWait) {
    std::string a;
    auto s = begin([&](const EnginePtr& e) {
        write(e, "/a", "1");
        write(e, "/b", "1");
        a = uidOf(vid(e), "/a");
    });
    step(s, [&](const EnginePtr& e) {
        write(e, "/b", "b changes, one group");
        trash(e, "/a");
    });
    retireAndMirror(s);
    Replay replay(s.rec);
    copyOnly(replay, s);
    const auto inode = one<int64_t>("SELECT COALESCE(inode, 0) FROM fs_entry WHERE id = " +
                                    std::to_string(entryId(s.mirrorId, "/a")));
    bool open = true;
    const ap::Options opts{.isOpen = [&](const uint64_t ino) { return open && (inode == 0 || ino == static_cast<uint64_t>(inode)); }};
    const auto r = follow(replay, s.mirrorId, opts);
    EXPECT_EQ(r.step, mf::Step::Waiting) << r.detail;
    EXPECT_LT(mirrorRow(s).position(), s.rec.stepEnds.back()) << "the group that trashes the open file waits";
    EXPECT_NE(entryId(s.mirrorId, "/a"), 0u);
    EXPECT_EQ(mirrorRow(s).state, "live");
    for (const auto& g : s.rec.steps.back()) {
        const auto again = ap::applyGroup(s.mirrorId, g, opts);
        EXPECT_TRUE(again.status == ap::Status::AlreadyApplied || again.status == ap::Status::Deferred)
            << ap::toString(again.status);
    }
    EXPECT_NE(entryId(s.mirrorId, "/a"), 0u);
    open = false;   // closed: the group applies
    for (const auto& g : s.rec.steps.back()) {
        const auto done = ap::applyGroup(s.mirrorId, g, opts);
        EXPECT_TRUE(done.status == ap::Status::AlreadyApplied || done.status == ap::Status::Applied)
            << ap::toString(done.status) << " " << done.reason;
    }
    expectAt(s, s.rec.stepEnds.back());
    EXPECT_EQ(entryId(s.mirrorId, "/a"), 0u) << "finished once it closed";
}

TEST_F(MirrorFollowDbTest, AKeyVersionThisServerDoesNotHoldStopsTheVault) {
    auto s = begin([&](const EnginePtr& e) { write(e, "/a", "1"); });
    retireAndMirror(s);
    Replay replay(s.rec);
    followAll(replay, s);
    ap::LogGroup g{.term = s.rec.at.term, .txid = 99, .first_seq = s.rec.at.seq + 1, .last_seq = s.rec.at.seq + 1};
    g.rows.push_back({.seq = g.first_seq, .op = "key", .state = {{"v", 1}, {"version", 99}, {"key_check", "x"}}});
    const auto r = ap::applyGroup(s.mirrorId, g);
    EXPECT_EQ(r.status, ap::Status::Stopped);
    const auto mv = mirrorRow(s);
    EXPECT_EQ(mv.state, "stopped");
    EXPECT_EQ(mv.stop_reason.value_or(""), "mirror_key_missing");
    EXPECT_EQ(mv.stop_detail.value("version", 0), 99);
    EXPECT_EQ(mv.position(), s.rec.at);
}

TEST_F(MirrorFollowDbTest, ExpiredStopsTheVaultWithoutLooping) {
    auto s = begin([&](const EnginePtr& e) { write(e, "/a", "1"); });
    retireAndMirror(s);
    Replay replay(s.rec);
    followAll(replay, s);
    replay.override_ = [](const std::string& command, const json&) -> std::optional<mf::Transport::Answer> {
        if (command == "peer.mirror.log") return mf::Transport::Answer{.ok = true, .data = {{"expired", true}}};
        return std::nullopt;
    };
    const auto r = follow(replay, s.mirrorId);
    EXPECT_EQ(r.step, mf::Step::Stopped);
    EXPECT_EQ(mirrorRow(s).state, "expired");
    EXPECT_EQ(mirrorRow(s).stop_reason.value_or(""), "mirror_log_expired");
    const auto asked = replay.requests;
    EXPECT_EQ(follow(replay, s.mirrorId).step, mf::Step::Stopped);
    EXPECT_EQ(replay.requests, asked) << "a stopped vault asks nothing";

    // The core no longer mirroring the vault with this server: the lane's not_found, the same stop.
    auto t = begin([&](const EnginePtr& e) { write(e, "/b", "1"); });
    retireAndMirror(t);
    Replay gone(t.rec);
    gone.override_ = [](const std::string&, const json&) -> std::optional<mf::Transport::Answer> {
        return mf::Transport::Answer{.ok = false, .code = "not_found", .error = "Not found"};
    };
    EXPECT_EQ(follow(gone, t.mirrorId).step, mf::Step::Stopped);
    EXPECT_EQ(mirrorRow(t).state, "expired");
    EXPECT_EQ(mirrorRow(t).stop_reason.value_or(""), "mirror_core_gone");
}

TEST_F(MirrorFollowDbTest, TheFollowerStopsCleanlyWhenItsRowGoes) {
    auto s = begin([&](const EnginePtr& e) { write(e, "/a", "1"); });
    retireAndMirror(s);
    Replay replay(s.rec);
    (void)mq::MirrorVaults::remove(s.mirrorId);
    EXPECT_EQ(follow(replay, s.mirrorId).step, mf::Step::Gone);
    EXPECT_EQ(replay.requests, 0u);
    replay.up = false;
    (void)mq::MirrorVaults::startMirror(s.mirrorId, peerId);
    EXPECT_EQ(follow(replay, s.mirrorId).step, mf::Step::Waiting) << "the link down: nothing asked";
    EXPECT_EQ(replay.requests, 0u);
}

// ---- serving -----------------------------------------------------------------------------------------------------------

TEST_F(MirrorFollowDbTest, ServingAnswersNotFoundToAnyoneButTheVaultsMirror) {
    AsCore as("core-node-" + mfTag());
    const auto core = localVault("mf_serve_");
    write(core, "/a", "1");
    (void)mq::MirrorVaults::startCore(vid(core), peerId);
    const auto uid = *mq::MirrorVaults::vaultUidOf(vid(core));
    const auto plain = localVault("mf_plain_");
    const auto plainUid = *mq::MirrorVaults::vaultUidOf(vid(plain));

    const auto expectNotFound = [](const std::function<json()>& f, const std::string& what) {
        try {
            (void)f();
            ADD_FAILURE() << what << " answered";
        } catch (const ops::NotFound& e) {
            EXPECT_STREQ(e.what(), "Not found") << what << ": the sealed lane's answer";
        }
    };
    for (const auto& [caller, vaultUid, what] :
         std::vector<std::tuple<uint32_t, std::string, std::string>>{{otherPeerId, uid, "another linked server"},
                                                                    {peerId, plainUid, "a vault not mirrored"},
                                                                    {peerId, "00000000-0000-0000-0000-000000000000", "no such vault"},
                                                                    {peerId, "not-a-uuid", "not a uid"}}) {
        expectNotFound([&] { return mf::serveTree(caller, {{"vault_uid", vaultUid}, {"after", 0}}); }, what + " (tree)");
        expectNotFound([&] { return mf::serveLog(caller, {{"vault_uid", vaultUid}, {"term", 1}, {"seq", 0}}); },
                       what + " (log)");
        expectNotFound([&] {
            return mf::serveAck(caller, {{"vault_uid", vaultUid}, {"term", 1}, {"seq", 0},
                                         {"digest", std::string(64, '0')}, {"entries", 0}});
        }, what + " (ack)");
    }
    // The core's own role: a notice for a vault this server is the core of is not this server's to take.
    expectNotFound([&] { return mf::receiveNotify(peerId, {{"vault_uid", uid}, {"term", 1}, {"seq", 1}}); }, "notify (core)");
    EXPECT_NO_THROW((void)mf::serveTree(peerId, {{"vault_uid", uid}, {"after", 0}}));
    (void)mq::MirrorVaults::remove(vid(core));
}

TEST_F(MirrorFollowDbTest, AcknowledgementsCompareDigestsAndRetentionFollowsThem) {
    AsCore as("core-node-" + mfTag());
    const auto core = localVault("mf_ack_");
    write(core, "/a", "1");
    const auto start = mq::MirrorVaults::startCore(vid(core), peerId);
    const auto uid = *mq::MirrorVaults::vaultUidOf(vid(core));
    for (int i = 0; i < 5; ++i) write(core, "/f" + std::to_string(i), std::to_string(i));
    (void)mq::Log::sequence(vid(core));
    const auto rows = [&] { return one<int>("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(vid(core))); };
    const auto n = rows();
    ASSERT_GT(n, 0);

    // Nothing acknowledged: retention keeps everything, however old.
    (void)mq::Log::prune(std::chrono::seconds(0), 0);
    EXPECT_EQ(rows(), n);

    // The baseline acknowledged with its digest: recorded, the baseline dropped.
    ASSERT_TRUE(start.baseline && start.baseline_digest);
    auto ack = mf::serveAck(peerId, {{"vault_uid", uid}, {"term", start.baseline->term}, {"seq", start.baseline->seq},
                                     {"digest", start.baseline_digest->hex()}, {"entries", start.baseline_digest->entries}});
    EXPECT_TRUE(ack["match"].get<bool>()) << ack.dump();
    EXPECT_EQ(mf::serveTree(peerId, {{"vault_uid", uid}, {"after", 0}}).value("expired", false), true)
        << "the baseline goes with the first acknowledgement";

    // Half the log acknowledged: retention moves to it and no further; a mirror that stops acknowledging holds the rest.
    const auto page = mq::Log::groupsAfter(vid(core), *start.baseline, 10'000);
    ASSERT_GE(page.groups.size(), 4u);
    const auto& mid = page.groups[page.groups.size() / 2];
    const mq::Position midAt{mid.term, mid.last_seq};
    const auto midDigest = *mq::MirrorVaults::digestAt(vid(core), midAt);
    ack = mf::serveAck(peerId, {{"vault_uid", uid}, {"term", midAt.term}, {"seq", midAt.seq},
                                {"digest", midDigest.hex()}, {"entries", midDigest.entries}});
    EXPECT_TRUE(ack["recorded"].get<bool>()) << ack.dump();
    (void)mq::Log::prune(std::chrono::seconds(0), 0);
    EXPECT_EQ(rows(), static_cast<int>(page.last.seq - midAt.seq)) << "retention reached the acknowledgement, not past";
    for (int i = 0; i < 3; ++i) write(core, "/g" + std::to_string(i), std::to_string(i));
    (void)mq::Log::sequence(vid(core));
    const auto held = rows();
    (void)mq::Log::prune(std::chrono::seconds(0), 0);
    EXPECT_EQ(rows(), held) << "a mirror that stops acknowledging holds the log (known limit)";

    // A repeated acknowledgement below what was recorded is answered as matching, without moving anything back.
    ack = mf::serveAck(peerId, {{"vault_uid", uid}, {"term", start.baseline->term}, {"seq", start.baseline->seq},
                                {"digest", start.baseline_digest->hex()}, {"entries", start.baseline_digest->entries}});
    EXPECT_TRUE(ack["match"].get<bool>());
    EXPECT_FALSE(ack["recorded"].get<bool>());

    // A digest that is not the core's at that position stops the vault as diverged here.
    const auto& last = page.groups.back();
    ack = mf::serveAck(peerId, {{"vault_uid", uid}, {"term", last.term}, {"seq", last.last_seq},
                                {"digest", std::string(64, 'e')}, {"entries", 3}});
    EXPECT_FALSE(ack["match"].get<bool>());
    EXPECT_TRUE(ack["known"].get<bool>());
    const auto mv = mq::MirrorVaults::get(vid(core));
    EXPECT_EQ(mv->state, "diverged");
    EXPECT_EQ(mv->stop_reason.value_or(""), "mirror_digest_mismatch");
    EXPECT_EQ(mv->acked, std::optional<mq::Position>(midAt)) << "a mismatch records nothing";
    (void)mq::MirrorVaults::remove(vid(core));
}

// ---- the baseline: per vault ---------------------------------------------------------------------------------------------

TEST_F(MirrorFollowDbTest, StartingACoreNeverHoldsUpAnotherVaultsWriters) {
    const auto a = localVault("mf_a_");
    const auto b = localVault("mf_b_");
    write(a, "/x", "a");
    write(b, "/y", "b");
    const auto bEntry = entryId(vid(b), "/y");

    // A writer of vault B is running (uncommitted) when the start begins: the start waits for it, B's other writers
    // do not wait for the start.
    std::promise<void> holding, release;
    auto releaseF = release.get_future().share();
    auto writer = std::async(std::launch::async, [&] {
        db::Transactions::exec("mf open writer", [&](pqxx::work& txn) {
            txn.exec("UPDATE fs_entry SET mode = 416 WHERE id = $1", pqxx::params{bEntry});
            holding.set_value();
            releaseF.wait();
        });
    });
    holding.get_future().wait();
    const auto t0 = std::chrono::steady_clock::now();
    auto start = std::async(std::launch::async, [&] { return mq::MirrorVaults::startCore(vid(a), peerId); });
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(start.wait_for(0ms), std::future_status::timeout) << "the start waits for a writer already running";

    // Another writer of vault B while the start runs: never waits for it (the server-wide SHARE lock made it wait).
    const auto w0 = std::chrono::steady_clock::now();
    write(b, "/z", "a write of another vault");
    EXPECT_LT(std::chrono::steady_clock::now() - w0, 2s);
    EXPECT_EQ(start.wait_for(0ms), std::future_status::timeout);

    release.set_value();
    writer.get();
    const auto mv = start.get();
    EXPECT_LT(std::chrono::steady_clock::now() - t0, 10s);
    EXPECT_EQ(mv.state, "live");
    ASSERT_TRUE(mv.baseline_digest);
    EXPECT_EQ(*mv.baseline_digest, mq::Digests::recompute(vid(a)));

    // A write of the core vault after its baseline is logged, once.
    write(a, "/x", "after the baseline");
    (void)mq::Log::sequence(vid(a));
    const auto after = mq::MirrorVaults::get(vid(a));
    EXPECT_EQ(after->digest, mq::Digests::recompute(vid(a)));
    EXPECT_GT(after->last_seq, 0u);
    (void)mq::MirrorVaults::remove(vid(a));
}

TEST_F(MirrorFollowDbTest, AWriterOfTheVaultDuringTheBaselineIsInItOrLoggedNeverBoth) {
    const auto a = localVault("mf_race_");
    for (int i = 0; i < 200; ++i) write(a, "/f" + std::to_string(i), std::to_string(i));
    std::atomic<bool> stop{false};
    std::atomic<int> writes{0};
    auto writer = std::async(std::launch::async, [&] {
        for (int i = 0; !stop.load(); ++i) {
            write(a, "/f" + std::to_string(i % 200), "rewritten " + std::to_string(i));
            ++writes;
        }
    });
    std::this_thread::sleep_for(100ms);
    (void)mq::MirrorVaults::startCore(vid(a), peerId);
    std::this_thread::sleep_for(200ms);
    stop.store(true);
    writer.get();
    EXPECT_GT(writes.load(), 0);
    (void)mq::Log::sequence(vid(a));
    const auto mv = mq::MirrorVaults::get(vid(a));
    EXPECT_EQ(mv->digest, mq::Digests::recompute(vid(a))) << "baseline plus log is the tree: no change lost or doubled";
    EXPECT_EQ(mq::Digests::stored(vid(a)), mv->digest);
    (void)mq::MirrorVaults::remove(vid(a));
}

// ---- the trigger deadlock (wave 1's risk) --------------------------------------------------------------------------------

TEST_F(MirrorFollowDbTest, TypeRowWritersLockTheEntryFirstSoNoDeadlock) {
    const auto core = localVault("mf_lock_");
    write(core, "/f", "content");
    (void)mq::MirrorVaults::startCore(vid(core), peerId);
    const auto id = entryId(vid(core), "/f");

    // T2 changes the entry, then (later) its files row; T1 changes only the files row, in between.
    const auto race = [&](const std::function<void()>& t1) {
        std::promise<void> t2Holds, t2Go;
        auto go = t2Go.get_future().share();
        std::atomic<bool> deadlock{false};
        auto t2 = std::async(std::launch::async, [&] {
            try {
                db::Transactions::exec("mf t2", [&](pqxx::work& txn) {
                    txn.exec("UPDATE fs_entry SET mode = 416 WHERE id = $1", pqxx::params{id});
                    t2Holds.set_value();
                    go.wait();
                    txn.exec("UPDATE files SET content_hash = repeat('c', 64) WHERE fs_entry_id = $1", pqxx::params{id});
                });
            } catch (const pqxx::sql_error& e) {
                if (e.sqlstate() == "40P01") deadlock = true;
                else throw;
            }
        });
        t2Holds.get_future().wait();
        auto t1f = std::async(std::launch::async, [&] {
            try {
                t1();
            } catch (const pqxx::sql_error& e) {
                if (e.sqlstate() == "40P01") deadlock = true;
                else throw;
            }
        });
        std::this_thread::sleep_for(300ms);   // T1 is waiting for T2's entry lock (or holds the files row)
        t2Go.set_value();
        t2.get();
        t1f.get();
        return deadlock.load();
    };

    // The statement shape before the fix (files row first, the trigger's entry lock second): the crossing deadlocks.
    EXPECT_TRUE(race([&] {
        db::Transactions::exec("mf t1 old", [&](pqxx::work& txn) {
            txn.exec("UPDATE files f SET encryption_iv = f.encryption_iv, encrypted_with_key_version = "
                     "  f.encrypted_with_key_version + 1 FROM fs_entry fs WHERE f.fs_entry_id = fs.id AND fs.id = $1",
                     pqxx::params{id});
        });
    })) << "reproduced: the type trigger's entry lock crosses a writer of the entry then its files row";

    // The product's statement (the entry first): T1 waits for T2, both commit.
    EXPECT_FALSE(race([&] {
        const auto f = db::query::fs::File::getFileByPath(vid(core), "/f");
        ASSERT_TRUE(f);
        f->encrypted_with_key_version += 5;
        db::query::fs::File::setEncryptionIVAndVersion(f);
    }));
    (void)mq::Log::sequence(vid(core));
    EXPECT_EQ(mq::MirrorVaults::get(vid(core))->digest, mq::Digests::recompute(vid(core)));
    (void)mq::MirrorVaults::remove(vid(core));
}

// ---- measured: the baseline of a large vault (run by hand: --gtest_also_run_disabled_tests) ----------------------------

TEST_F(MirrorFollowDbTest, DISABLED_BaselineOfAHundredThousandEntries) {
    const auto v = localVault("mf_big_");
    const auto root = entryId(vid(v), "/");
    constexpr int kDirs = 100, kPerDir = 999;
    db::Transactions::exec("mf big", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, mode) "
                 "SELECT $1, $2, 'd' || g, substr(md5('d' || g || random()) || md5(random()::text), 1, 33), $3, $3, "
                 "  '/d' || g, 493 FROM generate_series(1, $4) g",
                 pqxx::params{vid(v), root, superUser->id, kDirs});
        txn.exec("INSERT INTO directories (fs_entry_id, uid) SELECT id, gen_random_uuid() FROM fs_entry "
                 "WHERE vault_id = $1 AND parent_id = $2",
                 pqxx::params{vid(v), root});
        txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, mode) "
                 "SELECT $1, d.id, 'f' || g, substr(md5(d.id || 'f' || g || random()) || md5(random()::text), 1, 33), $2, "
                 "  $2, d.path || '/f' || g, 420 FROM fs_entry d CROSS JOIN generate_series(1, $3) g "
                 "WHERE d.vault_id = $1 AND d.parent_id = $4",
                 pqxx::params{vid(v), superUser->id, kPerDir, root});
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, content_hash, encryption_iv, encrypted_with_key_version, "
                 "  object_uid) SELECT e.id, 10, repeat('0', 64), '', 1, gen_random_uuid() FROM fs_entry e "
                 "WHERE e.vault_id = $1 AND e.name LIKE 'f%'",
                 pqxx::params{vid(v)});
    });
    sql("ANALYZE fs_entry; ANALYZE files; ANALYZE directories");
    const auto s0 = std::chrono::steady_clock::now();
    (void)one<int64_t>("SELECT count(*) FROM vh_mirror_tree_states(" + std::to_string(vid(v)) + ")");
    const auto s1 = std::chrono::steady_clock::now();
    const auto t0 = std::chrono::steady_clock::now();
    const auto tree = mq::Digests::recompute(vid(v));
    const auto t1 = std::chrono::steady_clock::now();
    const auto mv = mq::MirrorVaults::startCore(vid(v), peerId);
    const auto t2 = std::chrono::steady_clock::now();
    EXPECT_EQ(tree.entries, kDirs + kDirs * kPerDir);
    EXPECT_EQ(*mv.baseline_digest, tree);
    const auto ms = [](auto d) { return std::chrono::duration_cast<std::chrono::milliseconds>(d).count(); };
    std::cout << "[measure] " << tree.entries << " entries: their state documents " << ms(s1 - s0)
              << " ms; hashing the tree (the scrub) " << ms(t1 - t0)
              << " ms; startCore with its baseline " << ms(t2 - t1) << " ms" << std::endl;
    (void)mq::MirrorVaults::remove(vid(v));
}

}
