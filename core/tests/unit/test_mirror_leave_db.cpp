// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Leaving a mirror (server mirror phase 2, wave 5, piece A; migration 167; design/peers/mirror.md "Leaving a mirror",
// "As built: leaving a mirror"; mirror::leave, ops::mirrors::detach, db::query::mirror::MirrorDetach). One database holds
// one server, so a held copy is made the way the follower leaves one (a local vault with files, then its `mirror` row,
// its grant, its first copy flag and its offer); files whose contents never arrived carry the content rows the applier
// writes, with no bytes on disk; pending and held changes are rows as mirror::submit leaves them. The core's end runs
// against its own vault (a `core` row and offer) and the wire's payload. The two-daemon proof is `vhh drill peers`
// step 9.
//
// Covered: detach in every state a held copy can be in (live with the link up and down, first copy unfinished,
// diverged, expired, orphaned), with pending changes, held changes and missing contents, ending as a writable local vault
// whose missing list is exact and whose missing files never read as anything; invariant 10; the core told once it is
// reachable, and a notice dropped by an unlink; the core ending its side and both ends refusing the same uid again; who
// may (a super admin, a granted admin, never a plain user, an agent, a scoped or a relayed device).

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/Detach.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Pending.hpp"
#include "db/query/mirror/Start.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Vault.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/leave/Leave.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/follow/Follower.hpp"
#include "mirror/switching/Switch.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/versions/Versions.hpp"
#include "recovery/local/Versions.hpp"
#include "ops/Error.hpp"
#include "ops/MirrorLeave.hpp"
#include "ops/Mirrors.hpp"
#include "ops/Users.hpp"
#include "ops/Recovery.hpp"
#include "ops/Vaults.hpp"
#include "ops/Fs.hpp"
#include "vault/Retention.hpp"
#include "vault/model/Deletion.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "rbac/Mirrored.hpp"
#include "rbac/permission/admin/Mirror.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/uid.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace vh::test_mirror_leave_db {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace mq = db::query::mirror;
namespace start = vh::mirror::start;
namespace leave = vh::mirror::leave;
using namespace std::chrono_literals;

std::string mlTag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000) + "l" +
           std::to_string(n.fetch_add(1));
}

json mlOk(json data = json::object()) { return {{"status", "OK"}, {"data", std::move(data)}}; }

class MirrorLeaveDbTest : public vh::test::db::Suite {
protected:
    inline static std::mutex sentMutex;
    inline static std::vector<std::pair<std::string, json>> sent;
    inline static std::optional<std::time_t> linkUp{1000};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mirror_leave")) return;
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        start::setTransportForTesting({});
        rbac::mirrored::resetForTesting();
        vh::mirror::access::resetForTesting();
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        {
            std::scoped_lock lock(sentMutex);
            sent.clear();
            linkUp = 1000;
        }
        start::setTransportForTesting(
            {.request = [](uint32_t, const std::string& command, const json& payload,
                           std::chrono::milliseconds) -> std::optional<json> {
                 std::scoped_lock lock(sentMutex);
                 if (!linkUp) return std::nullopt;
                 sent.emplace_back(command, payload);
                 return mlOk({{"recorded", true}});
             },
             .upSince = [](uint32_t) {
                 std::scoped_lock lock(sentMutex);
                 return linkUp;
             }});
        start::Service::instance()->resetForTesting();
        leave::resetDeletionNoticesForTesting();
    }

    void TearDown() override {
        start::setTransportForTesting({});
        (void)runtime::Deps::releaseSessions();   // the device sessions of the who-may test
    }

    static void sql(const std::string& statement) {
        db::Transactions::exec("mirror leave test", [&](pqxx::work& txn) { txn.exec(statement); });
    }
    static std::string scalar(const std::string& query) {
        return db::Transactions::exec("mirror leave test", [&](pqxx::work& txn) {
            const auto r = txn.exec(query);
            return r.empty() || r[0][0].is_null() ? std::string() : r[0][0].as<std::string>();
        });
    }
    static int64_t count(const std::string& query) { return std::stoll(scalar(query)); }

    static std::vector<std::pair<std::string, json>> sentWith(const std::string& command) {
        std::scoped_lock lock(sentMutex);
        std::vector<std::pair<std::string, json>> out;
        for (const auto& s : sent)
            if (s.first == command) out.push_back(s);
        return out;
    }

    static vh::peer::Record newPeer(const std::string& role) {
        const auto t = mlTag();
        db::query::peer::NewPeer p;
        p.node_id = role + "-" + t;
        p.name = role + "-" + t;
        p.spki_sha256 = std::string(48, role == "core" ? 'c' : 'd');
        for (const auto ch : t) p.spki_sha256.push_back(std::isdigit(static_cast<unsigned char>(ch)) ? ch : 'e');
        p.spki_sha256.resize(64, '0');
        p.wrap_public_key.fill(7);
        return db::query::peer::Peers::insert(p);
    }

    static std::string refusalCode(const std::function<void()>& f) {
        try {
            f();
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::NotFound&) {
            return "not_found";
        } catch (const ops::Denied&) {
            return "denied";
        } catch (const ops::Conflict&) {
            return "conflict";
        } catch (const ops::Invalid&) {
            return "invalid";
        }
        return "";
    }

    static EnginePtr engineOf(const uint32_t vaultId) { return runtime::Deps::get().storageManager->getEngine(vaultId); }

    static void write(const EnginePtr& engine, const std::string& path, const std::string& content) {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine, .user = superUser, .overwrite = true}));
    }

    static std::string read(const uint32_t vaultId, const std::string& path) {
        const auto engine = engineOf(vaultId);
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        if (!file) throw std::runtime_error("no file " + path);
        const auto reader = engine->openPlaintextReader(file);
        const auto bytes = storage::readAll(*reader, 1u << 20);
        return {bytes.begin(), bytes.end()};
    }

    static std::string fileUid(const uint32_t vaultId, const std::string& path) {
        return scalar("SELECT f.object_uid::text FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = " +
                      std::to_string(vaultId) + " AND e.path = '" + path + "'");
    }

    static mq::MirrorVault mirrorRowOf(const uint32_t vaultId) {
        const auto row = mq::MirrorVaults::get(vaultId);
        EXPECT_TRUE(row);
        return row.value_or(mq::MirrorVault{});
    }

    static int64_t entries(const uint32_t vaultId) {
        return count("SELECT count(*) FROM fs_entry WHERE vault_id = " + std::to_string(vaultId));
    }

    struct Held {
        uint32_t vaultId{};
        vh::peer::Record core;
        std::string vaultUuid;
        uint64_t pendingKept{}, pendingWrite{}, heldId{};
        std::string vaultName;
        std::string offerUid;
    };

    // This server as the core of a vault mirrored with `mirror` (its `core` row and its started offer).
    struct Core {
        uint32_t vaultId{};
        uint32_t offerId{};
        std::string vaultUuid;
        std::string offerUid;
    };
    static Core coreMirrored(const vh::peer::Record& mirror) {
        Core c;
        const auto v = ops::vaults::create(superUser, {.name = "ml_core_" + mlTag(),
                                                       .type = vault::model::VaultType::Local, .owner_id = superUser->id});
        c.vaultId = v->id;
        write(engineOf(v->id), "/x.txt", "the core's own");
        (void)mq::MirrorVaults::startCore(v->id, mirror.id);
        c.vaultUuid = scalar("SELECT uid::text FROM vault WHERE id = " + std::to_string(v->id));
        mq::Offer o;
        o.offer_uid = crypto::id::toUuid(crypto::id::newObjectUid());
        o.side = "core";
        o.peer_id = mirror.id;
        o.vault_uid = crypto::id::fromUuid(c.vaultUuid);
        o.vault_id = v->id;
        o.core_vault_id = v->id;
        o.root_uid = crypto::id::newObjectUid();
        o.name = v->name;
        o.owner = {.node = "own", .id = superUser->id, .name = superUser->name()};
        o.state = "offered";
        o.expires_at = std::time(nullptr) + 3600;
        const auto stored = mq::MirrorStart::insertOffer(o);
        sql("UPDATE mirror_offer SET state = 'started', notify = FALSE, finished_at = now() WHERE id = " +
            std::to_string(stored.id));
        c.offerId = stored.id;
        c.offerUid = o.offer_uid;
        return c;
    }

    // A copy of `core`'s vault as the follower leaves one: /a.txt, /dir/c.txt, /made-here (a folder a person made
    // here, still pending), /b.txt whose contents never arrived (its content row, no bytes); a pending write of /a.txt
    // whose bytes the file no longer holds (the core's state came back over it); one held change. Then `state`:
    // live (link up), live_down, unfinished, diverged, expired or orphaned.
    static Held heldCopy(const std::string& state) {
        Held h;
        h.core = newPeer("core");
        h.vaultName = "ml_held_" + mlTag();
        const auto v = ops::vaults::create(superUser, {.name = h.vaultName, .type = vault::model::VaultType::Local,
                                                       .owner_id = superUser->id});
        h.vaultId = v->id;
        const auto engine = engineOf(h.vaultId);
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/dir"), .engine = engine, .user = superUser});
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/made-here"), .engine = engine, .user = superUser});
        write(engine, "/a.txt", "alpha from the core");
        write(engine, "/b.txt", "bravo, never arrived");
        write(engine, "/dir/c.txt", "charlie from the core");
        h.vaultUuid = scalar("SELECT uid::text FROM vault WHERE id = " + std::to_string(h.vaultId));

        (void)mq::MirrorVaults::startMirror(h.vaultId, h.core.id);
        EXPECT_TRUE(mq::MirrorVaults::recordGrant(h.vaultId, {.role_name = "reader", .files = 0xffffffffu,
                                                              .directories = 0xffffffffu, .sync = 0, .roles = 0,
                                                              .granted_by_node = h.core.node_id, .granted_at = 0}));
        sql("UPDATE mirror_vault SET copy_finished = " + std::string(state == "unfinished" ? "FALSE" : "TRUE") +
            ", copy_cursor = 4, baseline_rows = 9, last_seq = 12, acked_term = 1, acked_seq = 10 WHERE vault_id = " +
            std::to_string(h.vaultId));
        // The mirror's offer of it, started (what tells the core later).
        mq::Offer o;
        o.offer_uid = crypto::id::toUuid(crypto::id::newObjectUid());
        o.side = "mirror";
        o.peer_id = h.core.id;
        o.vault_uid = crypto::id::fromUuid(h.vaultUuid);
        o.vault_id = h.vaultId;
        o.core_vault_id = 77;
        o.root_uid = crypto::id::newObjectUid();
        o.name = h.vaultName;
        o.owner = {.node = h.core.node_id, .id = 5, .name = "alice"};
        o.state = "pending";
        o.expires_at = std::time(nullptr) + 3600;
        const auto stored = mq::MirrorStart::insertOffer(o);
        sql("UPDATE mirror_offer SET state = 'started', finished_at = now() WHERE id = " + std::to_string(stored.id));
        h.offerUid = o.offer_uid;

        // /b.txt: its generation expected, its bytes not here.
        const auto b = db::query::fs::File::getFileByPath(h.vaultId, "/b.txt");
        mq::Expected e{.vault_id = h.vaultId, .object_uid = *b->object_uid, .generation = b->encryption_iv,
                       .key_version = b->encrypted_with_key_version, .size_bytes = b->size_bytes,
                       .content_hash = b->content_hash.value_or(std::string(64, '0')), .mtime_us = 0};
        mq::PendingContents::expect(e);
        std::filesystem::remove(b->backing_path);

        // Pending: the folder made here (its effect is in the tree), and a write of /a.txt the file no longer holds.
        const auto openPending = [&](const std::string& op, const std::string& entryUid, const json& args) {
            mq::NewPending n{.vault_id = h.vaultId, .request_id = "mlreq" + mlTag(), .entry_uid = entryUid, .op = op,
                             .args = args, .actor = {.node = "own", .id = superUser->id}};
            const auto row = mq::Pending::open(n, {}, {});
            mq::Pending::ready(row.id);
            return row.id;
        };
        h.pendingKept = openPending("mkdir", scalar("SELECT d.uid::text FROM directories d JOIN fs_entry e ON "
                                                    "e.id = d.fs_entry_id WHERE e.vault_id = " +
                                                    std::to_string(h.vaultId) + " AND e.path = '/made-here'"),
                                    {{"name", "made-here"}});
        h.pendingWrite = openPending("write", fileUid(h.vaultId, "/a.txt"),
                                     {{"name", "a.txt"}, {"size", 12}, {"generation", "the-person-s-version"}});
        const auto blob = vh::mirror::submit::contents::pendingBlob(h.vaultId, h.pendingWrite);
        std::filesystem::create_directories(blob.parent_path());
        std::ofstream(blob) << "the person's sealed bytes";
        db::Transactions::exec("ml held", [&](pqxx::work& txn) {
            mq::HeldChange held;
            held.vault_id = h.vaultId;
            held.kind = "held";
            held.request_id = "mlheld" + mlTag();
            held.op = "rename";
            held.entry_uid = fileUid(h.vaultId, "/dir/c.txt");
            held.args = {{"name", "renamed.txt"}};
            held.actor = {.node = "own", .id = superUser->id};
            held.reason_code = "denied";
            held.reason = "the core's role refused it";
            h.heldId = mq::Pending::hold(txn, held);
        });

        if (state == "live_down") vh::mirror::access::linkChanged(h.core.id, false);
        else vh::mirror::access::linkChanged(h.core.id, true);
        if (state == "diverged")
            (void)mq::MirrorVaults::stop(h.vaultId, "diverged", "mirror_digest_mismatch", {{"core", "x"}, {"mirror", "y"}});
        if (state == "expired") (void)mq::MirrorVaults::stop(h.vaultId, "expired", "mirror_log_expired");
        if (state == "orphaned") {
            (void)mq::MirrorVaults::orphan(h.vaultId);
            sql("UPDATE mirror_offer SET state = 'orphaned' WHERE id = " + std::to_string(stored.id));
        }
        vh::mirror::access::reload();
        return h;
    }
};

// ============================================================================================= detach, in every state

TEST_F(MirrorLeaveDbTest, EveryKindOfHeldCopyBecomesAWritableLocalVaultWithTheExactMissingList) {
    for (const std::string state : {"live", "live_down", "unfinished", "diverged", "expired", "orphaned"}) {
        SCOPED_TRACE(state);
        const auto h = heldCopy(state);
        const auto before = entries(h.vaultId);
        EXPECT_NE(vh::mirror::access::state(h.vaultId), vh::mirror::access::State::NotMirrored);

        // What the person reads first: the fork point, the digest there, the changes, every missing file.
        const auto p = ops::mirrors::detachPreview(superUser, h.vaultId);
        EXPECT_EQ(p.role, state == "orphaned" ? "orphaned" : "mirror");
        EXPECT_EQ(p.applied.seq, 12u);
        ASSERT_TRUE(p.confirmed);
        EXPECT_EQ(p.confirmed->seq, 10u);
        ASSERT_TRUE(p.digest_matched);
        EXPECT_EQ(*p.digest_matched, state != "diverged");
        EXPECT_EQ(p.copy_finished, state != "unfinished");
        EXPECT_EQ(p.pending_changes, 2u);
        EXPECT_EQ(p.held_changes, 1u);
        ASSERT_EQ(p.missing.size(), 1u);
        EXPECT_EQ(p.missing[0].path, "/b.txt");
        EXPECT_EQ(leave::toJson(p).at("missing").at(0).at("path"), "/b.txt") << "the list exports";
        EXPECT_EQ(entries(h.vaultId), before) << "the preview changes nothing";

        const auto d = ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
        EXPECT_EQ(d.missing, 1u);
        EXPECT_EQ(d.pending_kept, 1u) << "the folder made here is an ordinary folder now";
        EXPECT_EQ(d.pending_held, 1u) << "the person's version of /a.txt is theirs, held with its bytes";
        EXPECT_EQ(d.owner_id, superUser->id);

        // Not a copy any more: no row, no gate, no backstop, ordinary resolution.
        EXPECT_FALSE(mq::MirrorVaults::get(h.vaultId));
        EXPECT_EQ(vh::mirror::access::state(h.vaultId), vh::mirror::access::State::NotMirrored);
        EXPECT_FALSE(rbac::mirrored::find(h.vaultId));
        EXPECT_EQ(count("SELECT owner_id FROM vault WHERE id = " + std::to_string(h.vaultId)), superUser->id);
        EXPECT_TRUE(mq::Pending::list(h.vaultId).empty());
        EXPECT_TRUE(mq::Pending::dirtyUids(h.vaultId).empty());
        EXPECT_EQ(entries(h.vaultId), before) << "nothing is deleted";

        // Every file that was here reads; the missing one says so and never reads as anything.
        EXPECT_EQ(read(h.vaultId, "/a.txt"), "alpha from the core");
        EXPECT_EQ(read(h.vaultId, "/dir/c.txt"), "charlie from the core");
        try {
            (void)read(h.vaultId, "/b.txt");
            ADD_FAILURE() << "a file whose contents never arrived read as something";
        } catch (const std::exception& e) {
            EXPECT_NE(std::string(e.what()).find("mirror_contents_missing"), std::string::npos) << e.what();
        }
        const auto missing = mq::MirrorDetach::missing(h.vaultId);
        ASSERT_EQ(missing.size(), 1u) << "exactly the list the person saw";
        EXPECT_EQ(missing[0].path, "/b.txt");
        EXPECT_EQ(missing[0].state, "missing");
        EXPECT_TRUE(mq::PendingContents::outstanding(h.vaultId, 10, true).empty()) << "nothing is ever fetched for it";
        // Listings say which files are missing without opening them (the console's fs.dir.list, vh fs ls).
        {
            auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
            session->user = superUser;
            const auto listed = protocols::ws::handler::fs::Storage::listDir({{"vault_id", h.vaultId}, {"path", "/"}},
                                                                             session);
            bool sawMissing = false;
            for (const auto& f : listed.at("files")) {
                const bool missingHere = f.value("contents_missing", false);
                EXPECT_EQ(missingHere, f.value("name", "") == "b.txt") << f.dump();
                sawMissing = sawMissing || missingHere;
            }
            EXPECT_TRUE(sawMissing);
            EXPECT_TRUE(mq::PendingContents::missingFileIds(h.vaultId).contains(
                db::query::fs::File::getFileByPath(h.vaultId, "/b.txt")->id));
        }

        // Writable here, by every surface, with nothing pending.
        write(engineOf(h.vaultId), "/new.txt", "written after the detach");
        EXPECT_EQ(read(h.vaultId, "/new.txt"), "written after the detach");
        write(engineOf(h.vaultId), "/b.txt", "a new version of bravo");
        EXPECT_EQ(read(h.vaultId, "/b.txt"), "a new version of bravo") << "a new version supersedes the missing one";
        EXPECT_TRUE(mq::MirrorDetach::missing(h.vaultId).empty());
        EXPECT_TRUE(mq::Pending::list(h.vaultId).empty());

        // Held changes stay listed until discarded; the pending write's bytes moved with it.
        const auto held = ops::mirrors::held(superUser, h.vaultId, false);
        ASSERT_EQ(held.size(), 2u);
        bool sawDetached = false;
        for (const auto& c : held)
            if (c.reason_code == "mirror_detached") {
                sawDetached = true;
                EXPECT_TRUE(std::filesystem::exists(vh::mirror::submit::contents::heldBlob(h.vaultId, c.id)));
            }
        EXPECT_TRUE(sawDetached);
        EXPECT_FALSE(std::filesystem::exists(vh::mirror::submit::contents::pendingBlob(h.vaultId, h.pendingWrite)));

        // The record and the re-key recommendation.
        const auto info = ops::mirrors::get(superUser, h.vaultId);
        EXPECT_EQ(info.role, "detached");
        ASSERT_TRUE(info.detached);
        EXPECT_EQ(info.detached->fork.seq, 12u);
        EXPECT_TRUE(ops::mirrors::toJson(info).at("rekey_recommended").get<bool>());
        // The offer ended detached; the core is told (except an orphaned copy's: its core ended the mirror already).
        const auto offer = mq::MirrorStart::latestOffer(crypto::id::fromUuid(h.vaultUuid), "mirror");
        ASSERT_TRUE(offer);
        EXPECT_EQ(offer->state, "detached");
        EXPECT_EQ(offer->notify, state != "orphaned");
    }
}

// Invariant 10: detach completes with the peer unreachable, deletes nothing, and touches no bucket.
TEST_F(MirrorLeaveDbTest, Invariant10_DetachCompletesWithThePeerUnreachableDeletesNothingAndTouchesNoBucket) {
    const auto h = heldCopy("live_down");
    {
        std::scoped_lock lock(sentMutex);
        linkUp.reset();
    }
    (void)db::query::peer::Peers::revoke(h.core.id);
    const auto engine = engineOf(h.vaultId);
    std::set<std::string> backingBefore;
    for (const auto& f : std::filesystem::recursive_directory_iterator(engine->paths->backingVaultRoot))
        backingBefore.insert(f.path().string());
    const auto rowsBefore = entries(h.vaultId);

    const auto d = ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
    EXPECT_FALSE(d.core_told_later) << "an unlinked core is never told";
    EXPECT_EQ(entries(h.vaultId), rowsBefore);
    std::set<std::string> backingAfter;
    for (const auto& f : std::filesystem::recursive_directory_iterator(engineOf(h.vaultId)->paths->backingVaultRoot))
        backingAfter.insert(f.path().string());
    EXPECT_EQ(backingAfter, backingBefore) << "no byte on disk went";
    EXPECT_EQ(db::query::vault::Vault::getVault(h.vaultId)->type, vault::model::VaultType::Local) << "no remote, no bucket";
    start::Service::instance()->tick();
    EXPECT_TRUE(sentWith("peer.mirror.detached").empty()) << "nothing was asked of anyone";
}

// ======================================================================================================= the core told

TEST_F(MirrorLeaveDbTest, TheCoreIsToldWhenItIsReachableAndAnUnlinkDropsTheNotice) {
    auto h = heldCopy("live_down");
    {
        std::scoped_lock lock(sentMutex);
        linkUp.reset();
    }
    const auto d = ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
    EXPECT_TRUE(d.core_told_later);
    start::Service::instance()->tick();
    EXPECT_TRUE(sentWith("peer.mirror.detached").empty()) << "the link is down: queued";
    {
        std::scoped_lock lock(sentMutex);
        linkUp = 2000;
    }
    for (int i = 0; i < 3; ++i) start::Service::instance()->tick();
    std::vector<json> told;
    for (const auto& [c, p] : sentWith("peer.mirror.detached"))
        if (p.value("vault_uid", "") == vl::keykit::toBase32(crypto::id::fromUuid(h.vaultUuid))) told.push_back(p);
    ASSERT_EQ(told.size(), 1u) << "told once";
    EXPECT_EQ(told[0].at("at").at("seq"), 12);
    EXPECT_EQ(told[0].at("missing"), 1);
    EXPECT_FALSE(mq::MirrorStart::latestOffer(crypto::id::fromUuid(h.vaultUuid), "mirror")->notify);

    // A detach whose notice is still queued when the servers are unlinked: dropped, never delivered.
    auto g = heldCopy("live_down");
    {
        std::scoped_lock lock(sentMutex);
        linkUp.reset();
        sent.clear();
    }
    (void)ops::mirrors::detach(superUser, {.vault_id = g.vaultId});
    ASSERT_TRUE(mq::MirrorStart::latestOffer(crypto::id::fromUuid(g.vaultUuid), "mirror")->notify);
    (void)db::query::peer::Peers::revoke(g.core.id);
    {
        std::scoped_lock lock(sentMutex);
        linkUp = 3000;
    }
    for (int i = 0; i < 3; ++i) start::Service::instance()->tick();
    for (const auto& [c, p] : sentWith("peer.mirror.detached"))
        EXPECT_NE(p.value("vault_uid", ""), vl::keykit::toBase32(crypto::id::fromUuid(g.vaultUuid)));
    EXPECT_FALSE(mq::MirrorStart::latestOffer(crypto::id::fromUuid(g.vaultUuid), "mirror")->notify) << "dropped";
}

TEST_F(MirrorLeaveDbTest, TheCoreEndsItsSideRecordsItAndBothEndsRefuseToMirrorTheSameUidAgain) {
    // This server as the core of a vault mirrored with `mirror`.
    const auto mirror = newPeer("mirror");
    const auto v = ops::vaults::create(superUser, {.name = "ml_core_" + mlTag(), .type = vault::model::VaultType::Local,
                                                   .owner_id = superUser->id});
    write(engineOf(v->id), "/x.txt", "the core's own");
    (void)mq::MirrorVaults::startCore(v->id, mirror.id);
    const auto uuid = scalar("SELECT uid::text FROM vault WHERE id = " + std::to_string(v->id));
    mq::Offer o;
    o.offer_uid = crypto::id::toUuid(crypto::id::newObjectUid());
    o.side = "core";
    o.peer_id = mirror.id;
    o.vault_uid = crypto::id::fromUuid(uuid);
    o.vault_id = v->id;
    o.core_vault_id = v->id;
    o.root_uid = crypto::id::newObjectUid();
    o.name = v->name;
    o.owner = {.node = "own", .id = superUser->id, .name = superUser->name()};
    o.state = "offered";
    o.expires_at = std::time(nullptr) + 3600;
    const auto stored = mq::MirrorStart::insertOffer(o);
    sql("UPDATE mirror_offer SET state = 'started', notify = FALSE, finished_at = now() WHERE id = " +
        std::to_string(stored.id));

    // Someone else's word is not taken: only the server it was mirrored with.
    const auto stranger = newPeer("mirror");
    EXPECT_FALSE(leave::detachedReceived(stranger, {{"vault_uid", vl::keykit::toBase32(o.vault_uid)}})
                     .at("recorded")
                     .get<bool>());
    EXPECT_TRUE(mq::MirrorVaults::get(v->id));

    const auto answer = leave::detachedReceived(
        mirror, {{"offer_uid", o.offer_uid}, {"vault_uid", vl::keykit::toBase32(o.vault_uid)},
                 {"at", {{"term", 1}, {"seq", 4}}}, {"missing", 2}});
    EXPECT_TRUE(answer.at("recorded").get<bool>());
    EXPECT_FALSE(mq::MirrorVaults::get(v->id)) << "the mirror ended on the core: its row and log went";
    EXPECT_EQ(count("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(v->id)), 0);
    EXPECT_EQ(mq::MirrorStart::offer(stored.id)->copy_outcome.value_or(""), "detached");
    EXPECT_EQ(read(v->id, "/x.txt"), "the core's own") << "its own vault is unaffected";
    const auto rec = mq::MirrorDetach::forVault(v->id);
    ASSERT_TRUE(rec);
    EXPECT_EQ(rec->side, "core");
    EXPECT_EQ(rec->fork.seq, 4u);
    EXPECT_EQ(rec->missing, 2u);
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_EQ(count("SELECT count(*) FROM audit_event WHERE action = 'mirror.detached' AND vault_id = " +
                    std::to_string(v->id)),
              1);
    // Told again: nothing more.
    (void)leave::detachedReceived(mirror, {{"vault_uid", vl::keykit::toBase32(o.vault_uid)}});
    EXPECT_EQ(count("SELECT count(*) FROM mirror_detached WHERE vault_id = " + std::to_string(v->id)), 1);

    // The core does not offer that vault to that server again (they share its uid and keys)...
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::add(superUser, {.vault_id = v->id, .peer = std::to_string(mirror.id)}); }),
              "mirror_detached_copy");

    // ...and the server that detached refuses it as well as offering its own copy back.
    const auto h = heldCopy("live");
    (void)ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
    EXPECT_EQ(refusalCode([&] {
                  (void)ops::mirrors::add(superUser, {.vault_id = h.vaultId, .peer = std::to_string(h.core.id)});
              }),
              "mirror_detached_copy");
    mq::Offer back;
    back.peer_id = h.core.id;
    back.vault_uid = crypto::id::fromUuid(h.vaultUuid);
    const auto refusal = start::mirrorRefusal(back);
    ASSERT_TRUE(refusal);
    EXPECT_EQ(refusal->first, "mirror_detached_copy");
}

// ============================================================================================================ who may

TEST_F(MirrorLeaveDbTest, OnlyASuperAdminOrAHolderOfTheDetachPermissionDetachesNeverAnAgentOrAScopedOrRelayedDevice) {
    namespace stepup = auth::stepup;
    auto role = std::make_shared<rbac::role::Admin>(rbac::role::Admin::None());
    role->name = "ml_detacher_" + mlTag();
    role->description = "may detach mirrored vaults";
    role->mirror.grant(rbac::permission::admin::MirrorPermissions::Detach);
    (void)db::query::rbac::role::Admin::insert(role);
    const auto detacher = test::identities::createUser("ml_det_" + mlTag(), db::query::rbac::role::Admin::get(role->name),
                                                       "ml_det_" + mlTag() + "@vaulthalla.test");
    const auto plain = identities::manager().user(
        ops::users::create(superUser, {.name = "ml_plain_" + mlTag(), .role = "unprivileged",
                                       .password = std::string("Mirror-Leave-Pass-123")})
            .user->id);
    ASSERT_TRUE(detacher->mirrorPerms().canDetach());
    EXPECT_FALSE(plain->mirrorPerms().canDetach());

    const auto h = heldCopy("live");
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachPreview(plain, h.vaultId); }), "denied");
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detach(plain, {.vault_id = h.vaultId}); }), "denied");

    const auto deviceSession = [&](const std::string& scope, const bool relayed) {
        auto p = std::make_shared<vh::device::Peer>();
        p->spki.fill(relayed ? 0x51 : 0x52);
        p->spkiHex = vh::device::crypto::toHex(p->spki);
        p->address = "10.0.0.9";
        p->deviceRowId = 12;
        p->relayed = relayed;
        p->scope = scope;
        return protocols::ws::Session::devicePrincipal(std::move(p), superUser, [] {});
    };
    {
        const stepup::Scope agent(stepup::Channel::Agent);
        EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detach(superUser, {.vault_id = h.vaultId}); }), "peer_forbidden");
        EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachPreview(superUser, h.vaultId); }), "peer_forbidden");
    }
    for (const auto& [scope, relayed] : std::vector<std::pair<std::string, bool>>{{"write", false}, {"destructive", true}}) {
        const auto session = deviceSession(scope, relayed);
        const stepup::Scope s(session);
        EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detach(superUser, {.vault_id = h.vaultId}); }), "peer_forbidden")
            << scope;
    }
    EXPECT_TRUE(mq::MirrorVaults::get(h.vaultId)) << "nothing was detached by any of them";

    // A typed name that is not the vault's refuses; an owner that is another server's person refuses.
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detach(detacher, {.vault_id = h.vaultId, .confirm_name = "nope"}); }),
              "invalid");
    const auto remoteOwner = scalar("SELECT owner_id FROM vault WHERE id = " + std::to_string(h.vaultId));
    sql("UPDATE users SET remote = TRUE, home_node = 'elsewhere', home_id = 9 WHERE id = " + remoteOwner +
        " AND id <> " + std::to_string(superUser->id));
    // A holder of the permission detaches, naming the new owner.
    const auto d = ops::mirrors::detach(detacher, {.vault_id = h.vaultId, .owner = plain->name(),
                                                   .confirm_name = h.vaultName});
    EXPECT_EQ(d.owner_id, plain->id);
    EXPECT_FALSE(mq::MirrorVaults::get(h.vaultId));
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_EQ(count("SELECT count(*) FROM audit_event WHERE action = 'mirror.detach' AND vault_id = " +
                    std::to_string(h.vaultId)),
              1);
    // Not a held copy any more: nothing to detach.
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detach(superUser, {.vault_id = h.vaultId}); }), "mirror_not_held");
}

// ================================================================================== deleting a mirrored vault in one step

// The core's side of a mirrored vault's deletion (lead's review of c42e1d09; decisions log 601-602): the choice is
// required and recorded with the deletion; the mirror is NOT ended while the deletion can be taken back, only told it
// is being deleted (again on every link-up); a restore keeps the mirror; the purge ends it with the recorded choice.
TEST_F(MirrorLeaveDbTest, DeletingAMirroredVaultRecordsTheChoiceAndKeepsTheMirrorThroughTheRetentionWindow) {
    const auto mirror = newPeer("mirror");
    {
        const auto c = coreMirrored(mirror);
        EXPECT_EQ(refusalCode([&] { (void)ops::vaults::remove(superUser, {.id = c.vaultId}); }),
                  "mirror_copy_choice_required")
            << "no default when the vault is mirrored";
        EXPECT_EQ(refusalCode([&] { (void)ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = "keep"}); }),
                  "invalid");
        {
            const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
            EXPECT_EQ(refusalCode([&] { (void)ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = "leave"}); }),
                      "peer_forbidden")
                << "an agent never decides a mirror's end";
        }
        EXPECT_TRUE(mq::MirrorVaults::get(c.vaultId)) << "a refusal ends nothing";
        EXPECT_TRUE(runtime::Deps::get().storageManager->getVault(c.vaultId)) << "and deletes nothing";
    }
    for (const std::string choice : {"remove", "leave"}) {
        SCOPED_TRACE(choice);
        const auto c = coreMirrored(mirror);
        const auto deletion = ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = choice});
        ASSERT_TRUE(deletion);
        EXPECT_FALSE(runtime::Deps::get().storageManager->getVault(c.vaultId)) << "deleted the usual way";
        ASSERT_TRUE(db::query::vault::Deletion::get(c.vaultId)) << "with its retention window";
        // The mirror is not ended: its core row, its log and its offer stay; the choice waits with the deletion.
        ASSERT_TRUE(mq::MirrorVaults::get(c.vaultId)) << "the mirror matches the core until the core deletes the vault";
        EXPECT_EQ(mq::MirrorStart::offer(c.offerId)->state, "started");
        EXPECT_EQ(mq::MirrorDetach::deletingCopy(c.vaultId).value_or(""), choice);
        const auto shown = leave::deletionOf(c.vaultId);
        EXPECT_EQ(shown.value("copy", ""), choice);
        EXPECT_EQ(shown.value("purge_after", int64_t{0}), static_cast<int64_t>(db::query::vault::Deletion::get(c.vaultId)->purge_after));
        EXPECT_TRUE(ops::mirrors::toJson(ops::mirrors::get(superUser, c.vaultId)).at("deleting").is_object())
            << "vh mirror info on the core shows the pending deletion";
        // The mirror is told it is being deleted, never asked to remove anything yet.
        start::Service::instance()->tick();
        std::optional<json> told;
        for (const auto& [cmd, p] : sentWith("peer.mirror.deleting"))
            if (p.value("vault_uid", "") == vl::keykit::toBase32(crypto::id::fromUuid(c.vaultUuid))) told = p;
        ASSERT_TRUE(told);
        EXPECT_TRUE(told->value("deleting", false));
        EXPECT_EQ(told->value("copy", ""), choice);
        for (const auto& [cmd, p] : sentWith("peer.mirror.cancel")) EXPECT_NE(p.value("offer_uid", ""), c.offerUid);
        // Told again on a link-up (a new connection), not on every pass.
        const auto told2 = sentWith("peer.mirror.deleting").size();
        start::Service::instance()->tick();
        EXPECT_EQ(sentWith("peer.mirror.deleting").size(), told2);
        {
            std::scoped_lock lock(sentMutex);
            linkUp = 5000;
        }
        start::Service::instance()->tick();
        EXPECT_GT(sentWith("peer.mirror.deleting").size(), told2) << "learned again on reconnect";
        {
            std::scoped_lock lock(sentMutex);
            linkUp = 1000;
        }

        // Restored within the window: the mirror resumes where it was (nothing about it changed), told not deleting.
        ASSERT_TRUE(ops::vaults::restore(superUser, c.vaultId));
        EXPECT_TRUE(mq::MirrorVaults::get(c.vaultId));
        EXPECT_FALSE(mq::MirrorDetach::deletingCopy(c.vaultId)) << "the choice went with the deletion";
        EXPECT_TRUE(leave::deletionOf(c.vaultId).is_null());
        start::Service::instance()->tick();
        std::optional<json> resumed;
        for (const auto& [cmd, p] : sentWith("peer.mirror.deleting"))
            if (p.value("vault_uid", "") == vl::keykit::toBase32(crypto::id::fromUuid(c.vaultUuid))) resumed = p;
        ASSERT_TRUE(resumed);
        EXPECT_FALSE(resumed->value("deleting", true));
        EXPECT_EQ(mq::MirrorStart::offer(c.offerId)->state, "started") << "the same mirror, no new start";
    }
}

// After a restore the core's vault is the mirror's core again: its next write is logged, the digest moves with it, and
// the entries it held before the deletion hash as they did (the deletion and the restore are never replicated).
TEST_F(MirrorLeaveDbTest, ARestoredVaultLogsItsNextWriteAndItsEntriesHashAsBefore) {
    const auto mirror = newPeer("mirror");
    const auto c = coreMirrored(mirror);
    (void)mq::Log::sequence(c.vaultId);
    const auto before = mq::MirrorVaults::get(c.vaultId);
    const auto recomputedBefore = mq::Digests::recompute(c.vaultId);
    EXPECT_EQ(recomputedBefore, before->digest) << "the tables are the log's tree";
    (void)ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = "leave"});
    ASSERT_TRUE(ops::vaults::restore(superUser, c.vaultId));
    (void)mq::Log::sequence(c.vaultId);
    // The round trip logs the vault's own document once (its soft deletion, migration 160's rule) and no entry: the
    // deletion's bookkeeping keeps every modification time.
    EXPECT_EQ(count("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(c.vaultId) +
                    " AND seq > " + std::to_string(before->last_seq) + " AND op <> 'vault'"),
              0)
        << "no entry changed";
    EXPECT_EQ(mq::Digests::recompute(c.vaultId), recomputedBefore) << "every entry hashes as before";
    write(engineOf(c.vaultId), "/after_restore.txt", "after the restore");
    (void)mq::Log::sequence(c.vaultId);
    const auto after = mq::MirrorVaults::get(c.vaultId);
    EXPECT_GT(after->last_seq, before->last_seq) << "the write after the restore is logged";
    EXPECT_EQ(mq::Digests::recompute(c.vaultId), after->digest);
}

TEST_F(MirrorLeaveDbTest, ThePurgeEndsTheMirrorWithTheRecordedChoiceWhichCanChangeInTheWindow) {
    const auto mirror = newPeer("mirror");
    const auto purge = [](const uint32_t vaultId) {
        const auto d = db::query::vault::Deletion::get(vaultId);
        (void)vh::vault::retention::runPass(std::chrono::system_clock::from_time_t(d->purge_after) + std::chrono::seconds(1));
    };
    const auto cancelFor = [&](const Core& c) {
        std::optional<json> told;
        for (const auto& [cmd, p] : sentWith("peer.mirror.cancel"))
            if (p.value("offer_uid", "") == c.offerUid) told = p;
        return told;
    };
    // Scheduled with leave, changed to remove in the window (the same step-up rule as the delete), then purged.
    {
        const auto c = coreMirrored(mirror);
        (void)ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = "leave"});
        (void)ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = "remove"});
        EXPECT_EQ(mq::MirrorDetach::deletingCopy(c.vaultId).value_or(""), "remove");
        EXPECT_EQ(db::query::vault::Deletion::get(c.vaultId)->state, vh::vault::model::DeletionState::Pending)
            << "changing the choice purges nothing";
        start::Service::instance()->tick();
        EXPECT_FALSE(cancelFor(c)) << "nothing ended before the purge";
        purge(c.vaultId);
        EXPECT_EQ(db::query::vault::Deletion::get(c.vaultId)->state, vh::vault::model::DeletionState::Purged);
        EXPECT_FALSE(mq::MirrorVaults::get(c.vaultId)) << "the purge ended the mirror";
        EXPECT_EQ(mq::MirrorStart::offer(c.offerId)->state, "cancelled");
        EXPECT_TRUE(mq::MirrorStart::offer(c.offerId)->remove_copy);
        start::Service::instance()->tick();
        ASSERT_TRUE(cancelFor(c));
        EXPECT_TRUE(cancelFor(c)->value("remove_copy", false));
    }
    // --now with leave: both at once (the next pass).
    {
        const auto c = coreMirrored(mirror);
        (void)ops::vaults::remove(superUser, {.id = c.vaultId, .now = true, .confirm_now = true, .mirror_copy = "leave"});
        (void)vh::vault::retention::runPass(std::chrono::system_clock::now() + std::chrono::seconds(1));
        EXPECT_FALSE(mq::MirrorVaults::get(c.vaultId));
        EXPECT_FALSE(mq::MirrorStart::offer(c.offerId)->remove_copy);
        start::Service::instance()->tick();
        ASSERT_TRUE(cancelFor(c));
        EXPECT_FALSE(cancelFor(c)->value("remove_copy", true));
    }
    // The mirror down at the purge: the core ends its side; the request waits until the link is back.
    {
        const auto c = coreMirrored(mirror);
        (void)ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = "remove"});
        {
            std::scoped_lock lock(sentMutex);
            linkUp.reset();
        }
        purge(c.vaultId);
        EXPECT_FALSE(mq::MirrorVaults::get(c.vaultId));
        start::Service::instance()->tick();
        EXPECT_FALSE(cancelFor(c));
        EXPECT_TRUE(mq::MirrorStart::offer(c.offerId)->notify) << "queued";
        {
            std::scoped_lock lock(sentMutex);
            linkUp = 7000;
        }
        start::Service::instance()->tick();
        ASSERT_TRUE(cancelFor(c));
        EXPECT_TRUE(cancelFor(c)->value("remove_copy", false));
    }
}

// The mirror's side of the window: read-only with the reason, nothing submitted, pending changes kept, detach works,
// and a restore lets it follow again where it was.
TEST_F(MirrorLeaveDbTest, WhileItsCoreDeletesTheVaultTheCopyIsReadOnlyWithTheReasonAndCanStillLeave) {
    const auto h = heldCopy("live");
    const auto vaultUid = vl::keykit::toBase32(crypto::id::fromUuid(h.vaultUuid));
    const auto before = mirrorRowOf(h.vaultId);
    const auto pendingBefore = mq::Pending::list(h.vaultId).size();
    const auto purgeAfter = static_cast<int64_t>(std::time(nullptr) + 7 * 86400);
    EXPECT_EQ(refusalCode([&] {
                  (void)leave::deletingReceived(newPeer("core"), {{"vault_uid", vaultUid}, {"deleting", true},
                                                                  {"purge_after", purgeAfter}, {"copy", "remove"}});
              }),
              "not_found")
        << "only the vault's own core says so";
    mq::MirrorStart::setKeepVaults(h.core.id, true, superUser->id);
    (void)leave::deletingReceived(h.core, {{"vault_uid", vaultUid}, {"deleting", true}, {"purge_after", purgeAfter},
                                           {"copy", "remove"}});
    EXPECT_EQ(mirrorRowOf(h.vaultId).state, "paused");
    EXPECT_EQ(vh::mirror::access::reason(h.vaultId), vh::mirror::access::kCoreDeleting);
    EXPECT_NE(vh::mirror::access::sentence(vh::mirror::access::kCoreDeleting).find("vh mirror detach"), std::string::npos);
    try {
        ops::fs::mkdir(superUser, h.vaultId, "/while_deleting");
        ADD_FAILURE() << "a write went through while the core deletes the vault";
    } catch (const ops::ReadOnly& e) {
        EXPECT_EQ(e.reason, vh::mirror::access::kCoreDeleting);
    }
    EXPECT_EQ(mq::Pending::list(h.vaultId).size(), pendingBefore) << "pending changes stay pending";
    const auto shown = ops::mirrors::toJson(ops::mirrors::get(superUser, h.vaultId)).at("deleting");
    EXPECT_EQ(shown.value("purge_after", int64_t{0}), purgeAfter) << "vh mirror info shows the date";
    EXPECT_EQ(shown.value("copy", ""), "remove");
    EXPECT_EQ(shown.value("here", ""), "kept as an orphaned copy") << "and what this server's keep setting makes of it";
    EXPECT_EQ(mirrorRowOf(h.vaultId).last_seq, before.last_seq) << "it stays where it was";

    // Restored on the core: live again where it was, nothing to copy again.
    (void)leave::deletingReceived(h.core, {{"vault_uid", vaultUid}, {"deleting", false}});
    EXPECT_EQ(mirrorRowOf(h.vaultId).state, "live");
    EXPECT_EQ(mirrorRowOf(h.vaultId).position(), before.position());
    EXPECT_TRUE(mirrorRowOf(h.vaultId).copy_finished);
    EXPECT_EQ(vh::mirror::access::state(h.vaultId), vh::mirror::access::State::Live);
    EXPECT_EQ(mq::Pending::list(h.vaultId).size(), pendingBefore);

    // Deleting again; during the window the copy leaves with its files (invariant 10), whatever the core chose.
    (void)leave::deletingReceived(h.core, {{"vault_uid", vaultUid}, {"deleting", true}, {"purge_after", purgeAfter},
                                           {"copy", "remove"}});
    const auto d = ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
    EXPECT_EQ(d.record.was_state.value_or(""), "paused");
    EXPECT_FALSE(mq::MirrorVaults::get(h.vaultId));
    EXPECT_EQ(read(h.vaultId, "/a.txt"), "alpha from the core");
}

// Invariant 11: when a mirror ends (here: its core deleted the vault), the copy is removed only by the rule: removal
// asked and the keep setting off; otherwise kept, orphaned. Nothing else removes it, a delete on this server included.
TEST_F(MirrorLeaveDbTest, Invariant11_TheCopyIsRemovedOnlyByTheRuleWhenItsCoreDeletesTheVaultAndNeverByADeleteHere) {
    for (const std::string choice : {"remove", "leave"})
        for (const bool keep : {false, true}) {
            SCOPED_TRACE(choice + (keep ? " keep on" : " keep off"));
            const auto h = heldCopy("live");
            mq::MirrorStart::setKeepVaults(h.core.id, keep, superUser->id);
            const auto answer = start::cancelReceived(
                h.core, {{"offer_uid", h.offerUid}, {"vault_uid", vl::keykit::toBase32(crypto::id::fromUuid(h.vaultUuid))},
                         {"reason", "vault_deleted"}, {"remove_copy", choice == "remove"}});
            const bool removed = choice == "remove" && !keep;
            EXPECT_EQ(answer.value("copy", ""), removed ? "removed" : "kept");
            if (removed) {
                EXPECT_FALSE(mq::MirrorStart::vaultWithUid(crypto::id::fromUuid(h.vaultUuid)));
            } else {
                ASSERT_TRUE(mq::MirrorVaults::get(h.vaultId));
                EXPECT_EQ(mq::MirrorVaults::get(h.vaultId)->role, "orphaned");
            }
        }
    // Deleting a copy held here: refused, naming what to do instead.
    const auto live = heldCopy("live");
    try {
        (void)ops::vaults::remove(superUser, {.id = live.vaultId, .mirror_copy = "remove"});
        ADD_FAILURE() << "a held copy was deleted";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "vault_mirrored");
        EXPECT_NE(std::string(e.what()).find("vh mirror detach"), std::string::npos) << e.what();
    }
    const auto orphaned = heldCopy("orphaned");
    try {
        (void)ops::vaults::remove(superUser, {.id = orphaned.vaultId});
        ADD_FAILURE() << "an orphaned copy was deleted";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "vault_orphaned_copy");
        EXPECT_NE(std::string(e.what()).find("vh mirror cancel"), std::string::npos) << e.what();
        EXPECT_NE(std::string(e.what()).find("vh mirror detach"), std::string::npos) << e.what();
    }
    EXPECT_TRUE(mq::MirrorVaults::get(live.vaultId));
    EXPECT_TRUE(mq::MirrorVaults::get(orphaned.vaultId));
}

// ================================================================================================ versions on the mirror

TEST_F(MirrorLeaveDbTest, VersionsOnTheMirrorAreASuperAdminsChoiceBoundedRestoredAsAPendingWriteAndKeptAcrossADetach) {
    namespace lv = vh::recovery::local;
    const auto h = heldCopy("live");
    const auto plain = identities::manager().user(
        ops::users::create(superUser, {.name = "ml_vplain_" + mlTag(), .role = "unprivileged",
                                       .password = std::string("Mirror-Leave-Pass-123")})
            .user->id);
    EXPECT_FALSE(vh::mirror::versions::policyFor(h.vaultId)) << "off by default";
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::setVersions(plain, {.vault_id = h.vaultId, .enabled = true}); }),
              "denied");
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::setVersions(superUser, {.vault_id = h.vaultId, .enabled = true}); }),
                  "peer_forbidden");
    }
    const auto own = ops::vaults::create(superUser, {.name = "ml_own_" + mlTag(), .type = vault::model::VaultType::Local,
                                                     .owner_id = superUser->id});
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::setVersions(superUser, {.vault_id = own->id, .enabled = true}); }),
              "mirror_not_held");
    EXPECT_EQ(refusalCode([&] {
                  (void)ops::mirrors::setVersions(superUser, {.vault_id = h.vaultId, .enabled = true, .keep_last = 0,
                                                              .max_age_days = 0});
              }),
              "invalid")
        << "never unbounded";
    const auto set = ops::mirrors::setVersions(superUser, {.vault_id = h.vaultId, .enabled = true, .keep_last = 2});
    EXPECT_TRUE(set.policy.enabled);
    EXPECT_EQ(set.policy.keep_last.value_or(0), 2u);
    EXPECT_EQ(set.policy.max_age_days.value_or(0), vh::mirror::versions::kDefaultMaxAgeDays);
    const auto policy = vh::mirror::versions::policyFor(h.vaultId);
    ASSERT_TRUE(policy);

    // What the applier keeps (its own path is MirrorSubmitDbTest's): three generations of /a.txt, bounded to two.
    const auto engine = engineOf(h.vaultId);
    const auto digestBefore = mq::Digests::recompute(h.vaultId);
    for (int i = 0; i < 3; ++i) {
        const auto file = db::query::fs::File::getFileByPath(h.vaultId, "/a.txt");
        auto kept = lv::versions::retain(*engine, *file, lv::Reason::Overwrite,
                                         {.upstream = false, .held_copy_policy = *policy});
        ASSERT_TRUE(kept.active()) << "a held copy keeps what its setting asks for";
        db::Transactions::exec("ml keep", [&](pqxx::work& txn) { kept.attach(txn); });
        kept.committed();
    }
    const auto versionsOf = [&](const uint32_t vaultId) {
        return count("SELECT count(*) FROM file_versions WHERE origin = 'version' AND vault_id = " + std::to_string(vaultId));
    };
    EXPECT_EQ(versionsOf(h.vaultId), 2) << "keep_last bounds it";
    (void)lv::versions::maintain(std::time(nullptr), false);
    EXPECT_EQ(versionsOf(h.vaultId), 2);
    EXPECT_EQ(mq::Digests::recompute(h.vaultId), digestBefore) << "versions are never part of the digest";
    EXPECT_EQ(count("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(h.vaultId)), 0);
    EXPECT_TRUE(mq::Pending::list(h.vaultId).size() == 2u) << "nothing was submitted for them";

    // Listed for whoever may read the file here; restored as a change made here (a pending write), Live only.
    const auto points = ops::recovery::list(superUser, h.vaultId,
                                            {.path = "/a.txt", .include_snapshots = false, .include_versions = true,
                                             .include_provider = false});
    ASSERT_EQ(points.size(), 2u);
    const auto pendingBefore = mq::Pending::list(h.vaultId).size();
    const auto plan = ops::recovery::plan(superUser, {.recovery_id = points.front().id, .destination = "/restored"});
    const auto result = ops::recovery::restore(superUser, {.plan_id = plan.id, .token = plan.token});
    EXPECT_EQ(result.restored, 1u) << result.state << " "
                                   << (result.items.empty() ? std::string() : result.items.front().error.value_or(""));
    const auto pending = mq::Pending::list(h.vaultId);
    ASSERT_GT(pending.size(), pendingBefore) << "the destination folder and the file: changes made here";
    EXPECT_EQ(pending.back().op, "write") << "a pending write, submitted to the core like any change made here";
    vh::mirror::access::linkChanged(h.core.id, false);
    const auto again = ops::recovery::plan(superUser, {.recovery_id = points.front().id, .destination = "/again"});
    try {
        (void)ops::recovery::restore(superUser, {.plan_id = again.id, .token = again.token});
        ADD_FAILURE() << "a restore ran while the copy was read-only";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "read_only");
    }

    // After a detach they are the local vault's like any others; a removed copy takes them with it.
    (void)ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
    EXPECT_EQ(versionsOf(h.vaultId), 2);
    EXPECT_EQ(ops::recovery::list(superUser, h.vaultId,
                                  {.path = "/a.txt", .include_snapshots = false, .include_versions = true,
                                   .include_provider = false})
                  .size(),
              2u);
    const auto gone = heldCopy("live");
    (void)ops::mirrors::setVersions(superUser, {.vault_id = gone.vaultId, .enabled = true});
    {
        const auto file = db::query::fs::File::getFileByPath(gone.vaultId, "/a.txt");
        auto kept = lv::versions::retain(*engineOf(gone.vaultId), *file, lv::Reason::Delete,
                                         {.upstream = false, .held_copy_policy = vh::mirror::versions::policyFor(gone.vaultId)});
        db::Transactions::exec("ml keep", [&](pqxx::work& txn) { kept.attach(txn); });
        kept.committed();
    }
    EXPECT_EQ(versionsOf(gone.vaultId), 1);
    start::removeCopy(gone.vaultId);
    EXPECT_EQ(versionsOf(gone.vaultId), 0) << "removing the copy removes them";
}

// ================================================================================================ a held change's bytes

TEST_F(MirrorLeaveDbTest, AHeldWritesBytesAreDownloadedDecryptedAndNothingInTheVaultChanges) {
    const auto h = heldCopy("live");
    // A held write as the submit path leaves one: the person's sealed bytes under the held store.
    const auto engine = engineOf(h.vaultId);
    const auto a = db::query::fs::File::getFileByPath(h.vaultId, "/a.txt");
    uint64_t heldId = 0;
    db::Transactions::exec("ml held write", [&](pqxx::work& txn) {
        mq::HeldChange held;
        held.vault_id = h.vaultId;
        held.kind = "held";
        held.request_id = "mlwrite" + mlTag();
        held.op = "write";
        held.entry_uid = fileUid(h.vaultId, "/a.txt");
        held.args = {{"name", "a.txt"}, {"generation", a->encryption_iv}, {"key_version", a->encrypted_with_key_version},
                     {"size", a->size_bytes}};
        held.actor = {.node = "own", .id = superUser->id};
        held.reason_code = "denied";
        held.reason = "the core's role refused it";
        heldId = mq::Pending::hold(txn, held);
    });
    const auto blob = vh::mirror::submit::contents::heldBlob(h.vaultId, heldId);
    std::filesystem::create_directories(blob.parent_path());
    std::filesystem::copy_file(a->backing_path, blob);
    const auto before = entries(h.vaultId);
    const auto plain = identities::manager().user(
        ops::users::create(superUser, {.name = "ml_hplain_" + mlTag(), .role = "unprivileged",
                                       .password = std::string("Mirror-Leave-Pass-123")})
            .user->id);
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::heldContent(plain, heldId); }), "denied");
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::heldContent(superUser, h.heldId); }), "invalid")
        << "a rename holds no bytes";

    const auto content = ops::mirrors::heldContent(superUser, heldId);
    EXPECT_EQ(content.size, a->size_bytes);
    const auto bytes = storage::readAll(*content.reader, 1u << 20);
    EXPECT_EQ(std::string(bytes.begin(), bytes.end()), "alpha from the core");
    EXPECT_EQ(entries(h.vaultId), before) << "nothing in the vault changes";
    EXPECT_EQ(mq::Pending::heldChange(heldId)->state, "open");
}

// ================================================================================== with the planned switch (piece B)

// A link that answers nothing (the switch refusals asked here come before any request).
class MlNoLink final : public vh::mirror::follow::Transport {
public:
    bool connected(uint32_t) override { return true; }
    std::optional<Answer> request(uint32_t, const std::string&, const json&) override { return std::nullopt; }
    bool notify(uint32_t, const std::string&, const json&) override { return true; }
};

// A switch open on the mirror (prepared, waiting for the core's decision) never holds a detach up, and ends with it.
TEST_F(MirrorLeaveDbTest, ADetachDuringAPlannedSwitchCompletesAndLeavesNoSwitchOpen) {
    const auto h = heldCopy("live");
    sql("UPDATE mirror_vault SET state = 'switching' WHERE vault_id = " + std::to_string(h.vaultId));
    sql("INSERT INTO mirror_switch (switch_id, vault_id, peer_id, side, phase, term, deadline, asked_on) VALUES "
        "(gen_random_uuid(), " + std::to_string(h.vaultId) + ", " + std::to_string(h.core.id) +
        ", 'mirror', 'prepared', 1, now() + interval '1 minute', 'core')");
    vh::mirror::access::reload();
    const auto d = ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
    EXPECT_EQ(d.record.was_state.value_or(""), "switching");
    EXPECT_FALSE(mq::MirrorVaults::get(h.vaultId));
    EXPECT_EQ(count("SELECT count(*) FROM mirror_switch WHERE vault_id = " + std::to_string(h.vaultId) +
                    " AND (ended_at IS NULL OR notify)"),
              0)
        << "no switch is left open on this side";
    EXPECT_EQ(scalar("SELECT phase || ':' || reason FROM mirror_switch WHERE vault_id = " + std::to_string(h.vaultId)),
              "abandoned:mirror_detached");
    write(engineOf(h.vaultId), "/after.txt", "a local vault");
    EXPECT_EQ(read(h.vaultId, "/after.txt"), "a local vault");
}

// The old core decided `switched` (it is now the other server's mirror) when that server detached instead of taking
// the role: the detach notice leaves this server's copy orphaned (kept, read-only; its super admin detaches or removes
// it), and no switch here waits to be told.
TEST_F(MirrorLeaveDbTest, ADetachNoticeAfterASwitchWasDecidedLeavesTheOldCoreAnOrphanedCopy) {
    const auto h = heldCopy("live");   // this server: the old core, now the mirror of h.core in term 2
    sql("UPDATE mirror_vault SET state = 'switching', term = 2, last_seq = 0 WHERE vault_id = " + std::to_string(h.vaultId));
    sql("INSERT INTO mirror_switch (switch_id, vault_id, peer_id, side, phase, term, deadline, asked_on, notify, ended_at) "
        "VALUES (gen_random_uuid(), " + std::to_string(h.vaultId) + ", " + std::to_string(h.core.id) +
        ", 'core', 'switched', 1, now() + interval '1 minute', 'core', TRUE, now())");
    vh::mirror::access::reload();
    const auto answer = leave::detachedReceived(h.core, {{"vault_uid", vl::keykit::toBase32(crypto::id::fromUuid(h.vaultUuid))},
                                                         {"at", {{"term", 1}, {"seq", 12}}}, {"missing", 0}});
    EXPECT_TRUE(answer.at("recorded").get<bool>());
    EXPECT_EQ(answer.value("copy", ""), "kept");
    ASSERT_TRUE(mq::MirrorVaults::get(h.vaultId));
    EXPECT_EQ(mq::MirrorVaults::get(h.vaultId)->role, "orphaned");
    EXPECT_EQ(vh::mirror::access::reason(h.vaultId), vh::mirror::access::kOrphaned);
    EXPECT_TRUE(mq::Pending::list(h.vaultId).empty()) << "its pending changes are held";
    EXPECT_EQ(count("SELECT count(*) FROM mirror_switch WHERE vault_id = " + std::to_string(h.vaultId) + " AND notify"), 0)
        << "nothing left to tell a server that left";
    EXPECT_TRUE(mq::MirrorDetach::forVault(h.vaultId)) << "the same-uid refusal holds between the two";
    // Its super admin makes it this server's vault again.
    (void)ops::mirrors::detach(superUser, {.vault_id = h.vaultId});
    EXPECT_FALSE(mq::MirrorVaults::get(h.vaultId));
}

// While the core deletes the vault no switch moves the role, asked on either side; and each of this piece's settings
// follows the role a server holds now.
TEST_F(MirrorLeaveDbTest, ASwitchIsRefusedDuringTheDeletionWindowAndSettingsFollowTheRoleHeldNow) {
    MlNoLink link;
    const auto mirror = newPeer("mirror");
    const auto c = coreMirrored(mirror);
    (void)ops::vaults::remove(superUser, {.id = c.vaultId, .mirror_copy = "leave"});
    EXPECT_EQ(refusalCode([&] {
                  (void)vh::mirror::switching::request(c.vaultId, superUser->id, superUser->name(), link,
                                                       std::chrono::milliseconds(0));
              }),
              "mirror_vault_deleting")
        << "on the core";
    const auto h = heldCopy("live");
    (void)leave::deletingReceived(h.core, {{"vault_uid", vl::keykit::toBase32(crypto::id::fromUuid(h.vaultUuid))},
                                           {"deleting", true}, {"purge_after", static_cast<int64_t>(std::time(nullptr) + 600)},
                                           {"copy", "leave"}});
    EXPECT_EQ(refusalCode([&] {
                  (void)vh::mirror::switching::request(h.vaultId, superUser->id, superUser->name(), link,
                                                       std::chrono::milliseconds(0));
              }),
              "mirror_vault_deleting")
        << "on the mirror";
    (void)leave::deletingReceived(h.core, {{"vault_uid", vl::keykit::toBase32(crypto::id::fromUuid(h.vaultUuid))},
                                           {"deleting", false}});

    // Versions: the mirror's setting is dormant while that server is the core, and applies again when it is the mirror.
    (void)ops::mirrors::setVersions(superUser, {.vault_id = h.vaultId, .enabled = true});
    ASSERT_TRUE(vh::mirror::versions::policyFor(h.vaultId));
    // As a switch leaves it: the core in a new term, the grant gone (a core holds none).
    sql("UPDATE mirror_vault SET role = 'core', granted_role_name = NULL, granted_files_permissions = NULL, "
        "granted_directories_permissions = NULL, granted_sync_permissions = NULL, granted_roles_permissions = NULL, "
        "granted_by_node = NULL, granted_at = NULL WHERE vault_id = " + std::to_string(h.vaultId));
    vh::mirror::access::reload();
    rbac::mirrored::reload();
    vh::mirror::versions::invalidate();
    EXPECT_FALSE(vh::mirror::versions::policyFor(h.vaultId)) << "a core keeps no versions of its own changes";
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::setVersions(superUser, {.vault_id = h.vaultId, .enabled = false}); }),
              "mirror_not_held")
        << "the setting is the mirror's";
    // Detach is the mirror's: a core is not detached.
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detach(superUser, {.vault_id = h.vaultId}); }), "mirror_not_held");
    // The one-step delete is the core's: now it needs the choice.
    EXPECT_EQ(refusalCode([&] { (void)ops::vaults::remove(superUser, {.id = h.vaultId}); }), "mirror_copy_choice_required");
    sql("UPDATE mirror_vault SET role = 'mirror' WHERE vault_id = " + std::to_string(h.vaultId));
    vh::mirror::access::reload();
    rbac::mirrored::reload();
    vh::mirror::versions::invalidate();
    ASSERT_TRUE(vh::mirror::versions::policyFor(h.vaultId)) << "the mirror again: its setting applies again";
    EXPECT_EQ(refusalCode([&] { (void)ops::vaults::remove(superUser, {.id = h.vaultId, .mirror_copy = "leave"}); }),
              "vault_mirrored")
        << "and a copy held here is never deleted as a vault";
}

}
