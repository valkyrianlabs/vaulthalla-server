// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Detach a copy (server mirror phase 2, wave 5, piece C; migration 169; design/peers/mirror.md "Detach a copy", "As
// built: detach a copy"; mirror::copy, ops::mirrors::detachCopy, db::query::mirror::MirrorCopies). One database holds
// one server, so a held copy is made as the leave tests make one: a local vault with folders, files (one large enough to
// stream in several chunks, one empty), a symlink, chosen modes and modification times and a trashed file, then its
// `mirror` row and grant, with one file whose contents never arrived (its content row, no bytes on disk). The
// two-daemon proof is `vhh drill peers` step 9d.
//
// Covered: the new vault's contents and metadata equal the held copy's (names, folders, modes, modification times,
// symlinks; new vault uid, entry uids and key); the missing file listed and absent; trash not copied; the held copy
// untouched; who may and the refusals (not held, a plain user, an agent, a scoped device, the switch off, no room in
// the quota, a second copy, a taken name); a cancel before and during the copy leaving no vault; a stop mid-copy (a
// daemon restart) leaving the partial vault gated, read-only to everything else, and the next run starting over and
// finishing.

#include "../helpers/db_suite.hpp"
#include "auth/stepup/StepUp.hpp"
#include "audit/Trail.hpp"
#include "config/Registry.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/Copy.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fuse/resolver/Resolved.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/copy/Copy.hpp"
#include "ops/Error.hpp"
#include "ops/MirrorLeave.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "rbac/Mirrored.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace vh::test_mirror_copy_db {

using json = nlohmann::json;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace mq = db::query::mirror;
namespace copy = vh::mirror::copy;
namespace access = vh::mirror::access;

std::string mcTag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000) + "c" +
           std::to_string(n.fetch_add(1));
}

class MirrorCopyDbTest : public vh::test::db::Suite {
protected:
    inline static config::Config savedConfig;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mirror_copy")) return;
        savedConfig = config::Registry::get();
        setExperimental(true);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        config::Registry::set(savedConfig);
        rbac::mirrored::resetForTesting();
        access::resetForTesting();
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        setExperimental(true);
        copy::resetForTesting();
    }

    static void setExperimental(const bool on) {
        auto cfg = config::Registry::get();
        cfg.peers.experimental = on;
        config::Registry::set(cfg);
    }

    static void sql(const std::string& statement) {
        db::Transactions::exec("mirror copy test", [&](pqxx::work& txn) { txn.exec(statement); });
    }
    static std::string scalar(const std::string& query) {
        return db::Transactions::exec("mirror copy test", [&](pqxx::work& txn) {
            const auto r = txn.exec(query);
            return r.empty() || r[0][0].is_null() ? std::string() : r[0][0].as<std::string>();
        });
    }
    static int64_t count(const std::string& query) { return std::stoll(scalar(query)); }

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
        const auto bytes = storage::readAll(*reader, 4u << 20);
        return {bytes.begin(), bytes.end()};
    }

    static void setAttrs(const uint32_t vaultId, const std::string& path, const uint32_t mode, const int64_t mtimeUs) {
        const auto e = db::query::fs::Entry::getFSEntryByPath(vaultId, path);
        ASSERT_TRUE(e) << path;
        ASSERT_TRUE(db::query::fs::Entry::setAttributes(e->id, {.mode = mode, .mtime_us = mtimeUs}, superUser->id));
        if (const auto fresh = db::query::fs::Entry::getFSEntryById(e->id))
            runtime::Deps::get().fsCache->cacheEntry(fresh);
    }

    // Every entry of the vault, as "path kind mode mtime [target]", in path order: what a copy must equal.
    static std::string tree(const uint32_t vaultId, const bool withTimes = true) {
        return scalar("SELECT string_agg(e.path || ' ' || CASE WHEN d.fs_entry_id IS NOT NULL THEN 'd' WHEN "
                      "f.fs_entry_id IS NOT NULL THEN 'f' || f.size_bytes ELSE 'l' || s.target END || ' ' || "
                      "COALESCE(e.mode, 0)" +
                      std::string(withTimes ? " || ' ' || e.updated_at::text" : "") +
                      ", '|' ORDER BY e.path COLLATE \"C\") FROM fs_entry e "
                      "LEFT JOIN directories d ON d.fs_entry_id = e.id LEFT JOIN files f ON f.fs_entry_id = e.id "
                      "LEFT JOIN symlinks s ON s.fs_entry_id = e.id WHERE e.vault_id = " + std::to_string(vaultId) +
                      " AND e.path <> '/missing.txt'");
    }

    static vh::peer::Record newPeer() {
        const auto t = mcTag();
        db::query::peer::NewPeer p;
        p.node_id = "core-" + t;
        p.name = "core-" + t;
        p.spki_sha256 = std::string(40, 'c');
        for (const auto ch : t) p.spki_sha256.push_back(std::isdigit(static_cast<unsigned char>(ch)) ? ch : 'f');
        p.spki_sha256.resize(64, '0');
        p.wrap_public_key.fill(9);
        return db::query::peer::Peers::insert(p);
    }

    struct Held {
        uint32_t vaultId{};
        std::string name;
        std::string big;
    };

    // A held copy: /a.txt, /empty.txt, /dir (0750) with /dir/sub/c.txt (0600) and /dir/big.bin (~300 KiB), a symlink
    // /link -> dir/sub/c.txt, chosen modification times on everything, a trashed /gone.txt, and /missing.txt whose
    // contents never arrived. `orphaned` makes it an orphaned copy.
    static Held heldCopy(const bool orphaned = false) {
        Held h;
        h.name = "mc_held_" + mcTag();
        const auto v = ops::vaults::create(superUser, {.name = h.name, .type = vault::model::VaultType::Local,
                                                       .owner_id = superUser->id});
        h.vaultId = v->id;
        const auto engine = engineOf(h.vaultId);
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/dir/sub"), .engine = engine, .user = superUser});
        write(engine, "/a.txt", "alpha from the core");
        write(engine, "/empty.txt", "");
        write(engine, "/dir/sub/c.txt", "charlie, deep down");
        for (int i = 0; h.big.size() < 300 * 1024; ++i) h.big += "line " + std::to_string(i) + " of the big file\n";
        write(engine, "/dir/big.bin", h.big);
        write(engine, "/missing.txt", "never arrived");
        write(engine, "/gone.txt", "trashed before the copy");
        fs::Filesystem::remove(engine->vaultPathToFusePath("/gone.txt"), superUser->id);
        {
            fuse::resolver::Resolved r;
            r.user = superUser;
            r.engine = engine;
            r.path = engine->vaultPathToFusePath("/link");
            r.parentEntry = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath("/"));
            const auto [err, link] = fs::Filesystem::createSymlink({.resolved = r, .target = "dir/sub/c.txt"});
            EXPECT_EQ(err, 0);
        }
        int64_t t = 1577923200LL * 1000000 + 123456;   // 2020-01-02, with microseconds
        for (const auto& [path, mode] : std::vector<std::pair<std::string, uint32_t>>{
                 {"/a.txt", 0640}, {"/empty.txt", 0644}, {"/dir/sub/c.txt", 0600}, {"/dir/big.bin", 0644},
                 {"/link", 0777}, {"/dir/sub", 0700}, {"/dir", 0750}})
            setAttrs(h.vaultId, path, mode, t += 3600LL * 1000000);

        (void)mq::MirrorVaults::startMirror(h.vaultId, newPeer().id);
        EXPECT_TRUE(mq::MirrorVaults::recordGrant(h.vaultId, {.role_name = "reader", .files = 0xffffffffu,
                                                              .directories = 0xffffffffu, .sync = 0, .roles = 0,
                                                              .granted_by_node = "core", .granted_at = 0}));
        sql("UPDATE mirror_vault SET copy_finished = TRUE, last_seq = 12, acked_term = 1, acked_seq = 10 WHERE vault_id = " +
            std::to_string(h.vaultId));
        // /missing.txt: its generation expected, its bytes not here.
        const auto m = db::query::fs::File::getFileByPath(h.vaultId, "/missing.txt");
        mq::PendingContents::expect({.vault_id = h.vaultId, .object_uid = *m->object_uid, .generation = m->encryption_iv,
                                     .key_version = m->encrypted_with_key_version, .size_bytes = m->size_bytes,
                                     .content_hash = m->content_hash.value_or(std::string(64, '0')), .mtime_us = 0});
        std::filesystem::remove(m->backing_path);
        if (orphaned) (void)mq::MirrorVaults::orphan(h.vaultId);
        access::reload();
        return h;
    }

    static std::string sourceFingerprint(const uint32_t vaultId) {
        return tree(vaultId) + "#" +
               scalar("SELECT role || state FROM mirror_vault WHERE vault_id = " + std::to_string(vaultId)) + "#" +
               scalar("SELECT count(*) FROM mirror_content_pending WHERE vault_id = " + std::to_string(vaultId)) + "#" +
               scalar("SELECT count(*) FROM files_trashed WHERE vault_id = " + std::to_string(vaultId)) + "#" +
               scalar("SELECT string_agg(f.encryption_iv, ',' ORDER BY f.fs_entry_id) FROM files f JOIN fs_entry e ON "
                      "e.id = f.fs_entry_id WHERE e.vault_id = " + std::to_string(vaultId));
    }

    static bool vaultExists(const uint32_t id) {
        return count("SELECT count(*) FROM vault WHERE id = " + std::to_string(id)) == 1;
    }
};

// ============================================================================================ the copy itself

TEST_F(MirrorCopyDbTest, TheCopyEqualsTheHeldCopyInContentsAndMetadataListsTheMissingFileAndLeavesTheSourceUntouched) {
    for (const bool orphaned : {false, true}) {
        SCOPED_TRACE(orphaned ? "orphaned" : "mirror");
        const auto h = heldCopy(orphaned);
        const auto before = sourceFingerprint(h.vaultId);

        auto job = ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId});
        EXPECT_EQ(job.state, "running");
        EXPECT_EQ(job.name, h.name + " copy");
        EXPECT_EQ(job.owner_id, superUser->id) << "the caller by default";
        EXPECT_EQ(job.entries_total, 7u) << "a.txt, empty.txt, dir, dir/sub, dir/sub/c.txt, dir/big.bin, link";
        ASSERT_EQ(job.skipped.size(), 1u);
        EXPECT_EQ(job.skipped[0].path, "/missing.txt");
        EXPECT_EQ(job.skipped[0].reason, "contents_missing");

        job = copy::run(job.id);
        ASSERT_EQ(job.state, "finished") << job.error.value_or("");
        ASSERT_TRUE(job.vault_id);
        const auto target = *job.vault_id;
        EXPECT_EQ(job.entries_done, job.entries_total);
        EXPECT_EQ(job.bytes_done, job.bytes_total);
        EXPECT_EQ(job.attempts, 1u);
        const auto status = ops::mirrors::copyStatus(superUser, h.vaultId);
        ASSERT_TRUE(status);
        EXPECT_EQ(status->id, job.id);
        EXPECT_EQ(copy::toJson(*status).at("skipped").at(0).at("path"), "/missing.txt");

        // Equal: every name, folder, mode, modification time and symlink; the contents byte for byte.
        EXPECT_EQ(tree(target), tree(h.vaultId));
        for (const auto* want : {"/dir d 488 ", "/dir/sub/c.txt f18 384 2020-01-02 ", "/link ldir/sub/c.txt 511 ",
                                 "/empty.txt f0 420 ", "/dir/big.bin f"})
            EXPECT_NE(tree(target).find(want), std::string::npos) << want << " in " << tree(target);
        EXPECT_EQ(tree(target).find("/gone.txt"), std::string::npos) << "trash is not copied";
        EXPECT_EQ(read(target, "/a.txt"), "alpha from the core");
        EXPECT_EQ(read(target, "/empty.txt"), "");
        EXPECT_EQ(read(target, "/dir/sub/c.txt"), "charlie, deep down");
        EXPECT_EQ(read(target, "/dir/big.bin"), h.big) << "streamed in chunks, whole";
        // The missing file is absent; trash is not copied.
        EXPECT_FALSE(db::query::fs::File::getFileByPath(target, "/missing.txt"));
        EXPECT_EQ(count("SELECT count(*) FROM files_trashed WHERE vault_id = " + std::to_string(target)), 0);

        // A separate vault: its own uid, entry uids and key; a plain local vault owned by the caller, writable.
        const auto t = std::to_string(target), s = std::to_string(h.vaultId);
        EXPECT_NE(scalar("SELECT uid::text FROM vault WHERE id = " + t), scalar("SELECT uid::text FROM vault WHERE id = " + s));
        EXPECT_EQ(count("SELECT count(*) FROM files a JOIN fs_entry ea ON ea.id = a.fs_entry_id JOIN files b ON "
                        "b.object_uid = a.object_uid JOIN fs_entry eb ON eb.id = b.fs_entry_id WHERE ea.vault_id = " + t +
                        " AND eb.vault_id = " + s),
                  0) << "new entry uids";
        EXPECT_EQ(count("SELECT count(*) FROM vault_keys k JOIN vault_keys o ON o.encrypted_key = k.encrypted_key "
                        "WHERE k.vault_id = " + t + " AND o.vault_id = " + s),
                  0) << "its own key";
        EXPECT_EQ(count("SELECT owner_id FROM vault WHERE id = " + t), superUser->id);
        EXPECT_FALSE(mq::MirrorVaults::get(target));
        EXPECT_EQ(access::state(target), access::State::NotMirrored) << "the gate is off once the copy finished";
        write(engineOf(target), "/mine.txt", "written into the copy");
        EXPECT_EQ(read(target, "/mine.txt"), "written into the copy");

        // The held copy is exactly what it was, and still held.
        EXPECT_EQ(sourceFingerprint(h.vaultId), before);
        EXPECT_TRUE(access::held(h.vaultId));
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        EXPECT_EQ(count("SELECT count(*) FROM audit_event WHERE action = 'mirror.detach.copy' AND vault_id = " + s), 1);
        EXPECT_EQ(count("SELECT count(*) FROM audit_event WHERE action = 'mirror.detach.copy.finished' AND vault_id = " +
                        t),
                  1);
        // A second copy takes the next name.
        const auto again = ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId});
        EXPECT_EQ(again.name, h.name + " copy 2");
        EXPECT_EQ(copy::run(again.id).state, "finished");
    }
}

// ============================================================================================ who may, refusals

TEST_F(MirrorCopyDbTest, TheSamePermissionAndRefusalsAsDetachAndNoRoomOrATakenNameRefusesUpFront) {
    namespace stepup = auth::stepup;
    const auto h = heldCopy();
    const auto plain = identities::manager().user(
        ops::users::create(superUser, {.name = "mc_plain_" + mcTag(), .role = "unprivileged",
                                       .password = std::string("Mirror-Copy-Pass-123")})
            .user->id);
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(plain, {.vault_id = h.vaultId}); }), "denied");
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::copyStatus(plain, h.vaultId); }), "denied");
    {
        const stepup::Scope agent(stepup::Channel::Agent);
        EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId}); }),
                  "peer_forbidden");
    }
    setExperimental(false);
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId}); }),
              "peers_experimental");
    setExperimental(true);

    // A vault of this server's own is not a held copy.
    const auto own = ops::vaults::create(superUser, {.name = "mc_own_" + mcTag(), .type = vault::model::VaultType::Local,
                                                     .owner_id = superUser->id});
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(superUser, {.vault_id = own->id}); }), "mirror_not_held");
    // A taken name, and an owner that is not a sign-in account here.
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId, .name = own->name}); }),
              "conflict");
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId, .owner = "nobody_here"}); }),
              "not_found");
    // A quota that can't hold a second copy (the copy takes the held vault's).
    const auto small = heldCopy();
    sql("UPDATE vault SET quota = 4194304 WHERE id = " + std::to_string(small.vaultId));
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(superUser, {.vault_id = small.vaultId}); }),
              "mirror_copy_no_space");
    // One copy at a time; the cancel of none running is refused.
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::cancelCopy(superUser, h.vaultId); }), "mirror_copy_not_running");
    const auto job = ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId, .owner = plain->name()});
    EXPECT_EQ(job.owner_id, plain->id);
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId}); }), "conflict");
    const auto done = copy::run(job.id);
    ASSERT_EQ(done.state, "finished") << done.error.value_or("");
    EXPECT_EQ(count("SELECT owner_id FROM vault WHERE id = " + std::to_string(*done.vault_id)), plain->id);
    EXPECT_EQ(count("SELECT count(*) FROM vault WHERE id IN (" + std::to_string(h.vaultId) + ", " +
                    std::to_string(own->id) + ") AND owner_id = " + std::to_string(superUser->id)),
              2) << "nothing else changed hands";
}

// ============================================================================================ cancel and restart

TEST_F(MirrorCopyDbTest, ACancelBeforeOrDuringTheCopyLeavesNoVault) {
    const auto h = heldCopy();
    const auto before = sourceFingerprint(h.vaultId);
    const auto vaults = count("SELECT count(*) FROM vault");

    // Before it ran: nothing is ever created.
    auto job = ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId});
    (void)ops::mirrors::cancelCopy(superUser, h.vaultId);
    job = copy::run(job.id);
    EXPECT_EQ(job.state, "cancelled");
    EXPECT_FALSE(job.vault_id);
    EXPECT_EQ(count("SELECT count(*) FROM vault"), vaults);

    // While it runs (asked as it reaches its first file): the partial vault is removed.
    job = ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId});
    std::optional<uint32_t> partial;
    int asked = 0;
    job = copy::run(job.id, [&] {
        if (++asked == 3) {
            partial = mq::MirrorCopies::get(job.id)->vault_id;
            (void)ops::mirrors::cancelCopy(superUser, h.vaultId);
        }
        return false;
    });
    EXPECT_EQ(job.state, "cancelled");
    ASSERT_TRUE(partial) << "the new vault existed when the cancel came";
    EXPECT_FALSE(vaultExists(*partial));
    EXPECT_FALSE(job.vault_id);
    EXPECT_EQ(count("SELECT count(*) FROM vault"), vaults);
    EXPECT_EQ(access::state(*partial), access::State::NotMirrored);
    EXPECT_EQ(sourceFingerprint(h.vaultId), before);
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_EQ(count("SELECT count(*) FROM audit_event WHERE action = 'mirror.detach.copy.cancel' AND vault_id = " +
                    std::to_string(h.vaultId)),
              2);
}

TEST_F(MirrorCopyDbTest, AStopMidCopyKeepsThePartialVaultGatedAndTheNextRunStartsOverAndFinishes) {
    const auto h = heldCopy();
    auto job = ops::mirrors::detachCopy(superUser, {.vault_id = h.vaultId});
    int asked = 0;
    job = copy::run(job.id, [&] { return ++asked >= 4; });   // the daemon stops mid-file
    EXPECT_EQ(job.state, "running");
    ASSERT_TRUE(job.vault_id);
    const auto partial = *job.vault_id;
    EXPECT_TRUE(vaultExists(partial));

    // A restart: memory is gone, the gate comes back from the row before anything serves the vault.
    access::resetForTesting();
    access::reload();
    EXPECT_EQ(access::state(partial), access::State::ReadOnly);
    EXPECT_EQ(access::reason(partial), access::kCopyWriting);
    const auto engine = engineOf(partial);
    EXPECT_THROW((void)fs::Filesystem::createFile({.path = "/intruder.txt",
                                                   .fuse_path = engine->vaultPathToFusePath("/intruder.txt"),
                                                   .buffer = {'x'}, .engine = engine, .user = superUser}),
                 ops::Refused)
        << "nothing but the copy writes the partial vault";
    EXPECT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/intruder"), .engine = engine,
                                     .user = superUser}),
              -EROFS);

    job = copy::run(job.id);
    ASSERT_EQ(job.state, "finished") << job.error.value_or("");
    EXPECT_EQ(job.attempts, 2u);
    EXPECT_FALSE(vaultExists(partial)) << "the partial vault went; the copy started over";
    ASSERT_TRUE(job.vault_id);
    EXPECT_NE(*job.vault_id, partial);
    EXPECT_EQ(tree(*job.vault_id), tree(h.vaultId));
    EXPECT_EQ(read(*job.vault_id, "/dir/big.bin"), h.big);
    EXPECT_EQ(access::state(*job.vault_id), access::State::NotMirrored);
}

// The upgrade path of migration 169 is SqlDeployerHistoryDb.MirrorCopyMigration169IsAdditiveAndIdempotent.

}
