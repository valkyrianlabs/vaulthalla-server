// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// #259: the filesystem change journal (migration 115) and fs.changes.list. Triggers log every entry mutation in its own
// transaction, so these tests drive each write path's statements (the FUSE seal's row update, uploads' createFile, the
// ws mutations, copy, trash, symlinks, out-of-band SQL) and read the feed back through ops::fs_changes, as
// Desktop does. tools/contracts/test_fs_change_journal_contract.py keeps every SQL writer of the entry tables
// classified, so a new path can't bypass these triggers unnoticed.

#include "db/Transactions.hpp"
#include "db/query/fs/ChangeLog.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/FsChanges.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Changes.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_fs_change_journal {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
using Lines = std::vector<std::string>;
using ChangeLog = db::query::fs::ChangeLog;

std::string cjTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "j" + std::to_string(n.fetch_add(1));
}

class FsChangeJournalDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    EnginePtr engine;
    uint32_t vaultId{};

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_fs_change_journal] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_fs_change_journal_" + cjTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = vh::identities::manager().userByName("admin");

        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());
        protocols::http::access::clearCachesForTesting();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        const auto vault = ops::vaults::create(superUser, {.name = "cj_" + cjTag(), .type = vault::model::VaultType::Local});
        vaultId = vault->id;
        engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        ASSERT_TRUE(engine);
    }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    [[nodiscard]] std::shared_ptr<protocols::ws::Session> wsAs(const UserPtr& user) const {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = user;
        return session;
    }

    [[nodiscard]] json ws(const std::string& command, json payload) const {
        namespace h = protocols::ws::handler::fs;
        payload["vault_id"] = vaultId;
        const auto session = wsAs(superUser);
        if (command == "mkdir") return h::Storage::mkdir(payload, session);
        if (command == "rename") return h::Storage::rename(payload, session);
        if (command == "move") return h::Storage::move(payload, session);
        if (command == "copy") return h::Storage::copy(payload, session);
        if (command == "delete") return h::Storage::remove(payload, session);
        ADD_FAILURE() << "unknown command " << command;
        return {};
    }

    [[nodiscard]] uint64_t anchor(const UserPtr& user) const {
        const auto r = ops::fs_changes::list(user, {.vault_id = vaultId});
        EXPECT_TRUE(r.changes.empty());
        EXPECT_FALSE(r.expired);
        return r.revision;
    }

    [[nodiscard]] ops::fs_changes::ListResult since(const UserPtr& user, const uint64_t revision,
                                                    const uint64_t limit = ops::fs_changes::kMaxLimit) const {
        return ops::fs_changes::list(user, {.vault_id = vaultId, .since = revision, .limit = limit});
    }

    // "kind type path" per change ("rename file /b.txt <- /a.txt" for a rename or move).
    [[nodiscard]] static Lines lines(const std::vector<db::query::fs::Change>& changes) {
        Lines out;
        for (const auto& c : changes) {
            auto line = c.kind + " " + c.entry_type.value_or("?") + " " + c.path;
            if (c.old_path) line += " <- " + *c.old_path;
            out.push_back(std::move(line));
        }
        return out;
    }

    // Changes since `revision`, as lines, and moves the cursor.
    [[nodiscard]] Lines drain(const UserPtr& user, uint64_t& revision) const {
        const auto r = since(user, revision);
        EXPECT_FALSE(r.expired);
        EXPECT_FALSE(r.more);
        EXPECT_GE(r.revision, revision);
        for (const auto& c : r.changes) EXPECT_GT(c.revision, revision);
        revision = r.revision;
        return lines(r.changes);
    }

    [[nodiscard]] UserPtr userWithVaultRole(const std::string& role) const {
        const auto created = ops::users::create(superUser, {.name = "cj_user_" + cjTag(), .role = "unprivileged",
                                                            .password = std::string("Change-Journal-Pass-123")});
        (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = vaultId,
                                                                 .subject = {.type = "user", .id = created.user->id}},
                                                      .role = role});
        return vh::identities::manager().user(created.user->id);
    }

    void deny(const UserPtr& user, const std::vector<std::string>& permissions, const std::string& pattern) const {
        ops::roles::PermissionEdit edit;
        for (const auto& p : permissions) edit.changes.emplace_back(p, false);
        (void)ops::roles::addVaultRoleOverrides(superUser, {
            .target = {.vault_id = vaultId, .subject = {.type = "user", .id = user->id}},
            .permissions = edit,
            .pattern = pattern});
    }

    [[nodiscard]] uint32_t entryId(const std::string& path) const {
        const auto entry = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
        EXPECT_TRUE(entry) << path;
        return entry ? entry->id : 0;
    }
};

// Each write path's statements journal exactly what changed, with nothing for directory totals or updated_at.
TEST_F(FsChangeJournalDbTest, EveryWritePathJournalsItsChange) {
    auto cursor = anchor(superUser);

    // mkdir (FUSE mkdir and ws fs.dir.create go through Filesystem::mkdir) and uploads (createFile, the seal of every
    // HTTP and ws upload lane).
    engine->mkdir("/docs", superUser);
    write("/docs/a.txt", "first");
    EXPECT_EQ(drain(superUser, cursor), (Lines{"create directory /docs", "create file /docs/a.txt"}));

    write("/docs/a.txt", "second, longer");
    EXPECT_EQ(drain(superUser, cursor), (Lines{"update file /docs/a.txt"}));

    // The FUSE seal (WorkingCopies::seal → updateFile): new bytes under the same key version.
    auto sealed = db::query::fs::File::getFileByPath(vaultId, "/docs/a.txt");
    ASSERT_TRUE(sealed);
    sealed->size_bytes += 3;
    sealed->content_hash = "sealed-" + cjTag();
    db::query::fs::File::updateFile(sealed);
    EXPECT_EQ(drain(superUser, cursor), (Lines{"update file /docs/a.txt"}));

    // Key rotation re-encrypts under the next key version: no change to the plaintext, none in the feed.
    sealed->encryption_iv = "rotated-iv-" + cjTag();
    sealed->encrypted_with_key_version += 1;
    db::query::fs::File::setEncryptionIVAndVersion(sealed);
    EXPECT_EQ(drain(superUser, cursor), Lines{});

    // ws mutations.
    (void)ws("mkdir", {{"path", "/box"}});
    (void)ws("rename", {{"from", "/docs/a.txt"}, {"to", "/docs/b.txt"}});
    (void)ws("move", {{"from", "/docs/b.txt"}, {"to", "/box/b.txt"}});
    (void)ws("copy", {{"from", "/box/b.txt"}, {"to", "/docs/c.txt"}});
    EXPECT_EQ(drain(superUser, cursor), (Lines{"create directory /box", "rename file /docs/b.txt <- /docs/a.txt",
                                               "move file /box/b.txt <- /docs/b.txt", "create file /docs/c.txt"}));

    // Delete: a file goes to the trash (files row first), a folder takes its children with it.
    (void)ws("delete", {{"path", "/docs/c.txt"}});
    EXPECT_EQ(drain(superUser, cursor), (Lines{"delete file /docs/c.txt"}));
    (void)ws("delete", {{"path", "/box"}});
    const auto gone = drain(superUser, cursor);
    EXPECT_NE(std::ranges::find(gone, "delete directory /box"), gone.end()) << ::testing::PrintToString(gone);
    EXPECT_NE(std::ranges::find(gone, "delete file /box/b.txt"), gone.end()) << ::testing::PrintToString(gone);
}

TEST_F(FsChangeJournalDbTest, SymlinksAndOutOfBandSqlJournalToo) {
    engine->mkdir("/links", superUser);
    auto cursor = anchor(superUser);

    auto link = std::make_shared<fs::model::Symlink>();
    link->vault_id = static_cast<int32_t>(vaultId);
    link->parent_id = static_cast<int32_t>(entryId("/links"));
    link->name = "latest";
    link->path = "/links/latest";
    link->fuse_path = engine->vaultPathToFusePath(link->path);
    link->base32_alias = "cj" + cjTag();
    link->target = "a.txt";
    link->created_by = link->last_modified_by = static_cast<int32_t>(superUser->id);
    const auto linkId = db::query::fs::Symlink::upsertSymlink(link);
    EXPECT_EQ(drain(superUser, cursor), (Lines{"create symlink /links/latest"}));

    // psql by hand: a rename, a mode change, a new symlink target; updated_at alone is not a change.
    db::Transactions::exec("cj out of band", [&](pqxx::work& txn) {
        txn.exec("UPDATE fs_entry SET name = 'newest', path = '/links/newest' WHERE id = $1", pqxx::params{linkId});
        txn.exec("UPDATE fs_entry SET mode = 511 WHERE id = $1", pqxx::params{linkId});
        txn.exec("UPDATE symlinks SET target = 'b.txt' WHERE fs_entry_id = $1", pqxx::params{linkId});
        txn.exec("UPDATE fs_entry SET updated_at = NOW() + INTERVAL '1 minute' WHERE id = $1", pqxx::params{linkId});
    });
    EXPECT_EQ(drain(superUser, cursor), (Lines{"rename symlink /links/newest <- /links/latest",
                                               "update symlink /links/newest", "update symlink /links/newest"}));
}

// Revisions are commit order: a change that commits after another is numbered after it, whenever it was written.
TEST_F(FsChangeJournalDbTest, RevisionsFollowCommitOrder) {
    write("/early.txt", "e");
    write("/late.txt", "l");
    const auto earlyId = entryId("/early.txt");
    const auto lateId = entryId("/late.txt");
    auto cursor = anchor(superUser);

    db::Transactions::exec("cj written first, committed last", [&](pqxx::work& txn) {
        txn.exec("UPDATE fs_entry SET name = 'early2.txt', path = '/early2.txt' WHERE id = $1", pqxx::params{earlyId});
        db::Transactions::exec("cj written last, committed first", [&](pqxx::work& inner) {
            inner.exec("UPDATE fs_entry SET name = 'late2.txt', path = '/late2.txt' WHERE id = $1", pqxx::params{lateId});
        });
        // A reader now sees only the committed change, and its cursor passes it.
        EXPECT_EQ(drain(superUser, cursor), (Lines{"rename file /late2.txt <- /late.txt"}));
    });
    // The other change commits later and comes after that cursor, not before it.
    EXPECT_EQ(drain(superUser, cursor), (Lines{"rename file /early2.txt <- /early.txt"}));
}

TEST_F(FsChangeJournalDbTest, PagesFollowTheCursor) {
    auto cursor = anchor(superUser);
    for (int i = 0; i < 5; ++i) write("/p" + std::to_string(i) + ".txt", "x");

    Lines all;
    for (int page = 0; page < 3; ++page) {
        const auto r = since(superUser, cursor, 2);
        ASSERT_FALSE(r.expired);
        EXPECT_EQ(r.changes.size(), page < 2 ? 2u : 1u);
        EXPECT_EQ(r.more, page < 2);
        for (const auto& line : lines(r.changes)) all.push_back(line);
        cursor = r.revision;
    }
    EXPECT_EQ(all, (Lines{"create file /p0.txt", "create file /p1.txt", "create file /p2.txt", "create file /p3.txt",
                          "create file /p4.txt"}));
    EXPECT_TRUE(since(superUser, cursor).changes.empty());
}

// Changes are filtered by the caller's Lookup, the rule of every listing: a rename across the line reads as a create
// (into view) or a delete (out of it).
TEST_F(FsChangeJournalDbTest, ChangesAreFilteredByLookupVisibility) {
    engine->mkdir("/open", superUser);
    engine->mkdir("/private", superUser);
    const auto user = userWithVaultRole("power_user");
    deny(user, {"vault.fs.directories.list", "vault.fs.files.preview", "vault.fs.files.download"}, "/private/**");
    deny(user, {"vault.fs.directories.list"}, "/private");
    auto cursor = anchor(user);
    auto adminCursor = anchor(superUser);

    write("/open/a.txt", "a");
    write("/private/s.txt", "s");
    (void)ws("move", {{"from", "/open/a.txt"}, {"to", "/private/a.txt"}});
    (void)ws("move", {{"from", "/private/s.txt"}, {"to", "/open/s.txt"}});

    EXPECT_EQ(drain(user, cursor), (Lines{"create file /open/a.txt", "delete file /open/a.txt",
                                          "create file /open/s.txt"}));
    EXPECT_EQ(drain(superUser, adminCursor),
              (Lines{"create file /open/a.txt", "create file /private/s.txt", "move file /private/a.txt <- /open/a.txt",
                     "move file /open/s.txt <- /private/s.txt"}));

    // Someone who can't browse the vault can't follow it.
    const auto outsider = ops::users::create(superUser, {.name = "cj_out_" + cjTag(), .role = "unprivileged",
                                                         .password = std::string("Change-Journal-Pass-123")});
    EXPECT_THROW((void)ops::fs_changes::list(vh::identities::manager().user(outsider.user->id), {.vault_id = vaultId}),
                 ops::Denied);
}

// An authorization change that can change what an account sees in the vault expires its cursor (and only the cursors
// it concerns); so do retention and a revision this database never handed out.
TEST_F(FsChangeJournalDbTest, CursorsExpire) {
    const auto user = userWithVaultRole("power_user");
    const auto cursor = anchor(user);
    const auto adminCursor = anchor(superUser);
    write("/a.txt", "a");

    deny(user, {"vault.fs.files.preview"}, "/secret/**");
    const auto expired = since(user, cursor);
    EXPECT_TRUE(expired.expired);
    EXPECT_TRUE(expired.changes.empty());
    EXPECT_GE(expired.revision, cursor);
    // The anchor it hands back works.
    EXPECT_FALSE(since(user, expired.revision).expired);
    // The override concerns that account only.
    EXPECT_FALSE(since(superUser, adminCursor).expired);

    // A role template edit reaches everyone holding it in a vault that uses it.
    const auto before = anchor(user);
    (void)ops::roles::updateVaultRole(superUser, {.role = ops::roles::Ref{std::string("power_user")},
                                                  .description = std::string("cj " + cjTag())});
    EXPECT_TRUE(since(user, before).expired);

    // A revision from the future (another database) and one retention dropped.
    EXPECT_TRUE(since(superUser, ChangeLog::revision() + 1000).expired);
    write("/b.txt", "b");
    const auto old = anchor(superUser);
    write("/c.txt", "c");
    (void)ChangeLog::sequence();
    const auto pruned = ChangeLog::prune(std::chrono::seconds(0), 1'000'000);
    EXPECT_GE(pruned.pruned_through, old + 1);
    EXPECT_TRUE(since(superUser, old).expired);
    EXPECT_FALSE(since(superUser, ChangeLog::revision()).expired);
}

TEST_F(FsChangeJournalDbTest, WsCommandAnswersInTheContractShape) {
    const auto session = wsAs(superUser);
    const auto anchorJson = protocols::ws::handler::fs::Changes::list({{"vault_id", vaultId}}, session);
    EXPECT_EQ(anchorJson.at("changes"), json::array());
    write("/w.txt", "w");
    const auto page = protocols::ws::handler::fs::Changes::list(
        {{"vault_id", vaultId}, {"since", anchorJson.at("revision")}, {"limit", 10}}, session);
    ASSERT_EQ(page.at("changes").size(), 1u);
    const auto& change = page.at("changes")[0];
    EXPECT_EQ(change.at("kind"), "create");
    EXPECT_EQ(change.at("type"), "file");
    EXPECT_EQ(change.at("path"), "/w.txt");
    EXPECT_EQ(change.at("entry_id"), entryId("/w.txt"));
    EXPECT_FALSE(page.at("more").get<bool>());
    EXPECT_FALSE(page.at("expired").get<bool>());
    EXPECT_EQ(page.at("vault_id"), vaultId);

    EXPECT_THROW((void)protocols::ws::handler::fs::Changes::list({{"vault_id", vaultId}, {"limit", 0}}, session),
                 ops::Invalid);
    EXPECT_THROW((void)protocols::ws::handler::fs::Changes::list({{"vault_id", vaultId}, {"since", -1}}, session),
                 ops::Invalid);
    EXPECT_THROW((void)protocols::ws::handler::fs::Changes::list({{"vault_id", 999999}}, session), ops::NotFound);
}

}
