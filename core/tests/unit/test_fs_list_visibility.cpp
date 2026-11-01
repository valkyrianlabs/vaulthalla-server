// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// #255: fs.dir.list (and fs.list outside share mode) checked List on the folder and returned every child, so the web
// console and Desktop showed the names, sizes and dates of entries FUSE readdir hides from the same user (#170: deny
// means hidden). The folder totals next to a child folder counted what is hidden inside it too. Every listing surface
// now filters through rbac::fs::visibility (the evaluator's Lookup), and recounts the totals of folders whose subtree
// holds hidden entries. `vh fs ls` had the same gap. #269: fs.metadata on a folder still reported the stored size (a
// side channel on how much is hidden); it now covers the visible part too. FUSE getattr of a folder is covered in the
// Tier A "List Visibility Parity" scenario.

#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "rbac/fs/Visibility.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "UsageManager.hpp"
#include "vault/model/Vault.hpp"
#include "db/Transactions.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace vh::test_fs_list_visibility {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
using Names = std::set<std::string>;
namespace visibility = rbac::fs::visibility;

std::string lvTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "v" + std::to_string(n.fetch_add(1));
}

struct Counts {
    std::uintmax_t size = 0;
    unsigned files = 0;
    unsigned subdirs = 0;
    bool operator==(const Counts&) const = default;
};

std::ostream& operator<<(std::ostream& os, const Counts& c) {
    return os << "{size=" << c.size << ", files=" << c.files << ", subdirs=" << c.subdirs << "}";
}

// The fixture tree, sizes chosen so every total is distinguishable:
//   /box/a.txt (1)  /box/secret.txt (20)
//   /box/sub/b.txt (300)  /box/sub/hidden.bin (4000)
//   /box/sub/private/c.txt (50000)
//   /box/sub/open/d.txt (600000)
class FsListVisibilityDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    EnginePtr engine;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_fs_list_visibility] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_fs_list_visibility_" + lvTag());
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
        // Earlier suites in this binary used their own schema: their cached entries and engines (ids reused after the
        // reset) would answer for ours.
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = vh::identities::manager().userByName("admin");

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerAllCommands(router);

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
        const auto vault = ops::vaults::create(superUser, {.name = "lv_" + lvTag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);

        for (const auto* dir : {"/box", "/box/sub", "/box/sub/private", "/box/sub/open"}) engine->mkdir(dir, superUser);
        write("/box/a.txt", 1);
        write("/box/secret.txt", 20);
        write("/box/sub/b.txt", 300);
        write("/box/sub/hidden.bin", 4000);
        write("/box/sub/private/c.txt", 50000);
        write("/box/sub/open/d.txt", 600000);
    }

    void write(const std::string& path, const std::size_t size) const {
        const std::string content(size, 'x');
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    static std::shared_ptr<protocols::ws::Session> wsAs(const UserPtr& user) {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = user;
        return session;
    }

    [[nodiscard]] UserPtr userWithVaultRole(const std::string& role) const {
        const auto created = ops::users::create(superUser, {.name = "lv_user_" + lvTag(), .role = "unprivileged",
                                                            .password = std::string("List-Visibility-Pass-123")});
        (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = engine->vault->id,
                                                                 .subject = {.type = "user", .id = created.user->id}},
                                                      .role = role});
        return vh::identities::manager().user(created.user->id);
    }

    void deny(const UserPtr& user, const std::vector<std::string>& permissions, const std::string& pattern) const {
        ops::roles::PermissionEdit edit;
        for (const auto& p : permissions) edit.changes.emplace_back(p, false);
        (void)ops::roles::addVaultRoleOverrides(superUser, {
            .target = {.vault_id = engine->vault->id, .subject = {.type = "user", .id = user->id}},
            .permissions = edit,
            .pattern = pattern});
    }

    // A file the user cannot see: neither preview nor download (Lookup on a file falls back to the Read decision).
    void hideFile(const UserPtr& user, const std::string& pattern) const {
        deny(user, {"vault.fs.files.preview", "vault.fs.files.download"}, pattern);
    }

    [[nodiscard]] json list(const UserPtr& user, const std::string& path) const {
        return protocols::ws::handler::fs::Storage::listDir({{"vault_id", engine->vault->id}, {"path", path}}, wsAs(user));
    }

    [[nodiscard]] static Names names(const json& listing) {
        Names out;
        for (const auto& f : listing.at("files")) out.insert(f.at("name").get<std::string>());
        return out;
    }

    [[nodiscard]] static Counts countsOf(const json& listing, const std::string& name) {
        for (const auto& f : listing.at("files"))
            if (f.at("name") == name)
                return {f.at("size_bytes").get<std::uintmax_t>(), f.at("file_count").get<unsigned>(),
                        f.at("subdirectory_count").get<unsigned>()};
        ADD_FAILURE() << "no " << name << " in the listing";
        return {};
    }

    // The size fs.metadata reports for an entry (#269). Its `entry` carries the base members only: no counts.
    [[nodiscard]] std::uintmax_t metadataSize(const UserPtr& user, const std::string& path) const {
        const auto meta = protocols::ws::handler::fs::Storage::metadata(
            {{"vault_id", engine->vault->id}, {"path", path}}, wsAs(user));
        EXPECT_FALSE(meta.at("entry").contains("file_count")) << "same shape for every caller";
        return meta.at("entry").at("size_bytes").get<std::uintmax_t>();
    }

    // What FUSE readdir answers for the folder (fuse::Resolver::resolveList calls exactly this; the bridge itself is
    // proven against ws in the Tier A "List Visibility Parity" scenario).
    [[nodiscard]] Names readdirNames(const UserPtr& user, const std::string& path) const {
        const auto& cache = runtime::Deps::get().fsCache;
        const auto dir = cache->getEntry(engine->vaultPathToFusePath(path));
        Names out;
        for (const auto& e : visibility::visibleChildren(user, dir, cache->listDir(dir->id))) out.insert(e->name);
        return out;
    }

    [[nodiscard]] Names cliNames(const UserPtr& user, const std::string& path) const {
        const auto result = router->executeLine("fs ls " + std::to_string(engine->vault->id) + " " + path, user, nullptr);
        EXPECT_EQ(result.exit_code, 0) << result.stderr_text;
        Names out;
        for (const auto* name : {"a.txt", "secret.txt", "sub/", "b.txt", "hidden.bin", "private/", "open/"})
            if (result.stdout_text.find(std::string(" ") + name) != std::string::npos) out.insert(name);
        return out;
    }
};

TEST_F(FsListVisibilityDbTest, HiddenChildrenAreLeftOutOfTheListingAndOutOfTheTotals) {
    const auto user = userWithVaultRole("power_user");
    hideFile(user, "/box/secret.txt");
    hideFile(user, "/box/sub/hidden.bin");
    deny(user, {"vault.fs.directories.list"}, "/box/sub/private");

    const auto box = list(user, "/box");
    EXPECT_EQ(names(box), (Names{"a.txt", "sub"}));
    // sub holds b.txt and open/d.txt for this user; hidden.bin and the whole of private/ don't count.
    EXPECT_EQ(countsOf(box, "sub"), (Counts{.size = 600300, .files = 2, .subdirs = 1}));
    EXPECT_EQ(box.at("entry").at("size_bytes").get<std::uintmax_t>(), 600301u);
    // #269: fs.metadata of a folder covers the same visible part as the listing (a.txt, b.txt, open/d.txt).
    EXPECT_EQ(metadataSize(user, "/box"), 600301u);
    EXPECT_EQ(metadataSize(user, "/box/sub"), countsOf(box, "sub").size);

    const auto sub = list(user, "/box/sub");
    EXPECT_EQ(names(sub), (Names{"b.txt", "open"}));
    EXPECT_EQ(countsOf(sub, "open"), (Counts{.size = 600000, .files = 1, .subdirs = 0}));
    EXPECT_EQ(sub.at("entry").at("size_bytes").get<std::uintmax_t>(), 600300u);
    EXPECT_EQ(metadataSize(user, "/box/sub/open"), 600000u);
    EXPECT_EQ(metadataSize(user, "/box/a.txt"), 1u);  // a file's is its own

    EXPECT_THROW((void)list(user, "/box/sub/private"), ops::Denied);

    // The same set FUSE readdir answers, and `vh fs ls`.
    EXPECT_EQ(names(box), readdirNames(user, "/box"));
    EXPECT_EQ(names(sub), readdirNames(user, "/box/sub"));
    EXPECT_EQ(cliNames(user, "/box"), (Names{"a.txt", "sub/"}));
    EXPECT_EQ(cliNames(user, "/box/sub"), (Names{"b.txt", "open/"}));
}

TEST_F(FsListVisibilityDbTest, SuperAdminSeesEverythingWithTheStoredTotals) {
    const auto box = list(superUser, "/box");
    EXPECT_EQ(names(box), (Names{"a.txt", "secret.txt", "sub"}));
    EXPECT_EQ(countsOf(box, "sub"), (Counts{.size = 654300, .files = 4, .subdirs = 2}));
    EXPECT_EQ(box.at("entry").at("size_bytes").get<std::uintmax_t>(), 654321u);
    EXPECT_EQ(metadataSize(superUser, "/box"), 654321u);
    EXPECT_EQ(metadataSize(superUser, "/box/sub"), 654300u);
    EXPECT_EQ(names(list(superUser, "/box/sub")), (Names{"b.txt", "hidden.bin", "private", "open"}));
    EXPECT_EQ(cliNames(superUser, "/box"), (Names{"a.txt", "secret.txt", "sub/"}));
}

TEST_F(FsListVisibilityDbTest, AUserWithNothingHiddenGetsTheFullListing) {
    const auto user = userWithVaultRole("power_user");
    const auto box = list(user, "/box");
    EXPECT_EQ(names(box), (Names{"a.txt", "secret.txt", "sub"}));
    EXPECT_EQ(countsOf(box, "sub"), (Counts{.size = 654300, .files = 4, .subdirs = 2}));
    EXPECT_EQ(metadataSize(user, "/box"), 654321u);
    EXPECT_TRUE(visibility::seesWholeSubtree(user, runtime::Deps::get().fsCache->getEntry(
        engine->vaultPathToFusePath("/box"))));

    // An override elsewhere in the vault leaves this subtree on the fast path and unchanged.
    hideFile(user, "/elsewhere/*.txt");
    EXPECT_EQ(names(list(user, "/box")), (Names{"a.txt", "secret.txt", "sub"}));
    EXPECT_TRUE(visibility::seesWholeSubtree(user, runtime::Deps::get().fsCache->getEntry(
        engine->vaultPathToFusePath("/box"))));
}

// The listing shortcut skipped the per-entry check when no override matched the folder or lay on a literal corridor
// below it, so a wildcard reaching in from above hid an entry from lookup but not from readdir/fs.dir.list.
TEST_F(FsListVisibilityDbTest, WildcardOverridesReachingInFromAboveStillHide) {
    const auto user = userWithVaultRole("power_user");
    hideFile(user, "/**/hidden.bin");
    hideFile(user, "/box/*/private/c.txt");

    EXPECT_EQ(names(list(user, "/box/sub")), (Names{"b.txt", "private", "open"}));
    EXPECT_EQ(names(list(user, "/box/sub/private")), Names{});
    EXPECT_EQ(countsOf(list(user, "/box"), "sub"), (Counts{.size = 600300, .files = 2, .subdirs = 2}));
    EXPECT_EQ(names(list(user, "/box/sub")), readdirNames(user, "/box/sub"));
}

// A role that lists folders but may neither preview nor download files sees no files at all (Lookup on a file is
// Preview, falling back to Read): no override is involved, so the base permissions alone must hide them.
TEST_F(FsListVisibilityDbTest, BasePermissionsWithoutPreviewHideEveryFile) {
    const auto roleName = "lv_folders_only_" + lvTag();
    (void)ops::roles::createVaultRole(superUser, {.name = roleName,
                                                  .from = ops::roles::Ref{std::string("guest")},
                                                  .permissions = {.changes = {{"vault.fs.files.preview", false}}}});
    const auto user = userWithVaultRole(roleName);

    const auto box = list(user, "/box");
    EXPECT_EQ(names(box), (Names{"sub"}));
    EXPECT_EQ(countsOf(box, "sub"), (Counts{.size = 0, .files = 0, .subdirs = 2}));
    EXPECT_EQ(metadataSize(user, "/box"), 0u);
    EXPECT_EQ(box.at("entry").at("size_bytes").get<std::uintmax_t>(), 0u);
    EXPECT_EQ(names(list(user, "/box/sub")), (Names{"private", "open"}));
    EXPECT_EQ(names(box), readdirNames(user, "/box"));
    EXPECT_EQ(cliNames(user, "/box"), (Names{"sub/"}));
}

TEST_F(FsListVisibilityDbTest, ListAtTheVaultRootFiltersToo) {
    const auto user = userWithVaultRole("power_user");
    deny(user, {"vault.fs.directories.list"}, "/box");
    write("/top.txt", 7);

    const auto top = list(user, "/");
    EXPECT_TRUE(names(top).contains("top.txt"));
    EXPECT_FALSE(names(top).contains("box"));
    EXPECT_EQ(names(top), readdirNames(user, "/"));

    // The folder's own size is what the visible children add up to, not the stored subtree total.
    std::uintmax_t visible = 0;
    for (const auto& f : top.at("files")) visible += f.at("size_bytes").get<std::uintmax_t>();
    EXPECT_EQ(top.at("entry").at("size_bytes").get<std::uintmax_t>(), visible);
    EXPECT_LT(visible, 654321u);
}

}
