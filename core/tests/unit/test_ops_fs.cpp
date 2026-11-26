// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// ops::fs (ops/Fs.hpp): the file operations an account performs on a vault, with permission, name clash, the
// mutation, the operations record and the audit inside the op. The ws fs.* handlers call it (their behaviour is
// covered by test_fs_move_authz, test_fs_copy, test_fs_change_journal and the Tier A proofs); these tests run it the
// way a caller that is not a ws session will (a linked server's submitted change, design/peers/mirror.md): a
// constructed Actor and nothing else, including a file committed from bytes a SealedWriter already sealed.

#include "../helpers/db_suite.hpp"

#include "db/Transactions.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::test_ops_fs {

using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "o" + std::to_string(n.fetch_add(1));
}

class OpsFsDbTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<sync::Controller> previousController;

    EnginePtr engine;
    uint32_t vaultId{};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_ops_fs")) return;
        // The ops ask the sync controller for an early pass; an unstarted one just queues it.
        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        const auto vault = ops::vaults::create(superUser, {.name = "opsfs_" + tag(),
                                                           .type = vault::model::VaultType::Local});
        vaultId = vault->id;
        engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        ASSERT_TRUE(engine);
        for (const auto* dir : {"/src", "/src/dir", "/locked", "/open"}) engine->mkdir(dir, superUser);
        write("/src/a.txt", "alpha\n");
        write("/src/dir/inner.txt", "inner\n");
    }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    [[nodiscard]] std::shared_ptr<fs::model::Entry> entry(const std::string& path) const {
        return runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
    }

    [[nodiscard]] bool exists(const std::string& path) const { return entry(path) != nullptr; }

    [[nodiscard]] std::shared_ptr<fs::model::File> file(const std::string& path) const {
        return std::dynamic_pointer_cast<fs::model::File>(entry(path));
    }

    // The plaintext stored at `path`, read back through the vault's reader (authenticated, with the vault key).
    [[nodiscard]] std::optional<std::string> content(const std::string& path) const {
        const auto f = file(path);
        if (!f) return std::nullopt;
        const auto reader = engine->openPlaintextReader(f);
        const auto bytes = storage::readAll(*reader, 1u << 20);
        return std::string(bytes.begin(), bytes.end());
    }

    [[nodiscard]] std::string generation(const std::string& path) const {
        const auto f = file(path);
        return f ? storage::generationOf(*f).sourceId() : std::string{};
    }

    // Bytes sealed with the vault's key before the commit, as a linked server would send them: the commit encrypts
    // nothing. `calls` counts how often the commit ran the writer.
    [[nodiscard]] vh::fs::SealedWriter sealed(const std::string& text, const std::shared_ptr<int>& calls = nullptr) const {
        return [engine = engine, text, calls](const std::filesystem::path& dst) -> vh::fs::SealedContent {
            if (calls) ++*calls;
            const std::vector<uint8_t> plain(text.begin(), text.end());
            const auto scratch = std::make_shared<fs::model::File>();
            const auto bytes = engine->encryptionManager->encrypt(plain, scratch);
            std::ofstream out(dst, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            out.close();
            if (!out) throw std::runtime_error("could not write the sealed bytes");
            return {.encryption_iv = scratch->encryption_iv,
                    .key_version = scratch->encrypted_with_key_version,
                    .plaintext_size = plain.size(),
                    .mime_type = std::string("text/plain")};
        };
    }

    // A power user on the vault (may upload, overwrite, move, rename, copy, delete and create folders) except for
    // `denied` under `pattern`, loaded the way any caller loads an account: no session.
    [[nodiscard]] UserPtr powerUserDenied(const std::vector<std::string>& denied, const std::string& pattern) const {
        const auto created = ops::users::create(superUser, {.name = "opsfs_user_" + tag(), .role = "unprivileged",
                                                            .password = std::string("Ops-Fs-Pass-123")});
        const ops::roles::VaultSubject target{.vault_id = vaultId, .subject = {.type = "user", .id = created.user->id}};
        (void)ops::roles::assignVaultRole(superUser, {.target = target, .role = std::string("power_user")});
        if (!denied.empty()) {
            ops::roles::PermissionEdit edit;
            for (const auto& p : denied) edit.changes.emplace_back(p, false);
            (void)ops::roles::addVaultRoleOverrides(superUser, {.target = target, .permissions = edit, .pattern = pattern});
        }
        return identities::manager().user(created.user->id);
    }

    [[nodiscard]] UserPtr powerUser() const { return powerUserDenied({}, "/**"); }

    // The newest `operations` row for an entry: {operation, status, executed_by}.
    [[nodiscard]] static std::optional<std::vector<std::string>> lastOperation(const uint32_t entryId) {
        return db::Transactions::exec("OpsFsDbTest::lastOperation", [&](pqxx::work& txn)
                                          -> std::optional<std::vector<std::string>> {
            const auto res = txn.exec("SELECT operation, status, executed_by::text FROM operations "
                                      "WHERE fs_entry_id = $1 ORDER BY id DESC LIMIT 1",
                                      pqxx::params{entryId});
            if (res.empty()) return std::nullopt;
            return std::vector<std::string>{res[0][0].as<std::string>(), res[0][1].as<std::string>(),
                                            res[0][2].as<std::string>()};
        });
    }
};

// Every file operation runs for an account with nothing but the account: no ws session, no transport.
TEST_F(OpsFsDbTest, RunsForAnAccountWithoutASession) {
    const auto actor = powerUser();

    ops::fs::mkdir(actor, vaultId, "/made");
    EXPECT_TRUE(exists("/made"));

    ops::fs::copy(actor, vaultId, "/src/a.txt", "/made/a.txt");
    EXPECT_EQ(content("/made/a.txt"), "alpha\n");
    EXPECT_EQ(content("/src/a.txt"), "alpha\n");

    const auto movedId = entry("/made/a.txt")->id;
    ops::fs::move(actor, vaultId, "/made/a.txt", "/open/a.txt");
    EXPECT_FALSE(exists("/made/a.txt"));
    EXPECT_EQ(content("/open/a.txt"), "alpha\n");
    // The operations record names the operation and the account, as the console's move does.
    EXPECT_EQ(lastOperation(movedId), (std::vector<std::string>{"move", "success", std::to_string(actor->id)}));

    ops::fs::rename(actor, vaultId, "/src/dir", "/made/dir");
    EXPECT_FALSE(exists("/src/dir"));
    EXPECT_EQ(content("/made/dir/inner.txt"), "inner\n");

    ops::fs::remove(actor, vaultId, "/open/a.txt");
    EXPECT_FALSE(exists("/open/a.txt"));
    ops::fs::remove(actor, vaultId, "/made/dir");
    EXPECT_FALSE(exists("/made/dir"));
    EXPECT_FALSE(exists("/made/dir/inner.txt"));
}

TEST_F(OpsFsDbTest, RefusalsAreTypedAndChangeNothing) {
    const auto actor = powerUser();

    EXPECT_THROW(ops::fs::mkdir(nullptr, vaultId, "/x"), ops::Denied);
    EXPECT_THROW(ops::fs::remove(nullptr, vaultId, "/src/a.txt"), ops::Denied);
    EXPECT_THROW(ops::fs::mkdir(actor, 0, "/x"), ops::NotFound);

    EXPECT_THROW(ops::fs::mkdir(actor, vaultId, "/src"), ops::Conflict);
    EXPECT_THROW(ops::fs::mkdir(actor, vaultId, "/missing/x"), ops::NotFound);

    // A taken destination is never replaced.
    write("/open/a.txt", "other\n");
    EXPECT_THROW(ops::fs::move(actor, vaultId, "/src/a.txt", "/open/a.txt"), ops::Conflict);
    EXPECT_THROW(ops::fs::rename(actor, vaultId, "/src/a.txt", "/open/a.txt"), ops::Conflict);
    EXPECT_THROW(ops::fs::copy(actor, vaultId, "/src/a.txt", "/open/a.txt"), ops::Conflict);
    EXPECT_EQ(content("/src/a.txt"), "alpha\n");
    EXPECT_EQ(content("/open/a.txt"), "other\n");

    // A missing source: the vault's RBAC refuses an action on an entry that is not there (nothing is revealed to
    // whoever may not see it), so only an account the check passes for learns that it is missing.
    EXPECT_THROW(ops::fs::move(actor, vaultId, "/src/none.txt", "/open/none.txt"), ops::Denied);
    EXPECT_THROW(ops::fs::move(superUser, vaultId, "/src/none.txt", "/open/none.txt"), ops::NotFound);
    EXPECT_THROW(ops::fs::move(actor, vaultId, "/src/a.txt", "/missing/a.txt"), ops::NotFound);
    EXPECT_THROW(ops::fs::move(actor, vaultId, "/src", "/src/dir/src"), ops::Invalid);
    EXPECT_TRUE(exists("/src/dir/inner.txt"));
}

// The permission is the op's, whoever calls it: the ws handler adds none of its own.
TEST_F(OpsFsDbTest, ThePermissionCheckIsInsideTheOp) {
    const auto noDelete = powerUserDenied({"vault.fs.files.delete", "vault.fs.directories.delete"}, "/src/**");
    EXPECT_THROW(ops::fs::remove(noDelete, vaultId, "/src/a.txt"), ops::Denied);
    EXPECT_TRUE(exists("/src/a.txt"));

    const auto lockedOut = powerUserDenied({"vault.fs.files.upload", "vault.fs.directories.touch"}, "/locked/**");
    EXPECT_THROW(ops::fs::mkdir(lockedOut, vaultId, "/locked/x"), ops::Denied);
    EXPECT_THROW(ops::fs::move(lockedOut, vaultId, "/src/a.txt", "/locked/a.txt"), ops::Denied);
    EXPECT_THROW(ops::fs::copy(lockedOut, vaultId, "/src/a.txt", "/locked/a.txt"), ops::Denied);
    EXPECT_TRUE(exists("/src/a.txt"));
    EXPECT_FALSE(exists("/locked/a.txt"));
    EXPECT_FALSE(exists("/locked/x"));
}

TEST_F(OpsFsDbTest, CommitsANewFileFromSealedBytes) {
    const auto actor = powerUser();
    const auto calls = std::make_shared<int>(0);

    const auto committed = ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/src/new.txt",
                                                         .sealed = sealed("sealed elsewhere\n", calls)});
    ASSERT_TRUE(committed);
    EXPECT_EQ(*calls, 1);
    EXPECT_EQ(committed->size_bytes, std::string("sealed elsewhere\n").size());
    EXPECT_EQ(committed->created_by, std::optional<int32_t>(static_cast<int32_t>(actor->id)));
    EXPECT_EQ(content("/src/new.txt"), "sealed elsewhere\n");
    EXPECT_FALSE(generation("/src/new.txt").empty());
}

// A new file never replaces what is at its name: a file or a folder there is a Conflict (a name clash, not a
// ContentConflict), the writer never runs, and what was there is unchanged.
TEST_F(OpsFsDbTest, ANameClashIsRefusedNotOverwritten) {
    const auto actor = powerUser();
    const auto calls = std::make_shared<int>(0);

    try {
        (void)ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/src/a.txt", .sealed = sealed("x\n", calls)});
        ADD_FAILURE() << "a commit over an existing file was accepted";
    } catch (const ops::fs::ContentConflict&) {
        ADD_FAILURE() << "a name clash was reported as a content conflict";
    } catch (const ops::Conflict&) {
    }
    EXPECT_THROW((void)ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/src/dir",
                                                     .sealed = sealed("x\n", calls)}),
                 ops::Conflict);
    EXPECT_EQ(*calls, 0);
    EXPECT_EQ(content("/src/a.txt"), "alpha\n");
    EXPECT_TRUE(entry("/src/dir")->isDirectory());

    EXPECT_THROW((void)ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/missing/a.txt",
                                                     .sealed = sealed("x\n", calls)}),
                 ops::NotFound);
    EXPECT_THROW((void)ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/src/b.txt"}), ops::Invalid);
    EXPECT_FALSE(exists("/missing/a.txt"));
    EXPECT_FALSE(exists("/src/b.txt"));
}

// A replacement names the generation it was based on: it replaces that generation only. Once the file has another
// (or is gone), the commit is a ContentConflict and nothing is written.
TEST_F(OpsFsDbTest, AReplacementNeedsItsBaseGeneration) {
    const auto actor = powerUser();
    const auto base = generation("/src/a.txt");
    ASSERT_FALSE(base.empty());

    const auto replaced = ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/src/a.txt", .base = base,
                                                        .sealed = sealed("beta\n")});
    ASSERT_TRUE(replaced);
    EXPECT_EQ(content("/src/a.txt"), "beta\n");
    const auto current = generation("/src/a.txt");
    EXPECT_NE(current, base);

    // The same base again: the file has moved on.
    const auto calls = std::make_shared<int>(0);
    EXPECT_THROW((void)ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/src/a.txt", .base = base,
                                                     .sealed = sealed("gamma\n", calls)}),
                 ops::fs::ContentConflict);
    EXPECT_EQ(*calls, 0);
    EXPECT_EQ(content("/src/a.txt"), "beta\n");
    EXPECT_EQ(generation("/src/a.txt"), current);

    // A base for a file that is not there any more: Overwrite on a missing entry is refused by the vault's RBAC for
    // an account it applies to; one it passes for (the super admin) gets the ContentConflict.
    EXPECT_THROW((void)ops::fs::commitSealed(actor, {.vault_id = vaultId, .path = "/src/gone.txt", .base = base,
                                                     .sealed = sealed("gamma\n")}),
                 ops::Denied);
    EXPECT_THROW((void)ops::fs::commitSealed(superUser, {.vault_id = vaultId, .path = "/src/gone.txt", .base = base,
                                                         .sealed = sealed("gamma\n")}),
                 ops::fs::ContentConflict);
    EXPECT_FALSE(exists("/src/gone.txt"));
}

// A new file needs Write at its path, a replacement Overwrite, as every upload lane checks.
TEST_F(OpsFsDbTest, ASealedCommitNeedsWriteOrOverwrite) {
    const auto noUpload = powerUserDenied({"vault.fs.files.upload"}, "/locked/**");
    EXPECT_THROW((void)ops::fs::commitSealed(noUpload, {.vault_id = vaultId, .path = "/locked/new.txt",
                                                        .sealed = sealed("x\n")}),
                 ops::Denied);
    EXPECT_FALSE(exists("/locked/new.txt"));

    const auto noOverwrite = powerUserDenied({"vault.fs.files.overwrite"}, "/src/**");
    EXPECT_THROW((void)ops::fs::commitSealed(noOverwrite, {.vault_id = vaultId, .path = "/src/a.txt",
                                                           .base = generation("/src/a.txt"), .sealed = sealed("x\n")}),
                 ops::Denied);
    EXPECT_EQ(content("/src/a.txt"), "alpha\n");

    EXPECT_THROW((void)ops::fs::commitSealed(nullptr, {.vault_id = vaultId, .path = "/src/new.txt",
                                                       .sealed = sealed("x\n")}),
                 ops::Denied);
    EXPECT_FALSE(exists("/src/new.txt"));
}

}
