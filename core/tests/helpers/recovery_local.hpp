#pragma once

// Shared fixture for the local recovery suites (test_recovery_snapshots.cpp, test_recovery_local_restore.cpp):
// a private schema, real engines and keys, local vaults in mode local_snapshots, and small helpers to write, read,
// snapshot, plan and restore. DB-backed; every test is skipped without the VH_TEST_DB_* environment.

#include "../helpers/db_suite.hpp"
#include "../helpers/temp_dir.hpp"

#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/recovery/Blob.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/recovery/Snapshot.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "fs/ops/file.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Recovery.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "recovery/Model.hpp"
#include "recovery/Store.hpp"
#include "recovery/local/Points.hpp"
#include "recovery/local/Restore.hpp"
#include "recovery/local/Snapshots.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::test_support::recovery_local {

namespace rq = db::query::recovery;
namespace local = vh::recovery::local;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
using vh::recovery::ItemAction;
using vh::recovery::RecoveryId;

inline std::string tag() { return vh::test::uniqueTag('r'); }

inline RecoveryId snapId(const int64_t id) {
    return {.type = RecoveryId::Type::Snapshot, .id = static_cast<uint64_t>(id)};
}

inline RecoveryId lvId(const int64_t id) {
    return {.type = RecoveryId::Type::LocalGeneration, .id = static_cast<uint64_t>(id)};
}

// Rewrites the file at `path` (whose plaintext is `text`) in the legacy format: one AES-256-GCM message under the
// vault's current key, as builds before #367 stored every file; its row and cached entry point at the legacy IV.
inline void makeLegacyGcm(const std::shared_ptr<storage::Engine>& engine, const std::string& path,
                          const std::string& text) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, path);
    ASSERT_TRUE(f);
    const auto [key, version] = engine->encryptionManager->currentKey();
    std::vector<uint8_t> iv;
    const auto sealed =
        crypto::util::encrypt_aes256_gcm(std::vector<uint8_t>(text.begin(), text.end()), key->bytes(), iv);
    fs::ops::writeFileAtomic(f->backing_path, sealed);
    auto next = *f;
    next.encryption_iv = crypto::util::b64_encode(iv);
    next.encrypted_with_key_version = version;
    ASSERT_TRUE(db::query::fs::File::compareAndSetEncryptionIVAndVersion(next, f->encryption_iv,
                                                                        f->encrypted_with_key_version));
    if (const auto cached = std::dynamic_pointer_cast<fs::model::File>(
            runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path)))) {
        cached->encryption_iv = next.encryption_iv;
        cached->encrypted_with_key_version = version;
    }
    ASSERT_EQ(vault::content::formatOf(db::query::fs::File::getFileByPath(engine->vault->id, path)->encryption_iv),
              vault::content::Format::Gcm0);
}

class LocalRecoveryFixture : public vh::test::db::Suite {
protected:
    EnginePtr engine;

    static void setUpSuite(const std::string& name) { (void)setUpDbSuite(name); }
    static void tearDownSuite() { tearDownDbSuite(); }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        engine = newVault();
    }

    static void setMode(const uint32_t vaultId, const vh::recovery::Mode mode,
                        const std::optional<uint64_t> snapshotQuota = std::nullopt) {
        auto policy = rq::Policy::get(vaultId);
        policy.mode = mode;
        policy.snapshot_quota_bytes = snapshotQuota;
        rq::Policy::upsert(policy);
    }

    static EnginePtr newVault(const vh::recovery::Mode mode = vh::recovery::Mode::LocalSnapshots) {
        const auto vault = ops::vaults::create(superUser, {.name = "rl_" + tag(), .type = vault::model::VaultType::Local});
        setMode(vault->id, mode);
        return runtime::Deps::get().storageManager->getEngine(vault->id);
    }

    [[nodiscard]] uint32_t vaultId() const { return engine->vault->id; }

    void mkdir(const std::string& path) const { engine->mkdir(path, superUser); }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    void symlink(const std::string& path, const std::string& target) const {
        const auto& cache = runtime::Deps::get().fsCache;
        const auto fusePath = engine->vaultPathToFusePath(path);
        const auto parent = cache->getEntry(engine->vaultPathToFusePath(std::filesystem::path(path).parent_path()));
        ASSERT_TRUE(parent);
        auto link = std::make_shared<fs::model::Symlink>();
        link->vault_id = static_cast<int32_t>(engine->vault->id);
        link->parent_id = static_cast<int32_t>(parent->id);
        link->name = fusePath.filename().string();
        link->path = path;
        link->fuse_path = fusePath;
        link->target = target;
        link->base32_alias = "link" + tag();
        link->backing_path = parent->backing_path / link->base32_alias;
        link->mode = 0777;
        link->created_by = link->last_modified_by = static_cast<int32_t>(superUser->id);
        link->inode = cache->getOrAssignInode(fusePath);
        link->size_bytes = target.size();
        std::filesystem::create_symlink(target, link->backing_path);
        link->id = db::query::fs::Symlink::upsertSymlink(link);
        cache->cacheEntry(link);
    }

    [[nodiscard]] std::shared_ptr<fs::model::File> file(const std::string& path) const {
        return db::query::fs::File::getFileByPath(engine->vault->id, path);
    }

    [[nodiscard]] bool exists(const std::string& path) const {
        return runtime::Deps::get().fsCache->entryExists(engine->vaultPathToFusePath(path));
    }

    [[nodiscard]] bool isDir(const std::string& path) const {
        const auto e = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
        return e && e->isDirectory();
    }

    // What every byte consumer reads: authenticated plaintext of the current generation.
    [[nodiscard]] std::string plaintext(const std::string& path) const {
        const auto f = file(path);
        if (!f) return "<missing>";
        auto reader = engine->openPlaintextReader(f, {.integrity = storage::IntegrityPolicy::Strict});
        const auto bytes = storage::readAll(*reader, 64u << 20);
        return {bytes.begin(), bytes.end()};
    }

    void remove(const std::string& path) const { engine->remove(path, superUser->id); }

    [[nodiscard]] local::snapshots::Created snapshot(const std::string& path,
                                                     const std::optional<std::string>& name = std::nullopt) const {
        return local::snapshots::create(engine, superUser, path, name);
    }

    [[nodiscard]] std::vector<rq::GenerationRow> members(const int64_t snapshotId) const {
        return rq::Generation::listSnapshotMembers(snapshotId, "", 1000);
    }

    [[nodiscard]] std::optional<rq::GenerationRow> member(const int64_t snapshotId, const std::string& path) const {
        for (const auto& m : members(snapshotId))
            if (m.path == path) return m;
        return std::nullopt;
    }

    [[nodiscard]] std::vector<vh::recovery::ItemOutcome> restoreAll(const local::LocalPlan& plan,
                                                                    const UserPtr& actor = nullptr) const {
        std::vector<vh::recovery::ItemOutcome> out;
        for (const auto& item : plan.items) out.push_back(local::restore(engine, actor ? actor : superUser, item));
        return out;
    }

    static const vh::recovery::PlanItem* itemFor(const local::LocalPlan& plan, const std::string& destination) {
        for (const auto& item : plan.items)
            if (item.destination_path == destination) return &item;
        return nullptr;
    }

    static const vh::recovery::ItemOutcome* outcomeFor(const std::vector<vh::recovery::ItemOutcome>& outcomes,
                                                       const std::string& destination) {
        for (const auto& o : outcomes)
            if (o.destination_path == destination) return &o;
        return nullptr;
    }

    [[nodiscard]] UserPtr userWithVaultRole(const std::string& role) const {
        const auto created = ops::users::create(superUser, {.name = "rl_user_" + tag(), .role = "unprivileged",
                                                            .password = std::string("Recovery-Test-Pass-123")});
        (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = engine->vault->id,
                                                                 .subject = {.type = "user", .id = created.user->id}},
                                                      .role = role});
        return vh::identities::manager().user(created.user->id);
    }
};

}
