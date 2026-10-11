#pragma once

// Shared by test_sync_conflicts.cpp and test_ops_parity_conflicts.cpp (#187): an in-memory bucket (fake S3
// controller) and a DB-backed fixture that makes remote vaults, runs real sync passes inline and builds conflicts.

#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/sync/Conflict.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Conflicts.hpp"
#include "ops/Error.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "rbac/permission/vault/sync/Action.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/Cloud.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Baseline.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/Throughput.hpp"
#include "sync/tasks/Download.hpp"
#include "sync/tasks/Upload.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"
#include <gtest/gtest.h>
#include <paths.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vh::test_support::sync_conflicts {

using UserPtr = std::shared_ptr<identities::User>;
using Decision = sync::ConflictDecision;
using ActionType = sync::model::ActionType;

inline std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

inline std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

inline std::shared_ptr<vault::model::APIKey> fakeKey() {
    return std::make_shared<vault::model::APIKey>(1, "fake", vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                  "secret-value-0000000000000000000000000", "us-east-1",
                                                  "https://s3.example.com");
}

// A bucket in memory. Metadata keys are stored as the x-amz-meta-* headers a HEAD returns; GETs honour If-Match.
class FakeBucket final : public storage::s3::Controller {
public:
    struct Object {
        std::vector<uint8_t> body;
        std::string etag;
        std::unordered_map<std::string, std::string> meta;
    };

    FakeBucket() : Controller(fakeKey(), "fake-bucket") {}

    void put(const std::string& key, std::vector<uint8_t> body, const std::unordered_map<std::string, std::string>& meta) {
        std::scoped_lock lock(mutex_);
        Object o{std::move(body), "\"etag-" + std::to_string(++version_) + "\"", {}};
        for (const auto& [k, v] : meta) o.meta["x-amz-meta-" + k] = v;
        objects_[key] = std::move(o);
    }

    std::optional<Object> get(const std::string& key) const {
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key);
        if (it == objects_.end()) return std::nullopt;
        return it->second;
    }

    unsigned puts() const { return puts_.load(); }

    void uploadObjectWithMetadata(const std::filesystem::path& key, const std::filesystem::path& file,
                                  const storage::s3::RequestOptions& options) const override {
        recordRequest(RequestKind::Put);
        std::ifstream in(file, std::ios::binary);
        std::vector<uint8_t> body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const_cast<FakeBucket*>(this)->put(key.string(), std::move(body), options.metadata);
        ++puts_;
    }

    void uploadObjectWithMetadata(const std::filesystem::path& key, const std::filesystem::path& file,
                                  const std::unordered_map<std::string, std::string>& metadata) const override {
        uploadObjectWithMetadata(key, file, storage::s3::RequestOptions{.system_headers = {}, .metadata = metadata});
    }

    void uploadBufferWithMetadata(const std::filesystem::path& key, const std::vector<uint8_t>& buffer,
                                  const storage::s3::RequestOptions& options) const override {
        recordRequest(RequestKind::Put);
        const_cast<FakeBucket*>(this)->put(key.string(), buffer, options.metadata);
        ++puts_;
    }

    void uploadBufferWithMetadata(const std::filesystem::path& key, const std::vector<uint8_t>& buffer,
                                  const std::unordered_map<std::string, std::string>& metadata) const override {
        uploadBufferWithMetadata(key, buffer, storage::s3::RequestOptions{.system_headers = {}, .metadata = metadata});
    }

    void uploadBufferWithMetadataConditional(const std::filesystem::path& key, const std::vector<uint8_t>& buffer,
                                             const storage::s3::RequestOptions& options,
                                             const std::optional<std::string>& ifMatch,
                                             const std::optional<std::string>& ifNoneMatch) const override {
        recordRequest(RequestKind::Put);
        {
            std::scoped_lock lock(mutex_);
            const auto it = objects_.find(key.string());
            if (ifMatch && (it == objects_.end() || it->second.etag != *ifMatch))
                throw storage::s3::ConditionalRequestFailed("412");
            if (ifNoneMatch && *ifNoneMatch == "*" && it != objects_.end())
                throw storage::s3::ConditionalRequestFailed("412");
        }
        const_cast<FakeBucket*>(this)->put(key.string(), buffer, options.metadata);
    }

    void uploadBufferWithMetadataConditional(const std::filesystem::path& key, const std::vector<uint8_t>& buffer,
                                             const std::unordered_map<std::string, std::string>& metadata,
                                             const std::optional<std::string>& ifMatch,
                                             const std::optional<std::string>& ifNoneMatch) const override {
        uploadBufferWithMetadataConditional(key, buffer, storage::s3::RequestOptions{.system_headers = {}, .metadata = metadata},
                                            ifMatch, ifNoneMatch);
    }

    void downloadToBuffer(const std::filesystem::path& key, std::vector<uint8_t>& out) const override {
        recordRequest(RequestKind::Get);
        const auto o = get(key.string());
        if (!o) throw std::runtime_error("no such key: " + key.string());
        out = o->body;
    }

    std::optional<std::unordered_map<std::string, std::string>> getHeadObject(const std::filesystem::path& key) const override {
        recordRequest(RequestKind::Head);
        const auto o = get(key.string());
        if (!o) return std::nullopt;
        std::unordered_map<std::string, std::string> headers{{"ETag", o->etag},
                                                             {"Content-Length", std::to_string(o->body.size())}};
        for (const auto& [k, v] : o->meta) headers[k] = v;
        return headers;
    }

    std::u8string listObjects(const std::filesystem::path&) const override {
        recordRequest(RequestKind::List);
        return u8"<ListBucketResult></ListBucketResult>";
    }

protected:
    TransportResponse transportGet(const std::filesystem::path& key, const std::map<std::string, std::string>& extraHeaders,
                                   const TransportBodyFn& onBody) const override {
        TransportResponse response;
        const auto o = get(key.string());
        if (!o) {
            response.http_status = 404;
            return response;
        }
        if (const auto it = extraHeaders.find("if-match"); it != extraHeaders.end() && it->second != o->etag) {
            response.http_status = 412;
            return response;
        }
        response.http_status = 200;
        response.headers = "ETag: " + o->etag + "\r\n";
        if (!o->body.empty() && !onBody(200, {o->body.data(), o->body.size()})) {
            response.transport_ok = false;
            response.transport_error = "aborted";
        }
        return response;
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, Object> objects_;
    unsigned version_{0};
    mutable std::atomic<unsigned> puts_{0};
};

class Harness : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;

    struct Fixture {
        ops::vaults::VaultPtr vault;
        std::shared_ptr<storage::CloudEngine> engine;
        std::shared_ptr<FakeBucket> bucket;
    };

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[sync conflicts] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_sync_conflicts_" + tag());
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
        superUser = vh::identities::manager().userByName("admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static UserPtr createUser(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + tag(), .role = role,
                                                            .password = std::string("Sync-Conflict-Pass-123")});
        return vh::identities::manager().user(created.user->id);
    }

    static Fixture remoteVault(const UserPtr& owner, const sync::model::RemotePolicy::ConflictPolicy policy =
                                                         sync::model::RemotePolicy::ConflictPolicy::Ask) {
        auto key = std::make_shared<vault::model::APIKey>(owner->id, "sc_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-1", "https://s3.example.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        Fixture f;
        f.vault = ops::vaults::create(superUser, {.name = "sc_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                  .owner_id = owner->id,
                                                  .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = "sc-" + tag()}});
        f.engine = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(f.vault->id));
        f.bucket = std::make_shared<FakeBucket>();
        f.engine->setS3ControllerForTesting(f.bucket);
        const auto rp = f.engine->remote_policy();
        rp->strategy = sync::model::RemotePolicy::Strategy::Sync;
        rp->conflict_policy = policy;
        return f;
    }

    static std::shared_ptr<fs::model::File> write(const Fixture& f, const std::string& path, const std::string& content) {
        return fs::Filesystem::createFile({.path = path, .fuse_path = f.engine->vaultPathToFusePath(path),
                                           .buffer = bytes(content), .engine = f.engine, .user = superUser,
                                           .overwrite = true});
    }

    static std::string readLocal(const Fixture& f, const std::string& path) {
        const auto file = db::query::fs::File::getFileByPath(f.vault->id, path);
        const auto reader = f.engine->openPlaintextReader(file);
        const auto data = storage::readAll(*reader, 1 << 20);
        return {data.begin(), data.end()};
    }

    // Another writer changed the object: new encrypted bytes in the bucket, and the remote index (as a manifest
    // refresh would leave it) describing them.
    static void remoteWrite(const Fixture& f, const std::string& path, const std::string& content) {
        auto file = std::make_shared<fs::model::File>();
        file->vault_id = f.vault->id;
        file->path = path;
        file->name = std::filesystem::path(path).filename().string();
        const auto plaintext = bytes(content);
        const auto ciphertext = f.engine->encryptionManager->encrypt(plaintext, file);
        file->size_bytes = plaintext.size();
        file->content_hash = "remote-" + content;
        file->remote_encrypted = true;
        file->updated_at = std::time(nullptr);
        f.bucket->put(path.substr(1), ciphertext,
                      {{"vh-encrypted", "true"}, {"vh-iv", file->encryption_iv},
                       {"vh-key-version", std::to_string(file->encrypted_with_key_version)},
                       {"content-hash", *file->content_hash}});
        file->remote_etag = f.bucket->get(path.substr(1))->etag;
        db::query::sync::RemoteObjectIndex::upsertFile(f.vault->id, file, "manifest");
    }

    // One sync pass: the real planning and conflict bookkeeping, the real upload/download tasks run inline.
    static std::vector<sync::model::Action> pass(const Fixture& f) {
        auto cloud = std::make_shared<sync::Cloud>(f.engine);
        cloud->event = std::make_shared<sync::model::Event>();
        cloud->event->vault_id = f.vault->id;
        cloud->event->timestamp_begin = std::time(nullptr);
        db::query::sync::Event::create(cloud->event);
        cloud->initBins();
        const auto plan = cloud->planPass();
        for (const auto& a : plan) {
            if (a.type == ActionType::Upload)
                sync::tasks::Upload(f.engine, a.local, cloud->op(sync::model::Throughput::Metric::UPLOAD))();
            else if (a.type == ActionType::Download)
                sync::tasks::Download(f.engine, a.remote, cloud->op(sync::model::Throughput::Metric::DOWNLOAD), false)();
        }
        f.engine->applyRemoteIndexMutation(plan);
        cloud->clearBins();
        return plan;
    }

    static unsigned planned(const std::vector<sync::model::Action>& plan, const ActionType type, const std::string& path) {
        unsigned n = 0;
        for (const auto& a : plan) {
            const auto& file = a.local ? a.local : a.remote;
            if (a.type == type && file && file->path == path) ++n;
        }
        return n;
    }

    static unsigned openRows(const uint32_t fileId) {
        return db::Transactions::exec("SyncConflictHarness::openRows", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM sync_conflicts WHERE file_id = $1 AND resolution = 'unresolved'",
                            pqxx::params{fileId}).one_field_ref().as<unsigned>();
        });
    }

    static std::string resolutionOf(const uint32_t id) {
        return db::query::sync::Conflict::get(id)->resolution;
    }

    static std::optional<db::query::sync::ConflictRecord> openFor(const Fixture& f, const std::string& path) {
        const auto file = db::query::fs::File::getFileByPath(f.vault->id, path);
        const auto open = db::query::sync::Conflict::openForVault(f.vault->id);
        if (const auto it = open.find(file->id); it != open.end()) return it->second;
        return std::nullopt;
    }

    // A synced file with a conflict: both sides changed since they last agreed.
    static db::query::sync::ConflictRecord conflicted(const Fixture& f, const std::string& path) {
        write(f, path, "base");
        (void)pass(f);  // upload: both sides agree on "base"
        write(f, path, "local edit");
        remoteWrite(f, path, "remote edit");
        (void)pass(f);
        const auto c = openFor(f, path);
        if (!c) throw std::runtime_error("expected an open conflict on " + path);
        return *c;
    }

    static uint32_t vaultRole(const std::string& name, const rbac::role::vault::Base& base) {
        const auto role = rbac::role::Vault::Custom(name, "test", base);
        return db::Transactions::exec("SyncConflictHarness::vaultRole", [&](pqxx::work& txn) {
            return txn.exec(R"SQL(
                INSERT INTO vault_role (name, description, files_permissions, directories_permissions, sync_permissions,
                                        roles_permissions)
                VALUES ($1, 'test', $2::bit(32), $3::bit(32), $4::bit(32), $5::bit(16)) RETURNING id
            )SQL", pqxx::params{name, role.fs.files.toBitString(), role.fs.directories.toBitString(),
                                role.sync.toBitString(), role.roles.toBitString()}).one_field_ref().as<uint32_t>();
        });
    }

    static UserPtr assign(const UserPtr& user, const uint32_t vaultId, const uint32_t roleId) {
        db::Transactions::exec("SyncConflictHarness::assign", [&](pqxx::work& txn) {
            txn.exec("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
                     "VALUES ($1, 'user', $2, $3)", pqxx::params{vaultId, user->id, roleId});
        });
        return vh::identities::manager().user(user->id);
    }
};

}
