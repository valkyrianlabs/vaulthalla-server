// Vault key backup and restoration (Vaulthalla Desktop S2/S6, .claude/context/key-backup.md): the key check and its documented vectors,
// vault.keys.status (current, an unfinished rotation's outgoing key, recovery-referenced versions, deleted vaults),
// export refused outside paired devices and the local CLI (D4) and carrying every needed version (the mid-rotation
// gap), export confirmation (current version + matching key check only), and CLI ↔ ws verdicts for every seeded
// admin role; and key import (S6): a key that no longer unseals or is missing is restored after verification and the
// vault's files read again, a wrong key or one the host can still unseal is refused, partial version sets, deleted
// vaults within retention. The device listener itself (real TLS) is covered in test_device_http.cpp.

#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/vault/Key.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Users.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/Vaults.hpp"
#include "stats/model/SystemHealth.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/RemoteFetch.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "storage/PlaintextReader.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/types.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/vault/Keys.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "UsageManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/Vault.hpp"
#include "sync/rotation/Rotation.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <sodium.h>

#include <array>
#include <set>
#include <map>
#include <mutex>
#include <span>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace vh::test_vault_keys {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace keys = ops::vault_keys;
using WsKeys = protocols::ws::handler::VaultKeys;

// Any-length base64 (crypto::util::b64_decode is for 12-byte IVs only).
std::vector<uint8_t> unb64(const std::string& text) {
    std::vector<uint8_t> out(text.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        throw std::runtime_error("bad base64");
    out.resize(len);
    return out;
}

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "v" + std::to_string(n.fetch_add(1));
}


// ---- an in-memory bucket for upstream key verification (the production streamObject over a fake wire) -------------

class KeyBucket final : public storage::s3::Controller {
public:
    struct Object {
        std::vector<uint8_t> body;
        std::string etag;
        std::map<std::string, std::string> meta;
    };

    explicit KeyBucket(const std::shared_ptr<vault::model::APIKey>& key) : Controller(key, "key-bucket") {}

    void put(const std::string& key, Object object) {
        std::scoped_lock lock(mutex_);
        objects_[key] = std::move(object);
    }
    [[nodiscard]] std::vector<std::optional<std::string>> getIfMatches() const {
        std::scoped_lock lock(mutex_);
        return ifMatches_;
    }
    [[nodiscard]] int heads() const {
        std::scoped_lock lock(mutex_);
        return heads_;
    }

    [[nodiscard]] std::optional<Object> object(const std::string& key) const {
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key);
        if (it == objects_.end()) return std::nullopt;
        return it->second;
    }

    // A salvage re-uploads the re-encrypted object (CloudEngine::upload, small objects).
    void uploadBufferWithMetadata(const std::filesystem::path& key, const std::vector<uint8_t>& buffer,
                                  const storage::s3::RequestOptions& options) const override {
        std::scoped_lock lock(mutex_);
        Object object{.body = buffer, .etag = "\"etag-" + std::to_string(++puts_ + 100) + "\"", .meta = {}};
        for (const auto& [name, value] : options.metadata) object.meta["x-amz-meta-" + name] = value;
        objects_[key.string()] = std::move(object);
    }

    std::optional<std::unordered_map<std::string, std::string>> getHeadObject(const std::filesystem::path& key) const override {
        recordRequest(RequestKind::Head);
        std::scoped_lock lock(mutex_);
        ++heads_;
        const auto it = objects_.find(key.string());
        if (it == objects_.end()) return std::nullopt;
        std::unordered_map<std::string, std::string> headers{{"ETag", it->second.etag},
                                                             {"Content-Length", std::to_string(it->second.body.size())}};
        for (const auto& [name, value] : it->second.meta) headers[name] = value;
        return headers;
    }

protected:
    TransportResponse transportGet(const std::filesystem::path& key, const std::optional<std::string>&,
                                   const std::map<std::string, std::string>& extraHeaders,
                                   const TransportBodyFn& onBody) const override {
        Object object;
        std::optional<std::string> ifMatch;
        if (const auto it = extraHeaders.find("if-match"); it != extraHeaders.end()) ifMatch = it->second;
        {
            std::scoped_lock lock(mutex_);
            ifMatches_.push_back(ifMatch);
            const auto it = objects_.find(key.string());
            if (it == objects_.end()) return deliver(404, {}, onBody);
            object = it->second;
        }
        if (ifMatch && *ifMatch != object.etag) return deliver(412, {}, onBody);
        return deliver(200, object.body, onBody, object.etag);
    }

private:
    static TransportResponse deliver(const long status, const std::vector<uint8_t>& body, const TransportBodyFn& onBody,
                                     const std::string& etag = {}) {
        TransportResponse response;
        response.http_status = status;
        if (!etag.empty()) response.headers = "ETag: " + etag + "\r\n";
        for (std::size_t off = 0; off < body.size(); off += 4096) {
            const auto n = std::min<std::size_t>(4096, body.size() - off);
            if (!onBody(status, {body.data() + off, n})) {
                response.transport_ok = false;
                return response;
            }
        }
        return response;
    }

    mutable std::mutex mutex_;
    mutable std::map<std::string, Object> objects_;
    mutable int puts_{0};
    mutable std::vector<std::optional<std::string>> ifMatches_;
    mutable int heads_{0};
};

class NoopReservation final : public storage::RemoteFetchReservation {
public:
    void commit(const storage::s3::S3GatewayUpstreamUsage&) noexcept override {}
    void release() noexcept override {}
};

// ---- the key check (DB-free) --------------------------------------------------------------------------------------

TEST(VaultKeyCheck, MatchesTheDocumentedVectors) {
    std::array<uint8_t, 32> key{};
    std::iota(key.begin(), key.end(), uint8_t{0});
    // docs/vaults/secrets-and-key-export.md, .claude/context/key-backup.md; Desktop asserts the same values.
    EXPECT_EQ(vault::keyCheck(key, 42, 3), "72e4c8b7f8ab43b8ed8869a57cef1703");
    EXPECT_EQ(vault::keyCheck(key, 1, 1), "c7a67cdafd3140b29e19b0b5e543cb13");
    // Every input is bound: the vault, the version and the key.
    EXPECT_NE(vault::keyCheck(key, 42, 4), vault::keyCheck(key, 42, 3));
    EXPECT_NE(vault::keyCheck(key, 4, 23), vault::keyCheck(key, 42, 3));
    key[31] ^= 1;
    EXPECT_NE(vault::keyCheck(key, 42, 3), "72e4c8b7f8ab43b8ed8869a57cef1703");
    EXPECT_THROW((void)vault::keyCheck(std::span<const uint8_t>(key.data(), 16), 1, 1), std::invalid_argument);

    EXPECT_TRUE(vault::keyCheckEquals("72e4c8b7f8ab43b8ed8869a57cef1703", "72e4c8b7f8ab43b8ed8869a57cef1703"));
    EXPECT_FALSE(vault::keyCheckEquals("72e4c8b7f8ab43b8ed8869a57cef1703", "72e4c8b7f8ab43b8ed8869a57cef1704"));
    EXPECT_FALSE(vault::keyCheckEquals("72e4", "72e4"));
}

TEST(VaultKeyAttestation, MatchesTheDocumentedVector) {
    std::array<uint8_t, 32> seed{};
    std::iota(seed.begin(), seed.end(), uint8_t{0});
    const std::string node = "00000000-0000-4000-8000-000000000001";
    const auto msg = vault::attestation::message(node, 42, 3, "72e4c8b7f8ab43b8ed8869a57cef1703");
    ASSERT_EQ(msg.size(), 80u);
    EXPECT_EQ(std::string(msg.begin(), msg.begin() + 16), "vh-key-attest-v1");
    const auto hex = [](const std::vector<uint8_t>& b) {
        std::string out(b.size() * 2 + 1, '\0');
        sodium_bin2hex(out.data(), out.size(), b.data(), b.size());
        out.pop_back();
        return out;
    };
    // .claude/context/key-backup.md, vault/KeyAttestation.hpp, docs/vaults/secrets-and-key-export.md.
    const auto pk = vault::attestation::publicKeyFromSeed(seed);
    EXPECT_EQ(hex(pk), "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    const auto sig = vault::attestation::signWithSeed(seed, msg);
    EXPECT_EQ(hex(sig), "fbda258fa125ef4237a54b7cde732c073ba598fa4a1a782226aa82514ee5c36a"
                        "3ad452e6d36593337dc1619e61391c6ae20685155b11cc2b6deaf637e893840c");
    EXPECT_TRUE(vault::attestation::verifySignature(pk, msg, sig));
    // Every input is bound: node, vault, version and key check; a flipped bit fails.
    EXPECT_FALSE(vault::attestation::verifySignature(
        pk, vault::attestation::message("00000000-0000-4000-8000-000000000002", 42, 3, "72e4c8b7f8ab43b8ed8869a57cef1703"), sig));
    EXPECT_FALSE(vault::attestation::verifySignature(
        pk, vault::attestation::message(node, 43, 3, "72e4c8b7f8ab43b8ed8869a57cef1703"), sig));
    EXPECT_FALSE(vault::attestation::verifySignature(
        pk, vault::attestation::message(node, 42, 4, "72e4c8b7f8ab43b8ed8869a57cef1703"), sig));
    EXPECT_FALSE(vault::attestation::verifySignature(
        pk, vault::attestation::message(node, 42, 3, "72e4c8b7f8ab43b8ed8869a57cef1704"), sig));
    auto bad = sig;
    bad[0] ^= 1;
    EXPECT_FALSE(vault::attestation::verifySignature(pk, msg, bad));
    EXPECT_THROW((void)vault::attestation::message(node, 42, 3, "72E4C8B7F8AB43B8ED8869A57CEF1703"), std::invalid_argument);
}

// ---- against the test database ------------------------------------------------------------------------------------

class VaultKeysDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static std::filesystem::path root;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_vault_keys] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_vault_keys_" + tag());
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
        // Earlier suites in this binary used their own schema: their cached entries and engines would answer for ours.
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = identities::manager().userByName("admin");

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::vault::registerCommands(router);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static EnginePtr newVault(const std::string& prefix = "vk") {
        const auto v = ops::vaults::create(superUser, {.name = prefix + "_" + tag(), .type = vault::model::VaultType::Local});
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    static void write(const EnginePtr& engine, const std::string& path, const std::string& content) {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine, .user = superUser, .overwrite = true}));
    }

    static std::string checkOf(const EnginePtr& engine, const unsigned int version) {
        return vault::keyCheck(engine->encryptionManager->historicalKeySnapshot(version)->bytes(), engine->vault->id,
                               version);
    }

    static void addBlob(const unsigned int vaultId, const unsigned int keyVersion) {
        std::string name(32, 'a');
        for (auto& c : name) c = "abcdefghijklmnopqrstuvwxyz0123456789"[randombytes_uniform(36)];
        db::Transactions::exec("VaultKeysDbTest::addBlob", [&](pqxx::work& txn) {
            txn.exec("INSERT INTO recovery_blob (vault_id, storage_name, encryption_iv, key_version, cipher_bytes, "
                     "plaintext_bytes) VALUES ($1, $2, $3, $4, 32, 16)",
                     pqxx::params{vaultId, name, crypto::util::b64_encode(std::vector<uint8_t>(12, 7)), keyVersion});
        });
    }

    static UserPtr createUser(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + tag(), .role = role,
                                                            .password = std::string("Vault-Keys-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    // A browser session.
    static std::shared_ptr<protocols::ws::Session> console(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    // A paired device's session (the principal the device listener builds; no socket needed here).
    static std::shared_ptr<protocols::ws::Session> device(const UserPtr& user) {
        auto peer = std::make_shared<vh::device::Peer>();
        peer->spkiHex = std::string(64, 'a');
        peer->address = "127.0.0.1";
        peer->deviceRowId = 1;
        return protocols::ws::Session::devicePrincipal(peer, user, {});
    }

    struct Cli {
        int exit = 1;
        std::string out;
    };
    static Cli cli(const std::string& line, const UserPtr& user) {
        try {
            const auto res = router->executeLine(line, user, nullptr);
            return {res.exit_code, res.stdout_text + res.stderr_text};
        } catch (const std::exception& e) {
            return {1, e.what()};
        }
    }

    // The ws refusal code (data.code) a handler call ends with; "" when it succeeds.
    template <class Fn>
    static std::string wsCode(Fn&& fn) {
        try {
            (void)fn();
            return "";
        } catch (const ops::NeedsConfirmation& e) {
            return e.code;
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::Denied&) {
            return "denied";
        } catch (const ops::NotFound&) {
            return "not_found";
        } catch (const ops::Invalid&) {
            return "invalid";
        } catch (const ops::Conflict&) {
            return "conflict";
        }
    }

    static json statusOf(const unsigned int vaultId) {
        return WsKeys::status({{"vault_id", vaultId}}, console(superUser)).at("vaults").at(0);
    }

    static json neededOf(const json& status) {
        json out = json::array();
        for (const auto& n : status.at("needed_versions")) out.push_back({n.at("version"), n.at("reason")});
        return out;
    }
    // ---- import helpers

    static void corruptSealed(const std::string& table, const unsigned int vaultId,
                              const std::optional<unsigned int> version = std::nullopt) {
        std::vector<uint8_t> junk(48);
        randombytes_buf(junk.data(), junk.size());
        db::Transactions::exec("VaultKeysDbTest::corrupt", [&](pqxx::work& txn) {
            const auto sql = "UPDATE " + table + " SET encrypted_key = $2 WHERE vault_id = $1" +
                             (version ? " AND version = " + std::to_string(*version) : std::string{});
            txn.exec(sql, pqxx::params{vaultId, db::encoding::to_hex_bytea(junk)});
        });
    }

    static std::vector<uint8_t> sealedBytes(const std::string& table, const unsigned int vaultId, const unsigned int version) {
        return db::Transactions::exec("VaultKeysDbTest::sealed", [&](pqxx::work& txn) {
            const auto res = txn.exec("SELECT encrypted_key FROM " + table + " WHERE vault_id = $1 AND version = $2",
                                      pqxx::params{vaultId, version});
            return res.empty() ? std::vector<uint8_t>{}
                               : db::encoding::from_hex_bytea(res.one_field_ref().as<std::string>());
        });
    }

    // What a host whose key can't be unsealed looks like: no engine for the vault.
    static void dropEngine(const unsigned int vaultId) { runtime::Deps::get().storageManager->retireVault(vaultId); }

    static json importVia(const std::shared_ptr<protocols::ws::Session>& session, const unsigned int vaultId,
                          const json& keys, const std::optional<std::string>& confirm = std::nullopt) {
        json payload{{"vault_id", vaultId}, {"keys", keys}};
        if (confirm) payload["confirm_name"] = *confirm;
        return WsKeys::importKeys(payload, session);
    }

    static std::string readFile(const unsigned int vaultId, const std::string& path) {
        const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        if (!engine || !file) return "<missing>";
        const auto reader = engine->openPlaintextReader(file, {.integrity = storage::IntegrityPolicy::Strict});
        const auto bytes = storage::readAll(*reader, 1 << 20);
        return {bytes.begin(), bytes.end()};
    }

    static bool hasEngine(const unsigned int vaultId) {
        for (const auto& e : runtime::Deps::get().storageManager->getEngines())
            if (e && e->vault && e->vault->id == vaultId) return true;
        return false;
    }

    // An export of other bytes for the same version, with a key check that matches those bytes.
    static json forged(const json& genuine) {
        auto out = genuine;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        out["key"] = crypto::util::b64_encode(key);
        const auto version = out.at("key_info").at("key_version").get<unsigned int>();
        out["key_check"] = vault::keyCheck(key, out.at("vault_id").get<unsigned int>(), version);
        out["key_info"]["key_check"] = out["key_check"];
        out.erase("historical_keys");
        return out;
    }

    static std::string outcome(const json& result, const unsigned int version) {
        for (const auto& v : result.at("versions"))
            if (v.at("version") == version) return v.at("outcome").get<std::string>();
        return "<absent>";
    }

    static std::string detailOf(const json& result, const unsigned int version) {
        for (const auto& v : result.at("versions"))
            if (v.at("version") == version) return v.at("detail").get<std::string>();
        return "<absent>";
    }

    // An export from before attestations (revision 3): everything but the attestations.
    static json unattested(json keys) {
        keys.erase("attestation");
        keys["key_info"].erase("attestation");
        if (keys.contains("historical_keys"))
            for (auto& h : keys["historical_keys"]) h.erase("attestation");
        return keys;
    }

    static json salvageVia(const unsigned int vaultId, const json& keys, const std::optional<std::string>& confirm) {
        json payload{{"vault_id", vaultId}, {"keys", keys}, {"mode", "salvage"}};
        if (confirm) payload["confirm_name"] = *confirm;
        return WsKeys::importKeys(payload, device(superUser));
    }

    struct Recorded {
        std::optional<std::string> key_check;
        std::optional<unsigned int> key_id;
        std::vector<uint8_t> signature;
    };
    static Recorded recorded(const std::string& table, const unsigned int vaultId, const unsigned int version) {
        return db::Transactions::exec("VaultKeysDbTest::recorded", [&](pqxx::work& txn) {
            Recorded out;
            const auto res = txn.exec("SELECT key_check, attestation_key_id, attestation FROM " + table +
                                      " WHERE vault_id = $1 AND version = $2", pqxx::params{vaultId, version});
            if (res.empty()) return out;
            const auto row = res.one_row_ref();
            if (!row[0].is_null()) out.key_check = row[0].as<std::string>();
            if (!row[1].is_null()) out.key_id = row[1].as<unsigned int>();
            if (!row[2].is_null()) out.signature = db::encoding::from_hex_bytea(row[2].as<std::string>());
            return out;
        });
    }

    static void clearProvenance(const std::string& table, const unsigned int vaultId) {
        db::Transactions::exec("VaultKeysDbTest::clearProvenance", [&](pqxx::work& txn) {
            txn.exec("UPDATE " + table + " SET key_check = NULL, attestation_key_id = NULL, attestation = NULL "
                     "WHERE vault_id = $1", pqxx::params{vaultId});
        });
    }

    // The recorded provenance of (table, vault, version) is this key's check and verifies as this node's attestation.
    static bool attestedRow(const std::string& table, const unsigned int vaultId, const unsigned int version,
                            const std::string& check) {
        const auto r = recorded(table, vaultId, version);
        if (!r.key_check || *r.key_check != check || !r.key_id) return false;
        return vault::attestation::check({.key_id = *r.key_id, .signature = r.signature}, vaultId, version, check) ==
               vault::attestation::Verdict::Valid;
    }

    // Whether any key row of the vault unseals (under the test vault master) to exactly these bytes.
    static bool storedAnywhere(const unsigned int vaultId, const std::vector<uint8_t>& bytes) {
        crypto::secrets::KeyProvider provider("test_vault_master");
        provider.init();
        return db::Transactions::exec("VaultKeysDbTest::storedAnywhere", [&](pqxx::work& txn) {
            for (const auto* table : {"vault_keys", "vault_keys_trashed", "vault_deletion_key"})
                for (const auto& row : txn.exec(std::string("SELECT encrypted_key, iv FROM ") + table +
                                                " WHERE vault_id = $1", pqxx::params{vaultId})) {
                    try {
                        const auto raw = crypto::util::decrypt_aes256_gcm(
                            db::encoding::from_hex_bytea(row[0].as<std::string>()), provider.getMasterKey(),
                            db::encoding::from_hex_bytea(row[1].as<std::string>()));
                        if (raw == bytes) return true;
                    } catch (const std::exception&) {}
                }
            return false;
        });
    }

    static std::vector<uint8_t> keyBytes(const json& keyField) { return unb64(keyField.get<std::string>()); }

    // Replaces a file's ciphertext on disk with `bytes` (damage, or another key's file).
    static void overwriteBacking(const unsigned int vaultId, const std::string& path, const std::vector<uint8_t>& bytes) {
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        ASSERT_TRUE(file);
        std::ofstream out(file->backing_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    static std::vector<uint8_t> backingOf(const unsigned int vaultId, const std::string& path) {
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        std::ifstream in(file->backing_path, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    static unsigned int fileVersion(const unsigned int vaultId, const std::string& path) {
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        return file ? file->encrypted_with_key_version : 0;
    }
};

TEST_F(VaultKeysDbTest, StatusReportsTheCurrentKeyRotationAndRecoveryVersionsWithoutKeyBytes) {
    const auto engine = newVault();
    const auto id = engine->vault->id;
    const auto v1 = engine->encryptionManager->get_key_version();

    auto s = statusOf(id);
    EXPECT_EQ(s.at("vault_id"), id);
    EXPECT_EQ(s.at("vault_name"), engine->vault->name);
    EXPECT_EQ(s.at("version"), v1);
    EXPECT_EQ(s.at("key_check"), checkOf(engine, v1));
    EXPECT_TRUE(s.at("key_available").get<bool>());
    EXPECT_FALSE(s.at("rotation_in_progress").get<bool>());
    EXPECT_FALSE(s.at("deleted").get<bool>());
    EXPECT_TRUE(s.at("exported_version").is_null());
    EXPECT_EQ(neededOf(s), json::parse(R"([[)" + std::to_string(v1) + R"(, "current"]])"));
    EXPECT_EQ(s.dump().find("\"key\""), std::string::npos) << "status never carries key bytes";

    // A rotation that hasn't re-encrypted the vault yet: the outgoing key is still needed.
    engine->encryptionManager->prepare_key_rotation();
    const auto v2 = engine->encryptionManager->get_key_version();
    s = statusOf(id);
    EXPECT_EQ(s.at("version"), v2);
    EXPECT_TRUE(s.at("rotation_in_progress").get<bool>());
    EXPECT_EQ(s.at("key_check"), checkOf(engine, v2));
    ASSERT_EQ(s.at("needed_versions").size(), 2u);
    EXPECT_EQ(s.at("needed_versions")[1].at("version"), v1);
    EXPECT_EQ(s.at("needed_versions")[1].at("reason"), "rotation");
    EXPECT_EQ(s.at("needed_versions")[1].at("key_check"), checkOf(engine, v1));

    // Finished: v1 is needed only while recovery data references it (or live files are still sealed under it).
    engine->encryptionManager->finish_key_rotation();
    write(engine, "/a.txt", "alpha");
    s = statusOf(id);
    EXPECT_FALSE(s.at("rotation_in_progress").get<bool>());
    EXPECT_EQ(s.at("needed_versions").size(), 1u);
    addBlob(id, v1);
    s = statusOf(id);
    ASSERT_EQ(s.at("needed_versions").size(), 2u);
    EXPECT_EQ(s.at("needed_versions")[1].at("reason"), "recovery");
    EXPECT_EQ(s.at("needed_versions")[1].at("key_check"), checkOf(engine, v1));

    // A referenced version the vault no longer holds is reported missing, never invented.
    addBlob(id, v2 + 7);
    s = statusOf(id);
    EXPECT_EQ(s.at("missing_versions"), json::array({v2 + 7}));
    EXPECT_TRUE(s.at("needed_versions").back().at("key_check").is_null());

    // Every vault, through the CLI too (the same JSON).
    const auto all = WsKeys::status(json::object(), console(superUser)).at("vaults");
    EXPECT_TRUE(std::ranges::any_of(all, [&](const json& v) { return v.at("vault_id") == id; }));
    const auto viaCli = cli("vault keys status " + std::to_string(id) + " --json", superUser);
    ASSERT_EQ(viaCli.exit, 0) << viaCli.out;
    EXPECT_EQ(json::parse(viaCli.out).at("vaults").at(0), s);
}

TEST_F(VaultKeysDbTest, ExportIsForPairedDevicesAndTheCliAndCarriesEveryNeededVersion) {
    const auto engine = newVault();
    const auto id = engine->vault->id;
    write(engine, "/a.txt", "alpha");
    const auto v1 = engine->encryptionManager->get_key_version();
    engine->encryptionManager->prepare_key_rotation();  // mid-rotation: v1 still decrypts a.txt
    const auto v2 = engine->encryptionManager->get_key_version();
    const json payload{{"vault_id", id}};

    // D4: never through the browser, never to an agent.
    EXPECT_EQ(wsCode([&] { return WsKeys::exportKeys(payload, console(superUser)); }), "export_requires_device");
    EXPECT_EQ(wsCode([&] { return WsKeys::confirmExport({{"vault_id", id}, {"version", v2},
                                                         {"key_check", checkOf(engine, v2)}}, console(superUser)); }),
              "export_requires_device");
    {
        const protocols::shell::AgentCallScope agent;
        const auto refused = cli("vault keys export " + std::to_string(id), superUser);
        EXPECT_NE(refused.exit, 0);
        EXPECT_NE(refused.out.find("agents"), std::string::npos) << refused.out;
        EXPECT_EQ(refused.out.find("\"key\""), std::string::npos);
    }

    const auto exported = WsKeys::exportKeys(payload, device(superUser));
    EXPECT_EQ(exported.at("vault_id"), id);
    EXPECT_EQ(exported.at("key_info").at("key_version"), v2);
    EXPECT_EQ(exported.at("key_check"), checkOf(engine, v2));
    const auto bytes = *vh::device::crypto::fromBase64(exported.at("key").get<std::string>());
    EXPECT_EQ(exported.at("key_check"), vault::keyCheck(bytes, id, v2));
    ASSERT_TRUE(exported.contains("historical_keys")) << exported.dump();
    ASSERT_EQ(exported.at("historical_keys").size(), 1u);
    const auto& old = exported.at("historical_keys")[0];
    EXPECT_EQ(old.at("key_version"), v1);
    EXPECT_EQ(old.at("reason"), "rotation");
    EXPECT_EQ(vault::keyCheck(*vh::device::crypto::fromBase64(old.at("key").get<std::string>()), id, v1), checkOf(engine, v1));
    EXPECT_EQ(old.at("key_check"), checkOf(engine, v1));
    // A device's export isn't recorded until it confirms.
    EXPECT_TRUE(statusOf(id).at("exported_version").is_null());

    // The CLI export carries the outgoing key as well now, and records the current version as before.
    const auto viaCli = cli("vault keys export " + std::to_string(id), superUser);
    ASSERT_EQ(viaCli.exit, 0) << viaCli.out;
    const auto cliJson = json::parse(viaCli.out.substr(0, viaCli.out.rfind('}') + 1));
    EXPECT_EQ(cliJson.at("historical_keys")[0].at("key_version"), v1);
    EXPECT_EQ(cliJson.at("key"), exported.at("key"));
    EXPECT_EQ(statusOf(id).at("exported_version"), v2);
}

TEST_F(VaultKeysDbTest, ConfirmRecordsOnlyTheCurrentVersionWithAMatchingKeyCheck) {
    const auto engine = newVault();
    const auto id = engine->vault->id;
    const auto dev = device(superUser);
    const auto exported = WsKeys::exportKeys({{"vault_id", id}}, dev);
    const auto version = exported.at("key_info").at("key_version").get<unsigned int>();
    const auto check = exported.at("key_check").get<std::string>();

    // A key check of other bytes (the item holds another key) never counts.
    auto wrong = check;
    wrong[0] = wrong[0] == '0' ? '1' : '0';
    EXPECT_EQ(wsCode([&] { return WsKeys::confirmExport({{"vault_id", id}, {"version", version}, {"key_check", wrong}}, dev); }),
              "conflict");
    EXPECT_EQ(wsCode([&] { return WsKeys::confirmExport({{"vault_id", id}, {"version", version}, {"key_check", "XYZ"}}, dev); }),
              "invalid");
    EXPECT_TRUE(statusOf(id).at("exported_version").is_null());

    const auto confirmed = WsKeys::confirmExport({{"vault_id", id}, {"version", version}, {"key_check", check}}, dev);
    EXPECT_EQ(confirmed.at("version"), version);
    EXPECT_GT(confirmed.at("exported_at").get<int64_t>(), 0);
    EXPECT_EQ(statusOf(id).at("exported_version"), version);

    // A rotation between export and confirm: the exported version is no longer current, so it can't be confirmed.
    const auto again = WsKeys::exportKeys({{"vault_id", id}}, dev);
    engine->encryptionManager->prepare_key_rotation();
    EXPECT_EQ(wsCode([&] { return WsKeys::confirmExport({{"vault_id", id},
                                                         {"version", again.at("key_info").at("key_version")},
                                                         {"key_check", again.at("key_check")}}, dev); }),
              "conflict");
    const auto s = statusOf(id);
    EXPECT_EQ(s.at("exported_version"), version) << "the earlier confirmation stays; it is stale now";
    EXPECT_NE(s.at("version"), version);
    engine->encryptionManager->finish_key_rotation();
}

TEST_F(VaultKeysDbTest, DeletedVaultsWithinKeyRetentionAreListedAndExportable) {
    const auto engine = newVault("vkdel");
    const auto id = engine->vault->id;
    const auto check = checkOf(engine, engine->encryptionManager->get_key_version());
    (void)ops::vaults::remove(superUser, {.id = id});

    const auto all = WsKeys::status(json::object(), console(superUser)).at("vaults");
    const auto it = std::ranges::find_if(all, [&](const json& v) { return v.at("vault_id") == id; });
    ASSERT_NE(it, all.end());
    EXPECT_TRUE(it->at("deleted").get<bool>());
    EXPECT_FALSE(it->at("key_retain_until").is_null());
    EXPECT_EQ(it->at("key_check"), check);

    const auto exported = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    EXPECT_TRUE(exported.at("deleted_vault").get<bool>());
    EXPECT_EQ(exported.at("key_check"), check);
    (void)WsKeys::confirmExport({{"vault_id", id}, {"version", exported.at("key_info").at("key_version")},
                                 {"key_check", check}}, device(superUser));
    EXPECT_FALSE(statusOf(id).at("exported_at").is_null());
}

// The CLI and the ws handlers reach the same verdict for every seeded admin role: status needs the encryption-key
// View permission, export the Export permission (super admins hold both).
TEST_F(VaultKeysDbTest, EverySeededRoleGetsTheSameVerdictOnBothSurfaces) {
    const auto engine = newVault("vkpar");
    const auto id = std::to_string(engine->vault->id);
    for (const auto* role : {"unprivileged", "auditor", "support", "identity_admin", "security_admin",
                             "platform_operator", "super_admin"}) {
        const bool super = std::string(role) == "super_admin";
        const auto user = super ? superUser : createUser(std::string("vkp_") + role, role);
        const bool mayView = user->isSuperAdmin() || user->encryptionKeysPerms().canView();
        const bool mayExport = user->isSuperAdmin() || user->encryptionKeysPerms().canExport();

        const bool statusCli = cli("vault keys status " + id + " --json", user).exit == 0;
        const bool statusWs = wsCode([&] { return WsKeys::status({{"vault_id", engine->vault->id}}, console(user)); }).empty();
        EXPECT_EQ(statusCli, statusWs) << role;
        EXPECT_EQ(statusWs, mayView) << role;

        const auto exportCli = cli("vault keys export " + id, user);
        const bool exportWs = wsCode([&] { return WsKeys::exportKeys({{"vault_id", engine->vault->id}}, device(user)); }).empty();
        EXPECT_EQ(exportCli.exit == 0, exportWs) << role << ": " << exportCli.out;
        EXPECT_EQ(exportWs, mayExport) << role;
        if (super) {
            EXPECT_TRUE(exportWs);
        }
        if (std::string(role) == "unprivileged") {
            EXPECT_FALSE(statusWs || exportWs);
        }
    }
}


// ---- import (S6; revision 3: recovery restores only attested versions, salvage re-keys the rest) ------------------

TEST_F(VaultKeysDbTest, ProvenanceIsRecordedOnCreateAndRotateAndBackfilledWhenAVersionUnseals) {
    const auto engine = newVault("vkprov");
    const auto id = engine->vault->id;
    write(engine, "/a.txt", "alpha");
    const auto v1 = engine->encryptionManager->get_key_version();
    EXPECT_TRUE(attestedRow("vault_keys", id, v1, checkOf(engine, v1)));

    engine->encryptionManager->prepare_key_rotation();
    const auto v2 = engine->encryptionManager->get_key_version();
    EXPECT_TRUE(attestedRow("vault_keys", id, v2, checkOf(engine, v2)));
    EXPECT_TRUE(attestedRow("vault_keys_trashed", id, v1, checkOf(engine, v1))) << "the retired row keeps its own";

    // Status and export carry them (public), and the export's verify.
    const auto s = statusOf(id);
    ASSERT_TRUE(s.at("attestation").is_object()) << s.dump();
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    EXPECT_EQ(keys.at("attestation"), s.at("attestation"));
    EXPECT_EQ(keys.at("key_info").at("attestation"), keys.at("attestation"));
    ASSERT_EQ(keys.at("historical_keys").size(), 1u);
    EXPECT_TRUE(keys.at("historical_keys")[0].at("attestation").is_object());

    // Rows from before migration 113 (or a damaged record): filled in when the daemon next unseals them (a restart
    // mid-rotation unseals both).
    clearProvenance("vault_keys", id);
    clearProvenance("vault_keys_trashed", id);
    db::Transactions::exec("VaultKeysDbTest::wrongCheck", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_keys SET key_check = $2 WHERE vault_id = $1", pqxx::params{id, std::string(32, '0')});
    });
    dropEngine(id);
    (void)runtime::Deps::get().storageManager->reinstateVault(id);
    const auto restarted = runtime::Deps::get().storageManager->getEngine(id);
    ASSERT_TRUE(restarted);
    EXPECT_TRUE(attestedRow("vault_keys", id, v2, checkOf(restarted, v2)));
    EXPECT_TRUE(attestedRow("vault_keys_trashed", id, v1, checkOf(restarted, v1)));
    restarted->encryptionManager->finish_key_rotation();
}

TEST_F(VaultKeysDbTest, ImportRestoresAKeyThatNoLongerUnsealsAndTheFilesReadAgain) {
    const auto engine = newVault("vkimp");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/a.txt", "alpha");
    write(engine, "/b.txt", "bravo bravo");
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    const auto version = keys.at("key_info").at("key_version").get<unsigned int>();

    // The vault master changed (or the row was damaged): the sealed key no longer unseals and the vault can't start.
    corruptSealed("vault_keys", id);
    dropEngine(id);
    const auto broken = sealedBytes("vault_keys", id, version);
    auto s = statusOf(id);
    EXPECT_FALSE(s.at("key_available").get<bool>());
    EXPECT_TRUE(s.at("key_check").is_null());
    EXPECT_FALSE(s.at("unavailable_reason").is_null());

    // Never through the browser; nothing is written without the typed vault name.
    EXPECT_EQ(wsCode([&] { return importVia(console(superUser), id, keys, name); }), "import_requires_device");
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, keys); }), "vault_key_import");
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, keys, std::string("not-the-name")); }), "vault_key_import");
    EXPECT_EQ(sealedBytes("vault_keys", id, version), broken);
    {
        const protocols::shell::AgentCallScope agent;
        EXPECT_NE(router->executeLine("vault keys import " + std::to_string(id) + " --file k.json --confirm-name " + name,
                                      superUser, nullptr, std::nullopt, keys.dump()).exit_code, 0);
    }
    EXPECT_EQ(sealedBytes("vault_keys", id, version), broken);

    const auto result = importVia(device(superUser), id, keys, name);
    EXPECT_TRUE(result.at("written").get<bool>()) << result.dump();
    EXPECT_TRUE(result.at("key_available").get<bool>()) << result.dump();
    EXPECT_EQ(result.at("mode"), "recover");
    EXPECT_EQ(outcome(result, version), "restored");
    EXPECT_EQ(detailOf(result, version).rfind("attested by this node (signing key ", 0), 0u) << result.dump();
    EXPECT_NE(sealedBytes("vault_keys", id, version), broken);

    ASSERT_TRUE(hasEngine(id));
    EXPECT_EQ(readFile(id, "/a.txt"), "alpha");
    EXPECT_EQ(readFile(id, "/b.txt"), "bravo bravo");
    s = statusOf(id);
    EXPECT_TRUE(s.at("key_available").get<bool>());
    EXPECT_EQ(s.at("key_check"), keys.at("key_check"));

    // Importing the same key again is a no-op (no confirmation needed), on both surfaces.
    const auto again = importVia(device(superUser), id, keys);
    EXPECT_FALSE(again.at("written").get<bool>());
    EXPECT_EQ(outcome(again, version), "unchanged");
    const auto line = "vault keys import " + std::to_string(id) + " --file k.json --json";
    const auto viaCli = router->executeLine(line, superUser, nullptr, std::nullopt, keys.dump());
    ASSERT_EQ(viaCli.exit_code, 0) << viaCli.stderr_text << viaCli.stdout_text;
    EXPECT_EQ(outcome(json::parse(viaCli.stdout_text), version), "unchanged");
    // The CLI never reads a daemon-side path: without the attached file it refuses.
    EXPECT_NE(router->executeLine(line, superUser, nullptr).exit_code, 0);
}

// Adjusted for revision 3: an invented key used to be refused as a whole (`invalid`) because it authenticated none of
// the vault's files; ciphertext no longer decides canonical restores, so it is now needs_salvage (nothing written).
TEST_F(VaultKeysDbTest, ImportRefusesAWrongKeyAndNeverReplacesAKeyTheHostCanUnseal) {
    const auto engine = newVault("vkwrong");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/a.txt", "alpha");
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    const auto version = keys.at("key_info").at("key_version").get<unsigned int>();
    const auto wrong = forged(keys);  // other bytes, a matching key check, the genuine attestation

    // The host still unseals its key: other bytes are refused, the same bytes are unchanged.
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, wrong, name); }), "conflict");
    EXPECT_EQ(outcome(importVia(device(superUser), id, keys, name), version), "unchanged");

    corruptSealed("vault_keys", id);
    dropEngine(id);
    const auto broken = sealedBytes("vault_keys", id, version);

    // An invented key is never restored: the vault's recorded key check (and the attestation) don't match it.
    auto r = importVia(device(superUser), id, wrong, name);
    EXPECT_EQ(outcome(r, version), "needs_salvage") << r.dump();
    EXPECT_FALSE(r.at("written").get<bool>());
    // A key that doesn't match its own key check is a damaged backup; another vault's entry isn't this vault's.
    auto damaged = keys;
    damaged["key_check"] = wrong.at("key_check");
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, damaged, name); }), "invalid");
    auto otherVault = keys;
    otherVault["vault_id"] = id + 1000;
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, otherVault, name); }), "invalid");
    EXPECT_EQ(sealedBytes("vault_keys", id, version), broken);
    EXPECT_FALSE(hasEngine(id));
    EXPECT_FALSE(storedAnywhere(id, keyBytes(wrong.at("key"))));

    // Same permission as export.
    const auto plain = createUser("vkimp_plain", "unprivileged");
    EXPECT_EQ(wsCode([&] { return importVia(device(plain), id, keys, name); }), "denied");
    EXPECT_NE(router->executeLine("vault keys import " + std::to_string(id) + " --file k.json --confirm-name " + name,
                                  plain, nullptr, std::nullopt, keys.dump()).exit_code, 0);

    // The genuine backup restores it through the CLI.
    const auto viaCli = router->executeLine("vault keys import " + std::to_string(id) + " --file k.json --confirm-name " +
                                                name, superUser, nullptr, std::nullopt, keys.dump());
    ASSERT_EQ(viaCli.exit_code, 0) << viaCli.stderr_text << viaCli.stdout_text;
    EXPECT_EQ(readFile(id, "/a.txt"), "alpha");
}

TEST_F(VaultKeysDbTest, ImportHandlesPartialVersionSetsAndAMissingRetiredVersionMidRotation) {
    const auto engine = newVault("vkpart");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/old.txt", "sealed under v1");
    const auto v1 = engine->encryptionManager->get_key_version();
    engine->encryptionManager->prepare_key_rotation();  // the sync pass hasn't re-encrypted old.txt yet
    const auto v2 = engine->encryptionManager->get_key_version();
    write(engine, "/new.txt", "sealed under v2");
    const auto full = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    ASSERT_EQ(full.at("historical_keys").size(), 1u);
    auto partial = full;
    partial.erase("historical_keys");

    corruptSealed("vault_keys", id);
    corruptSealed("vault_keys_trashed", id, v1);
    dropEngine(id);

    // Only the current key: restored, but the vault still needs the outgoing one to start.
    auto r = importVia(device(superUser), id, partial, name);
    EXPECT_EQ(outcome(r, v2), "restored");
    EXPECT_FALSE(r.at("key_available").get<bool>()) << r.dump();
    EXPECT_FALSE(r.at("note").is_null());
    EXPECT_FALSE(hasEngine(id));

    // The whole set: v1 restored, v2 already there; both files read again and the rotation is still pending.
    r = importVia(device(superUser), id, full, name);
    EXPECT_EQ(outcome(r, v1), "restored");
    EXPECT_EQ(outcome(r, v2), "unchanged");
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    EXPECT_EQ(readFile(id, "/old.txt"), "sealed under v1");
    EXPECT_EQ(readFile(id, "/new.txt"), "sealed under v2");
    EXPECT_TRUE(statusOf(id).at("rotation_in_progress").get<bool>());

    // A database restored from before the rotation lost the outgoing key's row: the vault doesn't start (old.txt
    // would be unreadable); importing inserts the row again (its attestation proves it), the rotation resumes and the
    // vault starts.
    db::Transactions::exec("VaultKeysDbTest::dropRetired", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2", pqxx::params{id, v1});
    });
    dropEngine(id);
    try {
        (void)runtime::Deps::get().storageManager->reinstateVault(id);  // a restart
        ADD_FAILURE() << "the vault started without the key its files are sealed under";
    } catch (const vault::KeyUnavailable& e) {
        EXPECT_EQ(e.code(), "version_missing");
    }
    const auto missing = statusOf(id);
    EXPECT_FALSE(missing.at("rotation_in_progress").get<bool>());
    EXPECT_EQ(missing.at("unavailable_reason"), "version_missing");
    r = importVia(device(superUser), id, full, name);
    EXPECT_EQ(outcome(r, v1), "restored") << r.dump();
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    EXPECT_TRUE(statusOf(id).at("rotation_in_progress").get<bool>());
    EXPECT_EQ(readFile(id, "/old.txt"), "sealed under v1");
    EXPECT_TRUE(attestedRow("vault_keys_trashed", id, v1, full.at("historical_keys")[0].at("key_check")));
    engine->encryptionManager->finish_key_rotation();
}

TEST_F(VaultKeysDbTest, ImportIntoADeletedVaultWithinRetentionThenRestoreIt) {
    const auto engine = newVault("vkdelimp");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/kept.txt", "kept through deletion");
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    const auto version = keys.at("key_info").at("key_version").get<unsigned int>();
    (void)ops::vaults::remove(superUser, {.id = id});
    corruptSealed("vault_keys", id);
    corruptSealed("vault_deletion_key", id);

    // A deleted vault can't be salvaged (restore it first); it can be recovered.
    EXPECT_EQ(wsCode([&] { return salvageVia(id, unattested(keys), name); }), "conflict");
    const auto r = importVia(device(superUser), id, keys, name);
    EXPECT_TRUE(r.at("deleted").get<bool>());
    EXPECT_TRUE(r.at("written").get<bool>()) << r.dump();
    EXPECT_EQ(outcome(r, version), "restored") << r.dump();
    const auto s = WsKeys::status(json::object(), console(superUser)).at("vaults");
    const auto it = std::ranges::find_if(s, [&](const json& v) { return v.at("vault_id") == id; });
    ASSERT_NE(it, s.end());
    EXPECT_EQ(it->at("key_check"), keys.at("key_check"));

    (void)ops::vaults::restore(superUser, id);
    ASSERT_TRUE(hasEngine(id));
    EXPECT_EQ(readFile(id, "/kept.txt"), "kept through deletion");
}


// ---- revision 2 (still true): no key is minted over sealed content ------------------------------------------------

TEST_F(VaultKeysDbTest, AMissingKeyRowOverSealedFilesKeepsTheVaultUnavailableUntilImport) {
    const auto engine = newVault("vkmiss");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/a.txt", "alpha");
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    const auto version = keys.at("key_info").at("key_version").get<unsigned int>();

    db::Transactions::exec("VaultKeysDbTest::dropKeyRow", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_keys WHERE vault_id = $1", pqxx::params{id});
    });
    dropEngine(id);
    // A restart: the engine refuses to start rather than mint a key that could never decrypt a.txt.
    try {
        (void)runtime::Deps::get().storageManager->reinstateVault(id);
        ADD_FAILURE() << "the vault started without its key";
    } catch (const vault::KeyUnavailable& e) {
        EXPECT_EQ(e.code(), "key_missing");
        EXPECT_NE(std::string(e.what()).find("vh vault keys import " + std::to_string(id)), std::string::npos) << e.what();
    }
    EXPECT_TRUE(sealedBytes("vault_keys", id, version).empty()) << "no key was minted";
    EXPECT_FALSE(hasEngine(id));

    const auto unavailable = runtime::Deps::get().storageManager->unavailableVaults();
    const auto it = std::ranges::find_if(unavailable, [&](const auto& v) { return v.vault_id == id; });
    ASSERT_NE(it, unavailable.end());
    EXPECT_EQ(it->reason, "key_missing");
    const auto health = stats::model::SystemHealth::snapshot();
    EXPECT_FALSE(health.healthy());
    EXPECT_TRUE(std::ranges::any_of(health.vaultsUnavailable, [&](const auto& v) { return v.vaultId == id; }));

    auto s = statusOf(id);
    EXPECT_FALSE(s.at("key_available").get<bool>());
    EXPECT_EQ(s.at("unavailable_reason"), "key_missing");
    EXPECT_EQ(s.at("version"), version);

    const auto r = importVia(device(superUser), id, keys, name);
    EXPECT_EQ(outcome(r, version), "restored") << r.dump();
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    EXPECT_EQ(readFile(id, "/a.txt"), "alpha");
    EXPECT_TRUE(statusOf(id).at("unavailable_reason").is_null());
    EXPECT_TRUE(attestedRow("vault_keys", id, version, keys.at("key_check")));
    const auto after = runtime::Deps::get().storageManager->unavailableVaults();
    EXPECT_FALSE(std::ranges::any_of(after, [&](const auto& v) { return v.vault_id == id; }));
}

TEST_F(VaultKeysDbTest, AnEmptyVaultWithoutAKeyRowStillGetsAFreshKey) {
    const auto engine = newVault("vkempty");
    const auto id = engine->vault->id;
    db::Transactions::exec("VaultKeysDbTest::dropKeyRow", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_keys WHERE vault_id = $1", pqxx::params{id});
    });
    dropEngine(id);
    (void)runtime::Deps::get().storageManager->reinstateVault(id);
    EXPECT_TRUE(hasEngine(id));
    EXPECT_TRUE(db::query::vault::Key::getVaultKey(id) != nullptr);
    EXPECT_TRUE(statusOf(id).at("key_available").get<bool>());
}

// Replaces revision 2's AVersionWithNoCiphertextAnywhereIsAcceptedOnItsKeyCheckOnly: the backup's own key check is
// consistency only; a fresh rotation target (nothing sealed under it) is restored on this node's attestation, and an
// export without attestations restores nothing.
TEST_F(VaultKeysDbTest, AFreshRotationTargetIsRestoredOnItsAttestationNeverOnTheBackupsKeyCheck) {
    const auto engine = newVault("vkfresh");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/old.txt", "under v1");
    const auto v1 = engine->encryptionManager->get_key_version();
    engine->encryptionManager->prepare_key_rotation();  // v2: nothing sealed under it yet
    const auto v2 = engine->encryptionManager->get_key_version();
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    corruptSealed("vault_keys", id);
    corruptSealed("vault_keys_trashed", id, v1);
    dropEngine(id);

    // An export without attestations, whose own key checks are consistent: nothing is restored.
    auto r = importVia(device(superUser), id, unattested(keys), name);
    EXPECT_EQ(outcome(r, v2), "needs_salvage") << r.dump();
    EXPECT_EQ(outcome(r, v1), "needs_salvage") << r.dump();
    EXPECT_FALSE(r.at("written").get<bool>());
    EXPECT_FALSE(r.at("key_available").get<bool>());

    r = importVia(device(superUser), id, keys, name);
    EXPECT_EQ(outcome(r, v2), "restored") << r.dump();
    EXPECT_EQ(outcome(r, v1), "restored") << r.dump();
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    EXPECT_EQ(readFile(id, "/old.txt"), "under v1");
    engine->encryptionManager->finish_key_rotation();
}

// Master key lost, key rows present but unsealable, and the *current* row lost too: the recorded data and this node's
// attestations prove each version; nothing else does.
TEST_F(VaultKeysDbTest, RecoveryRefusesForgedTamperedForeignAndInventedVersions) {
    const auto engine = newVault("vkforge");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/a.txt", "alpha");
    const auto v1 = engine->encryptionManager->get_key_version();
    engine->encryptionManager->prepare_key_rotation();
    const auto v2 = engine->encryptionManager->get_key_version();
    write(engine, "/b.txt", "bravo");
    engine->encryptionManager->finish_key_rotation();  // a.txt stays under v1 (a database view; nothing reads it here)
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    const auto other = newVault("vkforge_other");
    const auto otherKeys = WsKeys::exportKeys({{"vault_id", other->vault->id}}, device(superUser));

    corruptSealed("vault_keys", id);
    dropEngine(id);
    const auto broken = sealedBytes("vault_keys", id, v2);

    const auto expectNeedsSalvage = [&](const json& doc, const std::string& why) {
        const auto r = importVia(device(superUser), id, doc, name);
        EXPECT_EQ(outcome(r, v2), "needs_salvage") << why << ": " << r.dump();
        EXPECT_FALSE(r.at("written").get<bool>()) << why;
        EXPECT_EQ(sealedBytes("vault_keys", id, v2), broken) << why;
    };

    auto flipped = keys;
    auto sig = unb64(flipped["attestation"]["signature"].get<std::string>());
    sig[5] ^= 1;
    flipped["attestation"]["signature"] = crypto::util::b64_encode(sig);
    flipped["key_info"].erase("attestation");
    expectNeedsSalvage(flipped, "a tampered signature");

    auto unknown = keys;
    unknown["attestation"]["key_id"] = 999999;
    unknown["key_info"].erase("attestation");
    expectNeedsSalvage(unknown, "an unknown signing key");

    // A key_id outside the signing key ids (key_attestation_keys.id, a PostgreSQL integer) is a malformed attestation.
    // The genuine id + 2^32 used to be narrowed to the genuine id and restore; 2^31 used to fail the lookup itself.
    const auto keyId = keys.at("attestation").at("key_id").get<uint64_t>();
    for (const uint64_t outOfRange : {keyId + (uint64_t{1} << 32), uint64_t{1} << 31, uint64_t{0}}) {
        auto wrapped = keys;
        wrapped["attestation"]["key_id"] = outOfRange;
        wrapped["key_info"].erase("attestation");
        expectNeedsSalvage(wrapped, "key_id " + std::to_string(outOfRange));
        const auto r = importVia(device(superUser), id, wrapped, name);
        EXPECT_NE(detailOf(r, v2).find("attestation is malformed"), std::string::npos) << r.dump();
    }

    auto otherVersion = keys;  // v1's attestation offered for v2
    otherVersion["key"] = keys.at("key");
    otherVersion["attestation"] = keys.at("historical_keys").is_array() && !keys.at("historical_keys").empty()
                                      ? keys.at("historical_keys")[0].at("attestation")
                                      : json(nullptr);
    otherVersion["key_info"].erase("attestation");
    otherVersion.erase("historical_keys");
    if (!otherVersion["attestation"].is_null()) expectNeedsSalvage(otherVersion, "another version's attestation");

    auto otherVaults = keys;  // another vault's attestation (same node)
    otherVaults["attestation"] = otherKeys.at("attestation");
    otherVaults["key_info"].erase("attestation");
    expectNeedsSalvage(otherVaults, "another vault's attestation");

    // Another node: the same export checked by a node with another id.
    std::string node;
    db::Transactions::exec("VaultKeysDbTest::node", [&](pqxx::work& txn) {
        node = txn.exec("SELECT node_id FROM device_node").one_field_ref().as<std::string>();
        txn.exec("UPDATE device_node SET node_id = 'another-node'");
    });
    expectNeedsSalvage(keys, "an attestation by another node");
    db::Transactions::exec("VaultKeysDbTest::nodeBack", [&](pqxx::work& txn) {
        txn.exec("UPDATE device_node SET node_id = $1", pqxx::params{node});
    });

    // An invented key for an invented version, and a backup that claims a version beyond anything recorded: refused,
    // and the current version stays what the records say.
    auto invented = keys;
    std::vector<uint8_t> random(32);
    randombytes_buf(random.data(), random.size());
    invented["historical_keys"].push_back({{"key_version", v2 + 5}, {"key", crypto::util::b64_encode(random)},
                                           {"key_check", vault::keyCheck(random, id, v2 + 5)}});
    auto r = importVia(device(superUser), id, invented, name);
    EXPECT_EQ(outcome(r, v2 + 5), "refused") << r.dump();
    EXPECT_EQ(outcome(r, v2), "restored") << r.dump();  // the genuine versions still recover
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    EXPECT_EQ(statusOf(id).at("version"), v2);
    EXPECT_FALSE(storedAnywhere(id, random));
    EXPECT_EQ(readFile(id, "/b.txt"), "bravo");

    // With the key row gone, the current version is the records' highest, never the backup's claim.
    db::Transactions::exec("VaultKeysDbTest::dropKeyRow", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_keys WHERE vault_id = $1", pqxx::params{id});
    });
    dropEngine(id);
    auto claim = keys;
    claim["key_info"]["key_version"] = v2 + 1;
    claim["key"] = crypto::util::b64_encode(random);
    claim["key_check"] = vault::keyCheck(random, id, v2 + 1);
    claim["key_info"]["key_check"] = claim["key_check"];
    claim["historical_keys"] = json::array({{{"key_version", v2}, {"key", keys.at("key")}, {"key_check", keys.at("key_check")},
                                             {"attestation", keys.at("attestation")}}});
    r = importVia(device(superUser), id, claim, name);
    EXPECT_EQ(outcome(r, v2 + 1), "refused") << r.dump();
    EXPECT_EQ(outcome(r, v2), "restored") << r.dump();
    EXPECT_EQ(db::query::vault::Key::getVaultKey(id)->version, v2);
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    (void)v1;
}

TEST_F(VaultKeysDbTest, ANewSigningKeyAfterATpmResetKeepsOldAttestationsValid) {
    const auto engine = newVault("vktpm");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/a.txt", "alpha");
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    const auto oldKeyId = keys.at("attestation").at("key_id").get<unsigned int>();

    // The sealed signing seed is gone (TPM or swtpm state reset): the next attestation uses a new keypair.
    std::filesystem::remove_all(paths::getBackingPath() / ".sealed_test_key_attest.blob");
    vault::attestation::resetForTesting();
    const auto later = newVault("vktpm_later");
    const auto newKeyId = recorded("vault_keys", later->vault->id, later->encryptionManager->get_key_version()).key_id;
    ASSERT_TRUE(newKeyId);
    EXPECT_NE(*newKeyId, oldKeyId);
    db::Transactions::exec("VaultKeysDbTest::retired", [&](pqxx::work& txn) {
        EXPECT_FALSE(txn.exec("SELECT retired_at FROM key_attestation_keys WHERE id = $1", pqxx::params{oldKeyId})
                         .one_field_ref().is_null());
    });

    // The old export still recovers: its signing key's public half is still on record.
    corruptSealed("vault_keys", id);
    dropEngine(id);
    const auto r = importVia(device(superUser), id, keys, name);
    EXPECT_EQ(outcome(r, keys.at("key_info").at("key_version").get<unsigned int>()), "restored") << r.dump();
    EXPECT_EQ(readFile(id, "/a.txt"), "alpha");
}


// ---- salvage -------------------------------------------------------------------------------------------------------

TEST_F(VaultKeysDbTest, SalvageReKeysWhatTheSuppliedKeyDecryptsAndNeverStoresIt) {
    const auto engine = newVault("vksalv");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/good.txt", "good file");
    write(engine, "/damaged.txt", "damaged file");
    write(engine, "/foreign.txt", "foreign file");
    const auto old = unattested(WsKeys::exportKeys({{"vault_id", id}}, device(superUser)));  // a pre-revision-3 export
    const auto version = old.at("key_info").at("key_version").get<unsigned int>();
    const auto supplied = keyBytes(old.at("key"));

    auto damaged = backingOf(id, "/damaged.txt");
    damaged[0] ^= 0xff;
    overwriteBacking(id, "/damaged.txt", damaged);
    std::vector<uint8_t> foreign(backingOf(id, "/foreign.txt").size());
    randombytes_buf(foreign.data(), foreign.size());  // another key's file, as far as any key can tell
    overwriteBacking(id, "/foreign.txt", foreign);
    corruptSealed("vault_keys", id);
    dropEngine(id);

    // Recover: needs salvage, nothing changes.
    auto r = importVia(device(superUser), id, old, name);
    EXPECT_EQ(outcome(r, version), "needs_salvage") << r.dump();
    EXPECT_FALSE(r.at("written").get<bool>());
    EXPECT_FALSE(hasEngine(id));

    // Salvage needs its own confirmation with the typed name.
    EXPECT_EQ(wsCode([&] { return salvageVia(id, old, std::nullopt); }), "vault_key_salvage");
    EXPECT_EQ(wsCode([&] { return salvageVia(id, old, std::string("nope")); }), "vault_key_salvage");
    EXPECT_FALSE(hasEngine(id));

    r = salvageVia(id, old, name);
    EXPECT_EQ(r.at("mode"), "salvage");
    EXPECT_EQ(outcome(r, version), "salvaged") << r.dump();
    ASSERT_TRUE(r.at("salvage").is_object()) << r.dump();
    const auto& report = r.at("salvage");
    EXPECT_EQ(report.at("state"), "finished");
    EXPECT_EQ(report.at("salvaged"), 1);
    EXPECT_EQ(report.at("unrecoverable"), 2);
    EXPECT_EQ(report.at("versions"), json::array({version}));
    const auto fresh = report.at("new_version").get<unsigned int>();
    EXPECT_EQ(fresh, version + 1);
    std::set<std::string> lost;
    for (const auto& f : report.at("failures")) {
        EXPECT_EQ(f.at("kind"), "unrecoverable");
        lost.insert(f.at("path").get<std::string>());
    }
    EXPECT_EQ(lost, (std::set<std::string>{"/damaged.txt", "/foreign.txt"}));

    // The vault runs on a fresh, attested daemon key; the good file reads; the supplied key is nowhere.
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    ASSERT_TRUE(hasEngine(id));
    EXPECT_EQ(readFile(id, "/good.txt"), "good file");
    EXPECT_EQ(fileVersion(id, "/good.txt"), fresh);
    EXPECT_EQ(fileVersion(id, "/damaged.txt"), version);
    const auto running = runtime::Deps::get().storageManager->getEngine(id);
    EXPECT_TRUE(attestedRow("vault_keys", id, fresh, checkOf(running, fresh)));
    EXPECT_FALSE(storedAnywhere(id, supplied));
    const auto s = statusOf(id);
    EXPECT_TRUE(s.at("key_available").get<bool>()) << s.dump();
    EXPECT_EQ(s.at("version"), fresh);
    EXPECT_EQ(s.at("last_salvage").at("id"), report.at("id"));
    EXPECT_FALSE(s.at("rotation_in_progress").get<bool>());

    // The salvaged version still can't be restored as canonical, and the CLI shows the same report.
    const auto viaCli = router->executeLine("vault keys import " + std::to_string(id) + " --file k.json --json",
                                            superUser, nullptr, std::nullopt, old.dump());
    ASSERT_EQ(viaCli.exit_code, 0) << viaCli.stderr_text << viaCli.stdout_text;
    EXPECT_EQ(outcome(json::parse(viaCli.stdout_text), version), "needs_salvage");
    // After a restart the vault starts: the unrecoverable files don't hold it hostage.
    dropEngine(id);
    EXPECT_NO_THROW((void)runtime::Deps::get().storageManager->reinstateVault(id));
    EXPECT_TRUE(hasEngine(id));
}

// mode salvage is always confirmed as a salvage, even when every version turns out to be restorable: the text says
// nothing needs salvage, and confirming only restores (no fresh key, no salvage pass).
TEST_F(VaultKeysDbTest, SalvageModeWithNothingToSalvageConfirmsAsASalvageAndOnlyRestores) {
    const auto engine = newVault("vksalvnone");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/a.txt", "alpha");
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));  // attested: recoverable
    const auto version = keys.at("key_info").at("key_version").get<unsigned int>();
    corruptSealed("vault_keys", id);
    dropEngine(id);
    const auto broken = sealedBytes("vault_keys", id, version);

    const auto confirmation = [&](const std::optional<std::string>& confirm) -> std::pair<std::string, std::string> {
        try {
            (void)salvageVia(id, keys, confirm);
        } catch (const ops::NeedsConfirmation& e) {
            return {e.code, e.what()};
        }
        return {"", ""};
    };
    for (const auto& confirm : {std::optional<std::string>{}, std::optional<std::string>("not-the-name")}) {
        const auto [code, text] = confirmation(confirm);
        EXPECT_EQ(code, "vault_key_salvage");
        EXPECT_NE(text.find("restores key version(s) " + std::to_string(version)), std::string::npos) << text;
        EXPECT_NE(text.find("Nothing needs salvage"), std::string::npos) << text;
        EXPECT_EQ(text.find("Salvaging"), std::string::npos) << text;
    }
    EXPECT_EQ(sealedBytes("vault_keys", id, version), broken);
    // The same document in recover mode keeps its own confirmation.
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, keys); }), "vault_key_import");

    const auto r = salvageVia(id, keys, name);
    EXPECT_EQ(r.at("mode"), "salvage");
    EXPECT_EQ(outcome(r, version), "restored") << r.dump();
    EXPECT_TRUE(r.at("salvage").is_null()) << r.dump();
    EXPECT_TRUE(r.at("written").get<bool>());
    EXPECT_TRUE(r.at("key_available").get<bool>()) << r.dump();
    EXPECT_EQ(readFile(id, "/a.txt"), "alpha");
    const auto s = statusOf(id);
    EXPECT_EQ(s.at("version"), version);  // no fresh key
    EXPECT_TRUE(s.at("last_salvage").is_null()) << s.dump();

    // Nothing left to write: no confirmation at all, in either mode.
    const auto again = salvageVia(id, keys, std::nullopt);
    EXPECT_FALSE(again.at("written").get<bool>());
    EXPECT_EQ(outcome(again, version), "unchanged");
}

TEST_F(VaultKeysDbTest, AnInterruptedSalvageResumesOnTheSameKeyWithoutLosingAFile) {
    const auto engine = newVault("vkcrash");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    for (const auto* f : {"/one.txt", "/two.txt", "/three.txt"}) write(engine, f, std::string("content of ") + f);
    const auto old = unattested(WsKeys::exportKeys({{"vault_id", id}}, device(superUser)));
    const auto version = old.at("key_info").at("key_version").get<unsigned int>();
    corruptSealed("vault_keys", id);
    dropEngine(id);

    // A crash right after the second file's row moved to the fresh key, before its sidecar was renamed.
    int committed = 0;
    keys::setSalvageStepHookForTesting([&](const int step, const std::shared_ptr<fs::model::File>&) {
        if (step == static_cast<int>(sync::rotation::Step::Committed) && ++committed == 2)
            throw sync::rotation::SimulatedCrash{sync::rotation::Step::Committed};
    });
    struct Reset {
        ~Reset() { keys::setSalvageStepHookForTesting({}); }
    } reset;
    bool crashed = false;
    try {
        (void)salvageVia(id, old, name);
    } catch (const sync::rotation::SimulatedCrash&) {
        crashed = true;
    }
    ASSERT_TRUE(crashed);
    keys::setSalvageStepHookForTesting({});
    const auto interrupted = db::query::vault::Key::runningSalvage(id);
    ASSERT_TRUE(interrupted);
    ASSERT_TRUE(interrupted->new_version);
    const auto fresh = *interrupted->new_version;

    // Run again with the same key: the same fresh version, the sidecar settled, the rest re-keyed.
    const auto r = salvageVia(id, old, name);
    ASSERT_TRUE(r.at("salvage").is_object()) << r.dump();
    EXPECT_EQ(r.at("salvage").at("new_version"), fresh);
    EXPECT_EQ(r.at("salvage").at("state"), "finished");
    EXPECT_EQ(r.at("salvage").at("unrecoverable"), 0);
    EXPECT_EQ(db::query::vault::Key::getVaultKey(id)->version, fresh) << "no second key was minted";
    for (const auto* f : {"/one.txt", "/two.txt", "/three.txt"}) {
        EXPECT_EQ(readFile(id, f), std::string("content of ") + f);
        EXPECT_EQ(fileVersion(id, f), fresh) << f;
        const auto file = db::query::fs::File::getFileByPath(id, f);
        EXPECT_FALSE(std::filesystem::exists(sync::rotation::sidecarPathFor(file->backing_path))) << f;
    }
    EXPECT_FALSE(db::query::vault::Key::runningSalvage(id));
    EXPECT_FALSE(storedAnywhere(id, keyBytes(old.at("key"))));
    (void)version;
}

TEST_F(VaultKeysDbTest, SalvageOfRemoteOnlyFilesGoesThroughThePricePreflight) {
    auto apiKey = std::make_shared<vault::model::APIKey>(superUser->id, "vk_key_" + tag(), vault::model::S3Provider::AWS,
                                                              "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                              "us-east-1", "https://s3.example.com");
    const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(apiKey);
    const auto created = ops::vaults::create(superUser, {.name = "vkcloud_" + tag(), .type = vault::model::VaultType::S3,
                                                         .s3 = ops::vaults::S3Spec{.api_key_id = keyId,
                                                                                   .bucket = "vk-" + tag()}});
    const auto id = created->id;
    const auto engine = runtime::Deps::get().storageManager->getEngine(id);
    write(engine, "/doc.txt", "only in the bucket");
    const auto file = db::query::fs::File::getFileByPath(id, "/doc.txt");
    ASSERT_TRUE(file && !file->encryption_iv.empty());
    const auto old = unattested(WsKeys::exportKeys({{"vault_id", id}}, device(superUser)));
    const auto version = file->encrypted_with_key_version;

    // The object is upstream; the local copy is gone (a cache vault, or a host that lost its backing store).
    auto bucket = std::make_shared<KeyBucket>(runtime::Deps::get().apiKeyManager->getAPIKey(keyId));
    std::ifstream in(file->backing_path, std::ios::binary);
    std::vector<uint8_t> sealed{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    bucket->put("doc.txt", {.body = sealed, .etag = "\"etag-1\"",
                            .meta = {{"x-amz-meta-vh-encrypted", "true"}, {"x-amz-meta-vh-iv", file->encryption_iv},
                                     {"x-amz-meta-vh-key-version", std::to_string(version)}}});
    std::filesystem::remove(file->backing_path);
    corruptSealed("vault_keys", id);
    dropEngine(id);

    bool refuse = true;
    int preflights = 0;
    keys::setSalvageEngineHookForTesting([&](const std::shared_ptr<storage::Engine>& e) {
        const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(e);
        ASSERT_TRUE(cloud);
        cloud->setS3ControllerForTesting(bucket);
        cloud->setRemoteFetchGate([&](const storage::CloudEngine&, const storage::RemoteFetchRequest& request)
                                      -> std::unique_ptr<storage::RemoteFetchReservation> {
            ++preflights;
            EXPECT_EQ(request.operation, "key_salvage");
            EXPECT_EQ(request.get_requests, 1u);
            if (refuse) throw storage::ContentUnavailable("S3 price budget refused key_salvage (test)");
            return std::make_unique<NoopReservation>();
        });
    });
    struct Reset {
        ~Reset() { keys::setSalvageEngineHookForTesting({}); }
    } reset;

    // A refused price preflight: skipped (with the estimate), nothing fetched.
    auto r = salvageVia(id, old, created->name);
    ASSERT_TRUE(r.at("salvage").is_object()) << r.dump();
    EXPECT_EQ(r.at("salvage").at("skipped_remote"), 1) << r.dump();
    EXPECT_EQ(r.at("salvage").at("salvaged"), 0);
    const auto& failure = r.at("salvage").at("failures").at(0);
    EXPECT_EQ(failure.at("kind"), "skipped_remote");
    EXPECT_NE(failure.at("reason").get<std::string>().find("estimate: 1 HEAD + 1 GET"), std::string::npos) << r.dump();
    EXPECT_EQ(preflights, 1);
    EXPECT_TRUE(bucket->getIfMatches().empty());
    const auto fresh = r.at("salvage").at("new_version").get<unsigned int>();
    EXPECT_EQ(fileVersion(id, "/doc.txt"), version);

    // The budget allows it now: one HEAD, one GET bound to its ETag, re-encrypted in memory and uploaded; same key.
    refuse = false;
    r = salvageVia(id, old, created->name);
    ASSERT_TRUE(r.at("salvage").is_object()) << r.dump();
    EXPECT_EQ(r.at("salvage").at("salvaged"), 1) << r.dump();
    EXPECT_EQ(r.at("salvage").at("new_version"), fresh);
    const auto ifMatches = bucket->getIfMatches();
    ASSERT_FALSE(ifMatches.empty());
    EXPECT_EQ(ifMatches.back(), std::optional<std::string>("\"etag-1\""));
    EXPECT_FALSE(std::filesystem::exists(file->backing_path)) << "nothing is written to disk";
    EXPECT_EQ(fileVersion(id, "/doc.txt"), fresh);
    const auto object = bucket->object("doc.txt");
    ASSERT_TRUE(object);
    EXPECT_EQ(object->meta.at("x-amz-meta-vh-key-version"), std::to_string(fresh));
    const auto row = db::query::fs::File::getFileByPath(id, "/doc.txt");
    const auto running = runtime::Deps::get().storageManager->getEngine(id);
    const auto plain = running->encryptionManager->decrypt(object->body, row->encryption_iv, fresh);
    EXPECT_EQ(std::string(plain.begin(), plain.end()), "only in the bucket");
    EXPECT_FALSE(storedAnywhere(id, keyBytes(old.at("key"))));
}

}
