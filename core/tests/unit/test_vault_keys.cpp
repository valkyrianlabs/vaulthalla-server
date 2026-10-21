// Vault key backup and restoration (Vaulthalla Desktop S2/S6, .claude/context/key-backup.md): the key check and its documented vectors,
// vault.keys.status (current, an unfinished rotation's outgoing key, recovery-referenced versions, deleted vaults),
// export refused outside paired devices and the local CLI (D4) and carrying every needed version (the mid-rotation
// gap), export confirmation (current version + matching key check only), and CLI ↔ ws verdicts for every seeded
// admin role; and key import (S6): a key that no longer unseals or is missing is restored after verification and the
// vault's files read again, a wrong key or one the host can still unseal is refused, partial version sets, deleted
// vaults within retention. The device listener itself (real TLS) is covered in test_device_http.cpp.

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
#include "vault/KeyCheck.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <sodium.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
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

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "v" + std::to_string(n.fetch_add(1));
}

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
};

TEST_F(VaultKeysDbTest, StatusReportsTheCurrentKeyRotationAndRecoveryVersionsWithoutKeyBytes) {
    const auto engine = newVault();
    const auto id = engine->vault->id;
    write(engine, "/a.txt", "alpha");
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

    // Finished: v1 is needed only while recovery data references it.
    engine->encryptionManager->finish_key_rotation();
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


// ---- import (S6) --------------------------------------------------------------------------------------------------

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
    EXPECT_EQ(outcome(result, version), "restored");
    EXPECT_EQ(result.at("versions")[0].at("verified_files"), 2);
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

TEST_F(VaultKeysDbTest, ImportRefusesAWrongKeyAndNeverReplacesAKeyTheHostCanUnseal) {
    const auto engine = newVault("vkwrong");
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;
    write(engine, "/a.txt", "alpha");
    const auto keys = WsKeys::exportKeys({{"vault_id", id}}, device(superUser));
    const auto version = keys.at("key_info").at("key_version").get<unsigned int>();
    const auto wrong = forged(keys);

    // The host still unseals its key: other bytes are refused, the same bytes are unchanged.
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, wrong, name); }), "conflict");
    EXPECT_EQ(outcome(importVia(device(superUser), id, keys, name), version), "unchanged");

    corruptSealed("vault_keys", id);
    dropEngine(id);
    const auto broken = sealedBytes("vault_keys", id, version);

    // A key that authenticates none of the vault's files is not its key; a key that doesn't match its own key check
    // is a damaged backup. Neither writes anything.
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, wrong, name); }), "invalid");
    auto damaged = keys;
    damaged["key_check"] = wrong.at("key_check");
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, damaged, name); }), "invalid");
    auto otherVault = keys;
    otherVault["vault_id"] = id + 1000;
    EXPECT_EQ(wsCode([&] { return importVia(device(superUser), id, otherVault, name); }), "invalid");
    EXPECT_EQ(sealedBytes("vault_keys", id, version), broken);
    EXPECT_FALSE(hasEngine(id));

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

    // A database restored from before the rotation lost the outgoing key's row: it is inserted again, the rotation
    // resumes and the running vault reloads it.
    db::Transactions::exec("VaultKeysDbTest::dropRetired", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2", pqxx::params{id, v1});
    });
    dropEngine(id);
    (void)runtime::Deps::get().storageManager->reinstateVault(id);  // a restart: the vault starts without v1
    EXPECT_FALSE(statusOf(id).at("rotation_in_progress").get<bool>());
    r = importVia(device(superUser), id, full, name);
    EXPECT_EQ(outcome(r, v1), "restored") << r.dump();
    EXPECT_TRUE(statusOf(id).at("rotation_in_progress").get<bool>());
    EXPECT_EQ(readFile(id, "/old.txt"), "sealed under v1");
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

    const auto r = importVia(device(superUser), id, keys, name);
    EXPECT_TRUE(r.at("deleted").get<bool>());
    EXPECT_TRUE(r.at("written").get<bool>()) << r.dump();
    EXPECT_EQ(outcome(r, version), "restored") << r.dump();
    EXPECT_GE(r.at("versions")[0].at("verified_files").get<unsigned int>(), 1u);
    const auto s = WsKeys::status(json::object(), console(superUser)).at("vaults");
    const auto it = std::ranges::find_if(s, [&](const json& v) { return v.at("vault_id") == id; });
    ASSERT_NE(it, s.end());
    EXPECT_EQ(it->at("key_check"), keys.at("key_check"));

    (void)ops::vaults::restore(superUser, id);
    ASSERT_TRUE(hasEngine(id));
    EXPECT_EQ(readFile(id, "/kept.txt"), "kept through deletion");
}

}
