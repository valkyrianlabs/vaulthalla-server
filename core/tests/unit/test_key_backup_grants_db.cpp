// vh-test-tier: db-only
// Key-backup grants (#362; MFA design note section 6.4, decisions D1 and D4), DB-backed, through the real ws handlers
// under the router's step-up scope:
//   - D1: the migration carries exactly each live device's export authority (no escalation, no loss), a rotation in
//     the same window stays exportable through the grant (no backup gap), and the migration never runs twice;
//   - a grant-scoped export needs no step-up, from a reconnect too; anything outside it gets the keys step-up bound to
//     its target, and a person's approval of that one export works;
//   - create, extend and confirm need a device.trust approval for their exact target; revoke needs none;
//   - the cap: the 61st export in an hour suspends the grant and notifies; confirming lifts it;
//   - every revocation trigger: device revoked, user deactivated, deleted or without Export, recovery and MFA reset,
//     a device idle for 90 days;
//   - D4: during a recovery cooldown only the device's approval key registered before the recovery re-creates the
//     revoked grant, and only for the vaults it named;
//   - the audit events of every grant change and use.
#include "../helpers/identities.hpp"
#include "audit/Trail.hpp"
#include "auth/approval/Approvals.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/ApprovalKey.hpp"
#include "db/query/device/BackupGrant.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/BackupGrants.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "ops/Users.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/Vaults.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/Refusal.hpp"
#include "protocols/ws/handler/Approvals.hpp"
#include "protocols/ws/handler/Devices.hpp"
#include "protocols/ws/handler/vault/Keys.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/SqlDeployer.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <paths.h>
#include <pqxx/pqxx>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace vh::test_key_backup_grants_db {

using json = nlohmann::json;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;
using UserPtr = std::shared_ptr<identities::User>;
using Grant = db::query::device::BackupGrant;
using Grants = db::query::device::BackupGrants;
namespace bg = ops::backup_grants;
namespace crypto = vh::device::crypto;
namespace h = protocols::ws::handler;
using auth::stepup::Scope;

struct Answer {
    bool ok{false};
    json data{};
    std::string code{};
    std::string message{};
};

Answer call(const std::function<json()>& fn) {
    try {
        return {.ok = true, .data = fn()};
    } catch (...) {
        auto reply = protocols::ws::core::describeCurrentError();
        const auto code = reply.data.is_object() ? reply.data.value("code", std::string{}) : std::string{};
        return {.ok = false, .data = reply.data, .code = code, .message = reply.message};
    }
}

// A command as the router runs it: under the request's step-up scope.
Answer run(const SessionPtr& s, const std::function<json()>& fn) {
    const Scope scope(s);
    return call(fn);
}

// A P-256 key standing in for Desktop's Secure Enclave approval key.
class ApprovalKey {
public:
    ApprovalKey() : key_(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256")) {
        if (!key_) throw std::runtime_error("keygen");
    }
    ~ApprovalKey() { EVP_PKEY_free(key_); }
    ApprovalKey(const ApprovalKey&) = delete;
    ApprovalKey& operator=(const ApprovalKey&) = delete;

    [[nodiscard]] std::vector<uint8_t> spki() const {
        unsigned char* der = nullptr;
        const int len = i2d_PUBKEY(key_, &der);
        std::vector<uint8_t> out(der, der + len);
        OPENSSL_free(der);
        return out;
    }
    [[nodiscard]] std::string spkiHex() const { return crypto::toHex(crypto::sha256(spki())); }

    [[nodiscard]] std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::size_t len = 0;
        EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key_);
        EVP_DigestSign(ctx, nullptr, &len, message.data(), message.size());
        std::vector<uint8_t> sig(len);
        EVP_DigestSign(ctx, sig.data(), &len, message.data(), message.size());
        EVP_MD_CTX_free(ctx);
        sig.resize(len);
        return sig;
    }

private:
    EVP_PKEY* key_;
};

std::string uniqueTag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(::getpid()) + "_" + std::to_string(n.fetch_add(1));
}

class KeyBackupGrantsDb : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::filesystem::path root;
    std::shared_ptr<auth::session::Manager> previousSessions;
    std::shared_ptr<const vh::device::ServerIdentity> previousIdentity;
    std::vector<Grant> notices;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_key_backup_grants] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_key_backup_grants_" + std::to_string(::getpid()));
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
        protocols::device::endpoints::clearNodeIdForTesting();
        audit::Trail::instance()->resetForTesting();
        superUser = identities::manager().userByName("admin");
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        identities::Manager::setPublishedHook({});
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        auth::session::Issuer::setJwtSecretForTesting("key-backup-grants-test-secret");
        previousSessions = runtime::Deps::get().sessionManager;
        runtime::Deps::get().sessionManager = std::make_shared<auth::session::Manager>();
        auth::mfa::policy::setLevel(auth::mfa::policy::Level::Optional);
        previousIdentity = vh::device::currentServerIdentity();
        vh::device::setCurrentServerIdentity(vh::device::ServerIdentity::generate());
        auth::approval::resetForTesting();
        bg::resetExportWindowsForTesting();
        bg::setSuspendNoticeForTesting([this](const Grant& g) { notices.push_back(g); });
        bg::installIdentityHook();
    }

    void TearDown() override {
        if (skipTests) return;
        identities::Manager::setPublishedHook({});
        bg::setSuspendNoticeForTesting({});
        bg::resetExportWindowsForTesting();
        auth::approval::resetForTesting();
        vh::device::setCurrentServerIdentity(previousIdentity);
        auth::mfa::policy::setLevel(auth::mfa::policy::Level::Admins);
        runtime::Deps::get().sessionManager = previousSessions;
        auth::session::Issuer::clearJwtSecretForTesting();
    }

    static UserPtr newUser(const std::string& role) {
        const auto r = db::query::rbac::role::Admin::get(role);
        if (!r) throw std::runtime_error("Missing role " + role);
        return identities::manager().user(
            test::identities::createUser("kbg_" + role + "_" + uniqueTag(), r, std::nullopt,
                                         vh::crypto::hash::password("Key-Backup-Grants-1-xyz"))->id);
    }

    static std::shared_ptr<storage::Engine> newVault() {
        const auto v = ops::vaults::create(superUser, {.name = "kbg_" + uniqueTag(), .type = vault::model::VaultType::Local});
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    static void write(const std::shared_ptr<storage::Engine>& engine, const std::string& path, const std::string& text) {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(text.begin(), text.end()),
                                                .engine = engine, .user = superUser, .overwrite = true}));
    }

    struct Paired {
        vh::device::Device row;
        std::shared_ptr<vh::device::Peer> peer;
        SessionPtr session;
    };

    static Paired pairedDevice(const UserPtr& user, const ApprovalKey* approvalKey = nullptr) {
        auto peer = std::make_shared<vh::device::Peer>();
        peer->spki = crypto::randomNonce();
        peer->spkiHex = crypto::toHex(peer->spki);
        peer->address = "192.0.2.30";
        db::query::device::NewDevice d{.user_id = user->id, .approved_by = user->id, .name = "Mac " + uniqueTag(),
                                       .platform = "macOS", .app_version = "1.0", .spki_sha256 = peer->spkiHex,
                                       .last_ip = "192.0.2.30"};
        if (approvalKey) {
            d.approval_key_spki = approvalKey->spki();
            d.approval_key_sha256 = approvalKey->spkiHex();
        }
        const auto row = db::query::device::Devices::insert(d);
        peer->deviceRowId = row.id;
        return {.row = row, .peer = peer, .session = protocols::ws::Session::devicePrincipal(peer, user, [] {})};
    }

    static SessionPtr reconnect(const Paired& d, const UserPtr& user) {
        return protocols::ws::Session::devicePrincipal(d.peer, user, [] {});
    }

    // The device's approval key answers a challenge for family/target on its session.
    static Answer approveWithKey(const SessionPtr& s, const ApprovalKey& key, const std::string& family,
                                 const std::string& target) {
        const auto c = run(s, [&] { return h::Approvals::challenge(json{{"family", family}, {"target", target}}, s); });
        if (!c.ok) return c;
        const auto payload = *crypto::fromBase64(c.data.at("payload_b64").get<std::string>());
        return run(s, [&] {
            return h::Approvals::submit(json{{"challenge_id", c.data.at("challenge_id")},
                                             {"signature_b64", crypto::toBase64(key.sign(payload))}},
                                        s);
        });
    }

    static Answer exportVia(const SessionPtr& s, const uint32_t vaultId) {
        return run(s, [&] { return h::VaultKeys::exportKeys(json{{"vault_id", vaultId}}, s); });
    }

    // A command that answers step_up_required, approved with the device's key, then sent again.
    static Answer approvedWithKey(const SessionPtr& s, const ApprovalKey& key, const std::function<json()>& fn) {
        const auto first = run(s, fn);
        if (first.code != "step_up_required") return first;
        const auto approved = approveWithKey(s, key, first.data.at("family"), first.data.at("target"));
        if (!approved.ok) return approved;
        return run(s, fn);
    }

    static std::optional<Grant> live(const Paired& d) { return Grants::liveForDevice(d.row.id); }

    // The vaults the device may export now without a person's approval: every vault in `candidates` its grant covers.
    static std::set<uint32_t> coveredBy(const Paired& d, const std::vector<uint32_t>& candidates) {
        std::set<uint32_t> out;
        const Scope scope(d.session);
        for (const auto v : candidates)
            if (bg::covering({v})) out.insert(v);
        bg::resetExportWindowsForTesting();
        return out;
    }

    static std::vector<std::string> auditFor(const uint32_t grantId, const int64_t afterSeq = 0) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("kbg audit", [&](pqxx::work& txn) {
            std::vector<std::string> out;
            for (const auto& r : txn.exec("SELECT action, COALESCE(details::jsonb->>'reason', '') FROM audit_event "
                                          "WHERE action LIKE 'keys.backup.%' AND (details::jsonb->>'grant_id')::BIGINT = $1 "
                                          "AND seq > $2 ORDER BY seq",
                                          pqxx::params{grantId, afterSeq})) {
                auto a = r[0].as<std::string>();
                if (const auto reason = r[1].as<std::string>(); !reason.empty()) a += "/" + reason;
                out.push_back(a);
            }
            return out;
        });
    }

    static int64_t auditHead() {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("kbg audit head", [](pqxx::work& txn) {
            return txn.exec("SELECT COALESCE(MAX(seq), 0) FROM audit_event").one_field_ref().as<int64_t>();
        });
    }

    // Re-runs migration 130 on this database as an upgrade would: the grant tables emptied and the snapshot dropped,
    // then the file itself (it snapshots the live devices) and the daemon's first-start step.
    // `before` sets up what a 129-era database held (the interim columns of #360).
    static std::size_t rerunMigration(const std::function<void(pqxx::work&)>& before = {}) {
        db::Transactions::exec("kbg rerun migration", [&](pqxx::work& txn) {
            txn.exec("DELETE FROM key_backup_grants");
            txn.exec("DROP TABLE IF EXISTS key_backup_grant_migration");
            if (before) before(txn);
            txn.exec(db::seed::readFileToString(std::filesystem::path(paths::getPsqlSchemasPath()) /
                                                "130_key_backup_grants.sql"));
        });
        return bg::migratePending();
    }
};

// D1 (acceptance): for every seeded device the set of vaults it may export without a prompt is identical before and
// after the migration (no escalation, no loss), and a rotation in the same window stays exportable through the grant
// (no backup gap). One keys.backup.grant.migrate per grant; nothing for a user without Export or a revoked device.
TEST_F(KeyBackupGrantsDb, TheMigrationCarriesExactlyTheExportAuthorityAndOpensNoBackupGap) {
    const auto exporter = newUser("key_custodian");
    const auto plain = newUser("unprivileged");
    ASSERT_TRUE(bg::mayHold(*superUser));
    ASSERT_TRUE(bg::mayHold(*exporter)) << "key_custodian holds encryption-key Export";
    ASSERT_FALSE(bg::mayHold(*plain));

    const auto a = newVault();
    const auto b = newVault();
    const auto doomed = newVault();
    write(a, "/a.txt", "alpha");
    (void)ops::vaults::remove(superUser, {.id = doomed->vault->id});

    const auto adminMac = pairedDevice(superUser);
    const auto exporterMac = pairedDevice(exporter);
    const auto plainMac = pairedDevice(plain);
    const auto revokedMac = pairedDevice(superUser);
    (void)db::query::device::Devices::revoke(revokedMac.row.id);

    // Before: what each device could export without a prompt was its user's whole export authority (D1).
    std::vector<uint32_t> candidates;
    for (const auto& v : db::query::vault::Vault::listLiveVaults()) candidates.push_back(v->id);
    candidates.push_back(doomed->vault->id);
    candidates.push_back(999'999);  // no such vault
    const auto before = [&](const UserPtr& u) {
        std::set<uint32_t> out;
        if (!bg::mayHold(*u)) return out;
        for (const auto v : ops::vault_keys::exportableVaults(u)) out.insert(v);
        return out;
    };
    const std::map<std::string, std::pair<Paired, std::set<uint32_t>>> seeded{
        {"admin", {adminMac, before(superUser)}},
        {"exporter", {exporterMac, before(exporter)}},
        {"plain", {plainMac, {}}},
    };
    ASSERT_TRUE(before(superUser).contains(doomed->vault->id)) << "a deleted vault within key retention is exportable";

    std::size_t holders = 0;
    for (const auto& d : db::query::device::Devices::listAll())
        if (!d.revoked())
            if (const auto u = identities::manager().user(d.user_id); u && bg::mayHold(*u)) ++holders;
    ASSERT_GE(holders, 2u);
    const auto head = auditHead();
    EXPECT_EQ(rerunMigration(), holders) << "one grant per live device whose user may export: admin's, the exporter's";
    for (const auto& [who, entry] : seeded) {
        const auto& [device, expected] = entry;
        EXPECT_EQ(coveredBy(device, candidates), expected) << who << ": no escalation, no loss";
        if (expected.empty()) {
            EXPECT_FALSE(live(device)) << who << " gets no grant";
            continue;
        }
        const auto g = live(device);
        ASSERT_TRUE(g) << who;
        EXPECT_EQ(g->origin, "migrated");
        EXPECT_FALSE(g->confirmed_at);
        EXPECT_EQ(auditFor(g->id, head), std::vector<std::string>{"keys.backup.grant.migrate/d1"}) << who;
    }
    EXPECT_FALSE(Grants::liveForDevice(revokedMac.row.id)) << "a revoked device gets nothing";

    // The same window: a rotation mid-sync. The device exports the new key and the outgoing one, with no prompt.
    const auto v1 = a->encryptionManager->get_key_version();
    a->encryptionManager->prepare_key_rotation();
    const auto v2 = a->encryptionManager->get_key_version();
    ASSERT_NE(v1, v2);
    const auto exported = exportVia(adminMac.session, a->vault->id);
    ASSERT_TRUE(exported.ok) << exported.code << " " << exported.message;
    EXPECT_EQ(exported.data.at("key_info").at("key_version"), v2);
    ASSERT_EQ(exported.data.at("historical_keys").size(), 1u);
    EXPECT_EQ(exported.data.at("historical_keys")[0].at("key_version"), v1);
    EXPECT_EQ(exported.data.at("historical_keys")[0].at("reason"), "rotation");
    const auto g = live(adminMac);
    ASSERT_TRUE(g);
    EXPECT_TRUE(g->last_used_at);
    EXPECT_EQ(auditFor(g->id, head).back(), "keys.backup.export");
    // And a reconnect (a new session of the same device) backs up without a prompt too.
    EXPECT_TRUE(exportVia(reconnect(adminMac, superUser), b->vault->id).ok);

    // Never twice: the snapshot row is spent, and running the file again snapshots nothing.
    EXPECT_EQ(bg::migratePending(), 0u);
    db::Transactions::exec("kbg rerun file", [](pqxx::work& txn) {
        txn.exec(db::seed::readFileToString(std::filesystem::path(paths::getPsqlSchemasPath()) / "130_key_backup_grants.sql"));
    });
    EXPECT_EQ(bg::migratePending(), 0u);
    EXPECT_FALSE(live(plainMac));
}

// #360's interim column (migration 129): a device whose implicit authority a recovery-code sign-in revoked gets no live
// grant, only a revoked migrated one over what it could export then; during the cooldown its approval key from before
// the recovery re-creates it for those vaults, and nothing wider.
TEST_F(KeyBackupGrantsDb, AnInterimRevocationCarriesOverAsARevokedGrantOnlyThePreRecoveryKeyReCreates) {
    const ApprovalKey key;
    const auto user = newUser("key_custodian");
    const auto mac = pairedDevice(user, &key);
    const auto kept = pairedDevice(user);
    const auto vault = newVault();
    const auto exportable = ops::vault_keys::exportableVaults(user);
    ASSERT_FALSE(exportable.empty());

    (void)rerunMigration([&](pqxx::work& txn) {
        txn.exec("ALTER TABLE devices ADD COLUMN IF NOT EXISTS key_backup_revoked_at TIMESTAMPTZ, "
                 "ADD COLUMN IF NOT EXISTS key_backup_revoked_reason TEXT");
        txn.exec("UPDATE devices SET key_backup_revoked_at = NOW(), key_backup_revoked_reason = 'recovery_code' "
                 "WHERE id = $1", pqxx::params{mac.row.id});
    });
    EXPECT_FALSE(live(mac)) << "no migrated grant for a device whose key backup was revoked";
    const auto carried = Grants::lastRevokedForDevice(mac.row.id);
    ASSERT_TRUE(carried);
    EXPECT_EQ(carried->origin, "migrated");
    EXPECT_EQ(carried->revoked_reason, std::optional<std::string>("recovery_code"));
    EXPECT_EQ(carried->vault_ids, std::vector<uint32_t>(exportable.begin(), exportable.end()));
    EXPECT_TRUE(coveredBy(mac, carried->vault_ids).empty());
    ASSERT_TRUE(live(kept)) << "the user's other device keeps its authority";
    EXPECT_EQ(auditFor(carried->id), std::vector<std::string>{"keys.backup.grant.migrate/d1"});
    EXPECT_TRUE(db::Transactions::exec("kbg columns", [](pqxx::work& txn) {
        return txn.exec("SELECT 1 FROM information_schema.columns WHERE table_name = 'devices' "
                        "AND column_name LIKE 'key_backup_revoked%'").empty();
    })) << "the interim columns are dropped once carried over";

    (void)auth::mfa::startRecoveryCooldown(user->id);
    const auto s = mac.session;
    const auto id = static_cast<uint32_t>(vault->vault->id);
    const std::vector<uint32_t> all(exportable.begin(), exportable.end());
    const auto recreated = approvedWithKey(s, key, [&] {
        return h::Devices::backupGrantCreate(json{{"vault_ids", all}}, s);
    });
    ASSERT_TRUE(recreated.ok) << recreated.code << " " << recreated.message;
    EXPECT_EQ(recreated.data.at("grant").at("vault_ids"), json(all));
    EXPECT_TRUE(exportVia(s, id).ok);
}

// A vault the grant names exports with no prompt; any other export is the keys step-up bound to its target, which a
// person's approval of exactly that export satisfies once. No grant ever covers a vault it doesn't name.
TEST_F(KeyBackupGrantsDb, AGrantScopedExportNeedsNoStepUpAndAnythingElseIsTargetBound) {
    const ApprovalKey key;
    const auto mac = pairedDevice(superUser, &key);
    const auto inside = newVault();
    const auto outside = newVault();
    (void)Grants::create({.device_id = mac.row.id, .user_id = superUser->id, .vault_ids = {inside->vault->id}});

    EXPECT_TRUE(exportVia(mac.session, inside->vault->id).ok);
    const auto refused = exportVia(mac.session, outside->vault->id);
    ASSERT_EQ(refused.code, "step_up_required");
    EXPECT_EQ(refused.data.at("family"), "keys");
    EXPECT_EQ(refused.data.at("target"), "vault.keys.export:" + std::to_string(outside->vault->id));
    EXPECT_EQ(refused.data.at("methods"), json::array({"device_approval", "console_approval"}));
    EXPECT_FALSE(refused.data.contains("key"));
    {
        // Export all is covered only when the grant names every live vault.
        const Scope scope(mac.session);
        try {
            (void)ops::vault_keys::exportAll(superUser, ops::vault_keys::Channel::Device);
            ADD_FAILURE() << "export all ran without an approval";
        } catch (const ops::StepUpRequired& e) {
            EXPECT_EQ(e.target, std::optional<std::string>("vault.keys.export:all"));
        }
    }

    // A person approves that one export (Touch ID): it runs once, and the next one asks again.
    ASSERT_TRUE(approveWithKey(mac.session, key, "keys", refused.data.at("target")).ok);
    EXPECT_TRUE(exportVia(mac.session, outside->vault->id).ok);
    EXPECT_EQ(exportVia(mac.session, outside->vault->id).code, "step_up_required");
    EXPECT_EQ(live(mac)->vault_ids, std::vector<uint32_t>{inside->vault->id}) << "an approved export never widens a grant";

    // Another user's device never uses this grant; a console session never gets keys at all.
    const auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = superUser;
    EXPECT_EQ(exportVia(web, inside->vault->id).code, "export_requires_device");
}

// device.backup.grant.create, extend and confirm need a device.trust approval for their exact target; revoke needs
// none. Each change is audited, and the grant only ever names what was approved.
TEST_F(KeyBackupGrantsDb, CreateExtendAndConfirmNeedADeviceTrustApprovalAndRevokeNeedsNone) {
    const ApprovalKey key;
    const auto mac = pairedDevice(superUser, &key);
    const auto first = newVault();
    const auto second = newVault();
    const auto ids = [](const auto& e) { return static_cast<uint32_t>(e->vault->id); };
    const auto s = mac.session;

    const auto createIt = [&] { return h::Devices::backupGrantCreate(json{{"vault_ids", json::array({ids(first)})}}, s); };
    const auto refused = run(s, createIt);
    ASSERT_EQ(refused.code, "step_up_required") << refused.message;
    EXPECT_EQ(refused.data.at("family"), "device.trust");
    EXPECT_EQ(refused.data.at("target"), bg::createTarget(mac.row.id, {ids(first)}));
    EXPECT_FALSE(live(mac));
    // An approval of another target (another vault set) doesn't carry over.
    ASSERT_TRUE(approveWithKey(s, key, "device.trust", bg::createTarget(mac.row.id, {ids(second)})).ok);
    EXPECT_EQ(run(s, createIt).code, "step_up_required");

    const auto created = approvedWithKey(s, key, createIt);
    ASSERT_TRUE(created.ok) << created.code << " " << created.message;
    const auto grantId = created.data.at("grant").at("id").get<uint32_t>();
    EXPECT_EQ(created.data.at("grant").at("origin"), "approved");
    EXPECT_EQ(created.data.at("grant").at("approved_via"), "device_approval");
    EXPECT_EQ(created.data.at("grant").at("vault_ids"), json::array({ids(first)}));
    EXPECT_EQ(created.data.at("grant").at("device_id"), mac.row.spki_sha256);
    EXPECT_EQ(run(s, createIt).code, "conflict") << "one live grant per device: extend it";

    const auto extendIt = [&] {
        return h::Devices::backupGrantExtend(json{{"grant_id", grantId}, {"vault_ids", json::array({ids(second)})}}, s);
    };
    EXPECT_EQ(run(s, extendIt).code, "step_up_required");
    const auto extended = approvedWithKey(s, key, extendIt);
    ASSERT_TRUE(extended.ok) << extended.message;
    EXPECT_EQ(extended.data.at("grant").at("vault_ids"), json::array({ids(first), ids(second)}));
    EXPECT_EQ(run(s, [&] {
                  return h::Devices::backupGrantExtend(json{{"grant_id", grantId}, {"vault_ids", json::array({999'999})}}, s);
              }).code,
              "not_found")
        << "only vaults the user may export";

    const auto confirmIt = [&] { return h::Devices::backupGrantConfirm(json{{"grant_id", grantId}}, s); };
    EXPECT_EQ(run(s, confirmIt).code, "step_up_required");
    ASSERT_TRUE(approvedWithKey(s, key, confirmIt).ok);

    const auto listed = run(s, [&] { return h::Devices::backupGrantList(s); });
    ASSERT_TRUE(listed.ok);
    ASSERT_EQ(listed.data.at("grants").size(), 1u);
    EXPECT_EQ(listed.data.at("grants")[0].at("active"), true);

    // Revoking needs nothing, and ends no-prompt backup at once.
    const auto revoked = run(s, [&] { return h::Devices::backupGrantRevoke(json{{"grant_id", grantId}}, s); });
    ASSERT_TRUE(revoked.ok) << revoked.message;
    EXPECT_EQ(revoked.data.at("grant").at("revoked_reason"), "manual");
    EXPECT_EQ(exportVia(s, ids(first)).code, "step_up_required");
    EXPECT_EQ(auditFor(grantId), (std::vector<std::string>{"keys.backup.grant.create", "keys.backup.grant.extend",
                                                           "keys.backup.grant.confirm",
                                                           "keys.backup.grant.revoke/manual"}));

    // Without the Export permission there is no grant to make; a console session names the device.
    const auto plain = newUser("unprivileged");
    const auto theirs = pairedDevice(plain);
    EXPECT_EQ(run(theirs.session, [&] {
                  return h::Devices::backupGrantCreate(json{{"vault_ids", json::array({ids(first)})}}, theirs.session);
              }).code,
              "denied");
    const auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = superUser;
    EXPECT_EQ(call([&] { return h::Devices::backupGrantCreate(json{{"vault_ids", json::array({ids(first)})}}, web); }).code,
              "invalid")
        << "device_id is required on a console session";
    EXPECT_EQ(call([&] {
                  return h::Devices::backupGrantCreate(json{{"vault_ids", json::array({ids(first)})}, {"device_id", theirs.row.spki_sha256}},
                                                       web);
              }).code,
              "not_found")
        << "only the caller's own devices";
}

// The cap (a stolen Mac sweeping keys): 60 vault exports an hour, then the grant is suspended, the user notified, and
// exports need a person's approval until the grant is confirmed again.
TEST_F(KeyBackupGrantsDb, TheSixtyFirstExportInAnHourSuspendsTheGrantAndNotifies) {
    const ApprovalKey key;
    const auto mac = pairedDevice(superUser, &key);
    const auto vault = newVault();
    const auto id = static_cast<uint32_t>(vault->vault->id);
    const auto g = Grants::create({.device_id = mac.row.id, .user_id = superUser->id, .vault_ids = {id}});
    {
        const Scope scope(mac.session);
        for (std::size_t i = 0; i < bg::kMaxExportsPerHour - 1; ++i) ASSERT_TRUE(bg::covering({id})) << i;
    }
    EXPECT_TRUE(exportVia(mac.session, id).ok) << "the 60th";
    EXPECT_TRUE(notices.empty());
    EXPECT_EQ(exportVia(mac.session, id).code, "step_up_required") << "the 61st";
    ASSERT_TRUE(live(mac));
    EXPECT_TRUE(live(mac)->suspended_at);
    ASSERT_EQ(notices.size(), 1u);
    EXPECT_EQ(notices[0].id, g.id);
    EXPECT_EQ(exportVia(reconnect(mac, superUser), id).code, "step_up_required") << "a reconnect doesn't lift it";

    const auto confirmed = approvedWithKey(mac.session, key, [&] {
        return h::Devices::backupGrantConfirm(json{{"grant_id", g.id}}, mac.session);
    });
    ASSERT_TRUE(confirmed.ok) << confirmed.message;
    EXPECT_TRUE(confirmed.data.at("grant").at("suspended_at").is_null());
    EXPECT_TRUE(exportVia(mac.session, id).ok);
    const auto events = auditFor(g.id);
    EXPECT_NE(std::ranges::find(events, "keys.backup.grant.suspend/export_cap"), events.end());
}

// Every automatic revocation trigger, each audited with its reason.
TEST_F(KeyBackupGrantsDb, EveryRevocationTriggerEndsTheGrant) {
    const auto vault = newVault();
    const auto id = static_cast<uint32_t>(vault->vault->id);
    const auto grantFor = [&](const Paired& d, const UserPtr& u) {
        return Grants::create({.device_id = d.row.id, .user_id = u->id, .vault_ids = {id}});
    };
    const auto reasonOf = [](const Grant& g) { return Grants::byId(g.id)->revoked_reason.value_or("live"); };

    // The device is revoked (in the revocation's own transaction).
    const auto unpaired = pairedDevice(superUser);
    const auto g1 = grantFor(unpaired, superUser);
    (void)ops::devices::revoke(superUser, unpaired.row.spki_sha256);
    EXPECT_EQ(reasonOf(g1), "device_revoked");
    EXPECT_EQ(auditFor(g1.id), std::vector<std::string>{"keys.backup.grant.revoke/device_revoked"});

    // The user is deactivated (the identities publication hook, at once).
    const auto leaving = newUser("key_custodian");
    const auto g2 = grantFor(pairedDevice(leaving), leaving);
    (void)ops::users::update(superUser, {.id = leaving->id, .is_active = false});
    EXPECT_EQ(reasonOf(g2), "user_inactive");

    // The user loses the Export permission.
    const auto demoted = newUser("key_custodian");
    const auto demotedMac = pairedDevice(demoted);
    const auto g3 = grantFor(demotedMac, demoted);
    (void)ops::users::update(superUser, {.id = demoted->id, .role = std::string("unprivileged")});
    EXPECT_EQ(reasonOf(g3), "export_permission");
    {
        const Scope scope(demotedMac.session);
        EXPECT_FALSE(bg::covering({id})) << "and nothing covers its exports";
    }

    // The user is deleted: the grant is revoked (audited) before the account and its devices go.
    const auto gone = newUser("key_custodian");
    const auto g4 = grantFor(pairedDevice(gone), gone);
    (void)ops::users::remove(superUser, {.id = gone->id, .confirmed = true});
    EXPECT_EQ(auditFor(g4.id), std::vector<std::string>{"keys.backup.grant.revoke/user_inactive"});

    // A recovery-code sign-in or an MFA reset (the recovery paths call revokeForUser).
    const auto recovering = newUser("key_custodian");
    const auto g5 = grantFor(pairedDevice(recovering), recovering);
    EXPECT_EQ(bg::revokeForUser(recovering->id, bg::Revocation::RecoveryCode, recovering->id).size(), 1u);
    EXPECT_EQ(reasonOf(g5), "recovery_code");
    const auto reset = newUser("key_custodian");
    const auto g6 = grantFor(pairedDevice(reset), reset);
    (void)bg::revokeForUser(reset->id, bg::Revocation::AdminReset, superUser->id);
    EXPECT_EQ(reasonOf(g6), "admin_reset");
    EXPECT_EQ(auditFor(g6.id), std::vector<std::string>{"keys.backup.grant.revoke/admin_reset"});

    // A device that hasn't connected for 90 days: the handshake and the sweep both end it; 89 days doesn't.
    const auto idle = pairedDevice(superUser);
    const auto g7 = grantFor(idle, superUser);
    const auto setLastSeen = [&](const int days) {
        db::Transactions::exec("kbg last seen", [&](pqxx::work& txn) {
            txn.exec("UPDATE devices SET last_seen_at = NOW() - make_interval(days => $2) WHERE id = $1",
                     pqxx::params{idle.row.id, days});
        });
    };
    setLastSeen(89);
    EXPECT_FALSE(bg::revokeIfIdle(*db::query::device::Devices::byId(idle.row.id)));
    EXPECT_EQ(bg::reconcile(), 0u);
    setLastSeen(91);
    EXPECT_EQ(bg::reconcile(), 1u);
    EXPECT_EQ(reasonOf(g7), "device_idle");
    EXPECT_FALSE(db::query::device::Devices::byId(idle.row.id)->revoked()) << "the device itself stays paired";
    const auto idle2 = pairedDevice(superUser);
    (void)grantFor(idle2, superUser);
    db::Transactions::exec("kbg never seen", [&](pqxx::work& txn) {
        txn.exec("UPDATE devices SET last_seen_at = NULL, created_at = NOW() - INTERVAL '100 days' WHERE id = $1",
                 pqxx::params{idle2.row.id});
    });
    EXPECT_TRUE(bg::revokeIfIdle(*db::query::device::Devices::byId(idle2.row.id))) << "never connected since pairing";
}

// D4: after a recovery-code sign-in revoked the grant, during the cooldown, only that device's approval key registered
// before the recovery re-creates it, only for the vaults the revoked grant named. No other approval, no other vault,
// no other device, no key registered during the recovery.
TEST_F(KeyBackupGrantsDb, DuringTheRecoveryCooldownOnlyAPreRecoveryApprovalKeyReCreatesTheSameVaults) {
    const ApprovalKey key;
    const auto user = newUser("key_custodian");
    const auto mac = pairedDevice(user, &key);
    const auto a = newVault();
    const auto b = newVault();
    const auto c = newVault();
    const auto ids = [](const auto& e) { return static_cast<uint32_t>(e->vault->id); };
    const auto g = Grants::create({.device_id = mac.row.id, .user_id = user->id, .vault_ids = {ids(a), ids(b)}});

    // A device paired before the recovery whose approval key is registered after it.
    const auto lateMac = pairedDevice(user);
    (void)Grants::create({.device_id = lateMac.row.id, .user_id = user->id, .vault_ids = {ids(a)}});

    ASSERT_EQ(bg::revokeForUser(user->id, bg::Revocation::RecoveryCode, user->id).size(), 2u);
    (void)auth::mfa::startRecoveryCooldown(user->id);
    const ApprovalKey lateKey;
    (void)db::query::device::ApprovalKeys::registerKey(lateMac.row.id, lateKey.spki(), lateKey.spkiHex(),
                                                       "console_approval");

    const auto s = mac.session;
    const auto createFor = [&](const SessionPtr& on, std::vector<uint32_t> vaults) {
        return [on, vaults] { return h::Devices::backupGrantCreate(json{{"vault_ids", vaults}}, on); };
    };
    const auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = user;
    EXPECT_EQ(call([&] {
                  return h::Devices::backupGrantCreate(json{{"vault_ids", json::array({ids(a)})}, {"device_id", mac.row.spki_sha256}},
                                                       web);
              }).code,
              "recovery_cooldown")
        << "not from the console";
    EXPECT_EQ(run(s, createFor(s, {ids(a), ids(c)})).code, "recovery_cooldown") << "never a vault it didn't name";
    EXPECT_EQ(approvedWithKey(lateMac.session, lateKey, createFor(lateMac.session, {ids(a)})).code, "recovery_cooldown")
        << "a key registered during the recovery";

    const auto refused = run(s, createFor(s, {ids(a)}));
    ASSERT_EQ(refused.code, "step_up_required");
    EXPECT_EQ(refused.data.at("methods"), json::array({"device_approval"})) << "the approval key, nothing else";
    // The exception is that target only: the approval key approves no other device.trust action in the cooldown.
    EXPECT_EQ(approveWithKey(s, key, "device.trust", "device.pairing.approve:r:k:c").code, "recovery_cooldown");
    EXPECT_EQ(approveWithKey(s, key, "keys", "vault.keys.export:" + std::to_string(ids(a))).code, "recovery_cooldown");
    // A console approval (a passkey possibly enrolled during the recovery) is not enough.
    s->stepUp().addGrant({.user_id = user->id, .family = auth::stepup::Family::DeviceTrust,
                          .target = refused.data.at("target").get<std::string>(),
                          .method = std::string(auth::stepup::kConsoleApprovalMethod),
                          .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5)});
    EXPECT_EQ(run(s, createFor(s, {ids(a)})).code, "step_up_required");

    const auto head = auditHead();
    const auto recreated = approvedWithKey(s, key, createFor(s, {ids(a)}));
    ASSERT_TRUE(recreated.ok) << recreated.code << " " << recreated.message;
    EXPECT_EQ(recreated.data.at("grant").at("approved_via"), "device_approval");
    EXPECT_EQ(recreated.data.at("grant").at("vault_ids"), json::array({ids(a)}));
    EXPECT_NE(recreated.data.at("grant").at("id"), g.id) << "a new grant, the revoked one stays revoked";
    EXPECT_EQ(auditFor(recreated.data.at("grant").at("id").get<uint32_t>(), head),
              std::vector<std::string>{"keys.backup.grant.create"});
    EXPECT_TRUE(exportVia(s, ids(a)).ok) << "backup resumes with no gap";
}

}
