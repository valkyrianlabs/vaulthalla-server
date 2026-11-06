// Rotation of the other master secrets (#353, design/sealing/master-secrets.md §6.5, migration 124).
//
// ak_master (api_keys: the S3 secret and the provider token) and s3gw_master (s3_gateway_credentials) go through the
// same staged rewrap as vault_master (#352), so they get the same acceptance matrix, run for both: interrupted staging
// at every batch boundary and at every other crash point, writes during staging and during the window, a tampered
// staged wrap and an old/new master mismatch, an unreadable row, TPM loss mid staging and mid window, explicit rollback
// (staging and window), finalize (by hand and on expiry), the guard trigger and the CLI. After every step the same
// proof: every row names the current master, and the managers that consume the secrets (APIKeyManager,
// CredentialManager) return exactly the values from before.
//
// The JWT secret and the device identity rotate by regeneration, each with its own consequence: everyone signs in
// again (every refresh token revoked, every live session ended), and every paired device is revoked and pairs again
// (never silently trusting the new identity). Both are tested through the CLI, the device identity also at its two
// crash points.

#include "audit/Trail.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Manager.hpp"
#include "crypto/secrets/Rewrap.hpp"
#include "crypto/secrets/Versioned.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/device/Device.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/MasterSecrets.hpp"
#include "ops/Users.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/types.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Manager.hpp"
#include "UsageManager.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace vh::test_master_secret_rotation {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
namespace rw = crypto::secrets::rewrap;
namespace vs = crypto::secrets::versioned;
using Slot = vs::Slot;

struct SimulatedCrash : std::runtime_error {
    SimulatedCrash() : std::runtime_error("simulated crash") {}
};

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

std::string randomHex(const std::size_t bytes) {
    std::vector<uint8_t> raw(bytes);
    randombytes_buf(raw.data(), raw.size());
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (const auto b : raw) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xf]);
    }
    return out;
}

// The plaintexts a row protects, field by field (nullopt: the field is NULL).
using Values = std::vector<std::optional<std::string>>;
using Expected = std::map<unsigned int, Values>;

struct StoredRow {
    unsigned int id{}, master{};
    bool next{false}, prev{false};
};

const char* tableOf(const Slot slot) { return slot == Slot::ApiKeyMaster ? "api_keys" : "s3_gateway_credentials"; }

class MasterSecretRotationBase : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::string skipWhy;
    inline static UserPtr superUser;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static std::filesystem::path root;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            skipWhy = "Skipping db tests due to missing environment variables.";
            std::cout << "[test_master_secret_rotation] " << skipWhy << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_secret_rotation_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        // Real sealing is the point of these tests; a backend that can't unseal what it seals (CI's container TPM)
        // skips them.
        try {
            std::vector<uint8_t> first;
            {
                crypto::secrets::KeyProvider probe("test_rotation_probe");
                probe.init();
                first.assign(probe.getMasterKey().begin(), probe.getMasterKey().end());
            }
            crypto::secrets::KeyProvider again("test_rotation_probe");
            again.init();
            if (!std::ranges::equal(again.getMasterKey(), first)) throw std::runtime_error("a different secret");
        } catch (const std::exception& e) {
            skipTests = true;
            skipWhy = std::string("sealing doesn't round-trip on this host: ") + e.what();
            return;
        }

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        vs::resetForTesting();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        superUser = identities::manager().userByName("admin");

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerSecretsCommands(router);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        rw::setCrashHookForTesting(nullptr);
        vh::device::setIdentityRotationHookForTesting(nullptr);
        vs::resetForTesting();
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << skipWhy;
        rw::setCrashHookForTesting(nullptr);
        // Every test starts with no rotation in progress on any slot.
        for (const auto slot : vs::kSlots) {
            const auto st = rw::state(slot);
            if (st.previous_version) (void)rw::finalize(slot);
            else if (st.staging_version) (void)rw::rollback(slot);
        }
    }

    void TearDown() override { rw::setCrashHookForTesting(nullptr); }

    static UserPtr createUser(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + tag(), .role = role,
                                                            .password = std::string("Secret-Rotation-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    static protocols::shell::CommandResult cli(const std::string& line, const UserPtr& user) {
        return router->executeLine(line, user, nullptr);
    }

    static long long auditCount(const std::string& action, const std::string& outcome,
                                const std::optional<std::string>& slot = std::nullopt) {
        (void)audit::Trail::instance()->flushNow();
        return db::Transactions::exec("rotationTest::audit", [&](pqxx::work& txn) {
            if (slot)
                return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = $1 AND outcome = $2 AND "
                                "details::jsonb->>'slot' = $3",
                                pqxx::params{action, outcome, *slot})
                    .one_field_ref()
                    .as<long long>();
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = $1 AND outcome = $2",
                            pqxx::params{action, outcome})
                .one_field_ref()
                .as<long long>();
        });
    }

    // A crash hook that throws at the n-th time `point` is reached (1-based).
    static rw::CrashHook crashAt(const std::string& point, const int n = 1) {
        auto seen = std::make_shared<int>(0);
        return [point, n, seen](const std::string_view p) {
            if (p == point && ++*seen == n) throw SimulatedCrash();
        };
    }

    static bool slotOnHost(const Slot slot, const unsigned int version) {
        return crypto::secrets::KeyProvider(vs::slotName(slot, version)).sealedExists();
    }
};

// ---- ak_master and s3gw_master: the staged rewrap ------------------------------------------------------------------

class WrappingMasterRotationTest : public MasterSecretRotationBase, public ::testing::WithParamInterface<Slot> {
protected:
    [[nodiscard]] static Slot slot() { return GetParam(); }
    [[nodiscard]] static const char* table() { return tableOf(slot()); }

    // A new protected row (an API key, with a provider token when `token`; or a gateway credential), and what it holds.
    static unsigned int addRow(Expected& expected, const bool token = true) {
        if (slot() == Slot::ApiKeyMaster) {
            auto key = std::make_shared<vault::model::APIKey>(superUser->id, "ak_" + tag(),
                                                              vault::model::S3Provider::CloudflareR2, "AKID" + tag(),
                                                              "secret-" + randomHex(16), "auto",
                                                              "https://example.r2.cloudflarestorage.com");
            const auto secret = key->secret_access_key;
            const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
            std::optional<std::string> tok;
            if (token) {
                tok = "token-" + randomHex(20);
                runtime::Deps::get().apiKeyManager->setProviderToken(id, *tok);
            }
            expected[id] = {secret, tok};
            return id;
        }
        const auto created = protocols::s3::CredentialManager{}.createCredential(superUser->id, "gw_" + tag());
        expected[created.credential.id] = {created.secret_access_key};
        return created.credential.id;
    }

    static Expected world() {
        Expected expected;
        (void)addRow(expected, true);
        (void)addRow(expected, false);
        (void)addRow(expected, true);
        (void)addRow(expected, true);
        return expected;
    }

    // What the consumer of the secrets reads for row `id`, after a process restart (masters unsealed afresh).
    static Values read(const unsigned int id) {
        if (slot() == Slot::ApiKeyMaster) {
            const auto key = runtime::Deps::get().apiKeyManager->getAPIKey(id);
            return {key->secret_access_key,
                    key->provider_token.empty() ? std::nullopt : std::optional<std::string>(key->provider_token)};
        }
        const auto accessKey = db::Transactions::exec("rotationTest::accessKey", [&](pqxx::work& txn) {
            return txn.exec("SELECT access_key FROM s3_gateway_credentials WHERE id = $1", pqxx::params{id})
                .one_field_ref()
                .as<std::string>();
        });
        const auto secret = protocols::s3::CredentialManager{}.findEnabledSecret(accessKey);
        if (!secret) throw std::runtime_error("credential not found");
        return {secret->secret_access_key};
    }

    static std::vector<StoredRow> storedRows() {
        return db::Transactions::exec("rotationTest::rows", [](pqxx::work& txn) {
            std::vector<StoredRow> out;
            for (const auto& r : txn.exec(std::string("SELECT id, master_version, master_version_next IS NOT NULL, "
                                                      "master_version_prev IS NOT NULL FROM ") +
                                          table() + " ORDER BY id"))
                out.push_back({.id = r[0].as<unsigned int>(), .master = r[1].as<unsigned int>(),
                               .next = r[2].as<bool>(), .prev = r[3].as<bool>()});
            return out;
        });
    }

    static unsigned int countMaster(const unsigned int version) {
        unsigned int n = 0;
        for (const auto& row : storedRows()) n += row.master == version ? 1 : 0;
        return n;
    }

    // The proof after every step: every row names the current master, and the consumer reads exactly what it stored.
    static void expectEveryRowReadable(const Expected& expected, const std::string& where) {
        vs::resetForTesting();  // a crashed process unseals from scratch
        const auto current = rw::state(slot()).version;
        for (const auto& row : storedRows()) {
            EXPECT_EQ(row.master, current) << where << ": row " << row.id;
            const auto it = expected.find(row.id);
            if (it == expected.end()) continue;
            try {
                EXPECT_EQ(read(row.id), it->second) << where << ": row " << row.id << " changed";
            } catch (const std::exception& e) {
                ADD_FAILURE() << where << ": row " << row.id << " does not read: " << e.what();
            }
        }
    }

    static std::string slotFlag() { return std::string(" --slot ") + std::string(vs::cliName(slot())); }
};

INSTANTIATE_TEST_SUITE_P(Slots, WrappingMasterRotationTest,
                         ::testing::Values(Slot::ApiKeyMaster, Slot::GatewayMaster),
                         [](const ::testing::TestParamInfo<Slot>& info) {
                             return info.param == Slot::ApiKeyMaster ? std::string("ak_master")
                                                                     : std::string("s3gw_master");
                         });

TEST_P(WrappingMasterRotationTest, RowsStartOnTheCurrentVersionAndTheGuardRefusesAnotherMaster) {
    Expected expected;
    const auto id = addRow(expected);
    const auto st = rw::state(slot());
    for (const auto& row : storedRows())
        if (row.id == id) {
            EXPECT_EQ(row.master, st.version);
        }

    // A row declaring a master other than the current one is refused: nothing would unwrap it after a window.
    EXPECT_ANY_THROW(db::Transactions::exec("rotationTest::stale", [&](pqxx::work& txn) {
        txn.exec(std::string("UPDATE ") + table() + " SET master_version = $2 WHERE id = $1",
                 pqxx::params{id, st.version + 7});
    }));
    // Unchanged bytes keep the staged and retained wraps; a change of the wrapped bytes drops them.
    db::Transactions::exec("rotationTest::stage", [&](pqxx::work& txn) {
        txn.exec(std::string("UPDATE ") + table() +
                     " SET encrypted_secret_access_key_next = encrypted_secret_access_key, iv_next = iv, "
                     "master_version_next = 99, encrypted_secret_access_key_prev = encrypted_secret_access_key, "
                     "iv_prev = iv, master_version_prev = 98 WHERE id = $1",
                 pqxx::params{id});
        txn.exec(std::string("UPDATE ") + table() + " SET iv = iv, name = name || 'x' WHERE id = $1",
                 pqxx::params{id});
    });
    auto mine = [&] {
        for (const auto& r : storedRows())
            if (r.id == id) return r;
        return StoredRow{};
    };
    EXPECT_TRUE(mine().next);
    EXPECT_TRUE(mine().prev);
    db::Transactions::exec("rotationTest::rewrite", [&](pqxx::work& txn) {
        txn.exec(std::string("UPDATE ") + table() + " SET iv = $2 WHERE id = $1",
                 pqxx::params{id, db::encoding::to_hex_bytea(std::vector<uint8_t>(12, 7))});
    });
    EXPECT_FALSE(mine().next);
    EXPECT_FALSE(mine().prev);
    db::Transactions::exec("rotationTest::cleanup", [&](pqxx::work& txn) {
        txn.exec(std::string("DELETE FROM ") + table() + " WHERE id = $1", pqxx::params{id});
    });
}

TEST_P(WrappingMasterRotationTest, RotateRewrapsEveryRowWithoutChangingAValue) {
    const auto expected = world();
    const auto from = rw::state(slot()).version;

    const auto r = rw::rotate(slot(), {.window = std::chrono::hours(1), .batch = 2});
    EXPECT_EQ(r.from, from);
    EXPECT_GT(r.to, from);
    EXPECT_EQ(r.to, rw::state(slot()).version);
    EXPECT_EQ(r.rows, storedRows().size());
    EXPECT_GE(r.batches, 2u);
    EXPECT_EQ(countMaster(r.to), storedRows().size());
    for (const auto& row : storedRows()) {
        EXPECT_TRUE(row.prev) << row.id;  // retained for the window
        EXPECT_FALSE(row.next) << row.id;
    }
    EXPECT_TRUE(slotOnHost(slot(), from));
    EXPECT_TRUE(slotOnHost(slot(), r.to));
    expectEveryRowReadable(expected, "after the switch");

    // The other masters are untouched.
    for (const auto other : vs::kSlots)
        if (other != slot()) {
            EXPECT_FALSE(rw::state(other).previous_version) << vs::id(other);
        }

    try {
        (void)rw::rotate(slot());
        ADD_FAILURE() << "a rotation inside the window must be refused";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "window_open");
    }

    const auto f = rw::finalize(slot());
    EXPECT_TRUE(f.finalized);
    EXPECT_EQ(f.deleted, std::vector<unsigned int>{from});
    EXPECT_FALSE(slotOnHost(slot(), from));
    for (const auto& row : storedRows()) EXPECT_FALSE(row.prev);
    expectEveryRowReadable(expected, "after finalize");
    EXPECT_FALSE(rw::finalize(slot()).finalized);
}

TEST_P(WrappingMasterRotationTest, AnInterruptedStagingResumesAtEveryBatchBoundary) {
    const auto expected = world();
    const auto from = rw::state(slot()).version;

    for (const auto* point : {"staging_recorded", "sealed"}) {
        rw::setCrashHookForTesting(crashAt(point));
        EXPECT_THROW((void)rw::rotate(slot(), {.batch = 1}), SimulatedCrash) << point;
        rw::setCrashHookForTesting(nullptr);
        EXPECT_EQ(rw::state(slot()).version, from) << point;
        ASSERT_TRUE(rw::state(slot()).staging_version) << point;
        expectEveryRowReadable(expected, point);
    }

    const auto target = *rw::state(slot()).staging_version;
    unsigned int crashes = 0, lastStaged = 0;
    for (;;) {
        rw::setCrashHookForTesting(crashAt("batch"));
        try {
            (void)rw::rotate(slot(), {.batch = 1});
            ADD_FAILURE() << "every batch is a crash point";
            break;
        } catch (const SimulatedCrash&) {
        }
        rw::setCrashHookForTesting(nullptr);
        ++crashes;
        const auto s = rw::status(slot());
        EXPECT_EQ(s.state.version, from);
        EXPECT_EQ(s.state.staging_version, target) << "a resumed staging keeps its master";
        EXPECT_EQ(s.staged, lastStaged + 1) << "each batch commits exactly its row";
        lastStaged = s.staged;
        expectEveryRowReadable(expected, "after batch " + std::to_string(crashes));
        if (s.staged == s.rows) break;
        ASSERT_LT(crashes, 1000u);
    }
    EXPECT_EQ(crashes, storedRows().size());

    rw::setCrashHookForTesting(crashAt("verified"));
    EXPECT_THROW((void)rw::rotate(slot(), {.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    EXPECT_EQ(rw::state(slot()).version, from);
    expectEveryRowReadable(expected, "between verify and switch");

    rw::setCrashHookForTesting(crashAt("switched"));
    EXPECT_THROW((void)rw::rotate(slot(), {.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto st = rw::state(slot());
    EXPECT_EQ(st.version, target);
    EXPECT_EQ(st.previous_version, from);
    EXPECT_FALSE(st.staging_version);
    expectEveryRowReadable(expected, "after the switch");

    rw::setCrashHookForTesting(crashAt("finalize_committed"));
    EXPECT_THROW((void)rw::finalize(slot()), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    EXPECT_FALSE(rw::state(slot()).previous_version);
    EXPECT_EQ(rw::state(slot()).discard_versions, std::vector<unsigned int>{from});
    EXPECT_TRUE(slotOnHost(slot(), from));
    expectEveryRowReadable(expected, "after an interrupted finalize");
    EXPECT_EQ(rw::finalize(slot()).deleted, std::vector<unsigned int>{from});
    EXPECT_FALSE(slotOnHost(slot(), from));
    expectEveryRowReadable(expected, "after finalize");
}

TEST_P(WrappingMasterRotationTest, WritesDuringStagingAreCaughtUpAtTheSwitch) {
    auto expected = world();
    const auto from = rw::state(slot()).version;
    const auto changed = expected.begin()->first;
    auto once = std::make_shared<bool>(false);
    rw::setCrashHookForTesting([&, once](const std::string_view point) {
        if (point != "verified" || *once) return;
        *once = true;
        // A new row, and (API keys) a provider token replaced on a staged row: both under the current master.
        (void)addRow(expected);
        if (slot() == Slot::ApiKeyMaster) {
            const std::string token = "replaced-" + randomHex(8);
            runtime::Deps::get().apiKeyManager->setProviderToken(changed, token);
            expected[changed][1] = token;
        }
        for (const auto& row : storedRows()) EXPECT_EQ(row.master, from) << "rows written meanwhile use the current";
    });
    const auto r = rw::rotate(slot());
    rw::setCrashHookForTesting(nullptr);
    EXPECT_GE(r.caught_up, slot() == Slot::ApiKeyMaster ? 2u : 1u);
    expectEveryRowReadable(expected, "after a switch with catch-up");
    (void)rw::finalize(slot());
    expectEveryRowReadable(expected, "after finalize");
}

TEST_P(WrappingMasterRotationTest, AStagedWrapThatIsNotTheRowsSecretAbortsBeforeTheSwitch) {
    const auto expected = world();
    rw::setCrashHookForTesting(crashAt("verified"));
    EXPECT_THROW((void)rw::rotate(slot()), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto from = rw::state(slot()).version;
    const auto target = *rw::state(slot()).staging_version;

    const std::string other = "not-the-secret";
    std::vector<uint8_t> iv;
    const auto forged =
        crypto::util::encrypt_aes256_gcm(crypto::viewBytes(other), vs::provider(slot(), target)->getMasterKey(), iv);
    db::Transactions::exec("rotationTest::forge", [&](pqxx::work& txn) {
        txn.exec(std::string("UPDATE ") + table() +
                     " SET encrypted_secret_access_key_next = $2, iv_next = $3 WHERE id = $1",
                 pqxx::params{expected.begin()->first, db::encoding::to_hex_bytea(forged),
                              db::encoding::to_hex_bytea(iv)});
    });
    try {
        (void)rw::rotate(slot());
        ADD_FAILURE() << "a staged wrap of another secret must abort the rotation";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "mismatch") << e.what();
    }
    EXPECT_EQ(rw::state(slot()).version, from) << "nothing switched";
    expectEveryRowReadable(expected, "after a mismatch");

    const auto r = rw::rotate(slot());
    EXPECT_EQ(r.to, target);
    expectEveryRowReadable(expected, "after the retry");
}

TEST_P(WrappingMasterRotationTest, AStagedMasterReplacedByAnotherSecretNeverSwitches) {
    const auto expected = world();
    rw::setCrashHookForTesting(crashAt("verified"));
    EXPECT_THROW((void)rw::rotate(slot()), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto from = rw::state(slot()).version;
    const auto target = *rw::state(slot()).staging_version;
    {
        crypto::secrets::KeyProvider staged(vs::slotName(slot(), target));
        staged.destroySealed();
        staged.init();
    }
    vs::resetForTesting();
    try {
        (void)rw::rotate(slot());
        ADD_FAILURE() << "wraps under another master must abort the rotation";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "mismatch") << e.what();
    }
    EXPECT_EQ(rw::state(slot()).version, from);
    expectEveryRowReadable(expected, "after an old/new master mismatch");
    EXPECT_EQ(rw::rotate(slot()).to, target);
    expectEveryRowReadable(expected, "after restaging");
}

TEST_P(WrappingMasterRotationTest, ARowThatDoesNotUnwrapRefusesBeforeAnythingIsSealed) {
    Expected expected;
    const auto id = addRow(expected);
    const auto st = rw::state(slot());
    const auto original = db::Transactions::exec("rotationTest::orig", [&](pqxx::work& txn) {
        return txn.exec(std::string("SELECT encrypted_secret_access_key FROM ") + table() + " WHERE id = $1",
                        pqxx::params{id})
            .one_field_ref()
            .as<std::string>();
    });
    db::Transactions::exec("rotationTest::junk", [&](pqxx::work& txn) {
        txn.exec(std::string("UPDATE ") + table() + " SET encrypted_secret_access_key = $2 WHERE id = $1",
                 pqxx::params{id, db::encoding::to_hex_bytea(std::vector<uint8_t>(48, 3))});
    });
    try {
        (void)rw::rotate(slot());
        ADD_FAILURE() << "an unreadable row must refuse the rotation";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "unreadable_rows");
        EXPECT_NE(std::string(e.what()).find(slot() == Slot::ApiKeyMaster ? "api-key" : "credential"),
                  std::string::npos)
            << e.what();
    }
    const auto after = rw::state(slot());
    EXPECT_EQ(after.version, st.version);
    EXPECT_FALSE(after.staging_version);
    EXPECT_EQ(after.highest_version, st.highest_version) << "no version number consumed";
    EXPECT_FALSE(slotOnHost(slot(), st.highest_version + 1)) << "nothing was sealed";
    db::Transactions::exec("rotationTest::restore", [&](pqxx::work& txn) {
        txn.exec(std::string("UPDATE ") + table() + " SET encrypted_secret_access_key = $2::bytea WHERE id = $1",
                 pqxx::params{id, original});
    });
    expectEveryRowReadable(expected, "restored");
}

TEST_P(WrappingMasterRotationTest, TpmLossMidStagingRestagesUnderAFreshMaster) {
    const auto expected = world();
    rw::setCrashHookForTesting(crashAt("batch", 2));
    EXPECT_THROW((void)rw::rotate(slot(), {.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto target = *rw::state(slot()).staging_version;
    EXPECT_GT(rw::status(slot()).staged, 0u);

    crypto::secrets::KeyProvider(vs::slotName(slot(), target)).destroySealed();
    vs::resetForTesting();
    const auto r = rw::rotate(slot());
    EXPECT_EQ(r.to, target);
    EXPECT_EQ(r.staged_now, storedRows().size()) << "every row is staged again under the new secret";
    expectEveryRowReadable(expected, "after restaging");
}

TEST_P(WrappingMasterRotationTest, TpmLossMidWindowRollsBackFromTheRetainedWraps) {
    const auto expected = world();
    const auto r = rw::rotate(slot());

    // The new master is lost inside the window: nothing regenerates it, and the error says how back.
    crypto::secrets::KeyProvider(vs::slotName(slot(), r.to)).destroySealed();
    vs::resetForTesting();
    try {
        (void)read(expected.begin()->first);
        ADD_FAILURE() << "a lost current master must not be regenerated";
    } catch (const crypto::secrets::MasterSecretLost& e) {
        EXPECT_NE(std::string(e.what()).find("vh secret master rollback" + slotFlag()), std::string::npos) << e.what();
    }
    try {
        if (slot() == Slot::ApiKeyMaster) {
            const vault::APIKeyManager probe;
        } else {
            const protocols::s3::CredentialManager probe;
        }
        ADD_FAILURE() << "a manager must refuse to start without its current master";
    } catch (const crypto::secrets::MasterSecretLost&) {
    }
    EXPECT_FALSE(slotOnHost(slot(), r.to)) << "nothing was sealed in its place";
    try {
        (void)rw::finalize(slot());
        ADD_FAILURE() << "finalize without the current master must be refused";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "verification_failed");
    }
    EXPECT_TRUE(slotOnHost(slot(), r.from));

    const auto back = rw::rollback(slot());
    EXPECT_EQ(back.kind, rw::RollbackResult::Kind::Reverted);
    EXPECT_EQ(back.to, r.from);
    EXPECT_EQ(back.rows, storedRows().size());
    EXPECT_EQ(back.rewrapped, 0u);
    EXPECT_EQ(rw::state(slot()).version, r.from);
    expectEveryRowReadable(expected, "after the rollback");
}

TEST_P(WrappingMasterRotationTest, RollbackInsideTheWindowRewrapsWhatChangedDuringIt) {
    auto expected = world();
    const auto r = rw::rotate(slot());
    // During the window: a new row (wrapped under the new master, nothing retained) and, for API keys, a token change.
    (void)addRow(expected);
    if (slot() == Slot::ApiKeyMaster) {
        const auto id = expected.begin()->first;
        const std::string token = "window-" + randomHex(8);
        runtime::Deps::get().apiKeyManager->setProviderToken(id, token);
        expected[id][1] = token;
    }
    const auto rows = storedRows().size();

    rw::setCrashHookForTesting(crashAt("rollback_committed"));
    EXPECT_THROW((void)rw::rollback(slot()), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto st = rw::state(slot());
    EXPECT_EQ(st.version, r.from);
    EXPECT_FALSE(st.previous_version);
    EXPECT_EQ(st.discard_versions, std::vector<unsigned int>{r.to});
    expectEveryRowReadable(expected, "after an interrupted rollback");
    EXPECT_EQ(countMaster(r.from), rows);
    EXPECT_EQ(rw::finalize(slot()).deleted, std::vector<unsigned int>{r.to});
    EXPECT_FALSE(slotOnHost(slot(), r.to));
    expectEveryRowReadable(expected, "after the rollback");

    const auto again = rw::rotate(slot());
    EXPECT_GT(again.to, r.to) << "a version number is never reused";
    expectEveryRowReadable(expected, "after another rotation");
    (void)rw::finalize(slot());
}

TEST_P(WrappingMasterRotationTest, RollbackWhileStagingAbandonsIt) {
    const auto expected = world();
    const auto from = rw::state(slot()).version;
    rw::setCrashHookForTesting(crashAt("batch"));
    EXPECT_THROW((void)rw::rotate(slot(), {.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto target = *rw::state(slot()).staging_version;

    const auto r = rw::rollback(slot());
    EXPECT_EQ(r.kind, rw::RollbackResult::Kind::AbandonedStaging);
    EXPECT_EQ(r.from, target);
    EXPECT_FALSE(rw::state(slot()).staging_version);
    EXPECT_EQ(rw::state(slot()).version, from);
    EXPECT_FALSE(slotOnHost(slot(), target));
    for (const auto& row : storedRows()) EXPECT_FALSE(row.next);
    expectEveryRowReadable(expected, "after abandoning");
    try {
        (void)rw::rollback(slot());
        ADD_FAILURE() << "nothing left to roll back";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "no_window");
    }
}

TEST_P(WrappingMasterRotationTest, TheWindowEndsByItselfWhenItExpires) {
    const auto expected = world();
    const auto r = rw::rotate(slot(), {.window = std::chrono::hours(2)});
    rw::expireAllIfDue(std::chrono::system_clock::now());
    EXPECT_TRUE(rw::state(slot()).previous_version) << "not due yet";
    rw::expireAllIfDue(std::chrono::system_clock::now() + std::chrono::hours(3));
    EXPECT_FALSE(rw::state(slot()).previous_version);
    EXPECT_FALSE(slotOnHost(slot(), r.from));
    expectEveryRowReadable(expected, "after expiry");
}

TEST_P(WrappingMasterRotationTest, TheCliIsSuperAdminOnlyConfirmsAndAuditsEveryStep) {
    const auto expected = world();
    const auto id = std::string(vs::id(slot()));
    const auto admin = createUser("rotadm", "admin");
    const auto deniedBefore = auditCount("secrets.master.rotate", "denied", id);
    EXPECT_NE(cli("secret master status" + slotFlag(), admin).exit_code, 0);
    EXPECT_NE(cli("secret master rotate --yes" + slotFlag(), admin).exit_code, 0);
    EXPECT_GT(auditCount("secrets.master.rotate", "denied", id), deniedBefore);

    const auto s = cli("secret master status --json" + slotFlag(), superUser);
    ASSERT_EQ(s.exit_code, 0) << s.stderr_text << s.stdout_text;
    const auto status = json::parse(s.stdout_text);
    EXPECT_EQ(status.at("slot"), id);
    EXPECT_EQ(status.at("phase"), "idle");
    EXPECT_EQ(status.at("rows").get<unsigned>(), storedRows().size());
    const auto all = json::parse(cli("secret master status --slot all --json", superUser).stdout_text);
    EXPECT_TRUE(all.contains("vault_master") && all.contains("ak_master") && all.contains("s3gw_master")) << all;
    EXPECT_NE(cli("secret master rotate --slot nope --yes", superUser).exit_code, 0);

    const auto from = rw::state(slot()).version;
    const auto refused = cli("secret master rotate" + slotFlag(), superUser);
    EXPECT_NE(refused.exit_code, 0);
    ASSERT_TRUE(refused.confirmation);
    EXPECT_EQ(refused.confirmation->code, id + "_rotate");
    EXPECT_EQ(rw::state(slot()).version, from);
    {
        const protocols::shell::AgentCallScope agent;
        EXPECT_NE(cli("secret master rotate --yes" + slotFlag(), superUser).exit_code, 0);
    }
    EXPECT_EQ(rw::state(slot()).version, from);

    const auto okBefore = auditCount("secrets.master.rotate", "success", id);
    const auto rotated = cli("secret master rotate --yes --window-hours 24 --json" + slotFlag(), superUser);
    ASSERT_EQ(rotated.exit_code, 0) << rotated.stderr_text << rotated.stdout_text;
    EXPECT_EQ(json::parse(rotated.stdout_text).at("from").get<unsigned>(), from);
    EXPECT_EQ(auditCount("secrets.master.rotate", "success", id), okBefore + 1);
    EXPECT_FALSE(rw::state(Slot::VaultMaster).previous_version) << "only the named slot rotated";
    EXPECT_EQ(json::parse(cli("secret master status --json" + slotFlag(), superUser).stdout_text).at("phase"),
              "recovery_window");

    const auto rb = cli("secret master rollback --yes" + slotFlag(), superUser);
    ASSERT_EQ(rb.exit_code, 0) << rb.stderr_text << rb.stdout_text;
    EXPECT_EQ(rw::state(slot()).version, from);
    EXPECT_GE(auditCount("secrets.master.rollback", "success", id), 1);
    EXPECT_NE(cli("secret master rollback --yes" + slotFlag(), superUser).exit_code, 0);
    EXPECT_GE(auditCount("secrets.master.rollback", "failure", id), 1);

    ASSERT_EQ(cli("secret master rotate --yes" + slotFlag(), superUser).exit_code, 0);
    const auto fin = cli("secret master finalize --yes" + slotFlag(), superUser);
    ASSERT_EQ(fin.exit_code, 0) << fin.stderr_text << fin.stdout_text;
    EXPECT_GE(auditCount("secrets.master.finalize", "success", id), 1);
    expectEveryRowReadable(expected, "after the CLI round trip");
}

// ---- the JWT secret --------------------------------------------------------------------------------------------

class JwtSecretRotationTest : public MasterSecretRotationBase {
protected:
    static std::string sign(const std::string& secret) {
        const auto now = std::chrono::system_clock::now();
        return jwt::create<jwt::traits::nlohmann_json>()
            .set_issuer("Vaulthalla")
            .set_subject("rotation-test")
            .set_issued_at(now)
            .set_expires_at(now + std::chrono::hours(1))
            .set_id(randomHex(16))
            .sign(jwt::algorithm::hs256{secret});
    }

    static long long liveRefreshTokens() {
        return db::Transactions::exec("rotationTest::live", [](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM refresh_tokens WHERE revoked IS NOT TRUE")
                .one_field_ref()
                .as<long long>();
        });
    }
};

TEST_F(JwtSecretRotationTest, EveryoneSignsInAgainAndNothingElseChanges) {
    auth::session::Issuer::clearJwtSecretForTesting();
    const auto& deps = runtime::Deps::get();
    const auto old = deps.secretsManager->jwtSecret();
    const auto oldToken = sign(old);
    ASSERT_TRUE(auth::session::Issuer::decode(oldToken));

    // Two stored sessions, one live socket, and another internal secret under the same host master.
    db::Transactions::exec("rotationTest::sessions", [&](pqxx::work& txn) {
        for (int i = 0; i < 2; ++i)
            txn.exec("INSERT INTO refresh_tokens (jti, user_id, token_hash) VALUES (gen_random_uuid(), $1, $2)",
                     pqxx::params{superUser->id, randomHex(32)});
    });
    ASSERT_GE(liveRefreshTokens(), 2);
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spkiHex = randomHex(32);
    peer->address = "127.0.0.1";
    peer->deviceRowId = 1;
    const auto live = protocols::ws::Session::devicePrincipal(peer, superUser, {});
    deps.sessionManager->cache(live);
    ASSERT_TRUE(deps.sessionManager->getActive().contains(live->uuid));
    deps.secretsManager->setSecret("rotation_test_other", "stays");

    // Super admins only (audited), confirmation, never an agent.
    const auto admin = createUser("jwtadm", "admin");
    const auto deniedBefore = auditCount("secrets.jwt.rotate", "denied");
    EXPECT_NE(cli("secret jwt rotate --yes", admin).exit_code, 0);
    EXPECT_GT(auditCount("secrets.jwt.rotate", "denied"), deniedBefore);
    const auto refused = cli("secret jwt rotate", superUser);
    EXPECT_NE(refused.exit_code, 0);
    ASSERT_TRUE(refused.confirmation);
    EXPECT_EQ(refused.confirmation->code, "jwt_secret_rotate");
    {
        const protocols::shell::AgentCallScope agent;
        EXPECT_NE(cli("secret jwt rotate --yes", superUser).exit_code, 0);
    }
    EXPECT_EQ(deps.secretsManager->jwtSecret(), old) << "nothing changed before the confirmation";
    EXPECT_GE(liveRefreshTokens(), 2);

    const auto okBefore = auditCount("secrets.jwt.rotate", "success");
    const auto rotated = cli("secret jwt rotate --yes --json", superUser);
    ASSERT_EQ(rotated.exit_code, 0) << rotated.stderr_text << rotated.stdout_text;
    const auto out = json::parse(rotated.stdout_text);
    EXPECT_GE(out.at("refresh_tokens_revoked").get<long long>(), 2);
    EXPECT_GE(out.at("sessions_ended").get<long long>(), 1);
    EXPECT_EQ(auditCount("secrets.jwt.rotate", "success"), okBefore + 1);

    // Every stored session is revoked, every token signed before stops verifying, the live socket is gone.
    EXPECT_EQ(liveRefreshTokens(), 0);
    const auto fresh = deps.secretsManager->jwtSecret();
    EXPECT_NE(fresh, old);
    EXPECT_EQ(fresh.size(), old.size());
    EXPECT_FALSE(auth::session::Issuer::decode(oldToken)) << "a token signed with the old secret still verifies";
    EXPECT_TRUE(auth::session::Issuer::decode(sign(fresh)));
    EXPECT_FALSE(deps.sessionManager->getActive().contains(live->uuid));
    EXPECT_TRUE(live->closing());
    // The new secret is the stored one (a restart serves it), and the host master's other secrets are untouched.
    EXPECT_EQ(deps.secretsManager->getSecret("jwt_secret").value_or(""), fresh);
    EXPECT_EQ(deps.secretsManager->getSecret("rotation_test_other").value_or(""), "stays");
}

// ---- the device identity ----------------------------------------------------------------------------------------

namespace {
const char* identityCrashAt = nullptr;
void identityHook(const std::string_view point) {
    if (identityCrashAt && point == identityCrashAt) throw SimulatedCrash();
}
}

class DeviceIdentityRotationTest : public MasterSecretRotationBase {
protected:
    static unsigned int pairDevice() {
        return db::query::device::Devices::insert({.user_id = superUser->id, .approved_by = superUser->id,
                                                   .name = "dev " + tag(), .platform = "macOS",
                                                   .app_version = "1.0", .spki_sha256 = randomHex(32),
                                                   .last_ip = "127.0.0.1"})
            .id;
    }

    static std::size_t activeDevices() { return db::query::device::Devices::countActive(); }

    static void TearDownTestSuite() {
        identityCrashAt = nullptr;
        vh::device::setIdentityRotationHookForTesting(nullptr);
        vh::device::setCurrentServerIdentity(nullptr);
        MasterSecretRotationBase::TearDownTestSuite();
    }
};

TEST_F(DeviceIdentityRotationTest, ACrashOnEitherSideOfTheSwitchIsConsistent) {
    const auto first = vh::device::loadOrCreateServerIdentity();
    const auto v = vh::device::currentIdentityVersion();
    (void)pairDevice();
    (void)pairDevice();
    const auto active = activeDevices();
    ASSERT_GE(active, 2u);
    vh::device::setIdentityRotationHookForTesting(identityHook);

    // Sealed, not switched: still the old identity, no device revoked; the next start deletes the leftover key.
    identityCrashAt = "identity_sealed";
    EXPECT_THROW((void)vh::device::rotateServerIdentity(), SimulatedCrash);
    identityCrashAt = nullptr;
    EXPECT_EQ(vh::device::currentIdentityVersion(), v);
    EXPECT_EQ(activeDevices(), active);
    const auto leftover = db::Transactions::exec("rotationTest::highest", [](pqxx::work& txn) {
        return txn.exec("SELECT highest_version FROM master_secret_state WHERE slot = 'device_tls'")
            .one_field_ref()
            .as<unsigned int>();
    });
    EXPECT_TRUE(crypto::secrets::KeyProvider(vh::device::identitySlotName(leftover)).sealedExists());
    const auto reloaded = vh::device::loadOrCreateServerIdentity();
    EXPECT_EQ(reloaded->spkiHex(), first->spkiHex());
    EXPECT_FALSE(crypto::secrets::KeyProvider(vh::device::identitySlotName(leftover)).sealedExists());

    // Switched, the certificate not written yet: the new key, every device revoked, the certificate reissued on load.
    identityCrashAt = "identity_switched";
    EXPECT_THROW((void)vh::device::rotateServerIdentity(), SimulatedCrash);
    identityCrashAt = nullptr;
    const auto now = vh::device::currentIdentityVersion();
    EXPECT_GT(now, leftover) << "a version number is never reused";
    EXPECT_EQ(activeDevices(), 0u);
    const auto after = vh::device::loadOrCreateServerIdentity();
    EXPECT_NE(after->spkiHex(), first->spkiHex());
    EXPECT_FALSE(crypto::secrets::KeyProvider(vh::device::identitySlotName(v)).sealedExists()) << "old key deleted";
    EXPECT_EQ(vh::device::loadOrCreateServerIdentity()->spkiHex(), after->spkiHex()) << "stable across restarts";
    vh::device::setIdentityRotationHookForTesting(nullptr);
}

TEST_F(DeviceIdentityRotationTest, EveryPairedDeviceIsRevokedAndPairsAgain) {
    const auto before = vh::device::loadOrCreateServerIdentity();
    vh::device::setCurrentServerIdentity(before);
    const auto v = vh::device::currentIdentityVersion();
    (void)pairDevice();
    (void)pairDevice();
    (void)pairDevice();
    ASSERT_GE(activeDevices(), 3u);
    auto& pairing = vh::device::Pairing::instance();
    pairing.resetForTesting();
    (void)pairing.open(superUser->id, vh::device::PairingClock::now());
    ASSERT_TRUE(pairing.window(vh::device::PairingClock::now()));

    const auto admin = createUser("devadm", "admin");
    const auto deniedBefore = auditCount("secrets.device_identity.rotate", "denied");
    EXPECT_NE(cli("secret device-identity rotate --yes", admin).exit_code, 0);
    EXPECT_GT(auditCount("secrets.device_identity.rotate", "denied"), deniedBefore);
    const auto refused = cli("secret device-identity rotate", superUser);
    EXPECT_NE(refused.exit_code, 0);
    ASSERT_TRUE(refused.confirmation);
    EXPECT_EQ(refused.confirmation->code, "device_identity_rotate");
    {
        const protocols::shell::AgentCallScope agent;
        EXPECT_NE(cli("secret device-identity rotate --yes", superUser).exit_code, 0);
    }
    EXPECT_EQ(vh::device::currentIdentityVersion(), v) << "nothing changed before the confirmation";
    EXPECT_GE(activeDevices(), 3u);

    const auto okBefore = auditCount("secrets.device_identity.rotate", "success");
    const auto rotated = cli("secret device-identity rotate --yes --json", superUser);
    ASSERT_EQ(rotated.exit_code, 0) << rotated.stderr_text << rotated.stdout_text;
    const auto out = json::parse(rotated.stdout_text);
    EXPECT_EQ(out.at("from").get<unsigned>(), v);
    EXPECT_GT(out.at("to").get<unsigned>(), v);
    EXPECT_EQ(out.at("previous_spki_sha256"), before->spkiHex());
    EXPECT_NE(out.at("spki_sha256"), before->spkiHex());
    EXPECT_GE(out.at("devices_revoked").get<unsigned>(), 3u);
    EXPECT_EQ(auditCount("secrets.device_identity.rotate", "success"), okBefore + 1);

    // No device is trusted under the new identity: every one was revoked, and pairing starts over.
    EXPECT_EQ(activeDevices(), 0u);
    EXPECT_FALSE(pairing.window(vh::device::PairingClock::now()));
    ASSERT_TRUE(vh::device::currentServerIdentity());
    EXPECT_EQ(vh::device::currentServerIdentity()->spkiHex(), out.at("spki_sha256").get<std::string>());
    // A restart loads exactly the new key and its certificate; the old key is gone.
    const auto reloaded = vh::device::loadOrCreateServerIdentity();
    EXPECT_EQ(reloaded->spkiHex(), out.at("spki_sha256").get<std::string>());
    EXPECT_FALSE(reloaded->certificateIsNew()) << "the rotation wrote the new certificate";
    EXPECT_FALSE(crypto::secrets::KeyProvider(vh::device::identitySlotName(v)).sealedExists());
    // A device paired after the rotation stays paired.
    (void)pairDevice();
    EXPECT_EQ(activeDevices(), 1u);
}

}
