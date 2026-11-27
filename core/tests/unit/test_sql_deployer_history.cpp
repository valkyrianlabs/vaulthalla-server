// Regression guard for migrations that were edited in place after shipping (P0: 1.5.x -> 1.6.x upgrades
// crash-looped on "Migration file was modified after being applied: 060_acl.sql").
//
// Non-DB tests always run. DB-backed tests need VH_TEST_DB_{USER,PASS,HOST,PORT,NAME} and run every scenario
// inside a transaction that is rolled back, so they leave the test database exactly as they found it (apart from
// bringing it up to the current schema once, which init_tables_if_not_exists() does in other suites too).

#include "seed/include/SqlDeployer.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/permission/vault/sync/Action.hpp"

#include <paths.h>
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace vh_sql_deployer_history_test {

namespace migseed = vh::db::seed;
namespace mfs = std::filesystem;

// The repo's deploy/psql (what test mode uses), without flipping global test-mode state for other suites.
mfs::path repoPsqlDir() { return VH_PSQL_TEST_SCHEMAS_PATH; }

std::string currentHash(const std::string& filename) {
    return migseed::sha256Hex(migseed::readFileToString(repoPsqlDir() / filename));
}

std::optional<std::string> env(const char* key) {
    if (const auto* v = std::getenv(key); v && *v) return std::string(v);
    return std::nullopt;
}

std::optional<std::string> testDbConnectionString() {
    const auto user = env("VH_TEST_DB_USER");
    const auto pass = env("VH_TEST_DB_PASS");
    const auto host = env("VH_TEST_DB_HOST");
    const auto port = env("VH_TEST_DB_PORT");
    const auto name = env("VH_TEST_DB_NAME");
    if (!user || !pass || !host || !port || !name) return std::nullopt;
    return "user=" + *user + " password=" + *pass + " host=" + *host + " port=" + *port + " dbname=" + *name;
}

std::vector<vh::rbac::role::Admin> builtInAdminRoles() {
    using vh::rbac::role::Admin;
    return {
        Admin::None(), Admin::Auditor(), Admin::Support(), Admin::IdentityAdmin(), Admin::PlatformOperator(),
        Admin::VaultAdmin(), Admin::SecurityAdmin(), Admin::OrgAdmin(), Admin::SuperAdmin(), Admin::KeyCustodian()
    };
}

bool columnExists(pqxx::work& txn, const std::string& table, const std::string& column) {
    return !txn.exec(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
        pqxx::params{table, column}
    ).empty();
}

std::string recordedHash(pqxx::work& txn, const std::string& filename) {
    return txn.exec("SELECT sha256 FROM schema_migrations WHERE filename = $1", pqxx::params{filename})
        .one_row_ref()[0].as<std::string>();
}

bool reconciled(const migseed::SqlDeployReport& r, const std::string& filename) {
    return std::ranges::any_of(r.reconciled, [&](const auto& m) { return m.filename == filename; });
}

bool applied(const migseed::SqlDeployReport& r, const std::string& filename) {
    return std::ranges::find(r.applied, filename) != r.applied.end();
}

// Helpers above and the tests below share this namespace (unity build: avoid clashing with other suites).

// ---------------------------------------------------------------------------------------------------------------
// Allowlist shape (no DB)
// ---------------------------------------------------------------------------------------------------------------

TEST(SqlDeployerHistory, AcceptsOnlyListedHistoricalChecksums) {
    EXPECT_TRUE(migseed::isAcceptedHistoricalChecksum(
        "060_acl.sql", "c154cd7e10f7931f29c12b9221c90f66d6b953cfb5e3dc15ea50f0940e5d4220"));
    EXPECT_TRUE(migseed::isAcceptedHistoricalChecksum(
        "020_vaults.sql", "64170212eb3f9fbe0f7c949791b953f0376a1f2bcf66b3dec7afc5db6325d570"));
    EXPECT_TRUE(migseed::isAcceptedHistoricalChecksum(
        "082_stats_metric_samples.sql", "720caaa27c0d51635fe3f459a8426f019d3f0dbdc0b7ae176d283309933a7f53"));

    // Hash belongs to 060, not 020: acceptance is per file.
    EXPECT_FALSE(migseed::isAcceptedHistoricalChecksum(
        "020_vaults.sql", "c154cd7e10f7931f29c12b9221c90f66d6b953cfb5e3dc15ea50f0940e5d4220"));
    EXPECT_FALSE(migseed::isAcceptedHistoricalChecksum("060_acl.sql", std::string(64, '0')));
    EXPECT_FALSE(migseed::isAcceptedHistoricalChecksum("060_acl.sql", ""));
}

TEST(SqlDeployerHistory, EveryEntryNamesAnExistingFileAndForwardMigration) {
    for (const auto& e : migseed::kHistoricalMigrationChecksums) {
        const std::string filename{e.filename};
        SCOPED_TRACE(filename);

        ASSERT_TRUE(mfs::exists(repoPsqlDir() / filename));
        EXPECT_EQ(e.sha256.size(), 64u);
        EXPECT_NE(std::string(e.sha256), currentHash(filename))
            << "a historical checksum must differ from the current file";

        const std::string note{e.note};
        const auto pos = note.find("forward: ");
        ASSERT_NE(pos, std::string::npos) << "note must name the forward migration that owns the delta";
        const auto start = pos + std::string("forward: ").size();
        const auto forward = note.substr(start, note.find(')', start) - start);
        EXPECT_TRUE(mfs::exists(repoPsqlDir() / forward)) << forward;
        EXPECT_GT(forward, filename) << "forward migration must sort after the edited file";
    }
}

// ---------------------------------------------------------------------------------------------------------------
// DB-backed upgrade simulations
// ---------------------------------------------------------------------------------------------------------------

class SqlDeployerHistoryDb : public ::testing::Test {
protected:
    inline static std::optional<std::string> conninfo;
    inline static std::string skipReason;

    static void SetUpTestSuite() {
        conninfo = testDbConnectionString();
        if (!conninfo) {
            skipReason = "VH_TEST_DB_* not set";
            return;
        }

        // Bring the test DB to the current schema (committed), exactly like init_tables_if_not_exists().
        pqxx::connection conn(*conninfo);
        pqxx::work txn(conn);
        migseed::SqlDeployer::ensureMigrationsTable(txn);
        migseed::SqlDeployer::applyDir(txn, repoPsqlDir());
        txn.commit();
    }

    void SetUp() override {
        if (!conninfo) GTEST_SKIP() << skipReason;
    }

    // Runs `fn` in a transaction that is always rolled back.
    static void inRolledBackTxn(const std::function<void(pqxx::work&)>& fn) {
        pqxx::connection conn(*conninfo);
        pqxx::work txn(conn);
        fn(txn);
        txn.abort();
    }
};

TEST_F(SqlDeployerHistoryDb, UpgradeFromPre160AclChecksumSucceedsAndAddsGatewayColumn) {
    inRolledBackTxn([](pqxx::work& txn) {
        const auto oldHash = std::string("c154cd7e10f7931f29c12b9221c90f66d6b953cfb5e3dc15ea50f0940e5d4220");

        // Recreate the state of a database initialized by <= 1.5.1: old 060 shape (no s3_gateway_permissions),
        // old 060 checksum recorded, 097 never applied, built-in admin roles seeded without gateway bits.
        txn.exec("ALTER TABLE admin_role DROP COLUMN s3_gateway_permissions");
        txn.exec("UPDATE schema_migrations SET sha256 = $1 WHERE filename = '060_acl.sql'", pqxx::params{oldHash});
        txn.exec("DELETE FROM schema_migrations WHERE filename = '097_admin_role_s3_gateway_permissions.sql'");

        for (const auto& role : builtInAdminRoles()) {
            txn.exec(R"SQL(
                INSERT INTO admin_role (name, description, identity_permissions, audit_permissions,
                                        settings_permissions, roles_permissions, vaults_permissions, keys_permissions)
                VALUES ($1, $2, $3::bit(32), $4::bit(8), $5::bit(64), $6::bit(16), $7::bit(32), $8::bit(32))
                ON CONFLICT (name) DO NOTHING
            )SQL", pqxx::params{
                role.name, role.description, role.identities.toBitString(), role.audits.toBitString(),
                role.settings.toBitString(), role.roles.toBitString(), role.vaults.toBitString(),
                role.keys.toBitString()
            });
        }
        txn.exec(R"SQL(
            INSERT INTO admin_role (name, description, identity_permissions, audit_permissions,
                                    settings_permissions, roles_permissions, vaults_permissions, keys_permissions)
            VALUES ('claude_test_custom_role', 'custom', B'0'::bit(32), B'0'::bit(8), B'0'::bit(64),
                    B'0'::bit(16), B'0'::bit(32), B'0'::bit(32))
        )SQL");
        ASSERT_FALSE(columnExists(txn, "admin_role", "s3_gateway_permissions"));

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));

        EXPECT_TRUE(reconciled(report, "060_acl.sql"));
        EXPECT_TRUE(applied(report, "097_admin_role_s3_gateway_permissions.sql"));
        EXPECT_FALSE(applied(report, "060_acl.sql")) << "060 must not be re-executed";
        EXPECT_EQ(recordedHash(txn, "060_acl.sql"), currentHash("060_acl.sql"));

        ASSERT_TRUE(columnExists(txn, "admin_role", "s3_gateway_permissions"));
        const auto col = txn.exec(R"SQL(
            SELECT data_type, character_maximum_length, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'admin_role'
              AND column_name = 's3_gateway_permissions'
        )SQL").one_row();
        EXPECT_EQ(col[0].as<std::string>(), "bit");
        EXPECT_EQ(col[1].as<int>(), 8);
        EXPECT_EQ(col[2].as<std::string>(), "NO");
        EXPECT_NE(col[3].as<std::string>().find("00000000"), std::string::npos);

        // Built-in templates get the same bits a fresh install seeds; custom roles stay least-privilege.
        for (const auto& role : builtInAdminRoles()) {
            SCOPED_TRACE(role.name);
            const auto bits = txn.exec("SELECT s3_gateway_permissions::text FROM admin_role WHERE name = $1",
                                       pqxx::params{role.name}).one_row_ref()[0].as<std::string>();
            EXPECT_EQ(bits, role.s3Gateway.toBitString());
        }
        EXPECT_EQ(txn.exec("SELECT s3_gateway_permissions::text FROM admin_role WHERE name = 'claude_test_custom_role'")
                      .one_row_ref()[0].as<std::string>(), "00000000");

        // Second run is a clean no-op with strict checks back in force.
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        EXPECT_TRUE(again.reconciled.empty());
    });
}

TEST_F(SqlDeployerHistoryDb, ForwardMigrationIsNoOpOnDatabasesThatRanNewAcl) {
    inRolledBackTxn([](pqxx::work& txn) {
        // A >= 1.6.0 database where an operator deliberately changed a built-in role's gateway bits.
        txn.exec(R"SQL(
            INSERT INTO admin_role (name, description, identity_permissions, audit_permissions,
                                    settings_permissions, roles_permissions, vaults_permissions, keys_permissions,
                                    s3_gateway_permissions)
            VALUES ('super_admin', 'x', B'0'::bit(32), B'0'::bit(8), B'0'::bit(64), B'0'::bit(16), B'0'::bit(32),
                    B'0'::bit(32), B'00000000')
            ON CONFLICT (name) DO UPDATE SET s3_gateway_permissions = B'00000000'
        )SQL");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '097_admin_role_s3_gateway_permissions.sql'");

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "097_admin_role_s3_gateway_permissions.sql"));
        EXPECT_TRUE(report.reconciled.empty());
        EXPECT_EQ(txn.exec("SELECT s3_gateway_permissions::text FROM admin_role WHERE name = 'super_admin'")
                      .one_row_ref()[0].as<std::string>(), "00000000");
    });
}

// #166: an upgraded database gets admin_role.stats_permissions with the same grants a fresh install seeds, and
// every role that passed the old isAdmin() stats gate keeps stats access.
TEST_F(SqlDeployerHistoryDb, StatsPermissionMigrationMatchesFreshSeedAndKeepsOldGateHolders) {
    inRolledBackTxn([](pqxx::work& txn) {
        // A <= 1.10.x database: no stats column, 105 never applied, no catalog row.
        txn.exec("ALTER TABLE admin_role DROP COLUMN stats_permissions");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '105_admin_stats_permission.sql'");
        txn.exec("DELETE FROM permission WHERE name = 'admin.stats.view' AND category = 'admin'");

        const auto upsert = [&](const std::string& name, const vh::rbac::role::Admin& bits) {
            txn.exec(R"SQL(
                INSERT INTO admin_role (name, description, identity_permissions, audit_permissions,
                                        settings_permissions, roles_permissions, vaults_permissions, keys_permissions,
                                        s3_gateway_permissions)
                VALUES ($1, 'x', $2::bit(32), $3::bit(8), $4::bit(64), $5::bit(16), $6::bit(32), $7::bit(32), $8::bit(8))
                ON CONFLICT (name) DO UPDATE SET
                    identity_permissions = EXCLUDED.identity_permissions, audit_permissions = EXCLUDED.audit_permissions,
                    settings_permissions = EXCLUDED.settings_permissions, roles_permissions = EXCLUDED.roles_permissions,
                    vaults_permissions = EXCLUDED.vaults_permissions, keys_permissions = EXCLUDED.keys_permissions,
                    s3_gateway_permissions = EXCLUDED.s3_gateway_permissions
            )SQL", pqxx::params{
                name, bits.identities.toBitString(), bits.audits.toBitString(), bits.settings.toBitString(),
                bits.roles.toBitString(), bits.vaults.toBitString(), bits.keys.toBitString(),
                bits.s3Gateway.toBitString()
            });
        };
        for (const auto& role : builtInAdminRoles()) upsert(role.name, role);

        // The old gate: admin.identities.admins.delete AND admin.vaults.admin.remove. The migration reads those two
        // bits by position, so build them from the permission model rather than hard-coding them here.
        vh::rbac::role::Admin oldGate;
        oldGate.identities.admins.grant(vh::rbac::permission::admin::identities::IdentityPermissions::Delete);
        oldGate.vaults.admin.grant(vh::rbac::permission::admin::VaultPermissions::Remove);
        upsert("claude_test_old_gate_role", oldGate);
        vh::rbac::role::Admin halfGate;
        halfGate.identities.admins.grant(vh::rbac::permission::admin::identities::IdentityPermissions::Delete);
        upsert("claude_test_half_gate_role", halfGate);
        upsert("claude_test_plain_role", vh::rbac::role::Admin{});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "105_admin_stats_permission.sql"));

        const auto bitsOf = [&](const std::string& name) {
            return txn.exec("SELECT stats_permissions::text FROM admin_role WHERE name = $1", pqxx::params{name})
                .one_row_ref()[0].as<std::string>();
        };
        for (const auto& role : builtInAdminRoles()) {
            SCOPED_TRACE(role.name);
            EXPECT_EQ(bitsOf(role.name), role.stats.toBitString()) << "migration and fresh seed disagree";
        }
        EXPECT_EQ(bitsOf("claude_test_old_gate_role"), "00000001");
        EXPECT_EQ(bitsOf("claude_test_half_gate_role"), "00000000");
        EXPECT_EQ(bitsOf("claude_test_plain_role"), "00000000");

        const auto catalog = txn.exec(
            "SELECT bit_position FROM permission WHERE name = 'admin.stats.view' AND category = 'admin'");
        ASSERT_EQ(catalog.size(), 1u);
        EXPECT_EQ(catalog.one_row_ref()[0].as<int>(), 0);

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
    });
}

// #237: 110 adds the upstream control plane on an upgraded database: admin.upstream grants equal the fresh seed for
// every built-in role (custom roles get nothing), the six catalog rows, admin columns on api_keys that leave existing
// keys plain storage credentials, and the new tables. Re-running applies nothing.
TEST_F(SqlDeployerHistoryDb, UpstreamControlPlaneMigrationMatchesFreshSeedAndIsIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        // A <= 1.13.x database: none of 110 exists.
        for (const auto* table : {"upstream_write_intent", "upstream_event_inbox", "upstream_event_subscription",
                                  "upstream_event_channel", "upstream_audit", "upstream_bucket"})
            txn.exec(std::string("DROP TABLE ") + table + " CASCADE");
        for (const auto* column : {"admin_enabled", "provider_account_id", "encrypted_provider_token", "provider_token_iv",
                                   "admin_capabilities", "admin_validated_at"})
            txn.exec(std::string("ALTER TABLE api_keys DROP COLUMN ") + column);
        txn.exec("ALTER TABLE admin_role DROP COLUMN upstream_permissions");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '110_upstream_control_plane.sql'");
        txn.exec("DELETE FROM permission WHERE name LIKE 'admin.upstream.%' AND category = 'admin'");

        const auto upsert = [&](const std::string& name, const vh::rbac::role::Admin& bits) {
            txn.exec(R"SQL(
                INSERT INTO admin_role (name, description, identity_permissions, audit_permissions,
                                        settings_permissions, roles_permissions, vaults_permissions, keys_permissions,
                                        s3_gateway_permissions, stats_permissions)
                VALUES ($1, 'x', $2::bit(32), $3::bit(8), $4::bit(64), $5::bit(16), $6::bit(32), $7::bit(32), $8::bit(8),
                        $9::bit(8))
                ON CONFLICT (name) DO UPDATE SET
                    identity_permissions = EXCLUDED.identity_permissions, audit_permissions = EXCLUDED.audit_permissions,
                    settings_permissions = EXCLUDED.settings_permissions, roles_permissions = EXCLUDED.roles_permissions,
                    vaults_permissions = EXCLUDED.vaults_permissions, keys_permissions = EXCLUDED.keys_permissions,
                    s3_gateway_permissions = EXCLUDED.s3_gateway_permissions, stats_permissions = EXCLUDED.stats_permissions
            )SQL", pqxx::params{
                name, bits.identities.toBitString(), bits.audits.toBitString(), bits.settings.toBitString(),
                bits.roles.toBitString(), bits.vaults.toBitString(), bits.keys.toBitString(),
                bits.s3Gateway.toBitString(), bits.stats.toBitString()
            });
        };
        for (const auto& role : builtInAdminRoles()) upsert(role.name, role);
        upsert("claude_test_custom_full_role", vh::rbac::role::Admin::SuperAdmin());   // custom name: no grant

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "110_upstream_control_plane.sql"));

        const auto bitsOf = [&](const std::string& name) {
            return txn.exec("SELECT upstream_permissions::text FROM admin_role WHERE name = $1", pqxx::params{name})
                .one_row_ref()[0].as<std::string>();
        };
        for (const auto& role : builtInAdminRoles()) {
            SCOPED_TRACE(role.name);
            EXPECT_EQ(bitsOf(role.name), role.upstream.toBitString()) << "migration and fresh seed disagree";
        }
        EXPECT_EQ(bitsOf("super_admin"), "00111111");
        EXPECT_EQ(bitsOf("claude_test_custom_full_role"), "00000000");

        const auto catalog = txn.exec(
            "SELECT name, bit_position FROM permission WHERE name LIKE 'admin.upstream.%' AND category = 'admin' "
            "ORDER BY bit_position");
        ASSERT_EQ(catalog.size(), 6u);
        const std::vector<std::string> names{"admin.upstream.view", "admin.upstream.configure", "admin.upstream.provision",
                                             "admin.upstream.protect", "admin.upstream.unprotect", "admin.upstream.destroy"};
        for (std::size_t i = 0; i < names.size(); ++i) {
            EXPECT_EQ(catalog[static_cast<int>(i)][0].as<std::string>(), names[i]);
            EXPECT_EQ(catalog[static_cast<int>(i)][1].as<int>(), static_cast<int>(i));
        }
        // The catalog rows a fresh install seeds from core are the same names at the same bits.
        for (const auto& p : vh::rbac::role::Admin::SuperAdmin().toPermissions()) {
            if (!p.qualified_name.starts_with("admin.upstream.")) continue;
            const auto it = std::ranges::find(names, p.qualified_name);
            ASSERT_NE(it, names.end()) << p.qualified_name;
            EXPECT_EQ(static_cast<std::size_t>(p.bit_position), static_cast<std::size_t>(it - names.begin()));
        }

        const auto adminDefault = txn.exec(
            "SELECT column_default, is_nullable FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'api_keys' AND column_name = 'admin_enabled'");
        ASSERT_EQ(adminDefault.size(), 1u);
        EXPECT_EQ(adminDefault.one_row_ref()[0].as<std::string>(), "false");
        EXPECT_EQ(adminDefault.one_row_ref()[1].as<std::string>(), "NO");
        for (const auto* table : {"upstream_bucket", "upstream_audit", "upstream_event_channel",
                                  "upstream_event_subscription", "upstream_event_inbox", "upstream_write_intent"})
            EXPECT_EQ(txn.exec("SELECT to_regclass($1) IS NOT NULL", pqxx::params{table}).one_field_ref().as<bool>(), true)
                << table;

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        EXPECT_EQ(bitsOf("super_admin"), "00111111");
    });
}

// #187: 107 grants vault.sync.action.resolve_conflicts wherever sync trigger is held (built-in and custom vault roles,
// admin vault globals), lists the permission, makes event_id survive event pruning, and closes duplicate open
// conflicts before enforcing one open conflict per file.
TEST_F(SqlDeployerHistoryDb, SyncConflictMigrationGrantsResolveWhereTriggerIsAndKeepsOneOpenConflictPerFile) {
    inRolledBackTxn([](pqxx::work& txn) {
        using SyncAction = vh::rbac::permission::vault::sync::SyncActionPermissions;
        using vh::rbac::role::Vault;

        // A <= 1.10.x database: 107 never applied.
        txn.exec("DROP INDEX IF EXISTS uq_sync_conflicts_open_file");
        txn.exec("DROP INDEX IF EXISTS idx_sync_conflicts_open_vault");
        txn.exec("DROP TABLE IF EXISTS sync_file_baseline");
        txn.exec("ALTER TABLE sync_conflict_artifacts DROP COLUMN IF EXISTS remote_etag, DROP COLUMN IF EXISTS encrypted");
        txn.exec("ALTER TABLE sync_conflicts DROP COLUMN IF EXISTS vault_id, DROP COLUMN IF EXISTS updated_at");
        txn.exec("ALTER TABLE sync_conflicts DROP CONSTRAINT IF EXISTS sync_conflicts_event_id_fkey");
        txn.exec("ALTER TABLE sync_conflicts DROP CONSTRAINT IF EXISTS sync_conflicts_resolution_check");
        txn.exec("DELETE FROM sync_conflicts WHERE event_id IS NULL OR resolution NOT IN ('unresolved', 'kept_local', "
                 "'kept_remote', 'kept_both', 'overwritten', 'fixed_remote_encryption')");
        txn.exec("ALTER TABLE sync_conflicts ADD CONSTRAINT sync_conflicts_event_id_fkey FOREIGN KEY (event_id) "
                 "REFERENCES sync_event (id) ON DELETE CASCADE");
        txn.exec("ALTER TABLE sync_conflicts ALTER COLUMN event_id SET NOT NULL");
        txn.exec("ALTER TABLE sync_conflicts ADD CONSTRAINT sync_conflicts_resolution_check CHECK (resolution IN "
                 "('unresolved', 'kept_local', 'kept_remote', 'kept_both', 'overwritten', 'fixed_remote_encryption'))");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '107_sync_conflict_resolution.sql'");
        txn.exec("DELETE FROM permission WHERE name = 'vault.sync.action.resolve_conflicts' AND category = 'vault'");

        // Vault roles as an old install has them: the built-ins as seeded then (no resolve bit), plus custom ones.
        const auto oldBits = [](Vault role) {
            role.sync.action.revoke(SyncAction::ResolveConflicts);
            return role.sync.toBitString();
        };
        const auto upsert = [&](const std::string& name, const std::string& syncBits) {
            txn.exec(R"SQL(
                INSERT INTO vault_role (name, description, files_permissions, directories_permissions, sync_permissions,
                                        roles_permissions)
                VALUES ($1, 'x', B'00000000000000000000000000000000', B'00000000000000000000000000000000', $2::bit(32),
                        B'0000000000000000')
                ON CONFLICT (name) DO UPDATE SET sync_permissions = EXCLUDED.sync_permissions
            )SQL", pqxx::params{name, syncBits});
        };
        const std::vector<Vault> builtins{Vault::ImplicitDeny(), Vault::Guest(), Vault::Reader(), Vault::Contributor(),
                                          Vault::Editor(), Vault::Manager(), Vault::PowerUser()};
        for (const auto& role : builtins) upsert(role.name, oldBits(role));
        Vault trigger, waiver, none;
        trigger.sync.action.grant(SyncAction::Trigger);
        waiver.sync.action.grant(SyncAction::SignWaiver);
        upsert("claude_test_trigger_role", trigger.sync.toBitString());
        upsert("claude_test_waiver_role", waiver.sync.toBitString());
        upsert("claude_test_plain_role", none.sync.toBitString());

        // A user with admin vault globals holding trigger, and a vault with a file that has two open conflicts (what
        // every pass used to add) and one closed one.
        const auto userId = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_107_user', 'x') "
                                     "RETURNING id").one_field_ref().as<int>();
        txn.exec(R"SQL(
            INSERT INTO user_global_vault_policy (user_id, scope, files_permissions, directories_permissions,
                                                  sync_permissions, roles_permissions)
            VALUES ($1, 'admin', B'00000000000000000000000000000000', B'00000000000000000000000000000000', $2::bit(32),
                    B'0000000000000000'),
                   ($1, 'user', B'00000000000000000000000000000000', B'00000000000000000000000000000000', $3::bit(32),
                    B'0000000000000000')
        )SQL", pqxx::params{userId, trigger.sync.toBitString(), none.sync.toBitString()});
        const auto vaultId = txn.exec("INSERT INTO vault (type, name, owner_id, mount_point, uid) "
                                      "VALUES ('s3', 'claude_test_107_vault', $1, '0123456789ABCDEFGHJKMNPQRSTVWX107', gen_random_uuid()) "
                                      "RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();
        const auto fileId = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, 'f.txt', '/f.txt') "
                                     "RETURNING id", pqxx::params{vaultId}).one_field_ref().as<int>();
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, object_uid) VALUES ($1, 1, gen_random_uuid())", pqxx::params{fileId});
        std::vector<int> conflicts;
        for (const auto* resolution : {"kept_local", "unresolved", "unresolved"}) {
            const auto eventId = txn.exec("INSERT INTO sync_event (vault_id) VALUES ($1) RETURNING id",
                                          pqxx::params{vaultId}).one_field_ref().as<int>();
            conflicts.push_back(txn.exec("INSERT INTO sync_conflicts (event_id, file_id, conflict_type, resolution) "
                                         "VALUES ($1, $2, 'mismatch', $3) RETURNING id",
                                         pqxx::params{eventId, fileId, resolution}).one_field_ref().as<int>());
        }

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "107_sync_conflict_resolution.sql"));

        const auto syncBitsOf = [&](const std::string& name) {
            return txn.exec("SELECT sync_permissions::text FROM vault_role WHERE name = $1", pqxx::params{name})
                .one_field_ref().as<std::string>();
        };
        for (const auto& role : builtins) {
            SCOPED_TRACE(role.name);
            EXPECT_EQ(syncBitsOf(role.name), role.sync.toBitString()) << "migration and fresh seed disagree";
        }
        Vault triggerAfter = trigger;
        triggerAfter.sync.action.grant(SyncAction::ResolveConflicts);
        EXPECT_EQ(syncBitsOf("claude_test_trigger_role"), triggerAfter.sync.toBitString());
        EXPECT_EQ(syncBitsOf("claude_test_waiver_role"), waiver.sync.toBitString());
        EXPECT_EQ(syncBitsOf("claude_test_plain_role"), none.sync.toBitString());

        const auto globalBits = [&](const std::string& scope) {
            return txn.exec("SELECT sync_permissions::text FROM user_global_vault_policy WHERE user_id = $1 AND scope = $2",
                            pqxx::params{userId, scope}).one_field_ref().as<std::string>();
        };
        EXPECT_EQ(globalBits("admin"), triggerAfter.sync.toBitString()) << "admin vault globals with trigger";
        EXPECT_EQ(globalBits("user"), none.sync.toBitString());

        const auto catalog = txn.exec(
            "SELECT bit_position FROM permission WHERE name = 'vault.sync.action.resolve_conflicts' AND category = 'vault'");
        ASSERT_EQ(catalog.size(), 1u);
        const auto permissions = Vault().toPermissions();
        const auto exported = std::ranges::find_if(permissions, [](const auto& p) {
            return p.qualified_name == "vault.sync.action.resolve_conflicts";
        });
        ASSERT_NE(exported, permissions.end());
        EXPECT_EQ(catalog.one_field_ref().as<int>(), static_cast<int>(exported->bit_position)) << "same as the fresh seed";

        // One open conflict per file: the newest stays open, the older duplicate is superseded, history untouched.
        const auto resolution = [&](const int id) {
            return txn.exec("SELECT resolution, vault_id FROM sync_conflicts WHERE id = $1", pqxx::params{id}).one_row();  // owning: the result is a temporary
        };
        EXPECT_EQ(resolution(conflicts[0])[0].as<std::string>(), "kept_local");
        EXPECT_EQ(resolution(conflicts[1])[0].as<std::string>(), "superseded");
        EXPECT_EQ(resolution(conflicts[2])[0].as<std::string>(), "unresolved");
        EXPECT_EQ(resolution(conflicts[2])[1].as<int>(), vaultId) << "vault_id backfilled";
        {
            pqxx::subtransaction dup(txn, "dup");
            EXPECT_THROW(dup.exec("INSERT INTO sync_conflicts (event_id, file_id, conflict_type, resolution) "
                                  "VALUES (NULL, $1, 'mismatch', 'unresolved')", pqxx::params{fileId}),
                         std::exception) << "a second open conflict for the file is refused";
        }

        // Pruning a sync event no longer deletes the conflict it first saw.
        const auto eventOfOpen = txn.exec("SELECT event_id FROM sync_conflicts WHERE id = $1",
                                          pqxx::params{conflicts[2]}).one_field_ref().as<int>();
        txn.exec("DELETE FROM sync_event WHERE id = $1", pqxx::params{eventOfOpen});
        EXPECT_TRUE(txn.exec("SELECT event_id FROM sync_conflicts WHERE id = $1", pqxx::params{conflicts[2]})
                        .one_field_ref().is_null());

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
    });
}

TEST_F(SqlDeployerHistoryDb, EveryHistoricalChecksumReconcilesToCurrent) {
    for (const auto& e : migseed::kHistoricalMigrationChecksums) {
        const std::string filename{e.filename};
        const std::string oldHash{e.sha256};
        SCOPED_TRACE(filename);

        inRolledBackTxn([&](pqxx::work& txn) {
            if (filename == "020_vaults.sql") {
                // <= 1.5.0 shape: no s3.storage_tier_id, 090 not yet applied.
                txn.exec("ALTER TABLE s3 DROP COLUMN storage_tier_id");
                txn.exec("DELETE FROM schema_migrations WHERE filename = '090_s3_storage_tier_id.sql'");
            }
            txn.exec("UPDATE schema_migrations SET sha256 = $2 WHERE filename = $1", pqxx::params{filename, oldHash});

            migseed::SqlDeployReport report;
            ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
            EXPECT_TRUE(reconciled(report, filename));
            EXPECT_FALSE(applied(report, filename));
            EXPECT_EQ(recordedHash(txn, filename), currentHash(filename));

            if (filename == "020_vaults.sql") {
                EXPECT_TRUE(applied(report, "090_s3_storage_tier_id.sql"));
                EXPECT_TRUE(columnExists(txn, "s3", "storage_tier_id"));
            }
        });
    }
}

TEST_F(SqlDeployerHistoryDb, UnknownChecksumStillFailsClosed) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("UPDATE schema_migrations SET sha256 = $1 WHERE filename = '060_acl.sql'",
                 pqxx::params{std::string(64, 'a')});
        EXPECT_THROW(migseed::SqlDeployer::applyDir(txn, repoPsqlDir()), std::runtime_error);
    });
}

// 111 (file recovery): on a 110-era database, file_versions' file_id cascade becomes SET NULL (retained generations
// outlive the live file), the new tables/columns/trigger appear with defaults that change nothing, and re-running the
// migration file is a no-op.
namespace {

void dropFileRecovery(pqxx::work& txn) {
    txn.exec("DROP TRIGGER IF EXISTS recovery_guard_retired_vault_key ON vault_keys_trashed");
    txn.exec("DROP FUNCTION IF EXISTS recovery_guard_retired_vault_key()");
    txn.exec("DROP TABLE IF EXISTS recovery_plan, vault_upstream_usage_daily, upstream_object_version CASCADE");
    txn.exec("DELETE FROM file_versions");
    txn.exec(R"SQL(
        ALTER TABLE file_versions
            DROP COLUMN IF EXISTS vault_id, DROP COLUMN IF EXISTS snapshot_id, DROP COLUMN IF EXISTS blob_id,
            DROP COLUMN IF EXISTS rel_path, DROP COLUMN IF EXISTS mode, DROP COLUMN IF EXISTS source_updated_at,
            DROP COLUMN IF EXISTS origin, DROP COLUMN IF EXISTS reason, DROP COLUMN IF EXISTS upstream_state,
            DROP COLUMN IF EXISTS upstream_key, DROP COLUMN IF EXISTS upstream_version_id,
            DROP COLUMN IF EXISTS upstream_attempts, DROP COLUMN IF EXISTS upstream_error,
            DROP COLUMN IF EXISTS upstream_sent_at
    )SQL");
    txn.exec("DROP TABLE IF EXISTS recovery_snapshot, recovery_blob, vault_recovery_policy CASCADE");
    txn.exec("ALTER TABLE file_versions DROP CONSTRAINT IF EXISTS file_versions_file_id_fkey");
    txn.exec("ALTER TABLE file_versions ADD CONSTRAINT file_versions_file_id_fkey FOREIGN KEY (file_id) "
             "REFERENCES files (fs_entry_id) ON DELETE CASCADE");
    txn.exec("ALTER TABLE file_versions ALTER COLUMN content_hash SET NOT NULL");
    txn.exec(R"SQL(
        ALTER TABLE upstream_bucket
            DROP COLUMN IF EXISTS versioning_status, DROP COLUMN IF EXISTS versioning_checked_at,
            DROP COLUMN IF EXISTS versioning_enabled_at, DROP COLUMN IF EXISTS versioning_enabled_by,
            DROP COLUMN IF EXISTS versioning_enabled_by_vaulthalla, DROP COLUMN IF EXISTS versioning_settles_at,
            DROP COLUMN IF EXISTS versioning_mfa_delete, DROP COLUMN IF EXISTS object_lock_enabled,
            DROP COLUMN IF EXISTS noncurrent_retention_mode, DROP COLUMN IF EXISTS noncurrent_retention_days,
            DROP COLUMN IF EXISTS noncurrent_retention_set_at, DROP COLUMN IF EXISTS noncurrent_retention_set_by
    )SQL");
    txn.exec("DELETE FROM schema_migrations WHERE filename = '111_file_recovery.sql'");
}

// The delete actions of the foreign keys on file_versions.file_id ('c' cascade, 'n' set null).
std::vector<std::string> fileVersionFileIdActions(pqxx::work& txn) {
    const auto res = txn.exec(R"SQL(
        SELECT c.confdeltype::text FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
        WHERE c.conrelid = 'file_versions'::regclass AND c.contype = 'f' AND a.attname = 'file_id'
        ORDER BY c.conname
    )SQL");
    std::vector<std::string> out;
    for (const auto row : res) out.push_back(row[0].as<std::string>());
    return out;
}

}

TEST_F(SqlDeployerHistoryDb, FileRecoveryMigrationKeepsGenerationsWhenTheLiveFileGoes) {
    inRolledBackTxn([](pqxx::work& txn) {
        dropFileRecovery(txn);
        ASSERT_EQ(fileVersionFileIdActions(txn), std::vector<std::string>{"c"});
        ASSERT_FALSE(columnExists(txn, "file_versions", "blob_id"));

        // A 110-era row (the table existed, unused): file_id cascades.
        const auto userId = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_111_user', 'x') "
                                     "RETURNING id").one_field_ref().as<int>();
        const auto vaultId = txn.exec("INSERT INTO vault (type, name, owner_id, mount_point, uid) "
                                      "VALUES ('local', 'claude_test_111_vault', $1, '0123456789ABCDEFGHJKMNPQRSTVWX111', gen_random_uuid()) "
                                      "RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();
        const auto fileId = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, 'v.txt', '/v.txt') "
                                     "RETURNING id", pqxx::params{vaultId}).one_field_ref().as<int>();
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, object_uid) VALUES ($1, 5, gen_random_uuid())", pqxx::params{fileId});
        const auto versionId = txn.exec("INSERT INTO file_versions (file_id, version_number, content_hash, size_bytes, path) "
                                        "VALUES ($1, 1, 'h', 5, '/v.txt') RETURNING id",
                                        pqxx::params{fileId}).one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "111_file_recovery.sql"));
        EXPECT_EQ(recordedHash(txn, "111_file_recovery.sql"), currentHash("111_file_recovery.sql"));
        EXPECT_EQ(fileVersionFileIdActions(txn), std::vector<std::string>{"n"}) << "exactly one FK, SET NULL";

        // The old row keeps its meaning: a snapshot-origin generation outside any backlog.
        const auto old = txn.exec("SELECT origin, upstream_state, upstream_attempts, vault_id IS NULL, blob_id IS NULL "
                                  "FROM file_versions WHERE id = $1", pqxx::params{versionId}).one_row();
        EXPECT_EQ(old[0].as<std::string>(), "snapshot");
        EXPECT_EQ(old[1].as<std::string>(), "none");
        EXPECT_EQ(old[2].as<int>(), 0);
        EXPECT_TRUE(old[3].as<bool>());
        EXPECT_TRUE(old[4].as<bool>());

        // Deleting the live file keeps the generation.
        txn.exec("DELETE FROM fs_entry WHERE id = $1", pqxx::params{fileId});
        EXPECT_TRUE(txn.exec("SELECT file_id FROM file_versions WHERE id = $1", pqxx::params{versionId})
                        .one_field_ref().is_null());

        // Every vault starts without a policy; the trigger that guards retired keys exists (its behavior:
        // test_recovery_keys.cpp TheGuardTriggerKeepsReferencedRetiredKeysAndVaultDeletionStillCascades).
        EXPECT_EQ(txn.exec("SELECT count(*) FROM vault_recovery_policy").one_field_ref().as<int>(), 0);
        EXPECT_EQ(txn.exec("SELECT count(*) FROM pg_trigger WHERE tgname = 'recovery_guard_retired_vault_key' "
                           "AND tgrelid = 'vault_keys_trashed'::regclass").one_field_ref().as<int>(), 1);

        // Applying again does nothing; executing the file again changes nothing either (idempotent on upgraded installs).
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "111_file_recovery.sql")));
        EXPECT_EQ(fileVersionFileIdActions(txn), std::vector<std::string>{"n"});
        EXPECT_EQ(txn.exec("SELECT count(*) FROM pg_trigger WHERE tgname = 'recovery_guard_retired_vault_key'")
                      .one_field_ref().as<int>(), 1);
    });
}

// 112 (paired devices): on a 111-era database the devices and device_node tables appear empty, a device dies with its
// user (ON DELETE CASCADE) while approved_by only lets go (SET NULL), keys are unique as current and as previous, and
// re-running the file changes nothing.
TEST_F(SqlDeployerHistoryDb, DevicesMigrationIsAdditiveAndCascadesWithTheUser) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS devices, device_node CASCADE");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '112_devices.sql'");

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "112_devices.sql"));
        EXPECT_EQ(recordedHash(txn, "112_devices.sql"), currentHash("112_devices.sql"));
        EXPECT_EQ(txn.exec("SELECT count(*) FROM devices").one_field_ref().as<int>(), 0);
        EXPECT_EQ(txn.exec("SELECT count(*) FROM device_node").one_field_ref().as<int>(), 0);

        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_112_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto approver = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_112_approver', 'x') "
                                       "RETURNING id").one_field_ref().as<int>();
        const std::string key(64, 'a'), other(64, 'b');
        const auto device = txn.exec("INSERT INTO devices (user_id, approved_by, name, platform, spki_sha256) "
                                     "VALUES ($1, $2, 'Mac', 'macOS', $3) RETURNING id",
                                     pqxx::params{owner, approver, key}).one_field_ref().as<int>();
        {
            pqxx::subtransaction dup(txn, "dup");
            EXPECT_THROW(dup.exec("INSERT INTO devices (user_id, name, platform, spki_sha256) VALUES ($1, 'x', 'macOS', $2)",
                                  pqxx::params{owner, key}), pqxx::unique_violation);
        }
        {
            pqxx::subtransaction bad(txn, "bad");
            EXPECT_THROW(bad.exec("INSERT INTO devices (user_id, name, platform, spki_sha256) VALUES ($1, 'x', 'macOS', 'XYZ')",
                                  pqxx::params{owner}), pqxx::check_violation);
        }
        txn.exec("UPDATE devices SET previous_spki_sha256 = spki_sha256, spki_sha256 = $2 WHERE id = $1",
                 pqxx::params{device, other});

        txn.exec("DELETE FROM users WHERE id = $1", pqxx::params{approver});
        EXPECT_TRUE(txn.exec("SELECT approved_by FROM devices WHERE id = $1", pqxx::params{device})
                        .one_field_ref().is_null());
        txn.exec("DELETE FROM users WHERE id = $1", pqxx::params{owner});
        EXPECT_EQ(txn.exec("SELECT count(*) FROM devices WHERE id = $1", pqxx::params{device}).one_field_ref().as<int>(), 0);

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "112_devices.sql")));
    });
}

// 113 (vault key provenance): on a 112-era database (no provenance columns, no attestation keys, no salvage table) the
// columns appear NULL on existing key rows, the attestation-key foreign keys exist once, one running salvage per vault,
// and re-running the file changes nothing.
TEST_F(SqlDeployerHistoryDb, KeyProvenanceMigrationIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS vault_key_salvage CASCADE");
        for (const auto* table : {"vault_keys", "vault_keys_trashed", "vault_deletion_key"})
            txn.exec(std::string("ALTER TABLE ") + table + " DROP COLUMN IF EXISTS key_check, "
                     "DROP COLUMN IF EXISTS attestation_key_id, DROP COLUMN IF EXISTS attestation");
        txn.exec("DROP TABLE IF EXISTS key_attestation_keys CASCADE");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '113_vault_key_provenance.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_113_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_113', $1, 'local', 'claude_test_113', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        txn.exec("INSERT INTO vault_keys (vault_id, encrypted_key, iv, version) VALUES ($1, '\\x00', '\\x00', 2) "
                 "ON CONFLICT (vault_id) DO UPDATE SET version = 2", pqxx::params{vault});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "113_vault_key_provenance.sql"));
        EXPECT_EQ(recordedHash(txn, "113_vault_key_provenance.sql"), currentHash("113_vault_key_provenance.sql"));
        const auto row = txn.exec("SELECT key_check, attestation_key_id, attestation FROM vault_keys WHERE vault_id = $1",
                                  pqxx::params{vault}).one_row();
        EXPECT_TRUE(row[0].is_null() && row[1].is_null() && row[2].is_null());
        const auto fks = [&] {
            return txn.exec("SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND confrelid = "
                            "'key_attestation_keys'::regclass").one_field_ref().as<int>();
        };
        EXPECT_EQ(fks(), 3);
        {
            pqxx::subtransaction bad(txn, "bad_pk");
            EXPECT_THROW(bad.exec("INSERT INTO key_attestation_keys (public_key) VALUES ('\\x00')"),
                         pqxx::check_violation);
        }
        txn.exec("INSERT INTO vault_key_salvage (vault_id, versions) VALUES ($1, '{1}')", pqxx::params{vault});
        {
            pqxx::subtransaction dup(txn, "dup_running");
            EXPECT_THROW(dup.exec("INSERT INTO vault_key_salvage (vault_id, versions) VALUES ($1, '{1}')",
                                  pqxx::params{vault}), pqxx::unique_violation);
        }

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "113_vault_key_provenance.sql")));
        EXPECT_EQ(fks(), 3);
        txn.exec("DELETE FROM vault WHERE id = $1", pqxx::params{vault});
        EXPECT_EQ(txn.exec("SELECT count(*) FROM vault_key_salvage WHERE vault_id = $1", pqxx::params{vault})
                      .one_field_ref().as<int>(), 0);
    });
}

// 119 (#354, session assurance): on a 118-era database refresh_tokens has no aal / amr / auth_time. Existing rows
// were password sign-ins and read as aal 1, amr {pwd}, auth_time = issued_at; the level is checked; re-running the
// file changes nothing.
TEST_F(SqlDeployerHistoryDb, RefreshTokenAssuranceMigrationIsAdditiveAndOldRowsReadAsAal1) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP INDEX IF EXISTS idx_refresh_tokens_user_live");
        txn.exec("ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS aal, DROP COLUMN IF EXISTS amr, "
                 "DROP COLUMN IF EXISTS auth_time");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '119_refresh_token_assurance.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_119_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        txn.exec("INSERT INTO refresh_tokens (jti, user_id, token_hash, issued_at, expires_at) VALUES "
                 "('00000000-0000-4000-8000-000000000119', $1, 'sha256:x', '2026-01-02 03:04:05', "
                 "'2026-01-09 03:04:05')", pqxx::params{owner});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "119_refresh_token_assurance.sql"));
        EXPECT_EQ(recordedHash(txn, "119_refresh_token_assurance.sql"), currentHash("119_refresh_token_assurance.sql"));

        const auto old = txn.exec("SELECT aal, array_to_string(amr, ','), auth_time = issued_at FROM refresh_tokens "
                                  "WHERE jti = '00000000-0000-4000-8000-000000000119'").one_row();
        EXPECT_EQ(old[0].as<int>(), 1) << "a row written before assurance was a password sign-in";
        EXPECT_EQ(old[1].as<std::string>(), "pwd");
        EXPECT_TRUE(old[2].as<bool>()) << "auth_time is backfilled from issued_at";

        // New rows default the same way, and the level is 1 or 2 only.
        txn.exec("INSERT INTO refresh_tokens (jti, user_id, token_hash) VALUES "
                 "('00000000-0000-4000-8000-000000000120', $1, 'sha256:y')", pqxx::params{owner});
        EXPECT_FALSE(txn.exec("SELECT auth_time IS NULL FROM refresh_tokens WHERE jti = "
                              "'00000000-0000-4000-8000-000000000120'").one_field_ref().as<bool>());
        {
            pqxx::subtransaction bad(txn, "bad_aal");
            EXPECT_THROW(bad.exec("INSERT INTO refresh_tokens (jti, user_id, token_hash, aal) VALUES "
                                  "('00000000-0000-4000-8000-000000000121', $1, 'sha256:z', 3)", pqxx::params{owner}),
                         pqxx::check_violation);
        }
        {
            pqxx::subtransaction bad(txn, "null_auth_time");
            EXPECT_THROW(bad.exec("UPDATE refresh_tokens SET auth_time = NULL WHERE jti = "
                                  "'00000000-0000-4000-8000-000000000119'"),
                         pqxx::not_null_violation);
        }

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "119_refresh_token_assurance.sql")));
        EXPECT_EQ(txn.exec("SELECT aal FROM refresh_tokens WHERE jti = '00000000-0000-4000-8000-000000000119'")
                      .one_field_ref().as<int>(), 1);
    });
}

// 120 (#356, MFA factor storage): on a 119-era database none of the factor tables exist. The file creates them with
// their checks (32-byte user handle, one active recovery batch per account, 32-byte code hashes, a 12-byte TOTP IV),
// touches no existing table, and re-running it changes nothing.
TEST_F(SqlDeployerHistoryDb, MfaFactorsMigrationIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        for (const auto* table : {"recovery_codes", "recovery_code_batches", "totp_factors", "webauthn_credentials",
                                  "user_mfa"})
            txn.exec(std::string("DROP TABLE IF EXISTS ") + table + " CASCADE");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '120_mfa_factors.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_122_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto usersCols = txn.exec("SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'users'")
                                   .one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "120_mfa_factors.sql"));
        EXPECT_EQ(recordedHash(txn, "120_mfa_factors.sql"), currentHash("120_mfa_factors.sql"));
        EXPECT_EQ(txn.exec("SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'users'")
                      .one_field_ref().as<int>(), usersCols) << "users is not touched";

        txn.exec("INSERT INTO user_mfa (user_id, webauthn_user_handle) VALUES ($1, decode(repeat('ab', 32), 'hex'))",
                 pqxx::params{owner});
        {
            pqxx::subtransaction bad(txn, "short_handle");
            EXPECT_THROW(bad.exec("UPDATE user_mfa SET webauthn_user_handle = '\\x00' WHERE user_id = $1",
                                  pqxx::params{owner}), pqxx::check_violation);
        }
        txn.exec("INSERT INTO recovery_code_batches (id, user_id, acknowledged_at) VALUES "
                 "('00000000-0000-4000-8000-000000000120', $1, NOW())", pqxx::params{owner});
        {
            pqxx::subtransaction bad(txn, "two_active");
            EXPECT_THROW(bad.exec("INSERT INTO recovery_code_batches (id, user_id, acknowledged_at) VALUES "
                                  "('00000000-0000-4000-8000-000000000121', $1, NOW())", pqxx::params{owner}),
                         pqxx::unique_violation) << "one active batch per account";
        }
        txn.exec("INSERT INTO recovery_code_batches (id, user_id) VALUES "
                 "('00000000-0000-4000-8000-000000000122', $1)", pqxx::params{owner});  // pending: allowed
        {
            pqxx::subtransaction bad(txn, "short_hash");
            EXPECT_THROW(bad.exec("INSERT INTO recovery_codes (batch_id, user_id, code_hash) VALUES "
                                  "('00000000-0000-4000-8000-000000000120', $1, '\\x00')", pqxx::params{owner}),
                         pqxx::check_violation);
        }
        {
            pqxx::subtransaction bad(txn, "short_iv");
            EXPECT_THROW(bad.exec("INSERT INTO totp_factors (factor_uuid, user_id, label, secret_sealed, secret_iv) "
                                  "VALUES ('00000000-0000-4000-8000-000000000123', $1, 'Phone', '\\x00', '\\x00')",
                                  pqxx::params{owner}), pqxx::check_violation);
        }

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "120_mfa_factors.sql")));
        EXPECT_EQ(txn.exec("SELECT COUNT(*) FROM recovery_code_batches WHERE user_id = $1", pqxx::params{owner})
                      .one_field_ref().as<int>(), 2) << "re-running keeps the rows";
    });
}

// 122 + 123 (#366, provider-blind storage schema) on a 121-era database: every existing vault and file gets a uid from
// the deployer's data step (distinct, never PostgreSQL's v4 UUIDs), encrypting vaults get path_v0 and the others
// transparent (a NULL encrypt_upstream counts as encrypting, as the daemon always read it), the uids become NOT NULL,
// and nothing changes when the deploy or the files run again.
TEST_F(SqlDeployerHistoryDb, StorageLayoutMigrationBackfillsUidsAndLayoutsAndIsIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON vault");
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON files");
        // 125 (#368) also hangs its directory/symlink uid triggers on the function: a 121-era database has neither.
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON directories");
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON symlinks");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '125_manifest_v2.sql'");
        // 145 hangs the snapshot uid's trigger on it too.
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON recovery_snapshot");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '145_manifest_applier_base.sql'");
        txn.exec("DROP FUNCTION IF EXISTS vh_uid_immutable()");
        txn.exec("ALTER TABLE s3 DROP CONSTRAINT IF EXISTS s3_storage_layout_check");
        txn.exec("ALTER TABLE s3 DROP COLUMN IF EXISTS storage_layout");
        txn.exec("ALTER TABLE s3 ALTER COLUMN encrypt_upstream DROP NOT NULL");
        txn.exec("ALTER TABLE vault DROP COLUMN IF EXISTS uid");
        txn.exec("ALTER TABLE files DROP COLUMN IF EXISTS object_uid");
        txn.exec("DELETE FROM schema_migrations WHERE filename IN ('122_storage_layout.sql', '123_object_uids_required.sql')");
        ASSERT_FALSE(columnExists(txn, "vault", "uid"));

        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_122_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = [&](const std::string& name, const std::string& type) {
            return txn.exec("INSERT INTO vault (name, owner_id, type, mount_point) VALUES ($1, $2, $3, $4) RETURNING id",
                            pqxx::params{name, owner, type, name}).one_field_ref().as<int>();
        };
        const auto local = vault("claude_test_122_local", "local");
        const auto encrypting = vault("claude_test_122_enc", "s3");
        const auto plain = vault("claude_test_122_plain", "s3");
        const auto unset = vault("claude_test_122_null", "s3");
        txn.exec("INSERT INTO s3 (vault_id, bucket, encrypt_upstream) VALUES ($1, 'b122-enc', TRUE), "
                 "($2, 'b122-plain', FALSE), ($3, 'b122-null', NULL)", pqxx::params{encrypting, plain, unset});
        std::vector<int> files;
        for (int i = 0; i < 3; ++i) {
            const auto name = "f" + std::to_string(i);
            const auto id = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, $2, $3) RETURNING id",
                                     pqxx::params{i == 0 ? local : encrypting, name, "/" + name}).one_field_ref().as<int>();
            txn.exec("INSERT INTO files (fs_entry_id, size_bytes) VALUES ($1, 1)", pqxx::params{id});
            files.push_back(id);
        }

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "122_storage_layout.sql"));
        EXPECT_TRUE(applied(report, "123_object_uids_required.sql"));
        EXPECT_EQ(recordedHash(txn, "122_storage_layout.sql"), currentHash("122_storage_layout.sql"));

        EXPECT_EQ(txn.exec("SELECT count(*) FROM vault WHERE uid IS NULL").one_field_ref().as<int>(), 0);
        EXPECT_EQ(txn.exec("SELECT count(*) FROM files WHERE object_uid IS NULL").one_field_ref().as<int>(), 0);
        const auto snapshot = [&] {
            return txn.exec("SELECT string_agg(uid::text, ',' ORDER BY id) FROM vault").one_field_ref().as<std::string>() +
                   "|" + txn.exec("SELECT string_agg(object_uid::text, ',' ORDER BY fs_entry_id) FROM files")
                             .one_field_ref().as<std::string>();
        };
        const auto before = snapshot();
        EXPECT_EQ(txn.exec("SELECT count(DISTINCT object_uid) FROM files WHERE fs_entry_id = ANY($1::int[])",
                           pqxx::params{"{" + std::to_string(files[0]) + "," + std::to_string(files[1]) + "," +
                                        std::to_string(files[2]) + "}"}).one_field_ref().as<int>(), 3);
        // Raw CSPRNG bytes: across a backfill, not every uid has the version-4 nibble PostgreSQL's would.
        EXPECT_GT(txn.exec("SELECT count(*) FROM (SELECT uid::text AS t FROM vault UNION ALL "
                           "SELECT object_uid::text FROM files) u WHERE substr(t, 15, 1) <> '4'").one_field_ref().as<int>(), 0)
            << "uids must come from libsodium, not gen_random_uuid()";

        const auto layout = [&](const int id) {
            return txn.exec("SELECT storage_layout || '/' || encrypt_upstream::text FROM s3 WHERE vault_id = $1",
                            pqxx::params{id}).one_field_ref().as<std::string>();
        };
        EXPECT_EQ(layout(encrypting), "path_v0/true");
        EXPECT_EQ(layout(plain), "transparent/false");
        EXPECT_EQ(layout(unset), "path_v0/true");

        {
            pqxx::subtransaction noUid(txn, "no_uid");
            EXPECT_THROW(noUid.exec("INSERT INTO vault (name, owner_id, type, mount_point) VALUES "
                                    "('claude_test_122_nouid', $1, 'local', 'x')", pqxx::params{owner}),
                         pqxx::not_null_violation);
        }

        // Applying again does nothing; executing both files again changes nothing (idempotent on upgraded installs).
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "122_storage_layout.sql")));
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "123_object_uids_required.sql")));
        ASSERT_NO_THROW(migseed::assignObjectUids(txn));
        EXPECT_EQ(snapshot(), before);
        EXPECT_EQ(layout(plain), "transparent/false");
        EXPECT_EQ(txn.exec("SELECT count(*) FROM pg_constraint WHERE conrelid = 's3'::regclass AND "
                           "conname = 's3_storage_layout_check'").one_field_ref().as<int>(), 1);
    });
}

// LayoutCheckConstraint (spec 01 §4.6): the database refuses a layout that contradicts encrypt_upstream, and a uid
// never changes once assigned.
TEST_F(SqlDeployerHistoryDb, LayoutCheckConstraintRefusesMismatchedPairsAndUidsAreImmutable) {
    inRolledBackTxn([](pqxx::work& txn) {
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_122c_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_122c', $1, 's3', 'claude_test_122c', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        const auto refused = [&](const std::string& encrypt, const std::string& layout) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec("INSERT INTO s3 (vault_id, bucket, encrypt_upstream, storage_layout) VALUES ($1, 'b122c', " +
                         encrypt + ", $2)", pqxx::params{vault, layout});
            } catch (const pqxx::check_violation&) {
                return true;
            }
            sub.abort();
            return false;
        };
        EXPECT_TRUE(refused("TRUE", "transparent"));
        EXPECT_TRUE(refused("FALSE", "path_v0"));
        EXPECT_TRUE(refused("FALSE", "opaque_v1"));
        EXPECT_TRUE(refused("TRUE", "opaque"));
        EXPECT_FALSE(refused("TRUE", "path_v0"));
        EXPECT_FALSE(refused("TRUE", "opaque_v1"));
        EXPECT_FALSE(refused("FALSE", "transparent"));

        txn.exec("INSERT INTO s3 (vault_id, bucket, encrypt_upstream, storage_layout) VALUES ($1, 'b122c', TRUE, "
                 "'path_v0')", pqxx::params{vault});
        {
            pqxx::subtransaction flip(txn, "flip");
            EXPECT_THROW(flip.exec("UPDATE s3 SET encrypt_upstream = FALSE WHERE vault_id = $1", pqxx::params{vault}),
                         pqxx::check_violation) << "turning encryption off must move the layout too";
        }
        txn.exec("UPDATE s3 SET encrypt_upstream = FALSE, storage_layout = 'transparent' WHERE vault_id = $1",
                 pqxx::params{vault});

        const auto file = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, 'u', '/u') RETURNING id",
                                   pqxx::params{vault}).one_field_ref().as<int>();
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, object_uid) VALUES ($1, 1, gen_random_uuid())",
                 pqxx::params{file});
        {
            pqxx::subtransaction change(txn, "vault_uid");
            EXPECT_THROW(change.exec("UPDATE vault SET uid = gen_random_uuid() WHERE id = $1", pqxx::params{vault}),
                         pqxx::sql_error);
        }
        {
            pqxx::subtransaction change(txn, "file_uid");
            EXPECT_THROW(change.exec("UPDATE files SET object_uid = gen_random_uuid() WHERE fs_entry_id = $1",
                                     pqxx::params{file}), pqxx::sql_error);
        }
        // Content changes and same-value writes pass.
        txn.exec("UPDATE files SET size_bytes = 2, object_uid = object_uid WHERE fs_entry_id = $1", pqxx::params{file});
    });
}

// 125 (#368, manifest v2) on a 124-era database: additive (chain position and refused root on remote_manifest_state,
// the root history, directory/symlink uids, the trashed file's object uid), existing manifest rows keep their values,
// the CHECKs hold, and running the file again changes nothing (uid immutability: test_manifest_db.cpp
// UidsAreAssignedOnceAndTrashKeepsTheObjectUid).
TEST_F(SqlDeployerHistoryDb, ManifestV2MigrationIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS remote_manifest_root");
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON directories");
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON symlinks");
        txn.exec("ALTER TABLE remote_manifest_state DROP CONSTRAINT IF EXISTS remote_manifest_state_chain_check");
        txn.exec("ALTER TABLE remote_manifest_state DROP CONSTRAINT IF EXISTS remote_manifest_state_refused_check");
        for (const auto* column : {"epoch", "root_sha256", "refused_reason", "refused_epoch", "refused_root_sha256",
                                   "refused_at", "gc_at"})
            txn.exec(std::string("ALTER TABLE remote_manifest_state DROP COLUMN IF EXISTS ") + column);
        txn.exec("ALTER TABLE directories DROP COLUMN IF EXISTS uid");
        txn.exec("ALTER TABLE symlinks DROP COLUMN IF EXISTS uid");
        txn.exec("ALTER TABLE files_trashed DROP COLUMN IF EXISTS object_uid");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '125_manifest_v2.sql'");
        ASSERT_FALSE(columnExists(txn, "remote_manifest_state", "epoch"));

        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_125_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_125', $1, 's3', 'claude_test_125', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        txn.exec("INSERT INTO remote_manifest_state (vault_id, manifest_key, etag) VALUES ($1, '.vaulthalla/index-v1.json', "
                 "'\"e1\"')", pqxx::params{vault});
        const auto dir = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, 'd', '/d') RETURNING id",
                                  pqxx::params{vault}).one_field_ref().as<int>();
        txn.exec("INSERT INTO directories (fs_entry_id) VALUES ($1)", pqxx::params{dir});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "125_manifest_v2.sql"));
        EXPECT_EQ(recordedHash(txn, "125_manifest_v2.sql"), currentHash("125_manifest_v2.sql"));
        for (const auto* column : {"epoch", "root_sha256", "refused_reason", "refused_epoch", "refused_root_sha256",
                                   "refused_at", "gc_at"})
            EXPECT_TRUE(columnExists(txn, "remote_manifest_state", column)) << column;
        EXPECT_TRUE(columnExists(txn, "directories", "uid"));
        EXPECT_TRUE(columnExists(txn, "symlinks", "uid"));
        EXPECT_TRUE(columnExists(txn, "files_trashed", "object_uid"));
        EXPECT_EQ(txn.exec("SELECT etag FROM remote_manifest_state WHERE vault_id = $1", pqxx::params{vault})
                      .one_field_ref().as<std::string>(), "\"e1\"") << "existing rows keep their values";

        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql, pqxx::params{vault});
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET epoch = 0, root_sha256 = repeat('a', 64) WHERE vault_id = $1"));
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET epoch = 1 WHERE vault_id = $1")) << "epoch and hash go together";
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET epoch = 1, root_sha256 = 'ABC' WHERE vault_id = $1"));
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET refused_reason = 'other' WHERE vault_id = $1"));
        EXPECT_FALSE(refused("UPDATE remote_manifest_state SET epoch = 3, root_sha256 = repeat('a', 64), "
                             "refused_reason = 'fork' WHERE vault_id = $1"));
        EXPECT_TRUE(refused("INSERT INTO remote_manifest_root (vault_id, epoch, root_sha256) VALUES ($1, 0, repeat('a', 64))"));

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "125_manifest_v2.sql")));
    });
}

// 145 (the manifest applier's base copy and snapshot uids) on a 144-era database: additive (a nullable snapshot uid,
// the base root and applying marker on remote_manifest_state, the base table), existing rows keep their values and get
// no uid from PostgreSQL (the collector gives one), the CHECKs and the uid immutability hold, and running the file again
// changes nothing.
TEST_F(SqlDeployerHistoryDb, ManifestApplierBaseMigrationIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS remote_manifest_base");
        txn.exec("DROP TRIGGER IF EXISTS vh_uid_immutable ON recovery_snapshot");
        txn.exec("DROP INDEX IF EXISTS uq_recovery_snapshot_uid");
        txn.exec("ALTER TABLE remote_manifest_state DROP CONSTRAINT IF EXISTS remote_manifest_state_applying_check");
        for (const auto* column : {"base_root", "applying_epoch", "applying_root_sha256"})
            txn.exec(std::string("ALTER TABLE remote_manifest_state DROP COLUMN IF EXISTS ") + column);
        txn.exec("ALTER TABLE recovery_snapshot DROP COLUMN IF EXISTS uid");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '145_manifest_applier_base.sql'");
        ASSERT_FALSE(columnExists(txn, "recovery_snapshot", "uid"));

        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_145_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_145', $1, 's3', 'claude_test_145', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        txn.exec("INSERT INTO remote_manifest_state (vault_id, manifest_key, etag, epoch, root_sha256) VALUES "
                 "($1, '.vaulthalla/root', '\"e1\"', 4, repeat('b', 64))", pqxx::params{vault});
        const auto snap = txn.exec("INSERT INTO recovery_snapshot (vault_id, name, root_path, root_type, state) "
                                   "VALUES ($1, 'kept', '/', 'directory', 'ready') RETURNING id",
                                   pqxx::params{vault}).one_field_ref().as<int64_t>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "145_manifest_applier_base.sql"));
        EXPECT_EQ(recordedHash(txn, "145_manifest_applier_base.sql"), currentHash("145_manifest_applier_base.sql"));
        EXPECT_TRUE(columnExists(txn, "recovery_snapshot", "uid"));
        for (const auto* column : {"base_root", "applying_epoch", "applying_root_sha256"})
            EXPECT_TRUE(columnExists(txn, "remote_manifest_state", column)) << column;
        const auto row = txn.exec("SELECT etag, epoch, base_root IS NULL, applying_epoch IS NULL FROM remote_manifest_state "
                                  "WHERE vault_id = $1", pqxx::params{vault}).one_row();
        EXPECT_EQ(row[0].as<std::string>(), "\"e1\"") << "existing rows keep their values";
        EXPECT_EQ(row[1].as<int>(), 4);
        EXPECT_TRUE(row[2].as<bool>()) << "no base copy until the next recorded root";
        EXPECT_TRUE(row[3].as<bool>());
        EXPECT_TRUE(txn.exec("SELECT uid IS NULL FROM recovery_snapshot WHERE id = $1", pqxx::params{snap})
                        .one_field_ref().as<bool>()) << "145 gives no uid (158's data step does), never PostgreSQL";

        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql, pqxx::params{vault});
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET applying_epoch = 5 WHERE vault_id = $1"))
            << "epoch and hash go together";
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET applying_epoch = 5, applying_root_sha256 = 'x' "
                            "WHERE vault_id = $1"));
        EXPECT_FALSE(refused("UPDATE remote_manifest_state SET applying_epoch = 5, applying_root_sha256 = repeat('c', 64) "
                             "WHERE vault_id = $1"));
        EXPECT_TRUE(refused("INSERT INTO remote_manifest_base (vault_id, sid, object_sha256, bytes) "
                            "VALUES ($1, 's', 'nothex', '\\x00')"));
        txn.exec("UPDATE recovery_snapshot SET uid = gen_random_uuid() WHERE vault_id = $1", pqxx::params{vault});
        EXPECT_TRUE(refused("UPDATE recovery_snapshot SET uid = gen_random_uuid() WHERE vault_id = $1"))
            << "and never changes";

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "145_manifest_applier_base.sql")));
    });
}

// 146-148 (the manifest applier, its replica prerequisites and the shared-trash collection) on a 145-era database:
// additive (new tables, nullable or defaulted columns), existing state rows keep their values and read the defaults, the
// CHECKs hold, and running the files again changes nothing.
TEST_F(SqlDeployerHistoryDb, ManifestApplierMigrations146To148AreAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        for (const auto* t : {"manifest_apply_deferred", "manifest_foreign_envelope", "remote_manifest_pending",
                              "manifest_apply_report", "manifest_shared_purge"})
            txn.exec(std::string("DROP TABLE IF EXISTS ") + t);
        for (const auto* c : {"publishing_roots", "writers"})
            txn.exec(std::string("ALTER TABLE remote_manifest_state DROP COLUMN IF EXISTS ") + c);
        txn.exec("DELETE FROM schema_migrations WHERE filename IN ('146_manifest_apply.sql', "
                 "'147_manifest_replicas.sql', '148_manifest_shared_purge.sql')");
        ASSERT_FALSE(columnExists(txn, "remote_manifest_state", "writers"));

        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_146_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_146', $1, 's3', 'claude_test_146', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        txn.exec("INSERT INTO remote_manifest_state (vault_id, manifest_key, etag, epoch, root_sha256) VALUES "
                 "($1, '.vaulthalla/root', '\"e1\"', 4, repeat('b', 64))", pqxx::params{vault});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        for (const auto* f : {"146_manifest_apply.sql", "147_manifest_replicas.sql", "148_manifest_shared_purge.sql"}) {
            EXPECT_TRUE(applied(report, f)) << f;
            EXPECT_EQ(recordedHash(txn, f), currentHash(f)) << f;
        }
        const auto row = txn.exec("SELECT etag, epoch, cardinality(publishing_roots), cardinality(writers) "
                                  "FROM remote_manifest_state WHERE vault_id = $1", pqxx::params{vault}).one_row();
        EXPECT_EQ(row[0].as<std::string>(), "\"e1\"") << "existing rows keep their values";
        EXPECT_EQ(row[1].as<int>(), 4);
        EXPECT_EQ(row[2].as<int>(), 0);
        EXPECT_EQ(row[3].as<int>(), 0);

        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql, pqxx::params{vault});
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        EXPECT_TRUE(refused("INSERT INTO manifest_apply_deferred (vault_id, uid, op, target, root_epoch, root_sha256) "
                            "VALUES ($1, gen_random_uuid(), 'delete', '{}'::jsonb, 1, repeat('a', 64))"))
            << "a delete carries no target";
        EXPECT_TRUE(refused("INSERT INTO manifest_foreign_envelope (vault_id, kid, key_version, recipient_id) "
                            "VALUES ($1, 'not a kid', 1, repeat('a', 64))"));
        EXPECT_TRUE(refused("INSERT INTO manifest_shared_purge (vault_id, object_key) VALUES ($1, 'seg/x')"));
        EXPECT_FALSE(refused("INSERT INTO manifest_shared_purge (vault_id, object_key) VALUES "
                             "($1, 'o/aaaaaaaaaaaaaaaaaaaaaaaaaa')"));

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        for (const auto* f : {"146_manifest_apply.sql", "147_manifest_replicas.sql", "148_manifest_shared_purge.sql"})
            ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / f))) << f;
    });
}

// 149: on a 148-era database (the generic trigger), an explicit fs_entry.updated_at was overwritten with the current
// time; after it an explicit value is kept and any other update is stamped as before. Running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, FsEntryMtimeMigration149KeepsAnExplicitTimeAndStampsTheRest) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TRIGGER IF EXISTS set_fs_entry_updated_at ON fs_entry");
        txn.exec("CREATE TRIGGER set_fs_entry_updated_at BEFORE UPDATE ON fs_entry FOR EACH ROW "
                 "EXECUTE FUNCTION set_updated_at()");
        txn.exec("DROP FUNCTION IF EXISTS vh_fs_entry_updated_at()");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '149_fs_entry_explicit_mtime.sql'");
        const auto id = txn.exec("INSERT INTO fs_entry (name, path) VALUES ('claude_test_149', '/claude_test_149') "
                                 "RETURNING id").one_field_ref().as<long long>();
        const auto year = [&] {
            return txn.exec("SELECT extract(year FROM updated_at)::int FROM fs_entry WHERE id = $1", pqxx::params{id})
                .one_field_ref().as<int>();
        };
        txn.exec("UPDATE fs_entry SET updated_at = '2020-01-02T03:04:05Z' WHERE id = $1", pqxx::params{id});
        EXPECT_NE(year(), 2020) << "before 149: the explicit time is lost";

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "149_fs_entry_explicit_mtime.sql"));
        EXPECT_EQ(recordedHash(txn, "149_fs_entry_explicit_mtime.sql"), currentHash("149_fs_entry_explicit_mtime.sql"));
        txn.exec("UPDATE fs_entry SET updated_at = '2020-01-02T03:04:05Z' WHERE id = $1", pqxx::params{id});
        EXPECT_EQ(year(), 2020) << "an explicit time is kept";
        txn.exec("UPDATE fs_entry SET name = name WHERE id = $1", pqxx::params{id});
        EXPECT_NE(year(), 2020) << "any other update is stamped";

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "149_fs_entry_explicit_mtime.sql")));
        txn.exec("UPDATE fs_entry SET updated_at = '2020-01-02T03:04:05Z' WHERE id = $1", pqxx::params{id});
        EXPECT_EQ(year(), 2020);
        // A transaction that writes the times itself keeps them, an unchanged one included.
        txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
        txn.exec("UPDATE fs_entry SET name = name WHERE id = $1", pqxx::params{id});
        EXPECT_EQ(year(), 2020) << "vh.keep_mtime: kept";
    });
}

// 150 (replicated vaults: the writers change and each writer's last root) on a 149-era database: additive, existing
// state rows read no change, the CHECKs hold, and running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, ReplicaJoinMigration150IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS manifest_writer_root");
        txn.exec("ALTER TABLE remote_manifest_state DROP COLUMN IF EXISTS writers_change");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '150_manifest_replicas_join.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_150_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_150', $1, 's3', 'claude_test_150', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        txn.exec("INSERT INTO remote_manifest_state (vault_id, manifest_key, etag, epoch, root_sha256) VALUES "
                 "($1, '.vaulthalla/root', '\"e1\"', 4, repeat('b', 64))", pqxx::params{vault});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "150_manifest_replicas_join.sql"));
        EXPECT_EQ(recordedHash(txn, "150_manifest_replicas_join.sql"), currentHash("150_manifest_replicas_join.sql"));
        EXPECT_TRUE(txn.exec("SELECT writers_change FROM remote_manifest_state WHERE vault_id = $1", pqxx::params{vault})
                        .one_field_ref().is_null());
        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql, pqxx::params{vault});
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET writers_change = '{\"kind\": \"swap\", \"node\": \"n\"}' "
                            "WHERE vault_id = $1"));
        EXPECT_TRUE(refused("UPDATE remote_manifest_state SET writers_change = '{\"kind\": \"add\"}' WHERE vault_id = $1"));
        EXPECT_FALSE(refused("UPDATE remote_manifest_state SET writers_change = '{\"kind\": \"remove\", \"node\": \"n\"}' "
                             "WHERE vault_id = $1"));
        EXPECT_TRUE(refused("INSERT INTO manifest_writer_root (vault_id, node_id, epoch, root_sha256) VALUES ($1, 'n', 1, 'x')"));
        EXPECT_FALSE(refused("INSERT INTO manifest_writer_root (vault_id, node_id, epoch, root_sha256) VALUES "
                             "($1, 'n', 1, repeat('a', 64))"));

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "150_manifest_replicas_join.sql")));
    });
}

// 151 (remote connectors, design/core/mcp-remote-signin.md) on a 150-era database: new tables only, the switch can't
// be on without an origin, a grant can't name an unknown scope or reason, a refresh token is stored as a digest, and
// running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, ConnectorGrantsMigration151IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS connector_refresh_tokens");
        txn.exec("DROP TABLE IF EXISTS connector_grants");
        txn.exec("DROP TABLE IF EXISTS connector_clients");
        txn.exec("DROP TABLE IF EXISTS connector_settings");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '151_connector_grants.sql'");

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "151_connector_grants.sql"));
        EXPECT_EQ(recordedHash(txn, "151_connector_grants.sql"), currentHash("151_connector_grants.sql"));
        EXPECT_EQ(txn.exec("SELECT count(*) FROM connector_settings").one_field_ref().as<int>(), 0) << "absent = off";

        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_151_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql);
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        EXPECT_TRUE(refused("INSERT INTO connector_settings (enabled) VALUES (TRUE)"));
        EXPECT_TRUE(refused("INSERT INTO connector_settings (public_origin) VALUES ('http://vh.example')"));
        EXPECT_TRUE(refused("INSERT INTO connector_settings (id) VALUES (2)"));
        txn.exec("INSERT INTO connector_settings (enabled, public_origin) VALUES (TRUE, 'https://vh.example')");
        EXPECT_EQ(txn.exec("SELECT max_scope FROM connector_settings").one_field_ref().as<std::string>(), "write");
        EXPECT_FALSE(txn.exec("SELECT dcr_enabled FROM connector_settings").one_field_ref().as<bool>());

        const auto client = txn.exec("INSERT INTO connector_clients (client_id, kind, name, redirect_uris) VALUES "
                                     "('https://client.example/c.json', 'cimd', 'Client', "
                                     "ARRAY['https://client.example/cb']) RETURNING id::text")
                                .one_field_ref().as<std::string>();
        EXPECT_TRUE(refused("INSERT INTO connector_clients (client_id, kind, name, redirect_uris) VALUES "
                            "('x', 'other', 'n', ARRAY['https://a/b'])"));
        const auto grant = [&](const std::string& scope, const std::string& extra = "") {
            return "INSERT INTO connector_grants (user_id, client_row, client_id, client_name, redirect_uri, scope, "
                   "resource, approved_via, expires_at" + std::string(extra.empty() ? "" : ", revoked_at, revoked_reason") +
                   ") VALUES (" + std::to_string(owner) + ", '" + client + "', 'c', 'n', 'https://client.example/cb', '" +
                   scope + "', 'https://vh.example/mcp', 'webauthn', NOW() + interval '90 days'" + extra + ")";
        };
        txn.exec(grant("read"));
        EXPECT_TRUE(refused(grant("admin")));
        EXPECT_TRUE(refused(grant("read", ", NOW(), 'whatever'")));
        txn.exec(grant("write", ", NOW(), 'refresh_reuse'"));
        const auto g = txn.exec("SELECT id::text FROM connector_grants LIMIT 1").one_field_ref().as<std::string>();
        EXPECT_TRUE(refused("INSERT INTO connector_refresh_tokens (grant_id, token_digest, expires_at) VALUES ('" + g +
                            "', 'vh_rt_plaintext', NOW())"));

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "151_connector_grants.sql")));
    });
}

// 152 (scoped devices) on a 151-era database: existing devices read destructive (unchanged rights), the CHECK holds,
// and running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, DeviceScopeMigration152KeepsEveryDeviceUnscoped) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_scope");
        txn.exec("ALTER TABLE devices DROP COLUMN IF EXISTS scope");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '152_device_scope.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_152_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto device = txn.exec("INSERT INTO devices (user_id, name, platform, spki_sha256) VALUES "
                                     "($1, 'Mac', 'macOS', repeat('c', 64)) RETURNING id",
                                     pqxx::params{owner}).one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "152_device_scope.sql"));
        EXPECT_EQ(recordedHash(txn, "152_device_scope.sql"), currentHash("152_device_scope.sql"));
        EXPECT_EQ(txn.exec("SELECT scope FROM devices WHERE id = $1", pqxx::params{device}).one_field_ref().as<std::string>(),
                  "destructive");
        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql, pqxx::params{device});
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        EXPECT_TRUE(refused("UPDATE devices SET scope = 'admin' WHERE id = $1"));
        txn.exec("UPDATE devices SET scope = 'read' WHERE id = $1", pqxx::params{device});

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "152_device_scope.sql")));
        EXPECT_EQ(txn.exec("SELECT scope FROM devices WHERE id = $1", pqxx::params{device}).one_field_ref().as<std::string>(),
                  "read") << "re-running keeps a set scope";
    });
}

// 153 (Backblaze B2 identity) on a 152-era database: B2 buckets recorded as 's3:backblaze-b2', or under another
// generic label with a B2 S3 endpoint as their account, become 'backblaze-b2' with everything else unchanged, so their
// protection locks and bindings still match what a B2 key resolves to. Other providers' rows and the audit history
// are left alone, a bucket recorded under several generic labels gets one row renamed (no unique-key collision), a lock
// is never lost to a collision, and running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, BackblazeIdentityMigration153KeepsEveryLockAndRecord) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DELETE FROM schema_migrations WHERE filename = '153_backblaze_b2_identity.sql'");
        const std::string host = "s3.us-west-004.backblazeb2.com";
        const auto add = [&](const std::string& provider, const std::string& account, const std::string& bucket,
                             const bool locked, const std::string& ownership = "unmanaged") {
            return txn.exec("INSERT INTO upstream_bucket (provider, account_ref, bucket, ownership, is_protected, "
                            "protected_by_name, protection_reason) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                            pqxx::params{provider, account, bucket, ownership, locked,
                                         locked ? std::optional<std::string>("claude_test_153") : std::nullopt,
                                         locked ? std::optional<std::string>("keep out") : std::nullopt})
                .one_field_ref().as<long>();
        };
        const auto row = [&](const long id) {
            const auto res = txn.exec("SELECT provider, account_ref, bucket, ownership, is_protected, "
                                      "COALESCE(protection_reason, '') FROM upstream_bucket WHERE id = $1",
                                      pqxx::params{id});
            const auto r = res.one_row();
            return std::tuple{r[0].as<std::string>(), r[1].as<std::string>(), r[2].as<std::string>(),
                              r[3].as<std::string>(), r[4].as<bool>(), r[5].as<std::string>()};
        };

        const auto locked = add("s3:backblaze-b2", host, "claude-test-153-locked", true);
        const auto managed = add("s3:backblaze-b2", host, "claude-test-153-managed", false, "managed");
        const auto otherLabel = add("s3:other", host, "claude-test-153-other-label", true);
        const auto minio = add("s3:minio", "minio.lan", "claude-test-153-minio", true);
        const auto lookalike = add("s3:other", "s3.us-west-004.backblazeb2.com.evil.example", "claude-test-153-lookalike", true);
        const auto aws = add("aws-s3", "111122223333", "claude-test-153-aws", true);
        // The same bucket recorded twice: unlocked as Backblaze B2, locked through a key saved as "Other".
        const auto twiceB2 = add("s3:backblaze-b2", host, "claude-test-153-twice", false, "adopted");
        const auto twiceOther = add("s3:other", host, "claude-test-153-twice", true);
        // The same bucket under two generic labels and never as 's3:backblaze-b2': only one row can take the identity.
        // The adopted record wins over the older unmanaged one, and the lock comes over from the row left behind.
        const auto pairOther = add("s3:other", host, "claude-test-153-pair", true);
        const auto pairMinio = add("s3:minio", host, "claude-test-153-pair", false, "adopted");
        // Two plain records: the older one wins.
        const auto tieOlder = add("s3:other", host, "claude-test-153-tie", false);
        const auto tieNewer = add("s3:minio", host, "claude-test-153-tie", false);
        txn.exec("INSERT INTO upstream_audit (action, provider, account_ref, bucket, outcome) VALUES "
                 "('protect', 's3:backblaze-b2', $1, 'claude-test-153-locked', 'ok')", pqxx::params{host});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "153_backblaze_b2_identity.sql"));
        EXPECT_EQ(recordedHash(txn, "153_backblaze_b2_identity.sql"), currentHash("153_backblaze_b2_identity.sql"));

        const auto check = [&] {
            EXPECT_EQ(row(locked), (std::tuple{std::string("backblaze-b2"), host, std::string("claude-test-153-locked"),
                                               std::string("unmanaged"), true, std::string("keep out")}));
            EXPECT_EQ(row(managed), (std::tuple{std::string("backblaze-b2"), host, std::string("claude-test-153-managed"),
                                                std::string("managed"), false, std::string()}));
            EXPECT_EQ(std::get<0>(row(otherLabel)), "backblaze-b2") << "the identity follows the endpoint, not the label";
            EXPECT_TRUE(std::get<4>(row(otherLabel)));
            EXPECT_EQ(std::get<0>(row(minio)), "s3:minio");
            EXPECT_EQ(std::get<0>(row(lookalike)), "s3:other") << "only a real B2 S3 endpoint host";
            EXPECT_EQ(std::get<0>(row(aws)), "aws-s3");
            // The collision: the row that now carries the identity took the lock over and kept its own record.
            EXPECT_EQ(row(twiceB2), (std::tuple{std::string("backblaze-b2"), host, std::string("claude-test-153-twice"),
                                                std::string("adopted"), true, std::string("keep out")}));
            EXPECT_EQ(std::get<0>(row(twiceOther)), "s3:other") << "left as it was";
            EXPECT_EQ(row(pairMinio), (std::tuple{std::string("backblaze-b2"), host, std::string("claude-test-153-pair"),
                                                  std::string("adopted"), true, std::string("keep out")}));
            EXPECT_EQ(row(pairOther), (std::tuple{std::string("s3:other"), host, std::string("claude-test-153-pair"),
                                                  std::string("unmanaged"), true, std::string("keep out")}))
                << "left as it was";
            EXPECT_EQ(std::get<0>(row(tieOlder)), "backblaze-b2");
            EXPECT_EQ(std::get<0>(row(tieNewer)), "s3:minio");
            EXPECT_EQ(txn.exec("SELECT count(*) FROM upstream_bucket WHERE provider = 'backblaze-b2' AND is_protected "
                               "AND bucket LIKE 'claude-test-153-%'").one_field_ref().as<int>(), 4);
            EXPECT_EQ(txn.exec("SELECT provider FROM upstream_audit WHERE bucket = 'claude-test-153-locked'")
                          .one_field_ref().as<std::string>(), "s3:backblaze-b2") << "history is not rewritten";
        };
        check();

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "153_backblaze_b2_identity.sql")));
        check();
    });
}

// 154 (S3 gateway upstream profiles) on a 153-era database: existing credentials and buckets keep everything and get
// "no upstream source" (a CreateBucket still makes a local vault); the new table refuses what the gateway would
// misread ("local" as a profile name, a credential with two sources); running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, S3GatewayUpstreamProfilesMigration154IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "154_s3_gateway_upstream_profiles.sql";
        txn.exec("ALTER TABLE s3_gateway_bucket DROP COLUMN IF EXISTS created_by_credential_id, "
                 "DROP COLUMN IF EXISTS upstream_profile_id");
        txn.exec("ALTER TABLE s3_gateway_credentials DROP COLUMN IF EXISTS upstream_profile_id, "
                 "DROP COLUMN IF EXISTS upstream_server_default, DROP COLUMN IF EXISTS upstream_reapply");
        txn.exec("DROP TABLE IF EXISTS s3_gateway_credential_upstream_profile");
        txn.exec("DROP TABLE IF EXISTS s3_gateway_upstream_profile");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});

        const auto userId = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_154_user', 'x') "
                                     "RETURNING id").one_field_ref().as<int>();
        const auto vaultId = txn.exec("INSERT INTO vault (type, name, owner_id, mount_point, uid) "
                                      "VALUES ('local', 'claude_test_154_vault', $1, '0123456789ABCDEFGHJKMNPQRSTVWX154', gen_random_uuid()) "
                                      "RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();
        const auto credentialId = txn.exec(
            "INSERT INTO s3_gateway_credentials (user_id, principal_user_id, name, access_key, "
            "encrypted_secret_access_key, iv, scope_mode, description) "
            "VALUES ($1, $1, 'claude_test_154_cred', 'VHCLAUDETEST154', '\\x00', '\\x00', 'user_access', 'kept') "
            "RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();
        txn.exec("INSERT INTO s3_gateway_bucket (vault_id, bucket_name, api_exclusive, mode) "
                 "VALUES ($1, 'claude-test-154', TRUE, 'local')", pqxx::params{vaultId});
        const auto keyId = txn.exec(
            "INSERT INTO api_keys (user_id, name, provider, access_key, encrypted_secret_access_key, iv, region, endpoint) "
            "VALUES ($1, 'claude_test_154_key', 'Backblaze B2', 'k', '\\x00', '\\x00', 'us-west-004', "
            "'https://s3.us-west-004.backblazeb2.com') RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));

        const auto check = [&] {
            const auto cred = txn.exec("SELECT description, scope_mode, upstream_profile_id IS NULL, upstream_server_default, "
                                       "upstream_reapply IS NULL FROM s3_gateway_credentials WHERE id = $1",
                                       pqxx::params{credentialId}).one_row();
            EXPECT_EQ(cred[0].as<std::string>(), "kept");
            EXPECT_EQ(cred[1].as<std::string>(), "user_access");
            EXPECT_TRUE(cred[2].as<bool>()) << "no profile: a CreateBucket still makes a local vault";
            EXPECT_FALSE(cred[3].as<bool>()) << "an existing credential never follows a server default";
            EXPECT_TRUE(cred[4].as<bool>());
            const auto bucket = txn.exec("SELECT mode, api_exclusive, created_by_credential_id IS NULL, "
                                         "upstream_profile_id IS NULL FROM s3_gateway_bucket WHERE bucket_name = "
                                         "'claude-test-154'").one_row();
            EXPECT_EQ(bucket[0].as<std::string>(), "local");
            EXPECT_TRUE(bucket[1].as<bool>());
            EXPECT_TRUE(bucket[2].as<bool>());
            EXPECT_TRUE(bucket[3].as<bool>());
        };
        check();

        // What the schema itself refuses.
        const auto insertProfile = [&](const std::string& name, const std::string& strategy, const std::string& prefix) {
            pqxx::subtransaction sub(txn);
            const auto id = sub.exec("INSERT INTO s3_gateway_upstream_profile (name, api_key_id, sync_strategy, "
                                     "conflict_policy, bucket_prefix) VALUES ($1, $2, $3, 'keep_local', $4) RETURNING id",
                                     pqxx::params{name, keyId, strategy, prefix}).one_field_ref().as<int>();
            sub.commit();
            return id;
        };
        for (const auto* bad : {"local", "Upper", "-lead", "trail-", "under_score", ""})
            EXPECT_ANY_THROW((void)insertProfile(bad, "mirror", "")) << bad;
        EXPECT_ANY_THROW((void)insertProfile("claude-154-a", "copy", ""));
        EXPECT_ANY_THROW((void)insertProfile("claude-154-b", "mirror", "Bad_Prefix"));
        const auto profileId = insertProfile("claude-154", "mirror", "vlp-");
        EXPECT_ANY_THROW((void)insertProfile("claude-154", "sync", "")) << "names are unique";
        {
            pqxx::subtransaction sub(txn);
            EXPECT_ANY_THROW(sub.exec("UPDATE s3_gateway_credentials SET upstream_profile_id = $2, "
                                      "upstream_server_default = TRUE WHERE id = $1", pqxx::params{credentialId, profileId}))
                << "one upstream source at most";
        }
        txn.exec("UPDATE s3_gateway_credentials SET upstream_profile_id = $2 WHERE id = $1",
                 pqxx::params{credentialId, profileId});
        {
            pqxx::subtransaction sub(txn);
            EXPECT_ANY_THROW(sub.exec("DELETE FROM s3_gateway_upstream_profile WHERE id = $1", pqxx::params{profileId}))
                << "a profile a credential uses is not deleted from under it";
        }
        {
            pqxx::subtransaction sub(txn);
            EXPECT_ANY_THROW(sub.exec("DELETE FROM api_keys WHERE id = $1", pqxx::params{keyId}))
                << "nor is the API key of a profile";
        }
        txn.exec("UPDATE s3_gateway_credentials SET upstream_profile_id = NULL WHERE id = $1", pqxx::params{credentialId});
        // The allowlist: one row per (credential, profile), and it holds its profile in place too.
        txn.exec("INSERT INTO s3_gateway_credential_upstream_profile (credential_id, profile_id) VALUES ($1, $2)",
                 pqxx::params{credentialId, profileId});
        {
            pqxx::subtransaction sub(txn);
            EXPECT_ANY_THROW(sub.exec("INSERT INTO s3_gateway_credential_upstream_profile (credential_id, profile_id) "
                                      "VALUES ($1, $2)", pqxx::params{credentialId, profileId}));
        }
        {
            pqxx::subtransaction sub(txn);
            EXPECT_ANY_THROW(sub.exec("DELETE FROM s3_gateway_upstream_profile WHERE id = $1", pqxx::params{profileId}))
                << "a profile on a credential's allowlist stays";
        }
        txn.exec("DELETE FROM s3_gateway_credential_upstream_profile WHERE credential_id = $1", pqxx::params{credentialId});

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
        check();
        EXPECT_EQ(txn.exec("SELECT count(*) FROM s3_gateway_upstream_profile WHERE name = 'claude-154'")
                      .one_field_ref().as<int>(), 1);
    });
}

// 155 (vault read grants) on a 154-era database (v1.25.0): three new tables and the read_grants permission row, nothing
// else touched; the schema refuses what ops::read_grants relies on never existing (a short fingerprint, two live pins
// of one key, a revoked row without revoked_at, an unknown state); a deleted vault leaves the grant row so its upstream
// key can still be revoked; running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, VaultReadGrantsMigration155IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "155_vault_read_grants.sql";
        txn.exec("DROP TABLE IF EXISTS vault_read_grant_recipient");
        txn.exec("DROP TABLE IF EXISTS vault_read_grant");
        txn.exec("DROP TABLE IF EXISTS read_grant_recipient");
        txn.exec("DELETE FROM permission WHERE name = 'vault.sync.action.read_grants'");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});
        const auto rolesBefore = txn.exec("SELECT count(*), coalesce(sum(get_bit(sync_permissions, 31 - 11)), 0) "
                                          "FROM vault_role").one_row();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(report.applied.size(), 1u) << "only 155 was missing";
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));
        for (const auto* table : {"read_grant_recipient", "vault_read_grant", "vault_read_grant_recipient"})
            EXPECT_TRUE(columnExists(txn, table, "fingerprint") || columnExists(txn, table, "grant_id")) << table;
        EXPECT_EQ(txn.exec("SELECT bit_position FROM permission WHERE name = 'vault.sync.action.read_grants' "
                           "AND category = 'vault'").one_field_ref().as<int>(), 11);
        const auto rolesAfter = txn.exec("SELECT count(*), coalesce(sum(get_bit(sync_permissions, 31 - 11)), 0) "
                                         "FROM vault_role").one_row();
        EXPECT_EQ(rolesAfter[0].as<int>(), rolesBefore[0].as<int>());
        EXPECT_EQ(rolesAfter[1].as<int>(), rolesBefore[1].as<int>()) << "no role is granted read_grants by the migration";

        const auto userId = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_155_user', 'x') "
                                     "RETURNING id").one_field_ref().as<int>();
        const auto vaultId = txn.exec("INSERT INTO vault (type, name, owner_id, mount_point, uid) "
                                      "VALUES ('local', 'claude_test_155_vault', $1, '0123456789ABCDEFGHJKMNPQRSTVWX155', "
                                      "gen_random_uuid()) RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();
        const auto fails = [&](const std::string& sql, const pqxx::params& params) {
            pqxx::subtransaction sub(txn);
            try {
                sub.exec(sql, params);
            } catch (const std::exception&) {
                return true;
            }
            return false;
        };
        const std::string fpr = "A6A1752984DFB0DB38DD235D2096C49D7A8F000A";
        const auto pin = std::string("INSERT INTO read_grant_recipient (fingerprint, algorithm, public_key, source, "
                                     "pinned_by_name) VALUES ($1, 'ed25519/cv25519', 'k', $2, 'test')");
        EXPECT_TRUE(fails(pin, pqxx::params{"2096C49D7A8F000A", "input"})) << "a key id is not a fingerprint";
        EXPECT_TRUE(fails(pin, pqxx::params{"a6a1752984dfb0db38dd235d2096c49d7a8f000a", "input"})) << "upper case only";
        EXPECT_TRUE(fails(pin, pqxx::params{fpr, "email"})) << "a key is never pinned by its address";
        const auto recipientId = txn.exec(pin + " RETURNING id", pqxx::params{fpr, "keyserver"}).one_field_ref().as<int>();
        EXPECT_TRUE(fails(pin, pqxx::params{fpr, "input"})) << "one live pin per fingerprint";
        txn.exec("UPDATE read_grant_recipient SET removed_at = now() WHERE id = $1", pqxx::params{recipientId});
        const auto repinned = txn.exec(pin + " RETURNING id", pqxx::params{fpr, "input"}).one_field_ref().as<int>();

        const auto grant = std::string("INSERT INTO vault_read_grant (grant_id, vault_id, vault_name, state, "
                                       "issued_by_name, revoked_at) VALUES ($1, $2, 'v', $3, 'test', $4) RETURNING id");
        EXPECT_TRUE(fails(grant, pqxx::params{"short", vaultId, "issuing", std::optional<std::string>{}}));
        EXPECT_TRUE(fails(grant, pqxx::params{"0123456789abcdefghjkmnpqrs", vaultId, "pending", std::optional<std::string>{}}));
        EXPECT_TRUE(fails(grant, pqxx::params{"0123456789abcdefghjkmnpqrs", vaultId, "revoked", std::optional<std::string>{}}))
            << "revoked means revoked_at";
        const auto grantRow = txn.exec(grant, pqxx::params{"0123456789abcdefghjkmnpqrs", vaultId, "active",
                                                           std::optional<std::string>{}}).one_field_ref().as<int>();
        txn.exec("INSERT INTO vault_read_grant_recipient (grant_row_id, recipient_id, fingerprint) VALUES ($1, $2, $3)",
                 pqxx::params{grantRow, repinned, fpr});
        EXPECT_TRUE(fails("DELETE FROM read_grant_recipient WHERE id = $1", pqxx::params{repinned}))
            << "a recipient a grant was encrypted to stays";
        txn.exec("DELETE FROM vault WHERE id = $1", pqxx::params{vaultId});
        const auto kept = txn.exec("SELECT vault_id IS NULL, vault_name, state FROM vault_read_grant WHERE id = $1",
                                   pqxx::params{grantRow}).one_row();
        EXPECT_TRUE(kept[0].as<bool>()) << "the grant outlives its vault, so its upstream key can still be revoked";
        EXPECT_EQ(kept[2].as<std::string>(), "active");

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
        EXPECT_EQ(txn.exec("SELECT count(*) FROM vault_read_grant WHERE id = $1", pqxx::params{grantRow})
                      .one_field_ref().as<int>(), 1);
        EXPECT_EQ(txn.exec("SELECT count(*) FROM permission WHERE name = 'vault.sync.action.read_grants'")
                      .one_field_ref().as<int>(), 1);
    });
}

// 156 (Backblaze B2 provider versioning) on a 155-era database: noncurrent_retention_mode gains 'latest' (no days, like
// 'indefinite'), every existing row still passes the widened check, and s3_gateway_upstream_profile gains a nullable
// versioning (off | indefinite | <N>d up to 36500, NULL = off); running it again changes nothing.
TEST_F(SqlDeployerHistoryDb, B2ProviderVersioningMigration156IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "156_b2_provider_versioning.sql";
        txn.exec("ALTER TABLE s3_gateway_upstream_profile DROP COLUMN IF EXISTS versioning");
        txn.exec("ALTER TABLE upstream_bucket DROP CONSTRAINT IF EXISTS upstream_bucket_noncurrent_retention_check");
        txn.exec("ALTER TABLE upstream_bucket ADD CONSTRAINT upstream_bucket_noncurrent_retention_check "
                 "CHECK ((noncurrent_retention_mode = 'days' AND noncurrent_retention_days BETWEEN 1 AND 36500) "
                 "OR (noncurrent_retention_mode IN ('unset', 'indefinite') AND noncurrent_retention_days IS NULL))");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});

        const auto fails = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn);
            try {
                sub.exec(sql);
            } catch (const std::exception&) {
                return true;
            }
            return false;
        };
        const auto bucket = txn.exec("INSERT INTO upstream_bucket (provider, account_ref, bucket, ownership, "
                                     "noncurrent_retention_mode, noncurrent_retention_days) VALUES ('backblaze-b2', "
                                     "'s3.us-west-004.backblazeb2.com', 'claude-test-156', 'managed', 'days', 30) "
                                     "RETURNING id").one_field_ref().as<int64_t>();
        EXPECT_TRUE(fails("UPDATE upstream_bucket SET noncurrent_retention_mode = 'latest', noncurrent_retention_days = NULL "
                          "WHERE id = " + std::to_string(bucket)))
            << "before 156 there is no 'latest'";

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(report.applied.size(), 1u) << "only 156 was missing";
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));
        EXPECT_TRUE(columnExists(txn, "s3_gateway_upstream_profile", "versioning"));

        const auto id = std::to_string(bucket);
        EXPECT_FALSE(fails("UPDATE upstream_bucket SET noncurrent_retention_mode = 'latest', noncurrent_retention_days = NULL "
                           "WHERE id = " + id));
        EXPECT_TRUE(fails("UPDATE upstream_bucket SET noncurrent_retention_mode = 'latest', noncurrent_retention_days = 1 "
                          "WHERE id = " + id)) << "latest carries no days";
        EXPECT_FALSE(fails("UPDATE upstream_bucket SET noncurrent_retention_mode = 'days', noncurrent_retention_days = 30 "
                           "WHERE id = " + id)) << "what was valid stays valid";

        const auto keyOwner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_156_user', 'x') "
                                       "RETURNING id").one_field_ref().as<int>();
        const auto apiKey = txn.exec("INSERT INTO api_keys (user_id, name, provider, access_key, encrypted_secret_access_key, "
                                     "iv, region, endpoint) VALUES ($1, 'claude_test_156_key', 'Backblaze B2', 'k', "
                                     "'\\x00'::bytea, '\\x00'::bytea, 'us-west-004', "
                                     "'https://s3.us-west-004.backblazeb2.com') RETURNING id",
                                     pqxx::params{keyOwner});
        int seq = 0;
        const auto profile = [&](const std::string& versioning) {
            return "INSERT INTO s3_gateway_upstream_profile (name, api_key_id, sync_strategy, conflict_policy, versioning) "
                   "VALUES ('claude-test-156-" + std::to_string(++seq) + "', " +
                   std::to_string(apiKey.one_field_ref().as<int>()) + ", 'cache', 'keep_local', " + versioning + ")";
        };
        for (const auto* ok : {"NULL", "'off'", "'indefinite'", "'30d'", "'1d'", "'36500d'"})
            EXPECT_FALSE(fails(profile(ok))) << ok;
        for (const auto* bad : {"'0d'", "'36501d'", "'30'", "'forever'", "''", "'d'"})
            EXPECT_TRUE(fails(profile(bad))) << bad;

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
    });
}

TEST_F(SqlDeployerHistoryDb, RecoveryRecipientsMigrationIsAdditiveIdempotentAndCustomerOnly) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS vault_key_envelope");
        txn.exec("DROP TABLE IF EXISTS vault_recovery_grant");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '127_recovery_recipients.sql'");

        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_127_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_127', $1, 's3', 'claude_test_127', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "127_recovery_recipients.sql"));
        EXPECT_EQ(recordedHash(txn, "127_recovery_recipients.sql"), currentHash("127_recovery_recipients.sql"));
        EXPECT_EQ(txn.exec("SELECT COUNT(*) FROM vault_recovery_grant").one_field_ref().as<int>(), 0)
            << "an upgrade enrolls no recipient";

        const auto insert = [&](const std::string& cls, const int suite, const int keyBytes, const std::string& grant) {
            pqxx::subtransaction sub(txn, "grant");
            try {
                sub.exec("INSERT INTO vault_recovery_grant (vault_id, grant_id, recipient_id, public_key, suite, class, "
                         "authorized_by) VALUES ($1, $2, repeat('a', 64), decode(repeat('01', $4), 'hex'), $3, $5, 'test')",
                         pqxx::params{vault, grant, suite, keyBytes, cls});
                sub.commit();
                return true;
            } catch (const pqxx::sql_error&) {
                return false;
            }
        };
        EXPECT_FALSE(insert("custodian", 1, 32, "00000000000000000000000000")) << "only customer grants exist";
        EXPECT_FALSE(insert("customer", 2, 65, "00000000000000000000000000")) << "recovery recipients are X25519";
        EXPECT_FALSE(insert("customer", 1, 32, "not-a-grant-id")) << "grant ids are base32 uids";
        EXPECT_TRUE(insert("customer", 1, 32, "00000000000000000000000000"));
        EXPECT_FALSE(insert("customer", 1, 32, "00000000000000000000000004")) << "one active grant per recipient";

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "127_recovery_recipients.sql")));
        EXPECT_EQ(txn.exec("SELECT COUNT(*) FROM vault_recovery_grant").one_field_ref().as<int>(), 1)
            << "re-running keeps existing grants";
    });
}

// 128 (#361, device approval keys) on a 127-era database: one new table, nothing existing changes, the CHECKs and the
// one-key-per-device / unique-hash rules hold, a device's removal takes its key, and running the file again changes
// nothing.
TEST_F(SqlDeployerHistoryDb, DeviceApprovalKeysMigrationIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS device_approval_keys");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '128_device_approval_keys.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_128_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto device = txn.exec("INSERT INTO devices (user_id, name, platform, spki_sha256) VALUES ($1, 'Mac', "
                                     "'macOS', repeat('a', 64)) RETURNING id",
                                     pqxx::params{owner}).one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "128_device_approval_keys.sql"));
        EXPECT_EQ(recordedHash(txn, "128_device_approval_keys.sql"), currentHash("128_device_approval_keys.sql"));
        EXPECT_TRUE(columnExists(txn, "device_approval_keys", "public_key_spki"));
        EXPECT_EQ(txn.exec("SELECT name FROM devices WHERE id = $1", pqxx::params{device}).one_field_ref().as<std::string>(),
                  "Mac") << "existing rows keep their values";
        EXPECT_TRUE(txn.exec("SELECT 1 FROM device_approval_keys").empty()) << "no device gets a key by migration";

        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql, pqxx::params{device});
                sub.commit();  // kept: the next check sees it
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        const std::string spki = "decode(repeat('30', 91), 'hex')";
        EXPECT_TRUE(refused("INSERT INTO device_approval_keys (device_id, public_key_spki, spki_sha256, registered_via) "
                            "VALUES ($1, decode('30', 'hex'), repeat('b', 64), 'pairing')")) << "91 bytes";
        EXPECT_TRUE(refused("INSERT INTO device_approval_keys (device_id, public_key_spki, spki_sha256, registered_via) "
                            "VALUES ($1, " + spki + ", 'ABC', 'pairing')")) << "lowercase hex";
        EXPECT_TRUE(refused("INSERT INTO device_approval_keys (device_id, public_key_spki, spki_sha256, registered_via) "
                            "VALUES ($1, " + spki + ", repeat('b', 64), 'client_flag')")) << "how a person approved it";
        EXPECT_FALSE(refused("INSERT INTO device_approval_keys (device_id, public_key_spki, spki_sha256, registered_via) "
                             "VALUES ($1, " + spki + ", repeat('b', 64), 'pairing')"));
        EXPECT_TRUE(refused("INSERT INTO device_approval_keys (device_id, public_key_spki, spki_sha256, registered_via) "
                            "VALUES ($1, " + spki + ", repeat('c', 64), 'console_approval')")) << "one key per device";
        txn.exec("DELETE FROM devices WHERE id = $1", pqxx::params{device});
        EXPECT_TRUE(txn.exec("SELECT 1 FROM device_approval_keys").empty()) << "the key goes with its device";

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "128_device_approval_keys.sql")));
    });
}

// 129 (#360, MFA recovery effects on paired devices): on a 128-era database devices has no key_backup_revoked_* columns.
// The file adds them, nullable, keeps every row as it was (an existing device's grant is not revoked), refuses an
// unknown reason, and re-running it changes nothing.
TEST_F(SqlDeployerHistoryDb, MfaRecoveryGrantsMigrationIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("ALTER TABLE devices DROP COLUMN IF EXISTS key_backup_revoked_reason, "
                 "DROP COLUMN IF EXISTS key_backup_revoked_at");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '129_mfa_recovery_grants.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_129_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto device = txn.exec("INSERT INTO devices (user_id, name, platform, spki_sha256) VALUES "
                                     "($1, 'Mac', 'macOS', repeat('d', 64)) RETURNING id",
                                     pqxx::params{owner}).one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "129_mfa_recovery_grants.sql"));
        EXPECT_EQ(recordedHash(txn, "129_mfa_recovery_grants.sql"), currentHash("129_mfa_recovery_grants.sql"));
        EXPECT_TRUE(txn.exec("SELECT key_backup_revoked_at IS NULL AND key_backup_revoked_reason IS NULL "
                             "FROM devices WHERE id = $1", pqxx::params{device}).one_field_ref().as<bool>())
            << "an existing device keeps its grant";
        {
            pqxx::subtransaction bad(txn, "bad_reason");
            EXPECT_THROW(bad.exec("UPDATE devices SET key_backup_revoked_reason = 'whim' WHERE id = $1",
                                  pqxx::params{device}), pqxx::check_violation);
        }
        txn.exec("UPDATE devices SET key_backup_revoked_at = NOW(), key_backup_revoked_reason = 'recovery_code' "
                 "WHERE id = $1", pqxx::params{device});

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "129_mfa_recovery_grants.sql")));
        EXPECT_EQ(txn.exec("SELECT key_backup_revoked_reason FROM devices WHERE id = $1", pqxx::params{device})
                      .one_field_ref().as<std::string>(), "recovery_code") << "re-running keeps the values";
    });
}

// 130 (#362, key-backup grants) on a 129-era database: new tables only, nothing existing changes; D1's snapshot holds
// exactly the devices live when the migration ran, and running the file again never adds a device paired since.
TEST_F(SqlDeployerHistoryDb, KeyBackupGrantsMigrationIsAdditiveIdempotentAndSnapshotsLiveDevicesOnce) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS key_backup_grant_vaults");
        txn.exec("DROP TABLE IF EXISTS key_backup_grants");
        txn.exec("DROP TABLE IF EXISTS key_backup_grant_migration");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '130_key_backup_grants.sql'");
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_130_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto live = txn.exec("INSERT INTO devices (user_id, name, platform, spki_sha256) VALUES ($1, 'Mac', "
                                   "'macOS', repeat('d', 64)) RETURNING id",
                                   pqxx::params{owner}).one_field_ref().as<int>();
        const auto revoked = txn.exec("INSERT INTO devices (user_id, name, platform, spki_sha256, revoked_at) VALUES "
                                      "($1, 'Old Mac', 'macOS', repeat('e', 64), NOW()) RETURNING id",
                                      pqxx::params{owner}).one_field_ref().as<int>();
        // 129's interim columns (#360), as a 129-era database has them: one device's authority was revoked.
        txn.exec("ALTER TABLE devices ADD COLUMN IF NOT EXISTS key_backup_revoked_at TIMESTAMPTZ, "
                 "ADD COLUMN IF NOT EXISTS key_backup_revoked_reason TEXT");
        const auto recovered = txn.exec("INSERT INTO devices (user_id, name, platform, spki_sha256, "
                                        "key_backup_revoked_at, key_backup_revoked_reason) VALUES ($1, 'Mac 2', 'macOS', "
                                        "repeat('9', 64), NOW(), 'admin_reset') RETURNING id",
                                        pqxx::params{owner}).one_field_ref().as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "130_key_backup_grants.sql"));
        EXPECT_EQ(recordedHash(txn, "130_key_backup_grants.sql"), currentHash("130_key_backup_grants.sql"));
        EXPECT_TRUE(columnExists(txn, "key_backup_grants", "revoked_reason"));
        EXPECT_TRUE(columnExists(txn, "key_backup_grant_vaults", "vault_id"));
        EXPECT_EQ(txn.exec("SELECT name FROM devices WHERE id = $1", pqxx::params{live}).one_field_ref().as<std::string>(),
                  "Mac") << "existing rows keep their values";
        EXPECT_TRUE(txn.exec("SELECT 1 FROM key_backup_grants").empty()) << "grants are the daemon's to make (D1)";
        std::vector<int> snapshot;
        for (const auto& r : txn.exec("SELECT device_id FROM key_backup_grant_migration WHERE device_id IN ($1, $2, $3) "
                                      "ORDER BY device_id",
                                      pqxx::params{live, revoked, recovered}))
            snapshot.push_back(r[0].as<int>());
        EXPECT_EQ(snapshot, (std::vector<int>{live, recovered})) << "live devices only, not device " << revoked;
        EXPECT_EQ(txn.exec("SELECT revoked_reason FROM key_backup_grant_migration WHERE device_id = $1",
                           pqxx::params{recovered}).one_field_ref().as<std::string>(),
                  "admin_reset") << "the interim revocation is carried over";
        EXPECT_TRUE(txn.exec("SELECT revoked_at IS NULL FROM key_backup_grant_migration WHERE device_id = $1",
                             pqxx::params{live}).one_field_ref().as<bool>());
        EXPECT_FALSE(columnExists(txn, "devices", "key_backup_revoked_at")) << "the interim columns are gone";
        EXPECT_FALSE(columnExists(txn, "devices", "key_backup_revoked_reason"));

        const auto refused = [&](const std::string& sql) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec(sql, pqxx::params{live, owner});
                sub.commit();  // kept: the next check sees it
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        EXPECT_TRUE(refused("INSERT INTO key_backup_grants (device_id, user_id, origin) VALUES ($1, $2, 'implicit')"))
            << "origin";
        EXPECT_TRUE(refused("INSERT INTO key_backup_grants (device_id, user_id, origin, approved_via) VALUES ($1, $2, "
                            "'approved', 'client_flag')")) << "how a person approved it";
        EXPECT_TRUE(refused("INSERT INTO key_backup_grants (device_id, user_id, origin, revoked_at) VALUES ($1, $2, "
                            "'approved', NOW())")) << "a revocation carries its reason";
        EXPECT_FALSE(refused("INSERT INTO key_backup_grants (device_id, user_id, origin) VALUES ($1, $2, 'migrated')"));
        EXPECT_TRUE(refused("INSERT INTO key_backup_grants (device_id, user_id, origin) VALUES ($1, $2, 'approved')"))
            << "one live grant per device";
        EXPECT_FALSE(refused("UPDATE key_backup_grants SET revoked_at = NOW(), revoked_reason = 'manual' "
                             "WHERE device_id = $1 AND $2 > 0"));
        EXPECT_FALSE(refused("INSERT INTO key_backup_grants (device_id, user_id, origin) VALUES ($1, $2, 'approved')"))
            << "a new grant after a revocation";
        const auto grant = txn.exec("SELECT id FROM key_backup_grants WHERE revoked_at IS NULL").one_field_ref().as<int>();
        txn.exec("INSERT INTO key_backup_grant_vaults (grant_id, vault_id) VALUES ($1, 424242)", pqxx::params{grant});

        // A device paired after the migration: running the file again doesn't snapshot it.
        const auto later = txn.exec("INSERT INTO devices (user_id, name, platform, spki_sha256) VALUES ($1, 'New Mac', "
                                    "'macOS', repeat('f', 64)) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "130_key_backup_grants.sql")));
        EXPECT_TRUE(txn.exec("SELECT 1 FROM key_backup_grant_migration WHERE device_id = $1", pqxx::params{later}).empty());

        txn.exec("DELETE FROM devices WHERE id = $1", pqxx::params{live});
        EXPECT_TRUE(txn.exec("SELECT 1 FROM key_backup_grants WHERE device_id = $1", pqxx::params{live}).empty())
            << "grants go with their device";
        EXPECT_TRUE(txn.exec("SELECT 1 FROM key_backup_grant_vaults WHERE grant_id = $1", pqxx::params{grant}).empty());
        EXPECT_TRUE(txn.exec("SELECT 1 FROM key_backup_grant_migration WHERE device_id = $1", pqxx::params{live}).empty());
    });
}

// 131 (#371, recovered key versions) on a 130-era database: one new table, nothing existing changes, the CHECKs hold,
// a vault's removal takes its rows, and running the file again changes nothing.
TEST_F(SqlDeployerHistoryDb, VaultKeyOriginMigrationIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        txn.exec("DROP TABLE IF EXISTS vault_key_origin");
        txn.exec("DELETE FROM schema_migrations WHERE filename = '131_vault_key_origin.sql'");
        const auto vault = txn.exec("INSERT INTO vault (name, type, mount_point, uid) VALUES ('claude_test_131', 'local', "
                                    "'claude_test_131_mount', '00000000-0000-4000-8000-000000000131') RETURNING id")
                               .one_field_ref()
                               .as<int>();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "131_vault_key_origin.sql"));
        EXPECT_EQ(recordedHash(txn, "131_vault_key_origin.sql"), currentHash("131_vault_key_origin.sql"));
        EXPECT_TRUE(columnExists(txn, "vault_key_origin", "origin_node_id"));
        EXPECT_TRUE(txn.exec("SELECT 1 FROM vault_key_origin").empty()) << "no vault gets an origin by migration";

        const auto refused = [&](const std::string& values) {
            pqxx::subtransaction sub(txn, "check");
            try {
                sub.exec("INSERT INTO vault_key_origin (vault_id, version, origin_node_id, origin_vault_id, "
                         "origin_key_check, attestation_key_id, attestation_public_key, attestation, anchor) VALUES " +
                             values,
                         pqxx::params{vault});
                sub.commit();
            } catch (const pqxx::sql_error&) {
                return true;
            }
            return false;
        };
        const std::string pk = "decode(repeat('ab', 32), 'hex')", sig = "decode(repeat('cd', 64), 'hex')";
        const std::string check = "repeat('0', 32)";
        EXPECT_TRUE(refused("($1, 0, 'n', 1, " + check + ", 1, " + pk + ", " + sig + ", 'kit')")) << "version >= 1";
        EXPECT_TRUE(refused("($1, 1, 'n', 1, 'ABC', 1, " + pk + ", " + sig + ", 'kit')")) << "key check hex";
        EXPECT_TRUE(refused("($1, 1, 'n', 1, " + check + ", 1, decode('ab', 'hex'), " + sig + ", 'kit')"))
            << "32-byte public key";
        EXPECT_TRUE(refused("($1, 1, 'n', 1, " + check + ", 1, " + pk + ", decode('cd', 'hex'), 'kit')"))
            << "64-byte signature";
        EXPECT_TRUE(refused("($1, 1, 'n', 1, " + check + ", 1, " + pk + ", " + sig + ", 'bucket')"))
            << "anchored only by customer material";
        EXPECT_FALSE(refused("($1, 1, 'n', 1, " + check + ", 1, " + pk + ", " + sig + ", 'kit')"));
        EXPECT_TRUE(refused("($1, 1, 'n', 1, " + check + ", 1, " + pk + ", " + sig + ", 'export')"))
            << "one row per version";
        txn.exec("DELETE FROM vault WHERE id = $1", pqxx::params{vault});
        EXPECT_TRUE(txn.exec("SELECT 1 FROM vault_key_origin").empty()) << "the rows go with their vault";

        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "131_vault_key_origin.sql")));
    });
}

// 158 + 159 (server mirror phase 1b) on a 157-era database with realistic rows: built-in and ordinary accounts, a
// group, role templates, a local vault and an opaque_v1 bucket vault with folders, symlinks, files, trash and
// snapshots, some uids already published (the manifest collector gave the opaque vault's folders theirs). Afterwards
// every folder, symlink and snapshot has its uid, every uid that was set is unchanged, every account is local and
// otherwise untouched (no identity log entry, change-journal row or updated_at), the columns are NOT NULL and
// immutable, and running everything again changes nothing.
TEST_F(SqlDeployerHistoryDb, PermanentIdsMigration158BackfillsEveryRowKeepsEveryUidAndIsIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        // ---- back to the 157 schema (remote accounts an earlier suite left here first: 157 had none)
        txn.exec("DELETE FROM users WHERE remote");
        txn.exec("DELETE FROM groups WHERE remote");
        for (const auto* t : {"users", "groups"})
            txn.exec(std::string("DROP TRIGGER IF EXISTS vh_remote_account_guard ON ") + t);
        for (const auto* t : {"refresh_tokens", "webauthn_credentials", "totp_factors", "recovery_code_batches",
                              "recovery_codes", "devices", "connector_grants", "key_backup_grants",
                              "admin_role_assignments", "user_global_vault_policy", "s3_gateway_credentials",
                              "peer_vault_policy" /* 162's, on 158's function */})
            txn.exec(std::string("DROP TRIGGER IF EXISTS vh_refuse_remote_account ON ") + t);
        txn.exec("DROP FUNCTION IF EXISTS vh_remote_account_guard()");
        txn.exec("DROP FUNCTION IF EXISTS vh_refuse_remote_account()");
        txn.exec("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_remote_check");
        txn.exec("ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_remote_check");
        txn.exec("DROP INDEX IF EXISTS users_local_name_key");
        txn.exec("DROP INDEX IF EXISTS users_local_email_key");
        txn.exec("DROP INDEX IF EXISTS groups_local_name_key");
        txn.exec("DROP INDEX IF EXISTS users_remote_home_key");
        txn.exec("DROP INDEX IF EXISTS groups_remote_home_key");
        for (const auto* c : {"home_node", "home_id", "remote"}) {
            txn.exec(std::string("ALTER TABLE users DROP COLUMN IF EXISTS ") + c);
            txn.exec(std::string("ALTER TABLE groups DROP COLUMN IF EXISTS ") + c);
        }
        txn.exec("ALTER TABLE users ADD CONSTRAINT users_name_key UNIQUE (name)");
        txn.exec("ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email)");
        txn.exec("ALTER TABLE groups ADD CONSTRAINT groups_name_key UNIQUE (name)");
        for (const auto* t : {"directories", "symlinks", "recovery_snapshot"})
            txn.exec(std::string("ALTER TABLE ") + t + " ALTER COLUMN uid DROP NOT NULL");
        txn.exec("DELETE FROM schema_migrations WHERE filename IN ('158_permanent_ids.sql', "
                 "'159_permanent_ids_required.sql')");
        ASSERT_FALSE(columnExists(txn, "users", "remote"));

        // ---- rows as a 157-era install has them
        txn.exec("SELECT set_config('vaulthalla.bootstrap', 'on', true)");  // the protected flags are bootstrap-only
        txn.exec("INSERT INTO users (name, password_hash, protected, system_only) VALUES ('root', 'x', TRUE, TRUE), "
                 "('system', 'x', TRUE, TRUE), ('admin', 'x', TRUE, FALSE) ON CONFLICT (name) DO NOTHING");
        txn.exec("SELECT set_config('vaulthalla.bootstrap', 'off', true)");
        const auto owner = txn.exec("INSERT INTO users (name, email, password_hash) VALUES ('claude_test_158_owner', "
                                    "'claude_test_158@vaulthalla.test', 'x') RETURNING id").one_field_ref().as<int>();
        txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_158_other', 'x')");
        const auto group = txn.exec("INSERT INTO groups (name) VALUES ('claude_test_158_group') RETURNING id")
                               .one_field_ref().as<int>();
        txn.exec("INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)", pqxx::params{group, owner});
        for (const auto& role : builtInAdminRoles())
            txn.exec("INSERT INTO admin_role (name, description, identity_permissions, audit_permissions, "
                     "settings_permissions, roles_permissions, vaults_permissions, keys_permissions) VALUES ($1, '', "
                     "B'0'::bit(32), B'0'::bit(8), B'0'::bit(64), B'0'::bit(16), B'0'::bit(32), B'0'::bit(32)) "
                     "ON CONFLICT (name) DO NOTHING", pqxx::params{role.name});
        for (const std::string name : {"reader", "power_user", "claude_test_158_custom"})
            txn.exec("INSERT INTO vault_role (name, description, files_permissions, directories_permissions, "
                     "sync_permissions, roles_permissions) VALUES ($1, '', B'0'::bit(32), B'0'::bit(32), B'0'::bit(32), "
                     "B'0'::bit(16)) ON CONFLICT (name) DO NOTHING", pqxx::params{name});

        const auto vault = [&](const std::string& name, const std::string& type) {
            return txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES ($1, $2, $3, $4, "
                            "gen_random_uuid()) RETURNING id",
                            pqxx::params{name, owner, type, name}).one_field_ref().as<int>();
        };
        const auto local = vault("claude_test_158_local", "local");
        const auto opaque = vault("claude_test_158_opaque", "s3");
        txn.exec("INSERT INTO s3 (vault_id, bucket, encrypt_upstream, storage_layout) VALUES ($1, 'b158', TRUE, "
                 "'opaque_v1')", pqxx::params{opaque});
        const auto entry = [&](const int vaultId, const std::optional<int> parent, const std::string& name,
                               const std::string& path) {
            return txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, path) VALUES ($1, $2, $3, $4) RETURNING id",
                            pqxx::params{vaultId, parent, name, path}).one_field_ref().as<int>();
        };
        // The opaque vault published a manifest: its folders and its symlink have the collector's uids.
        const auto published = [] { return vh::crypto::id::toUuid(vh::crypto::id::newObjectUid()); };
        const auto opaqueRoot = entry(opaque, std::nullopt, "", "/");
        const auto opaqueDir = entry(opaque, opaqueRoot, "docs", "/docs");
        const auto opaqueNew = entry(opaque, opaqueRoot, "new", "/new");   // made after the last publish: no uid yet
        const auto opaqueLink = entry(opaque, opaqueRoot, "latest", "/latest");
        const auto opaqueFile = entry(opaque, opaqueDir, "a.txt", "/docs/a.txt");
        const auto rootUid = published(), dirUid = published(), linkUid = published();
        txn.exec("INSERT INTO directories (fs_entry_id, uid) VALUES ($1, $2::uuid), ($3, $4::uuid), ($5, NULL)",
                 pqxx::params{opaqueRoot, rootUid, opaqueDir, dirUid, opaqueNew});
        txn.exec("INSERT INTO symlinks (fs_entry_id, target, uid) VALUES ($1, 'docs/a.txt', $2::uuid)",
                 pqxx::params{opaqueLink, linkUid});
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, object_uid) VALUES ($1, 1, gen_random_uuid())",
                 pqxx::params{opaqueFile});
        // The local vault never published: nothing has a uid.
        const auto localRoot = entry(local, std::nullopt, "", "/");
        const auto localDir = entry(local, localRoot, "photos", "/photos");
        const auto localLink = entry(local, localRoot, "shortcut", "/shortcut");
        txn.exec("INSERT INTO directories (fs_entry_id) VALUES ($1), ($2)", pqxx::params{localRoot, localDir});
        txn.exec("INSERT INTO symlinks (fs_entry_id, target) VALUES ($1, 'photos')", pqxx::params{localLink});
        // Trash: from before 125 on both (no object uid), and one that kept it on the opaque vault.
        const auto trash = [&](const int vaultId, const std::string& path, const std::optional<std::string>& uid) {
            return txn.exec("INSERT INTO files_trashed (vault_id, path, backing_path, base32_alias, object_uid) "
                            "VALUES ($1, $2, '', rpad($2, 33, 'x'), $3::uuid) RETURNING id",
                            pqxx::params{vaultId, path, uid}).one_field_ref().as<int>();
        };
        const auto trashedUid = published();
        const auto localTrash = trash(local, "/old.jpg", std::nullopt);
        const auto opaqueTrashOld = trash(opaque, "/docs/old.txt", std::nullopt);
        const auto opaqueTrashKept = trash(opaque, "/docs/kept.txt", trashedUid);
        // Snapshots: a published one with its uid, one still being made.
        const auto snapshotUid = published();
        const auto snap = [&](const int vaultId, const std::string& state, const std::optional<std::string>& uid) {
            return txn.exec("INSERT INTO recovery_snapshot (vault_id, root_path, root_type, state, uid) "
                            "VALUES ($1, '/', 'directory', $2, $3::uuid) RETURNING id",
                            pqxx::params{vaultId, state, uid}).one_field_ref().as<int64_t>();
        };
        const auto readySnap = snap(opaque, "ready", snapshotUid);
        const auto creatingSnap = snap(local, "creating", std::nullopt);
        const auto count = [&](const std::string& query) { return txn.exec(query).one_field_ref().as<int64_t>(); };
        const auto identityLog = count("SELECT count(*) FROM identity_change_log");
        const auto changeJournal = count("SELECT count(*) FROM fs_change_log");
        const auto updatedAt = [&] {
            return txn.exec("SELECT string_agg(id || '=' || updated_at::text, ',' ORDER BY id) FROM users")
                .one_field_ref().as<std::string>();
        };
        const auto updatedBefore = updatedAt();

        // ---- the upgrade
        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, "158_permanent_ids.sql"));
        EXPECT_TRUE(applied(report, "159_permanent_ids_required.sql"));
        EXPECT_EQ(recordedHash(txn, "158_permanent_ids.sql"), currentHash("158_permanent_ids.sql"));

        for (const auto* t : {"directories", "symlinks", "recovery_snapshot"}) {
            EXPECT_EQ(count(std::string("SELECT count(*) FROM ") + t + " WHERE uid IS NULL"), 0) << t;
            EXPECT_EQ(txn.exec("SELECT is_nullable FROM information_schema.columns WHERE table_schema = current_schema() "
                               "AND table_name = $1 AND column_name = 'uid'", pqxx::params{std::string(t)})
                          .one_field_ref().as<std::string>(), "NO") << t;
        }
        const auto uidOf = [&](const std::string& query, const pqxx::params& params) {
            return txn.exec(query, params).one_field_ref().as<std::string>();
        };
        EXPECT_EQ(uidOf("SELECT uid::text FROM directories WHERE fs_entry_id = $1", pqxx::params{opaqueRoot}), rootUid)
            << "a published uid never changes";
        EXPECT_EQ(uidOf("SELECT uid::text FROM directories WHERE fs_entry_id = $1", pqxx::params{opaqueDir}), dirUid);
        EXPECT_EQ(uidOf("SELECT uid::text FROM symlinks WHERE fs_entry_id = $1", pqxx::params{opaqueLink}), linkUid);
        EXPECT_EQ(uidOf("SELECT uid::text FROM recovery_snapshot WHERE id = $1", pqxx::params{readySnap}), snapshotUid);
        EXPECT_EQ(uidOf("SELECT object_uid::text FROM files_trashed WHERE id = $1", pqxx::params{opaqueTrashKept}),
                  trashedUid);
        EXPECT_FALSE(txn.exec("SELECT uid FROM recovery_snapshot WHERE id = $1", pqxx::params{creatingSnap})
                         .one_field_ref().is_null());
        EXPECT_FALSE(txn.exec("SELECT object_uid FROM files_trashed WHERE id = $1", pqxx::params{localTrash})
                         .one_field_ref().is_null()) << "a trashed file outside opaque_v1 gets a uid";
        EXPECT_TRUE(txn.exec("SELECT object_uid FROM files_trashed WHERE id = $1", pqxx::params{opaqueTrashOld})
                        .one_field_ref().is_null()) << "an opaque_v1 trash row never gets an invented object uid";

        // Accounts, groups and roles get no second id; every existing account and group is local. Folders and
        // symlinks: raw libsodium bytes.
        for (const auto* t : {"users", "groups", "vault_role", "admin_role"})
            EXPECT_FALSE(columnExists(txn, t, "uid")) << t;
        for (const auto* t : {"users", "groups"})
            EXPECT_EQ(count(std::string("SELECT count(*) FROM ") + t +
                            " WHERE remote OR home_node IS NOT NULL OR home_id IS NOT NULL"), 0) << t;
        EXPECT_GT(count("SELECT count(*) FROM (SELECT d.uid::text AS t FROM directories d JOIN fs_entry e ON "
                        "e.id = d.fs_entry_id WHERE e.vault_id = " + std::to_string(local) + " UNION ALL SELECT "
                        "uid::text FROM directories WHERE fs_entry_id = " + std::to_string(opaqueNew) +
                        " UNION ALL SELECT uid::text FROM symlinks WHERE fs_entry_id = " + std::to_string(localLink) +
                        ") u WHERE substr(t, 15, 1) <> '4'"), 0)
            << "folder and symlink uids come from libsodium, not gen_random_uuid()";

        // The backfill touched no identity, access or file history.
        EXPECT_EQ(count("SELECT count(*) FROM identity_change_log"), identityLog);
        EXPECT_EQ(count("SELECT count(*) FROM fs_change_log"), changeJournal);
        EXPECT_EQ(updatedAt(), updatedBefore);

        // From here on: NOT NULL and immutable; accounts insert as before, and identity tracking still sees them.
        {
            pqxx::subtransaction noUid(txn, "no_uid");
            EXPECT_THROW(noUid.exec("INSERT INTO directories (fs_entry_id) VALUES ($1)", pqxx::params{opaqueFile}),
                         pqxx::not_null_violation);
        }
        {
            pqxx::subtransaction change(txn, "change");
            EXPECT_THROW(change.exec("UPDATE directories SET uid = gen_random_uuid() WHERE fs_entry_id = $1",
                                     pqxx::params{opaqueDir}), pqxx::sql_error);
        }
        EXPECT_NO_THROW(txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_158_new', 'x')"));
        txn.exec("UPDATE users SET email = 'claude_test_158_b@vaulthalla.test' WHERE id = $1", pqxx::params{owner});
        EXPECT_GT(count("SELECT count(*) FROM identity_change_log"), identityLog) << "identity tracking is on";

        const auto snapshot = [&] {
            return txn.exec("SELECT concat_ws('|', "
                            "(SELECT string_agg(uid::text, ',' ORDER BY fs_entry_id) FROM directories), "
                            "(SELECT string_agg(uid::text, ',' ORDER BY fs_entry_id) FROM symlinks), "
                            "(SELECT string_agg(uid::text, ',' ORDER BY id) FROM recovery_snapshot), "
                            "(SELECT string_agg(COALESCE(object_uid::text, '-'), ',' ORDER BY id) FROM files_trashed))")
                .one_field_ref().as<std::string>();
        };
        const auto before = snapshot();
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "158_permanent_ids.sql")));
        ASSERT_NO_THROW(migseed::assignPermanentIds(txn));
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / "159_permanent_ids_required.sql")));
        EXPECT_EQ(snapshot(), before) << "running 158, its data step and 159 again changes nothing";
    });
}

// Migration 160 (the replication log of a mirrored vault): new tables, functions and triggers only. On an upgraded
// database with a tree in it, it changes no existing row and writes no log row (nothing is mirrored), and a second run
// of the file changes nothing.
TEST_F(SqlDeployerHistoryDb, ReplicationLogMigration160IsAdditiveAndWritesNothingUntilAVaultIsMirrored) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "160_replication_log.sql";
        const auto count = [&](const std::string& q) { return txn.exec(q).one_field_ref().as<int64_t>(); };

        // ---- back to the 159 schema
        for (const auto* t : {"fs_entry", "files", "directories", "symlinks", "files_trashed", "vault", "sync", "fsync",
                              "rsync", "vault_recovery_policy", "vault_keys"})
            // 165's write gate hangs off a vh_mirror_ function too (its triggers go first, or the function can't).
            for (const auto* trigger : {"vh_mirror_track", "vh_mirror_track_update", "vh_mirror_track_delete",
                                        "vh_mirror_gate", "vh_mirror_gate_update"})
                txn.exec(std::string("DROP TRIGGER IF EXISTS ") + trigger + " ON " + t);
        txn.exec("DROP TABLE IF EXISTS vault_replication_log, mirror_entry_hash, mirror_vault");
        txn.exec("DO $$ DECLARE f RECORD; BEGIN "
                 "  FOR f IN SELECT p.oid::regprocedure AS sig, p.prokind FROM pg_proc p "
                 "           WHERE p.proname LIKE 'vh\\_mirror\\_%' AND p.pronamespace = current_schema()::regnamespace "
                 "           ORDER BY p.prokind = 'a' DESC LOOP "
                 "    EXECUTE format(CASE WHEN f.prokind = 'a' THEN 'DROP AGGREGATE %s' ELSE 'DROP FUNCTION %s' END, f.sig); "
                 "  END LOOP; END $$");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});
        ASSERT_EQ(count("SELECT count(*) FROM pg_proc WHERE proname LIKE 'vh\\_mirror\\_%'"), 0);

        // ---- a tree as an upgraded install has it
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_160_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_160', $1, 'local', 'claude_test_160', gen_random_uuid()) RETURNING id", pqxx::params{owner}).one_field_ref().as<int>();
        const auto root = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, '', '/') RETURNING id",
                                   pqxx::params{vault}).one_field_ref().as<int>();
        txn.exec("INSERT INTO directories (fs_entry_id, uid) VALUES ($1, gen_random_uuid())", pqxx::params{root});
        const auto file1 = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, path, created_by) "
                                    "VALUES ($1, $2, 'a.txt', '/a.txt', $3) RETURNING id",
                                    pqxx::params{vault, root, owner}).one_field_ref().as<int>();
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, encryption_iv, encrypted_with_key_version, object_uid) "
                 "VALUES ($1, 1, '', 0, gen_random_uuid())", pqxx::params{file1});
        const auto rows = [&] {
            return txn.exec("SELECT md5(string_agg(t, ',' ORDER BY t)) FROM ("
                            "  SELECT e::text AS t FROM fs_entry e WHERE e.vault_id = $1 "
                            "  UNION ALL SELECT f::text FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                            "  WHERE e.vault_id = $1) x", pqxx::params{vault}).one_field_ref().as<std::string>();
        };
        const auto rowsBefore = rows();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(report.applied.size(), 1u) << "only 160 was missing";
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));
        for (const auto* t : {"mirror_vault", "mirror_entry_hash", "vault_replication_log"})
            EXPECT_TRUE(columnExists(txn, t, "vault_id")) << t;
        EXPECT_EQ(count("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'vh\\_mirror\\_track%' AND NOT tgisinternal"),
                  23);
        EXPECT_EQ(rows(), rowsBefore) << "no existing row changes";

        // Nothing is mirrored: writes log nothing, and no existing row changed.
        txn.exec("UPDATE fs_entry SET name = 'b.txt', path = '/b.txt' WHERE id = $1", pqxx::params{file1});
        txn.exec("UPDATE fs_entry SET name = 'a.txt', path = '/a.txt' WHERE id = $1", pqxx::params{file1});
        EXPECT_EQ(count("SELECT count(*) FROM vault_replication_log"), 0);
        EXPECT_EQ(count("SELECT count(*) FROM mirror_entry_hash"), 0);

        // A second run of the file, and of the deployer, changes nothing.
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
        EXPECT_EQ(count("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'vh\\_mirror\\_track%' AND NOT tgisinternal"),
                  23);
        EXPECT_EQ(count("SELECT count(*) FROM vault_replication_log"), 0);
    });
}

// Migration 162 (a linked server's vault role): on an upgraded database with assignments and a mirrored vault in it,
// the peer subject, the link's default and the mirror's grant columns are added, existing rows are untouched, and a
// second run of the file changes nothing. Afterwards a peer assignment must name a peer row, takes no override, and a
// grant is all or nothing and never on a core row.
TEST_F(SqlDeployerHistoryDb, PeerVaultRoleMigration162IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "162_peer_vault_role.sql";
        const auto count = [&](const std::string& q) { return txn.exec(q).one_field_ref().as<int64_t>(); };

        // ---- back to the 161 schema
        txn.exec("DROP TRIGGER IF EXISTS vh_peer_vault_assignment_check ON vault_role_assignments");
        txn.exec("DROP TRIGGER IF EXISTS vh_peer_vault_override_check ON vault_permission_overrides");
        txn.exec("DROP FUNCTION IF EXISTS vh_peer_vault_assignment_check(), vh_peer_vault_override_check()");
        txn.exec("DROP TABLE IF EXISTS peer_vault_policy");
        txn.exec("ALTER TABLE mirror_vault DROP CONSTRAINT IF EXISTS mirror_vault_grant_check");
        for (const auto* c : {"granted_role_name", "granted_files_permissions", "granted_directories_permissions",
                              "granted_sync_permissions", "granted_roles_permissions", "granted_by_node", "granted_at"})
            txn.exec(std::string("ALTER TABLE mirror_vault DROP COLUMN IF EXISTS ") + c);
        txn.exec("ALTER TABLE vault_role_assignments DROP CONSTRAINT vault_role_assignments_subject_type_check");
        txn.exec("ALTER TABLE vault_role_assignments ADD CONSTRAINT vault_role_assignments_subject_type_check "
                 "CHECK (subject_type IN ('user', 'group'))");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});

        // ---- what an upgraded install holds: a user's and a group's assignments, a linked server, a mirrored vault
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_162_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto group = txn.exec("INSERT INTO groups (name) VALUES ('claude_test_162_group') RETURNING id")
                               .one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_162', $1, 'local', 'claude_test_162', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        const auto role = txn.exec("INSERT INTO vault_role (name, files_permissions, directories_permissions, "
                                   "  sync_permissions, roles_permissions) "
                                   "VALUES ('claude_test_162_role', 1::bigint::bit(32), 0::bit(32), 0::bit(32), 0::bit(16)) "
                                   "RETURNING id").one_field_ref().as<int>();
        txn.exec("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) VALUES "
                 "($1, 'user', $2, $3), ($1, 'group', $4, $3)",
                 pqxx::params{vault, owner, role, group});
        const auto peer = txn.exec("INSERT INTO peer (node_id, name, spki_sha256, wrap_public_key) "
                                   "VALUES ('claude-162-node', 'vps', repeat('ab', 32), decode(repeat('00', 32), 'hex')) "
                                   "RETURNING id")
                              .one_field_ref().as<int>();
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role) VALUES ($1, $2, 'core')", pqxx::params{vault, peer});
        const auto rows = [&] {
            return txn.exec("SELECT md5(string_agg(t, ',' ORDER BY t)) FROM ("
                            "  SELECT (id, vault_id, subject_type, subject_id, role_id, assigned_at)::text AS t "
                            "  FROM vault_role_assignments "
                            "  UNION ALL SELECT (vault_id, peer_id, role, term, last_seq, digest, state)::text "
                            "  FROM mirror_vault) x").one_field_ref().as<std::string>();
        };
        const auto rowsBefore = rows();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(report.applied.size(), 1u) << "only 162 was missing";
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));
        EXPECT_TRUE(columnExists(txn, "peer_vault_policy", "role_id"));
        for (const auto* c : {"granted_role_name", "granted_files_permissions", "granted_by_node", "granted_at"})
            EXPECT_TRUE(columnExists(txn, "mirror_vault", c)) << c;
        EXPECT_EQ(rows(), rowsBefore) << "existing assignments and mirror rows untouched";
        EXPECT_EQ(count("SELECT count(*) FROM mirror_vault WHERE granted_role_name IS NOT NULL"), 0);

        // A second run of the file, and of the deployer, changes nothing.
        const auto schema = [&] {
            return txn.exec("SELECT md5(string_agg(conname || ':' || pg_get_constraintdef(oid), ',' ORDER BY conname)) "
                            "FROM pg_constraint WHERE conrelid IN ('vault_role_assignments'::regclass, "
                            "  'mirror_vault'::regclass, 'peer_vault_policy'::regclass)").one_field_ref().as<std::string>();
        };
        const auto schemaBefore = schema();
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
        EXPECT_EQ(schema(), schemaBefore);
        EXPECT_EQ(rows(), rowsBefore);
        EXPECT_EQ(count("SELECT count(*) FROM pg_constraint WHERE conrelid = 'vault_role_assignments'::regclass "
                        "AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%subject_type%'"), 1);
        EXPECT_EQ(count("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'vh\\_peer\\_vault\\_%' AND NOT tgisinternal"), 2);

        // ---- what it allows and refuses
        const auto refused = [&](const std::string& q, const pqxx::params& params) {
            pqxx::subtransaction sub(txn, "claude_162");
            try {
                sub.exec(q, params);
            } catch (const pqxx::sql_error&) {
                sub.abort();
                return true;
            }
            sub.abort();
            return false;
        };
        txn.exec("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) VALUES ($1, 'peer', $2, $3)",
                 pqxx::params{vault, peer, role});
        EXPECT_TRUE(refused("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
                            "VALUES ($1, 'peer', $2, $3)", pqxx::params{vault, peer + 100000, role}))
            << "a peer assignment names a peer row";
        EXPECT_TRUE(refused("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
                            "VALUES ($1, 'device', 1, $2)", pqxx::params{vault, role}));
        const auto peerAssignment = txn.exec("SELECT id FROM vault_role_assignments WHERE subject_type = 'peer' AND vault_id = $1",
                                             pqxx::params{vault}).one_field_ref().as<int>();
        const auto perm = txn.exec("SELECT id FROM permission ORDER BY id LIMIT 1").one_field_ref().as<int>();
        EXPECT_TRUE(refused("INSERT INTO vault_permission_overrides (assignment_id, permission_id, glob_path, effect) "
                            "VALUES ($1, $2, '/**', 'allow')", pqxx::params{peerAssignment, perm}))
            << "a linked server's role takes no path override";
        txn.exec("INSERT INTO peer_vault_policy (peer_id, role_id, set_by) VALUES ($1, $2, $3)",
                 pqxx::params{peer, role, owner});
        EXPECT_TRUE(refused("DELETE FROM vault_role WHERE id = $1", pqxx::params{role})) << "a default role in use stays";
        EXPECT_TRUE(refused("UPDATE mirror_vault SET granted_role_name = 'reader' WHERE vault_id = $1", pqxx::params{vault}))
            << "a grant is all or nothing";
        EXPECT_TRUE(refused("UPDATE mirror_vault SET granted_role_name = 'reader', granted_files_permissions = 0::bit(32), "
                            "  granted_directories_permissions = 0::bit(32), granted_sync_permissions = 0::bit(32), "
                            "  granted_roles_permissions = 0::bit(16), granted_by_node = 'n', granted_at = now() "
                            "WHERE vault_id = $1", pqxx::params{vault}))
            << "never on a vault this server is the core of";
        txn.exec("UPDATE mirror_vault SET role = 'mirror', granted_role_name = 'reader', "
                 "  granted_files_permissions = 5::bigint::bit(32), granted_directories_permissions = 0::bit(32), "
                 "  granted_sync_permissions = 0::bit(32), granted_roles_permissions = 0::bit(16), "
                 "  granted_by_node = 'claude-162-node', granted_at = now() WHERE vault_id = $1",
                 pqxx::params{vault});
        EXPECT_EQ(count("SELECT granted_files_permissions::bigint FROM mirror_vault WHERE vault_id = " +
                        std::to_string(vault)), 5);
    });
}


// Migration 166 (a change made on the mirror): on an upgraded database with a mirrored vault in it, the pending,
// dirty, held and submission tables are added empty, nothing existing changes, and a second run of the file changes
// nothing.
TEST_F(SqlDeployerHistoryDb, MirrorPendingMigration166IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "166_mirror_pending.sql";
        const auto count = [&](const std::string& q) { return txn.exec(q).one_field_ref().as<int64_t>(); };

        // ---- back to the 165 schema: no tables of 166, and 160's and 164's functions as those migrations left them
        txn.exec("DROP TABLE IF EXISTS mirror_pending, mirror_dirty, mirror_held, mirror_submission");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});
        const auto definition = [](const std::string& migration, const std::string& name) {
            const auto text = migseed::readFileToString(repoPsqlDir() / migration);
            const auto at = text.find("CREATE OR REPLACE FUNCTION " + name + "(");
            const auto end = at == std::string::npos ? at : text.find("\n$$ LANGUAGE", at);
            const auto semi = end == std::string::npos ? end : text.find(';', end);
            EXPECT_NE(semi, std::string::npos) << name << " in " << migration;
            return semi == std::string::npos ? std::string{} : text.substr(at, semi + 1 - at);
        };
        const std::vector<std::pair<std::string, std::string>> replaced{
            {"164_mirror_follow.sql", "vh_mirror_entry_state"}, {"164_mirror_follow.sql", "vh_mirror_tree_states"},
            {"160_replication_log.sql", "vh_mirror_log_state"}, {"160_replication_log.sql", "vh_mirror_track_trash"}};
        for (const auto& [migration, name] : replaced) txn.exec(definition(migration, name));
        txn.exec("DROP FUNCTION IF EXISTS vh_mirror_upload_staging(text)");
        const auto excludesStaging = [&](const std::string& name) {
            return txn.exec("SELECT pg_get_functiondef(p.oid) LIKE '%vh_mirror_upload_staging%' FROM pg_proc p "
                            "WHERE p.proname = $1",
                            pqxx::params{name}).one_field_ref().as<bool>();
        };
        for (const auto& [migration, name] : replaced) ASSERT_FALSE(excludesStaging(name)) << name << " as " << migration;

        // ---- what an upgraded install holds: a vault mirrored with a linked server
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_166_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_166', $1, 'local', 'claude_test_166', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        const auto peer = txn.exec("INSERT INTO peer (node_id, name, spki_sha256, wrap_public_key) "
                                   "VALUES ('claude-166-node', 'vps', repeat('cd', 32), decode(repeat('00', 32), 'hex')) "
                                   "RETURNING id")
                              .one_field_ref().as<int>();
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role) VALUES ($1, $2, 'core')", pqxx::params{vault, peer});
        const auto rows = [&] {
            return txn.exec("SELECT md5(string_agg(t, ',' ORDER BY t)) FROM ("
                            "  SELECT (vault_id, peer_id, role, term, last_seq, digest, state)::text AS t "
                            "  FROM mirror_vault) x").one_field_ref().as<std::string>();
        };
        const auto rowsBefore = rows();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(report.applied.size(), 1u) << "only 166 was missing";
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));
        for (const auto* t : {"mirror_pending", "mirror_dirty", "mirror_held", "mirror_submission"})
            EXPECT_TRUE(columnExists(txn, t, "vault_id")) << t;
        for (const auto* t : {"mirror_pending", "mirror_dirty", "mirror_held", "mirror_submission"})
            EXPECT_EQ(count(std::string("SELECT count(*) FROM ") + t), 0) << t;
        EXPECT_EQ(rows(), rowsBefore) << "existing mirror rows untouched";
        // An HTTP upload's staging file is never content (the log, the tree, the trash): the four functions replaced.
        for (const auto& [migration, name] : replaced) EXPECT_TRUE(excludesStaging(name)) << name;
        EXPECT_TRUE(txn.exec("SELECT vh_mirror_upload_staging('.upload-http-0a1b-2.part')").one_field_ref().as<bool>());
        for (const auto* name : {"upload-http-0a1b-2.part", ".upload-http-0a1b-2.txt", "a.part", ".upload-https-x.part"})
            EXPECT_FALSE(txn.exec("SELECT vh_mirror_upload_staging($1)", pqxx::params{std::string(name)})
                             .one_field_ref().as<bool>())
                << name;

        // A second run of the file, and of the deployer, changes nothing.
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
        EXPECT_EQ(rows(), rowsBefore);

        // A vault that goes takes its pending, dirty and held rows with it.
        txn.exec("INSERT INTO mirror_pending (vault_id, request_id, entry_uid, op, actor_node, actor_id) "
                 "VALUES ($1, 'claude166request', gen_random_uuid(), 'mkdir', 'n', 1)", pqxx::params{vault});
        txn.exec("INSERT INTO mirror_dirty (vault_id, entry_uid, confirmed_kind) VALUES ($1, gen_random_uuid(), 'none')",
                 pqxx::params{vault});
        txn.exec("DELETE FROM mirror_vault WHERE vault_id = $1", pqxx::params{vault});
        txn.exec("DELETE FROM vault WHERE id = $1", pqxx::params{vault});
        EXPECT_EQ(count("SELECT count(*) FROM mirror_pending") + count("SELECT count(*) FROM mirror_dirty"), 0);
    });
}

TEST_F(SqlDeployerHistoryDb, MirrorSwitchMigration168IsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "168_mirror_switch.sql";
        // ---- back to the schema before 168
        for (const auto* c : {"resync_at", "resync_by", "resync_count", "scrubbed_at"})
            txn.exec(std::string("ALTER TABLE mirror_vault DROP COLUMN IF EXISTS ") + c);
        txn.exec("DROP TABLE IF EXISTS mirror_switch");
        // 164's state CHECK (no 'switching').
        txn.exec("ALTER TABLE mirror_vault DROP CONSTRAINT IF EXISTS mirror_vault_state_check");
        txn.exec("ALTER TABLE mirror_vault ADD CONSTRAINT mirror_vault_state_check "
                 "CHECK (state IN ('starting', 'live', 'paused', 'diverged', 'expired', 'stopped'))");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});

        // ---- an upgraded install: a vault mirrored with a linked server
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_168_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_168', $1, 'local', 'claude_test_168', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        const auto peer = txn.exec("INSERT INTO peer (node_id, name, spki_sha256, wrap_public_key) "
                                   "VALUES ('claude-168-node', 'vps', repeat('ce', 32), decode(repeat('00', 32), 'hex')) "
                                   "RETURNING id").one_field_ref().as<int>();
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role, term, last_seq) VALUES ($1, $2, 'mirror', 3, 7)",
                 pqxx::params{vault, peer});

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(report.applied.size(), 1u) << "only 168 was missing";
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));
        for (const auto* c : {"resync_at", "resync_by", "resync_count", "scrubbed_at"})
            EXPECT_TRUE(columnExists(txn, "mirror_vault", c)) << c;
        const auto row = txn.exec("SELECT term, last_seq, resync_count, resync_at IS NULL AS never, "
                                  "  scrubbed_at IS NULL AS unscrubbed FROM mirror_vault WHERE vault_id = $1",
                                  pqxx::params{vault}).one_row();
        EXPECT_EQ(row["term"].as<int>(), 3) << "the row is untouched";
        EXPECT_EQ(row["last_seq"].as<int>(), 7);
        EXPECT_EQ(row["resync_count"].as<int>(), 0);
        EXPECT_TRUE(row["never"].as<bool>());
        EXPECT_TRUE(row["unscrubbed"].as<bool>());
        // The planned switch: its table, the state it holds a vault in, the freeze in the triggers.
        EXPECT_TRUE(columnExists(txn, "mirror_switch", "switch_id"));
        EXPECT_TRUE(columnExists(txn, "mirror_switch", "accept_no_access"));
        EXPECT_NO_THROW(txn.exec("SAVEPOINT s168; UPDATE mirror_vault SET state = 'switching' WHERE vault_id = " +
                                 std::to_string(vault) + "; ROLLBACK TO SAVEPOINT s168"));
        EXPECT_NE(txn.exec("SELECT prosrc FROM pg_proc WHERE proname = 'vh_mirror_core_term'")
                      .one_field_ref().as<std::string>().find("'switching'"),
                  std::string::npos);

        // A second run of the file, and of the deployer, changes nothing.
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
    });
}

// Migration 167 (leaving a mirror, wave 5 piece A): on an upgraded database with mirror offers and expected contents in
// it, admin.mirror.detach goes to super_admin only (the fresh seed's grants), the offer and content CHECKs learn
// 'detached' and 'missing' without changing a row, mirror_detached and keep_versions are added empty, and a second run
// changes nothing.
TEST_F(SqlDeployerHistoryDb, MirrorLeaveMigration167MatchesFreshSeedAndIsAdditiveAndIdempotent) {
    inRolledBackTxn([](pqxx::work& txn) {
        const std::string file = "167_mirror_leave.sql";
        const auto count = [&](const std::string& q) { return txn.exec(q).one_field_ref().as<int64_t>(); };

        // ---- back to the 166 schema
        txn.exec("DROP TABLE IF EXISTS mirror_detached");
        txn.exec("ALTER TABLE admin_role DROP COLUMN IF EXISTS mirror_permissions");
        txn.exec("DELETE FROM permission WHERE name = 'admin.mirror.detach' AND category = 'admin'");
        for (const auto* c : {"keep_versions", "keep_versions_set_by", "keep_versions_set_at", "deleting_copy"})
            txn.exec(std::string("ALTER TABLE mirror_vault DROP COLUMN IF EXISTS ") + c);
        for (const auto* c : {"mirror_offer_state_check", "mirror_offer_copy_outcome_check", "mirror_offer_side_state_check",
                              "mirror_offer_finished_check"})
            txn.exec(std::string("ALTER TABLE mirror_offer DROP CONSTRAINT IF EXISTS ") + c);
        txn.exec("ALTER TABLE mirror_offer ADD CHECK (state IN ('offered', 'pending', 'accepted', 'keys_acked', "
                 "'installed', 'started', 'declined', 'cancelled', 'expired', 'failed', 'orphaned'))");
        txn.exec("ALTER TABLE mirror_offer ADD CHECK (copy_outcome IS NULL OR copy_outcome IN ('removed', 'kept', 'none'))");
        txn.exec("ALTER TABLE mirror_offer ADD CHECK ((side = 'core' AND state IN ('offered', 'accepted', 'keys_acked', "
                 "'started', 'declined', 'cancelled', 'expired', 'failed')) OR (side = 'mirror' AND state IN ('pending', "
                 "'accepted', 'installed', 'started', 'declined', 'cancelled', 'expired', 'failed', 'orphaned')))");
        txn.exec("ALTER TABLE mirror_offer ADD CHECK ((finished_at IS NULL) = (state IN ('offered', 'pending', 'accepted', "
                 "'keys_acked', 'installed')))");
        txn.exec("ALTER TABLE mirror_content_pending DROP CONSTRAINT IF EXISTS mirror_content_pending_state_check");
        txn.exec("ALTER TABLE mirror_content_pending ADD CHECK (state IN ('waiting', 'failed'))");
        txn.exec("DELETE FROM schema_migrations WHERE filename = $1", pqxx::params{file});
        // The built-in roles, as an upgraded install holds them.
        for (const auto& role : builtInAdminRoles())
            txn.exec(R"SQL(
                INSERT INTO admin_role (name, description, identity_permissions, audit_permissions, settings_permissions,
                                        roles_permissions, vaults_permissions, keys_permissions, s3_gateway_permissions)
                VALUES ($1, 'x', $2::bit(32), $3::bit(8), $4::bit(64), $5::bit(16), $6::bit(32), $7::bit(32), $8::bit(8))
                ON CONFLICT (name) DO NOTHING
            )SQL", pqxx::params{role.name, role.identities.toBitString(), role.audits.toBitString(),
                                role.settings.toBitString(), role.roles.toBitString(), role.vaults.toBitString(),
                                role.keys.toBitString(), role.s3Gateway.toBitString()});

        // ---- what an upgraded install holds: a linked server, a mirrored vault, its started offer, a file expected
        const auto owner = txn.exec("INSERT INTO users (name, password_hash) VALUES ('claude_test_167_owner', 'x') "
                                    "RETURNING id").one_field_ref().as<int>();
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point, uid) VALUES "
                                    "('claude_test_167', $1, 'local', 'claude_test_167', gen_random_uuid()) RETURNING id",
                                    pqxx::params{owner}).one_field_ref().as<int>();
        const auto peer = txn.exec("INSERT INTO peer (node_id, name, spki_sha256, wrap_public_key) "
                                   "VALUES ('claude-167-node', 'vps', repeat('ef', 32), decode(repeat('00', 32), 'hex')) "
                                   "RETURNING id")
                              .one_field_ref().as<int>();
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role) VALUES ($1, $2, 'mirror')", pqxx::params{vault, peer});
        const auto offerInsert = std::string(
            "INSERT INTO mirror_offer (offer_uid, side, peer_id, vault_uid, vault_id, core_vault_id, root_uid, name, owner, "
            "  state, copy_outcome, expires_at, finished_at) "
            "SELECT gen_random_uuid(), $3, $1, uid, id, 7, gen_random_uuid(), 'claude_test_167', '{}'::jsonb, $4, $5, "
            "  now() + interval '1 day', CASE WHEN $4 IN ('pending', 'offered') THEN NULL ELSE now() END "
            "FROM vault WHERE id = $2");
        txn.exec(offerInsert, pqxx::params{peer, vault, std::string("mirror"), std::string("started"),
                                           std::optional<std::string>{}});
        txn.exec("INSERT INTO mirror_content_pending (vault_id, object_uid, generation, key_version, size_bytes, "
                 "  content_hash, mtime_us) VALUES ($1, gen_random_uuid(), '', 1, 0, repeat('0', 64), 0)",
                 pqxx::params{vault});
        const auto rows = [&] {
            return txn.exec("SELECT md5(string_agg(t, ',' ORDER BY t)) FROM ("
                            "  SELECT (vault_id, peer_id, role, term, last_seq, state)::text AS t FROM mirror_vault "
                            "  UNION ALL SELECT (side, state, copy_outcome, notify)::text FROM mirror_offer "
                            "  UNION ALL SELECT (vault_id, object_uid, generation, state)::text FROM mirror_content_pending"
                            ") x").one_field_ref().as<std::string>();
        };
        const auto rowsBefore = rows();

        migseed::SqlDeployReport report;
        ASSERT_NO_THROW(report = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(applied(report, file));
        EXPECT_EQ(report.applied.size(), 1u) << "only 167 was missing";
        EXPECT_EQ(recordedHash(txn, file), currentHash(file));
        EXPECT_EQ(rows(), rowsBefore) << "no existing row changes";
        for (const auto& role : builtInAdminRoles()) {
            SCOPED_TRACE(role.name);
            const auto r = txn.exec("SELECT mirror_permissions::text FROM admin_role WHERE name = $1",
                                    pqxx::params{role.name});
            if (r.empty()) continue;   // a built-in role this database was never seeded with
            EXPECT_EQ(r[0][0].as<std::string>(), role.mirror.toBitString()) << "migration and fresh seed disagree";
        }
        EXPECT_EQ(txn.exec("SELECT mirror_permissions::text FROM admin_role WHERE name = 'super_admin'")
                      .one_row_ref()[0].as<std::string>(),
                  "00000001");
        EXPECT_EQ(count("SELECT count(*) FROM permission WHERE name = 'admin.mirror.detach' AND bit_position = 0"), 1);
        EXPECT_TRUE(columnExists(txn, "mirror_detached", "vault_uid"));
        EXPECT_TRUE(columnExists(txn, "mirror_vault", "keep_versions"));
        EXPECT_EQ(count("SELECT count(*) FROM mirror_detached"), 0);
        EXPECT_EQ(count("SELECT count(*) FROM mirror_vault WHERE keep_versions IS NOT NULL OR deleting_copy IS NOT NULL"), 0);

        // A second run of the file, and of the deployer, changes nothing.
        const auto schema = [&] {
            return txn.exec("SELECT md5(string_agg(conname || ':' || pg_get_constraintdef(oid), ',' ORDER BY conname)) "
                            "FROM pg_constraint WHERE conrelid IN ('mirror_offer'::regclass, "
                            "  'mirror_content_pending'::regclass, 'mirror_detached'::regclass)")
                .one_field_ref().as<std::string>();
        };
        const auto schemaBefore = schema();
        migseed::SqlDeployReport again;
        ASSERT_NO_THROW(again = migseed::SqlDeployer::applyDir(txn, repoPsqlDir()));
        EXPECT_TRUE(again.applied.empty());
        ASSERT_NO_THROW(txn.exec(migseed::readFileToString(repoPsqlDir() / file)));
        EXPECT_EQ(schema(), schemaBefore);
        EXPECT_EQ(rows(), rowsBefore);

        // ---- what it allows and refuses
        const auto refused = [&](const std::string& q, const pqxx::params& params) {
            pqxx::subtransaction sub(txn, "claude_167");
            try {
                sub.exec(q, params);
            } catch (const pqxx::sql_error&) {
                sub.abort();
                return true;
            }
            sub.abort();
            return false;
        };
        EXPECT_FALSE(refused(offerInsert, pqxx::params{peer, vault, std::string("mirror"), std::string("detached"),
                                                       std::optional<std::string>{}}))
            << "a mirror's offer ends detached";
        EXPECT_TRUE(refused(offerInsert, pqxx::params{peer, vault, std::string("core"), std::string("detached"),
                                                      std::optional<std::string>{}}))
            << "never the core's";
        EXPECT_FALSE(refused(offerInsert, pqxx::params{peer, vault, std::string("core"), std::string("cancelled"),
                                                       std::optional<std::string>("detached")}))
            << "the core records that its mirror left with a copy";
        EXPECT_TRUE(refused("UPDATE mirror_offer SET state = 'detached', finished_at = NULL WHERE vault_id = $1",
                            pqxx::params{vault}))
            << "detached is a finished state";
        EXPECT_FALSE(refused("UPDATE mirror_content_pending SET state = 'missing' WHERE vault_id = $1", pqxx::params{vault}));
        EXPECT_TRUE(refused("UPDATE mirror_content_pending SET state = 'lost' WHERE vault_id = $1", pqxx::params{vault}));
        EXPECT_TRUE(refused("UPDATE mirror_vault SET keep_versions = '[1]'::jsonb WHERE vault_id = $1", pqxx::params{vault}));
        EXPECT_FALSE(refused("UPDATE mirror_vault SET deleting_copy = 'remove' WHERE vault_id = $1", pqxx::params{vault}));
        EXPECT_TRUE(refused("UPDATE mirror_vault SET deleting_copy = 'keep' WHERE vault_id = $1", pqxx::params{vault}))
            << "the purge's choice is remove or leave";
        // A vault that goes takes its detach records with it.
        txn.exec("INSERT INTO mirror_detached (side, vault_id, vault_uid, peer_id) SELECT 'mirror', id, uid, $2 FROM vault "
                 "WHERE id = $1", pqxx::params{vault, peer});
        txn.exec("DELETE FROM mirror_offer WHERE vault_id = $1", pqxx::params{vault});
        txn.exec("DELETE FROM mirror_vault WHERE vault_id = $1", pqxx::params{vault});
        txn.exec("DELETE FROM vault WHERE id = $1", pqxx::params{vault});
        EXPECT_EQ(count("SELECT count(*) FROM mirror_detached WHERE peer_id = " + std::to_string(peer)), 0);
    });
}

} // namespace vh_sql_deployer_history_test
