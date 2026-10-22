// Regression guard for migrations that were edited in place after shipping (P0: 1.5.x -> 1.6.x upgrades
// crash-looped on "Migration file was modified after being applied: 060_acl.sql").
//
// Non-DB tests always run. DB-backed tests need VH_TEST_DB_{USER,PASS,HOST,PORT,NAME} and run every scenario
// inside a transaction that is rolled back, so they leave the test database exactly as they found it (apart from
// bringing it up to the current schema once, which init_tables_if_not_exists() does in other suites too).

#include "seed/include/SqlDeployer.hpp"
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
        const auto vaultId = txn.exec("INSERT INTO vault (type, name, owner_id, mount_point) "
                                      "VALUES ('s3', 'claude_test_107_vault', $1, '0123456789ABCDEFGHJKMNPQRSTVWX107') "
                                      "RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();
        const auto fileId = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, 'f.txt', '/f.txt') "
                                     "RETURNING id", pqxx::params{vaultId}).one_field_ref().as<int>();
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes) VALUES ($1, 1)", pqxx::params{fileId});
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
        const auto vaultId = txn.exec("INSERT INTO vault (type, name, owner_id, mount_point) "
                                      "VALUES ('local', 'claude_test_111_vault', $1, '0123456789ABCDEFGHJKMNPQRSTVWX111') "
                                      "RETURNING id", pqxx::params{userId}).one_field_ref().as<int>();
        const auto fileId = txn.exec("INSERT INTO fs_entry (vault_id, name, path) VALUES ($1, 'v.txt', '/v.txt') "
                                     "RETURNING id", pqxx::params{vaultId}).one_field_ref().as<int>();
        txn.exec("INSERT INTO files (fs_entry_id, size_bytes) VALUES ($1, 5)", pqxx::params{fileId});
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

        // Every vault starts without a policy; the trigger guards retired keys still needed by recoverable data.
        EXPECT_EQ(txn.exec("SELECT count(*) FROM vault_recovery_policy").one_field_ref().as<int>(), 0);
        EXPECT_EQ(txn.exec("SELECT count(*) FROM pg_trigger WHERE tgname = 'recovery_guard_retired_vault_key' "
                           "AND tgrelid = 'vault_keys_trashed'::regclass").one_field_ref().as<int>(), 1);
        txn.exec("INSERT INTO vault_keys_trashed (vault_id, version, encrypted_key, iv) VALUES ($1, 1, '\\x00', '\\x00')",
                 pqxx::params{vaultId});
        txn.exec("INSERT INTO recovery_blob (vault_id, storage_name, encryption_iv, key_version, cipher_bytes, "
                 "plaintext_bytes) VALUES ($1, 'abcdefghijklmnopqrstuvwxyz012345', 'iv', 1, 16, 0)",
                 pqxx::params{vaultId});
        {
            pqxx::subtransaction guarded(txn, "guarded");
            EXPECT_THROW(guarded.exec("DELETE FROM vault_keys_trashed WHERE vault_id = $1", pqxx::params{vaultId}),
                         pqxx::foreign_key_violation);
        }
        txn.exec("DELETE FROM vault WHERE id = $1", pqxx::params{vaultId});   // the vault's own deletion still cascades
        EXPECT_EQ(txn.exec("SELECT count(*) FROM vault_keys_trashed WHERE vault_id = $1", pqxx::params{vaultId})
                      .one_field_ref().as<int>(), 0);

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
        const auto vault = txn.exec("INSERT INTO vault (name, owner_id, type, mount_point) VALUES "
                                    "('claude_test_113', $1, 'local', 'claude_test_113') RETURNING id",
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

} // namespace vh_sql_deployer_history_test
