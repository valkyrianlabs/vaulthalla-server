#include "db/DBConnection.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "log/Registry.hpp"

#include <fstream>
#include <paths.h>
#include <pqxx/nontransaction>
#include <string_view>

using namespace vh::crypto;

namespace vh::db {

// Bounds (re)connect attempts so an unreachable server can't park a pool caller in connect() for the
// kernel's TCP timeout. libpq's default is to wait forever.
static constexpr int DB_CONNECT_TIMEOUT_SECONDS = 10;

// Session parameters every connection gets. TCP keepalives (probe after 30s idle, every 10s, give up after 3) and
// tcp_user_timeout make a server or network that silently stops answering surface as a broken connection within
// about a minute, which the pool then replaces, instead of a caller blocking in recv() for the kernel's ~2h default.
// libpq ignores them on Unix-domain sockets, where a dead server closes the socket anyway.
static void addSessionParams(std::vector<std::pair<std::string, std::string>>& params) {
    params.insert(params.end(), {
        {"connect_timeout", std::to_string(DB_CONNECT_TIMEOUT_SECONDS)},
        {"application_name", paths::testMode ? "vaulthalla-test" : "vaulthalla"},
        {"keepalives", "1"},
        {"keepalives_idle", "30"},
        {"keepalives_interval", "10"},
        {"keepalives_count", "3"},
        {"tcp_user_timeout", "60000"},
    });
}

// libpq takes the bare address: an IPv6 literal written for the old URI connection string ("[::1]") drops its brackets.
static std::string libpqHost(const std::string& host) {
    if (host.size() > 2 && host.front() == '[' && host.back() == ']') return host.substr(1, host.size() - 2);
    return host;
}

void Connection::configureSession(pqxx::connection& conn) {
    // Every daemon session runs in UTC: naive `timestamp` values are then written and read as UTC (the C++ side
    // parses and prints them as UTC), and timestamptz text carries +00. Before this, a non-UTC server TimeZone made
    // CURRENT_TIMESTAMP land in naive columns as local wall time, read back with a 'Z' (#157).
    // The zone the session started in (database/role/server default) is kept in vaulthalla.database_timezone, so
    // migration 100 can interpret rows written before the switch in that zone.
    pqxx::nontransaction tx(conn);
    const auto original = tx.exec("SELECT current_setting('TimeZone')").one_field_ref().as<std::string>();
    tx.exec("SELECT set_config('vaulthalla.database_timezone', $1, false), set_config('TimeZone', 'UTC', false)",
            pqxx::params{original});
}

static std::optional<std::string> getFirstInitDBPass() {
    const std::filesystem::path f{VH_DB_PASSWORD_SEED_PATH};  // the installed path, also in test mode

    if (!std::filesystem::exists(f)) {
        log::Registry::runtime()->debug("[seed] No pending db_password file at {}", f.string());
        return std::nullopt;
    }

    std::ifstream in(f);
    if (!in.is_open()) {
        log::Registry::runtime()->warn("[seed] Failed to open db_password file: {}", f.string());
        return std::nullopt;
    }

    std::string pass{};
    if (!(in >> pass)) {
        log::Registry::runtime()->warn("[seed] Invalid contents in {}", f.string());
        return std::nullopt;
    }

    return pass;
}

static void clearPendingDBPassIfPresent() {
    const std::filesystem::path f{VH_DB_PASSWORD_SEED_PATH};  // the installed path, also in test mode
    if (!std::filesystem::exists(f)) return;

    try {
        std::filesystem::remove(f);
        log::Registry::runtime()->debug("[seed] Consumed and removed pending db_password file {}", f.string());
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[seed] Failed to remove {}: {}", f.string(), e.what());
    }
}

// Test mode takes its database from the environment, all of it, or refuses: it never falls back to the production
// path (the config's database and the /run/vaulthalla/db_password handoff), which on a dev box is the dev database.
static std::optional<std::string> getTestEnvValue(const char* key) {
    if (const auto* value = std::getenv(key); value && *value) return std::string(value);
    return std::nullopt;
}

Connection::Connection() : tpmKeyProvider_(
    std::make_unique<secrets::KeyProvider>(paths::testMode ? "test_psql" : "psql")) {
    if (paths::testMode) {
        const auto user = getTestEnvValue("VH_TEST_DB_USER");
        const auto pass = getTestEnvValue("VH_TEST_DB_PASS");
        const auto host = getTestEnvValue("VH_TEST_DB_HOST");
        const auto port = getTestEnvValue("VH_TEST_DB_PORT");
        const auto name = getTestEnvValue("VH_TEST_DB_NAME");

        if (!(user && pass && host && port && name))
            throw std::runtime_error("test mode requires VH_TEST_DB_USER, VH_TEST_DB_PASS, VH_TEST_DB_HOST, "
                                     "VH_TEST_DB_PORT and VH_TEST_DB_NAME in the environment; refusing to fall back "
                                     "to the configured (production/dev) database");
        params_ = {{"user", *user}, {"password", *pass}, {"host", libpqHost(*host)}, {"port", *port},
                   {"dbname", *name}};
        addSessionParams(params_);
        conn_ = open();

        log::Registry::runtime()->info("[DBConnection] Test mode: using connection settings from the environment");
        return;
    }

    const auto initPass = getFirstInitDBPass();
    if (tpmKeyProvider_->sealedExists()) {
        try {
            tpmKeyProvider_->init();
        } catch (const std::exception& e) {
            const auto msg = std::string("Database password failed to initialize: could not unseal the stored DB "
                                         "password with the TPM (sealed under ") + paths::getBackingPath().string() +
                             "): " + e.what();
            log::Registry::runtime()->error("[DBConnection] {}", msg);
            throw std::runtime_error(msg);
        }
        if (initPass) {
            const auto replacement = std::vector<uint8_t>(initPass->begin(), initPass->end());
            tpmKeyProvider_->updateMasterKey(replacement);
            clearPendingDBPassIfPresent();
            log::Registry::runtime()->info("[seed] Reseeded TPM-stored DB password from pending handoff file");
        }
    } else {
        if (!initPass) {
            const auto msg = std::string("Database password failed to initialize: no TPM-sealed DB password under ") +
                             paths::getBackingPath().string() +
                             " and no pending password handoff at " VH_DB_PASSWORD_SEED_PATH " (the sealed secret was "
                             "removed, e.g. by a package purge, or first-time DB setup never ran). Write the "
                             "PostgreSQL role's password to " VH_DB_PASSWORD_SEED_PATH " (owner " VH_SERVICE_ACCOUNT
                             ", mode 0600) and restart " VH_HINT_SERVICE_NAME ".";
            log::Registry::runtime()->error("[DBConnection] {}", msg);
            throw std::runtime_error(msg);
        }
        tpmKeyProvider_->init(*initPass);
        clearPendingDBPassIfPresent();
    }

    const auto& key = tpmKeyProvider_->getMasterKey();
    const auto& db = config::Registry::get().database;
    params_ = {{"user", db.user}, {"password", std::string(key.begin(), key.end())}, {"host", libpqHost(db.host)},
               {"port", std::to_string(db.port)}, {"dbname", db.name}};
    addSessionParams(params_);
    try {
        conn_ = open();
    } catch (const std::exception& e) {
        // libpq's message names the cause (e.g. password authentication failed) and never includes the password.
        const auto msg = "Database connection failed for " + db.user + "@" + db.host + ":" + std::to_string(db.port) +
                         "/" + db.name + ": " + e.what();
        log::Registry::runtime()->error("[DBConnection] {}", msg);
        throw std::runtime_error(msg);
    }
}

Connection::~Connection() { if (conn_ && conn_->is_open()) conn_->close(); }

pqxx::connection& Connection::get() const { return *conn_; }

bool Connection::healthy() const noexcept { return !poisoned_ && conn_ && conn_->is_open(); }

std::unique_ptr<pqxx::connection> Connection::open() const {
    auto conn = std::make_unique<pqxx::connection>(params_);
    configureSession(*conn);
    return conn;
}

void Connection::reconnect() {
    auto fresh = open();
    conn_.swap(fresh);
    fresh.reset();
    poisoned_ = false;

    if (!prepared_) return;

    try {
        initPrepared();
    } catch (...) {
        // An open-but-unprepared session would fail every query by statement name. Close it so healthy()
        // reports false and the pool retries the whole reconnect later.
        conn_->close();
        throw;
    }
}

void Connection::initPrepared() {
    if (!conn_ || !conn_->is_open()) throw std::runtime_error("Database connection is not open");
    prepared_ = true;

    // Auth
    initPreparedUsers();
    initPreparedGroups();
    initPreparedRefreshTokens();

    // RBAC
    initPreparedGlobalVaultRoles();
    initPreparedAdminRoles();
    initPreparedAdminRoleAssignments();
    initPreparedVaultRoles();
    initPreparedVaultRoleAssignments();
    initPreparedPermOverrides();
    initPreparedPermissions();

    // Vaults
    initPreparedVaults();
    initPreparedVaultKeys();
    initPreparedAPIKeys();
    initPreparedVaultActivity();
    initPreparedVaultRecovery();
    initPreparedVaultSecurity();

    // Sync
    initPreparedSync();
    initPreparedSyncEvents();
    initPreparedSyncStats();
    initPreparedSyncThroughput();
    initPreparedSyncConflicts();
    initPreparedSyncConflictArtifacts();
    initPreparedSyncConflictReasons();

    // Filesystem
    initPreparedFsEntries();
    initPreparedFiles();
    initPreparedSymlinks();
    initPreparedDirectories();
    initPreparedOperations();
    initPreparedCache();

    // Share links
    initPreparedShareLinks();
    initPreparedShareSessions();
    initPreparedShareEmailChallenges();
    initPreparedShareUploads();
    initPreparedShareAuditEvents();
    initPreparedShareVaultRoles();
    initPreparedShareStats();

    // Stats
    initPreparedDbStats();
    initPreparedOperationStats();
    initPreparedRetentionStats();
    initPreparedStatsSnapshots();
    initPreparedStatsMetricSamples();

    // Email / notifications
    initPreparedOperatorNotificationDelivery();

    // Dashboard
    initPreparedDashboardPreferences();

    // Admin
    initPreparedSecrets();
    initPreparedWaivers();

    // Upstream control plane
    initPreparedUpstreamBuckets();
    initPreparedUpstreamEvents();
}

}
