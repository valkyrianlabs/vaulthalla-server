#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <pqxx/connection>

namespace vh::crypto::secrets { class KeyProvider; }

namespace vh::db {

class Connection {
  public:
    Connection();
    ~Connection();

    [[nodiscard]] pqxx::connection& get() const;

    // False once libpq has seen the server drop the session (PostgreSQL restart, pg_terminate_backend,
    // network loss), a libpqxx error poisoned it (markPoisoned), or a reconnect could not re-prepare
    // statements. DBPool replaces such connections on the next acquire().
    [[nodiscard]] bool healthy() const noexcept;

    // For errors after which libpqxx says the session can't be trusted (pqxx::failure::poisons_connection():
    // protocol violations, a COMMIT whose outcome is unknown, ...) even though the socket may still look open.
    void markPoisoned() noexcept { poisoned_ = true; }

    // Opens a fresh session with the stored connection string and re-prepares statements if this
    // connection had them. Throws, leaving the connection unhealthy, if either step fails.
    void reconnect();

    void initPrepared();

    // Forces the session to TimeZone=UTC and records the zone it started in as the custom setting
    // vaulthalla.database_timezone. Run on every new session (connect and reconnect).
    static void configureSession(pqxx::connection& conn);

  private:
    // libpq keyword/value parameters (user, password, host, ...), handed to libpq as-is: no connection string
    // to assemble, quote or URI-escape.
    using Params = std::vector<std::pair<std::string, std::string>>;

    std::unique_ptr<crypto::secrets::KeyProvider> tpmKeyProvider_;
    Params params_;
    std::unique_ptr<pqxx::connection> conn_;
    bool prepared_ = false;
    bool poisoned_ = false;

    [[nodiscard]] std::unique_ptr<pqxx::connection> open() const;

    // Auth
    void initPreparedUsers() const;
    void initPreparedGroups() const;
    void initPreparedRefreshTokens() const;

    // RBAC
    void initPreparedPermissions() const;
    void initPreparedAdminRoles() const;
    void initPreparedAdminRoleAssignments() const;
    void initPreparedGlobalVaultRoles() const;
    void initPreparedVaultRoles() const;
    void initPreparedVaultRoleAssignments() const;
    void initPreparedPermOverrides() const;

    // Vaults
    void initPreparedVaults() const;
    void initPreparedVaultKeys() const;
    void initPreparedAPIKeys() const;
    void initPreparedVaultActivity() const;
    void initPreparedVaultRecovery() const;
    void initPreparedVaultSecurity() const;

    // Sync
    void initPreparedSync() const;
    void initPreparedSyncEvents() const;
    void initPreparedSyncStats() const;
    void initPreparedSyncThroughput() const;
    void initPreparedSyncConflicts() const;
    void initPreparedSyncConflictArtifacts() const;
    void initPreparedSyncConflictReasons() const;

    // Filesystem
    void initPreparedFsEntries() const;
    void initPreparedFiles() const;
    void initPreparedSymlinks() const;
    void initPreparedDirectories() const;
    void initPreparedOperations() const;
    void initPreparedCache() const;

    // Share links
    void initPreparedShareLinks() const;
    void initPreparedShareSessions() const;
    void initPreparedShareEmailChallenges() const;
    void initPreparedShareUploads() const;
    void initPreparedShareAuditEvents() const;
    void initPreparedShareVaultRoles() const;
    void initPreparedShareStats() const;

    // Stats
    void initPreparedDbStats() const;
    void initPreparedOperationStats() const;
    void initPreparedRetentionStats() const;
    void initPreparedStatsSnapshots() const;
    void initPreparedStatsMetricSamples() const;

    // Email / notifications
    void initPreparedOperatorNotificationDelivery() const;

    // Dashboard
    void initPreparedDashboardPreferences() const;

    // Admin
    void initPreparedSecrets() const;
    void initPreparedWaivers() const;
};

struct PathPatterns {
    std::string like;
    std::string not_like;
};

inline PathPatterns computePatterns(const std::string& absPath, const bool recursive) {
    const std::string base = (absPath == "/") ? "" : absPath;
    if (recursive) return {base + "/%", ""};
    return {base + "/%", base + "/%/%"};
}

}
