#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The remote-connector tables (migration 151; design/core/mcp-remote-signin.md): connector_settings,
// connector_clients, connector_grants and connector_refresh_tokens. Trusted primitives: connector::Grants and
// ops::connector authorize, decide and audit. Refresh tokens are only ever handled here as digests.
namespace vh::db::query::connector {

struct SettingsRow {
    bool enabled{false};
    std::optional<std::string> public_origin{};
    std::string max_scope{"write"};
    bool dcr_enabled{false};
    std::vector<std::string> client_hosts{};  // empty: any https host
    std::optional<uint32_t> changed_by{};
    std::optional<std::time_t> changed_at{};  // absent: the row was never written (defaults)
};

struct Settings {
    // The row, or the defaults when there is none (off).
    [[nodiscard]] static SettingsRow get();
    static void put(const SettingsRow& row, std::optional<uint32_t> by);
};

struct ClientRow {
    std::string id{};         // uuid
    std::string client_id{};  // the CIMD URL, or vhc_... for registered and dynamic clients
    std::string kind{};       // cimd | registered | dcr
    std::string name{};
    std::vector<std::string> redirect_uris{};
    std::optional<std::string> document_sha256{};
    std::optional<std::time_t> fetched_at{}, cache_until{};
    std::optional<uint32_t> created_by{};
    std::time_t created_at{};
    std::optional<std::time_t> last_used_at{}, disabled_at{};

    [[nodiscard]] bool live() const noexcept { return !disabled_at; }
};

struct NewClient {
    std::string client_id{};
    std::string kind{};
    std::string name{};
    std::vector<std::string> redirect_uris{};
    std::optional<std::string> document_sha256{};
    std::optional<std::time_t> fetched_at{}, cache_until{};
    std::optional<uint32_t> created_by{};
};

struct Clients {
    [[nodiscard]] static std::optional<ClientRow> byClientId(const std::string& clientId);
    [[nodiscard]] static std::optional<ClientRow> byId(const std::string& id);
    // Live ones first, newest first.
    [[nodiscard]] static std::vector<ClientRow> list();
    // Throws on a duplicate client_id (pqxx::unique_violation).
    static ClientRow insert(const NewClient& client);
    // Sets disabled_at; true when it was live.
    static bool disable(const std::string& id);
};

struct GrantRow {
    std::string id{};  // uuid
    uint32_t user_id{};
    std::string client_row{};
    std::string client_id{};
    std::string client_name{};
    std::string redirect_uri{};
    std::string scope{};  // read | write | destructive
    std::string resource{};
    std::optional<std::string> label{};
    std::string approved_via{};
    std::time_t created_at{};
    std::time_t expires_at{};
    std::optional<std::time_t> last_used_at{};
    std::optional<std::string> last_ip{};
    std::optional<std::time_t> revoked_at{};
    std::optional<std::string> revoked_reason{};
    std::optional<uint32_t> revoked_by{};
    bool redeemed{false};  // a refresh token was ever issued
    // The current (unused, unrevoked) refresh token's expiry: past it, the grant has been idle too long.
    std::optional<std::time_t> refresh_expires_at{};

    [[nodiscard]] bool live() const noexcept { return !revoked_at; }
};

struct NewGrant {
    uint32_t user_id{};
    std::string client_row{};
    std::string client_id{};
    std::string client_name{};
    std::string redirect_uri{};
    std::string scope{};
    std::string resource{};
    std::optional<std::string> label{};
    std::string approved_via{};
    std::time_t expires_at{};
};

// What a refresh-token rotation found and did, in one transaction (both rows locked).
struct Rotation {
    enum class Outcome {
        Rotated,      // the token was current: marked used, its successor stored
        Allowance,    // used within the allowance and its successor never used: that successor revoked, a new one stored
        Reused,       // presented again outside the allowance: the grant and every token of it revoked
        Unknown,      // no such digest
        WrongClient,  // another client presented it: refused, nothing changed
        GrantEnded,   // the grant was revoked already
        Expired,      // the token or the grant expired: the grant revoked (reason expired)
    };
    Outcome outcome{Outcome::Unknown};
    std::optional<GrantRow> grant{};
};

struct Grants {
    static GrantRow create(const NewGrant& grant);
    [[nodiscard]] static std::optional<GrantRow> byId(const std::string& id);
    // Every grant (all users, or one), live first, newest first.
    [[nodiscard]] static std::vector<GrantRow> list(std::optional<uint32_t> userId = std::nullopt);
    // The live grants (all users, or those of `userIds`).
    [[nodiscard]] static std::vector<GrantRow> listLive(const std::optional<std::vector<uint32_t>>& userIds = std::nullopt);
    // Revokes a live grant and its tokens; true when it was live.
    static bool revoke(const std::string& id, const std::string& reason, std::optional<uint32_t> by);
    static void touch(const std::string& id, const std::optional<std::string>& ip);

    // The grant's first refresh token (the authorization code's redemption): stored only while the grant is live and
    // has none yet, so a code can never mint a second family.
    [[nodiscard]] static bool insertFirstRefreshToken(const std::string& grantId, const std::string& digest,
                                                      std::time_t expiresAt);
    // One refresh: see Rotation. `successorDigest` is stored only on Rotated / Allowance, expiring at
    // min(now + idle, the grant's expiry). The allowance applies while the presented token was used less than
    // `allowanceSeconds` ago.
    [[nodiscard]] static Rotation rotate(const std::string& digest, const std::string& clientId,
                                         const std::string& successorDigest, int64_t idleSeconds,
                                         int64_t allowanceSeconds);
};

}
