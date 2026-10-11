#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedRefreshTokens() const {
    conn_->prepare(
        "insert_refresh_token",
        "INSERT INTO refresh_tokens (jti, user_id, token_hash, ip_address, user_agent, issued_at, expires_at, last_used, revoked) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), FALSE)"
    );

    conn_->prepare(
        "get_refresh_token_by_jti",
        "SELECT * FROM refresh_tokens "
        "WHERE jti = $1"
    );

    conn_->prepare(
        "rewrite_refresh_token_hash",
        "UPDATE refresh_tokens "
        "SET token_hash = $3 "
        "WHERE jti = $1 AND token_hash = $2"
    );

    conn_->prepare(
        "touch_refresh_token_last_used",
        "UPDATE refresh_tokens "
        "SET last_used = NOW() "
        "WHERE jti = $1"
    );

    conn_->prepare(
        "revoke_refresh_token_by_jti",
        "UPDATE refresh_tokens "
        "SET revoked = TRUE "
        "WHERE jti = $1"
    );

    conn_->prepare(
        "revoke_all_refresh_tokens_for_user",
        "UPDATE refresh_tokens "
        "SET revoked = TRUE "
        "WHERE user_id = $1 AND revoked = FALSE"
    );

    conn_->prepare(
        "delete_refresh_token_by_jti",
        "DELETE FROM refresh_tokens "
        "WHERE jti = $1"
    );

    conn_->prepare(
        "delete_expired_refresh_tokens_for_user",
        "DELETE FROM refresh_tokens "
        "WHERE user_id = $1 AND expires_at < NOW()"
    );

    conn_->prepare(
        "delete_old_revoked_refresh_tokens_for_user",
        "DELETE FROM refresh_tokens "
        "WHERE user_id = $1 "
        "AND revoked = TRUE "
        "AND issued_at < NOW() - INTERVAL '7 days'"
    );

    conn_->prepare(
        "delete_old_revoked_refresh_tokens_global",
        "DELETE FROM refresh_tokens "
        "WHERE revoked = TRUE "
        "AND issued_at < NOW() - INTERVAL '7 days'"
    );

    conn_->prepare(
        "list_active_refresh_tokens_for_user",
        "SELECT * FROM refresh_tokens "
        "WHERE user_id = $1 AND revoked = FALSE AND expires_at >= NOW() "
        "ORDER BY issued_at DESC"
    );

    conn_->prepare(
        "count_active_refresh_tokens_for_user",
        "SELECT COUNT(*) "
        "FROM refresh_tokens "
        "WHERE user_id = $1 AND revoked = FALSE AND expires_at >= NOW()"
    );
}
