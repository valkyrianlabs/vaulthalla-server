#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedSecrets() const {
    conn_->prepare("upsert_internal_secret",
                   "INSERT INTO internal_secrets (key, value, iv, created_at, updated_at) "
                   "VALUES ($1, $2, $3, NOW(), NOW()) "
                   "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, iv = EXCLUDED.iv, updated_at = NOW()");

    conn_->prepare("get_internal_secret", "SELECT * FROM internal_secrets WHERE key = $1");

    conn_->prepare("internal_secret_exists", "SELECT EXISTS(SELECT 1 FROM internal_secrets WHERE key = $1) AS exists");

    conn_->prepare("delete_internal_secret", "DELETE FROM internal_secrets WHERE key = $1");
}
