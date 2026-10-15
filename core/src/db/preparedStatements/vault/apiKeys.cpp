#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedAPIKeys() const {

    conn_->prepare("get_api_key", "SELECT * FROM api_keys WHERE id = $1");

    // Provider administration (#237, migration 110). Absent values keep what is stored.
    conn_->prepare("api_key_set_admin", R"SQL(
        UPDATE api_keys SET
            admin_enabled       = $2,
            provider_account_id = COALESCE($3, provider_account_id),
            admin_capabilities  = COALESCE($4::jsonb, admin_capabilities),
            admin_validated_at  = CASE WHEN $5::double precision IS NULL THEN admin_validated_at
                                       ELSE to_timestamp($5::double precision) END
        WHERE id = $1
    )SQL");

    conn_->prepare("api_key_set_provider_token",
                   "UPDATE api_keys SET encrypted_provider_token = $2, provider_token_iv = $3 WHERE id = $1");

    conn_->prepare("api_key_clear_provider_token",
                   "UPDATE api_keys SET encrypted_provider_token = NULL, provider_token_iv = NULL WHERE id = $1");

    conn_->prepare("api_key_set_account_ref", "UPDATE api_keys SET provider_account_id = $2 WHERE id = $1");

    conn_->prepare("get_api_key_by_name", "SELECT * FROM api_keys WHERE name = $1");

    conn_->prepare("upsert_api_key",
                   "INSERT INTO api_keys (user_id, name, provider, access_key, "
                   "encrypted_secret_access_key, iv, region, endpoint) "
                   "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
                   "ON CONFLICT (user_id, name, access_key) DO UPDATE SET "
                   "  provider = EXCLUDED.provider, "
                   "  encrypted_secret_access_key = EXCLUDED.encrypted_secret_access_key, "
                   "  iv = EXCLUDED.iv, "
                   "  region = EXCLUDED.region, "
                   "  endpoint = EXCLUDED.endpoint, "
                   "  created_at = CURRENT_TIMESTAMP "
                   "RETURNING id");

    // In-place edit: the id (and so every vault's s3.api_key_id) stays.
    conn_->prepare("update_api_key",
                   "UPDATE api_keys SET name = $2, provider = $3, access_key = $4, "
                   "encrypted_secret_access_key = $5, iv = $6, region = $7, endpoint = $8 "
                   "WHERE id = $1");

    conn_->prepare("list_api_key_vaults",
                   // A deleted vault keeps its key until it is purged (an upstream purge needs it).
                   "SELECT v.id, v.name || CASE WHEN v.deleted_at IS NULL THEN '' ELSE ' (deleted, pending purge)' END AS name "
                   "FROM s3 JOIN vault v ON v.id = s3.vault_id "
                   "WHERE s3.api_key_id = $1 ORDER BY v.name, v.id");

    conn_->prepare("remove_api_key",
                   "DELETE FROM api_keys WHERE id = $1");

    conn_->prepare("get_api_key_owner",
                   R"(SELECT u.id
FROM api_keys ak
JOIN users u ON ak.user_id = u.id
WHERE ak.id = $1)");

}
