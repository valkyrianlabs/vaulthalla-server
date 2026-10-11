#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedAPIKeys() const {

    conn_->prepare("get_api_key", "SELECT * FROM api_keys WHERE id = $1");

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
