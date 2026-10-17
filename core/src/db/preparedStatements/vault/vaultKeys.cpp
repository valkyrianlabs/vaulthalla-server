#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedVaultKeys() const {
    conn_->prepare("insert_vault_key",
                   "INSERT INTO vault_keys (vault_id, encrypted_key, iv) "
                   "VALUES ($1, $2, $3) RETURNING version");

    conn_->prepare("update_vault_key",
                   "UPDATE vault_keys "
                   "SET encrypted_key = $2, iv = $3, updated_at = NOW() "
                   "WHERE vault_id = $1");

    conn_->prepare("get_vault_key", "SELECT * FROM vault_keys WHERE vault_id = $1");

    conn_->prepare("delete_vault_key", "DELETE FROM vault_keys WHERE vault_id = $1");

    conn_->prepare("rotate_vault_key",
                   "WITH "
                   "  _lock AS ( "
                   "    SELECT pg_advisory_xact_lock($1::bigint) "
                   "  ), "
                   "  current AS ( "
                   "    SELECT vk.vault_id, vk.encrypted_key, vk.iv, vk.created_at, vk.version "
                   "    FROM vault_keys vk "
                   "    WHERE vk.vault_id = $1 "
                   "    FOR UPDATE "
                   "  ), "
                   "  trashed AS ( "
                   "    INSERT INTO vault_keys_trashed (vault_id, encrypted_key, iv, created_at, trashed_at, version) "
                   "    SELECT c.vault_id, c.encrypted_key, c.iv, c.created_at, CURRENT_TIMESTAMP, c.version "
                   "    FROM current c "
                   "    RETURNING version "
                   "  ), "
                   "  next_version AS ( "
                   "    SELECT COALESCE((SELECT version FROM current), -1) + 1 AS version "
                   "  ), "
                   "  updated AS ( "
                   "    UPDATE vault_keys "
                   "    SET encrypted_key = $2, "
                   "        iv            = $3, "
                   "        version       = (SELECT version FROM next_version), "
                   "        created_at    = CURRENT_TIMESTAMP "
                   "    WHERE vault_id = $1 "
                   "    RETURNING version "
                   "  ), "
                   "  inserted AS ( "
                   "    INSERT INTO vault_keys (vault_id, encrypted_key, iv, version, created_at) "
                   "    SELECT $1, $2, $3, (SELECT version FROM next_version), CURRENT_TIMESTAMP "
                   "    WHERE NOT EXISTS (SELECT 1 FROM current) "
                   "    RETURNING version "
                   "  ) "
                   "SELECT COALESCE((SELECT version FROM updated), "
                   "                (SELECT version FROM inserted)) AS version;"
        );

    conn_->prepare("mark_vault_key_rotation_finished",
                   "UPDATE vault_keys_trashed SET rotation_completed_at = NOW() "
                   "WHERE vault_id = $1 AND rotation_completed_at IS NULL");

    conn_->prepare("vault_key_rotation_in_progress",
                   "SELECT EXISTS(SELECT 1 FROM vault_keys_trashed WHERE vault_id = $1 AND rotation_completed_at IS NULL) AS in_progress");

    // vault_keys_trashed has no updated_at column (vault::model::Key reads one): a retired key's is when it retired.
    conn_->prepare("get_rotation_old_vault_key",
                   "SELECT vault_id, version, encrypted_key, iv, created_at, COALESCE(trashed_at, created_at) AS updated_at "
                   "FROM vault_keys_trashed WHERE vault_id = $1 AND rotation_completed_at IS NULL");

    conn_->prepare("get_retired_vault_key",
                   "SELECT vault_id, version, encrypted_key, iv, created_at, COALESCE(trashed_at, created_at) AS updated_at "
                   "FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2");

    conn_->prepare("list_retired_vault_key_versions",
                   "SELECT version FROM vault_keys_trashed WHERE vault_id = $1 ORDER BY version");

    conn_->prepare("retired_vault_key_version_exists",
                   "SELECT EXISTS(SELECT 1 FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2)");

    // Mirrors trigger recovery_guard_retired_vault_key (migration 111).
    conn_->prepare("list_recovery_referenced_key_versions",
                   "SELECT key_version FROM recovery_blob WHERE vault_id = $1 AND key_version > 0 "
                   "UNION "
                   "SELECT key_version FROM upstream_object_version "
                   "WHERE vault_id = $1 AND gone_at IS NULL AND key_version IS NOT NULL AND key_version > 0 "
                   "ORDER BY 1");
}
