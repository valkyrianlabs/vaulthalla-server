#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedCache() const {
    conn_->prepare("upsert_cache_index",
                   "INSERT INTO cache_index (vault_id, file_id, path, type, size) "
                   "VALUES ($1, $2, $3, $4, $5) "
                   "ON CONFLICT (vault_id, path, type) DO UPDATE "
                   "SET type = EXCLUDED.type, "
                   "    size = EXCLUDED.size, "
                   "    last_accessed = CURRENT_TIMESTAMP");

    conn_->prepare("update_cache_index",
                   "UPDATE cache_index SET path = $2, type = $3, size = $4, last_accessed = NOW() WHERE id = $1");

    conn_->prepare("get_cache_index", "SELECT * FROM cache_index WHERE id = $1");

    conn_->prepare("get_cache_index_by_path", "SELECT * FROM cache_index WHERE vault_id = $1 AND path = $2");

    conn_->prepare("delete_cache_index", "DELETE FROM cache_index WHERE id = $1");

    conn_->prepare("delete_cache_index_by_path", "DELETE FROM cache_index WHERE vault_id = $1 AND path = $2");

    conn_->prepare("list_cache_indices", "SELECT * FROM cache_index WHERE vault_id = $1");

    conn_->prepare("list_cache_indices_by_path_recursive",
                   "SELECT * FROM cache_index WHERE vault_id = $1 AND path LIKE $2");

    conn_->prepare("list_cache_indices_by_path",
                   "SELECT * FROM cache_index WHERE vault_id = $1 AND path LIKE $2 AND path NOT LIKE $3");

    conn_->prepare("list_cache_indices_by_type",
                   "SELECT * FROM cache_index WHERE vault_id = $1 AND type = $2");

    conn_->prepare("list_cache_indices_by_file", "SELECT * FROM cache_index WHERE file_id = $1");

    conn_->prepare("n_largest_cache_indices",
                   "SELECT * FROM cache_index WHERE vault_id = $1 ORDER BY size DESC LIMIT $2");

    conn_->prepare("n_largest_cache_indices_by_path",
                   "SELECT * FROM cache_index WHERE vault_id = $1 "
                   "AND path LIKE $2 AND path NOT LIKE $3 ORDER BY size DESC LIMIT $4");

    conn_->prepare("n_largest_cache_indices_by_path_recursive",
                   "SELECT * FROM cache_index WHERE vault_id = $1 AND path LIKE $2 ORDER BY size DESC LIMIT $3");

    conn_->prepare("n_largest_cache_indices_by_type",
                   "SELECT * FROM cache_index WHERE vault_id = $1 AND type = $2 ORDER BY size DESC LIMIT $3");

    conn_->prepare("cache_index_exists",
                   "SELECT EXISTS (SELECT 1 FROM cache_index WHERE vault_id = $1 AND path = $2)");

    conn_->prepare("count_cache_indices", "SELECT COUNT(*) FROM cache_index WHERE vault_id = $1");

    conn_->prepare("count_cache_indices_by_type", "SELECT COUNT(*) FROM cache_index WHERE vault_id = $1 AND type = $2");

    // Derived artifacts (preview::cache::Store): identity (file_id, kind, variant), validity by source_id.
    conn_->prepare("upsert_derived_artifact",
                   "INSERT INTO cache_index (vault_id, file_id, path, type, size, kind, variant, source_id, "
                   "  generator_version, artifact_iv, artifact_key_version, status, failure_reason, page_count) "
                   "VALUES ($1, $2, $3, 'derived', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) "
                   "ON CONFLICT (file_id, kind, variant) WHERE type = 'derived' DO UPDATE SET "
                   "  vault_id = EXCLUDED.vault_id, path = EXCLUDED.path, size = EXCLUDED.size, "
                   "  source_id = EXCLUDED.source_id, generator_version = EXCLUDED.generator_version, "
                   "  artifact_iv = EXCLUDED.artifact_iv, artifact_key_version = EXCLUDED.artifact_key_version, "
                   "  status = EXCLUDED.status, failure_reason = EXCLUDED.failure_reason, page_count = EXCLUDED.page_count, "
                   "  last_accessed = NOW(), created_at = NOW()");

    conn_->prepare("get_derived_artifact",
                   "SELECT * FROM cache_index WHERE type = 'derived' AND file_id = $1 AND kind = $2 AND variant = $3");

    conn_->prepare("touch_derived_artifact",
                   "UPDATE cache_index SET last_accessed = NOW() "
                   "WHERE id = $1 AND last_accessed < NOW() - INTERVAL '5 minutes'");

    conn_->prepare("delete_derived_artifact_if_unchanged",
                   "DELETE FROM cache_index WHERE id = $1 AND COALESCE(source_id, '') = $2");

    conn_->prepare("list_derived_artifacts_by_file",
                   "SELECT * FROM cache_index WHERE type = 'derived' AND file_id = $1");

    conn_->prepare("list_derived_artifacts_by_vault",
                   "SELECT * FROM cache_index WHERE type = 'derived' AND vault_id = $1");

    conn_->prepare("derived_artifacts_total_size",
                   "SELECT COALESCE(SUM(size), 0) AS total FROM cache_index WHERE type = 'derived'");

    conn_->prepare("list_derived_artifacts_lru",
                   "SELECT * FROM cache_index WHERE type = 'derived' ORDER BY last_accessed ASC, id ASC LIMIT $1");

    conn_->prepare("list_derived_artifacts_idle",
                   "SELECT * FROM cache_index WHERE type = 'derived' "
                   "AND last_accessed < NOW() - ($1::bigint * INTERVAL '1 second') ORDER BY last_accessed ASC LIMIT $2");

    conn_->prepare("list_derived_artifacts_stale_key",
                   "SELECT * FROM cache_index WHERE type = 'derived' AND vault_id = $1 "
                   "AND status = 'ready' AND artifact_key_version IS DISTINCT FROM $2");

    conn_->prepare("list_derived_file_ids_by_vault",
                   "SELECT DISTINCT file_id FROM cache_index WHERE type = 'derived' AND vault_id = $1");
}
