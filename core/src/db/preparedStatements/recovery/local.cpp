#include "db/DBConnection.hpp"

#include <string>

// vault_recovery_policy, recovery_blob, recovery_snapshot, file_versions (retained generations), recovery_plan
// (migration 111). Times are read as epoch seconds (extract(epoch …)::bigint) and written from epoch seconds
// (to_timestamp). Id arrays travel as Postgres array literals ('{1,2}'), text arrays as JSON.
void vh::db::Connection::initPreparedRecoveryLocal() const {
    // ---- policy ----
    conn_->prepare("recovery_policy_get", R"SQL(
        SELECT vault_id, mode, snapshot_quota_bytes, trim_scale(cost_alert_monthly)::text AS cost_alert_monthly,
               cost_alert_currency, local_versioning, version_keep_last, version_max_age_days, version_quota_bytes,
               extract(epoch FROM updated_at)::bigint AS updated_at, updated_by
        FROM vault_recovery_policy WHERE vault_id = $1
    )SQL");

    conn_->prepare("recovery_policy_upsert", R"SQL(
        INSERT INTO vault_recovery_policy (vault_id, mode, snapshot_quota_bytes, cost_alert_monthly, cost_alert_currency,
                                           local_versioning, version_keep_last, version_max_age_days,
                                           version_quota_bytes, updated_at, updated_by)
        VALUES ($1, $2, $3::bigint, $4::numeric, $5, $6, $7::int, $8::int, $9::bigint, CURRENT_TIMESTAMP, $10)
        ON CONFLICT (vault_id) DO UPDATE SET
            mode = EXCLUDED.mode, snapshot_quota_bytes = EXCLUDED.snapshot_quota_bytes,
            cost_alert_monthly = EXCLUDED.cost_alert_monthly, cost_alert_currency = EXCLUDED.cost_alert_currency,
            local_versioning = EXCLUDED.local_versioning, version_keep_last = EXCLUDED.version_keep_last,
            version_max_age_days = EXCLUDED.version_max_age_days, version_quota_bytes = EXCLUDED.version_quota_bytes,
            updated_at = CURRENT_TIMESTAMP, updated_by = EXCLUDED.updated_by
    )SQL");

    conn_->prepare("recovery_policy_list_local_versioning",
                   "SELECT vault_id FROM vault_recovery_policy WHERE local_versioning ORDER BY vault_id");

    // ---- blobs ----
    const std::string blobColumns = R"SQL(
        b.id, b.vault_id, b.storage_name, b.encryption_iv, b.key_version, b.cipher_bytes, b.plaintext_bytes,
        b.content_hash, extract(epoch FROM b.created_at)::bigint AS created_at
    )SQL";

    conn_->prepare("recovery_blob_find_generation",
                   "SELECT " + blobColumns + " FROM recovery_blob b "
                   "WHERE b.vault_id = $1 AND b.encryption_iv = $2 AND b.key_version = $3 AND b.encryption_iv <> ''");

    conn_->prepare("recovery_blob_insert", R"SQL(
        INSERT INTO recovery_blob (vault_id, storage_name, encryption_iv, key_version, cipher_bytes, plaintext_bytes,
                                   content_hash)
        VALUES ($1, $2, $3, $4, $5::bigint, $6::bigint, $7)
        ON CONFLICT (vault_id, encryption_iv, key_version) WHERE encryption_iv <> '' DO NOTHING
        RETURNING id
    )SQL");

    conn_->prepare("recovery_blob_get", "SELECT " + blobColumns + " FROM recovery_blob b WHERE b.id = $1");

    conn_->prepare("recovery_blob_get_by_storage_name",
                   "SELECT " + blobColumns + " FROM recovery_blob b WHERE b.vault_id = $1 AND b.storage_name = $2");

    conn_->prepare("recovery_blob_ref_count", "SELECT count(*) FROM file_versions WHERE blob_id = $1");

    // Two statements: the lock first, then the reference check in a fresh snapshot that sees a capture which committed
    // a reference while this transaction waited for the lock.
    conn_->prepare("recovery_blob_lock", "SELECT id FROM recovery_blob WHERE id = $1 FOR UPDATE");

    conn_->prepare("recovery_blob_delete_unreferenced",
                   "DELETE FROM recovery_blob b WHERE b.id = $1 "
                   "AND NOT EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id) "
                   "RETURNING " + blobColumns);

    conn_->prepare("recovery_blob_physical_bytes",
                   "SELECT COALESCE(sum(cipher_bytes), 0)::bigint FROM recovery_blob WHERE vault_id = $1");

    conn_->prepare("recovery_blob_usage", R"SQL(
        SELECT count(*) AS blobs, COALESCE(sum(cipher_bytes), 0)::bigint AS bytes,
               COALESCE(sum(plaintext_bytes), 0)::bigint AS plaintext_bytes,
               count(*) FILTER (WHERE kind = 's') AS snapshot_only_blobs,
               COALESCE(sum(cipher_bytes) FILTER (WHERE kind = 's'), 0)::bigint AS snapshot_only_bytes,
               count(*) FILTER (WHERE kind = 'v') AS version_blobs,
               COALESCE(sum(cipher_bytes) FILTER (WHERE kind = 'v'), 0)::bigint AS version_bytes,
               count(*) FILTER (WHERE kind = 'n') AS unreferenced_blobs,
               COALESCE(sum(cipher_bytes) FILTER (WHERE kind = 'n'), 0)::bigint AS unreferenced_bytes
        FROM (
            SELECT b.cipher_bytes, b.plaintext_bytes,
                   CASE WHEN EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id AND fv.origin = 'version')
                        THEN 'v'
                        WHEN EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id) THEN 's'
                        ELSE 'n' END AS kind
            FROM recovery_blob b WHERE b.vault_id = $1
        ) x
    )SQL");

    conn_->prepare("recovery_blob_list_unreferenced",
                   "SELECT " + blobColumns + " FROM recovery_blob b "
                   "WHERE b.vault_id = $1 AND b.created_at < CURRENT_TIMESTAMP - make_interval(secs => $2::double precision) "
                   "AND NOT EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id) "
                   "ORDER BY b.created_at, b.id LIMIT $3");

    conn_->prepare("recovery_blob_list_by_vault",
                   "SELECT " + blobColumns + " FROM recovery_blob b WHERE b.vault_id = $1 AND b.id > $2 "
                   "ORDER BY b.id LIMIT $3");

    conn_->prepare("recovery_blob_existing_names",
                   "SELECT storage_name FROM recovery_blob WHERE vault_id = $1 "
                   "AND storage_name IN (SELECT jsonb_array_elements_text($2::jsonb))");

    conn_->prepare("recovery_blob_key_versions",
                   "SELECT DISTINCT key_version FROM recovery_blob WHERE vault_id = $1 AND encryption_iv <> '' "
                   "ORDER BY key_version");

    conn_->prepare("recovery_blob_still_unreferenced",
                   "SELECT b.id FROM recovery_blob b WHERE b.id = ANY($1::bigint[]) "
                   "AND NOT EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id) ORDER BY b.id");

    // ---- snapshots ----
    const std::string snapshotColumns = R"SQL(
        s.id, s.vault_id, s.name, s.root_path, s.root_type, s.root_entry_id, s.state, s.file_count, s.directory_count,
        s.plaintext_bytes, array_to_json(s.empty_directories)::text AS empty_directories, s.skipped::text AS skipped,
        extract(epoch FROM s.created_at)::bigint AS created_at,
        extract(epoch FROM s.completed_at)::bigint AS completed_at, s.created_by, s.created_by_name, s.error
    )SQL";

    conn_->prepare("recovery_snapshot_insert", R"SQL(
        INSERT INTO recovery_snapshot (vault_id, name, root_path, root_type, root_entry_id, created_by, created_by_name)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
    )SQL");

    conn_->prepare("recovery_snapshot_finish", R"SQL(
        UPDATE recovery_snapshot SET state = 'ready', file_count = $2, directory_count = $3, plaintext_bytes = $4::bigint,
                                     empty_directories = ARRAY(SELECT jsonb_array_elements_text($5::jsonb)),
                                     skipped = $6::jsonb,
                                     completed_at = CURRENT_TIMESTAMP, error = NULL
        WHERE id = $1 AND state = 'creating'
    )SQL");

    conn_->prepare("recovery_snapshot_fail", R"SQL(
        UPDATE recovery_snapshot SET state = 'failed', error = $2, completed_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND state = 'creating'
    )SQL");

    conn_->prepare("recovery_snapshot_get", "SELECT " + snapshotColumns + " FROM recovery_snapshot s WHERE s.id = $1");

    conn_->prepare("recovery_snapshot_get_by_name",
                   "SELECT " + snapshotColumns + " FROM recovery_snapshot s "
                   "WHERE s.vault_id = $1 AND s.name = $2 AND s.state <> 'deleting'");

    conn_->prepare("recovery_snapshot_list_by_vault",
                   "SELECT " + snapshotColumns + " FROM recovery_snapshot s "
                   "WHERE s.vault_id = $1 AND ($3::bigint <= 0 OR s.id < $3) "
                   "ORDER BY s.created_at DESC, s.id DESC LIMIT $2");

    // $3: LIKE pattern for '<path>/%' (escaped), '%' for the root.
    conn_->prepare("recovery_snapshot_list_under_path",
                   "SELECT " + snapshotColumns + " FROM recovery_snapshot s "
                   "WHERE s.vault_id = $1 AND (s.root_path = $2 OR s.root_path LIKE $3 ESCAPE '\\') "
                   "ORDER BY s.created_at DESC, s.id DESC LIMIT $4");

    conn_->prepare("recovery_snapshot_list_containing_path",
                   "SELECT " + snapshotColumns + " FROM recovery_snapshot s "
                   "WHERE s.vault_id = $1 AND s.state = 'ready' AND ("
                   "      s.root_path = $2 OR $2 = ANY(s.empty_directories)"
                   "   OR s.id IN (SELECT fv.snapshot_id FROM file_versions fv "
                   "               WHERE fv.vault_id = $1 AND fv.snapshot_id IS NOT NULL "
                   "                 AND (fv.path = $2 OR fv.path LIKE $3 ESCAPE '\\'))) "
                   "ORDER BY s.created_at DESC, s.id DESC LIMIT $4");

    conn_->prepare("recovery_snapshot_mark_deleting",
                   "UPDATE recovery_snapshot SET state = 'deleting' WHERE id = $1 AND state <> 'deleting'");

    conn_->prepare("recovery_snapshot_member_blobs",
                   "SELECT DISTINCT blob_id FROM file_versions WHERE snapshot_id = $1 AND blob_id IS NOT NULL");

    conn_->prepare("recovery_snapshot_delete", "DELETE FROM recovery_snapshot WHERE id = $1");

    conn_->prepare("recovery_snapshot_list_stale_creating",
                   "SELECT " + snapshotColumns + " FROM recovery_snapshot s WHERE s.state = 'creating' "
                   "AND s.created_at < CURRENT_TIMESTAMP - make_interval(secs => $1::double precision) ORDER BY s.id");

    // ---- generations (file_versions) ----
    const std::string generationColumns = R"SQL(
        fv.id, fv.vault_id, fv.file_id, fv.snapshot_id, fv.blob_id, fv.version_number, fv.content_hash, fv.size_bytes,
        fv.mime_type, fv.path, fv.rel_path, fv.mode,
        extract(epoch FROM fv.source_updated_at)::bigint AS source_updated_at,
        extract(epoch FROM fv.created_at)::bigint AS created_at, fv.created_by, fv.origin, fv.reason,
        fv.upstream_state, fv.upstream_key, fv.upstream_version_id, fv.upstream_attempts, fv.upstream_error,
        extract(epoch FROM fv.upstream_sent_at)::bigint AS upstream_sent_at,
        b.storage_name, b.encryption_iv, b.key_version, b.cipher_bytes
    )SQL";
    const std::string generationFrom = " FROM file_versions fv LEFT JOIN recovery_blob b ON b.id = fv.blob_id ";

    // Serializes version numbering per file key until the transaction ends.
    conn_->prepare("recovery_generation_lock_key", "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))");

    conn_->prepare("recovery_generation_next_number_file",
                   "SELECT COALESCE(max(version_number), 0) + 1 FROM file_versions WHERE file_id = $1");

    conn_->prepare("recovery_generation_next_number_path",
                   "SELECT COALESCE(max(version_number), 0) + 1 FROM file_versions "
                   "WHERE file_id IS NULL AND vault_id = $1 AND path = $2");

    conn_->prepare("recovery_generation_insert", R"SQL(
        INSERT INTO file_versions (vault_id, file_id, snapshot_id, blob_id, version_number, content_hash, size_bytes,
                                   mime_type, path, rel_path, mode, source_updated_at, created_by, origin, reason,
                                   upstream_state, upstream_key)
        VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, $8, $9, $10, $11,
                CASE WHEN $12::double precision IS NULL THEN NULL ELSE to_timestamp($12::double precision) END,
                $13, $14, $15, $16, $17)
        RETURNING id
    )SQL");

    conn_->prepare("recovery_generation_get", "SELECT " + generationColumns + generationFrom + "WHERE fv.id = $1");

    conn_->prepare("recovery_generation_list_by_file",
                   "SELECT " + generationColumns + generationFrom +
                   "WHERE fv.file_id = $1 ORDER BY fv.version_number DESC, fv.id DESC LIMIT $2");

    conn_->prepare("recovery_generation_list_by_path",
                   "SELECT " + generationColumns + generationFrom +
                   "WHERE fv.vault_id = $1 AND fv.path = $2 AND ($3::text IS NULL OR fv.origin = $3) "
                   "ORDER BY fv.created_at DESC, fv.id DESC LIMIT $4");

    conn_->prepare("recovery_generation_list_versions_under",
                   "SELECT " + generationColumns + generationFrom +
                   "WHERE fv.vault_id = $1 AND fv.origin = 'version' AND fv.path LIKE $2 ESCAPE '\\' "
                   "ORDER BY fv.created_at DESC, fv.id DESC LIMIT $3");

    conn_->prepare("recovery_generation_list_snapshot_members",
                   "SELECT " + generationColumns + generationFrom +
                   "WHERE fv.snapshot_id = $1 AND fv.rel_path > $2 ORDER BY fv.rel_path LIMIT $3");

    conn_->prepare("recovery_generation_count_snapshot_members",
                   "SELECT count(*) FROM file_versions WHERE snapshot_id = $1");

    conn_->prepare("recovery_generation_delete", "DELETE FROM file_versions WHERE id = $1 RETURNING blob_id");

    conn_->prepare("recovery_generation_release_blob", R"SQL(
        UPDATE file_versions fv SET blob_id = NULL
        FROM (SELECT id, blob_id FROM file_versions WHERE id = $1 FOR UPDATE) old
        WHERE fv.id = old.id AND fv.snapshot_id IS NULL AND fv.origin = 'version'
        RETURNING old.blob_id
    )SQL");

    conn_->prepare("recovery_generation_list_pending",
                   "SELECT " + generationColumns + generationFrom +
                   "WHERE fv.vault_id = $1 AND fv.upstream_state = 'pending' "
                   "ORDER BY fv.file_id NULLS LAST, fv.path, fv.version_number, fv.id LIMIT $2");

    conn_->prepare("recovery_generation_list_pending_for_file",
                   "SELECT " + generationColumns + generationFrom +
                   "WHERE fv.file_id = $1 AND fv.upstream_state = 'pending' ORDER BY fv.version_number, fv.id");

    conn_->prepare("recovery_generation_mark_sent", R"SQL(
        UPDATE file_versions SET upstream_state = 'sent', upstream_version_id = $2, upstream_sent_at = CURRENT_TIMESTAMP,
                                 upstream_error = NULL
        WHERE id = $1 AND upstream_state = 'pending'
    )SQL");

    conn_->prepare("recovery_generation_mark_skipped",
                   "UPDATE file_versions SET upstream_state = 'skipped' "
                   "WHERE id = ANY($1::bigint[]) AND upstream_state = 'pending'");

    conn_->prepare("recovery_generation_record_failure",
                   "UPDATE file_versions SET upstream_attempts = upstream_attempts + 1, upstream_error = $2 "
                   "WHERE id = $1 AND upstream_state = 'pending'");

    conn_->prepare("recovery_generation_backlog", R"SQL(
        SELECT count(*) AS pending, COALESCE(sum(size_bytes), 0)::bigint AS pending_bytes,
               extract(epoch FROM min(created_at))::bigint AS oldest_pending_at,
               count(*) FILTER (WHERE upstream_attempts > 0) AS failing,
               (SELECT upstream_error FROM file_versions
                WHERE vault_id = $1 AND upstream_state = 'pending' AND upstream_error IS NOT NULL
                ORDER BY id DESC LIMIT 1) AS last_error
        FROM file_versions WHERE vault_id = $1 AND upstream_state = 'pending'
    )SQL");

    // Distinct blobs per kind; counts: ready-or-creating snapshots, version rows.
    conn_->prepare("recovery_generation_usage", R"SQL(
        SELECT
            (SELECT count(*) FROM recovery_snapshot WHERE vault_id = $1 AND state IN ('ready', 'creating'))
                AS snapshot_count,
            (SELECT COALESCE(sum(b.cipher_bytes), 0)::bigint FROM recovery_blob b WHERE b.vault_id = $1
                AND EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id AND fv.origin = 'snapshot'))
                AS snapshot_bytes,
            (SELECT COALESCE(sum(b.plaintext_bytes), 0)::bigint FROM recovery_blob b WHERE b.vault_id = $1
                AND EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id AND fv.origin = 'snapshot'))
                AS snapshot_plaintext,
            (SELECT count(*) FROM file_versions WHERE vault_id = $1 AND origin = 'version') AS version_count,
            (SELECT COALESCE(sum(b.cipher_bytes), 0)::bigint FROM recovery_blob b WHERE b.vault_id = $1
                AND EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id AND fv.origin = 'version'))
                AS version_bytes,
            (SELECT COALESCE(sum(b.plaintext_bytes), 0)::bigint FROM recovery_blob b WHERE b.vault_id = $1
                AND EXISTS (SELECT 1 FROM file_versions fv WHERE fv.blob_id = b.id AND fv.origin = 'version'))
                AS version_plaintext
    )SQL");

    // Every local version of the vault with its rank per file key (1 = newest) and how many version rows share its
    // blob; the caller applies the rule (Generation::listPrunable).
    conn_->prepare("recovery_generation_retention_candidates",
                   "SELECT " + generationColumns + ", ranked.rn, "
                   "       (SELECT count(*) FROM file_versions o WHERE o.blob_id = fv.blob_id AND o.origin = 'version') "
                   "           AS blob_version_refs "
                   "FROM (SELECT id, row_number() OVER (PARTITION BY COALESCE('f' || file_id::text, 'p' || path) "
                   "                                    ORDER BY version_number DESC, id DESC) AS rn "
                   "      FROM file_versions WHERE vault_id = $1 AND origin = 'version') ranked "
                   "JOIN file_versions fv ON fv.id = ranked.id "
                   "LEFT JOIN recovery_blob b ON b.id = fv.blob_id "
                   "ORDER BY fv.created_at, fv.id");

    conn_->prepare("recovery_generation_delete_versions",
                   "DELETE FROM file_versions WHERE vault_id = $1 AND id = ANY($2::bigint[]) AND origin = 'version' "
                   "AND snapshot_id IS NULL AND upstream_state <> 'pending' RETURNING blob_id");

    // ---- plans ----
    const std::string planColumns = R"SQL(
        id, vault_id, token, source::text AS source, destination, items::text AS items, summary::text AS summary, state,
        result::text AS result, extract(epoch FROM created_at)::bigint AS created_at,
        extract(epoch FROM expires_at)::bigint AS expires_at, extract(epoch FROM started_at)::bigint AS started_at,
        extract(epoch FROM completed_at)::bigint AS completed_at, created_by
    )SQL";

    conn_->prepare("recovery_plan_insert", R"SQL(
        INSERT INTO recovery_plan (vault_id, token, source, destination, items, summary, expires_at, created_by)
        VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6::jsonb, to_timestamp($7::double precision), $8)
        RETURNING id
    )SQL");

    conn_->prepare("recovery_plan_get", "SELECT " + planColumns + " FROM recovery_plan WHERE id = $1");

    conn_->prepare("recovery_plan_start", R"SQL(
        UPDATE recovery_plan SET state = 'running', started_at = COALESCE(started_at, CURRENT_TIMESTAMP)
        WHERE id = $1 AND (state IN ('running', 'partial')
                           OR (state = 'planned' AND expires_at > to_timestamp($2::double precision)))
    )SQL");

    conn_->prepare("recovery_plan_finish", R"SQL(
        UPDATE recovery_plan SET state = $2, result = $3::jsonb, completed_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND state = 'running'
    )SQL");

    conn_->prepare("recovery_plan_save_result", "UPDATE recovery_plan SET result = $2::jsonb WHERE id = $1");

    conn_->prepare("recovery_plan_save_items",
                   "UPDATE recovery_plan SET items = $2::jsonb WHERE id = $1 AND state IN ('planned', 'running', 'partial')");

    conn_->prepare("recovery_plan_expire",
                   "UPDATE recovery_plan SET state = 'expired' "
                   "WHERE state = 'planned' AND expires_at <= to_timestamp($1::double precision)");

    conn_->prepare("recovery_plan_purge", R"SQL(
        DELETE FROM recovery_plan
        WHERE state IN ('done', 'failed', 'expired') AND COALESCE(completed_at, created_at) < to_timestamp($1::double precision)
    )SQL");

    conn_->prepare("recovery_plan_list_by_vault",
                   "SELECT " + planColumns + " FROM recovery_plan WHERE vault_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2");
}
