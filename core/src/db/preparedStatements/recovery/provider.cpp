#include "db/DBConnection.hpp"

#include <string>

// upstream_object_version and vault_upstream_usage_daily (migration 111). Times are read as epoch seconds and written
// from epoch seconds (to_timestamp; fractional seconds kept where a listing's start time is compared).
void vh::db::Connection::initPreparedRecoveryProvider() const {
    // ---- provider object versions ----
    const std::string versionColumns = R"SQL(
        v.id, v.vault_id, v.object_key, v.version_id, v.is_delete_marker, v.is_latest, v.etag, v.size_bytes,
        v.storage_class, extract(epoch FROM v.last_modified)::bigint AS last_modified, v.origin, v.encrypted,
        v.encryption_iv, v.key_version, v.content_hash, v.plaintext_bytes,
        extract(epoch FROM v.became_noncurrent_at)::bigint AS became_noncurrent_at,
        extract(epoch FROM v.gone_at)::bigint AS gone_at, extract(epoch FROM v.first_seen_at)::bigint AS first_seen_at,
        extract(epoch FROM v.last_seen_at)::bigint AS last_seen_at
    )SQL";

    // Never downgrades origin 'vaulthalla'; metadata an incoming row lacks is kept; seen again = not gone.
    conn_->prepare("recovery_object_version_upsert", R"SQL(
        INSERT INTO upstream_object_version AS v
            (vault_id, object_key, version_id, is_delete_marker, is_latest, etag, size_bytes, storage_class,
             last_modified, origin, encrypted, encryption_iv, key_version, content_hash, plaintext_bytes,
             became_noncurrent_at, first_seen_at, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, $8,
                CASE WHEN $9::double precision IS NULL THEN NULL ELSE to_timestamp($9::double precision) END,
                $10, $11, $12, $13::int, $14, $15::bigint,
                CASE WHEN $5 OR $16::double precision IS NULL THEN NULL ELSE to_timestamp($16::double precision) END,
                to_timestamp($17::double precision), to_timestamp($17::double precision))
        ON CONFLICT (vault_id, object_key, version_id) DO UPDATE SET
            is_delete_marker = v.is_delete_marker OR EXCLUDED.is_delete_marker,
            is_latest = EXCLUDED.is_latest,
            etag = COALESCE(EXCLUDED.etag, v.etag),
            size_bytes = COALESCE(EXCLUDED.size_bytes, v.size_bytes),
            storage_class = COALESCE(EXCLUDED.storage_class, v.storage_class),
            last_modified = COALESCE(EXCLUDED.last_modified, v.last_modified),
            origin = CASE WHEN v.origin = 'vaulthalla' THEN 'vaulthalla' ELSE EXCLUDED.origin END,
            encrypted = COALESCE(EXCLUDED.encrypted, v.encrypted),
            encryption_iv = COALESCE(EXCLUDED.encryption_iv, v.encryption_iv),
            key_version = COALESCE(EXCLUDED.key_version, v.key_version),
            content_hash = COALESCE(EXCLUDED.content_hash, v.content_hash),
            plaintext_bytes = COALESCE(EXCLUDED.plaintext_bytes, v.plaintext_bytes),
            became_noncurrent_at = CASE WHEN EXCLUDED.is_latest THEN NULL
                                        ELSE COALESCE(v.became_noncurrent_at, EXCLUDED.became_noncurrent_at) END,
            gone_at = NULL,
            last_seen_at = GREATEST(v.last_seen_at, EXCLUDED.last_seen_at)
        RETURNING id
    )SQL");

    conn_->prepare("recovery_object_version_supersede", R"SQL(
        UPDATE upstream_object_version
        SET is_latest = FALSE, became_noncurrent_at = COALESCE(became_noncurrent_at, to_timestamp($4::double precision))
        WHERE vault_id = $1 AND object_key = $2 AND version_id <> $3 AND gone_at IS NULL
          AND (is_latest OR became_noncurrent_at IS NULL)
    )SQL");

    conn_->prepare("recovery_object_version_make_current", R"SQL(
        UPDATE upstream_object_version SET is_latest = TRUE, became_noncurrent_at = NULL
        WHERE vault_id = $1 AND object_key = $2 AND version_id = $3 AND NOT is_latest
    )SQL");

    // is_latest is kept: a version that was current when it disappeared (deleted outright) never accrued
    // noncurrent storage.
    conn_->prepare("recovery_object_version_mark_gone", R"SQL(
        UPDATE upstream_object_version SET gone_at = CURRENT_TIMESTAMP
        WHERE vault_id = $1 AND gone_at IS NULL AND left(object_key, length($2)) = $2
          AND last_seen_at < to_timestamp($3::double precision)
    )SQL");

    conn_->prepare("recovery_object_version_get",
                   "SELECT " + versionColumns + " FROM upstream_object_version v WHERE v.id = $1");

    conn_->prepare("recovery_object_version_find",
                   "SELECT " + versionColumns + " FROM upstream_object_version v "
                   "WHERE v.vault_id = $1 AND v.object_key = $2 AND v.version_id = $3");

    conn_->prepare("recovery_object_version_list_for_key",
                   "SELECT " + versionColumns + " FROM upstream_object_version v "
                   "WHERE v.vault_id = $1 AND v.object_key = $2 AND ($3 OR v.gone_at IS NULL) "
                   "ORDER BY v.is_latest DESC, v.last_modified DESC NULLS LAST, v.id DESC LIMIT $4");

    conn_->prepare("recovery_object_version_list_under_prefix",
                   "SELECT " + versionColumns + " FROM upstream_object_version v "
                   "WHERE v.vault_id = $1 AND left(v.object_key, length($2)) = $2 AND ($3 OR v.gone_at IS NULL) "
                   "ORDER BY v.object_key, v.is_latest DESC, v.last_modified DESC NULLS LAST, v.id DESC LIMIT $4");

    conn_->prepare("recovery_object_version_list_as_of",
                   "SELECT DISTINCT ON (v.object_key) " + versionColumns + " FROM upstream_object_version v "
                   "WHERE v.vault_id = $1 AND left(v.object_key, length($2)) = $2 AND v.gone_at IS NULL "
                   "  AND v.last_modified IS NOT NULL AND v.last_modified <= to_timestamp($3::double precision) "
                   "ORDER BY v.object_key, v.last_modified DESC, v.id DESC LIMIT $4");

    conn_->prepare("recovery_object_version_noncurrent_summary", R"SQL(
        SELECT count(*) FILTER (WHERE NOT is_delete_marker AND NOT is_latest) AS versions,
               COALESCE(sum(size_bytes) FILTER (WHERE NOT is_delete_marker AND NOT is_latest), 0)::bigint AS bytes,
               count(*) FILTER (WHERE NOT is_delete_marker AND NOT is_latest AND size_bytes IS NULL) AS unknown_size,
               count(*) FILTER (WHERE is_delete_marker) AS delete_markers,
               extract(epoch FROM min(COALESCE(became_noncurrent_at, last_modified))
                   FILTER (WHERE NOT is_delete_marker AND NOT is_latest))::bigint AS oldest_noncurrent_at,
               extract(epoch FROM min(last_modified)
                   FILTER (WHERE NOT is_delete_marker AND NOT is_latest))::bigint AS oldest_last_modified
        FROM upstream_object_version WHERE vault_id = $1 AND gone_at IS NULL
    )SQL");

    // Noncurrent from became_noncurrent_at (else last_modified, else first seen: an upper bound) until gone_at (else
    // the window end), clipped to [$2, $3).
    conn_->prepare("recovery_object_version_byte_hours", R"SQL(
        WITH spans AS (
            SELECT size_bytes,
                   GREATEST(COALESCE(became_noncurrent_at, last_modified, first_seen_at),
                            to_timestamp($2::double precision)) AS s,
                   LEAST(COALESCE(gone_at, to_timestamp($3::double precision)),
                         to_timestamp($3::double precision)) AS e
            FROM upstream_object_version
            WHERE vault_id = $1 AND NOT is_delete_marker AND NOT is_latest
        )
        SELECT round(COALESCE(sum(size_bytes::numeric * extract(epoch FROM (e - s)) / 3600)
                         FILTER (WHERE size_bytes IS NOT NULL), 0), 6)::text AS byte_hours,
               count(*) FILTER (WHERE size_bytes IS NOT NULL) AS versions,
               count(*) FILTER (WHERE size_bytes IS NULL) AS unknown_size
        FROM spans WHERE e > s
    )SQL");

    conn_->prepare("recovery_object_version_key_versions",
                   "SELECT DISTINCT key_version FROM upstream_object_version "
                   "WHERE vault_id = $1 AND gone_at IS NULL AND key_version IS NOT NULL ORDER BY key_version");

    // ---- usage counters ----
    conn_->prepare("recovery_usage_add", R"SQL(
        INSERT INTO vault_upstream_usage_daily AS u
            (vault_id, day, list_requests, head_requests, get_requests, put_requests, copy_requests, delete_requests,
             multipart_uploads, multipart_parts, uploaded_bytes, downloaded_bytes, first_put_objects, first_put_bytes,
             overwrite_objects, overwritten_bytes, deleted_objects, deleted_bytes, version_list_requests,
             version_restore_requests, version_restore_bytes, updated_at)
        VALUES ($1, $2::date, $3::bigint, $4::bigint, $5::bigint, $6::bigint, $7::bigint, $8::bigint, $9::bigint,
                $10::bigint, $11::bigint, $12::bigint, $13::bigint, $14::bigint, $15::bigint, $16::bigint, $17::bigint,
                $18::bigint, $19::bigint, $20::bigint, $21::bigint, CURRENT_TIMESTAMP)
        ON CONFLICT (vault_id, day) DO UPDATE SET
            list_requests = u.list_requests + EXCLUDED.list_requests,
            head_requests = u.head_requests + EXCLUDED.head_requests,
            get_requests = u.get_requests + EXCLUDED.get_requests,
            put_requests = u.put_requests + EXCLUDED.put_requests,
            copy_requests = u.copy_requests + EXCLUDED.copy_requests,
            delete_requests = u.delete_requests + EXCLUDED.delete_requests,
            multipart_uploads = u.multipart_uploads + EXCLUDED.multipart_uploads,
            multipart_parts = u.multipart_parts + EXCLUDED.multipart_parts,
            uploaded_bytes = u.uploaded_bytes + EXCLUDED.uploaded_bytes,
            downloaded_bytes = u.downloaded_bytes + EXCLUDED.downloaded_bytes,
            first_put_objects = u.first_put_objects + EXCLUDED.first_put_objects,
            first_put_bytes = u.first_put_bytes + EXCLUDED.first_put_bytes,
            overwrite_objects = u.overwrite_objects + EXCLUDED.overwrite_objects,
            overwritten_bytes = u.overwritten_bytes + EXCLUDED.overwritten_bytes,
            deleted_objects = u.deleted_objects + EXCLUDED.deleted_objects,
            deleted_bytes = u.deleted_bytes + EXCLUDED.deleted_bytes,
            version_list_requests = u.version_list_requests + EXCLUDED.version_list_requests,
            version_restore_requests = u.version_restore_requests + EXCLUDED.version_restore_requests,
            version_restore_bytes = u.version_restore_bytes + EXCLUDED.version_restore_bytes,
            updated_at = CURRENT_TIMESTAMP
    )SQL");

    const std::string usageColumns = R"SQL(
        list_requests, head_requests, get_requests, put_requests, copy_requests, delete_requests, multipart_uploads,
        multipart_parts, uploaded_bytes, downloaded_bytes, first_put_objects, first_put_bytes, overwrite_objects,
        overwritten_bytes, deleted_objects, deleted_bytes, version_list_requests, version_restore_requests,
        version_restore_bytes
    )SQL";

    conn_->prepare("recovery_usage_range",
                   "SELECT vault_id, to_char(day, 'YYYY-MM-DD') AS day, " + usageColumns +
                   " FROM vault_upstream_usage_daily WHERE vault_id = $1 AND day BETWEEN $2::date AND $3::date "
                   "ORDER BY day");

    conn_->prepare("recovery_usage_last_days",
                   "SELECT vault_id, to_char(day, 'YYYY-MM-DD') AS day, " + usageColumns +
                   " FROM vault_upstream_usage_daily WHERE vault_id = $1 AND day > CURRENT_DATE - $2::int "
                   "AND day <= CURRENT_DATE ORDER BY day");

    // Sums as bigint (numeric sum cast back): counters never approach 2^63.
    std::string sums;
    for (const auto* c : {"list_requests", "head_requests", "get_requests", "put_requests", "copy_requests",
                          "delete_requests", "multipart_uploads", "multipart_parts", "uploaded_bytes",
                          "downloaded_bytes", "first_put_objects", "first_put_bytes", "overwrite_objects",
                          "overwritten_bytes", "deleted_objects", "deleted_bytes", "version_list_requests",
                          "version_restore_requests", "version_restore_bytes"})
        sums += std::string(sums.empty() ? "" : ", ") + "COALESCE(sum(" + c + "), 0)::bigint AS " + c;

    conn_->prepare("recovery_usage_totals",
                   "SELECT count(*) AS days, to_char(min(day), 'YYYY-MM-DD') AS first_day, "
                   "to_char(max(day), 'YYYY-MM-DD') AS last_day, " + sums +
                   " FROM vault_upstream_usage_daily WHERE vault_id = $1 "
                   "AND ($2::date IS NULL OR day >= $2::date) AND ($3::date IS NULL OR day <= $3::date)");
}
