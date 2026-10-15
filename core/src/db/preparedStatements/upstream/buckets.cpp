#include "db/DBConnection.hpp"

// upstream_bucket and upstream_audit (migration 110). Times arrive as epoch seconds and go through to_timestamp.
void vh::db::Connection::initPreparedUpstreamBuckets() const {
    conn_->prepare("upstream_bucket_get", "SELECT * FROM upstream_bucket WHERE id = $1");

    conn_->prepare("upstream_bucket_get_by_identity",
                   "SELECT * FROM upstream_bucket WHERE provider = $1 AND account_ref = $2 AND bucket = $3");

    conn_->prepare("upstream_bucket_get_for_vault",
                   "SELECT * FROM upstream_bucket WHERE vault_id = $1 ORDER BY updated_at DESC LIMIT 1");

    conn_->prepare("upstream_bucket_list_for_account",
                   "SELECT * FROM upstream_bucket WHERE provider = $1 AND account_ref = $2 ORDER BY bucket");

    conn_->prepare("upstream_bucket_find_protected_by_name",
                   "SELECT * FROM upstream_bucket WHERE provider = $1 AND bucket = $2 AND is_protected ORDER BY account_ref");

    conn_->prepare("upstream_bucket_record_seen", R"SQL(
        INSERT INTO upstream_bucket (provider, account_ref, bucket, region, last_seen_api_key_id, discovered_at,
                                     last_seen_at)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (provider, account_ref, bucket) DO UPDATE SET
            region               = COALESCE(EXCLUDED.region, upstream_bucket.region),
            last_seen_api_key_id = COALESCE(EXCLUDED.last_seen_api_key_id, upstream_bucket.last_seen_api_key_id),
            discovered_at        = COALESCE(upstream_bucket.discovered_at, CURRENT_TIMESTAMP),
            last_seen_at         = CURRENT_TIMESTAMP,
            updated_at           = CURRENT_TIMESTAMP
    )SQL");

    // The create path's lease. Inserting is the only way in for an unknown identity.
    conn_->prepare("upstream_bucket_claim_insert", R"SQL(
        INSERT INTO upstream_bucket (provider, account_ref, bucket, region, ownership, provisioning_state,
                                     created_by_vaulthalla, operation_token, last_seen_api_key_id)
        VALUES ($1, $2, $3, $4, 'managed', 'creating', TRUE, $5, $6)
        ON CONFLICT (provider, account_ref, bucket) DO NOTHING
        RETURNING *
    )SQL");

    // Our own earlier attempt: unbound, unlocked, and failed, deleted, or abandoned in creating.
    conn_->prepare("upstream_bucket_claim_retry", R"SQL(
        UPDATE upstream_bucket SET
            provisioning_state = 'creating',
            ownership          = 'managed',
            operation_token    = $4,
            region             = COALESCE($5, region),
            last_seen_api_key_id = COALESCE($6, last_seen_api_key_id),
            last_error         = NULL,
            updated_at         = CURRENT_TIMESTAMP
        WHERE provider = $1 AND account_ref = $2 AND bucket = $3
          AND created_by_vaulthalla
          AND vault_id IS NULL
          AND NOT is_protected
          AND (provisioning_state IN ('failed', 'deleted')
               OR (provisioning_state = 'creating' AND updated_at < CURRENT_TIMESTAMP - make_interval(secs => $7::double precision)))
        RETURNING *
    )SQL");

    conn_->prepare("upstream_bucket_lock_by_identity",
                   "SELECT * FROM upstream_bucket WHERE provider = $1 AND account_ref = $2 AND bucket = $3 FOR UPDATE");

    conn_->prepare("upstream_bucket_insert_adopted", R"SQL(
        INSERT INTO upstream_bucket (provider, account_ref, bucket, region, ownership, provisioning_state,
                                     operation_token, last_seen_api_key_id, discovered_at, last_seen_at)
        VALUES ($1, $2, $3, $4, 'adopted', 'configuring', $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING *
    )SQL");

    conn_->prepare("upstream_bucket_take_for_adoption", R"SQL(
        UPDATE upstream_bucket SET
            ownership          = CASE WHEN ownership = 'managed' THEN 'managed' ELSE 'adopted' END,
            provisioning_state = 'configuring',
            operation_token    = $2,
            region             = COALESCE($3, region),
            last_seen_api_key_id = COALESCE($4, last_seen_api_key_id),
            last_error         = NULL,
            updated_at         = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
    )SQL");

    conn_->prepare("upstream_bucket_set_provisioning_state", R"SQL(
        UPDATE upstream_bucket SET provisioning_state = $2, last_error = $4, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND ($3::text IS NULL OR operation_token = $3)
        RETURNING id
    )SQL");

    conn_->prepare("upstream_bucket_bind_vault", R"SQL(
        UPDATE upstream_bucket SET vault_id = $2, ownership = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1
    )SQL");

    conn_->prepare("upstream_bucket_unbind_vault",
                   "UPDATE upstream_bucket SET vault_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1");

    conn_->prepare("upstream_bucket_set_ownership", R"SQL(
        UPDATE upstream_bucket SET ownership = $2, provisioning_state = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1
    )SQL");

    conn_->prepare("upstream_bucket_set_region",
                   "UPDATE upstream_bucket SET region = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1");

    conn_->prepare("upstream_bucket_protect", R"SQL(
        INSERT INTO upstream_bucket (provider, account_ref, bucket, region, is_protected, protected_at, protected_by,
                                     protected_by_name, protection_reason)
        VALUES ($1, $2, $3, $4, TRUE, CURRENT_TIMESTAMP, $5, $6, $7)
        ON CONFLICT (provider, account_ref, bucket) DO UPDATE SET
            region            = COALESCE(upstream_bucket.region, EXCLUDED.region),
            protected_at      = CASE WHEN upstream_bucket.is_protected THEN upstream_bucket.protected_at
                                     ELSE CURRENT_TIMESTAMP END,
            is_protected      = TRUE,
            protected_by      = EXCLUDED.protected_by,
            protected_by_name = EXCLUDED.protected_by_name,
            protection_reason = EXCLUDED.protection_reason,
            updated_at        = CURRENT_TIMESTAMP
        RETURNING *
    )SQL");

    conn_->prepare("upstream_bucket_unprotect", R"SQL(
        UPDATE upstream_bucket SET
            is_protected = FALSE, protected_at = NULL, protected_by = NULL, protected_by_name = NULL,
            protection_reason = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE provider = $1 AND account_ref = $2 AND bucket = $3
        RETURNING *
    )SQL");

    conn_->prepare("upstream_bucket_list_stale_provisioning", R"SQL(
        SELECT * FROM upstream_bucket
        WHERE provisioning_state IN ('creating', 'configuring')
          AND updated_at < CURRENT_TIMESTAMP - make_interval(secs => $1::double precision)
        ORDER BY updated_at
    )SQL");

    conn_->prepare("upstream_audit_append", R"SQL(
        INSERT INTO upstream_audit (user_id, user_name, action, provider, account_ref, bucket, api_key_id, vault_id,
                                    outcome, detail)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
        RETURNING id
    )SQL");

    conn_->prepare("upstream_audit_list", R"SQL(
        SELECT * FROM upstream_audit
        WHERE ($1::text IS NULL OR bucket = $1)
        ORDER BY at DESC, id DESC
        LIMIT $2
    )SQL");
}
