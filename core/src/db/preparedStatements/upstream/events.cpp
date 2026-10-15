#include "db/DBConnection.hpp"

// upstream_event_channel, upstream_event_subscription, upstream_event_inbox, upstream_write_intent (migration 110).
// Times arrive as epoch seconds and go through to_timestamp.
void vh::db::Connection::initPreparedUpstreamEvents() const {
    // ---- channels ----
    conn_->prepare("upstream_channel_get_or_create", R"SQL(
        INSERT INTO upstream_event_channel (provider, account_ref, region, queue_name, api_key_id)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (provider, account_ref, region, queue_name) DO UPDATE SET
            api_key_id = COALESCE(EXCLUDED.api_key_id, upstream_event_channel.api_key_id),
            state      = CASE WHEN upstream_event_channel.state = 'removed' THEN 'provisioning'
                              ELSE upstream_event_channel.state END,
            updated_at = CURRENT_TIMESTAMP
        RETURNING *
    )SQL");

    conn_->prepare("upstream_channel_get", "SELECT * FROM upstream_event_channel WHERE id = $1");

    conn_->prepare("upstream_channel_find", R"SQL(
        SELECT * FROM upstream_event_channel
        WHERE provider = $1 AND account_ref = $2 AND region = $3 AND state <> 'removed'
        ORDER BY (state = 'active') DESC, id
        LIMIT 1
    )SQL");

    conn_->prepare("upstream_channel_update_refs", R"SQL(
        UPDATE upstream_event_channel SET
            queue_ref = $2, queue_arn = $3, dlq_ref = $4, dlq_arn = $5,
            created_by_vaulthalla = created_by_vaulthalla OR $6, state = $7, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_channel_set_state", R"SQL(
        UPDATE upstream_event_channel SET
            state = $2,
            last_error = CASE WHEN $3::text IS NULL THEN last_error WHEN $3 = '' THEN NULL ELSE $3 END,
            last_error_at = CASE WHEN $3::text IS NULL OR $3 = '' THEN last_error_at ELSE CURRENT_TIMESTAMP END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_channel_set_api_key",
                   "UPDATE upstream_event_channel SET api_key_id = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1");

    conn_->prepare("upstream_channel_record_poll_ok", R"SQL(
        UPDATE upstream_event_channel SET
            last_poll_at = CURRENT_TIMESTAMP,
            last_success_at = CURRENT_TIMESTAMP,
            last_message_at = CASE WHEN $2::int > 0 THEN CURRENT_TIMESTAMP ELSE last_message_at END,
            consecutive_failures = 0,
            backlog_estimate = COALESCE($3::bigint, backlog_estimate),
            next_poll_at = CASE WHEN $4::double precision IS NULL THEN NULL ELSE to_timestamp($4::double precision) END,
            state = CASE WHEN state = 'degraded' THEN 'active' ELSE state END,
            -- A delivery gap longer than what the queue keeps: messages may have expired unread.
            continuity_broken_at = CASE
                WHEN last_success_at IS NOT NULL
                     AND last_success_at < CURRENT_TIMESTAMP - make_interval(secs => $5::double precision)
                THEN CURRENT_TIMESTAMP ELSE continuity_broken_at END,
            continuity_note = CASE
                WHEN last_success_at IS NOT NULL
                     AND last_success_at < CURRENT_TIMESTAMP - make_interval(secs => $5::double precision)
                THEN 'no successful poll for longer than the queue retention' ELSE continuity_note END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_channel_mark_continuity_broken", R"SQL(
        UPDATE upstream_event_channel SET continuity_broken_at = CURRENT_TIMESTAMP, continuity_note = $2,
                                          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_channel_set_dlq_depth", R"SQL(
        UPDATE upstream_event_channel SET dlq_depth = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1
    )SQL");

    conn_->prepare("upstream_channel_record_poll_failed", R"SQL(
        UPDATE upstream_event_channel SET
            last_poll_at = CURRENT_TIMESTAMP,
            consecutive_failures = consecutive_failures + 1,
            last_error = $2,
            last_error_at = CURRENT_TIMESTAMP,
            next_poll_at = CASE WHEN $3::double precision IS NULL THEN NULL ELSE to_timestamp($3::double precision) END,
            state = CASE WHEN state = 'active' AND consecutive_failures + 1 >= 3 THEN 'degraded' ELSE state END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_channel_list_pollable", R"SQL(
        SELECT c.* FROM upstream_event_channel c
        WHERE c.state IN ('active', 'degraded')
          AND c.api_key_id IS NOT NULL
          AND EXISTS (SELECT 1 FROM upstream_event_subscription s
                      WHERE s.channel_id = c.id AND s.state IN ('pending', 'active'))
        ORDER BY c.id
    )SQL");

    conn_->prepare("upstream_channel_count_subscriptions", R"SQL(
        SELECT COUNT(*) FROM upstream_event_subscription WHERE channel_id = $1 AND state = ANY($2::text[])
    )SQL");

    // ---- subscriptions ----
    conn_->prepare("upstream_subscription_create", R"SQL(
        INSERT INTO upstream_event_subscription (channel_id, upstream_bucket_id, vault_id, prefix, foreign_objects,
                                                 baseline_state)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (vault_id) WHERE state <> 'removed' AND vault_id IS NOT NULL DO NOTHING
        RETURNING *
    )SQL");

    conn_->prepare("upstream_subscription_get", "SELECT * FROM upstream_event_subscription WHERE id = $1");

    conn_->prepare("upstream_subscription_get_live_for_vault",
                   "SELECT * FROM upstream_event_subscription WHERE vault_id = $1 AND state <> 'removed' LIMIT 1");

    conn_->prepare("upstream_subscription_list_live_for_bucket", R"SQL(
        SELECT s.* FROM upstream_event_subscription s
        JOIN upstream_bucket b ON b.id = s.upstream_bucket_id
        WHERE b.provider = $1 AND b.account_ref = $2 AND b.bucket = $3 AND s.state <> 'removed'
        ORDER BY s.id
    )SQL");

    conn_->prepare("upstream_subscription_set_state", R"SQL(
        UPDATE upstream_event_subscription SET
            state = $2,
            last_error = CASE WHEN $3::text IS NULL THEN last_error WHEN $3 = '' THEN NULL ELSE $3 END,
            activated_at = CASE WHEN $2 = 'active' THEN COALESCE(activated_at, CURRENT_TIMESTAMP) ELSE activated_at END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_subscription_set_rule_ids",
                   "UPDATE upstream_event_subscription SET rule_ids = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1");

    conn_->prepare("upstream_subscription_set_channel",
                   "UPDATE upstream_event_subscription SET channel_id = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1");

    conn_->prepare("upstream_subscription_set_settings", R"SQL(
        UPDATE upstream_event_subscription SET prefix = $2, foreign_objects = $3, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_subscription_set_baseline", R"SQL(
        UPDATE upstream_event_subscription SET
            baseline_state = $2,
            baseline_started_at = CASE WHEN $3::double precision IS NULL THEN baseline_started_at
                                       ELSE to_timestamp($3::double precision) END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_subscription_set_foreign_rules",
                   "UPDATE upstream_event_subscription SET foreign_rules = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1");

    conn_->prepare("upstream_subscription_list_for_channel",
                   "SELECT * FROM upstream_event_subscription WHERE channel_id = $1 ORDER BY id");

    conn_->prepare("upstream_subscription_list_by_state",
                   "SELECT * FROM upstream_event_subscription WHERE state = $1 ORDER BY id");

    conn_->prepare("upstream_subscription_list_active_vault_ids", R"SQL(
        SELECT vault_id FROM upstream_event_subscription
        WHERE state = 'active' AND vault_id IS NOT NULL ORDER BY vault_id
    )SQL");

    conn_->prepare("upstream_subscription_count_active_using_key", R"SQL(
        SELECT COUNT(*) FROM upstream_event_subscription s
        JOIN upstream_event_channel c ON c.id = s.channel_id
        WHERE c.api_key_id = $1 AND s.state IN ('pending', 'active', 'removing')
    )SQL");

    // ---- inbox ----
    conn_->prepare("upstream_inbox_insert", R"SQL(
        INSERT INTO upstream_event_inbox (channel_id, subscription_id, vault_id, provider, account_ref, bucket,
                                          object_key, kind, event_name, dedupe_key, message_id, sequencer, version_id,
                                          etag, size_bytes, event_time, state, origin, note, event_time_ms, finished_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, to_timestamp($16::double precision),
                $17, $18, $19, $20, CASE WHEN $17 IN ('skipped', 'done') THEN CURRENT_TIMESTAMP END)
        ON CONFLICT (provider, account_ref, bucket, dedupe_key) DO NOTHING
        RETURNING id
    )SQL");

    // Hex sequencers compare numerically once left-padded: AWS documents "left-pad the shorter value with zeros, then
    // compare lexicographically" (S3 event message structure, `sequencer`).
    conn_->prepare("upstream_inbox_claim_for_vault", R"SQL(
        SELECT * FROM upstream_event_inbox
        WHERE vault_id = $1 AND state = 'pending'
          AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
        ORDER BY object_key, lpad(lower(ltrim(COALESCE(sequencer, ''), '0')), 64, '0'),
                 COALESCE(event_time_ms, (EXTRACT(EPOCH FROM event_time) * 1000)::bigint), id
        LIMIT $2
        FOR UPDATE SKIP LOCKED
    )SQL");

    conn_->prepare("upstream_inbox_list_applied", R"SQL(
        SELECT * FROM upstream_event_inbox
        WHERE vault_id = $1 AND state = 'applied'
          AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
        ORDER BY id
        LIMIT $2
    )SQL");

    conn_->prepare("upstream_inbox_list_vaults_with_work", R"SQL(
        SELECT DISTINCT vault_id FROM upstream_event_inbox
        WHERE vault_id IS NOT NULL AND state IN ('pending', 'applied')
          AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
        ORDER BY vault_id
    )SQL");

    conn_->prepare("upstream_inbox_mark_applied", R"SQL(
        UPDATE upstream_event_inbox SET state = 'applied', origin = COALESCE($2, origin), next_attempt_at = NULL,
                                        last_error = NULL
        WHERE id = ANY($1::bigint[]) AND state = 'pending'
    )SQL");

    conn_->prepare("upstream_inbox_mark_done", R"SQL(
        UPDATE upstream_event_inbox SET state = 'done', finished_at = CURRENT_TIMESTAMP, next_attempt_at = NULL,
                                        last_error = NULL
        WHERE id = ANY($1::bigint[]) AND state = 'applied'
    )SQL");

    conn_->prepare("upstream_inbox_mark_skipped", R"SQL(
        UPDATE upstream_event_inbox SET state = 'skipped', note = $2, origin = $3, finished_at = CURRENT_TIMESTAMP,
                                        next_attempt_at = NULL
        WHERE id = ANY($1::bigint[]) AND state IN ('pending', 'applied')
    )SQL");

    conn_->prepare("upstream_inbox_mark_failed", R"SQL(
        UPDATE upstream_event_inbox SET
            attempts = attempts + 1,
            last_error = $2,
            state = CASE WHEN $3::double precision IS NULL THEN 'failed' ELSE state END,
            next_attempt_at = CASE WHEN $3::double precision IS NULL THEN NULL ELSE to_timestamp($3::double precision) END,
            finished_at = CASE WHEN $3::double precision IS NULL THEN CURRENT_TIMESTAMP ELSE finished_at END
        WHERE id = $1 AND state IN ('pending', 'applied')
    )SQL");

    conn_->prepare("upstream_inbox_requeue_applied", R"SQL(
        UPDATE upstream_event_inbox SET
            attempts = attempts + 1,
            next_attempt_at = to_timestamp($3::double precision),
            last_error = NULLIF($4, '')
        WHERE vault_id = $1 AND id = ANY($2::bigint[]) AND state = 'applied'
    )SQL");

    conn_->prepare("upstream_inbox_counts", R"SQL(
        SELECT
            COUNT(*) FILTER (WHERE state = 'pending')                                                   AS pending,
            COUNT(*) FILTER (WHERE state = 'applied')                                                   AS applied,
            COUNT(*) FILTER (WHERE state = 'failed')                                                    AS failed,
            COUNT(*) FILTER (WHERE state = 'done' AND finished_at > CURRENT_TIMESTAMP - INTERVAL '24 hours') AS done_24h,
            COUNT(*) FILTER (WHERE origin = 'self' AND received_at > CURRENT_TIMESTAMP - INTERVAL '24 hours') AS self_24h,
            MAX(event_time)                                                                             AS last_event_at
        FROM upstream_event_inbox
        WHERE vault_id = $1
    )SQL");

    // Events that arrived (and were stored as unrouted) while the subscription was being set up: only keys under its
    // prefix and only since just before it was created become work again; older ones stay skipped.
    conn_->prepare("upstream_inbox_route_unassigned", R"SQL(
        UPDATE upstream_event_inbox SET vault_id = $4, subscription_id = $5, state = 'pending', note = NULL,
                                        finished_at = NULL, next_attempt_at = NULL
        WHERE vault_id IS NULL AND state = 'skipped' AND provider = $1 AND account_ref = $2 AND bucket = $3
          AND starts_with(object_key, $6) AND received_at >= to_timestamp($7::double precision)
    )SQL");

    conn_->prepare("upstream_inbox_sweep_finished", R"SQL(
        DELETE FROM upstream_event_inbox
        WHERE state IN ('done', 'skipped')
          AND finished_at < CURRENT_TIMESTAMP - make_interval(secs => $1::double precision)
    )SQL");

    conn_->prepare("upstream_inbox_latest_for_key", R"SQL(
        SELECT * FROM upstream_event_inbox
        WHERE vault_id = $1 AND object_key = $2
        ORDER BY lpad(lower(ltrim(COALESCE(sequencer, ''), '0')), 64, '0') DESC,
                 COALESCE(event_time_ms, (EXTRACT(EPOCH FROM event_time) * 1000)::bigint) DESC, id DESC
        LIMIT 1
    )SQL");

    // ---- write intents ----
    conn_->prepare("upstream_write_intent_record", R"SQL(
        INSERT INTO upstream_write_intent (vault_id, object_key, op, expected_size, expires_at)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP + make_interval(secs => $5::double precision))
        RETURNING id
    )SQL");

    conn_->prepare("upstream_write_intent_consume", R"SQL(
        DELETE FROM upstream_write_intent
        WHERE id = (
            SELECT id FROM upstream_write_intent
            WHERE vault_id = $1 AND object_key = $2 AND op = $3
              AND expires_at > CURRENT_TIMESTAMP
              AND recorded_at <= to_timestamp($5::double precision) + INTERVAL '5 seconds'
              AND ($4::bigint IS NULL OR expected_size IS NULL OR expected_size = $4::bigint)
              AND ($6::text IS NULL OR etag IS NULL OR etag = $6::text)
            ORDER BY recorded_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id
    )SQL");

    // The request finished: the intent lives `ttl` from now (a long multipart upload must not outlive its intent).
    conn_->prepare("upstream_write_intent_complete", R"SQL(
        UPDATE upstream_write_intent SET completed_at = CURRENT_TIMESTAMP, etag = COALESCE($2, etag),
                                         expires_at = CURRENT_TIMESTAMP + make_interval(secs => $3::double precision)
        WHERE id = $1
    )SQL");

    conn_->prepare("upstream_write_intent_remove", "DELETE FROM upstream_write_intent WHERE id = $1");

    conn_->prepare("upstream_write_intent_sweep",
                   "DELETE FROM upstream_write_intent WHERE expires_at <= CURRENT_TIMESTAMP");
}
