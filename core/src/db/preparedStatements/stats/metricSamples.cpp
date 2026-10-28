#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedStatsMetricSamples() const {
    conn_->prepare("stats_metric_sample.insert",
        R"SQL(
            INSERT INTO stats_metric_sample (
                scope, vault_id, metric_key, series_key, series_label, unit, snapshot_type,
                window_start, window_end, window_seconds, sample_count,
                value_min, value_avg, value_max, value_last, delta_value, rate_per_second, tags
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                to_timestamp($8::double precision), to_timestamp($9::double precision), $10, $11,
                $12, $13, $14, $15, $16, $17, $18::jsonb
            );
        )SQL"
    );

    conn_->prepare("stats_threadpool_sample.upsert",
        R"SQL(
            INSERT INTO stats_threadpool_sample (
                pool_name, window_start, window_end, window_seconds, sample_count,
                pressure_min, pressure_avg, pressure_max, pressure_last,
                queue_depth_min, queue_depth_avg, queue_depth_max, queue_depth_last,
                busy_workers_min, busy_workers_avg, busy_workers_max, busy_workers_last,
                idle_workers_min, idle_workers_avg, idle_workers_max, idle_workers_last,
                pressured_sample_count, saturated_sample_count, queue_depth_high_water,
                pressure_high_water, last_status
            )
            VALUES (
                $1, to_timestamp($2::double precision), to_timestamp($3::double precision), $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, $13,
                $14, $15, $16, $17,
                $18, $19, $20, $21,
                $22, $23, $24, $25, $26
            )
            ON CONFLICT (pool_name, window_start) DO UPDATE SET
                window_end = EXCLUDED.window_end,
                window_seconds = EXCLUDED.window_seconds,
                sample_count = EXCLUDED.sample_count,
                pressure_min = EXCLUDED.pressure_min,
                pressure_avg = EXCLUDED.pressure_avg,
                pressure_max = EXCLUDED.pressure_max,
                pressure_last = EXCLUDED.pressure_last,
                queue_depth_min = EXCLUDED.queue_depth_min,
                queue_depth_avg = EXCLUDED.queue_depth_avg,
                queue_depth_max = EXCLUDED.queue_depth_max,
                queue_depth_last = EXCLUDED.queue_depth_last,
                busy_workers_min = EXCLUDED.busy_workers_min,
                busy_workers_avg = EXCLUDED.busy_workers_avg,
                busy_workers_max = EXCLUDED.busy_workers_max,
                busy_workers_last = EXCLUDED.busy_workers_last,
                idle_workers_min = EXCLUDED.idle_workers_min,
                idle_workers_avg = EXCLUDED.idle_workers_avg,
                idle_workers_max = EXCLUDED.idle_workers_max,
                idle_workers_last = EXCLUDED.idle_workers_last,
                pressured_sample_count = EXCLUDED.pressured_sample_count,
                saturated_sample_count = EXCLUDED.saturated_sample_count,
                queue_depth_high_water = EXCLUDED.queue_depth_high_water,
                pressure_high_water = EXCLUDED.pressure_high_water,
                last_status = EXCLUDED.last_status;
        )SQL"
    );

    conn_->prepare("stats_fuse_op_sample.upsert",
        R"SQL(
            INSERT INTO stats_fuse_op_sample (
                op, window_start, window_end, window_seconds,
                count_delta, success_delta, error_delta,
                expected_error_delta, alertable_error_delta,
                error_rate, expected_error_rate, alertable_error_rate,
                read_bytes_delta, write_bytes_delta,
                avg_latency_ms, max_latency_ms, counter_reset
            )
            VALUES (
                $1, to_timestamp($2::double precision), to_timestamp($3::double precision), $4,
                $5, $6, $7,
                $8, $9,
                $10, $11, $12,
                $13, $14, $15, $16, $17
            )
            ON CONFLICT (op, window_start) DO UPDATE SET
                window_end = EXCLUDED.window_end,
                window_seconds = EXCLUDED.window_seconds,
                count_delta = EXCLUDED.count_delta,
                success_delta = EXCLUDED.success_delta,
                error_delta = EXCLUDED.error_delta,
                expected_error_delta = EXCLUDED.expected_error_delta,
                alertable_error_delta = EXCLUDED.alertable_error_delta,
                error_rate = EXCLUDED.error_rate,
                expected_error_rate = EXCLUDED.expected_error_rate,
                alertable_error_rate = EXCLUDED.alertable_error_rate,
                read_bytes_delta = EXCLUDED.read_bytes_delta,
                write_bytes_delta = EXCLUDED.write_bytes_delta,
                avg_latency_ms = EXCLUDED.avg_latency_ms,
                max_latency_ms = EXCLUDED.max_latency_ms,
                counter_reset = EXCLUDED.counter_reset;
        )SQL"
    );

    conn_->prepare("stats_cache_sample.upsert",
        R"SQL(
            INSERT INTO stats_cache_sample (
                source, window_start, window_end, window_seconds, sample_count,
                hit_delta, miss_delta, eviction_delta, insert_delta, invalidation_delta, hit_rate,
                bytes_read_delta, bytes_written_delta,
                occupancy_min, occupancy_avg, occupancy_max, occupancy_last,
                used_bytes_min, used_bytes_avg, used_bytes_max, used_bytes_last,
                op_count_delta, avg_latency_ms, max_latency_ms, counter_reset
            )
            VALUES (
                $1, to_timestamp($2::double precision), to_timestamp($3::double precision), $4, $5,
                $6, $7, $8, $9, $10, $11,
                $12, $13,
                $14, $15, $16, $17,
                $18, $19, $20, $21,
                $22, $23, $24, $25
            )
            ON CONFLICT (source, window_start) DO UPDATE SET
                window_end = EXCLUDED.window_end,
                window_seconds = EXCLUDED.window_seconds,
                sample_count = EXCLUDED.sample_count,
                hit_delta = EXCLUDED.hit_delta,
                miss_delta = EXCLUDED.miss_delta,
                eviction_delta = EXCLUDED.eviction_delta,
                insert_delta = EXCLUDED.insert_delta,
                invalidation_delta = EXCLUDED.invalidation_delta,
                hit_rate = EXCLUDED.hit_rate,
                bytes_read_delta = EXCLUDED.bytes_read_delta,
                bytes_written_delta = EXCLUDED.bytes_written_delta,
                occupancy_min = EXCLUDED.occupancy_min,
                occupancy_avg = EXCLUDED.occupancy_avg,
                occupancy_max = EXCLUDED.occupancy_max,
                occupancy_last = EXCLUDED.occupancy_last,
                used_bytes_min = EXCLUDED.used_bytes_min,
                used_bytes_avg = EXCLUDED.used_bytes_avg,
                used_bytes_max = EXCLUDED.used_bytes_max,
                used_bytes_last = EXCLUDED.used_bytes_last,
                op_count_delta = EXCLUDED.op_count_delta,
                avg_latency_ms = EXCLUDED.avg_latency_ms,
                max_latency_ms = EXCLUDED.max_latency_ms,
                counter_reset = EXCLUDED.counter_reset;
        )SQL"
    );

    conn_->prepare("stats_metric_rollup.upsert_system",
        R"SQL(
            INSERT INTO stats_metric_rollup (
                scope, vault_id, metric_key, series_key, series_label, unit, snapshot_type,
                resolution_seconds, window_start, window_end,
                value_min, value_avg, value_max, value_last,
                delta_value, rate_per_second, source_sample_count
            )
            VALUES (
                'system', NULL, $1, $2, $3, $4, $5,
                $6::int,
                to_timestamp(floor($7::double precision / ($6::int)::double precision) * ($6::int)::double precision),
                to_timestamp((floor($7::double precision / ($6::int)::double precision) + 1) * ($6::int)::double precision),
                $8, $9, $10, $11, $12, $13, $14
            )
            ON CONFLICT (resolution_seconds, metric_key, series_key, snapshot_type, window_start)
            WHERE scope = 'system' AND vault_id IS NULL
            DO UPDATE SET
                series_label = EXCLUDED.series_label,
                unit = EXCLUDED.unit,
                value_min = CASE
                    WHEN stats_metric_rollup.value_min IS NULL THEN EXCLUDED.value_min
                    WHEN EXCLUDED.value_min IS NULL THEN stats_metric_rollup.value_min
                    ELSE LEAST(stats_metric_rollup.value_min, EXCLUDED.value_min)
                END,
                value_avg = CASE
                    WHEN stats_metric_rollup.value_avg IS NULL THEN EXCLUDED.value_avg
                    WHEN EXCLUDED.value_avg IS NULL THEN stats_metric_rollup.value_avg
                    ELSE (
                        stats_metric_rollup.value_avg * GREATEST(stats_metric_rollup.source_sample_count, 1)
                        + EXCLUDED.value_avg * GREATEST(EXCLUDED.source_sample_count, 1)
                    ) / NULLIF(GREATEST(stats_metric_rollup.source_sample_count, 1) + GREATEST(EXCLUDED.source_sample_count, 1), 0)
                END,
                value_max = CASE
                    WHEN stats_metric_rollup.value_max IS NULL THEN EXCLUDED.value_max
                    WHEN EXCLUDED.value_max IS NULL THEN stats_metric_rollup.value_max
                    ELSE GREATEST(stats_metric_rollup.value_max, EXCLUDED.value_max)
                END,
                value_last = EXCLUDED.value_last,
                delta_value = CASE
                    WHEN stats_metric_rollup.delta_value IS NULL THEN EXCLUDED.delta_value
                    WHEN EXCLUDED.delta_value IS NULL THEN stats_metric_rollup.delta_value
                    ELSE stats_metric_rollup.delta_value + EXCLUDED.delta_value
                END,
                rate_per_second = CASE
                    WHEN stats_metric_rollup.rate_per_second IS NULL THEN EXCLUDED.rate_per_second
                    WHEN EXCLUDED.rate_per_second IS NULL THEN stats_metric_rollup.rate_per_second
                    ELSE (
                        stats_metric_rollup.rate_per_second * GREATEST(stats_metric_rollup.source_sample_count, 1)
                        + EXCLUDED.rate_per_second * GREATEST(EXCLUDED.source_sample_count, 1)
                    ) / NULLIF(GREATEST(stats_metric_rollup.source_sample_count, 1) + GREATEST(EXCLUDED.source_sample_count, 1), 0)
                END,
                source_sample_count = stats_metric_rollup.source_sample_count + EXCLUDED.source_sample_count;
        )SQL"
    );

    conn_->prepare("stats_metric_rollup.upsert_vault",
        R"SQL(
            INSERT INTO stats_metric_rollup (
                scope, vault_id, metric_key, series_key, series_label, unit, snapshot_type,
                resolution_seconds, window_start, window_end,
                value_min, value_avg, value_max, value_last,
                delta_value, rate_per_second, source_sample_count
            )
            VALUES (
                'vault', $1, $2, $3, $4, $5, $6,
                $7::int,
                to_timestamp(floor($8::double precision / ($7::int)::double precision) * ($7::int)::double precision),
                to_timestamp((floor($8::double precision / ($7::int)::double precision) + 1) * ($7::int)::double precision),
                $9, $10, $11, $12, $13, $14, $15
            )
            ON CONFLICT (resolution_seconds, vault_id, metric_key, series_key, snapshot_type, window_start)
            WHERE scope = 'vault' AND vault_id IS NOT NULL
            DO UPDATE SET
                series_label = EXCLUDED.series_label,
                unit = EXCLUDED.unit,
                value_min = CASE
                    WHEN stats_metric_rollup.value_min IS NULL THEN EXCLUDED.value_min
                    WHEN EXCLUDED.value_min IS NULL THEN stats_metric_rollup.value_min
                    ELSE LEAST(stats_metric_rollup.value_min, EXCLUDED.value_min)
                END,
                value_avg = CASE
                    WHEN stats_metric_rollup.value_avg IS NULL THEN EXCLUDED.value_avg
                    WHEN EXCLUDED.value_avg IS NULL THEN stats_metric_rollup.value_avg
                    ELSE (
                        stats_metric_rollup.value_avg * GREATEST(stats_metric_rollup.source_sample_count, 1)
                        + EXCLUDED.value_avg * GREATEST(EXCLUDED.source_sample_count, 1)
                    ) / NULLIF(GREATEST(stats_metric_rollup.source_sample_count, 1) + GREATEST(EXCLUDED.source_sample_count, 1), 0)
                END,
                value_max = CASE
                    WHEN stats_metric_rollup.value_max IS NULL THEN EXCLUDED.value_max
                    WHEN EXCLUDED.value_max IS NULL THEN stats_metric_rollup.value_max
                    ELSE GREATEST(stats_metric_rollup.value_max, EXCLUDED.value_max)
                END,
                value_last = EXCLUDED.value_last,
                delta_value = CASE
                    WHEN stats_metric_rollup.delta_value IS NULL THEN EXCLUDED.delta_value
                    WHEN EXCLUDED.delta_value IS NULL THEN stats_metric_rollup.delta_value
                    ELSE stats_metric_rollup.delta_value + EXCLUDED.delta_value
                END,
                rate_per_second = CASE
                    WHEN stats_metric_rollup.rate_per_second IS NULL THEN EXCLUDED.rate_per_second
                    WHEN EXCLUDED.rate_per_second IS NULL THEN stats_metric_rollup.rate_per_second
                    ELSE (
                        stats_metric_rollup.rate_per_second * GREATEST(stats_metric_rollup.source_sample_count, 1)
                        + EXCLUDED.rate_per_second * GREATEST(EXCLUDED.source_sample_count, 1)
                    ) / NULLIF(GREATEST(stats_metric_rollup.source_sample_count, 1) + GREATEST(EXCLUDED.source_sample_count, 1), 0)
                END,
                source_sample_count = stats_metric_rollup.source_sample_count + EXCLUDED.source_sample_count;
        )SQL"
    );

    conn_->prepare("stats_threadpool_sample.purge_older_than",
        R"SQL(
            DELETE FROM stats_threadpool_sample WHERE window_end < CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day');
        )SQL"
    );

    conn_->prepare("stats_fuse_op_sample.purge_older_than",
        R"SQL(
            DELETE FROM stats_fuse_op_sample WHERE window_end < CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day');
        )SQL"
    );

    conn_->prepare("stats_cache_sample.purge_older_than",
        R"SQL(
            DELETE FROM stats_cache_sample WHERE window_end < CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day');
        )SQL"
    );

    conn_->prepare("stats_metric_sample.purge_older_than",
        R"SQL(
            DELETE FROM stats_metric_sample WHERE window_end < CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day');
        )SQL"
    );

    // One rollup tier ($1 = resolution_seconds) at a time: each has its own retention (stats_snapshots.rollup_*).
    conn_->prepare("stats_samples.purge_rollups_older_than",
        R"SQL(
            DELETE FROM stats_metric_rollup
            WHERE resolution_seconds = $1::int
              AND window_end < CURRENT_TIMESTAMP - ($2::int * INTERVAL '1 day');
        )SQL"
    );
}
