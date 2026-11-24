#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedSyncThroughput() const {
    // ---------------------------------------
    // UPSERT (overwrite values)
    // num_ops, failed_ops, size_bytes and duration_ms are BIGINT: the parameters are cast (sync_event.upsert says why).
    // ---------------------------------------
    conn_->prepare("sync_throughput.upsert",
                   R"SQL(
            INSERT INTO sync_throughput
            (
                vault_id,
                run_uuid,
                metric_type,
                num_ops,
                failed_ops,
                size_bytes,
                duration_ms
            )
            VALUES
            (
                $1,
                $2,
                $3,
                COALESCE($4::bigint, 0),
                COALESCE($5::bigint, 0),
                COALESCE($6::bigint, 0),
                COALESCE($7::bigint, 0)
            )
            ON CONFLICT (vault_id, run_uuid, metric_type)
            DO UPDATE SET
                num_ops     = EXCLUDED.num_ops,
                failed_ops  = EXCLUDED.failed_ops,
                size_bytes  = EXCLUDED.size_bytes,
                duration_ms = EXCLUDED.duration_ms
            RETURNING id;
        )SQL"
    );

    // ---------------------------------------
    // ACCUMULATE (additive worker updates)
    // ---------------------------------------
    conn_->prepare("sync_throughput.accumulate",
                   R"SQL(
            INSERT INTO sync_throughput
            (
                vault_id,
                run_uuid,
                metric_type,
                num_ops,
                failed_ops,
                size_bytes,
                duration_ms
            )
            VALUES
            (
                $1,
                $2,
                $3,
                COALESCE($4::bigint, 0),
                COALESCE($5::bigint, 0),
                COALESCE($6::bigint, 0),
                COALESCE($7::bigint, 0)
            )
            ON CONFLICT (vault_id, run_uuid, metric_type)
            DO UPDATE SET
                num_ops     = sync_throughput.num_ops + EXCLUDED.num_ops,
                failed_ops  = sync_throughput.failed_ops + EXCLUDED.failed_ops,
                size_bytes  = sync_throughput.size_bytes + EXCLUDED.size_bytes,
                duration_ms = sync_throughput.duration_ms + EXCLUDED.duration_ms
            RETURNING id;
        )SQL"
    );

    // ---------------------------------------
    // READ ALL throughput for run
    // ---------------------------------------
    conn_->prepare("sync_throughput.read_all_for_run",
                   R"SQL(
            SELECT *
            FROM sync_throughput
            WHERE vault_id = $1
              AND run_uuid = $2
            ORDER BY metric_type;
        )SQL"
    );

    // ---------------------------------------
    // DELETE ALL throughput for run
    // ---------------------------------------
    conn_->prepare("sync_throughput.delete_for_run",
                   R"SQL(
            DELETE FROM sync_throughput
            WHERE vault_id = $1
              AND run_uuid = $2;
        )SQL"
    );
}
