#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedHealthFindingState() const {
    conn_->prepare("health_finding_state.list",
        R"SQL(
            SELECT class, subject, state, severity, set_by, set_by_name,
                   EXTRACT(EPOCH FROM set_at)::bigint AS set_at,
                   EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at,
                   note
            FROM health_finding_state
            ORDER BY class, subject;
        )SQL"
    );

    conn_->prepare("health_finding_state.put",
        R"SQL(
            INSERT INTO health_finding_state (class, subject, state, severity, set_by, set_by_name, expires_at, note)
            VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7::bigint), $8)
            ON CONFLICT (class, subject) DO UPDATE
               SET state = EXCLUDED.state,
                   severity = EXCLUDED.severity,
                   set_by = EXCLUDED.set_by,
                   set_by_name = EXCLUDED.set_by_name,
                   set_at = NOW(),
                   expires_at = EXCLUDED.expires_at,
                   note = EXCLUDED.note
            RETURNING class, subject, state, severity, set_by, set_by_name,
                      EXTRACT(EPOCH FROM set_at)::bigint AS set_at,
                      EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at,
                      note;
        )SQL"
    );

    conn_->prepare("health_finding_state.remove",
        R"SQL(
            DELETE FROM health_finding_state WHERE class = $1 AND subject = $2;
        )SQL"
    );
}
