-- Health findings: what an operator said about them (design/health/findings.md §3; health::Findings, ops::health).
--
-- A finding is computed, never stored: the dashboard cards raise it under a stable code, its class. This table holds
-- only the two things a person can say about a class (and a subject, '' for the whole server, which is every
-- finding today):
--   acknowledged  "I have seen this occurrence". Removed when the finding clears or its severity rises.
--   silenced      "do not tell me about this class". Kept until expires_at, or until someone turns it back on; it
--                 does not cover a severity above the one recorded here.
-- The server holds it so the web console, the CLI and every paired Mac show the same thing. Severity is never
-- rewritten by it: a silenced error is still an error (stats never fake health).
--
-- Changing it needs a new permission, admin.stats.manage (admin_role.stats_permissions bit 1). Built-in roles are
-- seeded from core only on a fresh database, where super_admin holds every stats permission; on an upgraded one the
-- built-in super_admin gets the bit here, and the permission is listed in the catalog. No other role gains it.
--
-- Additive: one new table, one permission row, one bit on one built-in role. Safe to run again.
CREATE TABLE IF NOT EXISTS health_finding_state (
    class       TEXT        NOT NULL,
    subject     TEXT        NOT NULL DEFAULT '',
    state       TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    set_by      INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    set_by_name TEXT        NOT NULL,
    set_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    note        TEXT,
    PRIMARY KEY (class, subject),
    CONSTRAINT health_finding_state_class_len CHECK (length(class) BETWEEN 1 AND 128),
    CONSTRAINT health_finding_state_subject_len CHECK (length(subject) <= 128),
    CONSTRAINT health_finding_state_state CHECK (state IN ('acknowledged', 'silenced')),
    CONSTRAINT health_finding_state_severity CHECK (severity IN ('warning', 'error')),
    CONSTRAINT health_finding_state_note_len CHECK (note IS NULL OR length(note) <= 500),
    -- An acknowledgement lasts as long as its occurrence, never until a date.
    CONSTRAINT health_finding_state_ack_no_expiry CHECK (state <> 'acknowledged' OR expires_at IS NULL)
);

UPDATE admin_role
SET stats_permissions = stats_permissions | B'00000010'
WHERE name = 'super_admin'
  AND get_bit(stats_permissions, 7 - 1) = 0;

INSERT INTO permission (name, description, category, bit_position)
VALUES ('admin.stats.manage', 'Allows acknowledging and silencing health findings.', 'admin', 1)
ON CONFLICT DO NOTHING;
