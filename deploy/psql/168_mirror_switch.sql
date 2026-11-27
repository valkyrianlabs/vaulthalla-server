-- Moving the core and resync (server mirror phase 2, wave 5 piece B; design/peers/mirror.md "Parity", "Moving the
-- core", "As built: resync and the scrub", "As built: the planned switch"; db::query::mirror::Resync,
-- db::query::mirror::Switches, mirror::resync, mirror::switching).
--
--   mirror_vault.resync_at / resync_by / resync_count   mirror: when a person here (users.id) last started the copy
--                      over from the core's tree (mirror.resync), and how many times. While the copy that a resync
--                      started is unfinished, the first-copy applier takes this server's own entries as they are (by
--                      uid) instead of refusing them, and at its end keeps what the core's tree does not hold as held
--                      changes. Core: when its mirror last asked it to start over.
--   mirror_vault.scrubbed_at   both: when the scrub (the entry hashes recomputed from the tables and compared with
--                      the recorded ones) last ran for the vault.
--   mirror_vault.state 'switching'   a planned switch of the core role (mirror.switch) holds the vault read-only on
--                      this server: on the core from its freeze until it decided (and, once it is the mirror, until the
--                      new core confirmed); on the mirror from the core's first prepare until the decision arrives.
--   mirror_switch      one row per planned switch on each server that took part (the protocol's state, then its
--                      record): the shared switch_id, this server's side when it began, the phase, the term it
--                      leaves, the core's last numbered position and digest under the freeze, the writers the freeze
--                      waited for, whether the core's decision is still to be told to the mirror, who asked and
--                      where, why it was abandoned, its deadline. At most one open switch per vault.
--
-- The backstop of the freeze: vh_mirror_core_term (every entry trigger of a core vault asks it for the term) and the
-- vault-settings trigger refuse a change of a core vault whose row is switching, so nothing commits on the core after
-- the position the switch hands over; the write surfaces refuse first (mirror::access, reason mirror_switching).
--
-- Idempotent and safe on upgraded installs: new nullable columns and one with a default, a new table, the state CHECK
-- widened once, two functions replaced; nothing is mirrored before this release.

ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS resync_at TIMESTAMPTZ;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS resync_by INTEGER;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS resync_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS scrubbed_at TIMESTAMPTZ;

-- 164's CHECK on state, replaced once by one that knows 'switching'.
DO $$
DECLARE
    c RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'mirror_vault'::regclass AND contype = 'c' AND conname = 'mirror_vault_state_check'
                     AND pg_get_constraintdef(oid) LIKE '%''switching''%') THEN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'mirror_vault'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%state%' AND pg_get_constraintdef(oid) LIKE '%''diverged''%'
        LOOP
            EXECUTE format('ALTER TABLE mirror_vault DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE mirror_vault ADD CONSTRAINT mirror_vault_state_check
            CHECK (state IN ('starting', 'live', 'paused', 'diverged', 'expired', 'stopped', 'switching'));
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------- the switch

CREATE TABLE IF NOT EXISTS mirror_switch
(
    id            BIGSERIAL PRIMARY KEY,
    switch_id     UUID        NOT NULL,
    vault_id      INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    peer_id       INTEGER     NOT NULL REFERENCES peer (id),
    -- this server's role when the switch began
    side          TEXT        NOT NULL CHECK (side IN ('core', 'mirror')),
    -- core: draining -> preparing -> switched | abandoned; mirror: requested -> preparing -> prepared -> switched |
    -- abandoned
    phase         TEXT        NOT NULL CHECK (phase IN ('requested', 'draining', 'preparing', 'prepared', 'switched',
                                                        'abandoned')),
    term          BIGINT      NOT NULL CHECK (term >= 1),     -- the term the switch leaves; the new one is term + 1
    seq           BIGINT      CHECK (seq IS NULL OR seq >= 0),
    digest        BYTEA       CHECK (digest IS NULL OR octet_length(digest) = 32),
    entries       BIGINT,
    writers       TEXT[],
    notify        BOOLEAN     NOT NULL DEFAULT FALSE,
    asked_on      TEXT        NOT NULL CHECK (asked_on IN ('core', 'mirror')),
    asked_by_node TEXT        CHECK (asked_by_node IS NULL OR length(asked_by_node) BETWEEN 1 AND 64),
    asked_by_id   INTEGER,
    asked_by_name TEXT        CHECK (asked_by_name IS NULL OR length(asked_by_name) <= 255),
    reason        TEXT        CHECK (reason IS NULL OR length(reason) <= 64),
    detail        JSONB,
    deadline      TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at      TIMESTAMPTZ,
    CHECK ((ended_at IS NULL) = (phase IN ('requested', 'draining', 'preparing', 'prepared'))),
    CHECK (NOT notify OR side = 'core')
);

CREATE UNIQUE INDEX IF NOT EXISTS mirror_switch_uid_key ON mirror_switch (switch_id, side);
CREATE UNIQUE INDEX IF NOT EXISTS mirror_switch_open_key ON mirror_switch (vault_id) WHERE ended_at IS NULL;
-- What the follower's pass looks at: what is open, or decided and not yet told.
CREATE INDEX IF NOT EXISTS mirror_switch_active_idx ON mirror_switch (vault_id) WHERE ended_at IS NULL OR notify;

-- ---------------------------------------------------------------------------------------------------- the freeze

-- As 164's, and a core vault whose row is switching takes no change: the switch hands its mirror the position the
-- freeze numbered last, and a change after it would be on this server alone.
CREATE OR REPLACE FUNCTION vh_mirror_core_term(vault INTEGER) RETURNS BIGINT AS $$
#variable_conflict use_column
DECLARE
    st TEXT;
BEGIN
    IF COALESCE(current_setting('vh.mirror_apply', true), '') = 'on' THEN
        RETURN NULL;
    END IF;
    SELECT m.state INTO st FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
    IF st IS NULL THEN
        RETURN NULL;
    END IF;
    IF st = 'switching' THEN
        RAISE EXCEPTION 'mirror_read_only: vault % is handing its core role to its linked server; it takes no change now',
            vault
            USING ERRCODE = 'P0001', HINT = 'design/peers/mirror.md "Planned switch": the write gate missed this path';
    END IF;
    IF st = 'starting' THEN
        PERFORM 1 FROM mirror_vault m WHERE m.vault_id = vault FOR SHARE;
    END IF;
    RETURN (
        SELECT m.term FROM mirror_vault m
        WHERE m.vault_id = vault AND m.role = 'core' AND m.state <> 'starting'
          AND NOT EXISTS (SELECT 1 FROM vault v WHERE v.id = vault AND v.deleted_at IS NOT NULL)
    );
END;
$$ LANGUAGE plpgsql VOLATILE;

-- As 160's, and the vault's own settings (name, description, quota, owner) of a switching core are refused too (that
-- branch reads the term without vh_mirror_core_term).
CREATE OR REPLACE FUNCTION vh_mirror_track_vault() RETURNS TRIGGER AS $$
DECLARE
    vault INTEGER;
    t     BIGINT;
    st    TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role = 'core') THEN
        RETURN NULL;
    END IF;
    IF COALESCE(current_setting('vh.mirror_apply', true), '') = 'on' THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'vault' THEN
        -- Its soft deletion is the last change of a deleted vault that is logged.
        IF OLD.deleted_at IS NOT NULL THEN
            RETURN NULL;
        END IF;
        vault := NEW.id;
    ELSIF TG_TABLE_NAME IN ('fsync', 'rsync') THEN
        SELECT s.vault_id INTO vault FROM sync s
        WHERE s.id = CASE WHEN TG_OP = 'DELETE' THEN OLD.sync_id ELSE NEW.sync_id END;
    ELSE
        vault := CASE WHEN TG_OP = 'DELETE' THEN OLD.vault_id ELSE NEW.vault_id END;
    END IF;
    IF TG_TABLE_NAME = 'vault' THEN
        SELECT m.term, m.state INTO t, st FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
        IF st = 'switching' THEN
            RAISE EXCEPTION 'mirror_read_only: vault % is handing its core role to its linked server; its settings take '
                            'no change now', vault
                USING ERRCODE = 'P0001', HINT = 'design/peers/mirror.md "Planned switch": the write gate missed this path';
        END IF;
    ELSE
        SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
        IF t IS NOT NULL THEN
            t := vh_mirror_core_term(vault);
        END IF;
    END IF;
    IF t IS NOT NULL THEN
        PERFORM vh_mirror_append(vault, t, 'vault', vh_mirror_vault_state(vault), NULL, NULL,
                                 CASE WHEN TG_OP <> 'DELETE' THEN (to_jsonb(NEW) ->> 'updated_by')::integer END);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
