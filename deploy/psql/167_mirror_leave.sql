-- Leaving a mirror (server mirror phase 2, wave 5, piece A; design/peers/mirror.md "Leaving a mirror", "Ending a mirror
-- from the core, and deleting", "As built: leaving a mirror"): the permission to detach, the record of a detach on both
-- servers, the contents a detached vault never received, and versions a mirror keeps of what its core replaces or
-- deletes.
--
--   admin_role.mirror_permissions
--                         the admin module `mirror` (bit 0 detach: turn a copy of another server's vault held here
--                         into a standalone vault). Super admins hold it; no other built-in role does. Take over as core
--                         is the next bit.
--   mirror_offer          on the mirror, a started (or orphaned) offer whose copy was detached ends as 'detached', with
--                         `notify` until the core is told (peer.mirror.detached; dropped on unlink like every notice);
--                         on the core, copy_outcome 'detached' records that the mirror left with its copy.
--   mirror_detached       one row per detach on each server that took part: side 'mirror' on the server that detached
--                         its copy (the vault here, from which core, the last (term, seq) confirmed, whether the digest
--                         matched there, how many files' contents never arrived, the new owner, who and when), side
--                         'core' on the core that was told (its own vault, the mirror, when). The vault keeps the
--                         original's uid and keys until the re-key pass runs (rekeyed_at): until then it can't be
--                         mirrored between those two servers (both refuse the offer). Goes with the vault.
--   mirror_content_pending.state 'missing'
--                         a file of a detached vault whose contents never arrived from the core: the entry stays, an open
--                         fails with mirror_contents_missing (never empty, never another generation's bytes), and it is
--                         listed exactly. A new version written here supersedes it.
--   mirror_vault.keep_versions (+ _set_by, _set_at)
--                         on the mirror, per held vault: keep versions of what the core replaces or deletes (the local
--                         versioning policy's shape: {enabled, keep_last, max_age_days, quota_bytes}; NULL = off). The
--                         kept generations are this server's own state, never logged, hashed or submitted.
--
-- Additive and idempotent on installs that ran 160 to 166: new columns with defaults or NULL, one new table, CHECKs of
-- 163's and 161's tables widened once (unreleased; no existing row changes meaning).

-- ---------------------------------------------------------------------------------------------------- the permission

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'admin_role'
          AND column_name = 'mirror_permissions'
    ) THEN
        ALTER TABLE admin_role
            ADD COLUMN mirror_permissions BIT(8) NOT NULL DEFAULT B'00000000';

        UPDATE admin_role SET mirror_permissions = B'00000001' WHERE name = 'super_admin';
    END IF;
END $$;

INSERT INTO permission (name, description, category, bit_position)
VALUES ('admin.mirror.detach', 'Allows detaching mirrored vaults: a copy of another server''s vault held here becomes a '
                               'standalone vault on this server.', 'admin', 0)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------------------------------- mirror_offer

DO $$
DECLARE
    c RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'mirror_offer'::regclass AND contype = 'c' AND conname = 'mirror_offer_state_check'
                     AND pg_get_constraintdef(oid) LIKE '%''detached''%') THEN
        -- 163's inline CHECKs on state, copy_outcome and the side/state and finished pairs, whatever they were named.
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'mirror_offer'::regclass AND contype = 'c'
                   AND (pg_get_constraintdef(oid) LIKE '%state%' OR pg_get_constraintdef(oid) LIKE '%copy_outcome%')
        LOOP
            EXECUTE format('ALTER TABLE mirror_offer DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE mirror_offer ADD CONSTRAINT mirror_offer_state_check
            CHECK (state IN ('offered', 'pending', 'accepted', 'keys_acked', 'installed', 'started', 'declined',
                             'cancelled', 'expired', 'failed', 'orphaned', 'detached'));
        ALTER TABLE mirror_offer ADD CONSTRAINT mirror_offer_copy_outcome_check
            CHECK (copy_outcome IS NULL OR copy_outcome IN ('removed', 'kept', 'none', 'detached'));
        ALTER TABLE mirror_offer ADD CONSTRAINT mirror_offer_side_state_check
            CHECK ((side = 'core' AND state IN ('offered', 'accepted', 'keys_acked', 'started', 'declined', 'cancelled',
                                                'expired', 'failed'))
                OR (side = 'mirror' AND state IN ('pending', 'accepted', 'installed', 'started', 'declined', 'cancelled',
                                                  'expired', 'failed', 'orphaned', 'detached')));
        ALTER TABLE mirror_offer ADD CONSTRAINT mirror_offer_finished_check
            CHECK ((finished_at IS NULL) = (state IN ('offered', 'pending', 'accepted', 'keys_acked', 'installed')));
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------- mirror_detached

CREATE TABLE IF NOT EXISTS mirror_detached
(
    id            SERIAL PRIMARY KEY,
    side          TEXT        NOT NULL CHECK (side IN ('mirror', 'core')),
    -- mirror: the vault that was detached here; core: this server's own vault, whose mirror left with its copy
    vault_id      INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    vault_uid     UUID        NOT NULL,
    peer_id       INTEGER     NOT NULL REFERENCES peer (id),
    fork_term     BIGINT      NOT NULL DEFAULT 0 CHECK (fork_term >= 0),
    fork_seq      BIGINT      NOT NULL DEFAULT 0 CHECK (fork_seq >= 0),
    digest_matched BOOLEAN,              -- mirror: the last acknowledgement matched (NULL: nothing acknowledged yet)
    was_state     TEXT        CHECK (was_state IS NULL OR length(was_state) <= 32),   -- live | stopped | orphaned ...
    missing       BIGINT      NOT NULL DEFAULT 0 CHECK (missing >= 0),
    owner_id      INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    detached_by   INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    detached_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rekeyed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS mirror_detached_uid_idx ON mirror_detached (vault_uid, peer_id);
CREATE INDEX IF NOT EXISTS mirror_detached_vault_idx ON mirror_detached (vault_id);

-- ---------------------------------------------------------------------------------------------------- missing contents

DO $$
DECLARE
    c RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'mirror_content_pending'::regclass AND contype = 'c'
                     AND conname = 'mirror_content_pending_state_check'
                     AND pg_get_constraintdef(oid) LIKE '%''missing''%') THEN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'mirror_content_pending'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%state%' AND pg_get_constraintdef(oid) LIKE '%''waiting''%'
        LOOP
            EXECUTE format('ALTER TABLE mirror_content_pending DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE mirror_content_pending ADD CONSTRAINT mirror_content_pending_state_check
            CHECK (state IN ('waiting', 'failed', 'missing'));
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------- versions kept

ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS keep_versions JSONB
    CHECK (keep_versions IS NULL OR jsonb_typeof(keep_versions) = 'object');
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS keep_versions_set_by INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS keep_versions_set_at TIMESTAMPTZ;
