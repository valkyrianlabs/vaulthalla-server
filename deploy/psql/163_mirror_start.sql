-- Starting a mirror (server mirror phase 2, wave 3, piece A; design/peers/mirror.md "Starting a mirror" and "As built:
-- starting a mirror"): the offer one server (the core) makes another (the mirror) for one of its vaults, the answer,
-- the key delivery and the begin, each side's record of where the start stands, and the per-link setting that accepts
-- every vault from a linked server without asking a person.
--
--   mirror_offer        one row per start on each server that takes part: side 'core' on the server that owns the
--                       vault, side 'mirror' on the one it is offered to, sharing offer_uid. What the core said about the
--                       vault (its uid, its numeric id there, which the key attestations bind, its root folder's uid,
--                       name, description, quota, size, file count, whether history is included (never, in this
--                       version), its owner as (home node, id there) and the role the core proposes for the mirror
--                       server, by name with its permissions). `state` is where the start stands on this side; `notify`
--                       says the other server has not been told it yet (the start service tells it while the link is
--                       up, and again after a restart). An offer a person has not answered expires (expires_at, 7 days);
--                       a finished row (started, declined, cancelled, expired, failed) is swept 30 days after it ended.
--                       Public facts only: no key material is ever stored here.
--                       On the core, remove_copy is what its cancel asked of the mirror's copy and copy_outcome
--                       what the mirror answered it did (removed | kept); on the mirror, a finished copy the core's
--                       cancel left in place ends its offer as 'orphaned'.
--   peer.accept_vaults  a linked server whose offers this server accepts without asking (default off; only a super
--                       admin here changes it), who set it and when.
--   peer.keep_vaults    keep the vaults this linked server, their core, removes: a cancel that asks to remove the copy
--                       leaves it orphaned here instead (default off; only a super admin here changes it), who set it
--                       and when.
--   vault_key_origin.anchor gains 'peer': a key version a linked server delivered for a vault this server mirrors,
--                       proven against the attestation key pinned at pairing (vault::recover::prove).
--
-- Additive and idempotent: one new table, six new columns with defaults, one widened CHECK; nothing existing changes
-- and a second run changes nothing.

ALTER TABLE peer ADD COLUMN IF NOT EXISTS accept_vaults BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS accept_vaults_set_by INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS accept_vaults_set_at TIMESTAMPTZ;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS keep_vaults BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS keep_vaults_set_by INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS keep_vaults_set_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS mirror_offer
(
    id            SERIAL PRIMARY KEY,
    offer_uid     UUID        NOT NULL,
    side          TEXT        NOT NULL CHECK (side IN ('core', 'mirror')),
    peer_id       INTEGER     NOT NULL REFERENCES peer (id),
    vault_uid     UUID        NOT NULL,
    -- core: the vault offered; mirror: the vault created for it, once the keys are installed
    vault_id      INTEGER     REFERENCES vault (id) ON DELETE SET NULL,
    core_vault_id BIGINT      NOT NULL CHECK (core_vault_id BETWEEN 1 AND 2147483647),
    root_uid      UUID        NOT NULL,
    term          BIGINT      NOT NULL DEFAULT 1 CHECK (term >= 1),
    name          TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description   TEXT        NOT NULL DEFAULT '' CHECK (length(description) <= 4096),
    quota         BIGINT      NOT NULL DEFAULT 0 CHECK (quota >= 0),
    size_bytes    BIGINT      NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    file_count    BIGINT      NOT NULL DEFAULT 0 CHECK (file_count >= 0),
    history       BOOLEAN     NOT NULL DEFAULT FALSE,
    owner         JSONB       NOT NULL CHECK (jsonb_typeof(owner) = 'object'),
    role          JSONB       CHECK (role IS NULL OR jsonb_typeof(role) = 'object'),
    state         TEXT        NOT NULL CHECK (state IN ('offered', 'pending', 'accepted', 'keys_acked', 'installed',
                                                        'started', 'declined', 'cancelled', 'expired', 'failed',
                                                        'orphaned')),
    notify        BOOLEAN     NOT NULL DEFAULT FALSE,
    remove_copy   BOOLEAN     NOT NULL DEFAULT FALSE,
    copy_outcome  TEXT        CHECK (copy_outcome IS NULL OR copy_outcome IN ('removed', 'kept', 'none')),
    reason        TEXT        CHECK (reason IS NULL OR length(reason) <= 64),
    detail        TEXT        CHECK (detail IS NULL OR length(detail) <= 2000),
    started_by    INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    decided_by    INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    attempts      INTEGER     NOT NULL DEFAULT 0,
    last_error    TEXT        CHECK (last_error IS NULL OR length(last_error) <= 2000),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ,
    CHECK ((side = 'core' AND state IN ('offered', 'accepted', 'keys_acked', 'started', 'declined', 'cancelled',
                                        'expired', 'failed'))
        OR (side = 'mirror' AND state IN ('pending', 'accepted', 'installed', 'started', 'declined', 'cancelled',
                                          'expired', 'failed', 'orphaned'))),
    CHECK ((finished_at IS NULL) = (state IN ('offered', 'pending', 'accepted', 'keys_acked', 'installed')))
);

CREATE UNIQUE INDEX IF NOT EXISTS mirror_offer_uid_key ON mirror_offer (offer_uid, side);
-- One start of a vault at a time on each side (finished rows stay for the record).
CREATE UNIQUE INDEX IF NOT EXISTS mirror_offer_active_key ON mirror_offer (vault_uid, side) WHERE finished_at IS NULL;
-- What the start service looks at on every pass: the rows that still have something to do or to tell.
CREATE INDEX IF NOT EXISTS mirror_offer_open_idx ON mirror_offer (peer_id) WHERE finished_at IS NULL OR notify;

-- 131's inline CHECK (anchor IN ('kit', 'export')) is replaced, whatever it was named, once.
DO $$
DECLARE
    c RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'vault_key_origin'::regclass AND contype = 'c'
                     AND conname = 'vault_key_origin_anchor_check'
                     AND pg_get_constraintdef(oid) LIKE '%''peer''%') THEN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'vault_key_origin'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%anchor%'
        LOOP
            EXECUTE format('ALTER TABLE vault_key_origin DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE vault_key_origin ADD CONSTRAINT vault_key_origin_anchor_check
            CHECK (anchor IN ('kit', 'export', 'peer'));
    END IF;
END $$;
