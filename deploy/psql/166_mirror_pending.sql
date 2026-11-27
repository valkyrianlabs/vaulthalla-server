-- A change made on the mirror (server mirror phase 2, wave 4 piece B; design/peers/mirror.md "A change made on the
-- mirror", "When the core refuses", "As built: a change made on the mirror"; db::query::mirror::Pending,
-- mirror::submit). On the mirror, a person's change to a mirrored vault is applied at once and recorded as pending; it
-- is submitted to the core, which executes it as that person and logs it with the request id in `origin`; the mirror
-- confirms it when those groups come back, or reverts it to the core's state and keeps the person's version (a conflict
-- copy beside it, or a held change) when the core refuses.
--
--   mirror_pending     mirror: one row per change made here and not yet settled with the core, in submission order
--                      (id). `request_id` is the origin the core echoes; `entry_uid` the entry the change is on (a
--                      created entry's uid, chosen here before the change, so both servers give it the same one);
--                      `args` what the core needs to execute it, every entry named by uid; the generation it was based
--                      on and the new one (contents); the person as (this server's node id, users.id); `uids` every
--                      entry the change touched here (what it holds dirty). State: local (being applied here), pending
--                      (applied here, to be submitted), submitted (the core has it, no outcome yet), executed (the core
--                      did it: confirmed once `groups_applied` reaches `groups_expected`, the core's count of its
--                      groups).
--   mirror_dirty       mirror: an entry whose tables may differ from what the core last confirmed, because a pending
--                      change touched it, with that confirmed state (the state document of the last change the log
--                      applied to it, or of the tables when it was clean; NULL with kind 'none': no such entry). The
--                      applier keeps it current; a settled entry is brought back to it and the row goes.
--   mirror_held        mirror: the person's version of a change the core refused, never dropped (kind 'held': kept
--                      outside the vault's tree until the person discards it or someone with the right retries it), and
--                      the conflict copies made beside an entry the core had changed (kind 'conflict': a record of
--                      what was renamed, for the listing). The reason is the core's refusal code and text.
--   mirror_submission  core: each change a mirror submitted, by request id, with what the core did the first time
--                      (a repeated submit is answered from here, never executed twice): queued, running, executed with
--                      the number of groups it logged, or refused with the code. Kept 30 days after it finished (the
--                      log's own retention).
--
-- No foreign keys from mirror_pending or mirror_dirty to the entry tables (a pending change outlives the rows it touched:
-- a removal). Idempotent and safe on upgraded installs: new tables only; nothing is mirrored before this release.

CREATE TABLE IF NOT EXISTS mirror_pending
(
    id              BIGSERIAL PRIMARY KEY,
    vault_id        INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    request_id      TEXT        NOT NULL CHECK (request_id ~ '^[a-z0-9-]{8,64}$'),
    entry_uid       UUID        NOT NULL,
    op              TEXT        NOT NULL CHECK (op IN ('mkdir', 'move', 'rename', 'remove', 'copy', 'write', 'setattr')),
    args            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    base_generation TEXT,
    new_generation  TEXT,
    actor_node      TEXT        NOT NULL CHECK (length(actor_node) BETWEEN 1 AND 64),
    actor_id        INTEGER     NOT NULL,
    uids            UUID[]      NOT NULL DEFAULT '{}',
    state           TEXT        NOT NULL DEFAULT 'local'
                                CHECK (state IN ('local', 'pending', 'submitted', 'executed')),
    groups_expected INTEGER CHECK (groups_expected >= 0),
    groups_applied  INTEGER     NOT NULL DEFAULT 0 CHECK (groups_applied >= 0),
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_at    TIMESTAMPTZ,
    executed_at     TIMESTAMPTZ,
    UNIQUE (vault_id, request_id)
);

CREATE INDEX IF NOT EXISTS mirror_pending_vault ON mirror_pending (vault_id, id);

CREATE TABLE IF NOT EXISTS mirror_dirty
(
    vault_id       INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    entry_uid      UUID    NOT NULL,
    confirmed      JSONB,
    confirmed_kind TEXT    NOT NULL CHECK (confirmed_kind IN ('live', 'trashed', 'none')),
    PRIMARY KEY (vault_id, entry_uid),
    CHECK ((confirmed IS NULL) = (confirmed_kind = 'none'))
);

CREATE TABLE IF NOT EXISTS mirror_held
(
    id           BIGSERIAL PRIMARY KEY,
    vault_id     INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    kind         TEXT        NOT NULL CHECK (kind IN ('held', 'conflict')),
    request_id   TEXT        NOT NULL,
    op           TEXT        NOT NULL,
    entry_uid    UUID,
    args         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    path         TEXT,
    copy_name    TEXT,
    actor_node   TEXT        NOT NULL,
    actor_id     INTEGER     NOT NULL,
    reason_code  TEXT        NOT NULL,
    reason       TEXT        NOT NULL,
    state        TEXT        NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'retried', 'discarded')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at  TIMESTAMPTZ,
    resolved_by  INTEGER
);

CREATE INDEX IF NOT EXISTS mirror_held_open ON mirror_held (vault_id, id) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS mirror_submission
(
    vault_id    INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    request_id  TEXT        NOT NULL,
    peer_id     INTEGER     NOT NULL,
    seq         BIGSERIAL,
    payload     JSONB       NOT NULL,
    state       TEXT        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'executed', 'refused')),
    groups      INTEGER,
    code        TEXT,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (vault_id, request_id)
);

CREATE INDEX IF NOT EXISTS mirror_submission_queued ON mirror_submission (vault_id, seq) WHERE state IN ('queued', 'running');
