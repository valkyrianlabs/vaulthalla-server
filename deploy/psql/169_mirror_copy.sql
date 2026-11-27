-- Detach a copy (server mirror phase 2, wave 5, piece C; design/peers/mirror.md "Detach a copy", "As built: detach a
-- copy"; db::query::mirror::MirrorCopies, mirror::copy).
--
--   mirror_copy   one row per copy of a held vault (role mirror or orphaned) written here as a new, separate local vault:
--                 the held vault it reads (source_vault_id; NULL once that vault is gone), the new vault while it is
--                 written and once it is complete (vault_id; NULL before it exists, and after a failed or cancelled copy
--                 removed it), its name and owner, the state (running -> finished | failed | cancelled), the progress
--                 (entries and bytes done of the totals the plan counted), the files left out (`skipped`: the files
--                 whose contents never arrived here, and any removed or unreadable while the copy ran, by path), who
--                 asked, a cancel asked for, how many times the copy started over (a daemon restart removes the
--                 partial vault and starts again), the error of a failed copy. At most one running copy per held vault
--                 and per (owner, name). While a copy runs its new vault is read-only to everything but the copy
--                 (mirror::access, reason mirror_copy_writing): nothing anyone writes there can be lost when a failed or
--                 cancelled copy removes it.
--
-- Idempotent and safe on upgraded installs: one new table and its indexes; nothing existing changes.

CREATE TABLE IF NOT EXISTS mirror_copy
(
    id               BIGSERIAL PRIMARY KEY,
    source_vault_id  INTEGER     REFERENCES vault (id) ON DELETE SET NULL,
    vault_id         INTEGER     REFERENCES vault (id) ON DELETE SET NULL,
    name             TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    owner_id         INTEGER     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    state            TEXT        NOT NULL DEFAULT 'running'
                                 CHECK (state IN ('running', 'finished', 'failed', 'cancelled')),
    entries_total    BIGINT      NOT NULL DEFAULT 0 CHECK (entries_total >= 0),
    entries_done     BIGINT      NOT NULL DEFAULT 0 CHECK (entries_done >= 0),
    bytes_total      BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_total >= 0),
    bytes_done       BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_done >= 0),
    skipped          JSONB       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(skipped) = 'array'),
    error            TEXT        CHECK (error IS NULL OR length(error) <= 2000),
    requested_by     INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    cancel_requested BOOLEAN     NOT NULL DEFAULT FALSE,
    cancelled_by     INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    attempts         INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at      TIMESTAMPTZ,
    CHECK ((finished_at IS NULL) = (state = 'running'))
);

CREATE UNIQUE INDEX IF NOT EXISTS mirror_copy_running_source_idx ON mirror_copy (source_vault_id) WHERE state = 'running';
CREATE UNIQUE INDEX IF NOT EXISTS mirror_copy_running_name_idx ON mirror_copy (owner_id, name) WHERE state = 'running';
CREATE INDEX IF NOT EXISTS mirror_copy_source_idx ON mirror_copy (source_vault_id, id);
