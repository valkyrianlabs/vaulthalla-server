-- Relinking a vault that two linked servers once mirrored (server mirror phase 2; design/peers/mirror.md "As built:
-- relink"): the vault is held on both with the same uid, keys and entry uids after a detach, an orphaned copy or a take
-- over, and the two trees drifted. A relink compares the trees by entry uid, keeps a plan (one choice per drifted entry),
-- and makes one server the core and the other its mirror again, keeping whatever the losing side had as held changes.
--
--   mirror_base, mirror_base_mark   the entry hashes a server last agreed with its peer, kept when its mirror row ends
--                                   (a detach, an orphaned copy's removal, a cancel, an unlink): with the other side's,
--                                   they say on which side an entry changed since. One per vault, replaced each time.
--   mirror_relink                   one relink of a vault on this server: the initiator keeps the comparison and the
--                                   plan; the other server (the responder) keeps the request, its super admin's answer
--                                   and the outcome it approved, then its part once the plan is applied. One open per
--                                   vault. Nothing of the responder's tree is served before a person there accepted
--                                   the request, and nothing changes there before one approved the outcome.
--   mirror_relink_entry             each drifted entry: how it differs, both sides' versions, the plan's choice and, on
--                                   the future mirror, what bringing its version onto the core did.
--   mirror_detached.relinked_at     a detach record a relink settled (it no longer refuses mirroring the uid).
--   mirror_takeover.settled_how, mirror_rejoin.phase   learn 'relinked'.
--
-- Additive and idempotent: new tables and columns, two CHECKs widened by one value; no existing row changes and a second
-- run changes nothing.

CREATE TABLE IF NOT EXISTS mirror_base
(
    vault_id   INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    entry_uid  UUID    NOT NULL,
    entry_hash BYTEA   NOT NULL CHECK (octet_length(entry_hash) = 32),
    PRIMARY KEY (vault_id, entry_uid)
);

CREATE TABLE IF NOT EXISTS mirror_base_mark
(
    vault_id  INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    peer_id   INTEGER     REFERENCES peer (id) ON DELETE SET NULL,
    -- the role the server held when the base was kept, and where (core: what its mirror last acknowledged; mirror,
    -- orphaned: the last position it applied; a take over's: its fork point)
    role      TEXT        NOT NULL CHECK (role IN ('core', 'mirror', 'orphaned')),
    term      BIGINT      NOT NULL CHECK (term >= 0),
    seq       BIGINT      NOT NULL CHECK (seq >= 0),
    entries   BIGINT      NOT NULL DEFAULT 0,
    source    TEXT        NOT NULL CHECK (source IN ('entry_hashes', 'acknowledged', 'fork_base')),
    taken_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mirror_relink
(
    id             BIGSERIAL PRIMARY KEY,
    relink_uid     UUID        NOT NULL,
    vault_id       INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    peer_id        INTEGER     NOT NULL REFERENCES peer (id),
    -- initiator: a person here compared (and planned); responder: the other server's relink, applied here
    side           TEXT        NOT NULL CHECK (side IN ('initiator', 'responder')),
    -- the handshake: requested (the responder's super admin has not answered) -> accepted (its tree may be served for
    -- the comparison) -> open (the initiator compared; the plan editable) -> proposed (the outcome waits for the
    -- responder's approval) -> approved; then prepared -> bring (the future mirror brings its chosen versions onto the
    -- core) -> copying (its copy starts over from the core's tree) -> done | failed | stale (a tree changed under the
    -- plan) | cancelled | declined (the responder's super admin said no) | expired (unanswered, or not carried out, in
    -- a day)
    phase          TEXT        NOT NULL CHECK (phase IN ('requested', 'accepted', 'open', 'proposed', 'approved',
                                                        'prepared', 'bring', 'copying', 'done', 'failed', 'stale',
                                                        'cancelled', 'declined', 'expired')),
    mode           TEXT        NOT NULL DEFAULT 'plan' CHECK (mode IN ('plan', 'override')),
    -- the plan: which server becomes the core (seen from this server), and the choice for entries left unset
    core           TEXT        NOT NULL DEFAULT 'this' CHECK (core IN ('this', 'theirs')),
    default_choice TEXT        CHECK (default_choice IS NULL OR default_choice IN ('this', 'theirs', 'both')),
    -- this server's part once applied, and the term the pair starts in
    role           TEXT        CHECK (role IS NULL OR role IN ('core', 'mirror')),
    term           BIGINT      CHECK (term IS NULL OR term >= 1),
    -- what each side was, and its tree's digest, when compared (a change under the plan invalidates it)
    this_status    TEXT        CHECK (this_status IS NULL OR length(this_status) <= 32),
    theirs_status  TEXT        CHECK (theirs_status IS NULL OR length(theirs_status) <= 32),
    this_digest    BYTEA       CHECK (this_digest IS NULL OR octet_length(this_digest) = 32),
    this_entries   BIGINT,
    theirs_digest  BYTEA       CHECK (theirs_digest IS NULL OR octet_length(theirs_digest) = 32),
    theirs_entries BIGINT,
    summary        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    by_node        TEXT        CHECK (by_node IS NULL OR length(by_node) BETWEEN 1 AND 64),
    by_id          INTEGER,
    by_name        TEXT        CHECK (by_name IS NULL OR length(by_name) <= 255),
    error          TEXT        CHECK (error IS NULL OR length(error) <= 2000),
    -- the handshake: until when the request (then the acceptance) holds; the responder's super admin who accepted it
    -- (on the initiator: the other server's, as it said); the outcome proposed (who becomes the core, the mode, what
    -- the responder's vault gains and loses, both digests, the plan's hash) and who approved it
    expires_at     TIMESTAMPTZ,
    accepted_at    TIMESTAMPTZ,
    accepted_by    TEXT        CHECK (accepted_by IS NULL OR length(accepted_by) <= 255),
    proposal       JSONB,
    approved_at    TIMESTAMPTZ,
    approved_by    TEXT        CHECK (approved_by IS NULL OR length(approved_by) <= 255),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    applied_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS mirror_relink_open_key ON mirror_relink (vault_id)
    WHERE phase IN ('requested', 'accepted', 'open', 'proposed', 'approved', 'prepared', 'bring', 'copying');
CREATE INDEX IF NOT EXISTS mirror_relink_uid_idx ON mirror_relink (relink_uid);

CREATE TABLE IF NOT EXISTS mirror_relink_entry
(
    relink_id    BIGINT  NOT NULL REFERENCES mirror_relink (id) ON DELETE CASCADE,
    entry_uid    UUID    NOT NULL,
    -- seen from the relink's server: only here, only on the other, or on both and changed here, there, on both since
    -- the last position both agreed on (differs: that cannot be told)
    kind         TEXT    NOT NULL CHECK (kind IN ('only_this', 'only_theirs', 'changed_this', 'changed_theirs',
                                                  'changed_both', 'differs')),
    aspects      TEXT[]  NOT NULL DEFAULT '{}',
    path         TEXT    NOT NULL DEFAULT '',
    this_state   JSONB,
    theirs_state JSONB,
    choice       TEXT    CHECK (choice IS NULL OR choice IN ('this', 'theirs', 'both')),
    -- the future mirror: what bringing its version onto the core did (submitted, executed, refused, kept, skipped)
    request_id   TEXT    CHECK (request_id IS NULL OR length(request_id) <= 64),
    outcome      TEXT    CHECK (outcome IS NULL OR length(outcome) <= 32),
    outcome_note TEXT    CHECK (outcome_note IS NULL OR length(outcome_note) <= 1000),
    PRIMARY KEY (relink_id, entry_uid)
);

CREATE INDEX IF NOT EXISTS mirror_relink_entry_path_idx ON mirror_relink_entry (relink_id, path, entry_uid);

ALTER TABLE mirror_detached ADD COLUMN IF NOT EXISTS relinked_at TIMESTAMPTZ;
ALTER TABLE mirror_detached ADD COLUMN IF NOT EXISTS relink_id BIGINT;

DO $$
DECLARE
    c RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'mirror_takeover'::regclass AND contype = 'c'
                     AND conname = 'mirror_takeover_settled_how_check'
                     AND pg_get_constraintdef(oid) LIKE '%''relinked''%') THEN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'mirror_takeover'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%''switched''%'
        LOOP
            EXECUTE format('ALTER TABLE mirror_takeover DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE mirror_takeover ADD CONSTRAINT mirror_takeover_settled_how_check
            CHECK (settled_how IS NULL OR settled_how IN ('switched', 'returned', 'merged', 'ended', 'relinked'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'mirror_rejoin'::regclass AND contype = 'c'
                     AND conname = 'mirror_rejoin_phase_check'
                     AND pg_get_constraintdef(oid) LIKE '%''relinked''%') THEN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'mirror_rejoin'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%''draining''%'
        LOOP
            EXECUTE format('ALTER TABLE mirror_rejoin DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE mirror_rejoin ADD CONSTRAINT mirror_rejoin_phase_check
            CHECK (phase IN ('draining', 'following', 'rejoining', 'forked', 'resynced', 'ended', 'relinked'));
    END IF;
END
$$;
