-- Moving the core and resync (server mirror phase 2, wave 5 piece B; design/peers/mirror.md "Parity", "Moving the
-- core", "As built: moving the core and resync"; db::query::mirror::Resync, mirror::resync).
--
--   mirror_vault.resync_at / resync_by / resync_count   mirror: when a person here (users.id) last started the copy
--                      over from the core's tree (mirror.resync), and how many times. While the copy that a resync
--                      started is unfinished, the first-copy applier takes this server's own entries as they are (by
--                      uid) instead of refusing them, and at its end keeps what the core's tree does not hold as held
--                      changes. Core: when its mirror last asked it to start over.
--   mirror_vault.scrubbed_at   both: when the scrub (the entry hashes recomputed from the tables and compared with
--                      the recorded ones) last ran for the vault.
--
-- Idempotent and safe on upgraded installs: new nullable columns and one with a default; nothing is mirrored before
-- this release.

ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS resync_at TIMESTAMPTZ;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS resync_by INTEGER;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS resync_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS scrubbed_at TIMESTAMPTZ;
