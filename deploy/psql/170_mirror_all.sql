-- Mirror every vault to a linked server (server mirror phase 2; design/peers/mirror.md "Starting a mirror"): a setting
-- per link on the core, beside 163's settings of the receiving side.
--
--   peer.mirror_vaults  this server, as core, offers the linked server every vault it owns that is not mirrored yet, and
--                       each new vault as it is created (default off; only a super admin here changes it, with the keys
--                       step-up, since every offer sends a vault's keys), who set it and when. An offer that ended since
--                       the setting was last turned on (declined, cancelled, expired, failed) is not made again.
--
-- Additive and idempotent: three new columns with defaults; nothing existing changes and a second run changes nothing.

ALTER TABLE peer ADD COLUMN IF NOT EXISTS mirror_vaults BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS mirror_vaults_set_by INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS mirror_vaults_set_at TIMESTAMPTZ;
