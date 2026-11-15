-- The Vaulthalla Cloud relay (design/cloud/relay.md, "As built"): a browser reaches this server through an outbound
-- connection the server keeps to the cloud's relay, and pairs with it like a device.
--
--   devices.paired_via         'listener' (paired on the device listener: Desktop) or 'relay' (a web browser through
--                              Vaulthalla Cloud). A relay-paired device is held to the read-only capability set on
--                              every connection; existing rows are Desktops ('listener').
--   cloud_relay                the local switch, one row at most: on for one linked installation only. Relinking (a new
--                              installation id) leaves it off until a super admin switches it on again; unlinking
--                              leaves a row that no longer matches anything.
--
-- Additive and idempotent: a defaulted column and a new table.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS paired_via TEXT NOT NULL DEFAULT 'listener';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'devices_paired_via') THEN
        ALTER TABLE devices ADD CONSTRAINT devices_paired_via CHECK (paired_via IN ('listener', 'relay'));
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS cloud_relay
(
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    installation_id TEXT        NOT NULL CHECK (installation_id <> ''),
    enabled_by      TEXT        NOT NULL CHECK (enabled_by <> ''),
    enabled_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
