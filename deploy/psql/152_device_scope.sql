-- Scoped devices (design/core/mcp-remote-signin.md, "Scoped devices"): a paired device may be limited to less than its
-- user's rights, so that an app pairing an AI tool (Vaulthalla Desktop's "Claude Code on <Mac>") can be read-only.
--
--   devices.scope   read | write | destructive: the effect ceiling of everything the device's sessions run (ws commands
--                   by their contract effect, /mcp through the MCP catalog's ceiling, the HTTP lanes by what they do).
--                   destructive = no limit beyond the account's own: every existing row, and a pairing that asks for
--                   none, keeps exactly the rights it had.
--
-- Additive and idempotent: a defaulted column and its CHECK.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'destructive';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'devices_scope') THEN
        ALTER TABLE devices ADD CONSTRAINT devices_scope CHECK (scope IN ('read', 'write', 'destructive'));
    END IF;
END
$$;
