-- VHF1 at rest for new writes (#367, WS2-b; design/encryption/02-authenticated-file-format.md §3.8, §6).
--
-- Every new content generation is written in VHF1. Its generation id is the header's 32-byte salt, and it lives where
-- the legacy 12-byte GCM IV always lived: files.encryption_iv, recovery_blob.encryption_iv (and the upload session,
-- provider version and remote index rows that copy it). The format is never a second field that could disagree with
-- that id: it is the id's length (base64 of 12 bytes is 16 symbols, of 32 bytes 44), and the daemon reads it that way
-- (vault/Content.hpp formatOf). The columns below are generated from it, so the local conversion (#372) and the
-- retirement gate (#376) can count legacy rows with an index instead of parsing every id:
--
--   plain  no generation: an empty file (stored as zero bytes) or plaintext an older build left behind
--   gcm0   the legacy headerless AES-256-GCM format (read until the conversion; never written for new content)
--   vhf1   the authenticated chunked format
--
-- Nothing is converted or rewritten here. Generated columns are computed by PostgreSQL on every write; no code
-- writes them. Idempotent and safe on upgraded installs (ADD COLUMN IF NOT EXISTS; adding a stored generated column
-- rewrites the table once).

ALTER TABLE files ADD COLUMN IF NOT EXISTS content_format TEXT GENERATED ALWAYS AS (
    CASE
        WHEN encryption_iv IS NULL OR encryption_iv = '' THEN 'plain'
        WHEN length(encryption_iv) = 44 THEN 'vhf1'
        ELSE 'gcm0'
    END) STORED;

ALTER TABLE recovery_blob ADD COLUMN IF NOT EXISTS content_format TEXT GENERATED ALWAYS AS (
    CASE
        WHEN encryption_iv = '' THEN 'plain'
        WHEN length(encryption_iv) = 44 THEN 'vhf1'
        ELSE 'gcm0'
    END) STORED;

CREATE INDEX IF NOT EXISTS idx_files_content_format_legacy ON files (content_format) WHERE content_format = 'gcm0';
CREATE INDEX IF NOT EXISTS idx_recovery_blob_content_format_legacy ON recovery_blob (vault_id)
    WHERE content_format = 'gcm0';

COMMENT ON COLUMN files.encryption_iv IS
    'Generation id of the stored content, base64: the 12-byte GCM IV (legacy gcm0) or the 32-byte VHF1 header salt';
COMMENT ON COLUMN recovery_blob.encryption_iv IS
    'Generation id of the retained content, base64: the 12-byte GCM IV (legacy gcm0) or the 32-byte VHF1 header salt';
