-- S3 gateway multipart parts are sealed at rest (#345).
--
-- Each part is stored as AES-256-GCM ciphertext (body ‖ 16-byte tag) under the vault's key, with a fresh random
-- 96-bit IV per write and AAD binding it to its vault, upload id, part number and plaintext size
-- (core/include/protocols/s3/PartCipher.hpp). The row records the IV and the key version; a part's file and its
-- row change together (every write gets a new file name), so an older copy of a part never authenticates under the
-- row's IV.
--
-- NULL encryption_iv marks a part written before this migration: plaintext on disk. The daemon seals those at
-- startup (and before CompleteMultipartUpload) after checking them against their recorded MD5, then deletes the
-- plaintext.

ALTER TABLE s3_gateway_multipart_part ADD COLUMN IF NOT EXISTS encryption_iv TEXT DEFAULT NULL;
ALTER TABLE s3_gateway_multipart_part ADD COLUMN IF NOT EXISTS key_version INTEGER DEFAULT NULL;

ALTER TABLE s3_gateway_multipart_part DROP CONSTRAINT IF EXISTS s3_gateway_multipart_part_sealed_check;
ALTER TABLE s3_gateway_multipart_part ADD CONSTRAINT s3_gateway_multipart_part_sealed_check
    CHECK ((encryption_iv IS NULL) = (key_version IS NULL));

COMMENT ON COLUMN s3_gateway_multipart_part.encryption_iv IS
    'Base64 AES-GCM IV of the sealed part file; NULL = a plaintext part from before migration 118 (sealed at startup).';
COMMENT ON COLUMN s3_gateway_multipart_part.key_version IS
    'Vault key version the part is sealed under; NULL with encryption_iv.';
