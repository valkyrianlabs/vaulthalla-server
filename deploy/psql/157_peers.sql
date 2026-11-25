-- Linked servers (design/peers/link.md): another Vaulthalla server this one is paired with. A peer is its own kind of
-- principal: never a row in `devices`, never a user. Experimental and off by default (peers.experimental in
-- config.yaml); with it off nothing reads this table.
--
--   node_id             the peer's device_node.node_id (its card)
--   name                shown in every UI; editable locally (starts as the name on the peer's card)
--   spki_sha256         the pin: SHA-256 of the peer's identity key (device_tls) SubjectPublicKeyInfo, lowercase hex
--   next_spki_sha256    a key the peer announced (peer.identity.rotate, signed by the current key) and is not using
--                       yet; either key is accepted until the new one is seen, then it replaces the pin
--   rotate_counter      the highest announcement counter accepted from the peer (a replayed or older one is refused)
--   attest_public_keys  the peer's Ed25519 key-attestation public keys, current and retired (base64 strings)
--   wrap_public_key     the peer's X25519 key that vault keys for it are wrapped to (32 bytes)
--   endpoints           where the peer can be reached ([{host, port, kind}]), last good first; refreshed over the link
--   sharing             identities | full (design/peers/identity.md); every link starts at identities
--   approved_by         who approved the link here
--   compared_by         how the pairing code was compared: person (terminal or console) or desktop (brokered)
--   peer_protocol       the peer protocol and product version the peer last said it speaks (its card, then
--   product_version     peer.hello)
--   revoked_at          unlinked; the row stays for the audit trail and a new pairing writes a new row
--
-- A server may be linked again after an unlink (its identity is not disposable): node_id and spki_sha256 are unique
-- among live rows only.
--
-- Additive and idempotent: a new table and its indexes.

CREATE TABLE IF NOT EXISTS peer
(
    id                 SERIAL PRIMARY KEY,
    node_id            TEXT        NOT NULL CHECK (char_length(node_id) BETWEEN 1 AND 64),
    name               TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    spki_sha256        TEXT        NOT NULL CHECK (spki_sha256 ~ '^[0-9a-f]{64}$'),
    next_spki_sha256   TEXT CHECK (next_spki_sha256 ~ '^[0-9a-f]{64}$'),
    rotate_counter     BIGINT      NOT NULL DEFAULT 0 CHECK (rotate_counter >= 0),
    attest_public_keys JSONB       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(attest_public_keys) = 'array'),
    wrap_public_key    BYTEA       NOT NULL CHECK (octet_length(wrap_public_key) = 32),
    endpoints          JSONB       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(endpoints) = 'array'),
    sharing            TEXT        NOT NULL DEFAULT 'identities' CHECK (sharing IN ('identities', 'full')),
    approved_by        INTEGER REFERENCES users (id) ON DELETE SET NULL,
    compared_by        TEXT        NOT NULL DEFAULT 'person' CHECK (compared_by IN ('person', 'desktop')),
    peer_protocol      INTEGER     NOT NULL DEFAULT 1 CHECK (peer_protocol >= 1),
    product_version    TEXT        NOT NULL DEFAULT '' CHECK (char_length(product_version) <= 64),
    linked_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at       TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    CHECK (next_spki_sha256 IS NULL OR next_spki_sha256 <> spki_sha256)
);

CREATE UNIQUE INDEX IF NOT EXISTS peer_live_node ON peer (node_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS peer_live_spki ON peer (spki_sha256) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS peer_live_next_spki ON peer (next_spki_sha256)
    WHERE revoked_at IS NULL AND next_spki_sha256 IS NOT NULL;
