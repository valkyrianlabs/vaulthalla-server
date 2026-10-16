#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedVaults() const {
    conn_->prepare("upsert_vault",
                   R"(INSERT INTO vault (name, type, description, owner_id, mount_point, quota, is_active, slug, fuse_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id)");

    conn_->prepare("upsert_s3_vault",
                   // The vault's own row (one per vault): a key or bucket change edits it in place. Conflicting on
                   // (api_key_id, bucket) used to make a key/bucket change insert a second row for the vault (s3_pkey
                   // violation), and a vault created on a pair another vault held took that vault's binding over.
                   // Another vault's (api_key_id, bucket) now fails the unique constraint; ops refuse it first.
                   "INSERT INTO s3 (vault_id, api_key_id, bucket, encrypt_upstream, storage_tier_id) VALUES ($1, $2, $3, $4, $5) "
                   "ON CONFLICT (vault_id) DO UPDATE "
                   "SET bucket = EXCLUDED.bucket, api_key_id = EXCLUDED.api_key_id, "
                   "encrypt_upstream = EXCLUDED.encrypt_upstream, storage_tier_id = EXCLUDED.storage_tier_id "
                   "RETURNING vault_id");

    conn_->prepare("insert_s3_vault", "INSERT INTO s3 (vault_id, api_key_id, bucket, storage_tier_id) VALUES ($1, $2, $3, $4) "
                   "ON CONFLICT (vault_id) DO NOTHING");

    conn_->prepare("vault_root_exists",
                   "SELECT EXISTS(SELECT 1 FROM fs_entry WHERE vault_id = $1 AND path = '/') AS exists");

    conn_->prepare("get_vault",
                   "SELECT v.*, s.* "
                   "FROM vault v "
                   "LEFT JOIN s3 s ON v.id = s.vault_id "
                   "WHERE v.id = $1 AND v.deleted_at IS NULL");

    conn_->prepare("get_vault_by_name_and_owner",
                   "SELECT v.*, s.* "
                   "FROM vault v "
                   "LEFT JOIN s3 s ON v.id = s.vault_id "
                   "WHERE v.name = $1 AND v.owner_id = $2 AND v.deleted_at IS NULL");

    conn_->prepare("get_vault_owners_name",
                   "SELECT u.name FROM users u "
                   "JOIN vault v ON u.id = v.owner_id "
                   "WHERE v.id = $1");

    conn_->prepare("get_vault_owner_id", "SELECT owner_id FROM vault WHERE id = $1");

    conn_->prepare("get_max_vault_id", "SELECT MAX(id) FROM vault");

    conn_->prepare("get_vault_root_dir_id_by_vault_id", "SELECT id FROM fs_entry WHERE vault_id = $1 AND path = '/'");

    // Counts deleted vaults too: a deleted vault's name stays reserved until it is purged (#162).
    conn_->prepare("vault_exists", "SELECT EXISTS(SELECT 1 FROM vault WHERE name = $1 AND owner_id = $2) AS exists");

    conn_->prepare("is_s3_vault", "SELECT EXISTS(SELECT 1 FROM s3 WHERE vault_id = $1) AS is_s3");

    conn_->prepare("get_vault_mount_point", "SELECT mount_point FROM vault WHERE id = $1");
}
