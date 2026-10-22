#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedFiles() const {
    conn_->prepare("upsert_file_by_entry_id",
                   "INSERT INTO files (fs_entry_id, size_bytes, mime_type, content_hash) "
                   "VALUES ($1, $2, $3, $4) "
                   "ON CONFLICT (fs_entry_id) DO UPDATE SET "
                   "size_bytes = EXCLUDED.size_bytes, "
                   "mime_type = EXCLUDED.mime_type, "
                   "content_hash = EXCLUDED.content_hash");

    conn_->prepare("update_file_only",
                   "WITH updated_entry AS ("
                   "  UPDATE fs_entry "
                   "  SET last_modified_by = $7, updated_at = NOW() "
                   "  WHERE id = $1 "
                   "  RETURNING id"
                   ") "
                   "UPDATE files SET size_bytes = $2, mime_type = $3, content_hash = $4, "
                   "encryption_iv = $5, encrypted_with_key_version = $6 "
                   "WHERE fs_entry_id = (SELECT id FROM updated_entry)");

    conn_->prepare("upsert_file_full",
                   "WITH upsert_entry AS ("
                   "  INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, inode, mode, owner_uid, group_gid, is_hidden, is_system) "
                   "  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) "
                   "  ON CONFLICT (parent_id, name) DO UPDATE SET "
                   "    last_modified_by = EXCLUDED.last_modified_by, "
                   "    parent_id = EXCLUDED.parent_id, "
                   "    inode = EXCLUDED.inode, "
                   "    mode = EXCLUDED.mode, "
                   "    owner_uid = EXCLUDED.owner_uid, "
                   "    group_gid = EXCLUDED.group_gid, "
                   "    is_hidden = EXCLUDED.is_hidden, "
                   "    is_system = EXCLUDED.is_system, "
                   "    updated_at = NOW() "
                   "  RETURNING id"
                   ") "
                   "INSERT INTO files (fs_entry_id, size_bytes, mime_type, content_hash, encryption_iv, encrypted_with_key_version) "
                   "SELECT id, $14, $15, $16, $17, $18 FROM upsert_entry "
                   "ON CONFLICT (fs_entry_id) DO UPDATE SET "
                   "  size_bytes = EXCLUDED.size_bytes, "
                   "  mime_type = EXCLUDED.mime_type, "
                   "  content_hash = EXCLUDED.content_hash, "
                   "  encryption_iv = EXCLUDED.encryption_iv, "
                   "  encrypted_with_key_version = EXCLUDED.encrypted_with_key_version "
                   "RETURNING fs_entry_id");

    conn_->prepare("get_file_mime_type",
                   "SELECT f.mime_type FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2");

    conn_->prepare(
        "mark_file_trashed",
        "WITH target AS ("
        "  SELECT fs.id AS fs_entry_id, "
        "         fs.base32_alias, "
        "         fs.vault_id, "
        "         fs.path, "
        "         f.size_bytes "
        "  FROM fs_entry fs "
        "  JOIN files f ON f.fs_entry_id = fs.id "
        "  WHERE fs.vault_id = $1 AND fs.path = $2"
        "), moved AS ("
        "  INSERT INTO files_trashed ("
        "      vault_id, "
        "      path, "
        "      backing_path, "
        "      base32_alias, "
        "      size_bytes, "
        "      trashed_at, "
        "      trashed_by"
        "  ) "
        "  SELECT "
        "      vault_id, "
        "      path, "
        "      $4, "
        "      base32_alias, "
        "      size_bytes, "
        "      NOW(), "
        "      $3 "
        "  FROM target"
        "), removed AS ("
        "  DELETE FROM files "
        "  WHERE fs_entry_id IN (SELECT fs_entry_id FROM target)"
        ") "
        "DELETE FROM fs_entry "
        "WHERE id IN (SELECT fs_entry_id FROM target);"
    );

    conn_->prepare(
        "mark_file_trashed_by_id",
        "WITH target AS ("
        "  SELECT fs.id AS fs_entry_id, "
        "         fs.base32_alias, "
        "         fs.vault_id, "
        "         fs.path, "
        "         f.size_bytes "
        "  FROM fs_entry fs "
        "  JOIN files f ON f.fs_entry_id = fs.id "
        "  WHERE fs.id = $1"
        "), moved AS ("
        "  INSERT INTO files_trashed ("
        "      vault_id, "
        "      path, "
        "      backing_path, "
        "      base32_alias, "
        "      size_bytes, "
        "      trashed_at, "
        "      trashed_by"
        "  ) "
        "  SELECT "
        "      vault_id, "
        "      path, "
        "      $3, "
        "      base32_alias, "
        "      size_bytes, "
        "      NOW(), "
        "      $2 "
        "  FROM target"
        "), removed AS ("
        "  DELETE FROM files "
        "  WHERE fs_entry_id IN (SELECT fs_entry_id FROM target)"
        ") "
        "DELETE FROM fs_entry "
        "WHERE id IN (SELECT fs_entry_id FROM target);"
    );

    conn_->prepare("list_trashed_files",
                   "SELECT * FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL");

    conn_->prepare("mark_trashed_file_deleted_by_base32_alias",
                   "UPDATE files_trashed SET deleted_at = NOW() "
                   "WHERE base32_alias = $1 AND deleted_at IS NULL");

    conn_->prepare("mark_trashed_file_deleted_by_id",
                   "UPDATE files_trashed SET deleted_at = NOW() "
                   "WHERE id = $1 AND deleted_at IS NULL");

    conn_->prepare("list_files_in_dir",
                   "SELECT f.*, fs.* "
                   "FROM fs_entry fs "
                   "JOIN files f ON fs.id = f.fs_entry_id "
                   "WHERE fs.vault_id = $1 AND fs.path LIKE $2 AND fs.path NOT LIKE $3");

    conn_->prepare("list_files_in_dir_recursive",
                   "SELECT f.*, fs.* "
                   "FROM fs_entry fs "
                   "JOIN files f ON fs.id = f.fs_entry_id "
                   "WHERE fs.vault_id = $1 AND fs.path LIKE $2");

    conn_->prepare("get_file_by_id",
                   "SELECT f.*, fs.* "
                   "FROM fs_entry fs "
                   "JOIN files f ON fs.id = f.fs_entry_id "
                   "WHERE fs.id = $1");

    conn_->prepare("get_file_by_path",
                   "SELECT f.*, fs.* "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2");

    conn_->prepare("get_file_by_base32_alias",
                   "SELECT f.*, fs.* "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.base32_alias = $1");

    conn_->prepare("get_file_by_inode",
                   "SELECT f.*, fs.* "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.inode = $1");

    conn_->prepare("list_files_in_dir_by_parent_id",
                   "SELECT f.*, fs.* "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.parent_id = $1 AND fs.id != 1");

    conn_->prepare("list_files_in_dir_by_parent_id_recursive",
                   "WITH RECURSIVE dir_tree AS ("
                   "    SELECT fs.*, f.* "
                   "    FROM fs_entry fs "
                   "    JOIN files f ON fs.id = f.fs_entry_id "
                   "    WHERE fs.parent_id = $1 "
                   "  UNION ALL "
                   "   SELECT fs2.*, f2.* "
                   "   FROM fs_entry fs2 "
                   "   JOIN files f2 ON fs2.id = f2.fs_entry_id "
                   "   JOIN dir_tree dt ON fs2.parent_id = dt.id "
                   ") "
                   "SELECT * FROM dir_tree");

    conn_->prepare("get_file_id_by_path",
                   "SELECT fs.id "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2");

    conn_->prepare("get_file_size_bytes", "SELECT size_bytes FROM files WHERE fs_entry_id = $1");

    conn_->prepare("get_file_size_by_inode",
                   "SELECT f.size_bytes "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.inode = $1");

    conn_->prepare("get_file_parent_id_and_size",
                   "SELECT fs.parent_id, f.size_bytes "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.id = $1");

    conn_->prepare("get_file_parent_id_and_size_by_path",
                   "SELECT fs.parent_id, f.size_bytes "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2");

    conn_->prepare("get_file_parent_id_and_size_by_inode",
                   "SELECT fs.parent_id, f.size_bytes "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.inode = $1");

    conn_->prepare("is_file",
                   "SELECT EXISTS (SELECT 1 FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2)");

    conn_->prepare("get_file_encryption_iv_and_version",
                   "SELECT f.encryption_iv, f.encrypted_with_key_version "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2");

    conn_->prepare("get_file_content_hash",
                   "SELECT content_hash FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2");

    conn_->prepare("set_file_encryption_iv_and_version",
                   R"(UPDATE files f
       SET encryption_iv = $3, encrypted_with_key_version = $4
       FROM fs_entry fs
       WHERE f.fs_entry_id = fs.id
         AND fs.vault_id = $1
         AND fs.path = $2)");

    // Key rotation commits a file's new IV only if the row still describes the ciphertext that was re-encrypted.
    conn_->prepare("compare_and_set_file_encryption_iv_and_version",
                   R"(UPDATE files f
       SET encryption_iv = $3, encrypted_with_key_version = $4
       FROM fs_entry fs
       WHERE f.fs_entry_id = fs.id
         AND fs.vault_id = $1
         AND fs.path = $2
         AND f.encryption_iv IS NOT DISTINCT FROM $5
         AND f.encrypted_with_key_version IS NOT DISTINCT FROM $6)");

    // Empty files and legacy plaintext have no IV: nothing sealed, nothing for a key rotation to re-encrypt.
    // A key rotation's pending files. Versions a key salvage names are left out (key-backup.md "Salvage"): their files
    // are re-keyed by the salvage pass or unrecoverable, and the rotation's outgoing key can't decrypt them.
    conn_->prepare("get_files_older_than_key_version",
                   "SELECT fs.*, f.* "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND f.encrypted_with_key_version < $2 "
                   "AND f.encryption_iv IS NOT NULL AND f.encryption_iv <> '' "
                   "AND NOT EXISTS (SELECT 1 FROM vault_key_salvage s WHERE s.vault_id = fs.vault_id "
                   "                AND f.encrypted_with_key_version = ANY (s.versions))");

    conn_->prepare("get_n_largest_files",
                   "SELECT fs.*, f.* "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 "
                   "ORDER BY f.size_bytes DESC "
                   "LIMIT $2");

    conn_->prepare("get_all_files",
                   "SELECT fs.*, f.* "
                   "FROM files f "
                   "JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1");

    conn_->prepare("get_top_extensions_by_size",
                   R"SQL(
    SELECT
        ext,
        SUM(f.size_bytes)::bigint AS total_bytes
    FROM files f
    JOIN fs_entry fs ON fs.id = f.fs_entry_id
    CROSS JOIN LATERAL (
        SELECT
            CASE
                -- ignore hidden dotfiles like ".bashrc" (treat as no extension)
                WHEN fs.name LIKE '.%' THEN NULL

                -- if there's no dot, or dot is last char => no extension
                WHEN position('.' in fs.name) = 0 THEN NULL
                WHEN right(fs.name, 1) = '.' THEN NULL

                -- take substring after last dot
                ELSE lower(regexp_replace(fs.name, '^.*\.', ''))
            END AS ext
    ) x
    WHERE fs.vault_id = $1
      AND x.ext IS NOT NULL
      AND x.ext <> ''
    GROUP BY ext
    ORDER BY total_bytes DESC
    LIMIT $2
)SQL");

    conn_->prepare("insert_file_activity",
                   "INSERT INTO file_activity (file_id, user_id, action) "
                   "VALUES ($1, $2, $3)");
}
