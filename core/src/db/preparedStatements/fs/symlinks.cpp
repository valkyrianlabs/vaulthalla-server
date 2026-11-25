#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedSymlinks() const {
    conn_->prepare(
        "insert_symlink_full",
        R"SQL(
            WITH inserted AS (
                INSERT INTO fs_entry (
                    vault_id,
                    parent_id,
                    name,
                    base32_alias,
                    created_by,
                    last_modified_by,
                    path,
                    inode,
                    mode,
                    owner_uid,
                    group_gid,
                    is_hidden,
                    is_system
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                RETURNING id
            )
            INSERT INTO symlinks (fs_entry_id, target, uid)
            SELECT id, $14, $15::uuid FROM inserted
            RETURNING fs_entry_id
        )SQL"
    );

    conn_->prepare("get_symlink_by_id",
                   "SELECT s.target, s.uid, char_length(s.target)::bigint AS size_bytes, fs.* "
                   "FROM symlinks s "
                   "JOIN fs_entry fs ON s.fs_entry_id = fs.id "
                   "WHERE fs.id = $1");

    conn_->prepare("get_symlink_by_path",
                   "SELECT s.target, s.uid, char_length(s.target)::bigint AS size_bytes, fs.* "
                   "FROM symlinks s "
                   "JOIN fs_entry fs ON s.fs_entry_id = fs.id "
                   "WHERE fs.vault_id = $1 AND fs.path = $2");

    conn_->prepare("get_symlink_by_base32_alias",
                   "SELECT s.target, s.uid, char_length(s.target)::bigint AS size_bytes, fs.* "
                   "FROM symlinks s "
                   "JOIN fs_entry fs ON s.fs_entry_id = fs.id "
                   "WHERE fs.base32_alias = $1");

    conn_->prepare("get_symlink_by_inode",
                   "SELECT s.target, s.uid, char_length(s.target)::bigint AS size_bytes, fs.* "
                   "FROM symlinks s "
                   "JOIN fs_entry fs ON s.fs_entry_id = fs.id "
                   "WHERE fs.inode = $1");

    conn_->prepare("list_symlinks_in_dir_by_parent_id",
                   "SELECT s.target, s.uid, char_length(s.target)::bigint AS size_bytes, fs.* "
                   "FROM symlinks s "
                   "JOIN fs_entry fs ON s.fs_entry_id = fs.id "
                   "WHERE fs.parent_id = $1 AND fs.id != 1");

    conn_->prepare("list_symlinks_in_dir_by_parent_id_recursive",
                   "WITH RECURSIVE dir_tree AS ("
                   "    SELECT fs.*, s.target, s.uid, char_length(s.target)::bigint AS size_bytes "
                   "    FROM fs_entry fs "
                   "    JOIN symlinks s ON fs.id = s.fs_entry_id "
                   "    WHERE fs.parent_id = $1 "
                   "  UNION ALL "
                   "   SELECT fs2.*, s2.target, s2.uid, char_length(s2.target)::bigint AS size_bytes "
                   "   FROM fs_entry fs2 "
                   "   JOIN symlinks s2 ON fs2.id = s2.fs_entry_id "
                   "   JOIN dir_tree dt ON fs2.parent_id = dt.id "
                   ") "
                   "SELECT * FROM dir_tree");

    conn_->prepare("get_symlink_parent_id_and_size",
                   "SELECT fs.parent_id, char_length(s.target)::bigint AS size_bytes "
                   "FROM symlinks s "
                   "JOIN fs_entry fs ON s.fs_entry_id = fs.id "
                   "WHERE fs.id = $1");
}
