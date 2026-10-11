#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedUsers() const {
    conn_->prepare("insert_user",
                   "INSERT INTO users (name, email, password_hash, is_active, linux_uid, last_modified_by) "
                   "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id");

    conn_->prepare("user_exists", "SELECT EXISTS(SELECT 1 FROM users WHERE name = $1) AS exists");

    // Never the password hash: that is update_user_password's alone.
    conn_->prepare("update_user",
                   "UPDATE users SET name = $2, email = $3, is_active = $4, linux_uid = $5, "
                   "last_modified_by = $6, updated_at = NOW() "
                   "WHERE id = $1");

    conn_->prepare("delete_user", "DELETE FROM users WHERE id = $1");

    conn_->prepare("update_user_password", "UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1");

    conn_->prepare("update_user_last_login", "UPDATE users SET last_login = NOW() WHERE id = $1");

    conn_->prepare("admin_user_exists", "SELECT EXISTS(SELECT 1 FROM users WHERE name = 'admin') AS exists");

}
