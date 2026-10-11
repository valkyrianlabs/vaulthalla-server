#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedGroups() const {
    conn_->prepare(
        "create_group",
        R"SQL(
            INSERT INTO groups (
                name,
                description,
                linux_gid
            )
            VALUES (
                $1,
                $2,
                $3
            )
            RETURNING
                id,
                linux_gid,
                name,
                description,
                created_at,
                updated_at
        )SQL"
    );

    conn_->prepare(
        "update_group",
        R"SQL(
            UPDATE groups
               SET name = $2,
                   description = $3,
                   linux_gid = $4,
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = $1
         RETURNING
               id,
               linux_gid,
               name,
               description,
               created_at,
               updated_at
        )SQL"
    );

    conn_->prepare(
        "delete_group",
        R"SQL(
            DELETE FROM groups
             WHERE id = $1
        )SQL"
    );

    conn_->prepare(
        "save_group_member",
        R"SQL(
            INSERT INTO group_members (
                group_id,
                user_id,
                joined_at
            )
            VALUES (
                $1,
                $2,
                CURRENT_TIMESTAMP
            )
            ON CONFLICT (group_id, user_id) DO UPDATE
                SET joined_at = group_members.joined_at
            RETURNING
                group_id,
                user_id,
                joined_at
        )SQL"
    );

    conn_->prepare(
        "remove_group_member",
        R"SQL(
            DELETE FROM group_members
             WHERE group_id = $1
               AND user_id = $2
        )SQL"
    );

    conn_->prepare(
        "group_exists_by_name",
        R"SQL(
            SELECT EXISTS(
                SELECT 1
                FROM groups g
                WHERE g.name = $1
            ) AS exists
        )SQL"
    );

    conn_->prepare(
        "group_member_exists",
        R"SQL(
            SELECT EXISTS(
                SELECT 1
                FROM group_members gm
                WHERE gm.group_id = $1
                  AND gm.user_id = $2
            ) AS exists
        )SQL"
    );

}
