#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedAdminRoleAssignments() const {
    conn_->prepare(
        "admin_role_assignment_upsert",
        R"SQL(
            INSERT INTO admin_role_assignments (
                user_id,
                role_id
            )
            VALUES (
                $1,
                $2
            )
            ON CONFLICT (user_id) DO UPDATE SET
                role_id = EXCLUDED.role_id,
                assigned_at = CURRENT_TIMESTAMP
            RETURNING
                id,
                user_id,
                role_id,
                assigned_at
        )SQL"
    );

    conn_->prepare(
        "admin_role_assignment_get_by_user_id",
        R"SQL(
            SELECT
                ara.id                          AS assignment_id,
                ara.user_id                     AS user_id,
                ara.role_id                     AS role_id,
                ara.assigned_at                 AS assigned_at,

                ar.id                           AS admin_role_id,
                ar.name                         AS role_name,
                ar.description                  AS role_description,
                ar.created_at                   AS role_created_at,
                ar.updated_at                   AS role_updated_at,
                ar.identity_permissions::bigint   AS identity_permissions,
                ar.audit_permissions::bigint      AS audit_permissions,
                ar.settings_permissions::bigint   AS settings_permissions,
                ar.roles_permissions::bigint      AS roles_permissions,
                ar.vaults_permissions::bigint     AS vaults_permissions,
                ar.keys_permissions::bigint       AS keys_permissions,
                ar.s3_gateway_permissions::bigint AS s3_gateway_permissions,
                ar.stats_permissions::bigint      AS stats_permissions
            FROM admin_role_assignments ara
            INNER JOIN admin_role ar
                ON ar.id = ara.role_id
            WHERE ara.user_id = $1
        )SQL"
    );

    conn_->prepare(
        "admin_role_assignment_get_by_assignment_id",
        R"SQL(
            SELECT
                ara.id                          AS assignment_id,
                ara.user_id                     AS user_id,
                ara.role_id                     AS role_id,
                ara.assigned_at                 AS assigned_at,

                ar.id                           AS admin_role_id,
                ar.name                         AS role_name,
                ar.description                  AS role_description,
                ar.created_at                   AS role_created_at,
                ar.updated_at                   AS role_updated_at,
                ar.identity_permissions::bigint   AS identity_permissions,
                ar.audit_permissions::bigint      AS audit_permissions,
                ar.settings_permissions::bigint   AS settings_permissions,
                ar.roles_permissions::bigint      AS roles_permissions,
                ar.vaults_permissions::bigint     AS vaults_permissions,
                ar.keys_permissions::bigint       AS keys_permissions,
                ar.s3_gateway_permissions::bigint AS s3_gateway_permissions,
                ar.stats_permissions::bigint      AS stats_permissions
            FROM admin_role_assignments ara
            INNER JOIN admin_role ar
                ON ar.id = ara.role_id
            WHERE ara.id = $1
        )SQL"
    );

    conn_->prepare(
        "admin_role_assignment_delete_by_user_id",
        R"SQL(
            DELETE FROM admin_role_assignments
            WHERE user_id = $1
        )SQL"
    );

    conn_->prepare(
        "admin_role_assignment_delete_by_assignment_id",
        R"SQL(
            DELETE FROM admin_role_assignments
            WHERE id = $1
        )SQL"
    );

    conn_->prepare(
        "admin_role_assignment_exists_by_user_id",
        R"SQL(
            SELECT EXISTS(
                SELECT 1
                FROM admin_role_assignments
                WHERE user_id = $1
            )
        )SQL"
    );

    conn_->prepare(
        "admin_role_assignment_list_all",
        R"SQL(
            SELECT
                ara.id                          AS assignment_id,
                ara.user_id                     AS user_id,
                ara.role_id                     AS role_id,
                ara.assigned_at                 AS assigned_at,

                ar.id                           AS admin_role_id,
                ar.name                         AS role_name,
                ar.description                  AS role_description,
                ar.created_at                   AS role_created_at,
                ar.updated_at                   AS role_updated_at,
                ar.identity_permissions::bigint   AS identity_permissions,
                ar.audit_permissions::bigint      AS audit_permissions,
                ar.settings_permissions::bigint   AS settings_permissions,
                ar.roles_permissions::bigint      AS roles_permissions,
                ar.vaults_permissions::bigint     AS vaults_permissions,
                ar.keys_permissions::bigint       AS keys_permissions,
                ar.s3_gateway_permissions::bigint AS s3_gateway_permissions,
                ar.stats_permissions::bigint      AS stats_permissions
            FROM admin_role_assignments ara
            INNER JOIN admin_role ar
                ON ar.id = ara.role_id
            ORDER BY ara.user_id
        )SQL"
    );

    conn_->prepare("count_admin_role_assignments_by_role_id",
        R"SQL(
            SELECT COUNT(*)
            FROM admin_role_assignments
            WHERE role_id = $1
            )SQL"
        );
}
