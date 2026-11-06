#include "db/query/s3/Gateway.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/encoding/timestamp.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/role/Vault.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <ctime>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <set>
#include <sstream>
#include <unordered_map>

namespace vh::db::query::s3 {

namespace {
using vh::db::encoding::from_hex_bytea;
using vh::db::encoding::parsePostgresTimestamp;
using vh::db::encoding::to_hex_bytea;

std::time_t ts(pqxx::row_ref row, const char* column) {
    if (row[column].is_null()) return 0;
    return parsePostgresTimestamp(row[column].as<std::string>());
}

std::optional<std::time_t> optionalTs(pqxx::row_ref row, const char* column) {
    if (row[column].is_null()) return std::nullopt;
    return parsePostgresTimestamp(row[column].as<std::string>());
}

GatewayCredential credentialFromRow(pqxx::row_ref row) {
    const auto userId = row["user_id"].as<uint32_t>();
    return {
        .id = row["id"].as<uint32_t>(),
        .user_id = userId,
        .created_by = row["created_by"].as<std::optional<uint32_t>>(),
        .principal_user_id = row["principal_user_id"].is_null()
            ? userId
            : row["principal_user_id"].as<uint32_t>(),
        .name = row["name"].as<std::string>(),
        .access_key = row["access_key"].as<std::string>(),
        .encrypted_secret_access_key = from_hex_bytea(row["encrypted_secret_access_key"].as<std::string>()),
        .iv = from_hex_bytea(row["iv"].as<std::string>()),
        .enabled = row["enabled"].as<bool>(),
        .enforce_budget_for_local_requests = row["enforce_budget_for_local_requests"].as<bool>(),
        .scope_mode = row["scope_mode"].as<std::string>(),
        .description = row["description"].as<std::optional<std::string>>(),
        .created_at = ts(row, "created_at"),
        .last_used_at = optionalTs(row, "last_used_at"),
        .expires_at = optionalTs(row, "expires_at")
    };
}

CredentialVaultRoleAssignment roleAssignmentFromRow(pqxx::row_ref row) {
    return {
        .id = row["id"].as<uint32_t>(),
        .credential_id = row["credential_id"].as<uint32_t>(),
        .vault_id = row["vault_id"].as<uint32_t>(),
        .vault_role_id = row["vault_role_id"].as<uint32_t>(),
        .enabled = row["enabled"].as<bool>(),
        .created_by = row["created_by"].as<std::optional<uint32_t>>(),
        .created_at = ts(row, "created_at"),
        .updated_at = ts(row, "updated_at")
    };
}

CredentialDefaultVaultRole defaultRoleFromRow(pqxx::row_ref row) {
    return {
        .id = row["id"].as<uint32_t>(),
        .credential_id = row["credential_id"].as<uint32_t>(),
        .vault_role_id = row["vault_role_id"].as<uint32_t>(),
        .enabled = row["enabled"].as<bool>(),
        .created_by = row["created_by"].as<std::optional<uint32_t>>(),
        .created_at = ts(row, "created_at"),
        .updated_at = ts(row, "updated_at")
    };
}

CredentialSelectedVault selectedVaultFromRow(pqxx::row_ref row) {
    return {
        .credential_id = row["credential_id"].as<uint32_t>(),
        .vault_id = row["vault_id"].as<uint32_t>(),
        .enabled = row["enabled"].as<bool>(),
        .created_by = row["created_by"].as<std::optional<uint32_t>>(),
        .created_at = ts(row, "created_at"),
        .updated_at = ts(row, "updated_at")
    };
}

uint32_t permissionIdForOverride(pqxx::work& txn, const ::vh::rbac::permission::Override& overrideRule) {
    if (overrideRule.permission.id != 0) return overrideRule.permission.id;
    if (overrideRule.permission.qualified_name.empty())
        throw std::runtime_error("S3 gateway credential role override permission id is required");
    const auto res = txn.exec(
        "SELECT id FROM permission WHERE name = $1 LIMIT 1",
        pqxx::params{overrideRule.permission.qualified_name});
    if (res.empty())
        throw std::runtime_error("S3 gateway credential role override permission is not registered: " +
                                 overrideRule.permission.qualified_name);
    return res.one_field_ref().as<uint32_t>();
}

std::optional<uint32_t> vaultRoleIdByName(pqxx::work& txn, const std::string& roleName) {
    const auto res = txn.exec(
        "SELECT id FROM vault_role WHERE name = $1 LIMIT 1",
        pqxx::params{roleName});
    if (res.empty()) return std::nullopt;
    return res.one_field_ref().as<uint32_t>();
}

uint32_t requireVaultRoleIdByName(pqxx::work& txn, const std::string& roleName) {
    const auto roleId = vaultRoleIdByName(txn, roleName);
    if (!roleId) throw std::runtime_error("S3 gateway vault role is not seeded: " + roleName);
    return *roleId;
}

uint32_t credentialRoleAssignmentId(pqxx::work& txn, const uint32_t credentialId, const uint32_t vaultId) {
    const auto res = txn.exec(
        R"SQL(
            SELECT id
            FROM s3_gateway_credential_vault_role_assignment
            WHERE credential_id = $1
              AND vault_id = $2
              AND enabled = TRUE
        )SQL",
        pqxx::params{credentialId, vaultId});
    if (res.empty())
        throw std::runtime_error("S3 gateway credential vault role assignment not found");
    return res.one_field_ref().as<uint32_t>();
}

uint32_t credentialDefaultRoleId(pqxx::work& txn, const uint32_t credentialId) {
    const auto res = txn.exec(
        R"SQL(
            SELECT id
            FROM s3_gateway_credential_default_vault_role
            WHERE credential_id = $1
              AND enabled = TRUE
        )SQL",
        pqxx::params{credentialId});
    if (res.empty())
        throw std::runtime_error("S3 gateway credential default vault role not found");
    return res.one_field_ref().as<uint32_t>();
}

pqxx::result credentialRoleOverrides(pqxx::work& txn, const uint32_t assignmentId) {
    return txn.exec(
        R"SQL(
            SELECT
                o.id                                      AS override_id,
                o.gateway_credential_vault_role_id        AS assignment_id,
                o.permission_id                           AS permission_id,
                o.glob_path                               AS glob_path,
                o.enabled                                 AS enabled,
                o.effect                                  AS effect,
                o.created_at                              AS created_at,
                o.updated_at                              AS updated_at,

                p.name                                    AS name,
                p.description                             AS description,
                p.category                                AS category,
                p.bit_position                            AS bit_position
            FROM s3_gateway_credential_vault_role_override o
            INNER JOIN permission p
                ON p.id = o.permission_id
            WHERE o.gateway_credential_vault_role_id = $1
            ORDER BY p.bit_position, o.glob_path
        )SQL",
        pqxx::params{assignmentId});
}

pqxx::result credentialDefaultRoleOverrides(pqxx::work& txn, const uint32_t defaultRoleId) {
    return txn.exec(
        R"SQL(
            SELECT
                o.id                                      AS override_id,
                o.gateway_credential_default_role_id      AS assignment_id,
                o.permission_id                           AS permission_id,
                o.glob_path                               AS glob_path,
                o.enabled                                 AS enabled,
                o.effect                                  AS effect,
                o.created_at                              AS created_at,
                o.updated_at                              AS updated_at,

                p.name                                    AS name,
                p.description                             AS description,
                p.category                                AS category,
                p.bit_position                            AS bit_position
            FROM s3_gateway_credential_default_vault_role_override o
            INNER JOIN permission p
                ON p.id = o.permission_id
            WHERE o.gateway_credential_default_role_id = $1
            ORDER BY p.bit_position, o.glob_path
        )SQL",
        pqxx::params{defaultRoleId});
}

pqxx::result credentialDefaultRoleRow(
    pqxx::work& txn,
    const uint32_t credentialId,
    const uint32_t vaultId) {
    return txn.exec(
        R"SQL(
            SELECT
                d.id                              AS assignment_id,
                $2::integer                      AS vault_id,
                'gateway_credential_default'     AS subject_type,
                d.credential_id                  AS subject_id,
                d.vault_role_id                  AS vault_role_id,
                d.created_at                     AS assigned_at,

                vr.id                            AS id,
                vr.name                          AS role_name,
                vr.description                   AS role_description,
                vr.created_at                    AS role_created_at,
                vr.updated_at                    AS role_updated_at,
                vr.files_permissions::bigint       AS files_permissions,
                vr.directories_permissions::bigint AS directories_permissions,
                vr.sync_permissions::bigint        AS sync_permissions,
                vr.roles_permissions::bigint       AS roles_permissions
            FROM s3_gateway_credential_default_vault_role d
            INNER JOIN vault_role vr
                ON vr.id = d.vault_role_id
            WHERE d.credential_id = $1
              AND d.enabled = TRUE
        )SQL",
        pqxx::params{credentialId, vaultId});
}

pqxx::result credentialVaultRoleRow(
    pqxx::work& txn,
    const uint32_t credentialId,
    const uint32_t vaultId) {
    return txn.exec(
        R"SQL(
            SELECT
                a.id                              AS assignment_id,
                a.vault_id                        AS vault_id,
                'gateway_credential'              AS subject_type,
                a.credential_id                   AS subject_id,
                a.vault_role_id                   AS vault_role_id,
                a.created_at                      AS assigned_at,

                vr.id                             AS id,
                vr.name                           AS role_name,
                vr.description                    AS role_description,
                vr.created_at                     AS role_created_at,
                vr.updated_at                     AS role_updated_at,
                vr.files_permissions::bigint       AS files_permissions,
                vr.directories_permissions::bigint AS directories_permissions,
                vr.sync_permissions::bigint        AS sync_permissions,
                vr.roles_permissions::bigint       AS roles_permissions
            FROM s3_gateway_credential_vault_role_assignment a
            INNER JOIN vault_role vr
                ON vr.id = a.vault_role_id
            WHERE a.credential_id = $1
              AND a.vault_id = $2
              AND a.enabled = TRUE
        )SQL",
        pqxx::params{credentialId, vaultId});
}

BucketBinding bucketFromRow(pqxx::row_ref row) {
    return {
        .vault_id = row["vault_id"].as<uint32_t>(),
        .bucket_name = row["bucket_name"].as<std::string>(),
        .api_exclusive = row["api_exclusive"].as<bool>(),
        .mode = row["mode"].as<std::string>(),
        .created_by = row["created_by"].as<std::optional<uint32_t>>(),
        .created_at = ts(row, "created_at"),
        .updated_at = ts(row, "updated_at")
    };
}

ObjectState objectFromRow(pqxx::row_ref row) {
    return {
        .vault_id = row["vault_id"].as<uint32_t>(),
        .object_key = row["object_key"].as<std::string>(),
        .etag = row["etag"].as<std::string>(),
        .size_bytes = row["size_bytes"].as<uint64_t>(),
        .content_type = row["content_type"].as<std::optional<std::string>>(),
        .storage_class = row["storage_class"].as<std::optional<std::string>>(),
        .last_modified = ts(row, "last_modified"),
        .multipart = row["multipart"].as<bool>(),
        .part_count = row["part_count"].as<std::optional<uint32_t>>()
    };
}

std::map<std::string, std::string> metadataFromJson(const std::string& raw) {
    std::map<std::string, std::string> out;
    if (raw.empty()) return out;
    const auto parsed = nlohmann::json::parse(raw);
    for (const auto& [key, value] : parsed.items())
        out[key] = value.is_string() ? value.get<std::string>() : value.dump();
    return out;
}

MultipartUpload uploadFromRow(pqxx::row_ref row) {
    return {
        .upload_id = row["upload_id"].as<std::string>(),
        .parts_dir_id = row["parts_dir_id"].as<std::string>(),
        .vault_id = row["vault_id"].as<uint32_t>(),
        .object_key = row["object_key"].as<std::string>(),
        .initiated_by = row["initiated_by"].as<uint32_t>(),
        .initiated_at = ts(row, "initiated_at"),
        .content_type = row["content_type"].as<std::optional<std::string>>(),
        .metadata = metadataFromJson(row["metadata"].as<std::string>()),
        .storage_class = row["storage_class"].as<std::optional<std::string>>(),
        .aborted = row["aborted"].as<bool>(),
        .completed = row["completed"].as<bool>()
    };
}

MultipartPart partFromRow(pqxx::row_ref row) {
    return {
        .upload_id = row["upload_id"].as<std::string>(),
        .part_number = row["part_number"].as<uint32_t>(),
        .etag = row["etag"].as<std::string>(),
        .size_bytes = row["size_bytes"].as<uint64_t>(),
        .md5 = from_hex_bytea(row["md5"].as<std::string>()),
        .path = row["path"].as<std::string>(),
        .created_at = ts(row, "created_at"),
        .encryption_iv = row["encryption_iv"].as<std::optional<std::string>>(),
        .key_version = row["key_version"].as<std::optional<uint32_t>>()
    };
}

std::string normalizeKey(std::string key) {
    while (!key.empty() && key.front() == '/') key.erase(key.begin());
    return key;
}

std::string makeMetadataJson(const std::map<std::string, std::string>& metadata) {
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [key, value] : metadata) out[key] = value;
    return out.dump();
}

std::string notHiddenByActiveTrashSql(const std::string& vaultIdExpr, const std::string& objectKeyExpr) {
    return
        "NOT EXISTS ("
        "  SELECT 1 "
        "  FROM files_trashed ft "
        "  WHERE ft.vault_id = " + vaultIdExpr + " "
        "    AND ft.path = ('/' || " + objectKeyExpr + ") "
        "    AND ft.deleted_at IS NULL "
        "    AND NOT EXISTS ("
        "      SELECT 1 "
        "      FROM fs_entry live "
        "      JOIN files live_file ON live_file.fs_entry_id = live.id "
        "      WHERE live.vault_id = ft.vault_id AND live.path = ft.path"
        "    )"
        ")";
}

std::string roleNameForScopeShorthand(const CredentialVaultAccessShorthand& scope) {
    if (scope.can_admin) return "manager";
    if (scope.can_delete) return "manager";
    if (scope.can_write) return "contributor";
    if (scope.can_read) return "reader";
    if (scope.can_list) return "guest";
    return "implicit_deny";
}

uint32_t roleRank(const std::string& roleName) {
    if (roleName == "implicit_deny") return 0;
    if (roleName == "guest") return 1;
    if (roleName == "reader") return 2;
    if (roleName == "contributor") return 3;
    if (roleName == "editor") return 4;
    if (roleName == "manager") return 5;
    if (roleName == "power_user") return 6;
    if (roleName == "full") return 7;
    return 8;
}

std::vector<::vh::rbac::permission::Override> mergeDefaultAndPerVaultOverrides(
    std::vector<::vh::rbac::permission::Override> defaults,
    const std::vector<::vh::rbac::permission::Override>& perVault) {
    for (const auto& overrideRule : perVault) {
        const auto existing = std::ranges::find_if(defaults, [&](const auto& candidate) {
            return candidate.permission.id == overrideRule.permission.id &&
                candidate.glob_path() == overrideRule.glob_path();
        });
        if (existing == defaults.end())
            defaults.push_back(overrideRule);
        else
            *existing = overrideRule;
    }
    return defaults;
}
}

uint32_t Gateway::createCredential(const GatewayCredential& credential) {
    return Transactions::exec("S3Gateway::createCredential", [&](pqxx::work& txn) {
        const auto principalUserId = credential.principal_user_id == 0
            ? credential.user_id
            : credential.principal_user_id;
        const auto compatibilityUserId = credential.user_id == 0
            ? principalUserId
            : credential.user_id;
        const auto res = txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_credentials
                    (user_id, created_by, principal_user_id, name, access_key, encrypted_secret_access_key, iv,
                     enabled, enforce_budget_for_local_requests, scope_mode, description, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, CASE WHEN $12::bigint IS NULL THEN NULL ELSE TO_TIMESTAMP($12::double precision) END)
                ON CONFLICT (user_id, name) DO UPDATE SET
                    created_by = EXCLUDED.created_by,
                    principal_user_id = EXCLUDED.principal_user_id,
                    access_key = EXCLUDED.access_key,
                    encrypted_secret_access_key = EXCLUDED.encrypted_secret_access_key,
                    iv = EXCLUDED.iv,
                    enabled = EXCLUDED.enabled,
                    enforce_budget_for_local_requests = EXCLUDED.enforce_budget_for_local_requests,
                    scope_mode = EXCLUDED.scope_mode,
                    description = EXCLUDED.description,
                    expires_at = EXCLUDED.expires_at
                RETURNING id
            )SQL",
            pqxx::params{
                compatibilityUserId,
                credential.created_by,
                principalUserId,
                credential.name,
                credential.access_key,
                to_hex_bytea(credential.encrypted_secret_access_key),
                to_hex_bytea(credential.iv),
                credential.enabled,
                credential.enforce_budget_for_local_requests,
                credential.scope_mode.empty() ? std::string{"user_access"} : credential.scope_mode,
                credential.description,
                credential.expires_at
            });
        return res.one_field_ref().as<uint32_t>();
    });
}

std::vector<GatewayCredential> Gateway::listCredentials(const std::optional<uint32_t> userId) {
    return Transactions::exec("S3Gateway::listCredentials", [&](pqxx::work& txn) {
        const auto res = userId
            ? txn.exec("SELECT * FROM s3_gateway_credentials WHERE principal_user_id = " + txn.quote(*userId) +
                       " OR (principal_user_id IS NULL AND user_id = " + txn.quote(*userId) + ") ORDER BY id")
            : txn.exec("SELECT * FROM s3_gateway_credentials ORDER BY id");
        return db::mapRows(res, credentialFromRow);
    });
}

std::vector<GatewayCredential> Gateway::listCredentialsForPrincipal(const uint32_t userId) {
    return listCredentials(userId);
}

std::vector<GatewayCredential> Gateway::listCredentialsAdmin(const bool includeDisabled) {
    return Transactions::exec("S3Gateway::listCredentialsAdmin", [&](pqxx::work& txn) {
        const auto res = txn.exec(std::string{"SELECT * FROM s3_gateway_credentials "} +
                                  (includeDisabled ? "" : "WHERE enabled = TRUE ") +
                                  "ORDER BY principal_user_id NULLS LAST, id");
        return db::mapRows(res, credentialFromRow);
    });
}

std::optional<GatewayCredential> Gateway::getCredentialByAccessKey(const std::string& accessKey) {
    return Transactions::exec("S3Gateway::getCredentialByAccessKey", [&](pqxx::work& txn) -> std::optional<GatewayCredential> {
        const auto res = txn.exec(
            "SELECT * FROM s3_gateway_credentials WHERE access_key = $1",
            pqxx::params{accessKey});
        if (res.empty()) return std::nullopt;
        return credentialFromRow(res.one_row_ref());
    });
}

bool Gateway::deleteCredentialByAccessKey(const std::string& accessKey) {
    return Transactions::exec("S3Gateway::deleteCredentialByAccessKey", [&](pqxx::work& txn) {
        return txn.exec("DELETE FROM s3_gateway_credentials WHERE access_key = $1", pqxx::params{accessKey}).affected_rows() > 0;
    });
}

bool Gateway::deleteCredentialByName(const uint32_t userId, const std::string& name) {
    return Transactions::exec("S3Gateway::deleteCredentialByName", [&](pqxx::work& txn) {
        return txn.exec(
            "DELETE FROM s3_gateway_credentials "
            "WHERE (principal_user_id = $1 OR (principal_user_id IS NULL AND user_id = $1)) AND name = $2",
            pqxx::params{userId, name}).affected_rows() > 0;
    });
}

void Gateway::updateCredentialLastUsed(const uint32_t id) {
    Transactions::exec("S3Gateway::updateCredentialLastUsed", [&](pqxx::work& txn) {
        txn.exec("UPDATE s3_gateway_credentials SET last_used_at = NOW() WHERE id = $1", pqxx::params{id});
    });
}

void Gateway::replaceCredentialScopeShorthand(
    const uint32_t credentialId,
    const std::vector<CredentialVaultAccessShorthand>& scopes) {
    Transactions::exec("S3Gateway::replaceCredentialScopeShorthand", [&](pqxx::work& txn) {
        txn.exec(
            "DELETE FROM s3_gateway_credential_selected_vault WHERE credential_id = $1",
            pqxx::params{credentialId});
        txn.exec(
            "DELETE FROM s3_gateway_credential_vault_role_assignment WHERE credential_id = $1",
            pqxx::params{credentialId});

        std::vector<std::pair<CredentialVaultAccessShorthand, uint32_t>> resolvedScopes;
        resolvedScopes.reserve(scopes.size());
        for (const auto& scope : scopes) {
            const auto roleName = roleNameForScopeShorthand(scope);
            resolvedScopes.emplace_back(scope, requireVaultRoleIdByName(txn, roleName));
            txn.exec(
                R"SQL(
                    INSERT INTO s3_gateway_credential_selected_vault
                        (credential_id, vault_id, enabled)
                    VALUES ($1, $2, TRUE)
                    ON CONFLICT (credential_id, vault_id) DO UPDATE SET
                        enabled = TRUE,
                        updated_at = CURRENT_TIMESTAMP
                )SQL",
                pqxx::params{
                    credentialId,
                    scope.vault_id
                });
        }

        if (resolvedScopes.empty()) {
            txn.exec(
                "DELETE FROM s3_gateway_credential_default_vault_role WHERE credential_id = $1",
                pqxx::params{credentialId});
            return;
        }

        const auto firstRoleId = resolvedScopes.front().second;
        const auto allSameRole = std::ranges::all_of(resolvedScopes, [&](const auto& item) {
            return item.second == firstRoleId;
        });

        uint32_t defaultRoleId = firstRoleId;
        if (!allSameRole) {
            if (const auto implicitDeny = vaultRoleIdByName(txn, "implicit_deny")) {
                defaultRoleId = *implicitDeny;
            } else {
                auto best = resolvedScopes.front();
                for (const auto& item : resolvedScopes) {
                    const auto itemRoleName = roleNameForScopeShorthand(item.first);
                    const auto bestRoleName = roleNameForScopeShorthand(best.first);
                    if (roleRank(itemRoleName) < roleRank(bestRoleName) ||
                        (roleRank(itemRoleName) == roleRank(bestRoleName) && item.second < best.second))
                        best = item;
                }
                defaultRoleId = best.second;
            }
        }

        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_credential_default_vault_role
                    (credential_id, vault_role_id, enabled)
                VALUES ($1, $2, TRUE)
                ON CONFLICT (credential_id) DO UPDATE SET
                    vault_role_id = EXCLUDED.vault_role_id,
                    enabled = TRUE,
                    updated_at = CURRENT_TIMESTAMP
            )SQL",
            pqxx::params{credentialId, defaultRoleId});

        for (const auto& [scope, roleId] : resolvedScopes) {
            if (roleId == defaultRoleId) continue;
            txn.exec(
                R"SQL(
                    INSERT INTO s3_gateway_credential_vault_role_assignment
                        (credential_id, vault_id, vault_role_id, enabled)
                    VALUES ($1, $2, $3, TRUE)
                    ON CONFLICT (credential_id, vault_id) DO UPDATE SET
                        vault_role_id = EXCLUDED.vault_role_id,
                        enabled = TRUE,
                        updated_at = CURRENT_TIMESTAMP
                )SQL",
                pqxx::params{credentialId, scope.vault_id, roleId});
        }
    });
}

std::vector<CredentialVaultRoleAssignment> Gateway::listCredentialVaultRoleAssignments(const uint32_t credentialId) {
    return Transactions::exec("S3Gateway::listCredentialVaultRoleAssignments", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                SELECT *
                FROM s3_gateway_credential_vault_role_assignment
                WHERE credential_id = $1
                ORDER BY vault_id
            )SQL",
            pqxx::params{credentialId});
        return db::mapRows(res, roleAssignmentFromRow);
    });
}

uint32_t Gateway::upsertCredentialVaultRoleAssignment(const CredentialVaultRoleAssignmentInput& input) {
    if (input.credential_id == 0) throw std::invalid_argument("S3 gateway credential role assignment requires credential_id");
    if (input.vault_id == 0) throw std::invalid_argument("S3 gateway credential role assignment requires vault_id");
    if (input.vault_role_id == 0) throw std::invalid_argument("S3 gateway credential role assignment requires vault_role_id");

    return Transactions::exec("S3Gateway::upsertCredentialVaultRoleAssignment", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_credential_vault_role_assignment
                    (credential_id, vault_id, vault_role_id, enabled, created_by)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (credential_id, vault_id) DO UPDATE SET
                    vault_role_id = EXCLUDED.vault_role_id,
                    enabled = EXCLUDED.enabled,
                    created_by = COALESCE(EXCLUDED.created_by, s3_gateway_credential_vault_role_assignment.created_by),
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            )SQL",
            pqxx::params{
                input.credential_id,
                input.vault_id,
                input.vault_role_id,
                input.enabled,
                input.created_by
            });
        const auto assignmentId = res.one_field_ref().as<uint32_t>();
        txn.exec(
            "DELETE FROM s3_gateway_credential_vault_role_override WHERE gateway_credential_vault_role_id = $1",
            pqxx::params{assignmentId});
        for (const auto& overrideRule : input.overrides) {
            txn.exec(
                R"SQL(
                    INSERT INTO s3_gateway_credential_vault_role_override
                        (gateway_credential_vault_role_id, permission_id, glob_path, enabled, effect)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (gateway_credential_vault_role_id, permission_id, glob_path)
                    DO UPDATE SET
                        enabled = EXCLUDED.enabled,
                        effect = EXCLUDED.effect,
                        updated_at = CURRENT_TIMESTAMP
                )SQL",
                pqxx::params{
                    assignmentId,
                    permissionIdForOverride(txn, overrideRule),
                    overrideRule.glob_path(),
                    overrideRule.enabled,
                    ::vh::rbac::permission::to_string(overrideRule.effect)
                });
        }
        return assignmentId;
    });
}

bool Gateway::deleteCredentialVaultRoleAssignment(const uint32_t credentialId, const uint32_t vaultId) {
    return Transactions::exec("S3Gateway::deleteCredentialVaultRoleAssignment", [&](pqxx::work& txn) {
        return txn.exec(
            R"SQL(
                DELETE FROM s3_gateway_credential_vault_role_assignment
                WHERE credential_id = $1 AND vault_id = $2
            )SQL",
            pqxx::params{credentialId, vaultId}).affected_rows() > 0;
    });
}

std::vector<::vh::rbac::permission::Override> Gateway::listCredentialVaultRoleOverrides(
    const uint32_t credentialId,
    const uint32_t vaultId) {
    return Transactions::exec("S3Gateway::listCredentialVaultRoleOverrides", [&](pqxx::work& txn) {
        const auto assignmentId = credentialRoleAssignmentId(txn, credentialId, vaultId);
        return ::vh::rbac::permission::permissionOverridesFromPqRes(credentialRoleOverrides(txn, assignmentId));
    });
}

uint32_t Gateway::upsertCredentialVaultRoleOverride(
    const uint32_t credentialId,
    const uint32_t vaultId,
    const ::vh::rbac::permission::Override& overrideRule) {
    if (credentialId == 0) throw std::invalid_argument("S3 gateway credential role override requires credential_id");
    if (vaultId == 0) throw std::invalid_argument("S3 gateway credential role override requires vault_id");

    return Transactions::exec("S3Gateway::upsertCredentialVaultRoleOverride", [&](pqxx::work& txn) {
        const auto assignmentId = credentialRoleAssignmentId(txn, credentialId, vaultId);
        const auto permissionId = permissionIdForOverride(txn, overrideRule);
        const auto res = txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_credential_vault_role_override
                    (gateway_credential_vault_role_id, permission_id, glob_path, enabled, effect)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (gateway_credential_vault_role_id, permission_id, glob_path)
                DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    effect = EXCLUDED.effect,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            )SQL",
            pqxx::params{
                assignmentId,
                permissionId,
                overrideRule.glob_path(),
                overrideRule.enabled,
                ::vh::rbac::permission::to_string(overrideRule.effect)
            });
        return res.one_field_ref().as<uint32_t>();
    });
}

bool Gateway::deleteCredentialVaultRoleOverride(
    const uint32_t credentialId,
    const uint32_t vaultId,
    const uint32_t overrideId) {
    return Transactions::exec("S3Gateway::deleteCredentialVaultRoleOverride", [&](pqxx::work& txn) {
        const auto assignmentId = credentialRoleAssignmentId(txn, credentialId, vaultId);
        return txn.exec(
            R"SQL(
                DELETE FROM s3_gateway_credential_vault_role_override
                WHERE id = $1
                  AND gateway_credential_vault_role_id = $2
            )SQL",
            pqxx::params{overrideId, assignmentId}).affected_rows() > 0;
    });
}

std::shared_ptr<::vh::rbac::role::Vault> Gateway::getCredentialVaultRoleForVault(
    const uint32_t credentialId,
    const uint32_t vaultId) {
    return Transactions::exec("S3Gateway::getCredentialVaultRoleForVault", [&](pqxx::work& txn) -> std::shared_ptr<::vh::rbac::role::Vault> {
        const auto res = credentialVaultRoleRow(txn, credentialId, vaultId);
        if (res.empty()) return nullptr;
        const auto assignmentId = res.one_row_ref()["assignment_id"].as<uint32_t>();
        return std::make_shared<::vh::rbac::role::Vault>(res.one_row_ref(), credentialRoleOverrides(txn, assignmentId));
    });
}

std::optional<CredentialDefaultVaultRole> Gateway::getCredentialDefaultVaultRole(const uint32_t credentialId) {
    return Transactions::exec("S3Gateway::getCredentialDefaultVaultRole", [&](pqxx::work& txn) -> std::optional<CredentialDefaultVaultRole> {
        const auto res = txn.exec(
            R"SQL(
                SELECT *
                FROM s3_gateway_credential_default_vault_role
                WHERE credential_id = $1
            )SQL",
            pqxx::params{credentialId});
        if (res.empty()) return std::nullopt;
        return defaultRoleFromRow(res.one_row_ref());
    });
}

uint32_t Gateway::upsertCredentialDefaultVaultRole(
    const uint32_t credentialId,
    const uint32_t vaultRoleId,
    const bool enabled,
    const std::optional<uint32_t> createdBy) {
    if (credentialId == 0) throw std::invalid_argument("S3 gateway credential default role requires credential_id");
    if (vaultRoleId == 0) throw std::invalid_argument("S3 gateway credential default role requires vault_role_id");

    return Transactions::exec("S3Gateway::upsertCredentialDefaultVaultRole", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_credential_default_vault_role
                    (credential_id, vault_role_id, enabled, created_by)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (credential_id) DO UPDATE SET
                    vault_role_id = EXCLUDED.vault_role_id,
                    enabled = EXCLUDED.enabled,
                    created_by = COALESCE(EXCLUDED.created_by, s3_gateway_credential_default_vault_role.created_by),
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            )SQL",
            pqxx::params{credentialId, vaultRoleId, enabled, createdBy});
        return res.one_field_ref().as<uint32_t>();
    });
}

bool Gateway::deleteCredentialDefaultVaultRole(const uint32_t credentialId) {
    return Transactions::exec("S3Gateway::deleteCredentialDefaultVaultRole", [&](pqxx::work& txn) {
        return txn.exec(
            R"SQL(
                DELETE FROM s3_gateway_credential_default_vault_role
                WHERE credential_id = $1
            )SQL",
            pqxx::params{credentialId}).affected_rows() > 0;
    });
}

std::vector<::vh::rbac::permission::Override> Gateway::listCredentialDefaultVaultRoleOverrides(
    const uint32_t credentialId) {
    return Transactions::exec("S3Gateway::listCredentialDefaultVaultRoleOverrides", [&](pqxx::work& txn) {
        const auto defaultRoleId = credentialDefaultRoleId(txn, credentialId);
        return ::vh::rbac::permission::permissionOverridesFromPqRes(credentialDefaultRoleOverrides(txn, defaultRoleId));
    });
}

uint32_t Gateway::upsertCredentialDefaultVaultRoleOverride(
    const uint32_t credentialId,
    const ::vh::rbac::permission::Override& overrideRule) {
    if (credentialId == 0) throw std::invalid_argument("S3 gateway credential default role override requires credential_id");

    return Transactions::exec("S3Gateway::upsertCredentialDefaultVaultRoleOverride", [&](pqxx::work& txn) {
        const auto defaultRoleId = credentialDefaultRoleId(txn, credentialId);
        const auto permissionId = permissionIdForOverride(txn, overrideRule);
        const auto res = txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_credential_default_vault_role_override
                    (gateway_credential_default_role_id, permission_id, glob_path, enabled, effect)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (gateway_credential_default_role_id, permission_id, glob_path)
                DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    effect = EXCLUDED.effect,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            )SQL",
            pqxx::params{
                defaultRoleId,
                permissionId,
                overrideRule.glob_path(),
                overrideRule.enabled,
                ::vh::rbac::permission::to_string(overrideRule.effect)
            });
        return res.one_field_ref().as<uint32_t>();
    });
}

bool Gateway::deleteCredentialDefaultVaultRoleOverride(
    const uint32_t credentialId,
    const uint32_t overrideId) {
    return Transactions::exec("S3Gateway::deleteCredentialDefaultVaultRoleOverride", [&](pqxx::work& txn) {
        const auto defaultRoleId = credentialDefaultRoleId(txn, credentialId);
        return txn.exec(
            R"SQL(
                DELETE FROM s3_gateway_credential_default_vault_role_override
                WHERE id = $1
                  AND gateway_credential_default_role_id = $2
            )SQL",
            pqxx::params{overrideId, defaultRoleId}).affected_rows() > 0;
    });
}

std::vector<CredentialSelectedVault> Gateway::listCredentialSelectedVaults(const uint32_t credentialId) {
    return Transactions::exec("S3Gateway::listCredentialSelectedVaults", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                SELECT *
                FROM s3_gateway_credential_selected_vault
                WHERE credential_id = $1
                ORDER BY vault_id
            )SQL",
            pqxx::params{credentialId});
        return db::mapRows(res, selectedVaultFromRow);
    });
}

void Gateway::replaceCredentialSelectedVaults(
    const uint32_t credentialId,
    const std::vector<uint32_t>& vaultIds,
    const std::optional<uint32_t> createdBy) {
    if (credentialId == 0) throw std::invalid_argument("S3 gateway selected vault replacement requires credential_id");

    Transactions::exec("S3Gateway::replaceCredentialSelectedVaults", [&](pqxx::work& txn) {
        txn.exec(
            "DELETE FROM s3_gateway_credential_selected_vault WHERE credential_id = $1",
            pqxx::params{credentialId});
        std::set<uint32_t> uniqueVaultIds(vaultIds.begin(), vaultIds.end());
        for (const auto vaultId : uniqueVaultIds) {
            if (vaultId == 0) continue;
            txn.exec(
                R"SQL(
                    INSERT INTO s3_gateway_credential_selected_vault
                        (credential_id, vault_id, enabled, created_by)
                    VALUES ($1, $2, TRUE, $3)
                    ON CONFLICT (credential_id, vault_id) DO UPDATE SET
                        enabled = TRUE,
                        created_by = COALESCE(EXCLUDED.created_by, s3_gateway_credential_selected_vault.created_by),
                        updated_at = CURRENT_TIMESTAMP
                )SQL",
                pqxx::params{credentialId, vaultId, createdBy});
        }
    });
}

CredentialSelectedVault Gateway::upsertCredentialSelectedVault(
    const uint32_t credentialId,
    const uint32_t vaultId,
    const bool enabled,
    const std::optional<uint32_t> createdBy) {
    if (credentialId == 0) throw std::invalid_argument("S3 gateway selected vault requires credential_id");
    if (vaultId == 0) throw std::invalid_argument("S3 gateway selected vault requires vault_id");

    return Transactions::exec("S3Gateway::upsertCredentialSelectedVault", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_credential_selected_vault
                    (credential_id, vault_id, enabled, created_by)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (credential_id, vault_id) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    created_by = COALESCE(EXCLUDED.created_by, s3_gateway_credential_selected_vault.created_by),
                    updated_at = CURRENT_TIMESTAMP
                RETURNING *
            )SQL",
            pqxx::params{credentialId, vaultId, enabled, createdBy});
        return selectedVaultFromRow(res.one_row_ref());
    });
}

bool Gateway::deleteCredentialSelectedVault(const uint32_t credentialId, const uint32_t vaultId) {
    return Transactions::exec("S3Gateway::deleteCredentialSelectedVault", [&](pqxx::work& txn) {
        return txn.exec(
            R"SQL(
                DELETE FROM s3_gateway_credential_selected_vault
                WHERE credential_id = $1
                  AND vault_id = $2
            )SQL",
            pqxx::params{credentialId, vaultId}).affected_rows() > 0;
    });
}

std::shared_ptr<::vh::rbac::role::Vault> Gateway::getEffectiveCredentialVaultRole(
    const uint32_t credentialId,
    const uint32_t vaultId,
    const std::string& scopeMode) {
    if (scopeMode == "user_access") return nullptr;

    return Transactions::exec("S3Gateway::getEffectiveCredentialVaultRole", [&](pqxx::work& txn) -> std::shared_ptr<::vh::rbac::role::Vault> {
        if (scopeMode == "vault_allowlist") {
            const auto selected = txn.exec(
                R"SQL(
                    SELECT 1
                    FROM s3_gateway_credential_selected_vault
                    WHERE credential_id = $1
                      AND vault_id = $2
                      AND enabled = TRUE
                )SQL",
                pqxx::params{credentialId, vaultId});
            if (selected.empty()) return nullptr;
        }

        const auto defaultRole = credentialDefaultRoleRow(txn, credentialId, vaultId);
        if (defaultRole.empty()) return nullptr;

        const auto defaultRoleId = defaultRole.one_row_ref()["assignment_id"].as<uint32_t>();
        const auto perVaultRole = credentialVaultRoleRow(txn, credentialId, vaultId);
        const auto usePerVaultRole = !perVaultRole.empty();
        const auto roleRow = usePerVaultRole ? perVaultRole.one_row_ref() : defaultRole.one_row_ref();

        auto overrides = ::vh::rbac::permission::permissionOverridesFromPqRes(
            credentialDefaultRoleOverrides(txn, defaultRoleId));
        if (usePerVaultRole) {
            const auto perVaultAssignmentId = perVaultRole.one_row_ref()["assignment_id"].as<uint32_t>();
            overrides = mergeDefaultAndPerVaultOverrides(
                std::move(overrides),
                ::vh::rbac::permission::permissionOverridesFromPqRes(
                    credentialRoleOverrides(txn, perVaultAssignmentId)));
        }

        auto role = std::make_shared<::vh::rbac::role::Vault>(roleRow);
        role->fs.overrides = std::move(overrides);
        return role;
    });
}

void Gateway::updateCredentialScopeMode(
    const uint32_t credentialId,
    const std::string& scopeMode,
    const uint32_t principalUserId,
    const std::optional<uint32_t> createdBy,
    const std::optional<std::string> description,
    const std::optional<std::time_t> expiresAt,
    const std::optional<bool> enforceBudgetForLocalRequests) {
    Transactions::exec("S3Gateway::updateCredentialScopeMode", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                UPDATE s3_gateway_credentials
                SET scope_mode = $2,
                    principal_user_id = $3,
                    user_id = $3,
                    created_by = $4,
                    description = $5,
                    expires_at = CASE WHEN $6::bigint IS NULL THEN NULL ELSE TO_TIMESTAMP($6::double precision) END,
                    enforce_budget_for_local_requests = COALESCE($7::boolean, enforce_budget_for_local_requests)
                WHERE id = $1
            )SQL",
            pqxx::params{credentialId, scopeMode, principalUserId, createdBy, description, expiresAt, enforceBudgetForLocalRequests});
    });
}

void Gateway::recordSyncOrigin(
    const uint32_t vaultId,
    const std::string& objectKey,
    const std::string& operation,
    const std::optional<uint32_t> gatewayCredentialId,
    const std::string& requestUuid) {
    Transactions::exec("S3Gateway::recordSyncOrigin", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_sync_origin
                    (vault_id, object_key, operation, gateway_credential_id, request_uuid)
                VALUES ($1, $2, $3, $4, $5)
            )SQL",
            pqxx::params{vaultId, normalizeKey(objectKey), operation, gatewayCredentialId, requestUuid});
    });
}

void Gateway::bindBucket(const BucketBinding& binding) {
    vh::vault::model::requireValidS3Name(binding.bucket_name);

    Transactions::exec("S3Gateway::bindBucket", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_bucket (vault_id, bucket_name, api_exclusive, mode, created_by)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (vault_id) DO UPDATE SET
                    bucket_name = EXCLUDED.bucket_name,
                    api_exclusive = EXCLUDED.api_exclusive,
                    mode = EXCLUDED.mode,
                    updated_at = NOW()
            )SQL",
            pqxx::params{
                binding.vault_id,
                binding.bucket_name,
                binding.api_exclusive,
                binding.mode,
                binding.created_by
            });
    });
}

bool Gateway::unbindBucket(const std::string& bucketName) {
    return Transactions::exec("S3Gateway::unbindBucket", [&](pqxx::work& txn) {
        return txn.exec(
            "DELETE FROM s3_gateway_bucket WHERE bucket_name = $1",
            pqxx::params{bucketName}).affected_rows() > 0;
    });
}

std::optional<BucketBinding> Gateway::resolveBucket(const std::string& bucketName) {
    return Transactions::exec("S3Gateway::resolveBucket", [&](pqxx::work& txn) -> std::optional<BucketBinding> {
        // A deleted vault's bucket is gone from the gateway at once (#162); the binding returns if the vault is restored.
        const auto res = txn.exec(
            "SELECT b.* FROM s3_gateway_bucket b JOIN vault v ON v.id = b.vault_id "
            "WHERE b.bucket_name = $1 AND v.deleted_at IS NULL", pqxx::params{bucketName});
        if (res.empty()) return std::nullopt;
        return bucketFromRow(res.one_row_ref());
    });
}

std::vector<BucketBinding> Gateway::listBuckets(const std::optional<uint32_t> userId) {
    return Transactions::exec("S3Gateway::listBuckets", [&](pqxx::work& txn) {
        const auto sql = userId
            ? "SELECT b.* FROM s3_gateway_bucket b JOIN vault v ON v.id = b.vault_id WHERE v.owner_id = " + txn.quote(*userId) +
                  " AND v.deleted_at IS NULL ORDER BY b.bucket_name"
            : "SELECT b.* FROM s3_gateway_bucket b JOIN vault v ON v.id = b.vault_id WHERE v.deleted_at IS NULL "
              "ORDER BY b.bucket_name";
        const auto res = txn.exec(sql);
        return db::mapRows(res, bucketFromRow);
    });
}

void Gateway::upsertObject(const ObjectState& state) {
    Transactions::exec("S3Gateway::upsertObject", [&](pqxx::work& txn) {
        const auto lastModified = state.last_modified == 0 ? std::time(nullptr) : state.last_modified;
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_object
                    (vault_id, object_key, etag, size_bytes, content_type, storage_class, last_modified, multipart, part_count)
                VALUES ($1, $2, $3, $4, $5, $6, TO_TIMESTAMP($7::double precision), $8, $9)
                ON CONFLICT (vault_id, object_key) DO UPDATE SET
                    etag = EXCLUDED.etag,
                    size_bytes = EXCLUDED.size_bytes,
                    content_type = EXCLUDED.content_type,
                    storage_class = EXCLUDED.storage_class,
                    last_modified = EXCLUDED.last_modified,
                    multipart = EXCLUDED.multipart,
                    part_count = EXCLUDED.part_count
            )SQL",
            pqxx::params{
                state.vault_id,
                normalizeKey(state.object_key),
                state.etag,
                state.size_bytes,
                state.content_type,
                state.storage_class,
                static_cast<long long>(lastModified),
                state.multipart,
                state.part_count
            });
    });
}

std::optional<ObjectState> Gateway::getObjectState(const uint32_t vaultId, const std::string& objectKey) {
    return Transactions::exec("S3Gateway::getObjectState", [&](pqxx::work& txn) -> std::optional<ObjectState> {
        const auto res = txn.exec(
            "SELECT * FROM s3_gateway_object "
            "WHERE vault_id = $1 AND object_key = $2 "
            "AND " + notHiddenByActiveTrashSql("s3_gateway_object.vault_id", "object_key"),
            pqxx::params{vaultId, normalizeKey(objectKey)});
        if (res.empty()) return std::nullopt;
        return objectFromRow(res.one_row_ref());
    });
}

void Gateway::deleteObjectState(const uint32_t vaultId, const std::string& objectKey) {
    Transactions::exec("S3Gateway::deleteObjectState", [&](pqxx::work& txn) {
        txn.exec(
            "DELETE FROM s3_gateway_object WHERE vault_id = $1 AND object_key = $2",
            pqxx::params{vaultId, normalizeKey(objectKey)});
    });
}

void Gateway::deleteObjectStateAndRemoteIndex(const uint32_t vaultId, const std::string& objectKey) {
    Transactions::exec("S3Gateway::deleteObjectStateAndRemoteIndex", [&](pqxx::work& txn) {
        const auto key = normalizeKey(objectKey);
        txn.exec(
            "DELETE FROM s3_gateway_object_metadata WHERE vault_id = $1 AND object_key = $2",
            pqxx::params{vaultId, key});
        txn.exec(
            "DELETE FROM s3_gateway_object WHERE vault_id = $1 AND object_key = $2",
            pqxx::params{vaultId, key});
        txn.exec(
            "DELETE FROM remote_object_index WHERE vault_id = $1 AND object_key = $2",
            pqxx::params{vaultId, key});
    });
}

ObjectListResult Gateway::listObjectStates(const uint32_t vaultId, const ObjectListParams& params) {
    return Transactions::exec("S3Gateway::listObjectStates", [&](pqxx::work& txn) {
        const auto prefix = normalizeKey(params.prefix);
        auto after = params.continuation_token.value_or(params.start_after.value_or(""));
        const uint32_t maxKeys = std::min(params.max_keys, 1000u);

        if (maxKeys == 0) return ObjectListResult{};

        if (params.delimiter && !params.delimiter->empty()) {
            const auto res = txn.exec(
                R"SQL(
                    WITH source AS (
                        SELECT
                            *,
                            SUBSTRING(object_key FROM CHAR_LENGTH($2) + 1) AS rest
                        FROM s3_gateway_object
                        WHERE vault_id = $1
                          AND LEFT(object_key, CHAR_LENGTH($2)) = $2
                          AND )SQL" + notHiddenByActiveTrashSql("s3_gateway_object.vault_id", "object_key") + R"SQL(
                    ),
                    items AS (
                        SELECT DISTINCT
                            ($2 || SUBSTRING(rest FROM 1 FOR STRPOS(rest, $3) + CHAR_LENGTH($3) - 1)) AS item_key,
                            TRUE AS common_prefix,
                            vault_id,
                            NULL::TEXT AS object_key,
                            NULL::TEXT AS etag,
                            NULL::BIGINT AS size_bytes,
                            NULL::TEXT AS content_type,
                            NULL::TEXT AS storage_class,
                            NULL::TIMESTAMPTZ AS last_modified,
                            NULL::BOOLEAN AS multipart,
                            NULL::INTEGER AS part_count
                        FROM source
                        WHERE STRPOS(rest, $3) > 0

                        UNION ALL

                        SELECT
                            object_key AS item_key,
                            FALSE AS common_prefix,
                            vault_id,
                            object_key,
                            etag,
                            size_bytes,
                            content_type,
                            storage_class,
                            last_modified,
                            multipart,
                            part_count
                        FROM source
                        WHERE STRPOS(rest, $3) = 0
                    )
                    SELECT *
                    FROM items
                    WHERE item_key > $4
                    ORDER BY item_key
                    LIMIT $5
                )SQL",
                pqxx::params{vaultId, prefix, *params.delimiter, after, maxKeys + 1});

            ObjectListResult out;
            uint32_t emitted = 0;
            std::optional<std::string> lastEmittedItemKey;
            for (const auto& row : res) {
                if (emitted >= maxKeys) {
                    out.is_truncated = true;
                    out.next_continuation_token = lastEmittedItemKey;
                    break;
                }

                if (row["common_prefix"].as<bool>()) {
                    out.common_prefixes.push_back(row["item_key"].as<std::string>());
                } else {
                    out.objects.push_back(objectFromRow(row));
                }
                lastEmittedItemKey = row["item_key"].as<std::string>();
                ++emitted;
            }
            return out;
        }

        const auto res = txn.exec(
                R"SQL(
                SELECT * FROM s3_gateway_object
                WHERE vault_id = $1
                  AND LEFT(object_key, CHAR_LENGTH($2)) = $2
                  AND object_key > $3
                  AND )SQL" + notHiddenByActiveTrashSql("s3_gateway_object.vault_id", "object_key") + R"SQL(
                ORDER BY object_key
                LIMIT $4
            )SQL",
            pqxx::params{vaultId, prefix, after, maxKeys + 1});

        ObjectListResult out;
        uint32_t emitted = 0;
        std::optional<std::string> lastEmittedObjectKey;

        for (const auto& row : res) {
            if (emitted >= maxKeys) {
                out.is_truncated = true;
                out.next_continuation_token = lastEmittedObjectKey;
                break;
            }

            auto object = objectFromRow(row);
            lastEmittedObjectKey = object.object_key;
            out.objects.push_back(std::move(object));
            ++emitted;
        }

        return out;
    });
}

void Gateway::upsertObjectMetadata(
    const uint32_t vaultId,
    const std::string& objectKey,
    const std::map<std::string, std::string>& metadata) {
    Transactions::exec("S3Gateway::upsertObjectMetadata", [&](pqxx::work& txn) {
        const auto key = normalizeKey(objectKey);
        txn.exec("DELETE FROM s3_gateway_object_metadata WHERE vault_id = $1 AND object_key = $2", pqxx::params{vaultId, key});
        for (const auto& [name, value] : metadata)
            txn.exec(
                R"SQL(
                    INSERT INTO s3_gateway_object_metadata (vault_id, object_key, name, value)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (vault_id, object_key, name) DO UPDATE SET value = EXCLUDED.value
                )SQL",
                pqxx::params{vaultId, key, name, value});
    });
}

std::map<std::string, std::string> Gateway::listObjectMetadata(const uint32_t vaultId, const std::string& objectKey) {
    return Transactions::exec("S3Gateway::listObjectMetadata", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT name, value FROM s3_gateway_object_metadata WHERE vault_id = $1 AND object_key = $2 ORDER BY name",
            pqxx::params{vaultId, normalizeKey(objectKey)});
        std::map<std::string, std::string> out;
        for (const auto& row : res) out[row["name"].as<std::string>()] = row["value"].as<std::string>();
        return out;
    });
}

void Gateway::deleteObjectMetadata(const uint32_t vaultId, const std::string& objectKey) {
    Transactions::exec("S3Gateway::deleteObjectMetadata", [&](pqxx::work& txn) {
        txn.exec(
            "DELETE FROM s3_gateway_object_metadata WHERE vault_id = $1 AND object_key = $2",
            pqxx::params{vaultId, normalizeKey(objectKey)});
    });
}

void Gateway::createMultipartUpload(const MultipartUpload& upload) {
    Transactions::exec("S3Gateway::createMultipartUpload", [&](pqxx::work& txn) {
        const auto partsDirId = upload.parts_dir_id.empty() ? upload.upload_id : upload.parts_dir_id;
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_multipart_upload
                    (upload_id, parts_dir_id, vault_id, object_key, initiated_by, content_type, metadata, storage_class)
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
            )SQL",
            pqxx::params{
                upload.upload_id,
                partsDirId,
                upload.vault_id,
                normalizeKey(upload.object_key),
                upload.initiated_by,
                upload.content_type,
                makeMetadataJson(upload.metadata),
                upload.storage_class
            });
    });
}

std::optional<MultipartUpload> Gateway::getMultipartUpload(const std::string& uploadId) {
    return Transactions::exec("S3Gateway::getMultipartUpload", [&](pqxx::work& txn) -> std::optional<MultipartUpload> {
        const auto res = txn.exec(
            "SELECT * FROM s3_gateway_multipart_upload WHERE upload_id = $1 AND aborted = FALSE AND completed = FALSE",
            pqxx::params{uploadId});
        if (res.empty()) return std::nullopt;
        return uploadFromRow(res.one_row_ref());
    });
}

std::vector<MultipartUpload> Gateway::listMultipartUploads(const uint32_t vaultId, const std::string& prefix) {
    return Transactions::exec("S3Gateway::listMultipartUploads", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                SELECT * FROM s3_gateway_multipart_upload
                WHERE vault_id = $1 AND LEFT(object_key, CHAR_LENGTH($2)) = $2 AND aborted = FALSE AND completed = FALSE
                ORDER BY object_key, initiated_at
            )SQL",
            pqxx::params{vaultId, normalizeKey(prefix)});
        return db::mapRows(res, uploadFromRow);
    });
}

std::vector<MultipartUpload> Gateway::listMultipartUploadsInitiatedBefore(const std::time_t cutoff) {
    return Transactions::exec("S3Gateway::listMultipartUploadsInitiatedBefore", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                SELECT * FROM s3_gateway_multipart_upload
                WHERE initiated_at < TO_TIMESTAMP($1::double precision)
                  AND aborted = FALSE
                  AND completed = FALSE
                ORDER BY initiated_at
            )SQL",
            pqxx::params{cutoff});
        return db::mapRows(res, uploadFromRow);
    });
}

std::vector<MultipartUpload> Gateway::listOpenMultipartUploads() {
    return Transactions::exec("S3Gateway::listOpenMultipartUploads", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT * FROM s3_gateway_multipart_upload WHERE aborted = FALSE AND completed = FALSE ORDER BY initiated_at");
        return db::mapRows(res, uploadFromRow);
    });
}

void Gateway::markMultipartUploadCompleted(const std::string& uploadId) {
    Transactions::exec("S3Gateway::markMultipartUploadCompleted", [&](pqxx::work& txn) {
        txn.exec("UPDATE s3_gateway_multipart_upload SET completed = TRUE WHERE upload_id = $1", pqxx::params{uploadId});
    });
}

void Gateway::abortMultipartUpload(const std::string& uploadId) {
    Transactions::exec("S3Gateway::abortMultipartUpload", [&](pqxx::work& txn) {
        txn.exec("UPDATE s3_gateway_multipart_upload SET aborted = TRUE WHERE upload_id = $1", pqxx::params{uploadId});
    });
}

std::optional<std::filesystem::path> Gateway::upsertMultipartPart(const MultipartPart& part) {
    return Transactions::exec("S3Gateway::upsertMultipartPart", [&](pqxx::work& txn) -> std::optional<std::filesystem::path> {
        const auto previous = txn.exec(
            "SELECT path FROM s3_gateway_multipart_part WHERE upload_id = $1 AND part_number = $2 FOR UPDATE",
            pqxx::params{part.upload_id, part.part_number});
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_multipart_part
                    (upload_id, part_number, etag, size_bytes, md5, path, encryption_iv, key_version)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (upload_id, part_number) DO UPDATE SET
                    etag = EXCLUDED.etag,
                    size_bytes = EXCLUDED.size_bytes,
                    md5 = EXCLUDED.md5,
                    path = EXCLUDED.path,
                    encryption_iv = EXCLUDED.encryption_iv,
                    key_version = EXCLUDED.key_version,
                    created_at = NOW()
            )SQL",
            pqxx::params{
                part.upload_id,
                part.part_number,
                part.etag,
                part.size_bytes,
                to_hex_bytea(part.md5),
                part.path.string(),
                part.encryption_iv,
                part.key_version
            });
        if (previous.empty()) return std::nullopt;
        return std::filesystem::path(previous.one_row_ref()["path"].as<std::string>());
    });
}

bool Gateway::sealLegacyMultipartPart(const std::string& uploadId, const uint32_t partNumber,
                                      const std::filesystem::path& plaintextPath,
                                      const std::filesystem::path& sealedPath, const std::string& encryptionIv,
                                      const uint32_t keyVersion) {
    return Transactions::exec("S3Gateway::sealLegacyMultipartPart", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            R"SQL(
                UPDATE s3_gateway_multipart_part
                SET path = $4, encryption_iv = $5, key_version = $6
                WHERE upload_id = $1 AND part_number = $2 AND path = $3 AND encryption_iv IS NULL
            )SQL",
            pqxx::params{uploadId, partNumber, plaintextPath.string(), sealedPath.string(), encryptionIv, keyVersion});
        return res.affected_rows() == 1;
    });
}

std::vector<MultipartPart> Gateway::listMultipartParts(const std::string& uploadId) {
    return Transactions::exec("S3Gateway::listMultipartParts", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT * FROM s3_gateway_multipart_part WHERE upload_id = $1 ORDER BY part_number",
            pqxx::params{uploadId});
        return db::mapRows(res, partFromRow);
    });
}

std::optional<MultipartPart> Gateway::getMultipartPart(const std::string& uploadId, const uint32_t partNumber) {
    return Transactions::exec("S3Gateway::getMultipartPart", [&](pqxx::work& txn) -> std::optional<MultipartPart> {
        const auto res = txn.exec(
            "SELECT * FROM s3_gateway_multipart_part WHERE upload_id = $1 AND part_number = $2",
            pqxx::params{uploadId, partNumber});
        if (res.empty()) return std::nullopt;
        return partFromRow(res.one_row_ref());
    });
}

void Gateway::deleteMultipartParts(const std::string& uploadId) {
    Transactions::exec("S3Gateway::deleteMultipartParts", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM s3_gateway_multipart_part WHERE upload_id = $1", pqxx::params{uploadId});
    });
}

void Gateway::backfillObjectStateFromFs(const uint32_t vaultId) {
    Transactions::exec("S3Gateway::backfillObjectStateFromFs", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_object (vault_id, object_key, etag, size_bytes, content_type, last_modified)
                SELECT
                    e.vault_id,
                    ltrim(e.path, '/') AS object_key,
                    ('"vh-meta-' || md5(e.vault_id::text || ':' || e.path || ':' || f.size_bytes::text || ':' || e.updated_at::text || ':' || COALESCE(f.content_hash, '')) || '"') AS etag,
                    f.size_bytes,
                    f.mime_type,
                    e.updated_at
                FROM fs_entry e
                JOIN files f ON f.fs_entry_id = e.id
                WHERE e.vault_id = $1
                  AND e.path <> '/'
                  AND NOT EXISTS (
                      SELECT 1 FROM s3_gateway_object o
                      WHERE o.vault_id = e.vault_id AND o.object_key = ltrim(e.path, '/')
                  )
            )SQL",
            pqxx::params{vaultId});
    });
}

void Gateway::backfillObjectStateFromRemoteIndex(const uint32_t vaultId) {
    Transactions::exec("S3Gateway::backfillObjectStateFromRemoteIndex", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_object (vault_id, object_key, etag, size_bytes, storage_class, last_modified)
                SELECT vault_id,
                       object_key,
                       COALESCE(etag, '""'),
                       size_bytes,
                       storage_class,
                       COALESCE(last_modified, indexed_at, CURRENT_TIMESTAMP)
                FROM remote_object_index
                WHERE vault_id = $1
                  AND )SQL" + notHiddenByActiveTrashSql("remote_object_index.vault_id", "object_key") + R"SQL(
                ON CONFLICT (vault_id, object_key) DO NOTHING
            )SQL",
            pqxx::params{vaultId});
    });
}

} // namespace vh::db::query::s3
