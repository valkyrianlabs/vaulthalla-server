#include "db/query/identities/Loader.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/timestamp.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace vh::db::query::identities {

namespace {

using vh::db::encoding::parsePostgresTimestamp;

// An INTEGER[] literal for = ANY($n::INTEGER[]); nullopt (SQL NULL) selects everything.
std::optional<std::string> intArray(const bool all, const std::vector<uint32_t>& ids) {
    if (all) return std::nullopt;
    std::string out = "{";
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (i) out += ',';
        out += std::to_string(ids[i]);
    }
    return out + "}";
}

template <typename T>
std::optional<T> opt(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

std::optional<std::time_t> optTime(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return parsePostgresTimestamp(f.as<std::string>());
}

void sortUnique(std::vector<uint32_t>& v) {
    std::ranges::sort(v);
    v.erase(std::unique(v.begin(), v.end()), v.end());
}

constexpr auto kUserColumns =
    "SELECT id, linux_uid, name, email, created_at, last_login, last_modified_by, updated_at, is_active, "
    "protected, system_only, password_changed_at FROM users";

constexpr auto kAdminRoles = R"SQL(
    SELECT
        ara.id                            AS assignment_id,
        ara.user_id                       AS user_id,
        ara.role_id                       AS role_id,
        ara.assigned_at                   AS assigned_at,
        ar.id                             AS admin_role_id,
        ar.name                           AS role_name,
        ar.description                    AS role_description,
        ar.created_at                     AS role_created_at,
        ar.updated_at                     AS role_updated_at,
        ar.identity_permissions::bigint   AS identity_permissions,
        ar.audit_permissions::bigint      AS audit_permissions,
        ar.settings_permissions::bigint   AS settings_permissions,
        ar.roles_permissions::bigint      AS roles_permissions,
        ar.vaults_permissions::bigint     AS vaults_permissions,
        ar.keys_permissions::bigint       AS keys_permissions,
        ar.s3_gateway_permissions::bigint AS s3_gateway_permissions,
        ar.stats_permissions::bigint      AS stats_permissions
    FROM admin_role_assignments ara
    INNER JOIN admin_role ar ON ar.id = ara.role_id
    WHERE ara.user_id = ANY($1::INTEGER[])
)SQL";

constexpr auto kGlobalPolicies = R"SQL(
    SELECT
        user_id,
        template_role_id,
        enforce_template,
        scope::text                      AS scope,
        created_at,
        updated_at,
        files_permissions::bigint        AS files_permissions,
        directories_permissions::bigint  AS directories_permissions,
        sync_permissions::bigint         AS sync_permissions,
        roles_permissions::bigint        AS roles_permissions
    FROM user_global_vault_policy
    WHERE user_id = ANY($1::INTEGER[])
    ORDER BY user_id, scope
)SQL";

constexpr auto kVaultRoles = R"SQL(
    SELECT
        vra.id                             AS assignment_id,
        vra.vault_id                       AS vault_id,
        vra.subject_type                   AS subject_type,
        vra.subject_id                     AS subject_id,
        vra.role_id                        AS vault_role_id,
        vra.assigned_at                    AS assigned_at,
        vr.name                            AS role_name,
        vr.description                     AS role_description,
        vr.created_at                      AS role_created_at,
        vr.updated_at                      AS role_updated_at,
        vr.files_permissions::bigint       AS files_permissions,
        vr.directories_permissions::bigint AS directories_permissions,
        vr.sync_permissions::bigint        AS sync_permissions,
        vr.roles_permissions::bigint       AS roles_permissions
    FROM vault_role_assignments vra
    INNER JOIN vault_role vr ON vr.id = vra.role_id
    WHERE (vra.subject_type = 'user' AND vra.subject_id = ANY($1::INTEGER[]))
       OR (vra.subject_type = 'group' AND vra.subject_id = ANY($2::INTEGER[]))
    ORDER BY vra.vault_id
)SQL";

constexpr auto kOverrides = R"SQL(
    SELECT
        vpo.id AS override_id,
        vpo.assignment_id,
        vpo.permission_id,
        vpo.glob_path,
        vpo.enabled,
        vpo.effect,
        vpo.created_at,
        vpo.updated_at,
        p.id AS permission_id,
        p.name,
        p.description,
        p.category,
        p.bit_position
    FROM vault_permission_overrides vpo
    INNER JOIN permission p ON p.id = vpo.permission_id
    WHERE vpo.assignment_id = ANY($1::INTEGER[])
    ORDER BY vpo.assignment_id, p.bit_position, vpo.glob_path
)SQL";

constexpr auto kGroupColumns = "SELECT id, linux_gid, name, description, created_at, updated_at FROM groups";

// The current revision, or 0 on a database without migration 108.
uint64_t readRevision(pqxx::work& txn) {
    const auto exists = txn.exec("SELECT to_regclass('public.identity_revision') IS NOT NULL").one_field().as<bool>();
    if (!exists) return 0;
    const auto res = txn.exec("SELECT rev FROM identity_revision WHERE id = 1");
    return res.empty() ? 0 : res.one_field().as<uint64_t>();
}

}

IdentitySnapshot Loader::load(const IdentitySelection& sel) {
    return Transactions::exec("identities::Loader::load", [&](pqxx::work& txn) {
        txn.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
        IdentitySnapshot snap;
        snap.revision = readRevision(txn);

        std::vector<uint32_t> userIds = sel.userIds;
        std::vector<uint32_t> groupIds = sel.groupIds;
        if (!sel.all) {
            if (sel.userName)
                for (const auto& row : txn.exec("SELECT id FROM users WHERE name = $1", pqxx::params{*sel.userName}))
                    userIds.push_back(row[0].as<uint32_t>());
            if (sel.linuxUid)
                for (const auto& row : txn.exec("SELECT id FROM users WHERE linux_uid = $1", pqxx::params{*sel.linuxUid}))
                    userIds.push_back(row[0].as<uint32_t>());
            if (sel.groupName)
                for (const auto& row : txn.exec("SELECT id FROM groups WHERE name = $1", pqxx::params{*sel.groupName}))
                    groupIds.push_back(row[0].as<uint32_t>());
            if (sel.linuxGid)
                for (const auto& row : txn.exec("SELECT id FROM groups WHERE linux_gid = $1", pqxx::params{*sel.linuxGid}))
                    groupIds.push_back(row[0].as<uint32_t>());
            sortUnique(userIds);
            sortUnique(groupIds);
            snap.requestedUserIds = userIds;
            snap.requestedGroupIds = groupIds;
            if (userIds.empty() && groupIds.empty()) return snap;
        }

        // Users.
        std::unordered_map<uint32_t, std::size_t> userAt;
        if (sel.all || !userIds.empty()) {
            const auto res = sel.all ? txn.exec(std::string(kUserColumns) + " ORDER BY id")
                                     : txn.exec(std::string(kUserColumns) + " WHERE id = ANY($1::INTEGER[]) ORDER BY id",
                                                pqxx::params{intArray(false, userIds)});
            for (const auto& row : res) {
                UserRecord rec;
                rec.id = row["id"].as<uint32_t>();
                rec.state = vh::identities::stateFromRow(row);
                userAt[rec.id] = snap.users.size();
                snap.users.push_back(std::move(rec));
            }
        }
        std::vector<uint32_t> loadedUsers;
        loadedUsers.reserve(snap.users.size());
        for (const auto& u : snap.users) loadedUsers.push_back(u.id);
        if (sel.all) snap.requestedUserIds = loadedUsers;
        const auto userArray = intArray(false, loadedUsers);

        // Memberships of the loaded users; their groups are loaded too, so every membership resolves.
        if (!loadedUsers.empty()) {
            for (const auto& row : txn.exec("SELECT user_id, group_id, joined_at FROM group_members "
                                            "WHERE user_id = ANY($1::INTEGER[]) ORDER BY group_id",
                                            pqxx::params{userArray})) {
                const auto uid = row["user_id"].as<uint32_t>();
                const auto gid = row["group_id"].as<uint32_t>();
                const auto joined = optTime(row["joined_at"]).value_or(0);
                snap.users[userAt.at(uid)].memberships.emplace_back(gid, joined);
                snap.users[userAt.at(uid)].state.joinedAt[gid] = joined;
                groupIds.push_back(gid);
            }
        }
        sortUnique(groupIds);

        // Groups.
        std::unordered_map<uint32_t, std::size_t> groupAt;
        if (sel.all || !groupIds.empty()) {
            const auto res = sel.all ? txn.exec(std::string(kGroupColumns) + " ORDER BY id")
                                     : txn.exec(std::string(kGroupColumns) + " WHERE id = ANY($1::INTEGER[]) ORDER BY id",
                                                pqxx::params{intArray(false, groupIds)});
            for (const auto& row : res) {
                GroupRecord rec;
                rec.id = row["id"].as<uint32_t>();
                rec.state = vh::identities::groupStateFromRow(row);
                groupAt[rec.id] = snap.groups.size();
                snap.groups.push_back(std::move(rec));
            }
        }
        std::vector<uint32_t> loadedGroups;
        for (const auto& g : snap.groups) loadedGroups.push_back(g.id);
        if (sel.all) snap.requestedGroupIds = loadedGroups;
        const auto groupArray = intArray(false, loadedGroups);

        // Admin role assignments + global vault policies.
        if (!loadedUsers.empty()) {
            std::unordered_map<uint32_t, std::shared_ptr<rbac::role::Admin>> admins;
            for (const auto& row : txn.exec(kAdminRoles, pqxx::params{userArray})) {
                auto role = std::make_shared<rbac::role::Admin>(row);
                role->user_id = row["user_id"].as<uint32_t>();
                admins[*role->user_id] = std::move(role);
            }
            for (const auto& row : txn.exec(kGlobalPolicies, pqxx::params{userArray})) {
                const auto it = admins.find(row["user_id"].as<uint32_t>());
                if (it == admins.end()) continue;
                it->second->vGlobals.assign(row);
            }
            for (auto& [uid, role] : admins)
                if (const auto at = userAt.find(uid); at != userAt.end())
                    snap.users[at->second].state.roles.admin = std::move(role);
        }

        // Vault role assignments (users and groups) and their overrides.
        if (!loadedUsers.empty() || !loadedGroups.empty()) {
            std::unordered_map<uint32_t, std::shared_ptr<rbac::role::Vault>> byAssignment;
            std::vector<std::tuple<std::string, uint32_t, uint32_t, std::shared_ptr<rbac::role::Vault>>> assigned;
            for (const auto& row : txn.exec(kVaultRoles, pqxx::params{userArray, groupArray})) {
                auto role = std::make_shared<rbac::role::Vault>(row);
                role->assignment_id = row["assignment_id"].as<uint32_t>();
                byAssignment[role->assignment_id] = role;
                assigned.emplace_back(row["subject_type"].as<std::string>(), row["subject_id"].as<uint32_t>(),
                                      row["vault_id"].as<uint32_t>(), role);
            }
            if (!byAssignment.empty()) {
                std::vector<uint32_t> assignmentIds;
                assignmentIds.reserve(byAssignment.size());
                for (const auto& [id, _] : byAssignment) assignmentIds.push_back(id);
                for (const auto& row : txn.exec(kOverrides, pqxx::params{intArray(false, assignmentIds)}))
                    if (const auto it = byAssignment.find(row["assignment_id"].as<uint32_t>()); it != byAssignment.end())
                        it->second->fs.overrides.emplace_back(row);
            }
            for (auto& [type, subject, vaultId, role] : assigned) {
                if (type == "user") {
                    if (const auto at = userAt.find(subject); at != userAt.end())
                        snap.users[at->second].state.roles.vaults[vaultId] = std::move(role);
                } else if (const auto at = groupAt.find(subject); at != groupAt.end()) {
                    snap.groups[at->second].state.roles.vaults[vaultId] = std::move(role);
                }
            }
        }

        for (auto& u : snap.users) u.state.revision = snap.revision;
        for (auto& g : snap.groups) g.state.revision = snap.revision;
        return snap;
    });
}

uint64_t Loader::currentRevision() {
    return Transactions::exec("identities::Loader::currentRevision", [](pqxx::work& txn) { return readRevision(txn); });
}

std::optional<std::vector<IdentityChange>> Loader::changesSince(const uint64_t since, uint64_t& upTo) {
    return Transactions::exec("identities::Loader::changesSince",
                              [&](pqxx::work& txn) -> std::optional<std::vector<IdentityChange>> {
        txn.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
        upTo = readRevision(txn);
        std::vector<IdentityChange> out;
        if (upTo <= since) return out;
        // The log must still hold the revision right after `since` (it is pruned by age).
        const auto oldest = txn.exec("SELECT min(rev) FROM identity_change_log").one_field();
        if (oldest.is_null() || oldest.as<uint64_t>() > since + 1) return std::nullopt;
        for (const auto& row : txn.exec("SELECT entity, entity_id, max(rev) AS rev FROM identity_change_log "
                                        "WHERE rev > $1 AND rev <= $2 GROUP BY entity, entity_id",
                                        pqxx::params{static_cast<int64_t>(since), static_cast<int64_t>(upTo)}))
            out.push_back({row["entity"].as<std::string>(), row["entity_id"].as<uint32_t>(), row["rev"].as<uint64_t>()});
        return out;
    });
}

void Loader::pruneChangeLog(const std::chrono::seconds olderThan) {
    Transactions::exec("identities::Loader::pruneChangeLog", [&](pqxx::work& txn) {
        // Keep the newest entry so the log always reaches the current revision.
        txn.exec("DELETE FROM identity_change_log WHERE changed_at < NOW() - ($1::bigint * INTERVAL '1 second') "
                 "AND rev < (SELECT rev FROM identity_revision WHERE id = 1)",
                 pqxx::params{static_cast<int64_t>(olderThan.count())});
    });
}

namespace {
std::optional<Credentials> credentials(pqxx::work& txn, const pqxx::result& res) {
    (void)txn;
    if (res.empty()) return std::nullopt;
    const auto row = res.one_row();
    Credentials c;
    c.id = row["id"].as<uint32_t>();
    c.passwordHash = row["password_hash"].as<std::string>();
    c.active = opt<bool>(row["is_active"]).value_or(true);
    c.systemOnly = opt<bool>(row["system_only"]).value_or(false);
    return c;
}
}

std::optional<Credentials> Loader::credentialsByName(const std::string& name) {
    return Transactions::exec("identities::Loader::credentialsByName", [&](pqxx::work& txn) {
        return credentials(txn, txn.exec("SELECT id, password_hash, is_active, system_only FROM users WHERE name = $1",
                                         pqxx::params{name}));
    });
}

std::optional<Credentials> Loader::credentialsById(const uint32_t id) {
    return Transactions::exec("identities::Loader::credentialsById", [&](pqxx::work& txn) {
        return credentials(txn, txn.exec("SELECT id, password_hash, is_active, system_only FROM users WHERE id = $1",
                                         pqxx::params{id}));
    });
}

}
