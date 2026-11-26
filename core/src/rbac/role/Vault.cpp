#include "rbac/role/Vault.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/has.hpp"
#include "rbac/resolver/permission/all.hpp"

#include <pqxx/result>
#include <nlohmann/json.hpp>
#include <ostream>

using namespace vh::db::encoding;

namespace vh::rbac::role {
    Vault::Vault(pqxx::row_ref row)
        : Meta(row),
          Base(row),
          assignment(std::nullopt) {
        if (hasColumn(row, "assignment_id") && !row["assignment_id"].is_null()) {
            assignment = AssignmentInfo();
            if (const auto id = try_get<uint32_t>(row, "subject_id")) assignment->subject_id = *id;
            if (const auto type = try_get<std::string>(row, "subject_type")) assignment->subject_type = *type;
            if (const auto vId = try_get<uint32_t>(row, "vault_id")) assignment->vault_id = *vId;
        }
    }

    Vault::Vault(pqxx::row_ref row, const pqxx::result &overrides)
        : Meta(row),
          Base(row, overrides),
          assignment(std::nullopt) {
        if (hasColumn(row, "assignment_id") && !row["assignment_id"].is_null()) {
            assignment = AssignmentInfo();
            if (const auto id = try_get<uint32_t>(row, "subject_id")) assignment->subject_id = *id;
            if (const auto type = try_get<std::string>(row, "subject_type")) assignment->subject_type = *type;
            if (const auto vId = try_get<uint32_t>(row, "vault_id")) assignment->vault_id = *vId;
        }
    }

    Vault::Vault(const nlohmann::json &j)
        : Meta(j),
          Base(j),
          assignment(std::nullopt) {
        if (j.contains("assignment") && !j["assignment"].is_null()) {
            assignment = AssignmentInfo();
            if (j["assignment"].contains("subject_id") && !j["assignment"]["subject_id"].is_null())
                assignment->subject_id = j["assignment"]["subject_id"].get<uint32_t>();
            if (j["assignment"].contains("vault_id") && !j["assignment"]["vault_id"].is_null())
                assignment->vault_id = j["assignment"]["vault_id"].get<uint32_t>();
            if (j["assignment"].contains("subject_type") && !j["assignment"]["subject_type"].is_null())
                assignment->subject_type = j["assignment"]["subject_type"].get<std::string>();
        }

        if (!j.contains("permissions") || !j["permissions"].is_array()) return;

        std::unordered_map<std::string, bool> pMap;
        for (const auto& p : j["permissions"])
            pMap.emplace(p.at("qualified").get<std::string>(), p.at("value").get<bool>());

        using PermResolver = resolver::PermissionResolverEnumPack<std::shared_ptr<Vault>>::type;
        // shared_from_this() throws bad_weak_ptr inside a constructor (no owner exists yet). A non-owning
        // aliasing pointer is enough for the resolver, which only mutates *this for the duration of the call.
        std::shared_ptr<Vault> self(std::shared_ptr<Vault>{}, this);
        PermResolver::applySnapshot(self, toPermissions(), pMap);
    }

    void Vault::updateFromJson(const nlohmann::json &j) {
        Meta::updateFromJson(j);

        if (j.contains("assignment") && !j["assignment"].is_null()) {
            assignment = AssignmentInfo();
            if (j["assignment"].contains("subject_id") && !j["assignment"]["subject_id"].is_null())
                assignment->subject_id = j["assignment"]["subject_id"].get<uint32_t>();
            if (j["assignment"].contains("vault_id") && !j["assignment"]["vault_id"].is_null())
                assignment->vault_id = j["assignment"]["vault_id"].get<uint32_t>();
            if (j["assignment"].contains("subject_type") && !j["assignment"]["subject_type"].is_null())
                assignment->subject_type = j["assignment"]["subject_type"].get<std::string>();
        }

        if (!j.contains("permissions") || !j["permissions"].is_array()) return;

        std::unordered_map<std::string, bool> pMap;
        for (const auto& p : j["permissions"])
            pMap.emplace(p.at("qualified").get<std::string>(), p.at("value").get<bool>());

        using PermResolver = resolver::PermissionResolverEnumPack<std::shared_ptr<Vault>>::type;
        auto self = shared_from_this();
        PermResolver::applySnapshot(self, toPermissions(), pMap);
    }

    std::vector<std::string> Vault::getFlags() const {
        auto rolesFlags = roles.getFlags();
        auto syncFlags = sync.getFlags();
        auto filesFlags = fs.files.getFlags();
        auto dirsFlags = fs.directories.getFlags();

        std::vector<std::string> flags;
        flags.reserve(rolesFlags.size() + syncFlags.size() + filesFlags.size() + dirsFlags.size());

        auto append = [&](auto &src) { std::move(src.begin(), src.end(), std::back_inserter(flags)); };

        append(rolesFlags);
        append(syncFlags);
        append(filesFlags);
        append(dirsFlags);

        return flags;
    }

    std::string Vault::usage() {
        return formatPermissionTable(
            ImplicitDeny().getFlags(),
            "Vault Permissions Flags:",
            "Use --allow-* or --deny-* to modify permissions individually,\n"
            "or use the shorthand (e.g. --share) to enable directly."
        );
    }

    std::vector<permission::Permission> Vault::toPermissions() const {
        auto rolesPerms = roles.exportPermissions();
        auto syncPerms = sync.exportPermissions();
        auto filesPerms = fs.files.exportPermissions();
        auto dirsPerms = fs.directories.exportPermissions();

        std::vector<permission::Permission> perms;
        perms.reserve(rolesPerms.size() + syncPerms.size() + filesPerms.size() + dirsPerms.size());

        auto appendMoved = [&](auto &exportResult) {
            auto &src = exportResult();
            std::move(src.begin(), src.end(), std::back_inserter(perms));
        };

        appendMoved(rolesPerms);
        appendMoved(syncPerms);
        appendMoved(filesPerms);
        appendMoved(dirsPerms);

        return perms;
    }

    Vault Vault::fromJson(const nlohmann::json &j) { return Vault(j); }

    std::string Vault::AssignmentInfo::toString(const uint8_t indent) const {
        std::ostringstream oss;
        oss << std::string(indent, ' ') << "Assignment Info:\n";
        const std::string in(indent + 2, ' ');
        oss << in << "Subject ID: " << subject_id << "\n";
        oss << in << "Vault ID: " << vault_id << "\n";
        oss << in << "Subject Type: " << subject_type << "\n";
        return oss.str();
    }

    std::string Vault::toString(const uint8_t indent) const {
        std::ostringstream oss;
        oss << std::string(indent, ' ') << "Vault Role:\n";
        const std::string in(indent + 2, ' ');
        if (assignment) oss << in << assignment->toString(indent);
        oss << Meta::toString(indent);
        oss << Base::toString(indent);
        return oss.str();
    }

    void to_json(nlohmann::json &j, const Vault::AssignmentInfo &r) {
        j = {
            {"subject_id", std::to_string(r.subject_id)},
            {"vault_id", std::to_string(r.vault_id)},
            {"subject_type", r.subject_type}
        };
        if (r.subject_name) j["subject_name"] = *r.subject_name;
        if (r.subject_node_id) j["subject_node_id"] = *r.subject_node_id;
        if (r.subject_revoked) j["subject_revoked"] = *r.subject_revoked;
        if (r.in_effect) j["in_effect"] = *r.in_effect;
        if (r.editable) j["editable"] = *r.editable;
        if (r.owned_by)
            j["owned_by"] = {{"peer_id", r.owned_by->peer_id}, {"node_id", r.owned_by->node_id},
                             {"name", r.owned_by->name}};
    }

    void from_json(const nlohmann::json &j, Vault::AssignmentInfo &r) {
        if (j.contains("subject_id") && !j["subject_id"].is_null()) r.subject_id = j["subject_id"].get<uint32_t>();
        if (j.contains("vault_id") && !j["vault_id"].is_null()) r.vault_id = j["vault_id"].get<uint32_t>();
        if (j.contains("subject_type") && !j["subject_type"].is_null())
            r.subject_type = j["subject_type"].get<std::string>();
    }

    void to_json(nlohmann::json &j, const std::vector<Vault> &roles) {
        j = nlohmann::json::array();
        for (const auto &role: roles) j.emplace_back(role);
    }

    void to_json(nlohmann::json &j, const std::vector<std::shared_ptr<Vault> > &roles) {
        j = nlohmann::json::array();
        for (const auto &role: roles) j.emplace_back(*role);
    }

    void to_json(nlohmann::json &j, const Vault &r) {
        j = static_cast<const Meta &>(r);
        j["permissions"] = r.toPermissions();

        if (r.assignment) j["assignment"] = *r.assignment;
    }

    void from_json(const nlohmann::json &j, Vault &r) { r = Vault(j); }

    std::unordered_map<uint32_t, std::shared_ptr<Vault> > vault_roles_from_pq_result(
        const pqxx::result &res, const pqxx::result &overrides) {
        std::unordered_map<uint32_t, std::shared_ptr<Vault> > roles;
        for (const auto &row: res) {
            const auto role = std::make_shared<Vault>(row, overrides);
            roles[role->id] = role;
        }
        return roles;
    }

    std::vector<Vault> vault_roles_from_json(const nlohmann::json &j) {
        std::vector<Vault> roles;
        if (j.is_array()) for (const auto &item: j) roles.emplace_back(item);
        else if (j.is_object()) roles.emplace_back(j);
        return roles;
    }

    void to_json(nlohmann::json &j, const std::unordered_map<uint32_t, std::shared_ptr<Vault> > &roles) {
        j = nlohmann::json::array();
        for (const auto &[id, role]: roles) j.emplace_back(*role);
    }

    std::string to_string(const std::vector<std::shared_ptr<Vault> > &roles) {
        std::ostringstream oss;
        for (const auto &role: roles) oss << role->toString(0) << "\n";
        return oss.str();
    }

    std::string to_string(const Vault &role) { return role.toString(0); }

Vault Vault::ImplicitDeny() {
    return make(
        "implicit_deny",
        "Role that denies all vault permissions.",
        vault::Base::None()
    );
}

Vault Vault::Guest() {
    return make(
        "guest",
        "Minimal access role for browsing and limited read-only interaction with vault content.",
        vault::Base::BrowseOnly()
    );
}

Vault Vault::Reader() {
    return make(
        "reader",
        "Read-only vault role with access to browse and download content.",
        vault::Base::Reader()
    );
}

Vault Vault::Contributor() {
    return make(
        "contributor",
        "Vault role for users who can add and update content without broader administrative control.",
        vault::Base::Contributor()
    );
}

Vault Vault::Editor() {
    return make(
        "editor",
        "Vault role for users who can fully edit and reorganize content within the vault.",
        vault::Base::Editor()
    );
}

Vault Vault::Manager() {
    return make(
        "manager",
        "Vault manager role with content, sync, and limited role-management authority.",
        vault::Base::Manager()
    );
}

Vault Vault::PowerUser() {
    return make(
        "power_user",
        "Advanced vault role with broad filesystem control, sync management, and strong collaborative authority.",
        vault::Base::PowerUser()
    );
}

Vault Vault::Full() {
    return make(
        "full",
        "Unrestricted vault role with full permissions across filesystem, sync, and role management.",
        vault::Base::Full()
    );
}

Vault Vault::RoleManager() {
    return make(
        "role_manager",
        "Specialized vault role focused on managing vault role assignments and access governance.",
        vault::Base::RoleManager()
    );
}

Vault Vault::SyncOperator() {
    return make(
        "sync_operator",
        "Specialized vault role focused on synchronization operations and configuration.",
        vault::Base::SyncOperator()
    );
}

}
