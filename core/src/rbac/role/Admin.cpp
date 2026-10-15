#include "rbac/role/Admin.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/has.hpp"
#include "protocols/shell/util/lineHelpers.hpp"
#include "usages.hpp"
#include "rbac/resolver/permission/all.hpp"

#include <pqxx/result>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

using namespace vh::db::encoding;
using namespace vh::protocols::shell;

namespace vh::rbac::role {
    Admin::Admin(pqxx::row_ref row, const pqxx::result &globalVaultRoles)
        : Meta(row),
          identities(static_cast<typename decltype(identities)::Mask>(
              row["identity_permissions"].as<uint64_t>())),
          vaults(row["vaults_permissions"].as<typename decltype(vaults)::Mask>()),
          audits(static_cast<typename decltype(audits)::Mask>(row["audit_permissions"].as<uint64_t>())),
          settings(static_cast<typename decltype(settings)::Mask>(
              row["settings_permissions"].as<uint64_t>())),
          roles(static_cast<typename decltype(roles)::Mask>(
              row["roles_permissions"].as<uint64_t>())),
          keys(static_cast<typename decltype(keys)::Mask>(
              row["keys_permissions"].as<uint64_t>())),
          s3Gateway(static_cast<typename decltype(s3Gateway)::Mask>(
              try_get<uint64_t>(row, "s3_gateway_permissions").value_or(0))),
          stats(static_cast<typename decltype(stats)::Mask>(
              try_get<uint64_t>(row, "stats_permissions").value_or(0))),
          upstream(static_cast<typename decltype(upstream)::Mask>(
              try_get<uint64_t>(row, "upstream_permissions").value_or(0))),
          vGlobals(globalVaultRoles) {
        if (const auto id = try_get<uint32_t>(row, "user_id")) user_id = *id;
    }

    Admin::Admin(pqxx::row_ref row)
        : Meta(row),
          identities(static_cast<typename decltype(identities)::Mask>(
              row["identity_permissions"].as<uint64_t>())),
          vaults(row["vaults_permissions"].as<typename decltype(vaults)::Mask>()),
          audits(static_cast<typename decltype(audits)::Mask>(row["audit_permissions"].as<uint64_t>())),
          settings(static_cast<typename decltype(settings)::Mask>(
              row["settings_permissions"].as<uint64_t>())),
          roles(static_cast<typename decltype(roles)::Mask>(
              row["roles_permissions"].as<uint64_t>())),
          keys(static_cast<typename decltype(keys)::Mask>(
              row["keys_permissions"].as<uint64_t>())),
          s3Gateway(static_cast<typename decltype(s3Gateway)::Mask>(
              try_get<uint64_t>(row, "s3_gateway_permissions").value_or(0))),
          stats(static_cast<typename decltype(stats)::Mask>(
              try_get<uint64_t>(row, "stats_permissions").value_or(0))),
          upstream(static_cast<typename decltype(upstream)::Mask>(
              try_get<uint64_t>(row, "upstream_permissions").value_or(0))) {
        if (const auto id = try_get<uint32_t>(row, "user_id")) user_id = *id;
    }

    Admin::Admin(const nlohmann::json &j)
        : Meta(j) {
        if (j.contains("user_id")) user_id = j["user_id"].get<uint32_t>();
        if (!j.contains("permissions") || !j["permissions"].is_array()) return;

        std::unordered_map<std::string, bool> pMap;
        for (const auto& p : j.at("permissions"))
            pMap.emplace(p.at("qualified").get<std::string>(), p.at("value").get<bool>());

        using PermResolver = resolver::PermissionResolverEnumPack<std::shared_ptr<Admin>>::type;
        // shared_from_this() throws bad_weak_ptr inside a constructor (no owner exists yet). A non-owning
        // aliasing pointer is enough for the resolver, which only mutates *this for the duration of the call.
        std::shared_ptr<Admin> self(std::shared_ptr<Admin>{}, this);
        PermResolver::applySnapshot(self, toPermissions(), pMap);
    }

    void Admin::updateFromJson(const nlohmann::json &j) {
        Meta::updateFromJson(j);
        if (j.contains("user_id")) user_id = j["user_id"].get<uint32_t>();

        if (!j.contains("permissions") || !j["permissions"].is_array()) return;

        std::unordered_map<std::string, bool> pMap;
        for (const auto& p : j.at("permissions"))
            pMap.emplace(p.at("qualified").get<std::string>(), p.at("value").get<bool>());

        using PermResolver = resolver::PermissionResolverEnumPack<std::shared_ptr<Admin>>::type;
        auto self = shared_from_this();
        PermResolver::applySnapshot(self, toPermissions(), pMap);
    }

    std::string Admin::usage() {
        return formatPermissionTable(
            rbac::role::Admin::None().getFlags(),
            "Permission Flags:",
            "You can use either the --manage-* shorthand to set, or explicitly use --set/--unset."
        );
    }

    std::unordered_map<std::string, permission::Permission> Admin::toFlagMap() const {
        std::unordered_map<std::string, permission::Permission> flagMap;

        for (const auto &perm: toPermissions())
            for (const auto& flag : perm.flags)
                flagMap[flag] = perm;

        return flagMap;
    }

    std::vector<std::string> Admin::getFlags() const {
        auto identitiesFlags = identities.getFlags();
        auto vaultsFlags = vaults.getFlags();
        auto auditsFlags = audits.getFlags();
        auto settingsFlags = settings.getFlags();
        auto rolesFlags = roles.getFlags();
        auto keysFlags = keys.getFlags();
        auto s3GatewayFlags = s3Gateway.getFlags();
        auto statsFlags = stats.getFlags();
        auto upstreamFlags = upstream.getFlags();

        std::vector<std::string> flags;
        flags.reserve(
            identitiesFlags.size() +
            vaultsFlags.size() +
            auditsFlags.size() +
            settingsFlags.size() +
            rolesFlags.size() +
            keysFlags.size() +
            s3GatewayFlags.size() +
            statsFlags.size() +
            upstreamFlags.size()
        );

        auto append = [&](auto &src) { std::move(src.begin(), src.end(), std::back_inserter(flags)); };

        append(identitiesFlags);
        append(vaultsFlags);
        append(auditsFlags);
        append(settingsFlags);
        append(rolesFlags);
        append(keysFlags);
        append(s3GatewayFlags);
        append(statsFlags);
        append(upstreamFlags);

        return flags;
    }

    std::vector<permission::Permission> Admin::toPermissions() const {
        auto identitiesPerms = identities.exportPermissions();
        auto vaultsPerms = vaults.exportPermissions();
        auto auditsPerms = audits.exportPermissions();
        auto settingsPerms = settings.exportPermissions();
        auto rolesPerms = roles.exportPermissions();
        auto keysPerms = keys.exportPermissions();
        auto s3GatewayPerms = s3Gateway.exportPermissions();
        auto statsPerms = stats.exportPermissions();
        auto upstreamPerms = upstream.exportPermissions();

        std::vector<permission::Permission> perms;
        perms.reserve(
            identitiesPerms.size() +
            vaultsPerms.size() +
            auditsPerms.size() +
            settingsPerms.size() +
            rolesPerms.size() +
            keysPerms.size() +
            s3GatewayPerms.size() +
            statsPerms.size() +
            upstreamPerms.size()
        );

        auto appendMoved = [&](auto &exportResult) {
            auto &src = exportResult();
            std::move(src.begin(), src.end(), std::back_inserter(perms));
        };

        appendMoved(identitiesPerms);
        appendMoved(vaultsPerms);
        appendMoved(auditsPerms);
        appendMoved(settingsPerms);
        appendMoved(rolesPerms);
        appendMoved(keysPerms);
        appendMoved(s3GatewayPerms);
        appendMoved(statsPerms);
        appendMoved(upstreamPerms);

        return perms;
    }

    std::string Admin::toFlagsString() const {
        return identities.toFlagsString() + " " + vaults.toFlagsString() + " " + audits.toFlagsString() + " " + settings
               .toFlagsString() + " " +
               roles.toFlagsString() + " " + keys.toFlagsString() + " " + s3Gateway.toFlagsString() + " " +
               stats.toFlagsString() + " " + upstream.toFlagsString();
    }

    std::optional<Admin> Admin::builtin(const std::string_view name, const uint32_t userId) {
        for (auto role : {None(userId), Auditor(userId), Support(userId), IdentityAdmin(userId), SecurityAdmin(userId),
                          PlatformOperator(userId), VaultAdmin(userId), OrgAdmin(userId), SuperAdmin(userId),
                          KeyCustodian(userId)})
            if (role.name == name) return role;
        return std::nullopt;
    }

    Admin Admin::fromJson(const nlohmann::json &j) { return Admin(j); }

    void to_json(nlohmann::json &j, const Admin &a) {
        j = static_cast<const Meta &>(a);
        j["user_id"] = a.user_id;
        j["permissions"] = a.toPermissions();
        j["s3_gateway"] = a.s3Gateway;
    }

    void from_json(const nlohmann::json &j, Admin &a) { a = Admin(j); }

    void to_json(nlohmann::json &j, const std::vector<Admin> &roles) {
        j = nlohmann::json::array();
        for (const auto &role: roles) j.emplace_back(role);
    }

    void to_json(nlohmann::json &j, const std::vector<std::shared_ptr<Admin> > &roles) {
        j = nlohmann::json::array();
        for (const auto &role: roles) j.emplace_back(*role);
    }

    std::string Admin::toString(const uint8_t indent) const {
        std::ostringstream oss;
        oss << std::string(indent, ' ') << snake_case_to_title(name) << " (ID: " << id << ")\n";
        const auto i = indent + 2;
        const std::string in(i, ' ');
        if (user_id) oss << in << "- User ID: " << std::to_string(*user_id) << std::endl;
        oss << Meta::toString(indent)
                << identities.toString(i)
                << vaults.toString(i)
                << audits.toString(i)
                << settings.toString(i)
                << roles.toString(i)
                << keys.toString(i)
                << s3Gateway.toString(i)
                << stats.toString(i)
                << upstream.toString(i);
        return oss.str();
    }

    std::string to_string(const Admin &r) { return r.toString(); }

    std::string to_string(const std::vector<std::shared_ptr<Admin>> &roles) {
        std::ostringstream oss;
        for (const auto &role: roles) oss << role->toString() << "\n";
        return oss.str();
    }

Admin Admin::None(const std::optional<uint32_t> userId) {
    return make(
        "unprivileged",
        "User with no administrative privileges.",
        userId,
        permission::admin::Identities::None(),
        permission::admin::Vaults::None(),
        permission::admin::Audits::None(),
        permission::admin::Settings::None(),
        permission::admin::Roles::None(),
        permission::admin::Keys::None(),
        permission::admin::S3Gateway::None(),
        permission::admin::Stats::None(),
        permission::admin::Upstream::None(),
        permission::admin::VaultGlobals::NoneIfBound(userId)
    );
}

Admin Admin::Auditor(const std::optional<uint32_t> userId) {
    return make(
        "auditor",
        "Read-only administrative role for inspection, auditing, and operational visibility.",
        userId,
        permission::admin::Identities::ViewOnly(),
        permission::admin::Vaults::ViewOnly(),
        permission::admin::Audits::ViewOnly(),
        permission::admin::Settings::ViewOnly(),
        permission::admin::Roles::ViewOnly(),
        permission::admin::Keys::ViewOnly(),
        permission::admin::S3Gateway::ViewOnly(),
        permission::admin::Stats::ViewOnly(),
        permission::admin::Upstream::ViewOnly(),
        permission::admin::VaultGlobals::ReaderIfBound(userId)
    );
}

Admin Admin::Support(const std::optional<uint32_t> userId) {
    return make(
        "support",
        "Support role for user assistance, troubleshooting, and limited administrative visibility.",
        userId,
        permission::admin::Identities::UserSupport(),
        permission::admin::Vaults::ViewOnly(),
        permission::admin::Audits::ViewOnly(),
        permission::admin::Settings::Support(),
        permission::admin::Roles::ViewOnly(),
        permission::admin::Keys::ViewOnly(),
        permission::admin::S3Gateway::ViewOnly(),
        permission::admin::Stats::None(),
        permission::admin::Upstream::None(),
        permission::admin::VaultGlobals::ReaderIfBound(userId)
    );
}

Admin Admin::IdentityAdmin(const std::optional<uint32_t> userId) {
    return make(
        "identity_admin",
        "Administrative role focused on user, group, and identity lifecycle management.",
        userId,
        permission::admin::Identities::UserAndGroupManager(),
        permission::admin::Vaults::ViewOnly(),
        permission::admin::Audits::ViewOnly(),
        permission::admin::Settings::ViewOnly(),
        permission::admin::Roles::LifecycleManager(),
        permission::admin::Keys::ViewOnly(),
        permission::admin::S3Gateway::ViewOnly(),
        permission::admin::Stats::None(),
        permission::admin::Upstream::None(),
        permission::admin::VaultGlobals::ManagerIfBound(userId)
    );
}

Admin Admin::SecurityAdmin(const std::optional<uint32_t> userId) {
    return make(
        "security_admin",
        "Security-focused administrative role with strong visibility into audits, auth settings, and sensitive key material.",
        userId,
        permission::admin::Identities::PrivilegedIdentityManager(),
        permission::admin::Vaults::ViewOnly(),
        permission::admin::Audits::Full(),
        permission::admin::Settings::SecurityAdmin(),
        permission::admin::Roles::AdminManager(),
        permission::admin::Keys::SecurityAdmin(),
        permission::admin::S3Gateway::PrincipalAssigner(),
        permission::admin::Stats::None(),
        permission::admin::Upstream::Guardian(),
        permission::admin::VaultGlobals::ManagerIfBound(userId)
    );
}

Admin Admin::PlatformOperator(const std::optional<uint32_t> userId) {
    return make(
        "platform_operator",
        "Operational administrative role for infrastructure, service control, sync, and platform key management.",
        userId,
        permission::admin::Identities::UserManager(),
        permission::admin::Vaults::UserManager(),
        permission::admin::Audits::ViewOnly(),
        permission::admin::Settings::OperationsAdmin(),
        permission::admin::Roles::VaultManager(),
        permission::admin::Keys::PlatformOperator(),
        permission::admin::S3Gateway::Operator(),
        permission::admin::Stats::ViewOnly(),
        permission::admin::Upstream::Operator(),
        permission::admin::VaultGlobals::PowerUserIfBound(userId)
    );
}

Admin Admin::VaultAdmin(const std::optional<uint32_t> userId) {
    return make(
        "vault_admin",
        "Administrative role focused on vault governance, lifecycle, and broad vault-scoped control.",
        userId,
        permission::admin::Identities::UserAndGroupManager(),
        permission::admin::Vaults::Full(),
        permission::admin::Audits::ViewOnly(),
        permission::admin::Settings::ViewOnly(),
        permission::admin::Roles::VaultManager(),
        permission::admin::Keys::APIKeyManager(),
        permission::admin::S3Gateway::Operator(),
        permission::admin::Stats::None(),
        permission::admin::Upstream::ViewOnly(),
        permission::admin::VaultGlobals::PowerUserIfBound(userId)
    );
}

Admin Admin::OrgAdmin(const std::optional<uint32_t> userId) {
    return make(
        "admin",
        "System administrator with broad organizational control across identities, vaults, settings, roles, and keys.",
        userId,
        permission::admin::Identities::PrivilegedIdentityManagerWithPasswordReset(),
        permission::admin::Vaults::Full(),
        permission::admin::Audits::Full(),
        permission::admin::Settings::Full(),
        permission::admin::Roles::Full(),
        permission::admin::Keys::SecurityAdmin(),
        permission::admin::S3Gateway::Full(),
        permission::admin::Stats::ViewOnly(),
        permission::admin::Upstream::Operator(),
        permission::admin::VaultGlobals::FullIfBound(userId)
    );
}

Admin Admin::SuperAdmin(const std::optional<uint32_t> userId) {
    return make(
        "super_admin",
        "Root-level system owner with unrestricted administrative authority.",
        userId,
        permission::admin::Identities::Full(),
        permission::admin::Vaults::Full(),
        permission::admin::Audits::Full(),
        permission::admin::Settings::Full(),
        permission::admin::Roles::Full(),
        permission::admin::Keys::Full(),
        permission::admin::S3Gateway::Full(),
        permission::admin::Stats::Full(),
        permission::admin::Upstream::Full(),
        permission::admin::VaultGlobals::FullIfBound(userId)
    );
}

Admin Admin::KeyCustodian(const std::optional<uint32_t> userId) {
    return make(
        "key_custodian",
        "Highly restricted administrative role trusted with sensitive encryption key custody and related key operations.",
        userId,
        permission::admin::Identities::ViewOnly(),
        permission::admin::Vaults::ViewOnly(),
        permission::admin::Audits::ViewOnly(),
        permission::admin::Settings::SecurityAuditor(),
        permission::admin::Roles::ViewOnly(),
        permission::admin::Keys::KeyCustodian(),
        permission::admin::S3Gateway::ViewOnly(),
        permission::admin::Stats::None(),
        permission::admin::Upstream::None(),
        permission::admin::VaultGlobals::ReaderIfBound(userId)
    );
}

}
