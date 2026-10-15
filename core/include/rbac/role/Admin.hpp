#pragma once

#include <string_view>

#include "rbac/role/Meta.hpp"
#include "db/Fwd.hpp"
#include "rbac/permission/admin/all.hpp"
#include "rbac/permission/Permission.hpp"

#include <string>
#include <optional>
#include <memory>
#include <vector>
#include <unordered_map>
#include <nlohmann/json_fwd.hpp>

namespace vh::rbac::role {
    struct Admin final : Meta, std::enable_shared_from_this<Admin> {
        std::optional<uint32_t> user_id;

        permission::admin::Identities identities{};
        permission::admin::Vaults vaults{};
        permission::admin::Audits audits{};
        permission::admin::Settings settings{};
        permission::admin::Roles roles{};
        permission::admin::Keys keys{};
        permission::admin::S3Gateway s3Gateway{};
        permission::admin::Stats stats{};
        permission::admin::Upstream upstream{};
        permission::admin::VaultGlobals vGlobals{};

        Admin() = default;

        Admin(pqxx::row_ref row, const pqxx::result &globalVaultRoles);

        explicit Admin(pqxx::row_ref row);

        explicit Admin(const nlohmann::json &j);

        [[nodiscard]] std::string toString(uint8_t indent) const override;

        [[nodiscard]] std::string toString() const { return toString(0); }

        [[nodiscard]] std::string toFlagsString() const;

        [[nodiscard]] std::vector<std::string> getFlags() const;

        [[nodiscard]] std::vector<permission::Permission> toPermissions() const;

        [[nodiscard]] std::unordered_map<std::string, permission::Permission> toFlagMap() const;

        [[nodiscard]] static std::string usage();

        void updateFromJson(const nlohmann::json &j);

        static Admin fromJson(const nlohmann::json &j);

        // ---------- canonical builtins ----------

        // The built-in role with this name, bound to `userId` so its global vault policy (vGlobals) is populated.
        // Roles loaded from admin_role carry no vGlobals: an account's policy is its own (user_global_vault_policy)
        // and starts from this preset. nullopt for custom roles.
        static std::optional<Admin> builtin(std::string_view name, uint32_t userId);

        static Admin None(const std::optional<uint32_t> userId = std::nullopt);

        static Admin Auditor(const std::optional<uint32_t> userId = std::nullopt);

        static Admin Support(const std::optional<uint32_t> userId = std::nullopt);

        static Admin IdentityAdmin(const std::optional<uint32_t> userId = std::nullopt);

        static Admin SecurityAdmin(const std::optional<uint32_t> userId = std::nullopt);

        static Admin PlatformOperator(const std::optional<uint32_t> userId = std::nullopt);

        static Admin VaultAdmin(const std::optional<uint32_t> userId = std::nullopt);

        static Admin OrgAdmin(const std::optional<uint32_t> userId = std::nullopt);

        static Admin SuperAdmin(const std::optional<uint32_t> userId = std::nullopt);

        static Admin KeyCustodian(const std::optional<uint32_t> userId = std::nullopt);

        static Admin Custom(
            std::string name,
            std::string description,
            const permission::admin::Identities& identities,
            permission::admin::Vaults vaults,
            permission::admin::Audits audits,
            const permission::admin::Settings& settings,
            permission::admin::Roles roles,
            permission::admin::Keys keys,
            permission::admin::S3Gateway s3Gateway,
            const std::optional<uint32_t> userId = std::nullopt,
            std::optional<permission::admin::VaultGlobals> vGlobals = std::nullopt,
            permission::admin::Stats stats = permission::admin::Stats::None(),
            permission::admin::Upstream upstream = permission::admin::Upstream::None()
        ) {
            return make(
                std::move(name),
                std::move(description),
                userId,
                identities,
                std::move(vaults),
                std::move(audits),
                settings,
                std::move(roles),
                std::move(keys),
                std::move(s3Gateway),
                std::move(stats),
                std::move(upstream),
                std::move(vGlobals).value_or(permission::admin::VaultGlobals::NoneIfBound(userId))
            );
        }

    private:
        static Admin make(
            std::string name,
            std::string description,
            const std::optional<uint32_t> userId,
            const permission::admin::Identities& identities,
            permission::admin::Vaults vaults,
            permission::admin::Audits audits,
            const permission::admin::Settings& settings,
            permission::admin::Roles roles,
            permission::admin::Keys keys,
            permission::admin::S3Gateway s3Gateway,
            permission::admin::Stats stats,
            permission::admin::Upstream upstream,
            permission::admin::VaultGlobals vGlobals
        ) {
            Admin a;
            a.name = std::move(name);
            a.description = std::move(description);
            a.user_id = userId;

            a.identities = identities;
            a.vaults = std::move(vaults);
            a.audits = std::move(audits);
            a.settings = settings;
            a.roles = std::move(roles);
            a.keys = std::move(keys);
            a.s3Gateway = std::move(s3Gateway);
            a.stats = std::move(stats);
            a.upstream = std::move(upstream);
            a.vGlobals = std::move(vGlobals);

            return a;
        }
    };

    void to_json(nlohmann::json &j, const Admin &a);

    void from_json(const nlohmann::json &j, Admin &a);

    void to_json(nlohmann::json &j, const std::vector<Admin> &roles);

    void to_json(nlohmann::json &j, const std::vector<std::shared_ptr<Admin> > &roles);

    std::string to_string(const Admin &r);

    std::string to_string(const std::vector<std::shared_ptr<Admin>> &roles);
}
