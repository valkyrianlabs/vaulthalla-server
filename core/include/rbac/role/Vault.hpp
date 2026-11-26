#pragma once

#include "rbac/role/Meta.hpp"
#include "db/Fwd.hpp"
#include "vault/Base.hpp"
#include "rbac/permission/Permission.hpp"

#include <string>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include <memory>
#include <optional>
#include <unordered_map>

namespace vh::rbac::role {
    struct Vault final : Meta, vault::Base, std::enable_shared_from_this<Vault> {
        struct AssignmentInfo {
            // The server whose vault this is, for the role its core granted this server (rbac/Mirrored.hpp).
            struct Owner {
                uint32_t peer_id{};
                std::string node_id{};
                std::string name{};
            };

            uint32_t subject_id{}, vault_id{};
            // 'user', 'group', 'peer' (a linked server), 'public', 'actor'; 'server' (this server) in a mirrored
            // vault's listing, for what its core granted this server.
            std::string subject_type{};

            // Listing annotations (ops::roles::listVaultRoleAssignments), absent from JSON when unset.
            std::optional<std::string> subject_name{};     // peer: the linked server's name
            std::optional<std::string> subject_node_id{};  // peer: its node id
            std::optional<bool> subject_revoked{};         // peer: unlinked (the row grants nothing)
            std::optional<bool> in_effect{};               // false: a local row on a vault held as another's copy
            std::optional<bool> editable{};                // false: owned by another server, read-only here
            std::optional<Owner> owned_by{};               // the server that owns this entry

            [[nodiscard]] std::string toString(uint8_t indent) const;
        };

        std::optional<AssignmentInfo> assignment{std::nullopt};

        Vault() : Meta(), Base() {}

        explicit Vault(pqxx::row_ref row);

        Vault(pqxx::row_ref row, const pqxx::result &overrides);

        explicit Vault(const nlohmann::json &j);

        void assign(const uint32_t subject_id, const std::string &subject_type, const uint32_t vault_id) {
            assignment = AssignmentInfo{.subject_id = subject_id, .vault_id = vault_id, .subject_type = subject_type};
        }

        void updateFromJson(const nlohmann::json &j);

        [[nodiscard]] static std::string usage();

        [[nodiscard]] std::vector<std::string> getFlags() const;

        [[nodiscard]] std::vector<permission::Permission> toPermissions() const;

        [[nodiscard]] std::string toString(uint8_t indent) const override;

        [[nodiscard]] std::string toString() const { return toString(0); }

        [[nodiscard]] permission::vault::fs::Files &files() noexcept { return fs.files; }
        [[nodiscard]] const permission::vault::fs::Files &files() const noexcept { return fs.files; }

        [[nodiscard]] permission::vault::fs::Directories &directories() noexcept { return fs.directories; }
        [[nodiscard]] const permission::vault::fs::Directories &directories() const noexcept { return fs.directories; }

        [[nodiscard]] permission::vault::Roles &rolesPerms() noexcept { return roles; }
        [[nodiscard]] const permission::vault::Roles &rolesPerms() const noexcept { return roles; }

        [[nodiscard]] permission::vault::sync::Config &syncConfig() noexcept { return sync.config; }
        [[nodiscard]] const permission::vault::sync::Config &syncConfig() const noexcept { return sync.config; }

        [[nodiscard]] permission::vault::sync::Action &syncActions() noexcept { return sync.action; }
        [[nodiscard]] const permission::vault::sync::Action &syncActions() const noexcept { return sync.action; }

        static Vault fromJson(const nlohmann::json &j);

        static Vault ImplicitDeny();

        static Vault Guest();

        static Vault Reader();

        static Vault Contributor();

        static Vault Editor();

        static Vault Manager();

        static Vault PowerUser();

        static Vault Full();

        static Vault RoleManager();

        static Vault SyncOperator();

        static Vault Custom(
            std::string name,
            std::string description,
            const vault::Base& base
        ) {
            return make(std::move(name), std::move(description), base);
        }

    private:
        static Vault make(
            std::string name,
            std::string description,
            vault::Base base
        ) {
            Vault r;
            r.name = std::move(name);
            r.description = std::move(description);

            r.roles = std::move(base.roles);
            r.sync = std::move(base.sync);
            r.fs = std::move(base.fs);

            return r;
        }
    };

    void to_json(nlohmann::json &j, const Vault &r);

    void from_json(const nlohmann::json &j, Vault &r);

    void to_json(nlohmann::json &j, const std::vector<Vault> &roles);

    void to_json(nlohmann::json &j, const std::unordered_map<uint32_t, std::shared_ptr<Vault> > &roles);

    void to_json(nlohmann::json &j, const Vault::AssignmentInfo &r);

    void from_json(const nlohmann::json &j, Vault::AssignmentInfo &r);

    void to_json(nlohmann::json &j, const std::vector<std::shared_ptr<Vault> > &roles);

    std::vector<Vault> vault_roles_from_json(const nlohmann::json &j);

    std::unordered_map<uint32_t, std::shared_ptr<Vault> > vault_roles_from_pq_result(
        const pqxx::result &res, const pqxx::result &overrides);

    std::string to_string(const Vault &role);

    std::string to_string(const std::vector<std::shared_ptr<Vault>> &roles);
}
