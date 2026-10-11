#pragma once

#include "rbac/role/vault/Global.hpp"

#include <nlohmann/json_fwd.hpp>
#include "db/Fwd.hpp"

namespace vh::rbac::permission::admin {
    struct VaultGlobals {
        role::vault::Global self{}, admin{}, user{};

        // Each entry labelled with its own scope. The writer keys rows by scope, so three default (all "self")
        // entries collapsed into one empty self row and the admin/user rows were never written.
        VaultGlobals();

        explicit VaultGlobals(const pqxx::result &res);

        // One user_global_vault_policy row, into the scope it names.
        void assign(pqxx::row_ref row);

    public:
        static VaultGlobals None(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::None(),
                role::vault::Base::None(),
                role::vault::Base::None()
            );
        }

        static VaultGlobals BrowseOnly(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::BrowseOnly(),
                role::vault::Base::BrowseOnly(),
                role::vault::Base::BrowseOnly()
            );
        }

        static VaultGlobals Reader(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::Reader(),
                role::vault::Base::Reader(),
                role::vault::Base::Reader()
            );
        }

        static VaultGlobals Contributor(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::Contributor(),
                role::vault::Base::Contributor(),
                role::vault::Base::Contributor()
            );
        }

        static VaultGlobals Editor(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::Editor(),
                role::vault::Base::Editor(),
                role::vault::Base::Editor()
            );
        }

        static VaultGlobals Manager(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::Manager(),
                role::vault::Base::Manager(),
                role::vault::Base::Manager()
            );
        }

        static VaultGlobals PowerUser(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::PowerUser(),
                role::vault::Base::PowerUser(),
                role::vault::Base::PowerUser()
            );
        }

        static VaultGlobals Full(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::Full(),
                role::vault::Base::Full(),
                role::vault::Base::Full()
            );
        }

        static VaultGlobals Operator(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::Reader(), // self
                role::vault::Base::Manager(), // admin scope
                role::vault::Base::Contributor() // user scope
            );
        }

        static VaultGlobals Auditor(const uint32_t userId) {
            return make(
                userId,
                role::vault::Base::Reader(),
                role::vault::Base::Reader(),
                role::vault::Base::Reader()
            );
        }

        static VaultGlobals Custom(
            role::vault::Global self,
            role::vault::Global admin,
            role::vault::Global user
        ) {
            VaultGlobals vg;
            vg.self = std::move(self);
            vg.admin = std::move(admin);
            vg.user = std::move(user);
            return vg;
        }

        static VaultGlobals SelfOnly(const uint32_t userId, const role::vault::Base &base) {
            return make(userId, base, role::vault::Base::None(), role::vault::Base::None());
        }

        static VaultGlobals AdminOnly(const uint32_t userId, const role::vault::Base &base) {
            return make(userId, role::vault::Base::None(), base, role::vault::Base::None());
        }

        static VaultGlobals UserOnly(const uint32_t userId, const role::vault::Base &base) {
            return make(userId, role::vault::Base::None(), role::vault::Base::None(), base);
        }

        static VaultGlobals NoneIfBound(const std::optional<uint32_t> userId) {
            return userId ? None(*userId) : VaultGlobals{};
        }

        static VaultGlobals ReaderIfBound(const std::optional<uint32_t> userId) {
            return userId ? Reader(*userId) : VaultGlobals{};
        }

        static VaultGlobals ManagerIfBound(const std::optional<uint32_t> userId) {
            return userId ? Manager(*userId) : VaultGlobals{};
        }

        static VaultGlobals PowerUserIfBound(const std::optional<uint32_t> userId) {
            return userId ? PowerUser(*userId) : VaultGlobals{};
        }

        static VaultGlobals FullIfBound(const std::optional<uint32_t> userId) {
            return userId ? Full(*userId) : VaultGlobals{};
        }

        static VaultGlobals FromVaultRole(
            const uint32_t userId,
            const role::Vault &role,
            const std::optional<uint32_t> templateId = std::nullopt,
            const bool enforce = false
        ) {
            VaultGlobals vg;

            vg.self = role::vault::Global::FromVaultRole(userId, role::vault::Global::Scope::Self, role, templateId,
                                                         enforce);
            vg.admin = role::vault::Global::FromVaultRole(userId, role::vault::Global::Scope::Admin, role, templateId,
                                                          enforce);
            vg.user = role::vault::Global::FromVaultRole(userId, role::vault::Global::Scope::User, role, templateId,
                                                         enforce);

            return vg;
        }

    private:
        static VaultGlobals make(
            const uint32_t userId,
            const role::vault::Base &selfBase,
            const role::vault::Base &adminBase,
            const role::vault::Base &userBase
        ) {
            VaultGlobals vg;

            vg.self = role::vault::Global::Custom(userId, role::vault::Global::Scope::Self, selfBase);
            vg.admin = role::vault::Global::Custom(userId, role::vault::Global::Scope::Admin, adminBase);
            vg.user = role::vault::Global::Custom(userId, role::vault::Global::Scope::User, userBase);

            return vg;
        }
    };

    void to_json(nlohmann::json &j, const VaultGlobals &v);

    void from_json(const nlohmann::json &j, VaultGlobals &v);
}
