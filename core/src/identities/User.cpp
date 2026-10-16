#include "identities/User.hpp"

#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"
#include "rbac/permission/admin/Vaults.hpp"

#include "db/encoding/has.hpp"
#include "db/encoding/timestamp.hpp"
#include "protocols/shell/util/lineHelpers.hpp"
#include "protocols/shell/Table.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/row>
#include <pqxx/result>

#include <stdexcept>
#include <thread>
#include <utility>

using namespace vh::protocols::shell;
using namespace vh::db::encoding;
using namespace vh::rbac::role;

namespace {
    template<typename T>
    std::optional<T> try_as_optional(pqxx::row_ref row, const char *column) {
        // Check first, never catch: libpqxx marks row[name] [[gnu::pure]], which clang treats as non-throwing,
        // so a missing column would bypass this catch and terminate.
        if (!vh::db::encoding::hasColumn(row, column)) return std::nullopt;
        try {
            const auto field = row[column];
            if (field.is_null()) return std::nullopt;
            return field.as<T>();
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::string> try_as_optional_string(pqxx::row_ref row, const char *column) {
        // Check first, never catch: libpqxx marks row[name] [[gnu::pure]], which clang treats as non-throwing,
        // so a missing column would bypass this catch and terminate.
        if (!vh::db::encoding::hasColumn(row, column)) return std::nullopt;
        try {
            const auto field = row[column];
            if (field.is_null()) return std::nullopt;
            return field.as<std::string>();
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::time_t> try_as_optional_timestamp(pqxx::row_ref row, const char *column) {
        // Check first, never catch: libpqxx marks row[name] [[gnu::pure]], which clang treats as non-throwing,
        // so a missing column would bypass this catch and terminate.
        if (!vh::db::encoding::hasColumn(row, column)) return std::nullopt;
        try {
            const auto field = row[column];
            if (field.is_null()) return std::nullopt;
            return parsePostgresTimestamp(field.as<std::string>());
        } catch (...) {
            return std::nullopt;
        }
    }

    std::time_t try_as_timestamp_or_now(pqxx::row_ref row, const char *column) {
        // Check first, never catch: libpqxx marks row[name] [[gnu::pure]], which clang treats as non-throwing,
        // so a missing column would bypass this catch and terminate.
        if (!vh::db::encoding::hasColumn(row, column)) return std::time(nullptr);
        try {
            const auto field = row[column];
            if (field.is_null()) return std::time(nullptr);
            return parsePostgresTimestamp(field.as<std::string>());
        } catch (...) {
            return std::time(nullptr);
        }
    }

    bool superAdminShape(const vh::rbac::role::Admin &role) {
        return role.identities.admins.canDelete()
               && role.vaults.admin.canRemove()
               && role.keys.encryptionKeys.canRotate()
               && role.name == "super_admin";
    }

    bool adminShape(const vh::rbac::role::Admin &role) {
        return role.identities.admins.canDelete() && role.vaults.admin.canRemove();
    }

    // The admin role of an authorizing state; null otherwise (every permission accessor then answers "no").
    const vh::rbac::role::Admin *authorizingAdmin(const vh::identities::UserState &s) {
        return s.authorizing() && s.roles.admin ? s.roles.admin.get() : nullptr;
    }
} // namespace

namespace vh::identities {
    bool UserState::hasSuperAdminRole() const { return roles.admin && superAdminShape(*roles.admin); }

    bool UserState::hasAdminRole() const { return roles.admin && adminShape(*roles.admin); }

    const rbac::permission::admin::VaultGlobals *AuthzView::vaultGlobals() const {
        if (!authorizing() || !user->roles.admin) return nullptr;
        return &user->roles.admin->vGlobals;
    }

    std::shared_ptr<const rbac::role::Vault> AuthzView::directVaultRole(const uint32_t vaultId) const {
        if (!authorizing()) return nullptr;
        const auto it = user->roles.vaults.find(vaultId);
        return it == user->roles.vaults.end() ? nullptr : it->second;
    }

    bool AuthzView::isSuperAdmin() const { return authorizing() && user->hasSuperAdminRole(); }

    bool AuthzView::isAdmin() const { return authorizing() && user->hasAdminRole(); }

    User::User(const uint32_t id, std::shared_ptr<const UserState> initial, const bool detached)
        : id(id), state_(std::move(initial)), detached_(detached) {}

    std::shared_ptr<User> User::detached(const uint32_t id, UserState state) {
        return std::shared_ptr<User>(new User(id, std::make_shared<const UserState>(std::move(state)), true));
    }

    void User::replaceDetachedState(UserState next) {
        if (!detached_) throw std::logic_error("canonical users change only through identities::Manager");
        publish(std::make_shared<const UserState>(std::move(next)));
    }

    AuthzView User::authz() const {
        auto& seq = detail::publicationSeq;
        for (unsigned spins = 0;; ++spins) {
            const auto before = seq.load();
            if (before & 1u) {
                if (spins > 64) std::this_thread::yield();
                continue;
            }
            AuthzView view;
            view.user = state();
            if (view.user->authorizing()) {
                view.groups.reserve(view.user->groups.size());
                for (const auto &group: view.user->groups) {
                    if (!group) continue;
                    if (auto gs = group->state(); gs && !gs->deleted) view.groups.push_back(std::move(gs));
                }
            }
            if (seq.load() == before) return view;
        }
    }

    std::string User::name() const { return state()->name; }
    std::optional<std::string> User::email() const { return state()->email; }
    std::optional<uint32_t> User::linuxUid() const { return state()->meta.linux_uid; }
    bool User::isActive() const { return state()->meta.is_active; }
    bool User::authorizing() const { return state()->authorizing(); }
    bool User::isProtected() const { return state()->isProtected; }
    bool User::systemOnly() const { return state()->systemOnly; }
    bool User::deleted() const { return state()->deleted; }

    bool User::isSuperAdmin() const {
        const auto s = state();
        const auto *admin = authorizingAdmin(*s);
        return admin && superAdminShape(*admin);
    }

    bool User::isAdmin() const {
        const auto s = state();
        const auto *admin = authorizingAdmin(*s);
        return admin && adminShape(*admin);
    }

    std::shared_ptr<const rbac::role::Vault> User::getDirectVaultRole(const uint32_t vaultId) const {
        const auto s = state();
        if (!s->authorizing()) return nullptr;
        const auto it = s->roles.vaults.find(vaultId);
        return it == s->roles.vaults.end() ? nullptr : it->second;
    }

    bool User::hasDirectVaultRole(const uint32_t vaultId) const { return getDirectVaultRole(vaultId) != nullptr; }

#define VH_ADMIN_PERMS(method, Type, expr)                                       \
    Type User::method() const {                                                   \
        const auto s = state();                                                   \
        const auto *admin = authorizingAdmin(*s);                                 \
        return admin ? Type(admin->expr) : Type{};                                \
    }

    VH_ADMIN_PERMS(identities, rbac::permission::admin::Identities, identities)
    VH_ADMIN_PERMS(users, rbac::permission::admin::identities::Users, identities.users)
    VH_ADMIN_PERMS(groupPerms, rbac::permission::admin::identities::Groups, identities.groups)
    VH_ADMIN_PERMS(admins, rbac::permission::admin::identities::Admins, identities.admins)
    VH_ADMIN_PERMS(adminRolePerms, rbac::permission::admin::roles::Admin, roles.admin)
    VH_ADMIN_PERMS(vaultRolePerms, rbac::permission::admin::roles::Vault, roles.vault)
    VH_ADMIN_PERMS(settings, rbac::permission::admin::Settings, settings)
    VH_ADMIN_PERMS(audits, rbac::permission::admin::Audits, audits)
    VH_ADMIN_PERMS(vaultGlobals, rbac::permission::admin::VaultGlobals, vGlobals)
    VH_ADMIN_PERMS(vaultsPerms, rbac::permission::admin::Vaults, vaults)
    VH_ADMIN_PERMS(apiKeysPerms, rbac::permission::admin::keys::APIKeys, keys.apiKeys)
    VH_ADMIN_PERMS(s3GatewayPerms, rbac::permission::admin::S3Gateway, s3Gateway)
    VH_ADMIN_PERMS(statsPerms, rbac::permission::admin::Stats, stats)
    VH_ADMIN_PERMS(upstreamPerms, rbac::permission::admin::Upstream, upstream)
    VH_ADMIN_PERMS(encryptionKeysPerms, rbac::permission::admin::keys::EncryptionKey, keys.encryptionKeys)

#undef VH_ADMIN_PERMS

    UserState stateFromRow(pqxx::row_ref row) {
        UserState s;
        s.name = try_as_optional_string(row, "name").value_or("");
        s.email = try_as_optional_string(row, "email");
        s.isProtected = try_as_optional<bool>(row, "protected").value_or(false);
        s.systemOnly = try_as_optional<bool>(row, "system_only").value_or(false);

        s.meta.linux_uid = try_as_optional<uint32_t>(row, "linux_uid");
        s.meta.created_by = try_as_optional<uint32_t>(row, "created_by");

        // Support either new updated_by or legacy last_modified_by while you transition.
        s.meta.updated_by = try_as_optional<uint32_t>(row, "updated_by");
        if (!s.meta.updated_by) s.meta.updated_by = try_as_optional<uint32_t>(row, "last_modified_by");

        s.meta.created_at = try_as_timestamp_or_now(row, "created_at");
        s.meta.updated_at = try_as_timestamp_or_now(row, "updated_at");

        s.meta.last_login = try_as_optional_timestamp(row, "last_login");
        s.meta.password_changed_at = try_as_optional_timestamp(row, "password_changed_at");
        s.meta.deactivated_at = try_as_optional_timestamp(row, "deactivated_at");

        s.meta.is_active = try_as_optional<bool>(row, "is_active").value_or(true);
        return s;
    }

    namespace {
        void baseJson(nlohmann::json &j, const uint32_t id, const UserState &s) {
            j = {
                {"id", id},
                {"name", s.name},
                {"email", s.email},
                {"is_protected", s.isProtected},
                {"system_only", s.systemOnly},
                {"created_at", timestampToString(s.meta.created_at)},
                {"updated_at", timestampToString(s.meta.updated_at)},
                {"is_active", s.meta.is_active}
            };

            j["last_login"] = s.meta.last_login
                                  ? nlohmann::json(timestampToString(*s.meta.last_login))
                                  : nlohmann::json(nullptr);

            j["password_changed_at"] = s.meta.password_changed_at
                                           ? nlohmann::json(timestampToString(*s.meta.password_changed_at))
                                           : nlohmann::json(nullptr);

            j["deactivated_at"] = s.meta.deactivated_at
                                      ? nlohmann::json(timestampToString(*s.meta.deactivated_at))
                                      : nlohmann::json(nullptr);

            if (s.meta.linux_uid) j["linux_uid"] = *s.meta.linux_uid;
            if (s.meta.created_by) j["created_by"] = *s.meta.created_by;
            if (s.meta.updated_by) j["updated_by"] = *s.meta.updated_by;
        }
    }

    void to_json(nlohmann::json &j, const User &u) {
        const auto s = u.state();
        baseJson(j, u.id, *s);

        if (s->roles.admin) j["admin_role"] = *s->roles.admin;
        else {
            throw std::logic_error(
                "[User] admin role is null for user id=" + std::to_string(u.id) +
                " name=" + s->name + ". Did you mean to call to_public_json() instead?"
            );
        }

        nlohmann::json vaultRoles = nlohmann::json::array();
        for (const auto &[_, role]: s->roles.vaults)
            if (role) vaultRoles.push_back(*role);
        if (!vaultRoles.empty()) j["vault_roles"] = std::move(vaultRoles);
        else j["vault_roles"] = nlohmann::json::object();
    }

    nlohmann::json to_list_json(const std::vector<std::shared_ptr<User> > &users) {
        // A role's identity without its permission set: listing 100 users used to ship every user's full admin
        // permission array with descriptions (~13 KB each).
        const auto roleSummary = [](const vh::rbac::role::Meta &role, const char *type) {
            return nlohmann::json{
                {"id", role.id},
                {"name", role.name},
                {"description", role.description},
                {"type", type},
                {"assigned_at", role.assigned_at},
            };
        };

        nlohmann::json out = nlohmann::json::array();
        for (const auto &user: users) {
            if (!user) continue;
            const auto s = user->state();
            nlohmann::json j;
            baseJson(j, user->id, *s);
            j["admin_role"] = s->roles.admin ? roleSummary(*s->roles.admin, "admin") : nlohmann::json(nullptr);
            nlohmann::json vaultRoles = nlohmann::json::array();
            for (const auto &[_, role]: s->roles.vaults) {
                if (!role) continue;
                auto summary = roleSummary(*role, "vault");
                if (role->assignment) summary["assignment"] = *role->assignment;
                vaultRoles.push_back(std::move(summary));
            }
            j["vault_roles"] = std::move(vaultRoles);
            out.push_back(std::move(j));
        }
        return out;
    }

    nlohmann::json to_json(const std::vector<std::shared_ptr<User> > &users) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto &user: users)
            if (user) j.push_back(*user);
        return j;
    }

    nlohmann::json to_json(const std::shared_ptr<User> &user) {
        if (!user) return nullptr;
        return *user;
    }

    nlohmann::json to_public_json(const std::shared_ptr<User> &u) {
        if (!u) return nullptr;
        const auto s = u->state();

        return {
            {"id", u->id},
            {"name", s->name},
            {"email", s->email},
            {"is_active", s->meta.is_active}
        };
    }

    nlohmann::json to_public_json(const std::vector<std::shared_ptr<User> > &users) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto &user: users)
            if (user) j.push_back(to_public_json(user));
        return j;
    }

    std::string to_string(const std::shared_ptr<User> &user) {
        if (!user) return "No user found\n";
        const auto s = user->state();

        std::string out;
        out += "User ID: " + std::to_string(user->id) + "\n";
        out += "User: " + s->name + "\n";
        out += "Email: " + s->email.value_or("N/A") + "\n";

        if (s->meta.linux_uid) out += "Linux UID: " + std::to_string(*s->meta.linux_uid) + "\n";
        else out += "Linux UID: Not set\n";

        if (s->meta.created_by) out += "Created By: " + std::to_string(*s->meta.created_by) + "\n";
        else out += "Created By: N/A\n";

        if (s->meta.updated_by) out += "Updated By: " + std::to_string(*s->meta.updated_by) + "\n";
        else out += "Updated By: N/A\n";

        out += "Created At: " + timestampToString(s->meta.created_at) + "\n";
        out += "Updated At: " + timestampToString(s->meta.updated_at) + "\n";
        out += "Last Login: " + (s->meta.last_login ? timestampToString(*s->meta.last_login) : "Never") + "\n";
        out += "Password Changed At: " + (s->meta.password_changed_at
                                              ? timestampToString(*s->meta.password_changed_at)
                                              : "Unknown") + "\n";
        out += "Deactivated At: " + (s->meta.deactivated_at ? timestampToString(*s->meta.deactivated_at) : "N/A")
                + "\n";
        out += "Active: " + std::string(s->meta.is_active ? "Yes" : "No") + "\n";

        out += "Admin Role: ";
        out += s->roles.admin ? s->roles.admin->toString() : std::string("None\n");

        out += "Direct Vault Roles:\n";
        out += s->roles.vaults.empty() || !s->roles.admin ? "  None\n" : s->roles.admin->vaults.toString(2);

        out += "Groups: " + std::to_string(s->groups.size()) + "\n";

        return out;
    }

    std::string to_string(const std::vector<std::shared_ptr<User> > &users) {
        if (users.empty()) return "No users found\n";

        Table tbl({
                      {"ID", Align::Right, 4, 6, false, false},
                      {"Name", Align::Left, 4, 32, false, false},
                      {"Email", Align::Left, 4, 32, false, false},
                      {"Admin Role", Align::Left, 4, 20, false, false},
                      {"Created At", Align::Left, 4, 20, false, false},
                      {"Last Login", Align::Left, 4, 20, false, false},
                      {"Active", Align::Left, 4, 8, false, false}
                  }, term_width());

        for (const auto &user: users) {
            if (!user) continue;
            const auto s = user->state();

            tbl.add_row({
                std::to_string(user->id),
                s->name,
                s->email.value_or("N/A"),
                s->roles.admin ? snake_case_to_title(s->roles.admin->name) : "No Role",
                timestampToString(s->meta.created_at),
                s->meta.last_login ? timestampToString(*s->meta.last_login) : "Never",
                s->meta.is_active ? "Yes" : "No"
            });
        }

        return "Vaulthalla users:\n" + tbl.render();
    }
}
