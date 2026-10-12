#pragma once

#include "concurrency/AtomicSharedPtr.hpp"

#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include "identities/Fwd.hpp"
#include "rbac/Fwd.hpp"
#include "db/Fwd.hpp"

namespace vh::rbac::permission::admin {
    struct Identities;
    struct Audits;
    struct Settings;
    struct S3Gateway;
    struct Stats;
    struct Vaults;
    struct VaultGlobals;

    namespace keys {
        struct APIKeys;
        struct EncryptionKey;
    }

    namespace roles {
        struct Admin;
        struct Vault;
    }

    namespace identities {
        struct Users;
        struct Groups;
        struct Admins;
    }
}

namespace vh::identities {

    struct GroupState;

    // One immutable version of a user. Published into the canonical User by identities::Manager; never modified after
    // publication. Readers take one (User::state(), or User::authz() together with the user's groups) per logical
    // operation and drop it when done, so a superseded state lives only as long as the reads that started on it.
    struct UserState {
        struct RoleAssignments {
            std::shared_ptr<const rbac::role::Admin> admin{};
            std::unordered_map<uint32_t, std::shared_ptr<const rbac::role::Vault>> vaults{};
        };

        struct Meta {
            std::optional<uint32_t> linux_uid{std::nullopt};
            std::optional<uint32_t> created_by{std::nullopt};
            std::optional<uint32_t> updated_by{std::nullopt};

            std::time_t created_at{};
            std::time_t updated_at{};

            std::optional<std::time_t> last_login{std::nullopt};
            std::optional<std::time_t> password_changed_at{std::nullopt};
            std::optional<std::time_t> deactivated_at{std::nullopt};

            bool is_active{true};
        };

        std::string name{};
        std::optional<std::string> email{std::nullopt};
        bool isProtected = false;
        bool systemOnly = false;

        RoleAssignments roles{};
        std::vector<std::shared_ptr<Group>> groups{};          // canonical groups (live state, see Group)
        std::unordered_map<uint32_t, std::time_t> joinedAt{};  // group id -> membership start
        Meta meta{};

        bool deleted = false;    // tombstone: the account no longer exists
        uint64_t revision = 0;   // identity_revision the state was read at (0: never persisted)

        // An account that may be authorized at all: exists and is active. Every authorization accessor answers
        // "no" for anything else, whatever roles the state still records for display.
        [[nodiscard]] bool authorizing() const noexcept { return !deleted && meta.is_active; }

        // Role shape, regardless of whether the account is authorizing (used to judge an account as a target).
        [[nodiscard]] bool hasSuperAdminRole() const;
        [[nodiscard]] bool hasAdminRole() const;
    };

    // The authorization view of a user: one user state and the states of its live groups, read together so a
    // concurrent multi-object change (e.g. a group's role and a membership in one publication) is seen entirely or
    // not at all. Empty (denies everything) for a non-authorizing user.
    struct AuthzView {
        std::shared_ptr<const UserState> user{};
        std::vector<std::shared_ptr<const GroupState>> groups{};

        [[nodiscard]] bool authorizing() const noexcept { return user && user->authorizing(); }
        [[nodiscard]] const rbac::permission::admin::VaultGlobals* vaultGlobals() const;
        [[nodiscard]] std::shared_ptr<const rbac::role::Vault> directVaultRole(uint32_t vaultId) const;
        [[nodiscard]] bool isSuperAdmin() const;
        [[nodiscard]] bool isAdmin() const;
    };

    // The canonical, stable identity of one account. identities::Manager owns one per user id and hands out the same
    // shared_ptr to every caller; it never replaces the object, it publishes a new UserState into it. Anything holding
    // a shared_ptr<User> (a session, an engine, a request) sees every committed change on its next read, without
    // asking the Manager again. A deleted account keeps its object as a non-authorizing tombstone.
    class User final : public std::enable_shared_from_this<User> {
    public:
        const uint32_t id;

        User(const User&) = delete;
        User& operator=(const User&) = delete;

        // An object outside the Manager (tests, the CLI's synthetic caller for DB-free commands, a user that is about
        // to be created). Never registered, never refreshed.
        [[nodiscard]] static std::shared_ptr<User> detached(uint32_t id, UserState state);

        [[nodiscard]] std::shared_ptr<const UserState> state() const noexcept {
            return state_.load();
        }

        // User + group states read as one coherent version (see AuthzView).
        [[nodiscard]] AuthzView authz() const;

        // Single reads; each takes its own state. Use state() when several fields must agree.
        [[nodiscard]] std::string name() const;
        [[nodiscard]] std::optional<std::string> email() const;
        [[nodiscard]] std::optional<uint32_t> linuxUid() const;
        [[nodiscard]] bool isActive() const;
        [[nodiscard]] bool authorizing() const;
        [[nodiscard]] bool isProtected() const;
        [[nodiscard]] bool systemOnly() const;
        [[nodiscard]] bool deleted() const;

        // Authorization: false / deny-all unless the account is authorizing.
        [[nodiscard]] bool isAdmin() const;
        [[nodiscard]] bool isSuperAdmin() const;

        [[nodiscard]] std::shared_ptr<const rbac::role::Vault> getDirectVaultRole(uint32_t vaultId) const;
        [[nodiscard]] bool hasDirectVaultRole(uint32_t vaultId) const;

        // Admin permission sets (copies of the current state's; empty unless authorizing).
        [[nodiscard]] rbac::permission::admin::Identities identities() const;
        [[nodiscard]] rbac::permission::admin::identities::Users users() const;
        [[nodiscard]] rbac::permission::admin::identities::Admins admins() const;
        [[nodiscard]] rbac::permission::admin::identities::Groups groupPerms() const;
        [[nodiscard]] rbac::permission::admin::roles::Admin adminRolePerms() const;
        [[nodiscard]] rbac::permission::admin::roles::Vault vaultRolePerms() const;
        [[nodiscard]] rbac::permission::admin::Settings settings() const;
        [[nodiscard]] rbac::permission::admin::Audits audits() const;
        [[nodiscard]] rbac::permission::admin::Vaults vaultsPerms() const;
        [[nodiscard]] rbac::permission::admin::VaultGlobals vaultGlobals() const;
        [[nodiscard]] rbac::permission::admin::keys::APIKeys apiKeysPerms() const;
        [[nodiscard]] rbac::permission::admin::keys::EncryptionKey encryptionKeysPerms() const;
        [[nodiscard]] rbac::permission::admin::S3Gateway s3GatewayPerms() const;
        [[nodiscard]] rbac::permission::admin::Stats statsPerms() const;

        // Replaces a detached object's state (tests). Throws for a canonical object: those change only through
        // identities::Manager.
        void replaceDetachedState(UserState next);

    private:
        friend class Manager;

        User(uint32_t id, std::shared_ptr<const UserState> initial, bool detached);

        // Manager only, inside a publication (see identities::detail::Publication).
        void publish(std::shared_ptr<const UserState> next) noexcept { state_.store(std::move(next)); }

        concurrency::AtomicSharedPtr<const UserState> state_;
        const bool detached_;
    };

    [[nodiscard]] UserState stateFromRow(pqxx::row_ref row);

    void to_json(nlohmann::json &j, const User &u);

    nlohmann::json to_public_json(const std::shared_ptr<User> &u);

    nlohmann::json to_public_json(const std::vector<std::shared_ptr<User> > &u);

    nlohmann::json to_json(const std::vector<std::shared_ptr<User> > &users);

    // The list projection (auth.users.list): the user fields of to_json, with admin_role and each vault role reduced
    // to {id, name, description, type, assigned_at} (+ a vault role's assignment). No permission sets; the single
    // user reads (auth.user.get, auth.isAuthenticated) keep them.
    nlohmann::json to_list_json(const std::vector<std::shared_ptr<User> > &users);

    nlohmann::json to_json(const std::shared_ptr<User> &user);

    std::string to_string(const std::shared_ptr<User> &user);

    std::string to_string(const std::vector<std::shared_ptr<User> > &users);
}
