#pragma once

#include "ops/Actor.hpp"
#include "db/model/ListQueryParams.hpp"
#include "rbac/Fwd.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// User accounts, shared by `vh user ...` and the ws auth.register / auth.user.* commands.
//
// Who may manage an account depends on what the account can do: one whose admin role grants anything beyond the
// self scopes is an admin identity, governed by admin.identities.admins; anyone else is governed by
// admin.identities.users. On top of that, the escalation ceiling: nobody assigns a role that grants admin
// permissions they lack, and nobody changes, deletes or resets the password of an account whose role does.
// super_admin is never assigned, renamed or removed here, and protected accounts are not managed here at all.
namespace vh::ops::users {

using UserPtr = std::shared_ptr<identities::User>;

struct Create {
    std::string name;
    std::string role;                          // admin role name or id
    std::optional<std::string> email{};
    std::optional<std::string> password{};     // absent: generated and returned once
    bool is_active{true};
    std::optional<uint32_t> linux_uid{};
};

struct Created {
    UserPtr user;
    std::optional<std::string> generated_password{};
};

// Absent fields stay as they are.
struct Update {
    uint32_t id{};
    std::optional<std::string> name{};
    std::optional<std::optional<std::string>> email{};   // {{}}: clear it
    std::optional<std::string> role{};
    std::optional<bool> is_active{};
    std::optional<uint32_t> linux_uid{};
};

// True when the role grants any admin permission outside the self scopes.
[[nodiscard]] bool isAdminIdentity(const rbac::role::Admin& role);

// Creates the account and its default vault.
[[nodiscard]] Created create(const Actor& actor, const Create& req);
// Role changes and deactivation end the account's sessions.
UserPtr update(const Actor& actor, const Update& req);
// What deleting an account asks first (#133). NeedsConfirmation code: "user_delete".
inline constexpr const char* USER_DELETE_CONFIRMATION =
    "Are you sure you wish to delete this user? The user's existing vaults will be destroyed unless ownership is "
    "transferred.";

struct Remove {
    uint32_t id{};
    std::optional<uint32_t> transfer_to{};   // give every vault the account owns to this user; absent: destroy them
    bool confirmed{false};                   // false: throw NeedsConfirmation listing what happens to the vaults
};

// Checks every vault first (transfer or remove rights, name clashes), then transfers or destroys them, ends the
// account's sessions and removes it. Returns what was removed.
UserPtr remove(const Actor& actor, const Remove& req);
[[nodiscard]] UserPtr get(const Actor& actor, uint32_t id);
[[nodiscard]] UserPtr getByName(const Actor& actor, const std::string& name);
// The accounts the actor may view.
[[nodiscard]] std::vector<UserPtr> list(const Actor& actor, db::model::ListQueryParams params = {});
// `vh setup set-super-admin-password`: only the account bound to the configured super-admin Linux UID (the 'admin'
// account) may set that account's web password, over the local socket. Throws Denied for anyone else.
UserPtr requireSuperAdminOperator(const Actor& actor);

struct SuperAdminPasswordSet {
    UserPtr user;
    std::optional<std::string> leftover_file;   // the initial plaintext copy could not be removed: why
};

// Sets admin's web password (normal hashing and policy), ends its web sessions, records the rotation and removes the
// initial plaintext copy. A copy that can't be removed is reported, not rolled back.
SuperAdminPasswordSet setSuperAdminPassword(const Actor& actor, const std::string& newPassword);

// Whether `actor` may manage the MFA of account `targetId` (#360: auth.mfa.admin.*, `vh user mfa`): what resetting its
// password needs (admin.identities.users or .admins reset-password, within the actor's ceiling). A super admin's MFA
// only another super admin may manage; protected and system accounts are never managed here. Returns the target.
// Throws Denied / NotFound.
UserPtr requireMfaManager(const Actor& actor, uint32_t targetId);
// The same question without throwing (the CLI's "bound UID or users-manage" rule).
[[nodiscard]] bool mayManageMfa(const Actor& actor, const identities::User& target);

// Your own password needs the current one; anyone else's needs reset-password over them (and ends their sessions).
UserPtr changePassword(const Actor& actor, uint32_t id, const std::optional<std::string>& currentPassword,
                       const std::string& newPassword);

}
