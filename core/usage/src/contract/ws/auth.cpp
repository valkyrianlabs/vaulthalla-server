// ws book: auth.* (core/src/protocols/ws/handler/Auth.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField authUserObject(std::string name = "user") { return object(std::move(name), "User"); }

// The session user (Auth::sessionUser): User with role permissions reduced to {qualified, value}.
WsField authSessionUserObject() { return object("user", "SessionUser"); }

WsField authUserId(std::string name = "id") { return uinteger(std::move(name)).gen(gen::ref("user", {"id"})); }

}

std::vector<WsCommandUsage> authCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "auth.login",
        .description = "Sign in with a username and password. The access token comes back in the response envelope "
                       "(`token`), the refresh token as an HttpOnly cookie set at the handshake.",
        .auth = "session",
        .payload = {str("name").gen(gen::ref("user", {"name"})), str("password")},
        .response = {authSessionUserObject().desc("The signed-in user; role permissions reduced to {qualified, value}.")},
        .refusal_codes = {"error"},
        .operation = "auth.login",
        .client_timeout = 20s,
    });

    out.push_back({
        .command = "auth.logout",
        .description = "End the session (access and refresh tokens).",
        .auth = "session",
        .input = "none",
        .response = {},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.refresh",
        .description = "Issue a new access token from the envelope token or the refresh cookie.",
        .auth = "session",
        .input = "token",
        .response = {authSessionUserObject()},
        .refusal_codes = {"error"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.isAuthenticated",
        .description = "Whether the envelope token is a valid session for this socket.",
        .auth = "session",
        .input = "token",
        .response = {boolean("isAuthenticated"), authSessionUserObject().opt().desc("Present when authenticated.")},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.register",
        .description = "Create a user. role is an admin role name or id; the password is required (only the CLI "
                       "generates one).",
        .payload = {str("name").gen(gen::freshName("user_")),
                    str("email").opt().gen(gen::email()),
                    str("password").gen(gen::bytes(16, 24)),
                    boolean("is_active").opt(),
                    str("role").gen(gen::ref("role.admin", {"name", "id"}))},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .operation = "users.create",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.update",
        .description = "Patch a user (the caller when id is absent). Role changes and deactivation end the account's "
                       "sessions. linux_uid, updated_by, protected, is_protected, system_only and password are refused.",
        .payload = {authUserId().opt().nullable(),
                    str("name").opt().nullable().gen(gen::freshName("user_")),
                    str("email").opt().nullable().gen(gen::email()),
                    str("role").opt().gen(gen::ref("role.admin", {"name", "id"})),
                    boolean("is_active").opt().nullable()},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .operation = "users.update",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.delete",
        .description = "Delete a user. Without confirm the reply is a refusal with data.code 'user_delete' and the "
                       "question to ask. The user's vaults are destroyed unless transfer_to names who gets them.",
        .payload = {authUserId(), boolean("confirm").opt(), authUserId("transfer_to").opt().nullable()},
        .response = {uinteger("user_id")},
        .refusal_codes = {"denied", "invalid", "not_found", "conflict", "unauthorized", "user_delete"},
        .operation = "users.delete",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.change_password",
        .description = "Change (own, with old_password) or reset (another user's) a password.",
        .payload = {authUserId(), str("old_password").opt(), str("new_password").gen(gen::bytes(16, 24))},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.get",
        .description = "One user with its full roles and permissions.",
        .payload = {authUserId()},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.get.byName",
        .description = "One user by name.",
        .payload = {str("name").gen(gen::ref("user", {"name"}))},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.users.list",
        .description = "Users visible to the caller, slim projection (admin_role without permissions).",
        .input = "none",
        .response = {objectArray("users", "UserSummary")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.security.status",
        .description = "Security posture warning for the signed-in account: the super admin's initial password file "
                       "while the generated password is still in use, else null.",
        .input = "none",
        .response = {str("initial_password_file").nullable()},
        .refusal_codes = {"unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
