#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "identities/User.hpp"
#include "ops/Mfa.hpp"
#include "ops/Users.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace vh::protocols::shell::commands {

namespace {

std::optional<uint32_t> linuxUidFromOption(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage) {
    const auto value = optVal(call, usage->resolveOptional("linux-uid")->option_tokens);
    if (!value) return std::nullopt;
    const auto parsed = parseUInt(*value);
    if (!parsed || *parsed == 0) throw ops::Invalid("--linux-uid must be a positive integer");
    return *parsed;
}

// The positional names a user by name or id; ops decide what the caller may see of it.
std::optional<uint32_t> userIdFromPositional(const std::string& arg) {
    const auto lookup = resolveUser(arg, "");
    if (!lookup || !lookup.ptr) return std::nullopt;
    return lookup.ptr->id;
}

CommandResult userNotFound(const std::string_view prefix, const std::string& arg) {
    return invalid(std::string(prefix) + ": user not found: " + arg);
}

CommandResult createUser(const CommandCall& call) {
    const auto usage = resolveUsage({"user", "create"});
    validatePositionals(call, usage);
    return runOp("user create", [&] {
        const auto role = optVal(call, usage->resolveRequired("role")->option_tokens);
        if (!role) throw ops::Invalid("--role is required");
        return ops::users::create(call.user, {
            .name = call.positionals[0],
            .role = *role,
            .email = optVal(call, usage->resolveOptional("email")->option_tokens),
            .linux_uid = linuxUidFromOption(call, usage)
        });
    }, [](const ops::users::Created& created) {
        std::string out = "User created successfully: " + identities::to_string(created.user) + "\n";
        if (created.generated_password) out += "Password: " + *created.generated_password + "\n";
        return out;
    });
}

CommandResult updateUser(const CommandCall& call) {
    const auto usage = resolveUsage({"user", "update"});
    validatePositionals(call, usage);
    const auto id = userIdFromPositional(call.positionals[0]);
    if (!id) return userNotFound("user update", call.positionals[0]);
    return runOp("user update", [&] {
        if (hasFlag(call, "disable") && hasFlag(call, "enable")) throw ops::Invalid("--disable and --enable are mutually exclusive");
        ops::users::Update req{
            .id = *id,
            .name = optVal(call, usage->resolveOptional("name")->option_tokens),
            .role = optVal(call, usage->resolveOptional("role")->option_tokens),
            .linux_uid = linuxUidFromOption(call, usage)
        };
        if (const auto email = optVal(call, usage->resolveOptional("email")->option_tokens))
            req.email = std::optional<std::string>{*email};
        if (hasFlag(call, "disable")) req.is_active = false;
        if (hasFlag(call, "enable")) req.is_active = true;
        return ops::users::update(call.user, req);
    }, [](const ops::users::UserPtr& user) {
        return "User updated successfully: " + user->name() + "\n" + identities::to_string(user);
    });
}

CommandResult deleteUser(const CommandCall& call) {
    const auto usage = resolveUsage({"user", "delete"});
    validatePositionals(call, usage);
    const auto id = userIdFromPositional(call.positionals[0]);
    if (!id) return userNotFound("user delete", call.positionals[0]);

    ops::users::Remove req{.id = *id, .confirmed = hasFlag(call, "yes")};
    if (const auto heir = optVal(call, "transfer-to")) {
        const auto heirId = userIdFromPositional(*heir);
        if (!heirId) return userNotFound("user delete --transfer-to", *heir);
        req.transfer_to = *heirId;
    }
    const auto format = [](const ops::users::UserPtr& user) { return "User deleted successfully: " + user->name(); };
    try {
        return ok(format(ops::users::remove(call.user, req)));
    } catch (const ops::NeedsConfirmation& e) {
        if (!call.io) {
            noteConfirmationNeeded(e.code, {"--yes"});
            return invalid("user delete: " + std::string(e.what()) + "\nRe-run with --yes to confirm.");
        }
        if (!call.io->confirm(std::string(e.what()) + "\nDelete this user? [no]", true))
            return invalid("user delete: cancelled; nothing was changed");
        req.confirmed = true;
        return runOp("user delete", [&] { return ops::users::remove(call.user, req); }, format);
    } catch (const ops::Error& e) {
        return invalid("user delete: " + std::string(e.what()));
    }
}

CommandResult userInfo(const CommandCall& call) {
    const auto usage = resolveUsage({"user", "info"});
    validatePositionals(call, usage);
    const auto id = userIdFromPositional(call.positionals[0]);
    if (!id) return userNotFound("user info", call.positionals[0]);
    return runOp("user info", [&] { return ops::users::get(call.user, *id); },
                 [](const ops::users::UserPtr& user) { return identities::to_string(user); });
}

CommandResult listUsers(const CommandCall& call) {
    return runOp("user list", [&] { return ops::users::list(call.user, parseListQuery(call)); },
                 [](const std::vector<ops::users::UserPtr>& users) { return identities::to_string(users); });
}

// ---- vh user mfa (#360; ops/Mfa.hpp) -------------------------------------------------------------------------------

std::string mfaStatusText(const std::string& name, const ops::mfa::Status& st) {
    std::string out = "MFA for " + name + ": " + (st.required ? "required (" + st.reason + ")" : "not required") + "\n";
    if (st.required_flag) out += "  Required for this account (vh user mfa require).\n";
    if (st.factors.empty()) out += "  No sign-in factors.\n";
    for (const auto& f : st.factors)
        out += "  " + f.value("kind", std::string{}) + " #" + std::to_string(f.value("id", 0u)) + "  " +
               f.value("label", std::string{}) + (f.value("suspended", false) ? "  (suspended)" : "") +
               (f.value("allowed", true) ? "" : "  (not allowed by the policy)") +
               (f.value("created_during_recovery", false) ? "  (enrolled during recovery)" : "") + "\n";
    out += "  Recovery codes: " + (st.recovery_active ? std::to_string(st.recovery_remaining) + " left" : "none") + "\n";
    if (st.cooldown_until) out += "  Recovery cooldown until " + std::to_string(*st.cooldown_until) + " (Unix time)\n";
    return out;
}

CommandResult mfaStatus(const CommandCall& call) {
    const auto usage = resolveUsage({"user", "mfa", "status"});
    validatePositionals(call, usage);
    const auto id = userIdFromPositional(call.positionals[0]);
    if (!id) return userNotFound("user mfa status", call.positionals[0]);
    const bool json = hasFlag(call, usage->resolveFlag("json_output")->aliases);
    const auto name = call.positionals[0];
    return runOp("user mfa status", [&] { return ops::mfa::status(call.user, *id, ops::mfa::Channel::Cli); },
                 [&](const ops::mfa::Status& st) {
                     return json ? nlohmann::json(st).dump(2) + "\n" : mfaStatusText(name, st);
                 });
}

CommandResult mfaRequire(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"user", "mfa", "require"}));
    const auto id = userIdFromPositional(call.positionals[0]);
    if (!id) return userNotFound("user mfa require", call.positionals[0]);
    const bool required = !hasFlag(call, "off");
    return runOp("user mfa require", [&] {
        ops::mfa::require(call.user, *id, required, ops::mfa::Channel::Cli);
        return ops::mfa::status(call.user, *id, ops::mfa::Channel::Cli);
    }, [&](const ops::mfa::Status& st) { return mfaStatusText(call.positionals[0], st); });
}

CommandResult mfaReset(const CommandCall& call) {
    const auto usage = resolveUsage({"user", "mfa", "reset"});
    validatePositionals(call, usage);
    const auto id = userIdFromPositional(call.positionals[0]);
    if (!id) return userNotFound("user mfa reset", call.positionals[0]);
    const auto reason = optVal(call, usage->resolveOptional("reason")->option_tokens)
                            .value_or("host recovery (vh user mfa reset)");
    const auto name = call.positionals[0];
    if (!hasFlag(call, "yes")) {
        const auto question = "Reset the MFA of '" + name + "'? Their passkeys, authenticator apps and recovery "
                              "codes stop working and every session is signed out. [no]";
        if (!call.io) {
            noteConfirmationNeeded("mfa_reset", {"--yes"});
            return invalid("user mfa reset: this disables every sign-in factor of '" + name +
                           "'.\nRe-run with --yes to confirm.");
        }
        if (!call.io->confirm(question, true)) return invalid("user mfa reset: cancelled; nothing was changed");
    }
    return runOp("user mfa reset", [&] { return ops::mfa::reset(call.user, *id, reason, ops::mfa::Channel::Cli); },
                 [&](const auth::mfa::recovery::ResetEffects& e) {
                     return "MFA reset for " + name + ": " + std::to_string(e.factors_disabled) +
                            " factor(s) disabled, " + std::to_string(e.sessions_revoked) + " session(s) signed out, " +
                            std::to_string(e.grants_revoked) + " device key backup(s) paused.\n" + name +
                            " sets up a new second factor at the next sign-in; sensitive changes wait until the "
                            "recovery cooldown ends (Unix time " + std::to_string(e.cooldown_until) + ").\n";
                 });
}

CommandResult handleUserMfa(const CommandCall& call) {
    if (call.positionals.empty() || hasFlag(call, "h") || hasFlag(call, "help"))
        return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"user", "mfa", "status"}, sub)) return mfaStatus(subcall);
    if (isCommandMatch({"user", "mfa", "reset"}, sub)) return mfaReset(subcall);
    if (isCommandMatch({"user", "mfa", "require"}, sub)) return mfaRequire(subcall);
    return invalid(call.constructFullArgs(), "Unknown user mfa subcommand: '" + std::string(sub) + "'");
}

bool isUserMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"user", cmd}, input);
}

CommandResult handleUser(const CommandCall& call) {
    if (call.positionals.empty() || hasFlag(call, "h") || hasFlag(call, "help"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);

    if (isUserMatch("create", sub)) return createUser(subcall);
    if (isUserMatch("delete", sub)) return deleteUser(subcall);
    if (isUserMatch("info", sub)) return userInfo(subcall);
    if (isUserMatch("update", sub)) return updateUser(subcall);
    if (isUserMatch("list", sub) || isUserMatch("ls", sub)) return listUsers(subcall);
    if (isUserMatch("mfa", sub)) return handleUserMfa(subcall);

    return invalid(call.constructFullArgs(), "Unknown user subcommand: '" + std::string(sub) + "'");
}

}

void registerUserCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("user"), handleUser);
}

}
