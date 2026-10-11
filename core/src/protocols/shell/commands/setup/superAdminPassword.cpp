#include "auth/Bootstrap.hpp"
#include "identities/User.hpp"
#include "ops/Users.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/commands/router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"

#include <sodium.h>

#include <string>

namespace vh::protocols::shell::commands::setup {

namespace {

constexpr auto* kPrefix = "setup set-super-admin-password";

std::string formatResult(const ops::users::SuperAdminPasswordSet& result) {
    std::string out = "Super-admin web password changed for '" + result.user->name() +
                      "'. Its web sessions were ended; sign in again with the new password.\n";
    if (result.leftover_file)
        out += "WARNING: the initial plaintext password file is still on disk (" + *result.leftover_file +
               "). The new password is in effect; remove the file manually:\n  sudo rm -f " +
               auth::bootstrap::initialPasswordFile().string() + "\n";
    return out;
}

}

CommandResult handleSetSuperAdminPassword(const CommandCall& call) {
    const auto usage = resolveUsage({"setup", "set-super-admin-password"});
    validatePositionals(call, usage);

    // Refuse before asking anything of someone who may not run it.
    if (const auto refused = runOp(kPrefix, [&] { (void)ops::users::requireSuperAdminOperator(call.user); },
                                   [] { return std::string{}; });
        refused.exit_code != 0)
        return refused;

    if (!call.io) return invalid(std::string(kPrefix) + ": needs an interactive terminal to ask for the new password");

    auto password = call.io->promptSecret("New web console password for 'admin':");
    auto repeated = call.io->promptSecret("Repeat the new password:");
    const bool matches = password == repeated;
    sodium_memzero(repeated.data(), repeated.size());
    if (password.empty() || !matches) {
        sodium_memzero(password.data(), password.size());
        return invalid(std::string(kPrefix) + (password.empty() ? ": no password given" : ": the passwords do not match") +
                       "; nothing was changed");
    }

    auto result = runOp(kPrefix, [&] { return ops::users::setSuperAdminPassword(call.user, password); }, formatResult);
    sodium_memzero(password.data(), password.size());
    return result;
}

}
