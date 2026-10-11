#include "CommandUsage.hpp"
#include "db/query/identities/User.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/commands/router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"

#include <sstream>
#include <string>

namespace vh::protocols::shell::commands::setup {

namespace {

constexpr auto* kLifecycleHint =
    "handled by the local lifecycle utility. Re-run this command via the local 'vh' CLI binary.";

}

CommandResult handleAssignAdmin(const CommandCall& call) {
    const auto usage = resolveUsage({"setup", "assign-admin"});
    validatePositionals(call, usage);

    if (!call.user)
        return invalid("setup assign-admin: missing authenticated shell user context");

    if (!call.user->isSuperAdmin())
        return invalid("setup assign-admin: requires super_admin role");

    if (!call.user->linuxUid().has_value())
        return invalid("setup assign-admin: current shell user has no Linux UID mapping");

    const auto admin = vh::identities::manager().userByName("admin");
    if (!admin)
        return invalid("setup assign-admin: admin user record not found");

    const auto callerUid = *call.user->linuxUid();
    if (const auto adminUid = admin->linuxUid(); adminUid.has_value()) {
        if (*adminUid == callerUid) {
            std::ostringstream out;
            out << "setup assign-admin: already assigned\n";
            out << "  admin linux_uid: " << callerUid << "\n";
            out << "  owner: " << call.user->name();
            return ok(out.str());
        }

        std::ostringstream err;
        err << "setup assign-admin: admin linux_uid is already bound to UID "
            << *adminUid
            << " and does not match current operator UID "
            << callerUid
            << ". Refusing to rebind implicitly.";
        return invalid(err.str());
    }

    vh::identities::manager().bindLinuxUid(admin->id, callerUid, call.user->id);

    std::ostringstream out;
    out << "setup assign-admin: assigned\n";
    out << "  admin linux_uid: " << callerUid << "\n";
    out << "  owner: " << call.user->name();
    return ok(out.str());
}

CommandResult handleDb(const CommandCall& call) {
    const auto usage = resolveUsage({"setup", "db"});
    validatePositionals(call, usage);
    return invalid("setup db: " + std::string(kLifecycleHint));
}

CommandResult handleRemoteDb(const CommandCall& call) {
    const auto usage = resolveUsage({"setup", "remote-db"});
    validatePositionals(call, usage);
    return invalid("setup remote-db: " + std::string(kLifecycleHint));
}

}
