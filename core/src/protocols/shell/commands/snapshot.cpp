// `vh snapshot …`: explicit local snapshots (ops::recovery::createSnapshot / list / deletePoint). Same authorization
// and behaviour as the ws recovery.snapshot.create, recovery.list and recovery.point.delete commands.

#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/commands/recovery.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace vh::protocols::shell::commands::recovery_cli {

namespace {

namespace snrec = vh::ops::recovery;

CommandResult snCreate(const CommandCall& call) {
    const auto usage = resolveUsage({"snapshot", "create"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("snapshot create", [&] {
        nlohmann::json req = {{"path", call.positionals[1]}};
        if (const auto name = optVal(call, "name")) req["name"] = *name;
        return snrec::createSnapshot(call.user, vaultIdFrom(call, usage, "snapshot create"),
                                     snrec::snapshotRequestFromJson(req));
    }, [&](const snrec::PointDetail& d) { return json ? jsonText(d) : "Snapshot taken.\n" + formatDetail(d); });
}

CommandResult snList(const CommandCall& call) {
    const auto usage = resolveUsage({"snapshot", "list"});
    if (call.positionals.empty() || call.positionals.size() > 2) return invalid("snapshot list: expected <vault> [path]");
    const bool json = hasFlag(call, "json");
    return runOp("snapshot list", [&] {
        nlohmann::json q = {{"include_snapshots", true}, {"include_versions", false}, {"include_provider", false}};
        if (call.positionals.size() == 2) q["path"] = call.positionals[1];
        return snrec::list(call.user, vaultIdFrom(call, usage, "snapshot list"), snrec::listQueryFromJson(q));
    }, [&](const std::vector<vh::recovery::RecoveryPoint>& points) {
        return json ? jsonText(points) : (points.empty() ? std::string("No snapshots.\n") : formatPoints(points));
    });
}

CommandResult snDelete(const CommandCall& call) {
    const auto usage = resolveUsage({"snapshot", "delete"});
    validatePositionals(call, usage);
    const auto& id = call.positionals[0];
    if (!id.starts_with("snap-"))
        return invalid("snapshot delete: expected a snapshot id (snap-<id>); delete a local version with "
                       "'vh recovery delete " + id + "'");
    return runConfirmedText(call, "snapshot delete", snrec::POINT_DELETE, "DELETE", [&](const bool confirmed) {
        snrec::deletePoint(call.user, id, confirmed);
        return "Deleted " + id + ".\n";
    });
}

CommandResult snHandle(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"snapshot", "create"}, sub)) return snCreate(subcall);
    if (isCommandMatch({"snapshot", "list"}, sub)) return snList(subcall);
    if (isCommandMatch({"snapshot", "delete"}, sub)) return snDelete(subcall);
    return invalid(call.constructFullArgs(), "Unknown snapshot subcommand: '" + std::string(sub) + "'");
}

}

}

void vh::protocols::shell::commands::registerSnapshotCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("snapshot"), recovery_cli::snHandle);
}
