#include "protocols/shell/commands/all.hpp"

#include "ops/Error.hpp"
#include "ops/Mirrors.hpp"
#include "ops/Peers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <functional>
#include <optional>

// `vh mirror ...` (design/peers/mirror.md): parsing and rendering only. Who may, and what changes, is ops::mirrors.
// Minimal by design (wave 3): the polished CLI, the console and Desktop come later.
namespace vh::protocols::shell::commands {

// Named, not anonymous: the unity build joins this file with the other command files of this namespace.
namespace mirror_cli {
namespace {

namespace mirrors = ::vh::ops::mirrors;

std::string mirrorPretty(const nlohmann::json& j) {
    auto out = j.dump(4);
    out.push_back('\n');
    return out;
}

// Like runOp, with a refusal's stable code in front of its sentence ("mirror add: legacy_content: ...").
template <class Op, class Format>
CommandResult runMirrorOp(const std::string& prefix, Op&& op, Format&& format) {
    try {
        return ok(std::invoke(std::forward<Format>(format), std::invoke(std::forward<Op>(op))));
    } catch (const ops::Refused& e) {
        return invalid(prefix + ": " + e.code + ": " + e.what());
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

std::string offerLine(const mirrors::Offer& o) {
    return fmt::format("offer {}  vault \"{}\" ({} file(s), {} bytes) from linked server {}  {} ({}){}\n", o.id, o.name,
                       o.file_count, o.size_bytes, o.peer_id, o.state, mirrors::toJson(o).value("step", ""),
                       o.reason ? " " + *o.reason : std::string());
}

std::string mirroredText(const mirrors::Mirrored& m) {
    const auto j = mirrors::toJson(m);
    std::string out = fmt::format("vault {} \"{}\": {}", m.vault_id, m.vault_name, m.role);
    if (m.peer) out += fmt::format(" with linked server {} (\"{}\", node {})", m.peer->id, m.peer->name, m.peer->node_id);
    out += "\n";
    if (m.row) {
        out += fmt::format("  term {}, last seq {}, state {}\n", m.row->term, m.row->last_seq, m.row->state);
        if (m.row->role != "core")
            out += m.row->grant ? fmt::format("  granted: '{}' by {}\n", m.row->grant->role_name, m.row->grant->granted_by_node)
                                : std::string("  granted: nothing yet (nobody here has access)\n");
    }
    if (m.start)
        out += fmt::format("  start: offer {} {} ({}){}\n", m.start->id, m.start->state, j["start"].value("step", ""),
                           m.start->reason ? ", " + *m.start->reason : std::string());
    if (m.start && m.start->side == "core" && m.start->state == "cancelled")
        out += fmt::format("  ended here{}; the linked server's copy: {}\n",
                           m.start->remove_copy ? " (its removal asked)" : "",
                           m.start->copy_outcome.value_or(m.start->notify ? "not told yet" : "unknown"));
    if (m.row && m.row->role == "orphaned")
        out += fmt::format("  an orphaned copy: its core ended the mirror; remove it with vh mirror cancel {}\n", m.vault_id);
    return out;
}

CommandResult handleAdd(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "add"}));
    const auto json = hasFlag(call, "json");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault) return invalid("mirror add: the vault is its number (vh vault list)");
    const auto to = optVal(call, "to");
    if (!to) return invalid("mirror add: --to <linked server> is required");
    return runMirrorOp("mirror add",
                       [&] { return mirrors::add(call.user, {.vault_id = static_cast<uint32_t>(*vault), .peer = *to}); },
                       [&](const mirrors::Offer& o) {
                           return json ? mirrorPretty(mirrors::toJson(o))
                                       : fmt::format("Offered vault {} to linked server {} (offer {}). It starts once "
                                                     "that server accepts (vh mirror info {}).\n",
                                                     *vault, o.peer_id, o.id, *vault);
                       });
}

CommandResult handlePending(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "pending"}));
    const auto json = hasFlag(call, "json");
    return runMirrorOp("mirror pending", [&] { return mirrors::pending(call.user); },
                       [&](const std::vector<mirrors::Offer>& list) {
                           if (json) {
                               nlohmann::json offers = nlohmann::json::array();
                               for (const auto& o : list) offers.push_back(mirrors::toJson(o));
                               return mirrorPretty({{"offers", std::move(offers)}});
                           }
                           if (list.empty()) return std::string("No offers wait here.\n");
                           std::string out;
                           for (const auto& o : list) out += offerLine(o);
                           return out;
                       });
}

CommandResult handleDecision(const CommandCall& call, const bool acceptIt) {
    const auto* name = acceptIt ? "accept" : "decline";
    validatePositionals(call, resolveUsage({"mirror", name}));
    const auto json = hasFlag(call, "json");
    const auto& ref = call.positionals.at(0);
    return runMirrorOp(std::string("mirror ") + name,
                       [&] { return acceptIt ? mirrors::accept(call.user, ref) : mirrors::decline(call.user, ref); },
                       [&](const mirrors::Offer& o) {
                           return json ? mirrorPretty(mirrors::toJson(o))
                                       : fmt::format("Offer {} {}.\n", o.id, acceptIt ? "accepted: the keys come next"
                                                                                      : "declined");
                       });
}

CommandResult handleCancel(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "cancel"}));
    const auto json = hasFlag(call, "json");
    mirrors::CancelRequest req;
    if (const auto v = parseUInt(call.positionals.at(0)); v && *v > 0) req.vault_id = static_cast<uint32_t>(*v);
    req.offer = optVal(call, "offer");
    req.remove_copy = hasFlag(call, "remove-copy");
    return runMirrorOp("mirror cancel", [&] { return mirrors::cancel(call.user, req); },
                       [&](const mirrors::Cancelled& c) {
                           if (json) return mirrorPretty(mirrors::toJson(c));
                           if (c.side == "core")
                               return fmt::format("Ended the mirror of vault {} here. The linked server is told (when "
                                                  "it is reachable){}; vh mirror info {} shows what it did.\n",
                                                  c.vault_id.value_or(0),
                                                  c.remove_copy ? " and asked to remove its copy"
                                                                : " and keeps its copy, orphaned",
                                                  c.vault_id.value_or(0));
                           return std::string(c.removed ? "Cancelled: the vault and its keys were removed here; the core "
                                                          "is told.\n"
                                                        : "Cancelled; the core is told.\n");
                       });
}

CommandResult handleList(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "list"}));
    const auto json = hasFlag(call, "json");
    return runMirrorOp("mirror list", [&] { return mirrors::list(call.user); },
                       [&](const std::vector<mirrors::Mirrored>& list) {
                           if (json) {
                               nlohmann::json vaults = nlohmann::json::array();
                               for (const auto& m : list) vaults.push_back(mirrors::toJson(m));
                               return mirrorPretty({{"vaults", std::move(vaults)}});
                           }
                           if (list.empty()) return std::string("No mirrored vaults and no starts here.\n");
                           std::string out;
                           for (const auto& m : list) out += mirroredText(m);
                           return out;
                       });
}

CommandResult handleInfo(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "info"}));
    const auto json = hasFlag(call, "json");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault) return invalid("mirror info: the vault is its number (vh vault list)");
    return runMirrorOp("mirror info", [&] { return mirrors::get(call.user, static_cast<uint32_t>(*vault)); },
                       [&](const mirrors::Mirrored& m) {
                           return json ? mirrorPretty({{"vault", mirrors::toJson(m)}}) : mirroredText(m);
                       });
}

CommandResult handleAcceptAll(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "accept-all"}));
    const auto json = hasFlag(call, "json");
    const auto& peerRef = call.positionals.at(0);
    const auto& state = call.positionals.at(1);
    if (state != "on" && state != "off") return invalid("mirror accept-all: the state is on or off");
    return runMirrorOp("mirror accept-all", [&] { return mirrors::setAcceptAll(call.user, peerRef, state == "on"); },
                       [&](const ::vh::db::query::mirror::AcceptVaults& a) {
                           if (json) return mirrorPretty(mirrors::toJson(a, ::vh::ops::peers::resolveRef(peerRef)));
                           return std::string(a.enabled ? "Every vault that server offers is accepted here now.\n"
                                                        : "Offers from that server wait for a super admin here.\n");
                       });
}

CommandResult handleKeep(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "keep-removed"}));
    const auto json = hasFlag(call, "json");
    const auto& peerRef = call.positionals.at(0);
    const auto& state = call.positionals.at(1);
    if (state != "on" && state != "off") return invalid("mirror keep-removed: the state is on or off");
    return runMirrorOp("mirror keep-removed", [&] { return mirrors::setKeepRemoved(call.user, peerRef, state == "on"); },
                       [&](const ::vh::db::query::mirror::AcceptVaults& a) {
                           if (json) return mirrorPretty(mirrors::toJson(a, ::vh::ops::peers::resolveRef(peerRef)));
                           return std::string(a.enabled ? "Vaults that server removes are kept here, orphaned.\n"
                                                        : "Vaults that server removes are removed here when it asks.\n");
                       });
}

CommandResult handleMirror(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"mirror", name}, sub); };
    if (is("add")) return handleAdd(subcall);
    if (is("pending")) return handlePending(subcall);
    if (is("accept")) return handleDecision(subcall, true);
    if (is("decline")) return handleDecision(subcall, false);
    if (is("cancel")) return handleCancel(subcall);
    if (is("list")) return handleList(subcall);
    if (is("info")) return handleInfo(subcall);
    if (is("accept-all")) return handleAcceptAll(subcall);
    if (is("keep-removed")) return handleKeep(subcall);
    return invalid(call.constructFullArgs(), "Unknown mirror subcommand: '" + std::string(sub) + "'");
}

}
}

void registerMirrorCommands(const std::shared_ptr<Router>& r) {
    r->registerCommand(runtime::Deps::get().shellUsageManager->resolve("mirror"), mirror_cli::handleMirror);
}

}
