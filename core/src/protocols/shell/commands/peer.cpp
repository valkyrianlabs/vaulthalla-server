#include "protocols/shell/commands/all.hpp"

#include "config/Registry.hpp"
#include "device/Crypto.hpp"
#include "ops/Error.hpp"
#include "ops/Peers.hpp"
#include "peer/Links.hpp"
#include "peer/Peer.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <set>
#include <thread>

// `vh peer ...` (design/peers/link.md): parsing and rendering only. Who may, and what changes, is ops::peers.
namespace vh::protocols::shell::commands {

// Named, not anonymous: the unity build joins this file with the other command files of this namespace.
namespace peer_cli {
namespace {

namespace peers = ::vh::ops::peers;
using vh::peer::Record;

std::string clock(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
    return buf;
}

std::string pretty(const nlohmann::json& j) {
    auto out = j.dump(4);
    out.push_back('\n');
    return out;
}

std::string codes(const std::array<std::string, 3>& choices) {
    return fmt::format("[1] {}   [2] {}   [3] {}", vh::device::crypto::displayCode(choices[0]),
                       vh::device::crypto::displayCode(choices[1]), vh::device::crypto::displayCode(choices[2]));
}

std::string describeRequest(const vh::peer::PendingLink& r) {
    return fmt::format("Link request {} from server \"{}\" (node {}, Vaulthalla {}) at {}\n  key {}\n", r.request_id,
                       r.name, r.node_id, r.product_version.empty() ? "?" : r.product_version, r.source_ip,
                       r.spki_sha256);
}

std::string healthText(const vh::peer::Health& h) {
    if (h.connected)
        return fmt::format("connected since {} ({} dialled{}{})", clock(h.since.value_or(0)),
                           h.dialed_by == "peer" ? "it" : "this server", h.rtt_ms ? fmt::format(", {} ms", *h.rtt_ms) : "",
                           h.protocol_compatible == false ? ", other protocol: upgrade one of them" : "");
    std::string out = "not connected";
    if (h.last_error) out += ": " + *h.last_error;
    if (h.next_attempt_at) out += " (next try " + clock(*h.next_attempt_at) + ")";
    return out;
}

nlohmann::json linkedJson(const peers::Linked& l) {
    nlohmann::json j = l.record;
    j["health"] = vh::peer::toJson(l.health);
    return j;
}

nlohmann::json pendingJson(const peers::PendingLinks& list) {
    nlohmann::json requests = nlohmann::json::array();
    for (const auto& r : list.requests)
        requests.push_back({{"request_id", r.request_id}, {"node_id", r.node_id}, {"name", r.name},
                            {"product_version", r.product_version}, {"spki_sha256", r.spki_sha256},
                            {"source_ip", r.source_ip}, {"code_choices", r.code_choices},
                            {"created_at", static_cast<int64_t>(r.created_at)},
                            {"expires_at", static_cast<int64_t>(r.expires_at)}});
    return {{"window", list.window ? nlohmann::json{{"expires_at", static_cast<int64_t>(list.window->expires_at)}}
                                   : nlohmann::json(nullptr)},
            {"requests", std::move(requests)}};
}

struct Choice {
    enum class Kind { Approve, Deny, Skip } kind = Kind::Skip;
    std::string code{};
};

Choice askForCode(SocketIO& io, const vh::peer::PendingLink& r) {
    const auto answer = io.prompt(fmt::format("Which code does the other server show?  {}\n(1-3 or the code; d = deny, "
                                              "Enter = skip):",
                                              codes(r.code_choices)),
                                  "");
    std::string trimmed;
    for (const char c : answer)
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') trimmed.push_back(c);
    if (trimmed.empty() || trimmed == "s" || trimmed == "S") return {};
    if (trimmed == "d" || trimmed == "D") return {.kind = Choice::Kind::Deny};
    if (trimmed == "1" || trimmed == "2" || trimmed == "3")
        return {.kind = Choice::Kind::Approve, .code = r.code_choices[static_cast<std::size_t>(trimmed[0] - '1')]};
    return {.kind = Choice::Kind::Approve, .code = trimmed};
}

std::string windowText(const peers::OpenWindow& w) {
    std::string out = fmt::format("Window for linking a server open until {}.\nThis server: \"{}\", node {}\n  key {}\n",
                                  clock(w.window.expires_at), w.name, w.node_id, w.spki_sha256);
    if (w.endpoints.candidates.empty()) out += "  (the device listener advertises no address yet)\n";
    for (const auto& c : w.endpoints.candidates)
        out += fmt::format("  reachable at {}:{} ({})\n",
                           c.host.find(':') != std::string::npos ? "[" + c.host + "]" : c.host, c.port,
                           protocols::device::endpoints::to_string(c.kind));
    out += "On the other server run `vh peer link <address>`, then pick the code it shows here.\n";
    return out;
}

nlohmann::json windowJson(const peers::OpenWindow& w) {
    nlohmann::json candidates = nlohmann::json::array();
    for (const auto& c : w.endpoints.candidates)
        candidates.push_back({{"host", c.host}, {"port", c.port},
                              {"kind", std::string(protocols::device::endpoints::to_string(c.kind))}});
    return {{"window", {{"opened_at", static_cast<int64_t>(w.window.opened_at)},
                        {"expires_at", static_cast<int64_t>(w.window.expires_at)}}},
            {"node_id", w.node_id}, {"name", w.name}, {"spki_sha256", w.spki_sha256},
            {"port", w.endpoints.port}, {"listening", w.endpoints.listening}, {"candidates", std::move(candidates)}};
}

// Interactive `vh peer pair`: wait for requests and settle each by number matching; ends on the first link, when the
// window closes, or when the client hangs up.
CommandResult waitAndApprove(const CommandCall& call) {
    auto& io = *call.io;
    std::set<std::string> seen;
    io.print("Waiting for the other server... (Ctrl-C to stop)\n");
    for (;;) {
        if (!io.peerConnected()) {
            try {
                (void)peers::closeWindow(call.user);
            } catch (const ops::Error&) {
            }
            return invalid("peer pair: stopped");
        }
        peers::PendingLinks list;
        try {
            list = peers::pending(call.user);
        } catch (const ops::Error& e) {
            return invalid(std::string("peer pair: ") + e.what());
        }
        if (!list.window) return invalid("peer pair: the window closed (it lasts 10 minutes); run `vh peer pair` again");
        for (const auto& r : list.requests) {
            if (!seen.insert(r.request_id).second) continue;
            io.print(describeRequest(r));
            const auto choice = askForCode(io, r);
            try {
                if (choice.kind == Choice::Kind::Deny) {
                    peers::deny(call.user, r.request_id);
                    io.print("Denied.\n");
                } else if (choice.kind == Choice::Kind::Approve) {
                    const auto row = peers::approve(call.user, r.request_id, choice.code, std::nullopt);
                    return ok(fmt::format("Linked: \"{}\" (node {}, peer {}).\n", row.name, row.node_id, row.id));
                } else {
                    io.print("Skipped; approve it later with `vh peer approve " + r.request_id + "`.\n");
                }
            } catch (const ops::Error& e) {
                io.print(std::string("Not linked: ") + e.what() + "\n");
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

CommandResult handlePair(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "pair"}));
    const bool json = hasFlag(call, "json");
    if (hasFlag(call, "close"))
        return runOp("peer pair", [&] { return peers::closeWindow(call.user); }, [&](const bool closed) {
            if (json) return pretty({{"closed", closed}});
            return std::string(closed ? "Window closed; its requests expired.\n" : "No window of yours was open.\n");
        });
    peers::OpenWindow opened;
    try {
        opened = peers::openWindow(call.user);
    } catch (const ops::Error& e) {
        return invalid(std::string("peer pair: ") + e.what());
    }
    if (json) return ok(pretty(windowJson(opened)));
    if (!call.io) return ok(windowText(opened) + "Approve it with `vh peer pending`, then `vh peer approve <request> --code <code>`.\n");
    call.io->print(windowText(opened));
    return waitAndApprove(call);
}

CommandResult handlePending(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "pending"}));
    const bool json = hasFlag(call, "json");
    return runOp("peer pending", [&] { return peers::pending(call.user); }, [&](const peers::PendingLinks& list) {
        if (json) return pretty(pendingJson(list));
        if (!list.window) return std::string("No window of yours is open (`vh peer pair` opens one).\n");
        std::string out = fmt::format("Window open until {}.\n", clock(list.window->expires_at));
        if (list.requests.empty()) return out + "No server has asked to link yet.\n";
        for (const auto& r : list.requests) out += describeRequest(r) + "  codes " + codes(r.code_choices) + "\n";
        return out;
    });
}

CommandResult handleApprove(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "approve"}));
    const auto& requestId = call.positionals.at(0);
    const auto fingerprint = optVal(call, "fingerprint");
    auto code = optVal(call, "code");
    if (!code) {
        if (!call.io) return invalid("peer approve: --code is required when not interactive");
        peers::PendingLinks list;
        try {
            list = peers::pending(call.user);
        } catch (const ops::Error& e) {
            return invalid(std::string("peer approve: ") + e.what());
        }
        const auto it = std::ranges::find(list.requests, requestId, &vh::peer::PendingLink::request_id);
        if (it == list.requests.end())
            return invalid("peer approve: no pending link request '" + requestId + "' (it may have expired)");
        call.io->print(describeRequest(*it));
        const auto choice = askForCode(*call.io, *it);
        if (choice.kind == Choice::Kind::Skip) return invalid("peer approve: nothing approved");
        if (choice.kind == Choice::Kind::Deny)
            return runOp("peer approve", [&] { peers::deny(call.user, requestId); }, [] { return std::string("Denied.\n"); });
        code = choice.code;
    }
    return runOp("peer approve", [&] { return peers::approve(call.user, requestId, *code, fingerprint); },
                 [](const Record& r) { return fmt::format("Linked: \"{}\" (node {}, peer {}).\n", r.name, r.node_id, r.id); });
}

CommandResult handleDeny(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "deny"}));
    return runOp("peer deny", [&] { peers::deny(call.user, call.positionals.at(0)); },
                 [] { return std::string("Denied.\n"); });
}

std::string attemptText(const vh::peer::LinkAttempt& a) {
    std::string out;
    if (a.peer_card)
        out += fmt::format("Server \"{}\" (node {}, Vaulthalla {}) at {}\n  key {}\n", a.peer_card->name,
                           a.peer_card->node_id, a.peer_card->product_version, a.address, a.peer_spki_sha256);
    if (a.code) out += fmt::format("Code: {}  (pick it on the other server)\n", vh::device::crypto::displayCode(*a.code));
    return out;
}

CommandResult handleLink(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "link"}));
    const bool json = hasFlag(call, "json");
    const auto port = config::Registry::get().device_server.port;
    const auto endpoint = vh::peer::parseAddress(call.positionals.at(0), port == 0 ? 36972 : port);
    if (!endpoint) return invalid("peer link: '" + call.positionals.at(0) + "' is not host, host:port or [v6]:port");
    const auto fingerprint = optVal(call, "fingerprint");
    vh::peer::LinkAttempt a;
    try {
        a = peers::linkStart(call.user, {*endpoint}, fingerprint);
        // Until there is a code to show (or it failed): a few seconds at most.
        for (int i = 0; i < 300 && !a.code && !a.finished(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            a = peers::linkStatus(call.user, a.id);
        }
    } catch (const ops::Error& e) {
        return invalid(std::string("peer link: ") + e.what());
    }
    if (a.finished() && a.state != "linked")
        return invalid(fmt::format("peer link: {}{}", a.state, a.error.empty() ? "" : ": " + a.error));
    if (json || !call.io) return ok(json ? pretty(vh::peer::toJson(a)) : attemptText(a) + "Waiting for its approval (`vh peer list` shows the link once made).\n");
    call.io->print(attemptText(a) + "Waiting for the other server's approval... (Ctrl-C to cancel)\n");
    for (;;) {
        if (!call.io->peerConnected()) {
            try {
                (void)peers::linkCancel(call.user, a.id);
            } catch (const ops::Error&) {
            }
            return invalid("peer link: cancelled");
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        try {
            a = peers::linkStatus(call.user, a.id);
        } catch (const ops::Error& e) {
            return invalid(std::string("peer link: ") + e.what());
        }
        if (!a.finished()) continue;
        if (a.state == "linked")
            return ok(fmt::format("Linked: \"{}\" (node {}, peer {}).\n", a.peer_card ? a.peer_card->name : "?",
                                  a.peer_card ? a.peer_card->node_id : "?", a.peer_id.value_or(0)));
        return invalid(fmt::format("peer link: {}{}", a.state, a.error.empty() ? "" : ": " + a.error));
    }
}

CommandResult handleList(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "list"}));
    const bool json = hasFlag(call, "json");
    const bool all = hasFlag(call, "all");
    return runOp("peer list", [&] { return peers::list(call.user, all); }, [&](const std::vector<peers::Linked>& list) {
        if (json) {
            nlohmann::json out = nlohmann::json::array();
            for (const auto& l : list) out.push_back(linkedJson(l));
            return pretty({{"peers", std::move(out)}});
        }
        if (list.empty()) return std::string("No linked servers.\n");
        Table table({{.header = "#", .align = Align::Right}, {.header = "Name"}, {.header = "Node"}, {.header = "Key"},
                     {.header = "Version"}, {.header = "Link"}});
        for (const auto& l : list)
            table.add_row({std::to_string(l.record.id), l.record.name, l.record.node_id, l.record.shortId(),
                           l.record.product_version,
                           l.record.revoked() ? "unlinked " + clock(*l.record.revoked_at) : healthText(l.health)});
        return table.render();
    });
}

CommandResult handleInfo(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "info"}));
    const bool json = hasFlag(call, "json");
    return runOp("peer info", [&] { return peers::get(call.user, call.positionals.at(0)); }, [&](const peers::Linked& l) {
        if (json) return pretty(linkedJson(l));
        const auto& r = l.record;
        std::string out = fmt::format("Linked server {}: \"{}\"\n  node        {}\n  key         {}\n", r.id, r.name, r.node_id,
                                      r.spki_sha256);
        if (r.next_spki_sha256) out += fmt::format("  next key    {} (announced)\n", *r.next_spki_sha256);
        out += fmt::format("  version     {} (peer protocol {})\n  linked      {} (code compared by {})\n",
                           r.product_version.empty() ? "?" : r.product_version, r.peer_protocol, clock(r.linked_at),
                           r.compared_by);
        out += fmt::format("  sharing     {}\n  link        {}\n", r.sharing,
                           r.revoked() ? "unlinked " + clock(*r.revoked_at) : healthText(l.health));
        for (const auto& e : r.endpoints) out += fmt::format("  endpoint    {} ({})\n", vh::peer::toString(e), e.kind);
        return out;
    });
}

CommandResult handleRename(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "rename"}));
    return runOp("peer rename", [&] { return peers::rename(call.user, call.positionals.at(0), call.positionals.at(1)); },
                 [](const Record& r) { return fmt::format("Renamed: linked server {} is \"{}\".\n", r.id, r.name); });
}

CommandResult handleUnlink(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"peer", "unlink"}));
    return runOp("peer unlink", [&] { return peers::unlink(call.user, call.positionals.at(0)); },
                 [](const Record& r) {
                     return fmt::format("Unlinked: \"{}\" (node {}). Linking it again needs a new pairing.\n", r.name,
                                        r.node_id);
                 });
}

CommandResult handlePeer(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"peer", name}, sub); };
    if (is("pair")) return handlePair(subcall);
    if (is("pending")) return handlePending(subcall);
    if (is("approve")) return handleApprove(subcall);
    if (is("deny")) return handleDeny(subcall);
    if (is("link")) return handleLink(subcall);
    if (is("list")) return handleList(subcall);
    if (is("info")) return handleInfo(subcall);
    if (is("rename")) return handleRename(subcall);
    if (is("unlink")) return handleUnlink(subcall);
    return invalid(call.constructFullArgs(), "Unknown peer subcommand: '" + std::string(sub) + "'");
}

}
}

void registerPeerCommands(const std::shared_ptr<Router>& r) {
    r->registerCommand(runtime::Deps::get().shellUsageManager->resolve("peer"), peer_cli::handlePeer);
}

}
