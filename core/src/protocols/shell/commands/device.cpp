#include "protocols/shell/commands/all.hpp"

#include "device/Crypto.hpp"
#include "identities/User.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "protocols/device/Service.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"
#include "config/Registry.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <set>
#include <thread>

// `vh device ...`: parsing and rendering only. Who may do what, and what it changes, is ops::devices.
namespace vh::protocols::shell::commands {

// Named, not anonymous: the unity build joins this file with the other command files of this namespace.
namespace device_cli {
namespace {

namespace devices = ::vh::ops::devices;
using vh::device::Device;

std::string utc(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

std::string clockUtc(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[16]{};
    std::strftime(buf, sizeof(buf), "%H:%M:%S UTC", &tm);
    return buf;
}

std::string jsonText(const nlohmann::json& j) {
    auto out = j.dump(4);
    out.push_back('\n');
    return out;
}

std::string choicesLine(const std::array<std::string, 3>& choices) {
    return fmt::format("[1] {}   [2] {}   [3] {}", vh::device::crypto::displayCode(choices[0]),
                       vh::device::crypto::displayCode(choices[1]), vh::device::crypto::displayCode(choices[2]));
}

std::string describeRequest(const vh::device::PendingRequest& r) {
    return fmt::format("Pairing request {} from \"{}\" ({}{}) at {}\n  device id {}\n", r.request_id, r.name,
                       r.platform, r.app_version.empty() ? "" : " " + r.app_version, r.source_ip, r.device_id);
}

std::string describeDevice(const Device& d) {
    return fmt::format("\"{}\" (device {}, id {}) for {}", d.name, d.id, d.spki_sha256.substr(0, 16), d.user_name);
}

std::string listenerText(const protocols::device::ListenerStatus& s) {
    std::string out;
    if (!s.enabled) out += "Device listener: disabled in config.yaml (device_server.enabled)\n";
    else if (s.listening)
        out += fmt::format("Device listener: listening on {} ({})\n", s.address,
                           s.remote ? "every interface" : "loopback only");
    else out += fmt::format("Device listener: not listening{}\n", s.error ? ": " + *s.error : std::string{});
    out += fmt::format("Remote connections: {}\n", s.remote ? "on" : "off (devices on this machine only)");
    out += fmt::format("Port: {}\n", s.port);
    if (!s.server_spki_sha256.empty()) out += fmt::format("Server key (pin): {}\n", s.server_spki_sha256);
    out += fmt::format("Open connections: {}\n", s.connections);
    return out;
}

nlohmann::json listenerJson(const protocols::device::ListenerStatus& s) {
    return {{"enabled", s.enabled}, {"remote", s.remote}, {"port", s.port}, {"listening", s.listening},
            {"address", s.listening ? nlohmann::json(s.address) : nlohmann::json(nullptr)},
            {"error", s.error ? nlohmann::json(*s.error) : nlohmann::json(nullptr)},
            {"server_spki_sha256", s.server_spki_sha256}, {"connections", s.connections}};
}

// The person picks one of the three codes (or types the code); "d" denies, empty skips. nullopt = skip.
struct Choice {
    enum class Kind { Approve, Deny, Skip } kind = Kind::Skip;
    std::string code{};
};

Choice askForCode(SocketIO& io, const vh::device::PendingRequest& r) {
    const auto answer = io.prompt(fmt::format("Which code does the device show?  {}\n(1-3 or the code; d = deny, "
                                              "Enter = skip):",
                                              choicesLine(r.code_choices)),
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

// Interactive `vh device pair`: wait in the open window for requests and settle each by number matching. Ends on the
// first approval, when the window closes or expires, or when the client hangs up.
CommandResult waitAndApprove(const CommandCall& call) {
    auto& io = *call.io;
    std::set<std::string> seen;
    io.print("Waiting for a device... (Ctrl-C to stop; the window stays open until it expires or `vh device pair "
             "--close`)\n");
    for (;;) {
        if (!io.peerConnected()) {
            (void)devices::closeWindow(call.user);
            return invalid("device pair: stopped");
        }
        devices::PendingList list;
        try {
            list = devices::pending(call.user);
        } catch (const ops::Error& e) {
            return invalid(std::string("device pair: ") + e.what());
        }
        if (!list.window) return invalid("device pair: the pairing window closed (it lasts 10 minutes); run `vh device pair` again");

        for (const auto& r : list.requests) {
            if (seen.contains(r.request_id)) continue;
            seen.insert(r.request_id);
            io.print(describeRequest(r));
            const auto choice = askForCode(io, r);
            try {
                if (choice.kind == Choice::Kind::Deny) {
                    devices::deny(call.user, r.request_id);
                    io.print("Denied.\n");
                } else if (choice.kind == Choice::Kind::Approve) {
                    const auto device = devices::approve(call.user, r.request_id, choice.code);
                    (void)devices::closeWindow(call.user);
                    return ok(fmt::format("Approved: {} is paired with your account.\n", describeDevice(device)));
                } else {
                    io.print("Skipped; approve it later with `vh device approve " + r.request_id + "`.\n");
                }
            } catch (const ops::Error& e) {
                io.print(std::string("Not approved: ") + e.what() + "\n");
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

CommandResult handlePair(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"device", "pair"}));
    if (hasFlag(call, "close"))
        return runOp("device pair", [&] { return devices::closeWindow(call.user, hasFlag(call, "any")); },
                     [](const bool closed) {
            return std::string(closed ? "Pairing window closed; its requests expired.\n"
                                      : "No pairing window of yours was open.\n");
        });

    vh::device::PairingWindow window;
    try {
        window = devices::openWindow(call.user);
    } catch (const ops::Error& e) {
        return invalid(std::string("device pair: ") + e.what());
    }

    std::string text = fmt::format("Pairing window open until {}.\nIn Vaulthalla Desktop, add this node (device port "
                                   "{}); it shows a six-digit code when it asks to pair.\n",
                                   clockUtc(window.expires_at), config::Registry::get().device_server.port);
    if (!call.io)
        return ok(text + "Approve it with `vh device pending`, then `vh device approve <request> --code <code>`.\n");
    call.io->print(text);
    return waitAndApprove(call);
}

CommandResult handlePending(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"device", "pending"}));
    const bool json = hasFlag(call, "json");
    return runOp("device pending", [&] { return devices::pending(call.user); }, [&](const devices::PendingList& list) {
        if (json) {
            nlohmann::json requests = nlohmann::json::array();
            for (const auto& r : list.requests)
                requests.push_back({{"request_id", r.request_id}, {"name", r.name}, {"platform", r.platform},
                                    {"app_version", r.app_version}, {"source_ip", r.source_ip},
                                    {"device_id", r.device_id}, {"code_choices", r.code_choices},
                                    {"created_at", r.created_at}, {"expires_at", r.expires_at}});
            return jsonText({{"window", list.window ? nlohmann::json{{"expires_at", list.window->expires_at}}
                                                    : nlohmann::json(nullptr)},
                             {"requests", requests}});
        }
        if (!list.window) return std::string("No pairing window of yours is open (`vh device pair` opens one).\n");
        std::string out = fmt::format("Pairing window open until {}.\n", clockUtc(list.window->expires_at));
        if (list.requests.empty()) return out + "No device has asked to pair yet.\n";
        for (const auto& r : list.requests)
            out += describeRequest(r) + "  codes " + choicesLine(r.code_choices) + "\n";
        return out;
    });
}

CommandResult handleApprove(const CommandCall& call) {
    const auto usage = resolveUsage({"device", "approve"});
    validatePositionals(call, usage);
    const auto& requestId = call.positionals.at(0);
    auto code = optVal(call, "code");
    if (!code) {
        if (!call.io) return invalid("device approve: --code is required when not interactive");
        devices::PendingList list;
        try {
            list = devices::pending(call.user);
        } catch (const ops::Error& e) {
            return invalid(std::string("device approve: ") + e.what());
        }
        const auto it = std::ranges::find(list.requests, requestId, &vh::device::PendingRequest::request_id);
        if (it == list.requests.end())
            return invalid("device approve: no pending pairing request '" + requestId + "' (it may have expired)");
        call.io->print(describeRequest(*it));
        const auto choice = askForCode(*call.io, *it);
        if (choice.kind == Choice::Kind::Skip) return invalid("device approve: nothing approved");
        if (choice.kind == Choice::Kind::Deny)
            return runOp("device approve", [&] { devices::deny(call.user, requestId); },
                         [] { return std::string("Denied.\n"); });
        code = choice.code;
    }
    return runOp("device approve", [&] { return devices::approve(call.user, requestId, *code); },
                 [](const Device& d) { return fmt::format("Approved: {} is paired.\n", describeDevice(d)); });
}

CommandResult handleDeny(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"device", "deny"}));
    return runOp("device deny", [&] { devices::deny(call.user, call.positionals.at(0)); },
                 [] { return std::string("Denied.\n"); });
}

CommandResult handleList(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"device", "list"}));
    const bool all = hasFlag(call, "all");
    const bool json = hasFlag(call, "json");
    return runOp("device list", [&] { return devices::list(call.user, all); }, [&](const std::vector<Device>& list) {
        if (json) return jsonText(nlohmann::json(list));
        if (list.empty()) return std::string("No paired devices.\n");
        std::vector<Column> cols{{.header = "#", .align = Align::Right}, {.header = "Device id"}, {.header = "Name"},
                                 {.header = "Platform"}};
        if (all) cols.push_back({.header = "User"});
        cols.push_back({.header = "Last seen"});
        cols.push_back({.header = "Status"});
        Table table(cols);
        for (const auto& d : list) {
            std::vector<std::string> row{std::to_string(d.id), d.spki_sha256.substr(0, 16), d.name,
                                         d.platform + (d.app_version.empty() ? "" : " " + d.app_version)};
            if (all) row.push_back(d.user_name);
            row.push_back(d.last_seen_at ? utc(*d.last_seen_at) + (d.last_ip ? " from " + *d.last_ip : "") : "never");
            row.push_back(d.revoked_at ? "revoked " + utc(*d.revoked_at) : "paired");
            table.add_row(std::move(row));
        }
        return table.render();
    });
}

CommandResult handleRename(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"device", "rename"}));
    return runOp("device rename", [&] { return devices::rename(call.user, call.positionals.at(0), call.positionals.at(1)); },
                 [](const Device& d) { return fmt::format("Renamed: {}.\n", describeDevice(d)); });
}

CommandResult handleRevoke(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"device", "revoke"}));
    return runOp("device revoke", [&] { return devices::revoke(call.user, call.positionals.at(0)); },
                 [](const Device& d) { return fmt::format("Revoked: {}. It has to pair again with a new key.\n", describeDevice(d)); });
}

CommandResult handleRemote(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"device", "remote", "status"}, sub)) {
        validatePositionals(subcall, resolveUsage({"device", "remote", "status"}));
        const bool json = hasFlag(subcall, "json");
        return runOp("device remote status", [&] { return devices::remoteStatus(subcall.user); },
                     [&](const protocols::device::ListenerStatus& s) {
                         return json ? jsonText(listenerJson(s)) : listenerText(s);
                     });
    }
    for (const bool on : {true, false}) {
        if (!isCommandMatch({"device", "remote", on ? "enable" : "disable"}, sub)) continue;
        validatePositionals(subcall, resolveUsage({"device", "remote", on ? "enable" : "disable"}));
        return runOp("device remote", [&] { return devices::setRemote(subcall.user, on); },
                     [&](const protocols::device::ListenerStatus& s) {
                         return std::string(on ? "Remote device connections are on.\n"
                                               : "Remote device connections are off.\n") + listenerText(s);
                     });
    }
    return invalid(call.constructFullArgs(), "Unknown device remote subcommand: '" + std::string(sub) + "'");
}

CommandResult handleDevice(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"device", name}, sub); };
    if (is("pair")) return handlePair(subcall);
    if (is("pending")) return handlePending(subcall);
    if (is("approve")) return handleApprove(subcall);
    if (is("deny")) return handleDeny(subcall);
    if (is("list")) return handleList(subcall);
    if (is("rename")) return handleRename(subcall);
    if (is("revoke")) return handleRevoke(subcall);
    if (is("remote")) return handleRemote(subcall);
    return invalid(call.constructFullArgs(), "Unknown device subcommand: '" + std::string(sub) + "'");
}

}
}

void registerDeviceCommands(const std::shared_ptr<Router>& r) {
    r->registerCommand(runtime::Deps::get().shellUsageManager->resolve("device"), device_cli::handleDevice);
}

}
