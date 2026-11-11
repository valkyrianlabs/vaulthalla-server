#include "protocols/shell/commands/all.hpp"

#include "identities/User.hpp"
#include "ops/Cloud.hpp"
#include "ops/Error.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <thread>

// `vh cloud ...`: parsing and rendering only. Who may do what, and what it changes, is ops::cloud.
namespace vh::protocols::shell::commands {

// Named, not anonymous: the unity build joins this file with the other command files of this namespace.
namespace cloud_cli {
namespace {

namespace cloud = ::vh::ops::cloud;

std::string jsonText(const nlohmann::json& j) {
    auto out = j.dump(4);
    out.push_back('\n');
    return out;
}

std::string utc(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

cloud::Channel channel() { return AgentCallScope::active() ? cloud::Channel::Agent : cloud::Channel::Cli; }

nlohmann::json claimJson(const cloud::Claim& c) {
    return {{"status", c.status},
            {"installation_id", c.installation_id ? nlohmann::json(*c.installation_id) : nlohmann::json(nullptr)},
            {"account_id", c.account_id ? nlohmann::json(*c.account_id) : nlohmann::json(nullptr)}};
}

std::string claimText(const cloud::Claim& c) {
    if (c.status == "linked")
        return fmt::format("Linked: this server is installation {} of Vaulthalla Cloud account {}.\n",
                           c.installation_id.value_or("?"), c.account_id.value_or(0));
    if (c.status == "denied") return "The link request was denied on vaulthalla.cloud; nothing was linked.\n";
    if (c.status == "expired") return "The link request expired; run `vh cloud link` again.\n";
    return "Still waiting for approval on vaulthalla.cloud (`vh cloud link --finish` checks again).\n";
}

// Polls the pending request until it is decided, the request expires or the caller goes away.
CommandResult waitForApproval(const CommandCall& call) {
    auto& io = *call.io;
    io.print("Waiting for approval... (Ctrl-C to stop; `vh cloud link --finish` picks it up again)\n");
    for (;;) {
        if (!io.peerConnected()) return invalid("cloud link: stopped; the request stays open until it expires");
        cloud::Claim c;
        try {
            c = cloud::claimLink(call.user, channel());
        } catch (const ops::Error& e) {
            return invalid(std::string("cloud link: ") + e.what());
        }
        if (c.status != "pending") return c.status == "linked" ? ok(claimText(c)) : invalid("cloud link: " + claimText(c));
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

CommandResult handleLink(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "link"}));
    const bool json = hasFlag(call, "json");
    if (hasFlag(call, "finish")) {
        if (json || !call.io)
            return runOp("cloud link", [&] { return cloud::claimLink(call.user, channel()); },
                         [&](const cloud::Claim& c) { return json ? jsonText(claimJson(c)) : claimText(c); });
        return waitForApproval(call);
    }
    cloud::LinkStarted started;
    try {
        started = cloud::startLink(call.user, channel(), optVal(call, "name"));
    } catch (const ops::Error& e) {
        return invalid(std::string("cloud link: ") + e.what());
    }
    if (json)
        return ok(jsonText({{"user_code", started.user_code}, {"fingerprint", started.fingerprint},
                            {"name", started.name}, {"endpoint", started.endpoint}, {"expires_at", started.expires_at}}));
    const auto text = fmt::format(
        "To link \"{}\" to your Vaulthalla Cloud account ({}):\n"
        "  1. Sign in on vaulthalla.cloud and choose Link a server.\n"
        "  2. Enter the code   {}\n"
        "  3. Check that it shows this key fingerprint   {}\n"
        "     then approve it. The code expires at {}.\n",
        started.name, started.endpoint, started.user_code, started.fingerprint, utc(started.expires_at));
    if (!call.io) return ok(text + "Then run `vh cloud link --finish`.\n");
    call.io->print(text);
    return waitForApproval(call);
}

CommandResult handleStatus(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "status"}));
    const bool json = hasFlag(call, "json");
    return runOp("cloud status", [&] { return cloud::status(call.user); }, [&](const cloud::Status& s) {
        const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
        if (json)
            return jsonText({{"state", s.state}, {"endpoint", s.endpoint}, {"name", opt(s.name)},
                             {"fingerprint", opt(s.fingerprint)}, {"installation_id", opt(s.installation_id)},
                             {"account_id", opt(s.account_id)}, {"linked_at", opt(s.linked_at)},
                             {"request_expires_at", opt(s.request_expires_at)}, {"requested_by", opt(s.requested_by)},
                             {"cloud", opt(s.cloud)}, {"cloud_detail", opt(s.cloud_detail)}});
        if (s.state == "unlinked")
            return fmt::format("Not linked to Vaulthalla Cloud ({}). `vh cloud link` links it; it is never required.\n",
                               s.endpoint);
        std::string out = fmt::format("Name          {}\nEndpoint      {}\nKey           {}\n", s.name.value_or("?"),
                                      s.endpoint, s.fingerprint.value_or("?"));
        if (s.state == "pending")
            return out + fmt::format("State         waiting for approval on vaulthalla.cloud (requested by {}, "
                                     "until {})\n",
                                     s.requested_by.value_or("?"), s.request_expires_at ? utc(*s.request_expires_at) : "?");
        out += fmt::format("State         linked since {}\nInstallation  {}\nAccount       {}\n",
                           s.linked_at ? utc(*s.linked_at) : "?", s.installation_id.value_or("?"), s.account_id.value_or(0));
        out += "Cloud         " + s.cloud.value_or("?") + (s.cloud_detail ? " (" + *s.cloud_detail + ")" : "") + "\n";
        return out;
    });
}

CommandResult handleUnlink(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "unlink"}));
    return runOp("cloud unlink", [&] { return cloud::unlink(call.user, channel(), hasFlag(call, "force")); },
                 [](const cloud::Unlinked& u) {
        if (u.was == "unlinked") return std::string("This server wasn't linked to Vaulthalla Cloud.\n");
        if (u.was == "pending") return std::string("The pending link request was discarded.\n");
        return std::string(u.cloud_revoked ? "Unlinked: Vaulthalla Cloud revoked this server, and its identity key is "
                                             "gone.\n"
                                           : "Forgotten here. Vaulthalla Cloud didn't confirm it: revoke this server "
                                             "on vaulthalla.cloud.\n");
    });
}

CommandResult handleCloud(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"cloud", name}, sub); };
    if (is("link")) return handleLink(subcall);
    if (is("status")) return handleStatus(subcall);
    if (is("unlink")) return handleUnlink(subcall);
    return invalid(call.constructFullArgs(), "Unknown cloud subcommand: '" + std::string(sub) + "'");
}

}
}

void registerCloudCommands(const std::shared_ptr<Router>& r) {
    r->registerCommand(runtime::Deps::get().shellUsageManager->resolve("cloud"), cloud_cli::handleCloud);
}

}
