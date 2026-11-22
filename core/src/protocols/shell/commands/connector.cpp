#include "protocols/shell/commands/all.hpp"

#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Connector.hpp"
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

#include <ctime>
#include <sstream>

// `vh connector ...`: parsing and rendering only. Who may do what, and what it changes, is ops::connector.
namespace vh::protocols::shell::commands {

// Named, not anonymous: the unity build joins this file with the other command files of this namespace.
namespace connector_cli {

namespace op = ::vh::ops::connector;

std::string jsonText(const nlohmann::json& j) {
    auto out = j.dump(4);
    out.push_back('\n');
    return out;
}

std::string utcText(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

op::Channel channel() { return AgentCallScope::active() ? op::Channel::Agent : op::Channel::Cli; }

std::string statusText(const op::Status& s) {
    const auto& r = s.settings;
    std::string out = std::string("Remote connectors  ") + (r.enabled ? "on" : "off") + "\n";
    if (r.public_origin) out += "Public address     " + *r.public_origin + " (MCP endpoint " + *r.public_origin + "/mcp)\n";
    out += "Widest scope       " + r.max_scope + "\n";
    out += std::string("Dynamic clients    ") + (r.dcr_enabled ? "allowed" : "off") + "\n";
    std::string hosts = "any https host";
    if (!r.client_hosts.empty()) {
        hosts.clear();
        for (const auto& h : r.client_hosts) hosts += (hosts.empty() ? "" : ", ") + h;
    }
    out += "Client hosts       " + hosts + "\n";
    out += fmt::format("Connected apps     {} live\nClients            {} live\n", s.live_grants, s.clients);
    if (!r.enabled) out += "Off: no AI app can sign in to this server remotely (`vh connector enable --url https://<host>`).\n";
    return out;
}

std::string grantLine(const ::vh::connector::Grant& g) {
    const auto& r = g.row;
    const auto host = [](const std::string& h) { return h.empty() ? std::string("-") : h; };
    const auto j = op::toJson(g);
    const auto user = identities::manager().user(r.user_id);
    std::string out = fmt::format("{}  {}  {}  {}  via {}  ", r.id.substr(0, 8),
                                  user ? user->name() : "user " + std::to_string(r.user_id),
                                  r.client_name, r.scope, host(j.at("redirect_host").get<std::string>()));
    if (r.revoked_at) out += "ended " + utcText(*r.revoked_at) + " (" + r.revoked_reason.value_or("?") + ")";
    else out += "until " + utcText(r.expires_at) + (r.last_used_at ? ", last used " + utcText(*r.last_used_at) : "");
    return out + "\n";
}

std::string clientLine(const db::query::connector::ClientRow& c) {
    std::string uris;
    for (const auto& u : c.redirect_uris) uris += (uris.empty() ? "" : " ") + u;
    return fmt::format("{}  {}  {}  {}  {}{}\n", c.id.substr(0, 8), c.kind, c.client_id, c.name, uris,
                       c.disabled_at ? "  (removed)" : "");
}

std::optional<bool> onOff(const std::optional<std::string>& v) {
    if (!v) return std::nullopt;
    if (*v == "on") return true;
    if (*v == "off") return false;
    throw ops::Invalid("--dcr takes on or off");
}

CommandResult handleClient(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"connector", "client", name}, sub); };
    const bool json = hasFlag(subcall, "json");
    if (is("list")) {
        validatePositionals(subcall, resolveUsage({"connector", "client", "list"}));
        return runOp("connector client list", [&] { return op::listClients(subcall.user); }, [json](const auto& rows) {
            if (json) {
                nlohmann::json a = nlohmann::json::array();
                for (const auto& c : rows) a.push_back(op::toJson(c));
                return jsonText(nlohmann::json{{"clients", a}});
            }
            std::string out;
            for (const auto& c : rows) out += clientLine(c);
            return out.empty() ? std::string("No clients.\n") : out;
        });
    }
    if (is("add")) {
        validatePositionals(subcall, resolveUsage({"connector", "client", "add"}));
        const auto name = optVal(subcall, "name").value_or("");
        const auto redirect = optVal(subcall, "redirect").value_or("");
        return runOp("connector client add",
                     [&] { return op::addClient(subcall.user, channel(), name, std::vector<std::string>{redirect}); },
                     [json](const db::query::connector::ClientRow& c) {
                         if (json) return jsonText(op::toJson(c));
                         return "Registered. Configure the app with client id " + c.client_id + "\n";
                     });
    }
    if (is("remove")) {
        validatePositionals(subcall, resolveUsage({"connector", "client", "remove"}));
        return runOp("connector client remove",
                     [&] { return op::removeClient(subcall.user, channel(), subcall.positionals.at(0)); },
                     [](const std::size_t n) { return fmt::format("Removed; {} connected app(s) disconnected.\n", n); });
    }
    return invalid(call.constructFullArgs(), "Unknown connector client subcommand: '" + std::string(sub) + "'");
}

CommandResult handleConnector(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"connector", name}, sub); };
    const bool json = hasFlag(subcall, "json");
    const auto render = [json](const op::Status& s) { return json ? jsonText(op::toJson(s)) : statusText(s); };
    if (is("status")) {
        validatePositionals(subcall, resolveUsage({"connector", "status"}));
        return runOp("connector status", [&] { return op::status(subcall.user); }, render);
    }
    if (is("enable")) {
        validatePositionals(subcall, resolveUsage({"connector", "enable"}));
        const auto url = optVal(subcall, "url").value_or("");
        return runOp("connector enable", [&] { return op::enable(subcall.user, channel(), url); }, render);
    }
    if (is("disable")) {
        validatePositionals(subcall, resolveUsage({"connector", "disable"}));
        return runOp("connector disable", [&] { return op::disable(subcall.user, channel()); }, render);
    }
    if (is("set")) {
        validatePositionals(subcall, resolveUsage({"connector", "set"}));
        return runOp("connector set", [&] {
            op::Policy p{.max_scope = optVal(subcall, "max-scope"), .dcr_enabled = onOff(optVal(subcall, "dcr"))};
            if (const auto hosts = optVal(subcall, "client-hosts")) {
                std::vector<std::string> list;
                if (*hosts != "any") {
                    std::stringstream ss(*hosts);
                    for (std::string h; std::getline(ss, h, ',');)
                        if (!h.empty()) list.push_back(h);
                    if (list.empty()) throw ops::Invalid("--client-hosts takes any, or host names separated by commas");
                }
                p.client_hosts = list;
            }
            return op::setPolicy(subcall.user, channel(), p);
        }, render);
    }
    if (is("list")) {
        validatePositionals(subcall, resolveUsage({"connector", "list"}));
        const bool all = hasFlag(subcall, "all");
        return runOp("connector list", [&] { return op::listGrants(subcall.user, all); }, [json](const auto& grants) {
            if (json) {
                nlohmann::json a = nlohmann::json::array();
                for (const auto& g : grants) a.push_back(op::toJson(g));
                return jsonText(nlohmann::json{{"grants", a}});
            }
            std::string out;
            for (const auto& g : grants) out += grantLine(g);
            return out.empty() ? std::string("No connected apps.\n") : out;
        });
    }
    if (is("revoke")) {
        validatePositionals(subcall, resolveUsage({"connector", "revoke"}));
        return runOp("connector revoke", [&] { return op::revokeGrant(subcall.user, subcall.positionals.at(0)); },
                     [](const ::vh::connector::Grant& g) { return "Disconnected " + g.row.client_name + ".\n"; });
    }
    if (is("revoke-all")) {
        validatePositionals(subcall, resolveUsage({"connector", "revoke-all"}));
        return runOp("connector revoke-all", [&] {
            std::optional<uint32_t> user;
            if (const auto name = optVal(subcall, "user")) {
                const auto u = identities::manager().userByName(*name);
                if (!u) throw ops::NotFound("no such user: " + *name);
                user = u->id;
            }
            return op::revokeGrants(subcall.user, user);
        }, [](const std::size_t n) { return fmt::format("{} connected app(s) disconnected.\n", n); });
    }
    if (is("client")) return handleClient(subcall);
    return invalid(call.constructFullArgs(), "Unknown connector subcommand: '" + std::string(sub) + "'");
}

}

void registerConnectorCommands(const std::shared_ptr<Router>& r) {
    r->registerCommand(runtime::Deps::get().shellUsageManager->resolve("connector"), connector_cli::handleConnector);
}

}
