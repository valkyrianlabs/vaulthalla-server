// The MCP catalog (core/usage/src/mcp): every CLI leaf declares an effect, excluded commands are unreachable, tool
// schemas have the JSON Schema 2020-12 shape MCP clients expect, and every line a tool renders is parsed by the daemon
// exactly as checked and passes the Router's option validation. DB-free.

#include "CommandUsage.hpp"
#include "Contract.hpp"
#include "Mcp.hpp"
#include "UsageManager.hpp"
#include "protocols/shell/Parser.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/Token.hpp"
#include "protocols/shell/commands/all.hpp"
#include "runtime/Deps.hpp"
#include "identities/User.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace vh::test_mcp_catalog {

using json = nlohmann::json;
using protocols::shell::CommandEffect;
using protocols::shell::CommandUsage;

const mcp::Catalog& catalog() {
    static const mcp::Catalog c;
    return c;
}

std::shared_ptr<protocols::shell::Router> router() {
    static const auto r = [] {
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        auto rt = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerAllCommands(rt);
        return rt;
    }();
    return r;
}

json toolsByName() {
    json m = json::object();
    for (const auto& t : catalog().tools()) m[t.at("name").get<std::string>()] = t;
    return m;
}

std::string text(const json& result) { return result.at("content").at(0).at("text").get<std::string>(); }

// prepare() that must produce a command to run.
mcp::Invocation invocation(const std::string& tool, const json& args) {
    auto prepared = catalog().prepare(tool, args);
    if (const auto* refused = std::get_if<json>(&prepared)) {
        ADD_FAILURE() << tool << " " << args.dump() << " refused: " << refused->dump();
        return {};
    }
    return std::get<mcp::Invocation>(prepared);
}

// prepare() that must refuse; returns the refusal text.
std::string refusal(const std::string& tool, const json& args) {
    auto prepared = catalog().prepare(tool, args);
    if (std::holds_alternative<mcp::Invocation>(prepared)) {
        ADD_FAILURE() << tool << " " << args.dump() << " was accepted: " << std::get<mcp::Invocation>(prepared).line;
        return {};
    }
    const auto& r = std::get<json>(prepared);
    EXPECT_TRUE(r.at("isError").get<bool>());
    return text(r);
}

protocols::shell::CommandCall daemonParse(const std::string& line) {
    (void)router();  // tokenize() reads the usage manager's root aliases
    return protocols::shell::parseTokens(protocols::shell::tokenize(line));
}

// ---- effects ----------------------------------------------------------------------------------------------------

TEST(McpCatalog, EveryLeafDeclaresAnEffectAndOnlyLeaves) {
    const protocols::shell::UsageManager mgr;
    std::size_t leaves = 0;
    std::function<void(const std::shared_ptr<CommandUsage>&, const std::string&)> walk =
        [&](const std::shared_ptr<CommandUsage>& node, const std::string& path) {
            for (const auto& sc : node->subcommands) {
                const auto p = path + " " + sc->primary();
                if (sc->subcommands.empty()) {
                    ++leaves;
                    EXPECT_NE(sc->effect, CommandEffect::Unset) << "vh" << p << " declares no effect (read, write, "
                                                                   "destructive)";
                } else {
                    EXPECT_EQ(sc->effect, CommandEffect::Unset) << "vh" << p << " is a group; effects belong to leaves";
                }
                walk(sc, p);
            }
        };
    walk(mgr.root(), "");
    EXPECT_GT(leaves, 140u);
}

TEST(McpCatalog, EffectIsExportedForEveryLeaf) {
    const auto doc = json::parse(contract::document());
    for (const auto& cmd : doc.at("cli")) {
        const auto& effect = cmd.at("effect");
        if (cmd.at("subcommands").empty()) {
            ASSERT_TRUE(effect.is_string()) << cmd.at("path").dump();
            EXPECT_TRUE(effect == "read" || effect == "write" || effect == "destructive") << effect;
        } else {
            EXPECT_TRUE(effect.is_null()) << cmd.at("path").dump();
        }
    }
}

TEST(McpCatalog, EffectsOfKnownCommands) {
    std::map<std::string, CommandEffect> byCommand;
    for (const auto& l : catalog().leaves()) byCommand[l.command] = l.effect;
    EXPECT_EQ(byCommand.at("vault list"), CommandEffect::Read);
    EXPECT_EQ(byCommand.at("status"), CommandEffect::Read);
    EXPECT_EQ(byCommand.at("vault create"), CommandEffect::Write);
    EXPECT_EQ(byCommand.at("vault delete"), CommandEffect::Destructive);
    EXPECT_EQ(byCommand.at("vault key rotate"), CommandEffect::Destructive);
    EXPECT_EQ(byCommand.at("s3-gateway creds revoke"), CommandEffect::Destructive);
    EXPECT_EQ(byCommand.at("upstream cleanup"), CommandEffect::Destructive);
    EXPECT_EQ(byCommand.at("recovery restore"), CommandEffect::Destructive);
}

// ---- exclusions -------------------------------------------------------------------------------------------------

TEST(McpCatalog, ExclusionListIsExactlyTheAgreedOne) {
    std::vector<std::string> paths;
    for (const auto& ex : mcp::exclusions()) {
        std::string p;
        for (const auto& w : ex.path) p += (p.empty() ? "" : " ") + w;
        paths.push_back(p);
        EXPECT_FALSE(ex.reason.empty()) << p;
        // Every entry names a real command, so a rename can't silently drop an exclusion.
        const protocols::shell::UsageManager mgr;
        const auto node = mgr.resolve(ex.path);
        ASSERT_TRUE(node) << p;
        EXPECT_EQ(node->primary(), ex.path.back()) << p;
    }
    const std::vector<std::string> expected{"vault key export", "secrets export", "secrets update", "setup",
                                            "setup set-super-admin-password", "teardown", "fs get", "fs put", "mcp",
                                            "skill", "device pair", "device approve", "device deny",
                                            "device remote enable", "device remote disable"};
    EXPECT_EQ(paths, expected);
}

TEST(McpCatalog, ExcludedCommandsAreNeitherListedNorRunnable) {
    std::set<std::string> excluded;
    for (const auto& l : catalog().leaves())
        if (l.excluded) excluded.insert(l.command);
    for (const auto* c : {"vault key export", "secrets export", "secrets update", "setup db", "setup caddy",
                          "setup set-super-admin-password", "teardown db", "fs get", "fs put", "mcp", "skill install",
                          "device pair", "device approve", "device deny", "device remote enable",
                          "device remote disable"})
        EXPECT_TRUE(excluded.contains(c)) << c;

    // No typed tool binds one, and nothing in a tool definition offers it.
    const auto tools = catalog().tools().dump();
    for (const auto* needle : {"vault key export", "secrets export", "fs get", "fs put", "set-super-admin-password"})
        EXPECT_EQ(tools.find(needle), std::string::npos) << needle;

    // Every spelling an agent might use is refused before anything runs.
    for (const auto* command : {"vault keys export 3", "vault k export 3 --output /tmp/x", "VAULT KEY EXPORT 3",
                                "vaults key export 3", "secret export jwt-secret", "secrets get db-password",
                                "secret set jwt-secret /tmp/x", "setup db", "setup database", "teardown nginx",
                                "setup super-admin-password", "fs get 3 /a", "files download 3 /a", "fs put 3 a /a",
                                "fs upload 3 a /a", "mcp", "skills install --agent claude", "device pair",
                                "device approve 7f3a9c1d2e4b6a80 --code 482913", "device deny 7f3a9c1d2e4b6a80",
                                "device remote enable", "device remote on", "devices remote disable"})
        for (const auto* tool : {"vh_run", "vh_read"})
            EXPECT_NE(refusal(tool, {{"command", command}}).find("not available to agents"), std::string::npos)
                << tool << ": " << command;
    EXPECT_NE(refusal("vh_help", {{"path", "vault keys export"}}).find("not available"), std::string::npos);

    // Help never lists them either.
    const auto top = json::parse(text(std::get<json>(catalog().prepare("vh_help", json::object()))));
    for (const auto& c : top.at("commands"))
        for (const auto* hidden : {"setup", "teardown", "mcp", "skill"}) EXPECT_NE(c.at("name"), hidden);
    const auto keys = json::parse(text(std::get<json>(catalog().prepare("vh_help", {{"path", "vault keys"}}))));
    for (const auto& sc : keys.at("subcommands")) EXPECT_NE(sc.at("name"), "export");

    const auto ref = catalog().commandReference("test");
    const auto main = ref.substr(0, ref.find("## Not available to agents"));
    for (const auto* needle : {"vh vault key export", "vh secrets export", "vh fs get", "vh setup"})
        EXPECT_EQ(main.find(needle), std::string::npos) << needle;
}

// ---- schemas ----------------------------------------------------------------------------------------------------

// The JSON Schema 2020-12 subset tool schemas use; anything else is a mistake here, not a feature.
void checkSchema(const json& s, const std::string& where) {
    static const std::set<std::string> kKeywords{"type", "properties", "required", "additionalProperties",
                                                 "description", "enum", "const", "minimum", "minLength", "items"};
    static const std::set<std::string> kTypes{"object", "string", "integer", "number", "boolean", "array", "null"};
    ASSERT_TRUE(s.is_object()) << where;
    for (const auto& [k, v] : s.items()) EXPECT_TRUE(kKeywords.contains(k)) << where << ": keyword " << k;
    if (s.contains("type")) {
        const auto& t = s["type"];
        if (t.is_string()) {
            EXPECT_TRUE(kTypes.contains(t.get<std::string>())) << where;
        } else {
            ASSERT_TRUE(t.is_array() && !t.empty()) << where;
            for (const auto& e : t) EXPECT_TRUE(e.is_string() && kTypes.contains(e.get<std::string>())) << where;
        }
    } else {
        EXPECT_TRUE(s.contains("enum") || s.contains("const")) << where << ": no type";
    }
    if (s.contains("description")) {
        EXPECT_TRUE(s["description"].is_string()) << where;
    }
    if (s.contains("enum")) {
        EXPECT_TRUE(s["enum"].is_array() && !s["enum"].empty()) << where;
    }
    if (s.contains("properties")) {
        ASSERT_TRUE(s["properties"].is_object()) << where;
        for (const auto& [name, sub] : s["properties"].items()) checkSchema(sub, where + "." + name);
    }
    if (s.contains("required")) {
        ASSERT_TRUE(s["required"].is_array()) << where;
        for (const auto& r : s["required"]) {
            ASSERT_TRUE(r.is_string()) << where;
            EXPECT_TRUE(s.contains("properties") && s["properties"].contains(r.get<std::string>()))
                << where << ": required " << r << " is not a property";
        }
    }
    if (s.contains("additionalProperties") && !s["additionalProperties"].is_boolean())
        checkSchema(s["additionalProperties"], where + ".additionalProperties");
}

TEST(McpCatalog, ToolDefinitionsHaveTheShapeClientsExpect) {
    const std::regex name("^[a-zA-Z0-9_-]{1,64}$");  // what every major client accepts (no dots)
    std::set<std::string> names;
    std::size_t typed = 0;
    for (const auto& t : catalog().tools()) {
        const auto n = t.at("name").get<std::string>();
        EXPECT_TRUE(std::regex_match(n, name)) << n;
        EXPECT_TRUE(names.insert(n).second) << "duplicate tool " << n;
        EXPECT_FALSE(t.at("description").get<std::string>().empty()) << n;
        const auto& schema = t.at("inputSchema");
        EXPECT_EQ(schema.at("type"), "object") << n;
        EXPECT_EQ(schema.at("additionalProperties"), false) << n;
        checkSchema(schema, n);
        const auto& a = t.at("annotations");
        for (const auto* hint : {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"})
            EXPECT_TRUE(a.at(hint).is_boolean()) << n << " " << hint;
        EXPECT_FALSE(a.at("readOnlyHint").get<bool>() && a.at("destructiveHint").get<bool>()) << n;
        if (n != "vh_help" && n != "vh_read" && n != "vh_run") ++typed;
    }
    EXPECT_TRUE(names.contains("vh_help") && names.contains("vh_read") && names.contains("vh_run"));

    std::size_t withCli = 0;
    for (const auto& op : contract::operations()) withCli += op.cli ? 1 : 0;
    EXPECT_EQ(typed, withCli) << "one typed tool per operation with a CLI binding";

    const auto tools = toolsByName();
    EXPECT_TRUE(tools.at("vh_read").at("annotations").at("readOnlyHint").get<bool>());
    EXPECT_TRUE(tools.at("vh_run").at("annotations").at("destructiveHint").get<bool>());
    EXPECT_TRUE(tools.at("recovery_list").at("annotations").at("readOnlyHint").get<bool>());
    EXPECT_TRUE(tools.at("users_delete").at("annotations").at("destructiveHint").get<bool>());
    EXPECT_FALSE(tools.at("groups_create").at("annotations").at("destructiveHint").get<bool>());
    // A command that asks for confirmation takes it in `confirm`, never on its own.
    EXPECT_TRUE(tools.at("users_delete").at("inputSchema").at("properties").contains("confirm"));
    EXPECT_FALSE(tools.at("groups_create").at("inputSchema").at("properties").contains("confirm"));
}

// ---- rendered lines ---------------------------------------------------------------------------------------------

json sampleValue(const json& schema, const std::string& name) {
    if (schema.contains("enum")) return schema["enum"].front();
    const auto& t = schema.at("type");
    const auto type = t.is_array() ? t.front().get<std::string>() : t.get<std::string>();
    if (type == "integer") return 7;
    if (type == "boolean") return true;
    if (name == "path" || name == "to" || name == "destination") return "/docs/a b.txt";
    return name + "-x";
}

TEST(McpCatalog, TypedToolLinesPassTheRoutersOptionValidation) {
    for (const auto& t : catalog().tools()) {
        const auto name = t.at("name").get<std::string>();
        if (name == "vh_help" || name == "vh_read" || name == "vh_run") continue;
        const auto& props = t.at("inputSchema").at("properties");
        json all = json::object(), minimal = json::object();
        for (const auto& [field, schema] : props.items()) {
            if (field == "confirm") {
                json c = json::object();
                for (const auto& [gate, gs] : schema.at("properties").items())
                    c[gate] = gs.at("type") == "string" ? json("token") : json(true);
                all["confirm"] = c;
                continue;
            }
            all[field] = sampleValue(schema, field);
        }
        for (const auto& r : t.at("inputSchema").value("required", json::array()))
            minimal[r.get<std::string>()] = all[r.get<std::string>()];
        // The MCP-level acknowledgement only: the command's own confirmation flags must still not appear.
        const bool destructive = t.at("annotations").at("destructiveHint").get<bool>();
        if (destructive) minimal["confirm"] = {{"destructive", true}};
        EXPECT_EQ(destructive, props.contains("confirm") && props["confirm"]["properties"].contains("destructive")) << name;

        for (const auto& args : {all, minimal}) {
            const auto inv = invocation(name, args);
            if (inv.line.empty()) continue;
            EXPECT_FALSE(router()->optionError(inv.line).has_value())
                << name << ": " << inv.line << "\n  " << router()->optionError(inv.line).value_or("");
            // The daemon sees the argv the catalog built, token for token.
            const auto call = daemonParse(inv.line);
            EXPECT_EQ(call.name, inv.argv.front()) << inv.line;
            if (!args.contains("confirm") || args["confirm"].size() == (args["confirm"].contains("destructive") ? 1u : 0u)) {
                for (const auto& gate : inv.gates)
                    EXPECT_TRUE(std::ranges::none_of(call.options, [&](const auto& o) { return o.key == gate; }))
                        << name << " passes --" << gate << " without confirm: " << inv.line;
            }
        }
    }
}

TEST(McpCatalog, TypedToolRendering) {
    auto inv = invocation("roles_vault_assign", {{"vault", "docs"}, {"role", 3}, {"subject_type", "group"}, {"subject", "dev ops"}});
    EXPECT_EQ(inv.line, "vault role assign docs 3 --group \"dev ops\"");
    inv = invocation("vaults_create", {{"name", "team"}});
    EXPECT_EQ(inv.line, "vault create team --local");
    inv = invocation("users_delete", {{"user", "bob"}, {"confirm", {{"destructive", true}}}});
    EXPECT_EQ(inv.line, "user delete bob");
    EXPECT_EQ(inv.gates, std::vector<std::string>{"yes"});
    inv = invocation("users_delete", {{"user", "bob"}, {"confirm", {{"destructive", true}, {"yes", true}}}});
    EXPECT_EQ(inv.line, "user delete bob --yes");
    inv = invocation("recovery_status", {{"vault", 4}, {"refresh", true}});
    EXPECT_EQ(inv.line, "vault recovery status 4 --refresh --json");

    EXPECT_NE(refusal("users_delete", json::object()).find("user is required"), std::string::npos);
    EXPECT_NE(refusal("users_delete", {{"user", "bob"}, {"nope", 1}}).find("unknown argument"), std::string::npos);
    EXPECT_NE(refusal("users_delete", {{"user", "bob"}, {"confirm", {{"destructive", true}, {"accept-key-loss", true}}}})
                  .find("no confirmation"),
              std::string::npos);
    EXPECT_NE(refusal("recovery_update", {{"vault", 1}, {"mode", "sometimes"}}).find("one of"), std::string::npos);
}

TEST(McpCatalog, RunLinesParseAsCheckedForEveryDocumentedExample) {
    const protocols::shell::UsageManager mgr;
    std::size_t checked = 0;
    std::function<void(const std::shared_ptr<CommandUsage>&)> walk = [&](const std::shared_ptr<CommandUsage>& node) {
        for (const auto& example : node->examples) {
            auto line = example.cmd;
            if (!line.starts_with("vh ")) continue;
            line = line.substr(3);
            auto prepared = catalog().prepare("vh_run", {{"command", line}, {"confirm", {{"destructive", true}}}});
            if (std::holds_alternative<json>(prepared)) continue;  // excluded, a group, or a confirmation flag
            const auto& inv = std::get<mcp::Invocation>(prepared);
            ++checked;
            EXPECT_FALSE(router()->optionError(inv.line).has_value()) << "vh " << line << " -> " << inv.line;
            // Same command, same arguments as the original; only --json may be added.
            const auto original = daemonParse(line), rendered = daemonParse(inv.line);
            EXPECT_EQ(rendered.name, original.name) << inv.line;
            EXPECT_EQ(rendered.positionals, original.positionals) << "vh " << line << " -> " << inv.line;
            for (const auto& o : rendered.options) {
                const auto same = std::ranges::find_if(original.options, [&](const auto& x) { return x.key == o.key; });
                if (same == original.options.end()) {
                    EXPECT_EQ(o.key, "json") << "vh " << line << " -> " << inv.line;
                } else {
                    EXPECT_EQ(same->value, o.value) << "vh " << line << " -> " << inv.line;
                }
            }
        }
        for (const auto& sc : node->subcommands) walk(sc);
    };
    walk(mgr.root());
    EXPECT_GT(checked, 150u);
}

TEST(McpCatalog, RunRefusesWhatItCannotCheck) {
    EXPECT_NE(refusal("vh_run", {{"command", "user delete bob --yes"}}).find("confirmation"), std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", "sync resolve 4 --keep-local -y"}}).find("confirmation"), std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", "vault delete 3 --accept-key-loss"}}).find("confirmation"), std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", "upstream cleanup key bucket --confirm-token=abc"}}).find("confirmation"),
              std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", "vault info -- --x"}}).find("'--'"), std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", "frobnicate"}}).find("unknown command"), std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", "vault sync"}}).find("group of commands"), std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", ""}}).find("empty"), std::string::npos);
    EXPECT_NE(refusal("vh_read", {{"command", "vault delete 3"}}).find("vh_read only runs read-only"), std::string::npos);
    EXPECT_NE(refusal("vh_run", {{"command", "user delete bob"}, {"confirm", {{"accept-x", true}}}}).find("no confirmation"),
              std::string::npos);

    auto inv = invocation("vh_run", {{"command", "vh users"}});
    EXPECT_EQ(inv.command, "user list");
    EXPECT_EQ(inv.effect, CommandEffect::Read);
    inv = invocation("vh_run", {{"command", "upstream cleanup key bucket"},
                                {"confirm", {{"destructive", true}, {"confirm-token", "t 1"}}}});
    EXPECT_EQ(inv.line, "upstream cleanup key bucket --confirm-token \"t 1\" --json");
    inv = invocation("vh_read", {{"command", "group list --json"}});
    EXPECT_EQ(inv.line, "group list --json") << "--json is not added twice";
    inv = invocation("vh_read", {{"command", "vault delete --help"}});
    EXPECT_EQ(inv.effect, CommandEffect::Read) << "help is read-only";
}

// ---- results ----------------------------------------------------------------------------------------------------

TEST(McpCatalog, RefusalsNamingAConfirmationBecomeNeedsConfirmation) {
    const auto inv = invocation("users_delete", {{"user", "bob"}, {"confirm", {{"destructive", true}}}});
    auto r = catalog().finish(inv, {.exit_code = 2, .out = {},
                                    .err = "user delete: bob owns 2 vaults\nRe-run with --yes to confirm."});
    EXPECT_TRUE(r.at("isError").get<bool>());
    EXPECT_EQ(r.at("structuredContent").at("needs_confirmation"), "yes");
    EXPECT_NE(r.at("structuredContent").at("how_to_confirm").get<std::string>().find(
                  "\"confirm\": {\"destructive\": true, \"yes\": true}"),
              std::string::npos)
        << "keeps the acknowledgement already given";

    // Usage text that merely documents --yes is an ordinary failure.
    r = catalog().finish(inv, {.exit_code = 2, .out = "Usage: vh user delete <user> [--yes]", .err = "user delete: no such user"});
    EXPECT_FALSE(r.contains("structuredContent"));
    EXPECT_NE(text(r).find("exit 2"), std::string::npos);

    // Already confirmed: the refusal is reported as it is.
    const auto confirmed = invocation("users_delete", {{"user", "bob"}, {"confirm", {{"destructive", true}, {"yes", true}}}});
    r = catalog().finish(confirmed, {.exit_code = 2, .out = {}, .err = "user delete: Re-run with --yes to confirm."});
    EXPECT_FALSE(r.contains("structuredContent"));

    const auto vault = invocation("vaults_delete", {{"vault", 3}, {"confirm", {{"destructive", true}}}});
    r = catalog().finish(vault, {.exit_code = 2, .out = {},
                                 .err = "vault delete: the key was never exported\nRe-run with --accept-key-loss to "
                                        "delete anyway, or --delete-upstream to delete the upstream data too."});
    EXPECT_EQ(r.at("structuredContent").at("needs_confirmation"), "accept-key-loss");

    const auto waiver = invocation("vh_run", {{"command", "vault update 3 --encrypt"}});
    r = catalog().finish(waiver, {.exit_code = 2, .out = {},
                                  .err = "vault update: this change requires accepting an encryption waiver: re-run in "
                                         "an interactive terminal, or pass --accept-overwrite-waiver / "
                                         "--accept-decryption-waiver."});
    ASSERT_FALSE(waiver.gates.empty());
    EXPECT_EQ(r.at("structuredContent").at("needs_confirmation"), "accept-overwrite-waiver") << r.dump();
    EXPECT_EQ(r.at("structuredContent").at("confirm_options").size(), 2u);

    r = catalog().finish(inv, {.exit_code = 0, .out = "User deleted successfully: bob\n", .err = {}});
    EXPECT_FALSE(r.at("isError").get<bool>());
    EXPECT_EQ(text(r), "User deleted successfully: bob");
}

// ---- JSON-RPC ---------------------------------------------------------------------------------------------------

TEST(McpServer, LifecycleListAndCall) {
    std::vector<std::string> ran;
    mcp::Server server(catalog(), [&](const mcp::Invocation& call) {
        ran.push_back(call.line);
        return mcp::CommandOutput{.exit_code = 0, .out = "[]", .err = {}};
    }, "9.9.9");

    auto r = server.handle({{"jsonrpc", "2.0"}, {"id", 1}, {"method", "initialize"},
                            {"params", {{"protocolVersion", "2025-03-26"}, {"capabilities", json::object()}}}});
    ASSERT_TRUE(r);
    EXPECT_EQ((*r)["result"]["protocolVersion"], "2025-03-26");
    EXPECT_EQ((*r)["result"]["serverInfo"]["version"], "9.9.9");
    r = server.handle({{"jsonrpc", "2.0"}, {"id", "a"}, {"method", "initialize"}, {"params", {{"protocolVersion", "2099-01-01"}}}});
    EXPECT_EQ((*r)["result"]["protocolVersion"], "2025-11-25");
    EXPECT_EQ((*r)["id"], "a");

    EXPECT_FALSE(server.handle({{"jsonrpc", "2.0"}, {"method", "notifications/initialized"}}));
    EXPECT_FALSE(server.handle({{"jsonrpc", "2.0"}, {"id", 9}, {"result", json::object()}}));
    EXPECT_EQ((*server.handle({{"jsonrpc", "2.0"}, {"id", 2}, {"method", "ping"}}))["result"], json::object());
    EXPECT_EQ((*server.handle({{"jsonrpc", "2.0"}, {"id", 3}, {"method", "tools/list"}}))["result"]["tools"],
              catalog().tools());
    EXPECT_EQ((*server.handle({{"jsonrpc", "2.0"}, {"id", 4}, {"method", "nope"}}))["error"]["code"], -32601);
    EXPECT_EQ((*server.handle({{"jsonrpc", "2.0"}, {"id", 5}, {"method", "tools/call"}, {"params", {{"name", "nope"}}}}))
                  ["error"]["code"], -32602);
    EXPECT_EQ((*server.handle(json::array()))["error"]["code"], -32600);
    EXPECT_EQ((*server.handle({{"jsonrpc", 2}, {"id", 1}, {"method", "ping"}}))["error"]["code"], -32600);
    EXPECT_EQ((*server.handle({{"jsonrpc", "2.0"}, {"id", 8}, {"method", "initialize"}, {"params", {{"protocolVersion", 5}}}}))
                  ["result"]["protocolVersion"], "2025-11-25");
    EXPECT_EQ(mcp::Server::parseError()["error"]["code"], -32700);

    r = server.handle({{"jsonrpc", "2.0"}, {"id", 6}, {"method", "tools/call"},
                       {"params", {{"name", "vh_read"}, {"arguments", {{"command", "group list"}}}}}});
    EXPECT_FALSE((*r)["result"]["isError"].get<bool>());
    r = server.handle({{"jsonrpc", "2.0"}, {"id", 7}, {"method", "tools/call"},
                       {"params", {{"name", "vh_run"}, {"arguments", {{"command", "secrets export jwt-secret"}}}}}});
    EXPECT_TRUE((*r)["result"]["isError"].get<bool>());
    EXPECT_EQ(ran, std::vector<std::string>{"group list --json"}) << "an excluded command never reaches the executor";
}

// ---- the MCP layer's destructive gate ---------------------------------------------------------------------------

TEST(McpCatalog, DestructiveCommandsNeedTheAcknowledgementBeforeAnythingRuns) {
    struct Case {
        std::string tool;
        json args;
        std::string command;
    };
    const std::vector<Case> cases{
        {"vh_run", {{"command", "vault delete 3"}}, "vault delete"},
        {"vaults_delete", {{"vault", 3}}, "vault delete"},
        {"vh_run", {{"command", "user delete bob --transfer-to alice"}}, "user delete"},
        {"users_delete", {{"user", "bob"}}, "user delete"},
        {"vh_run", {{"command", "vault keys rotate 3"}}, "vault key rotate"},
        {"vh_run", {{"command", "vault key rotate all --now"}}, "vault key rotate"},
    };
    for (const auto& c : cases) {
        auto prepared = catalog().prepare(c.tool, c.args);
        ASSERT_TRUE(std::holds_alternative<json>(prepared)) << c.tool << " ran without the acknowledgement";
        const auto& r = std::get<json>(prepared);
        EXPECT_TRUE(r.at("isError").get<bool>());
        const auto& sc = r.at("structuredContent");
        EXPECT_EQ(sc.at("needs_confirmation"), "destructive") << c.tool;
        EXPECT_EQ(sc.at("command"), "vh " + c.command);
        EXPECT_NE(sc.at("message").get<std::string>().find("is destructive"), std::string::npos);
        EXPECT_NE(sc.at("message").get<std::string>().find("Nothing was run"), std::string::npos);

        auto acked = c.args;
        acked["confirm"] = {{"destructive", true}};
        const auto inv = invocation(c.tool, acked);
        EXPECT_EQ(inv.command, c.command);
        EXPECT_EQ(inv.effect, CommandEffect::Destructive);
        EXPECT_TRUE(std::ranges::none_of(inv.argv, [](const auto& a) { return a == "--destructive"; }))
            << "the acknowledgement is the MCP layer's, never a CLI flag: " << inv.line;
    }
    // false is no acknowledgement; write and read commands need none.
    EXPECT_TRUE(std::holds_alternative<json>(
        catalog().prepare("vaults_delete", {{"vault", 3}, {"confirm", {{"destructive", false}}}})));
    EXPECT_FALSE(invocation("vh_run", {{"command", "group create devs"}}).line.empty());
    EXPECT_FALSE(invocation("vh_read", {{"command", "vault list"}}).line.empty());

    // Through the server: the executor never sees an unacknowledged destructive call.
    std::vector<std::string> ran;
    mcp::Server server(catalog(), [&](const mcp::Invocation& call) {
        ran.push_back(call.line);
        return mcp::CommandOutput{.exit_code = 0, .out = "ok", .err = {}, .confirmation = {}};
    }, "test");
    auto r = server.handle({{"jsonrpc", "2.0"}, {"id", 1}, {"method", "tools/call"},
                            {"params", {{"name", "vaults_delete"}, {"arguments", {{"vault", 3}}}}}});
    EXPECT_EQ((*r)["result"]["structuredContent"]["needs_confirmation"], "destructive");
    EXPECT_TRUE(ran.empty());
    r = server.handle({{"jsonrpc", "2.0"}, {"id", 2}, {"method", "tools/call"},
                       {"params", {{"name", "vaults_delete"}, {"arguments", {{"vault", 3}, {"confirm", {{"destructive", true}}}}}}}});
    EXPECT_FALSE((*r)["result"]["isError"].get<bool>());
    EXPECT_EQ(ran, std::vector<std::string>{"vault delete 3"});
}

// ---- the daemon's structured confirmation signal ----------------------------------------------------------------

TEST(McpCatalog, StructuredConfirmationSignalWinsOverTheText) {
    const auto inv = invocation("users_delete", {{"user", "bob"}, {"confirm", {{"destructive", true}}}});
    // The text names no flag at all: only the frame's `confirmation` says what is missing.
    auto r = catalog().finish(inv, {.exit_code = 2, .out = {}, .err = "user delete: bob owns 2 vaults",
                                    .confirmation = mcp::Confirmation{.code = "user_delete", .flags = {"--yes"}}});
    EXPECT_EQ(r.at("structuredContent").at("needs_confirmation"), "yes");
    EXPECT_EQ(r.at("structuredContent").at("code"), "user_delete");
    // A flag the command doesn't take is not something an agent could confirm: an ordinary failure.
    r = catalog().finish(inv, {.exit_code = 2, .out = {}, .err = "Re-run with --yes",
                               .confirmation = mcp::Confirmation{.code = "x", .flags = {"--accept-nothing"}}});
    EXPECT_FALSE(r.contains("structuredContent"));
}

TEST(McpCatalog, RouterAttachesTheConfirmationNoteToARefusal) {
    using namespace protocols::shell;
    (void)router();
    Router r;
    auto usage = std::make_shared<CommandUsage>();
    usage->aliases = {"mcptestcmd"};
    usage->optional_flags = {Flag::Alias("ok", "succeed", "ok")};
    r.registerCommand(usage, [](const CommandCall& call) {
        noteConfirmationNeeded("test_code", {"--yes"});
        if (std::ranges::any_of(call.options, [](const auto& o) { return o.key == "ok"; })) return CommandResult{0, "done", ""};
        return CommandResult{2, "", "refused: Re-run with --yes"};
    });
    identities::UserState state;
    state.name = "mcp-test";
    const auto user = identities::User::detached(1, std::move(state));

    auto res = r.executeLine("mcptestcmd", user);
    EXPECT_EQ(res.exit_code, 2);
    ASSERT_TRUE(res.confirmation);
    EXPECT_EQ(res.confirmation->code, "test_code");
    EXPECT_EQ(res.confirmation->flags, std::vector<std::string>{"--yes"});

    res = r.executeLine("mcptestcmd --ok", user);
    EXPECT_EQ(res.exit_code, 0);
    EXPECT_FALSE(res.confirmation) << "a success never carries it";
    EXPECT_FALSE(takeConfirmationNeeded()) << "nothing left over for the next command";
}

// ---- skill ------------------------------------------------------------------------------------------------------

TEST(McpSkill, FrontmatterAndLocations) {
    const auto md = mcp::skill::skillMarkdown();
    ASSERT_TRUE(md.starts_with("---\nname: vaulthalla\ndescription: "));
    const auto descStart = md.find("description: ") + 13;
    const auto desc = md.substr(descStart, md.find('\n', descStart) - descStart);
    EXPECT_LE(desc.size(), 1024u) << "Agent Skills limit";
    EXPECT_NE(md.find("\n---\n"), std::string::npos);
    for (const auto* rule : {"Read before you write", "vh_help", "confirm", "vh vault keys export", "Report what changed"})
        EXPECT_NE(md.find(rule), std::string::npos) << rule;

    using mcp::skill::Agent;
    using mcp::skill::Scope;
    EXPECT_EQ(mcp::skill::skillDir(Agent::Claude, Scope::User, "/h", "/p"), "/h/.claude/skills/vaulthalla");
    EXPECT_EQ(mcp::skill::skillDir(Agent::Claude, Scope::Project, "/h", "/p"), "/p/.claude/skills/vaulthalla");
    EXPECT_EQ(mcp::skill::skillDir(Agent::Codex, Scope::User, "/h", "/p"), "/h/.agents/skills/vaulthalla");
    EXPECT_EQ(mcp::skill::skillDir(Agent::Codex, Scope::Project, "/h", "/p"), "/p/.agents/skills/vaulthalla");
    EXPECT_EQ(mcp::skill::registerCommand(Agent::Claude, Scope::User, "vh"),
              (std::vector<std::string>{"claude", "mcp", "add", "--scope", "user", "vaulthalla", "--", "vh", "mcp"}));
    EXPECT_EQ(mcp::skill::registerCommand(Agent::Codex, Scope::User, "vh"),
              (std::vector<std::string>{"codex", "mcp", "add", "vaulthalla", "--", "vh", "mcp"}));
    EXPECT_TRUE(mcp::skill::registerCommand(Agent::Codex, Scope::Project, "vh").empty());
}

}
