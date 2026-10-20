// The MCP tool catalog: typed tools from the operation catalog, vh_help over the usage book, vh_read / vh_run for any
// CLI leaf. Everything here is derived from the usage definitions, so a new command or operation shows up without
// touching this file; only the exclusion list is maintained by hand.

#include "Mcp.hpp"
#include "CommandUsage.hpp"
#include "Contract.hpp"
#include "UsageManager.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <unordered_set>
#include <utility>

namespace vh::mcp {

namespace {

using protocols::shell::CommandEffect;
using protocols::shell::CommandUsage;
using UsagePtr = std::shared_ptr<CommandUsage>;

constexpr std::string_view kKeysReason =
    "key and secret material is never handled by agents (D4); the human runs this in a terminal themselves";

}

const std::vector<Exclusion>& exclusions() {
    static const std::vector<Exclusion> list{
        {{"vault", "key", "export"}, kKeysReason},
        {{"secrets", "export"}, kKeysReason},
        {{"secrets", "update"}, "internal secrets are changed by the operator, never by an agent"},
        {{"setup"}, "installation and lifecycle commands need root and a human at the terminal (this includes "
                    "setup set-super-admin-password)"},
        {{"setup", "set-super-admin-password"}, "the super-admin password is set by a human at the terminal"},
        {{"teardown"}, "installation and lifecycle commands need root and a human at the terminal"},
        {{"fs", "get"}, "file bytes have no channel over MCP yet"},
        {{"fs", "put"}, "file bytes have no channel over MCP yet"},
        // Client-side commands: they only mean something to the vh binary itself.
        {{"mcp"}, "this is the MCP server itself"},
        {{"skill"}, "agent setup is done by the human"},
    };
    return list;
}

// Types that Catalog::Impl holds or captures in lambdas (an internal-linkage one is -Wsubobject-linkage on GCC).
namespace detail {

// One token of a command line: a flag (without dashes) or a word.
struct Tok {
    bool flag = false;
    std::string text{};
};

struct Parsed {
    std::string name{};
    std::vector<std::pair<std::string, std::optional<std::string>>> options{};
    std::vector<std::string> positionals{};
};

}

using detail::Parsed;
using detail::Tok;

namespace {

// ---- small helpers ----------------------------------------------------------------------------------------------

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string joinWords(const std::vector<std::string>& v, const std::string_view sep = " ") {
    std::string out;
    for (const auto& s : v) {
        if (!out.empty()) out += sep;
        out += s;
    }
    return out;
}

std::string effectText(const CommandEffect e) { return std::string(protocols::shell::effectName(e)); }

Json annotationsFor(const CommandEffect e, std::string title) {
    const bool read = e == CommandEffect::Read;
    return {{"title", std::move(title)},
            {"readOnlyHint", read},
            {"destructiveHint", e == CommandEffect::Destructive},
            {"idempotentHint", read},
            {"openWorldHint", false}};
}

Json textResult(std::string text, const bool isError) {
    return {{"content", Json::array({{{"type", "text"}, {"text", std::move(text)}}})}, {"isError", isError}};
}

Json errorResult(std::string text) { return textResult(std::move(text), true); }

// ---- the shell tokenizer, mirrored ------------------------------------------------------------------------------
//
// The same rules as protocols/shell/Token.hpp + Parser.hpp (which need daemon types). An agent's command is
// tokenized here, checked (leaf, exclusions, confirmation flags) and rendered again from these tokens, so what the
// daemon parses is exactly what was checked.


bool looksNegativeNumber(const std::string_view s) {
    if (s.size() < 2 || s[0] != '-') return false;
    bool dot = false, digit = false;
    for (size_t i = 1; i < s.size(); ++i) {
        const char c = s[i];
        if (c >= '0' && c <= '9') { digit = true; continue; }
        if (c == '.' && !dot) { dot = true; continue; }
        return false;
    }
    return digit;
}

bool looksGluedValue(const std::string_view tail) {
    return std::ranges::any_of(tail, [](const char c) { return c == '/' || c == '.' || c == ':' || c == '='; });
}

void pushFlag(std::vector<Tok>& out, std::string k) {
    if (!k.empty() && k[0] == '-') k.erase(k.begin());
    out.push_back({true, std::move(k)});
}

void pushWord(std::vector<Tok>& out, std::string v) { out.push_back({false, std::move(v)}); }

std::string readQuoted(size_t& p, const std::string& s, const char quote) {
    ++p;
    std::string buf;
    while (p < s.size()) {
        if (s[p] == quote) { ++p; break; }
        if (quote == '"' && s[p] == '\\' && p + 1 < s.size()) {
            ++p;
            buf.push_back(s[p++]);
            continue;
        }
        buf.push_back(s[p++]);
    }
    return buf;
}

std::string readUnquotedAtom(size_t& p, const std::string& s) {
    const size_t b = p;
    while (p < s.size() && s[p] != ' ' && s[p] != '\t' && s[p] != '"' && s[p] != '\'') ++p;
    return s.substr(b, p - b);
}

void skipWs(size_t& p, const std::string& s) {
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) ++p;
}

std::vector<Tok> tokenize(const std::string& line) {
    std::vector<Tok> out;
    size_t p = 0;
    const auto& s = line;
    skipWs(p, s);
    while (p < s.size()) {
        if (s[p] == '-' && p + 1 < s.size() && s[p + 1] == '-' && (p + 2 == s.size() || s[p + 2] == ' ' || s[p + 2] == '\t')) {
            p += 2;
            pushWord(out, "--");
            skipWs(p, s);
            continue;
        }
        if (s[p] == '"' || s[p] == '\'') {
            const char q = s[p];
            pushWord(out, readQuoted(p, s, q));
            skipWs(p, s);
            continue;
        }
        if (s[p] == '-') {
            std::string pre = readUnquotedAtom(p, s);
            if (p < s.size() && (s[p] == '"' || s[p] == '\'') && !pre.empty() &&
                (pre.back() == '=' || (pre.size() == 2 && pre[0] == '-' && pre[1] != '-'))) {
                const char q = s[p];
                pre += readQuoted(p, s, q);
            }
            if (looksNegativeNumber(pre)) {
                pushWord(out, std::move(pre));
            } else if (pre.starts_with("--")) {
                if (out.empty()) {
                    pushWord(out, std::move(pre));
                } else if (const auto eq = pre.find('='); eq == std::string::npos) {
                    pushFlag(out, pre.substr(2));
                } else {
                    pushFlag(out, pre.substr(2, eq - 2));
                    pushWord(out, pre.substr(eq + 1));
                }
            } else if (pre.size() >= 2 && pre[1] != '-') {
                if (pre.size() == 2) {
                    if (out.empty()) pushWord(out, pre);
                    else pushFlag(out, pre.substr(1));
                } else {
                    const std::string_view tail = std::string_view(pre).substr(2);
                    if (looksGluedValue(tail)) {
                        pushFlag(out, std::string(1, pre[1]));
                        std::string value(tail);
                        if (!value.empty() && value[0] == '=') value.erase(value.begin());
                        pushWord(out, std::move(value));
                    } else {
                        for (const char c : tail) pushFlag(out, std::string(1, c));
                    }
                }
            } else {
                pushWord(out, std::move(pre));
            }
            skipWs(p, s);
            continue;
        }
        std::string atom = readUnquotedAtom(p, s);
        if (p < s.size() && (s[p] == '"' || s[p] == '\'') && !atom.empty() && atom.back() == '=') {
            const char q = s[p];
            atom += readQuoted(p, s, q);
        }
        pushWord(out, std::move(atom));
        skipWs(p, s);
    }
    return out;
}

bool needsQuotes(const std::string& w) {
    if (w.empty() || w.front() == '-') return true;
    return std::ranges::any_of(w, [](const char c) { return c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '\\'; });
}

std::string quoteWord(const std::string& w) {
    if (!needsQuotes(w)) return w;
    std::string out{"\""};
    for (const char c : w) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

std::string renderToken(const Tok& t) {
    if (t.flag) return (t.text.size() == 1 ? "-" : "--") + t.text;
    return quoteWord(t.text);
}

bool plainOptionName(const std::string& k) {
    if (k.empty() || !std::isalpha(static_cast<unsigned char>(k.front()))) return false;
    return std::ranges::all_of(k, [](const unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; });
}


// parseTokens: the first word names the command; a flag followed by a word takes it as its value.
Parsed parse(const std::vector<Tok>& toks) {
    Parsed call;
    size_t i = 1;
    call.name = toks.front().text;
    for (; i < toks.size(); ++i) {
        const auto& t = toks[i];
        if (t.flag) {
            if (i + 1 < toks.size() && !toks[i + 1].flag) {
                call.options.emplace_back(t.text, toks[i + 1].text);
                ++i;
            } else {
                call.options.emplace_back(t.text, std::nullopt);
            }
            continue;
        }
        call.positionals.push_back(t.text);
    }
    return call;
}

// ---- the usage tree ---------------------------------------------------------------------------------------------

std::vector<std::string> canonicalPath(const CommandUsage& node) {
    std::vector<std::string> path;
    for (const auto* n = &node;;) {
        const auto parent = n->parent.lock();
        if (!parent) break;
        path.insert(path.begin(), n->aliases.front());
        n = parent.get();
    }
    return path;
}

const Exclusion* excludedBy(const std::vector<std::string>& path) {
    for (const auto& ex : exclusions())
        if (path.size() >= ex.path.size() && std::equal(ex.path.begin(), ex.path.end(), path.begin())) return &ex;
    return nullptr;
}

template <class F>
void forEachFlag(const CommandUsage& n, F&& f) {
    for (const auto& fl : n.required_flags) f(fl);
    for (const auto& fl : n.optional_flags) f(fl);
    for (const auto& g : n.groups)
        for (const auto& item : g.items)
            if (const auto* fl = std::get_if<protocols::shell::Flag>(&item)) f(*fl);
}

// f(option, required, default value or nullptr)
template <class F>
void forEachOption(const CommandUsage& n, F&& f) {
    for (const auto& o : n.required) f(o, true, nullptr);
    for (const auto& o : n.optional) f(o, false, o.default_value ? &*o.default_value : nullptr);
    for (const auto& g : n.groups)
        for (const auto& item : g.items)
            if (const auto* o = std::get_if<protocols::shell::Optional>(&item))
                f(*o, false, o->default_value ? &*o->default_value : nullptr);
}

}  // namespace

// Types Catalog::Impl holds or captures (an internal-linkage one would be -Wsubobject-linkage on GCC).
namespace detail {

// A flag (or the --confirm-token option) that bypasses a confirmation the command would otherwise ask a person for.
struct Gate {
    std::string name{};                  // the spelling agents pass in `confirm` ("yes", "accept-key-loss")
    std::vector<std::string> aliases{};  // every spelling the command accepts
    bool takesValue = false;
    std::string description{};
};

struct Leaf {
    std::shared_ptr<protocols::shell::CommandUsage> node{};
    std::vector<std::string> path{};
    std::string command{};  // "vault delete"
    std::vector<Gate> gates{};
    std::vector<std::string> jsonAliases{};
    const Exclusion* exclusion = nullptr;
    std::vector<std::string> typedTools{};

    [[nodiscard]] const Gate* gate(const std::string& name) const {
        for (const auto& g : gates)
            if (g.name == name || std::ranges::find(g.aliases, name) != g.aliases.end()) return &g;
        return nullptr;
    }
    [[nodiscard]] std::vector<std::string> gateNames() const {
        std::vector<std::string> v;
        for (const auto& g : gates) v.push_back(g.name);
        return v;
    }
};

struct Typed {
    std::string name{};
    contract::OperationSpec op{};
    const Leaf* leaf = nullptr;
    protocols::shell::CommandEffect effect = protocols::shell::CommandEffect::Unset;
    Json definition{};
};

}

using detail::Gate;
using detail::Leaf;
using detail::Typed;

namespace {

bool isGateSpelling(const std::string& a) { return a == "yes" || a.starts_with("accept-") || a == "confirm-token"; }

Leaf describeLeaf(const UsagePtr& node) {
    Leaf leaf{.node = node, .path = canonicalPath(*node)};
    leaf.command = joinWords(leaf.path);
    leaf.exclusion = excludedBy(leaf.path);
    forEachFlag(*node, [&](const protocols::shell::Flag& f) {
        if (std::ranges::find(f.aliases, "json") != f.aliases.end()) leaf.jsonAliases = f.aliases;
        const auto it = std::ranges::find_if(f.aliases, isGateSpelling);
        if (it == f.aliases.end()) return;
        const bool hasYes = std::ranges::find(f.aliases, "yes") != f.aliases.end();
        leaf.gates.push_back({.name = hasYes ? "yes" : *it, .aliases = f.aliases, .description = f.desc});
    });
    forEachOption(*node, [&](const protocols::shell::Option& o, bool, const std::string*) {
        if (std::ranges::find(o.option_tokens, "confirm-token") != o.option_tokens.end())
            leaf.gates.push_back({.name = "confirm-token", .aliases = o.option_tokens, .takesValue = true,
                                  .description = o.desc});
    });
    return leaf;
}

// ---- JSON Schema ------------------------------------------------------------------------------------------------

Json confirmSchema(const Leaf& leaf) {
    Json props = Json::object();
    for (const auto& g : leaf.gates)
        props[g.name] = g.takesValue
                            ? Json{{"type", "string"}, {"minLength", 1},
                                   {"description", g.description + " (the token the refusal printed)"}}
                            : Json{{"type", "boolean"}, {"const", true}, {"description", g.description}};
    return {{"type", "object"},
            {"description", "Confirmations, passed as --" + joinWords(leaf.gateNames(), " / --") +
                                ". Set one ONLY after the human explicitly approved this exact action in this "
                                "conversation, normally after a call without it returned needs_confirmation."},
            {"properties", props},
            {"additionalProperties", false}};
}

Json runSchema(const std::string& what) {
    return {{"type", "object"},
            {"properties",
             {{"command",
               {{"type", "string"},
                {"minLength", 1},
                {"description", "The vh command line without 'vh', e.g. \"" + what +
                                    "\". Quote values with spaces. Never include --yes, --accept-* or "
                                    "--confirm-token: use confirm."}}},
              {"confirm",
               {{"type", "object"},
                {"description", "Confirmation flags by name, e.g. {\"yes\": true} or {\"confirm-token\": \"<token>\"}. "
                                "Set them ONLY after the human explicitly approved this exact action in this "
                                "conversation, normally after a call without them returned needs_confirmation."},
                {"additionalProperties", {{"type", {"boolean", "string"}}}}}}}},
            {"required", {"command"}},
            {"additionalProperties", false}};
}

// ---- typed tools ------------------------------------------------------------------------------------------------

CommandEffect strongest(const CommandEffect a, const CommandEffect b) { return std::max(a, b); }

CommandEffect opEffect(const contract::Effect& e) {
    if (e.kind == "read") return CommandEffect::Read;
    if (e.kind == "delete") return CommandEffect::Destructive;
    return CommandEffect::Write;
}

std::pair<std::string, std::string> splitEntry(const std::string& entry) {
    const auto colon = entry.find(':');
    return {entry.substr(0, colon), colon == std::string::npos ? std::string{} : entry.substr(colon + 1)};
}

// The CLI entry a binding names ("optional:email"), for its description.
std::string entryDescription(const CommandUsage& n, const std::string& entry) {
    const auto [kind, label] = splitEntry(entry);
    if (kind == "positional")
        for (const auto& p : n.positionals)
            if (p.label == label) return p.desc;
    std::string found;
    if (kind == "option" || kind == "optional" || kind == "token")
        forEachOption(n, [&](const protocols::shell::Option& o, bool, const std::string*) {
            if (o.label == label) found = o.desc;
        });
    if (kind == "flag") forEachFlag(n, [&](const protocols::shell::Flag& f) { if (f.label == label) found = f.desc; });
    return found;
}

Json fieldSchema(const contract::FieldSpec& f, const std::string& fallbackDescription) {
    Json s;
    if (f.type == "uint") s = {{"type", "integer"}, {"minimum", 0}};
    else if (f.type == "bool") s = {{"type", "boolean"}};
    else if (f.type == "enum") s = {{"type", "string"}, {"enum", f.enum_values}};
    else if (f.type == "ref") s = {{"type", {"string", "integer"}}};
    else s = {{"type", "string"}};
    std::string d = f.description.empty() ? fallbackDescription : f.description;
    if (f.type == "ref" && !f.ref.empty()) d += (d.empty() ? "" : " ") + std::string("(a ") + f.ref + " name or id)";
    if (f.type == "path" && d.empty()) d = "Vault path, e.g. /docs/report.pdf";
    if (!d.empty()) s["description"] = d;
    return s;
}

}  // namespace

// ---- Impl -------------------------------------------------------------------------------------------------------

struct Catalog::Impl {
    protocols::shell::UsageManager usage;
    std::vector<Leaf> leaves;                 // every CLI leaf, depth-first in declaration order
    std::map<const CommandUsage*, size_t> leafIndex;
    std::vector<Typed> typed;
    Json tools = Json::array();
    std::set<std::string> toolNames;

    Impl() {
        std::unordered_set<const CommandUsage*> seen;
        collect(usage.root(), seen);
        buildTyped();
        buildTools();
    }

    void collect(const UsagePtr& node, std::unordered_set<const CommandUsage*>& seen) {
        if (!node || !seen.insert(node.get()).second) return;
        node->show_aliases = false;  // this tree is the catalog's own: synopses name each command once
        if (!node->parent.expired() && node->subcommands.empty()) {
            leafIndex[node.get()] = leaves.size();
            leaves.push_back(describeLeaf(node));
        }
        for (const auto& sc : node->subcommands) collect(sc, seen);
    }

    [[nodiscard]] const Leaf* leafOf(const CommandUsage* n) const {
        const auto it = leafIndex.find(n);
        return it == leafIndex.end() ? nullptr : &leaves[it->second];
    }

    // Resolution as shell::Router does it: the first word names a top-level command (any alias, any case, or a
    // plural that implies "list"); every later positional that names a subcommand of the node reached descends.
    struct Resolved {
        std::vector<UsagePtr> path;
        bool pluralList = false;
        std::string error;
    };

    [[nodiscard]] Resolved resolve(const std::string& name, const std::vector<std::string>& positionals) const {
        Resolved r;
        const auto first = lower(name);
        UsagePtr top = usage.root()->findSubcommand(first);
        if (!top)
            for (const auto& sc : usage.root()->subcommands)
                if (sc->pluralAliasImpliesList && lower(sc->primary()) + "s" == first) {
                    top = sc;
                    r.pluralList = positionals.empty();
                }
        if (!top) {
            r.error = "unknown command '" + name + "'. Call vh_help to see the commands.";
            return r;
        }
        r.path.push_back(top);
        auto words = positionals;
        if (r.pluralList) words.emplace_back("list");
        for (const auto& w : words)
            if (auto child = r.path.back()->findSubcommand(w)) r.path.push_back(std::move(child));
        return r;
    }

    void buildTyped() {
        for (auto& op : contract::operations()) {
            if (!op.cli) continue;
            UsagePtr node;
            try {
                node = usage.resolve(op.cli->usage_path);
            } catch (const std::exception&) {
                continue;
            }
            const auto idx = node ? leafIndex.find(node.get()) : leafIndex.end();
            if (idx == leafIndex.end() || leaves[idx->second].exclusion) continue;
            auto& leaf = leaves[idx->second];
            leaf.typedTools.push_back(op.id);
            std::ranges::replace(leaf.typedTools.back(), '.', '_');
            Typed t{.op = op, .leaf = &leaf};
            t.name = op.id;
            std::ranges::replace(t.name, '.', '_');
            t.effect = strongest(opEffect(op.effect), leaf.node->effect);
            typed.push_back(std::move(t));
        }
        for (auto& t : typed) t.definition = typedDefinition(t);
    }

    [[nodiscard]] static Json typedDefinition(const Typed& t) {
        Json props = Json::object();
        Json required = Json::array();
        const auto& cli = *t.op.cli;
        for (const auto& f : t.op.fields) {
            const auto it = cli.field_to_entry.find(f.name);
            if (it == cli.field_to_entry.end()) continue;  // a field this surface doesn't take (e.g. a password)
            props[f.name] = fieldSchema(f, entryDescription(*t.leaf->node, it->second));
            if (f.required) required.push_back(f.name);
        }
        if (!t.leaf->gates.empty()) props["confirm"] = confirmSchema(*t.leaf);
        std::string desc = t.op.description + "\nRuns: " + t.leaf->node->synopsisLine() + "\nEffect: " +
                           effectText(t.effect) + ".";
        if (!t.leaf->gates.empty())
            desc += " Asks for confirmation: a first call returns needs_confirmation; ask the human, then call again "
                    "with confirm.";
        Json schema{{"type", "object"}, {"properties", props}, {"additionalProperties", false}};
        if (!required.empty()) schema["required"] = required;
        return {{"name", t.name},
                {"title", t.op.description},
                {"description", desc},
                {"inputSchema", schema},
                {"annotations", annotationsFor(t.effect, "vh " + t.leaf->command)}};
    }

    void buildTools() {
        tools.push_back({{"name", "vh_help"},
                         {"title", "Vaulthalla command help"},
                         {"description",
                          "Browse the Vaulthalla command reference: without a path, the top-level commands; with a "
                          "path (\"vault\", \"vault role assign\"), that command's description, arguments, options, "
                          "examples, effect (read/write/destructive), confirmations and which tool runs it. Use it "
                          "before running anything you have not run before."},
                         {"inputSchema",
                          {{"type", "object"},
                           {"properties",
                            {{"path", {{"type", "string"}, {"description", "Command path, e.g. \"vault sync\""}}}}},
                           {"additionalProperties", false}}},
                         {"annotations", annotationsFor(CommandEffect::Read, "Vaulthalla command help")}});
        tools.push_back({{"name", "vh_read"},
                         {"title", "Run a read-only vh command"},
                         {"description",
                          "Run a read-only Vaulthalla CLI command (effect \"read\" in vh_help) as the human's own "
                          "Vaulthalla user, e.g. \"vault list\", \"user info alice\", \"status\". Output is JSON where "
                          "the command supports it. Commands that change anything are refused here: use a typed tool "
                          "or vh_run."},
                         {"inputSchema", runSchema("vault list")},
                         {"annotations", annotationsFor(CommandEffect::Read, "Run a read-only vh command")}});
        tools.push_back({{"name", "vh_run"},
                         {"title", "Run a vh command"},
                         {"description",
                          "Run any Vaulthalla CLI command available to agents (see vh_help) as the human's own "
                          "Vaulthalla user; prefer a typed tool when one exists and vh_read for read-only commands. "
                          "It may change or delete data: say what and why first. Commands that need confirmation "
                          "return needs_confirmation; ask the human, then call again with confirm. Key and secret "
                          "export, secrets update, setup, teardown and file transfer are never available."},
                         {"inputSchema", runSchema("vault create projects --desc 'Team files'")},
                         {"annotations", annotationsFor(CommandEffect::Destructive, "Run a vh command")}});
        for (const auto& t : typed) tools.push_back(t.definition);
        for (const auto& t : tools) toolNames.insert(t.at("name").get<std::string>());
    }

    // ---- invocations --------------------------------------------------------------------------------------------

    // Adds confirmations and --json, renders the line. `error` is set when the call is refused.
    std::variant<Invocation, Json> finalize(const std::string& tool, const Leaf& leaf, std::vector<Tok> toks,
                                            const Json& confirm, const bool help,
                                            const std::vector<std::pair<std::string, std::optional<std::string>>>& options) const {
        Invocation inv{.tool = tool, .command = leaf.command,
                       .effect = help ? CommandEffect::Read : leaf.node->effect, .gates = leaf.gateNames()};
        if (!confirm.is_null()) {
            if (!confirm.is_object()) return errorResult("confirm must be an object, e.g. {\"yes\": true}");
            for (const auto& [key, value] : confirm.items()) {
                auto name = key;
                while (name.starts_with("-")) name.erase(name.begin());
                const auto* gate = leaf.gate(name);
                if (!gate)
                    return errorResult("vh " + leaf.command + " has no confirmation '" + key + "'" +
                                       (leaf.gates.empty() ? std::string(": it never asks for one.")
                                                           : "; it takes: " + joinWords(leaf.gateNames(), ", ")));
                if (gate->takesValue) {
                    if (!value.is_string() || value.get<std::string>().empty())
                        return errorResult("confirm." + gate->name + " must be the token the refusal printed");
                    toks.push_back({true, gate->name});
                    toks.push_back({false, value.get<std::string>()});
                } else {
                    if (value != Json(true)) {
                        if (value == Json(false)) continue;
                        return errorResult("confirm." + gate->name + " must be true");
                    }
                    toks.push_back({true, gate->name});
                }
                inv.confirmed.push_back(gate->name);
            }
        }
        const bool hasJson = std::ranges::any_of(options, [&](const auto& o) {
            return std::ranges::find(leaf.jsonAliases, o.first) != leaf.jsonAliases.end();
        });
        if (!help && !leaf.jsonAliases.empty() && !hasJson) toks.push_back({true, "json"});

        for (const auto& t : toks) {
            inv.argv.push_back(t.flag ? (t.text.size() == 1 ? "-" : "--") + t.text : t.text);
            inv.line += (inv.line.empty() ? "" : " ") + renderToken(t);
        }
        return inv;
    }

    std::variant<Invocation, Json> prepareCommand(const std::string& tool, const Json& args) const {
        if (!args.is_object()) return errorResult("arguments must be an object with a command");
        for (const auto& [key, value] : args.items())
            if (key != "command" && key != "confirm") return errorResult("unknown argument '" + key + "'");
        if (!args.contains("command") || !args["command"].is_string())
            return errorResult("command (a string) is required, e.g. {\"command\": \"vault list\"}");

        auto toks = tokenize(args["command"].get<std::string>());
        while (!toks.empty() && !toks.front().flag &&
               (toks.front().text == "vh" || toks.front().text == "vaulthalla" || toks.front().text == "vaulthalla-cli"))
            toks.erase(toks.begin());
        if (toks.empty()) return errorResult("command is empty; call vh_help to see the commands");
        if (toks.front().flag) return errorResult("a command starts with its name, e.g. \"vault list\"");
        for (const auto& t : toks) {
            if (!t.flag && t.text == "--")
                return errorResult("'--' is not supported here; quote values that start with '-'");
            if (t.flag && !plainOptionName(t.text) && t.text != "?")
                return errorResult("unsupported option spelling '-" + t.text + "'");
        }

        const auto call = parse(toks);
        const auto r = resolve(call.name, call.positionals);
        if (!r.error.empty()) return errorResult(r.error);
        const auto& node = r.path.back();
        std::vector<std::string> path;
        for (const auto& n : r.path) path.push_back(n->primary());
        const auto spelled = "vh " + joinWords(path);

        if (const auto* ex = excludedBy(path)) return errorResult(spelled + " is not available to agents: " + std::string(ex->reason) + ".");
        // Defense in depth: the same walk ignoring case must not reach an excluded command either.
        std::vector<std::string> lowered;
        for (const auto& p : call.positionals) lowered.push_back(lower(p));
        if (const auto rl = resolve(call.name, lowered); rl.error.empty()) {
            std::vector<std::string> lpath;
            for (const auto& n : rl.path) lpath.push_back(n->primary());
            if (const auto* ex = excludedBy(lpath))
                return errorResult("vh " + joinWords(lpath) + " is not available to agents: " + std::string(ex->reason) + ".");
        }

        const bool help = node->primary() == "help" ||
                          std::ranges::any_of(call.options, [](const auto& o) { return o.first == "help" || o.first == "h"; });
        const auto* leaf = leafOf(node.get());
        if (!leaf) {
            if (!help) {
                std::vector<std::string> subs;
                for (const auto& sc : node->subcommands)
                    if (!excludedBy(canonicalPath(*sc))) subs.push_back(sc->primary());
                return errorResult(spelled + " is a group of commands (" + joinWords(subs, ", ") +
                                   "); name one. vh_help {\"path\": \"" + joinWords(path) + "\"} describes them.");
            }
            // Help on a group: read-only and gate-free; run it as the help leaf would.
            Leaf group{.node = node, .path = path, .command = joinWords(path)};
            return finalize(tool, group, std::move(toks), Json(), true, call.options);
        }

        for (const auto& [key, value] : call.options)
            if (isGateSpelling(key) || leaf->gate(key))
                return errorResult("--" + key + " is a confirmation: never put it in the command. Ask the human "
                                   "first, then pass confirm: {\"" + (leaf->gate(key) ? leaf->gate(key)->name : key) +
                                   "\": " + (key == "confirm-token" ? "\"<token>\"" : "true") + "}.");

        if (tool == "vh_read" && !help && leaf->node->effect != CommandEffect::Read)
            return errorResult(spelled + " is a " + effectText(leaf->node->effect) +
                               " command; vh_read only runs read-only commands. Use " +
                               (leaf->typedTools.empty() ? std::string("vh_run")
                                                         : "the typed tool " + leaf->typedTools.front() + " or vh_run") +
                               ".");
        return finalize(tool, *leaf, std::move(toks), args.value("confirm", Json()), help, call.options);
    }

    std::variant<Invocation, Json> prepareTyped(const Typed& t, const Json& args) const {
        if (!args.is_object()) return errorResult("arguments must be an object");
        const auto& cli = *t.op.cli;
        const auto& node = *t.leaf->node;
        std::map<std::string, const contract::FieldSpec*> fields;
        for (const auto& f : t.op.fields)
            if (cli.field_to_entry.contains(f.name)) fields[f.name] = &f;

        std::map<std::string, std::string> values;
        for (const auto& [key, value] : args.items()) {
            if (key == "confirm") continue;
            const auto it = fields.find(key);
            if (it == fields.end()) return errorResult("unknown argument '" + key + "' for " + t.name);
            const auto& f = *it->second;
            if (value.is_null()) continue;
            if (f.type == "bool") {
                if (!value.is_boolean()) return errorResult(key + " must be true or false");
                if (value.get<bool>()) values[key] = "true";
                continue;
            }
            if (f.type == "uint") {
                if (!value.is_number_integer() || value.get<std::int64_t>() < 0)
                    return errorResult(key + " must be a whole number >= 0");
                values[key] = std::to_string(value.get<std::int64_t>());
                continue;
            }
            if (f.type == "ref" && value.is_number_integer()) {
                values[key] = std::to_string(value.get<std::int64_t>());
                continue;
            }
            if (!value.is_string()) return errorResult(key + " must be a string");
            const auto s = value.get<std::string>();
            if (f.type == "enum" && std::ranges::find(f.enum_values, s) == f.enum_values.end())
                return errorResult(key + " must be one of: " + joinWords(f.enum_values, ", "));
            values[key] = s;
        }
        for (const auto& [name, f] : fields)
            if (f->required && !values.contains(name)) return errorResult(name + " is required");

        std::vector<Tok> toks;
        for (const auto& w : cli.usage_path) toks.push_back({false, w});

        // field -> entry, and the option token a "token:<label>" field picks for that option
        std::map<std::string, std::string> entryValue, tokenFor;
        for (const auto& [field, entry] : cli.field_to_entry) {
            if (!values.contains(field)) continue;
            const auto [kind, label] = splitEntry(entry);
            if (kind == "token") tokenFor[label] = values.at(field);
            else entryValue[entry] = values.at(field);
        }

        bool gap = false;
        for (const auto& p : node.positionals) {
            const auto it = entryValue.find("positional:" + p.label);
            if (it == entryValue.end()) { gap = true; continue; }
            if (gap) return errorResult("set the arguments before " + p.label + " too");
            toks.push_back({false, it->second});
        }
        std::string err;
        forEachOption(node, [&](const protocols::shell::Option& o, bool, const std::string*) {
            for (const auto* kind : {"option:", "optional:"}) {
                const auto it = entryValue.find(kind + o.label);
                if (it == entryValue.end()) continue;
                auto token = o.option_tokens.front();
                if (const auto tk = tokenFor.find(o.label); tk != tokenFor.end()) {
                    if (std::ranges::find(o.option_tokens, tk->second) == o.option_tokens.end()) {
                        err = "no --" + tk->second + " for " + o.label;
                        return;
                    }
                    token = tk->second;
                }
                toks.push_back({true, token});
                toks.push_back({false, it->second});
            }
        });
        if (!err.empty()) return errorResult(err);
        const auto addFlag = [&](const std::string& label, const std::string& spelling) {
            forEachFlag(node, [&](const protocols::shell::Flag& f) {
                if (f.label != label) return;
                const auto alias = spelling.empty() ? f.aliases.front() : spelling;
                toks.push_back({true, alias});
            });
        };
        for (const auto& [entry, value] : entryValue)
            if (entry.starts_with("flag:") && value == "true") addFlag(entry.substr(5), "");
        // Fixed entries the binding always passes, except confirmations: those only ever come from `confirm`.
        for (const auto& [entry, value] : cli.fixed) {
            const auto [kind, label] = splitEntry(entry);
            if (kind != "flag") continue;
            bool gate = false;
            forEachFlag(node, [&](const protocols::shell::Flag& f) {
                if (f.label == label && std::ranges::any_of(f.aliases, isGateSpelling)) gate = true;
            });
            if (!gate) addFlag(label, value);
        }

        Parsed parsed = parse(toks);
        return finalize(t.name, *t.leaf, std::move(toks), args.value("confirm", Json()), false, parsed.options);
    }

    // ---- vh_help ------------------------------------------------------------------------------------------------

    [[nodiscard]] Json optionsJson(const CommandUsage& n) const {
        Json out = Json::array();
        forEachOption(n, [&](const protocols::shell::Option& o, const bool req, const std::string* def) {
            std::string tokens;
            for (const auto& t : o.option_tokens) tokens += (tokens.empty() ? "" : " | ") + std::string(t.size() == 1 ? "-" : "--") + t;
            Json j{{"option", tokens}, {"value", "<" + joinWords(o.value_tokens, "|") + ">"}, {"required", req},
                   {"description", o.desc}};
            if (def) j["default"] = *def;
            out.push_back(std::move(j));
        });
        return out;
    }

    [[nodiscard]] Json flagsJson(const CommandUsage& n) const {
        Json out = Json::array();
        forEachFlag(n, [&](const protocols::shell::Flag& f) {
            std::string tokens;
            for (const auto& t : f.aliases) tokens += (tokens.empty() ? "" : " | ") + std::string(t.size() == 1 ? "-" : "--") + t;
            out.push_back({{"flag", tokens}, {"description", f.desc}});
        });
        return out;
    }

    [[nodiscard]] Json nodeHelp(const UsagePtr& node) const {
        const auto path = canonicalPath(*node);
        Json j{{"command", "vh " + joinWords(path)}, {"aliases", node->aliases}, {"description", node->description}};
        if (const auto* leaf = leafOf(node.get())) {
            j["usage"] = node->synopsisLine();
            j["effect"] = effectText(node->effect);
            Json positionals = Json::array();
            for (const auto& p : node->positionals) positionals.push_back({{"name", p.label}, {"description", p.desc}});
            j["arguments"] = positionals;
            j["options"] = optionsJson(*node);
            j["flags"] = flagsJson(*node);
            if (!leaf->gates.empty())
                j["confirmations"] = {{"names", leaf->gateNames()},
                                      {"how", "Never in the command. A call without them returns needs_confirmation; "
                                              "show it to the human, and only after explicit approval call again "
                                              "with confirm: {\"<name>\": true} (confirm-token: the printed token)."}};
            j["json_output"] = !leaf->jsonAliases.empty();
            j["run_with"] = node->effect == CommandEffect::Read ? "vh_read" : "vh_run";
            if (!leaf->typedTools.empty()) j["typed_tools"] = leaf->typedTools;
        }
        Json subs = Json::array();
        for (const auto& sc : node->subcommands) {
            if (excludedBy(canonicalPath(*sc))) continue;
            Json s{{"name", sc->primary()}, {"description", sc->description}};
            if (sc->subcommands.empty()) s["effect"] = effectText(sc->effect);
            subs.push_back(std::move(s));
        }
        if (!subs.empty()) j["subcommands"] = subs;
        Json examples = Json::array();
        for (const auto& e : node->examples) examples.push_back({{"cmd", e.cmd}, {"note", e.note}});
        if (!examples.empty()) j["examples"] = examples;
        return j;
    }

    [[nodiscard]] Json help(const Json& args) const {
        if (!args.is_object()) return errorResult("arguments must be an object");
        for (const auto& [key, value] : args.items())
            if (key != "path") return errorResult("unknown argument '" + key + "'");
        std::vector<std::string> words;
        if (args.contains("path") && !args["path"].is_null()) {
            if (!args["path"].is_string()) return errorResult("path must be a string, e.g. \"vault role\"");
            std::istringstream in(args["path"].get<std::string>());
            for (std::string w; in >> w;) words.push_back(w);
        }
        if (!words.empty() && (words.front() == "vh" || words.front() == "vaulthalla")) words.erase(words.begin());

        if (words.empty()) {
            Json commands = Json::array();
            for (const auto& sc : usage.root()->subcommands) {
                if (excludedBy(canonicalPath(*sc))) continue;
                Json c{{"name", sc->primary()}, {"description", sc->description}};
                if (sc->subcommands.empty()) c["effect"] = effectText(sc->effect);
                commands.push_back(std::move(c));
            }
            Json j{{"commands", commands},
                   {"next", "Call vh_help with a path (\"vault\", \"vault sync set\") for arguments, options and examples."},
                   {"tools", "Prefer the typed tools; vh_read runs read-only commands, vh_run any other command."}};
            return textResult(j.dump(2), false);
        }

        UsagePtr node = usage.root();
        std::vector<std::string> walked;
        for (const auto& w : words) {
            auto child = node->findSubcommand(walked.empty() ? lower(w) : w);
            if (!child) {
                std::vector<std::string> subs;
                for (const auto& sc : node->subcommands)
                    if (!excludedBy(canonicalPath(*sc))) subs.push_back(sc->primary());
                return errorResult("no command '" + w + "' under 'vh" + (walked.empty() ? "" : " " + joinWords(walked)) +
                                   "'. Available: " + joinWords(subs, ", "));
            }
            node = std::move(child);
            walked.push_back(node->primary());
        }
        if (const auto* ex = excludedBy(canonicalPath(*node)))
            return errorResult("vh " + joinWords(canonicalPath(*node)) + " is not available to agents: " +
                               std::string(ex->reason) + ".");
        return textResult(nodeHelp(node).dump(2), false);
    }
};

// ---- Catalog ----------------------------------------------------------------------------------------------------

Catalog::Catalog() : impl_(std::make_unique<Impl>()) {}
Catalog::~Catalog() = default;

const Json& Catalog::tools() const { return impl_->tools; }

bool Catalog::hasTool(const std::string& name) const { return impl_->toolNames.contains(name); }

std::variant<Invocation, Json> Catalog::prepare(const std::string& tool, const Json& arguments) const {
    const Json args = arguments.is_null() ? Json::object() : arguments;
    if (tool == "vh_help") return impl_->help(args);
    if (tool == "vh_read" || tool == "vh_run") return impl_->prepareCommand(tool, args);
    for (const auto& t : impl_->typed)
        if (t.name == tool) return impl_->prepareTyped(t, args);
    return errorResult("unknown tool " + tool);
}

namespace {

// "--yes" as a whole option (not "--yes-please") on a line that tells the person to re-run or pass it, the way every
// CLI confirmation refusal is worded ("Re-run with --yes to confirm.", "or pass --accept-overwrite-waiver"). A usage
// listing that merely documents the flag doesn't count.
bool asksForOption(const std::string& text, const std::string& alias) {
    const auto needle = "--" + alias;
    std::istringstream in(text);
    for (std::string line; std::getline(in, line);) {
        const auto lowered = lower(line);
        if (lowered.find("re-run") == std::string::npos && lowered.find("pass --") == std::string::npos) continue;
        for (size_t pos = line.find(needle); pos != std::string::npos; pos = line.find(needle, pos + 1)) {
            const size_t end = pos + needle.size();
            if (end == line.size()) return true;
            const auto c = static_cast<unsigned char>(line[end]);
            if (!std::isalnum(c) && c != '-' && c != '_') return true;
        }
    }
    return false;
}

std::string trimmed(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

}

Json Catalog::finish(const Invocation& call, const CommandOutput& output) const {
    const auto out = trimmed(output.out), err = trimmed(output.err);
    if (output.exit_code == 0) {
        std::string text = out.empty() ? "Done (no output)." : out;
        if (!err.empty()) text += "\n\n[stderr]\n" + err;
        return textResult(std::move(text), false);
    }

    // A refusal that names one of the command's confirmations: nothing ran; a person has to agree first.
    const auto combined = err + "\n" + out;
    std::vector<std::string> named;
    const Leaf* leaf = nullptr;
    for (const auto& l : impl_->leaves)
        if (l.command == call.command) leaf = &l;
    if (leaf)
        for (const auto& g : leaf->gates) {
            if (std::ranges::find(call.confirmed, g.name) != call.confirmed.end()) continue;
            if (std::ranges::any_of(g.aliases, [&](const std::string& a) { return asksForOption(combined, a); }))
                named.push_back(g.name);
        }
    if (!named.empty()) {
        std::string confirmJson;
        for (const auto& n : named)
            if (confirmJson.empty()) confirmJson = "{\"" + n + "\": " + (n == "confirm-token" ? "\"<token>\"" : "true") + "}";
        Json structured{
            {"needs_confirmation", named.front()},
            {"confirm_options", named},
            {"command", "vh " + call.command},
            {"message", trimmed(combined)},
            {"how_to_confirm",
             "Nothing was changed. Show this message to the human and ask whether to go ahead. Only if they "
             "explicitly approve, call " + call.tool + " again with the same arguments plus \"confirm\": " +
                 confirmJson + (named.size() > 1 ? " (or another of confirm_options, as the message explains)" : "") +
                 ". Never set confirm without that approval."}};
        return {{"content", Json::array({{{"type", "text"}, {"text", structured.dump(2)}}})},
                {"structuredContent", structured},
                {"isError", true}};
    }

    std::string text = "vh " + call.command + " failed (exit " + std::to_string(output.exit_code) + ")";
    if (!err.empty()) text += ":\n" + err;
    if (!out.empty()) text += (err.empty() ? ":\n" : "\n") + out;
    return errorResult(std::move(text));
}

std::vector<Catalog::LeafInfo> Catalog::leaves() const {
    std::vector<LeafInfo> out;
    for (const auto& l : impl_->leaves)
        out.push_back({.command = l.command, .effect = l.node->effect, .excluded = l.exclusion != nullptr,
                       .gates = l.gateNames(), .json = !l.jsonAliases.empty()});
    return out;
}

std::string Catalog::commandReference(const std::string_view version) const {
    std::ostringstream md;
    md << "# Vaulthalla command reference\n\n"
       << "Generated by `vh skill install` from the command definitions of vh " << version
       << ". Every command here runs through the vaulthalla MCP server: the typed tool named after it when there is "
          "one, `vh_read` when its effect is read, otherwise `vh_run`. `vh_help` gives the full arguments, options and "
          "examples of any command.\n\n"
       << "Effects: **read** changes nothing; **write** changes state that can be changed back; **destructive** "
          "deletes, revokes, rotates keys or cannot be undone. *confirm: …* lists the confirmations a command asks the "
          "human for.\n";
    std::string section;
    for (const auto& l : impl_->leaves) {
        if (l.exclusion) continue;
        if (l.path.front() != section) {
            section = l.path.front();
            md << "\n## " << section << "\n\n";
        }
        md << "- `" << l.node->synopsisLine() << "` (" << effectText(l.node->effect);
        if (!l.gates.empty()) md << "; confirm: " << joinWords(l.gateNames(), ", ");
        if (!l.typedTools.empty()) md << "; tool: " << joinWords(l.typedTools, ", ");
        md << ")";
        if (!l.node->description.empty()) md << " " << l.node->description;
        md << "\n";
    }
    md << "\n## Not available to agents\n\n";
    for (const auto& ex : exclusions()) md << "- `vh " << joinWords(ex.path) << "`: " << ex.reason << ".\n";
    return md.str();
}

}
