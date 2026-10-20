// JSON export of the contract (vh_usage --json) and its identity (meta.contract.get).
//
// Canonical form, which both hashes are computed over: nlohmann's compact dump (no whitespace, object keys sorted,
// UTF-8 unescaped), integers only. Python's json.dumps(obj, sort_keys=True, separators=(",", ":"),
// ensure_ascii=False) produces the same bytes, which tools/contracts/ws_contract.py relies on.

#include "Contract.hpp"
#include "CommandUsage.hpp"
#include "UsageManager.hpp"

#include <nlohmann/json.hpp>

#include <memory>
#include <string>
#include <unordered_set>
#include <variant>
#include <vector>

namespace vh::contract {

namespace {

using Json = nlohmann::json;
using protocols::shell::CommandUsage;

Json genJson(const FieldGenPtr& g) {
    if (!g) return nullptr;
    Json j{{"kind", FieldGen::kindName(g->kind)}};
    if (!g->values.empty()) j["values"] = g->values;
    if (!g->pattern.empty()) j["pattern"] = g->pattern;
    if (g->kind == FieldGen::Kind::IntRange || g->kind == FieldGen::Kind::Bytes) {
        j["min"] = g->min;
        j["max"] = g->max;
    }
    if (g->kind == FieldGen::Kind::Ref) {
        j["entity"] = g->entity;
        j["attrs"] = g->attrs;
        j["scope"] = g->scope;
    }
    if (g->fresh) j["fresh"] = true;
    return j;
}

// ---- CLI ------------------------------------------------------------------------------------------------------

std::vector<std::string> cliPath(const CommandUsage& cmd) {
    std::vector<std::string> path;
    for (const auto* node = &cmd; node;) {
        const auto parent = node->parent.lock();
        if (!parent) break;  // the root ("vh") is not part of a command's path
        path.insert(path.begin(), node->aliases.empty() ? std::string{} : node->aliases.front());
        node = parent.get();
    }
    return path;
}

std::string cliPathString(const CommandUsage& cmd) {
    std::string out;
    for (const auto& part : cliPath(cmd)) out += (out.empty() ? "" : " ") + part;
    return out;
}

Json optionJson(const protocols::shell::Option& o) {
    Json gens = Json::object();
    for (const auto& [token, g] : o.generators) gens[token] = genJson(g);
    return {{"label", o.label}, {"description", o.desc}, {"option_tokens", o.option_tokens},
            {"value_tokens", o.value_tokens}, {"generators", gens}};
}

Json optionalJson(const protocols::shell::Optional& o) {
    auto j = optionJson(o);
    j["default"] = o.default_value ? Json(*o.default_value) : Json(nullptr);
    return j;
}

Json flagJson(const protocols::shell::Flag& f) {
    return {{"label", f.label}, {"description", f.desc}, {"aliases", f.aliases}, {"default_state", f.default_state}};
}

Json testStepsJson(const std::vector<protocols::shell::TestCommandUsage>& steps) {
    Json out = Json::array();
    for (const auto& step : steps) {
        const auto target = step.command.lock();
        // An expired reference is exported as null (the unit test refuses it) rather than silently dropped.
        out.push_back({{"command", target ? Json(cliPathString(*target)) : Json(nullptr)},
                       {"min", step.minIter},
                       {"max", step.max_iter}});
    }
    return out;
}

Json commandJson(const CommandUsage& cmd) {
    Json positionals = Json::array();
    for (const auto& p : cmd.positionals)
        positionals.push_back({{"label", p.label}, {"description", p.desc}, {"aliases", p.aliases},
                               {"generator", genJson(p.generator)}});

    Json required = Json::array(), optional = Json::array();
    for (const auto& o : cmd.required) required.push_back(optionJson(o));
    for (const auto& o : cmd.optional) optional.push_back(optionalJson(o));

    Json requiredFlags = Json::array(), optionalFlags = Json::array();
    for (const auto& f : cmd.required_flags) requiredFlags.push_back(flagJson(f));
    for (const auto& f : cmd.optional_flags) optionalFlags.push_back(flagJson(f));

    Json groups = Json::array();
    for (const auto& g : cmd.groups) {
        Json groupOptional = Json::array(), groupFlags = Json::array();
        for (const auto& item : g.items) {
            if (const auto* o = std::get_if<protocols::shell::Optional>(&item)) groupOptional.push_back(optionalJson(*o));
            else groupFlags.push_back(flagJson(std::get<protocols::shell::Flag>(item)));
        }
        groups.push_back({{"title", g.title}, {"optional", groupOptional}, {"flags", groupFlags}});
    }

    Json examples = Json::array();
    for (const auto& e : cmd.examples) examples.push_back({{"cmd", e.cmd}, {"note", e.note}});

    Json subcommands = Json::array();
    for (const auto& sc : cmd.subcommands)
        if (sc && !sc->aliases.empty()) subcommands.push_back(sc->aliases.front());

    Json j{{"path", cliPath(cmd)},
           {"aliases", cmd.aliases},
           {"description", cmd.description},
           {"positionals", positionals},
           {"required", required},
           {"optional", optional},
           {"required_flags", requiredFlags},
           {"optional_flags", optionalFlags},
           {"groups", groups},
           {"option_prefixes", cmd.option_prefixes},
           {"plural_alias_implies_list", cmd.pluralAliasImpliesList},
           {"examples", examples},
           {"subcommands", subcommands}};
    if (cmd.synopsis) j["synopsis"] = *cmd.synopsis;

    const auto& t = cmd.test_usage;
    if (!t.setup.empty() || !t.lifecycle.empty() || !t.teardown.empty())
        j["test_usage"] = {{"setup", testStepsJson(t.setup)},
                           {"lifecycle", testStepsJson(t.lifecycle)},
                           {"teardown", testStepsJson(t.teardown)}};
    return j;
}

// Every command reachable from the root, depth-first in declaration order, each once (a node can be attached under
// two parents, e.g. "group users" and "group user list").
void collectCommands(const std::shared_ptr<CommandUsage>& node, std::unordered_set<const CommandUsage*>& seen,
                     Json& out) {
    if (!node || !seen.insert(node.get()).second) return;
    if (!node->parent.expired()) out.push_back(commandJson(*node));
    for (const auto& sc : node->subcommands) collectCommands(sc, seen, out);
}

Json cliJson() {
    const protocols::shell::UsageManager mgr;
    Json out = Json::array();
    std::unordered_set<const CommandUsage*> seen;
    collectCommands(mgr.root(), seen, out);
    return out;
}

// ---- ws -------------------------------------------------------------------------------------------------------

Json wsFieldsJson(const std::vector<WsField>& fields);

Json wsFieldJson(const WsField& f) {
    Json j{{"name", f.name}, {"types", f.types}, {"required", f.required}};
    if (!f.description.empty()) j["description"] = f.description;
    if (!f.enum_values.empty()) j["enum"] = f.enum_values;
    if (!f.items.empty()) j["items"] = f.items;
    if (!f.item_enum.empty()) j["item_enum"] = f.item_enum;
    if (!f.fields.empty()) j["fields"] = wsFieldsJson(f.fields);
    if (!f.model.empty()) j["model"] = f.model;
    if (f.minimum) j["minimum"] = *f.minimum;
    if (f.maximum) j["maximum"] = *f.maximum;
    if (f.generator) j["generator"] = genJson(f.generator);
    if (!f.one_of.empty()) j["one_of"] = wsFieldsJson(f.one_of);
    if (!f.values.empty()) j["values"] = wsFieldJson(f.values.front());
    if (!f.element.empty()) j["element"] = wsFieldJson(f.element.front());
    if (f.partial) j["partial"] = true;
    return j;
}

Json wsFieldsJson(const std::vector<WsField>& fields) {
    Json out = Json::array();
    for (const auto& f : fields) out.push_back(wsFieldJson(f));
    return out;
}

Json wsJson() {
    Json out = Json::array();
    for (const auto& c : ws::commands()) {
        Json variants = Json::array();
        for (const auto& v : c.variants)
            variants.push_back({{"mode", v.mode}, {"description", v.description},
                                {"payload", wsFieldsJson(v.payload)}, {"response", wsFieldsJson(v.response)}});
        out.push_back({{"command", c.command},
                       {"description", c.description},
                       {"auth", c.auth},
                       {"input", c.input},
                       {"payload", wsFieldsJson(c.payload)},
                       {"response", wsFieldsJson(c.response)},
                       {"variants", variants},
                       {"refusal_codes", c.refusal_codes},
                       {"untyped_refusals", c.untyped_refusals},
                       {"operation", c.operation ? Json(*c.operation) : Json(nullptr)},
                       {"response_model", c.response_model ? Json(*c.response_model) : Json(nullptr)},
                       {"client_timeout_ms", c.client_timeout.count()}});
    }
    return out;
}

Json modelsJson() {
    Json out = Json::array();
    for (const auto& m : ws::models())
        out.push_back({{"name", m.name}, {"description", m.description}, {"fields", wsFieldsJson(m.fields)}});
    return out;
}

// ---- operations -----------------------------------------------------------------------------------------------

Json stringMap(const std::map<std::string, std::string>& m) {
    Json j = Json::object();
    for (const auto& [k, v] : m) j[k] = v;
    return j;
}

Json operationsJson() {
    Json out = Json::array();
    for (const auto& op : operations()) {
        Json fields = Json::array();
        for (const auto& f : op.fields) {
            Json fj{{"name", f.name}, {"type", f.type}, {"required", f.required}};
            if (!f.enum_values.empty()) fj["enum"] = f.enum_values;
            if (!f.ref.empty()) fj["ref"] = f.ref;
            if (f.generator) fj["generator"] = genJson(f.generator);
            if (!f.description.empty()) fj["description"] = f.description;
            fields.push_back(fj);
        }

        Json bindings = {{"cli", nullptr}, {"ws", nullptr}, {"fuse", nullptr}, {"http", nullptr}};
        if (op.cli)
            bindings["cli"] = {{"usage_path", op.cli->usage_path}, {"field_to_entry", stringMap(op.cli->field_to_entry)},
                               {"fixed", stringMap(op.cli->fixed)}};
        if (op.ws)
            bindings["ws"] = {{"command", op.ws->command}, {"field_to_json", stringMap(op.ws->field_to_json)},
                              {"fixed", stringMap(op.ws->fixed)},
                              {"id_pointer", op.ws->id_pointer.empty() ? Json(nullptr) : Json(op.ws->id_pointer)}};
        if (op.fuse)
            bindings["fuse"] = {{"actor_op", op.fuse->actor_op}, {"field_to_arg", stringMap(op.fuse->field_to_arg)}};
        if (op.http)
            bindings["http"] = {{"method", op.http->method}, {"path", op.http->path},
                                {"field_to_param", stringMap(op.http->field_to_param)}};

        Json refusals = Json::object();
        for (const auto& [kind, r] : op.refusals)
            refusals[kind] = {{"cli_exit", r.cli_exit},
                              {"ws_status", r.ws_status},
                              {"ws_code", r.ws_code.empty() ? Json(nullptr) : Json(r.ws_code)},
                              {"errno", r.errno_name.empty() ? Json(nullptr) : Json(r.errno_name)},
                              {"http_status", r.http_status == 0 ? Json(nullptr) : Json(r.http_status)}};

        out.push_back({{"id", op.id},
                       {"description", op.description},
                       {"fields", fields},
                       {"requires_any", op.requires_any},
                       {"effect", {{"kind", op.effect.kind}, {"entity", op.effect.entity}}},
                       {"bindings", bindings},
                       {"deadline_ms", op.deadline.count()},
                       {"refusals", refusals}});
    }
    return out;
}

struct Built {
    Json document;
    Identity identity;
};

Built build() {
    Json body{{"contract_version", kVersion}, {"cli", cliJson()}, {"ws", wsJson()}, {"models", modelsJson()},
              {"operations", operationsJson()}};
    Built b;
    b.identity.version = kVersion;
    b.identity.contract_hash = sha256Hex(body.dump());
    b.identity.ws_hash = sha256Hex(body.at("ws").dump());
    b.identity.models_hash = sha256Hex(body.at("models").dump());
    body["contract_hash"] = b.identity.contract_hash;
    body["ws_hash"] = b.identity.ws_hash;
    body["models_hash"] = b.identity.models_hash;
    b.document = std::move(body);
    return b;
}

}

std::string document(const int indent) { return build().document.dump(indent) + "\n"; }

const Identity& identity() {
    static const Identity id = build().identity;
    return id;
}

}
