// The server-owned contract (core/usage): the ws command book, the operation catalog, the generators on CLI usage
// entries, the exported TestUsage graph, and meta.contract.get. DB-free.

#include "CommandUsage.hpp"
#include "Contract.hpp"
#include "UsageManager.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Meta.hpp"
#include "protocols/ws/model/Response.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace vh::test_usage_contract {

using json = nlohmann::json;
using protocols::shell::CommandUsage;

json document() { return json::parse(contract::document()); }

std::shared_ptr<CommandUsage> resolveCli(const protocols::shell::UsageManager& mgr, const std::vector<std::string>& path) {
    return mgr.resolve(path);
}

// "positional:<label>", "option:<label>", "optional:<label>", "flag:<label>", "token:<label>".
bool cliEntryExists(const CommandUsage& cmd, const std::string& ref) {
    const auto colon = ref.find(':');
    if (colon == std::string::npos) return false;
    const auto kind = ref.substr(0, colon);
    const auto label = ref.substr(colon + 1);
    const auto byLabel = [&](const auto& entries) {
        return std::ranges::any_of(entries, [&](const auto& e) { return e.label == label; });
    };
    if (kind == "positional") return byLabel(cmd.positionals);
    if (kind == "option" || kind == "token") return byLabel(cmd.required);
    if (kind == "optional") {
        if (byLabel(cmd.optional)) return true;
        for (const auto& g : cmd.groups)
            for (const auto& item : g.items)
                if (const auto* o = std::get_if<protocols::shell::Optional>(&item); o && o->label == label) return true;
        return false;
    }
    if (kind == "flag") {
        if (byLabel(cmd.optional_flags) || byLabel(cmd.required_flags)) return true;
        for (const auto& g : cmd.groups)
            for (const auto& item : g.items)
                if (const auto* f = std::get_if<protocols::shell::Flag>(&item); f && f->label == label) return true;
        return false;
    }
    return false;
}

const contract::WsCommandUsage* wsCommand(const std::vector<contract::WsCommandUsage>& book, const std::string& name) {
    const auto it = std::ranges::find(book, name, &contract::WsCommandUsage::command);
    return it == book.end() ? nullptr : &*it;
}

bool wsAcceptsMember(const contract::WsCommandUsage& cmd, const std::string& member) {
    const auto has = [&](const std::vector<contract::WsField>& fields) {
        return std::ranges::any_of(fields, [&](const contract::WsField& f) { return f.name == member; });
    };
    if (has(cmd.payload)) return true;
    return std::ranges::any_of(cmd.variants, [&](const contract::WsVariant& v) { return has(v.payload); });
}

// ---- hashing --------------------------------------------------------------------------------------------------

TEST(UsageContract, Sha256MatchesKnownVectorsAcrossPaddingBoundaries) {
    using contract::sha256Hex;
    EXPECT_EQ(sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    EXPECT_EQ(sha256Hex(std::string(55, 'a')), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    EXPECT_EQ(sha256Hex(std::string(56, 'a')), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    EXPECT_EQ(sha256Hex(std::string(63, 'a')), "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34");
    EXPECT_EQ(sha256Hex(std::string(64, 'a')), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    EXPECT_EQ(sha256Hex(std::string(119, 'a')), "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb");
    EXPECT_EQ(sha256Hex(std::string(1000, 'a')), "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
}

TEST(UsageContract, DocumentIsDeterministicAndCarriesItsOwnHashes) {
    const auto text = contract::document();
    EXPECT_EQ(text, contract::document());

    auto doc = json::parse(text);
    const auto& id = contract::identity();
    EXPECT_EQ(doc.at("contract_version").get<int>(), contract::kVersion);
    EXPECT_EQ(doc.at("contract_hash").get<std::string>(), id.contract_hash);
    EXPECT_EQ(doc.at("ws_hash").get<std::string>(), id.ws_hash);

    // The hashes cover the canonical (compact, sorted-key) JSON; tools/contracts/ws_contract.py recomputes them.
    EXPECT_EQ(contract::sha256Hex(doc.at("ws").dump()), id.ws_hash);
    EXPECT_EQ(doc.at("models_hash").get<std::string>(), id.models_hash);
    EXPECT_EQ(contract::sha256Hex(doc.at("models").dump()), id.models_hash);
    doc.erase("contract_hash");
    doc.erase("ws_hash");
    doc.erase("models_hash");
    EXPECT_EQ(contract::sha256Hex(doc.dump()), id.contract_hash);
}

// ---- ws book --------------------------------------------------------------------------------------------------

TEST(UsageContract, EveryWsBookCommandIsRegisteredByTheDaemon) {
    const auto router = std::make_shared<protocols::ws::Router>();
    protocols::ws::Handler::registerAllHandlers(router);
    const auto book = contract::ws::commands();
    ASSERT_GE(book.size(), 40u);
    for (const auto& cmd : book) EXPECT_TRUE(router->hasHandler(cmd.command)) << cmd.command;
}

// Registered commands the book deliberately leaves out, each with the reason. Keep it empty unless a command truly
// can't be described; tools/contracts/test_ws_contract.py holds the same list. An entry that is in the book or no
// longer registered fails as well, so the list only shrinks.
const std::map<std::string, std::string>& unbookedWsCommands() {
    static const std::map<std::string, std::string> kUnbooked{};
    return kUnbooked;
}

TEST(UsageContract, EveryRegisteredWsCommandHasABookEntry) {
    const auto router = std::make_shared<protocols::ws::Router>();
    protocols::ws::Handler::registerAllHandlers(router);
    const auto book = contract::ws::commands();
    const auto registered = router->commands();
    ASSERT_GT(registered.size(), 150u) << "found too few registered ws commands; did registration move?";

    for (const auto& command : registered)
        if (!unbookedWsCommands().contains(command)) {
            EXPECT_NE(wsCommand(book, command), nullptr)
                << command << " is registered but has no WsCommandUsage entry (core/usage/src/contract/ws/*.cpp)";
        }
    for (const auto& [command, reason] : unbookedWsCommands()) {
        EXPECT_FALSE(reason.empty()) << command;
        EXPECT_TRUE(router->hasHandler(command)) << command << " is allowlisted but no longer registered";
        EXPECT_EQ(wsCommand(book, command), nullptr) << command << " is allowlisted but now has a book entry";
    }
}

TEST(UsageContract, WsBookCoversTheEngineAndConsoleCommands) {
    const auto book = contract::ws::commands();
    for (const auto* name : {"auth.login", "auth.logout", "auth.refresh", "auth.isAuthenticated", "auth.register",
                             "auth.user.update", "auth.user.delete", "group.add", "group.remove", "group.member.add",
                             "group.member.remove", "role.vault.assign", "role.vault.unassign", "storage.vault.add",
                             "storage.vault.remove", "fs.dir.list", "fs.dir.create", "fs.entry.delete",
                             "fs.entry.rename", "fs.entry.copy", "fs.entry.move", "fs.upload.start",
                             "share.link.create", "share.link.revoke", "meta.contract.get"})
        EXPECT_NE(wsCommand(book, name), nullptr) << name;

    for (const auto& cmd : book) {
        EXPECT_FALSE(cmd.description.empty()) << cmd.command;
        EXPECT_TRUE(cmd.input == "payload" || cmd.input == "none" || cmd.input == "token") << cmd.command;
        EXPECT_TRUE(cmd.auth == "human" || cmd.auth == "session" || cmd.auth == "share" || cmd.auth == "public" ||
                    cmd.auth == "pairing" || cmd.auth == "device")
            << cmd.command;
        if (cmd.input != "payload") {
            EXPECT_TRUE(cmd.payload.empty()) << cmd.command << " takes no payload";
        }
        EXPECT_GT(cmd.client_timeout.count(), 0) << cmd.command;
        for (const auto& f : cmd.payload) {
            EXPECT_FALSE(f.types.empty()) << cmd.command << "." << f.name;
            if (f.required) {
                EXPECT_TRUE(f.generator || !f.enum_values.empty() || f.name == "password")
                    << cmd.command << "." << f.name << " is required but has no generator";
            }
        }
    }
}

// ---- models and shapes ----------------------------------------------------------------------------------------

using FieldVisitor = std::function<void(const contract::WsField&, const std::string&)>;

// Visits every member at every depth: inline object members, map values (".*"), array elements ("[]") and union
// alternatives (same path).
void walkFields(const std::vector<contract::WsField>& fields, const std::string& path, const FieldVisitor& visit);

void walkField(const contract::WsField& f, const std::string& path, const FieldVisitor& visit) {
    visit(f, path);
    walkFields(f.fields, f.items == "object" ? path + "[]" : path, visit);
    for (const auto& v : f.values) walkField(v, path + ".*", visit);
    for (const auto& e : f.element) walkField(e, path + "[]", visit);
    for (const auto& a : f.one_of) walkField(a, path, visit);
}

void walkFields(const std::vector<contract::WsField>& fields, const std::string& path, const FieldVisitor& visit) {
    for (const auto& f : fields) walkField(f, path + "." + f.name, visit);
}

// Every shape in the contract: each command's payload and response (and its session-mode variants), each model.
void walkContract(const FieldVisitor& visit) {
    for (const auto& c : contract::ws::commands()) {
        walkFields(c.payload, c.command + " payload", visit);
        walkFields(c.response, c.command + " response", visit);
        for (const auto& v : c.variants) {
            walkFields(v.payload, c.command + "[" + v.mode + "] payload", visit);
            walkFields(v.response, c.command + "[" + v.mode + "] response", visit);
        }
    }
    for (const auto& m : contract::ws::models()) walkFields(m.fields, m.name, visit);
}

// Objects (or arrays of objects) the contract leaves without a shape, each with the reason. Everything else is a
// model, inline fields, a map or a union. Paths as walkContract prints them.
const std::map<std::string, std::string>& opaqueObjects() {
    static const std::map<std::string, std::string> kOpaque{
        {"PriceBudgetNotification.metadata", "operator notification details stored as JSONB; each producer (budget preflight, gateway budgets, recovery cost alerts) records its own keys"},
        {"SessionUser.vault_roles", "the {} alternative: Auth::sessionUser keeps the empty object User sends for a user without vault roles"},
        {"ShareLink.metadata", "the link creator's free-form metadata, returned parsed"},
        {"SharePublicLink.metadata", "the link creator's free-form metadata, returned parsed"},
        {"SyncEvent.s3_price_breakdown", "price-estimate line items as the pricing engine (or the remote price bot) returned them, stored verbatim per sync run"},
        {"UpstreamAuditEntry.detail", "free-form per audit action (what the action recorded); {raw} when the stored text is not JSON"},
        {"User.vault_roles", "the {} alternative: identities::to_json(User) sends an empty object instead of [] for a user without vault roles"},
        {"share.link.create payload.metadata", "the object alternative: the link creator's free-form metadata, stored as given"},
        {"share.link.update payload.metadata", "the object alternative: the link creator's free-form metadata, stored as given"},
    };
    return kOpaque;
}

TEST(UsageContract, EveryModelReferenceResolvesAndEveryModelIsUsed) {
    const auto models = contract::ws::models();
    std::set<std::string> names;
    for (const auto& m : models) {
        EXPECT_TRUE(names.insert(m.name).second) << m.name;
        EXPECT_FALSE(m.description.empty()) << m.name;
        EXPECT_FALSE(m.fields.empty()) << m.name;
    }

    std::set<std::string> referenced;
    walkContract([&](const contract::WsField& f, const std::string& path) {
        if (f.model.empty()) return;
        referenced.insert(f.model);
        EXPECT_TRUE(names.contains(f.model)) << path << " names model " << f.model << ", which is not declared";
    });
    for (const auto& c : contract::ws::commands())
        if (c.response_model) {
            referenced.insert(*c.response_model);
            EXPECT_TRUE(names.contains(*c.response_model)) << c.command << " response_model " << *c.response_model;
        }
    for (const auto& name : names) EXPECT_TRUE(referenced.contains(name)) << "model " << name << " is never referenced";
}

TEST(UsageContract, ResponseModelCommandsListThatModelsFields) {
    for (const auto& c : contract::ws::commands()) {
        if (!c.response_model) continue;
        const auto fields = contract::ws::modelFields(*c.response_model);
        ASSERT_EQ(c.response.size(), fields.size()) << c.command;
        for (std::size_t i = 0; i < fields.size(); ++i) {
            EXPECT_EQ(c.response[i].name, fields[i].name) << c.command;
            EXPECT_EQ(c.response[i].types, fields[i].types) << c.command << "." << fields[i].name;
            EXPECT_EQ(c.response[i].required, fields[i].required) << c.command << "." << fields[i].name;
            EXPECT_EQ(c.response[i].model, fields[i].model) << c.command << "." << fields[i].name;
        }
    }
}

TEST(UsageContract, UnionsObjectsAndArraysAreSpelledOut) {
    std::set<std::string> opaqueSeen;
    walkContract([&](const contract::WsField& f, const std::string& path) {
        std::vector<std::string> concrete;
        for (const auto& t : f.types)
            if (t != "null") concrete.push_back(t);
        EXPECT_FALSE(concrete.empty()) << path << " has no concrete JSON type";

        if (concrete.size() > 1) {
            EXPECT_FALSE(f.one_of.empty()) << path << " is a union of " << concrete.size()
                                           << " types: spell out its alternatives (one_of)";
        }
        if (!f.one_of.empty()) {
            std::set<std::string> altTypes;
            for (const auto& a : f.one_of) {
                EXPECT_TRUE(a.name.empty()) << path << ": one_of alternatives are nameless";
                for (const auto& t : a.types) altTypes.insert(t);
            }
            EXPECT_EQ(altTypes, std::set<std::string>(concrete.begin(), concrete.end()))
                << path << ": the one_of alternatives must cover exactly the declared types";
            return;  // the alternatives carry the shapes
        }

        const bool isObject = std::ranges::find(f.types, "object") != f.types.end();
        if (f.partial) {
            EXPECT_TRUE(isObject && (!f.model.empty() || !f.fields.empty()))
                << path << ": only an object with a model or fields can be a partial (merge patch)";
        }
        const bool isArray = std::ranges::find(f.types, "array") != f.types.end();
        bool opaque = isObject && f.model.empty() && f.fields.empty() && f.values.empty();
        if (isArray) {
            EXPECT_TRUE(!f.items.empty() || !f.element.empty()) << path << " is an array without an element type";
            if (f.items == "object" && f.model.empty() && f.fields.empty()) opaque = true;
        }
        if (opaque) {
            opaqueSeen.insert(path);
            EXPECT_TRUE(opaqueObjects().contains(path)) << path << " is an object without a model, fields or map "
                                                                     "values (or list it in opaqueObjects() with the reason)";
        }
    });
    for (const auto& [path, reason] : opaqueObjects()) {
        EXPECT_FALSE(reason.empty()) << path;
        EXPECT_TRUE(opaqueSeen.contains(path)) << path << " is listed as opaque but is shaped (or gone)";
    }
}

// A member path ("provision.accept_adoption") the command's payload (or a session-mode variant's) declares.
bool payloadDeclares(const contract::WsCommandUsage& cmd, const std::string& dotted) {
    const auto inFields = [&](const std::vector<contract::WsField>& top) {
        const std::vector<contract::WsField>* fields = &top;
        std::string rest = dotted;
        while (true) {
            const auto dot = rest.find('.');
            const auto name = rest.substr(0, dot);
            const auto it = std::ranges::find(*fields, name, &contract::WsField::name);
            if (it == fields->end()) return false;
            if (dot == std::string::npos) return true;
            fields = &it->fields;
            rest = rest.substr(dot + 1);
        }
    };
    if (inFields(cmd.payload)) return true;
    return std::ranges::any_of(cmd.variants, [&](const contract::WsVariant& v) { return inFields(v.payload); });
}

TEST(UsageContract, RefusalsSplitGenericKindsFromConfirmations) {
    static const std::set<std::string> kKinds{"denied", "not_found", "invalid", "conflict", "unauthorized", "error"};
    // ops::Refused codes (core/include/ops/Error.hpp), each allowed only on the commands that send it: device
    // pairing's, and the vault key commands' D4 channel refusals (a session that isn't a paired device's).
    static const std::map<std::string, std::set<std::string>> kRefusedCodes{
        {"no_pairing_window", {}}, {"rate_limited", {}}, {"device_unknown", {}},
        {"export_requires_device", {"vault.keys.export", "vault.keys.export.confirm"}},
        {"import_requires_device", {"vault.keys.import"}}};
    const auto refusedCodeAllowed = [](const std::string& code, const std::string& command) {
        const auto it = kRefusedCodes.find(code);
        if (it == kRefusedCodes.end()) return false;
        return it->second.empty() ? command.starts_with("device.") : it->second.contains(command);
    };
    int confirmations = 0;
    for (const auto& cmd : contract::ws::commands()) {
        for (const auto& kind : cmd.refusal_codes) {
            EXPECT_TRUE(kKinds.contains(kind) || refusedCodeAllowed(kind, cmd.command))
                << cmd.command << ": refusal_codes holds generic kinds and the ops::Refused codes of the commands "
                << "that send them only; '" << kind << "' belongs in confirmations";
        }
        for (const auto& kind : cmd.untyped_refusals)
            EXPECT_TRUE(kKinds.contains(kind)) << cmd.command << ": untyped refusal '" << kind << "'";
        std::set<std::string> codes;
        for (const auto& c : cmd.confirmations) {
            ++confirmations;
            EXPECT_FALSE(kKinds.contains(c.code)) << cmd.command << ": " << c.code << " is a generic kind";
            EXPECT_TRUE(codes.insert(c.code).second) << cmd.command << " lists " << c.code << " twice";
            EXPECT_FALSE(c.description.empty()) << cmd.command << " " << c.code;
            if (!c.accept_field.empty()) {
                EXPECT_TRUE(payloadDeclares(cmd, c.accept_field))
                    << cmd.command << ": " << c.code << " is accepted by " << c.accept_field
                    << ", which its payload doesn't declare";
            }
        }
    }
    EXPECT_GE(confirmations, 15) << "the NeedsConfirmation codes left the book";
}

TEST(UsageContract, EnvelopeDescribesTheFramesTheDaemonSends) {
    const auto frames = contract::ws::envelope();
    const auto names = [](const std::vector<contract::WsField>& fields) {
        std::set<std::string> out;
        for (const auto& f : fields) out.insert(f.name);
        return out;
    };
    EXPECT_EQ(names(frames.request), (std::set<std::string>{"command", "payload", "requestId", "token"}));
    EXPECT_EQ(names(frames.response), (std::set<std::string>{"command", "status", "requestId", "data", "error", "token"}));
    EXPECT_EQ(names(frames.error_frame), (std::set<std::string>{"command", "status", "error", "message", "requestId"}));
    // The answer statuses are exactly what model::to_string can produce.
    const auto status = std::ranges::find(frames.response, "status", &contract::WsField::name);
    ASSERT_NE(status, frames.response.end());
    std::set<std::string> produced;
    for (const auto s : {protocols::ws::model::Status::OK, protocols::ws::model::Status::ERROR,
                         protocols::ws::model::Status::UNAUTHORIZED})
        produced.insert(protocols::ws::model::to_string(s));
    EXPECT_EQ(std::set<std::string>(status->enum_values.begin(), status->enum_values.end()), produced);
    EXPECT_TRUE(json::parse(contract::document()).contains("envelope"));
}

// ---- operation catalog ----------------------------------------------------------------------------------------

TEST(UsageContract, OperationBindingsResolveAgainstTheBooks) {
    const protocols::shell::UsageManager mgr;
    const auto book = contract::ws::commands();
    const auto ops = contract::operations();

    std::set<std::string> ids;
    for (const auto& op : ops) {
        EXPECT_TRUE(ids.insert(op.id).second) << "duplicate operation " << op.id;
        std::set<std::string> fieldNames;
        for (const auto& f : op.fields) fieldNames.insert(f.name);
        EXPECT_TRUE(op.cli || op.ws || op.fuse || op.http) << op.id << " has no surface";
        EXPECT_FALSE(op.refusals.empty()) << op.id;

        if (op.cli) {
            const auto cmd = resolveCli(mgr, op.cli->usage_path);
            ASSERT_NE(cmd, nullptr) << op.id;
            EXPECT_EQ(cmd->aliases.front(), op.cli->usage_path.back()) << op.id << ": usage path resolves elsewhere";
            for (const auto& [field, entry] : op.cli->field_to_entry) {
                EXPECT_TRUE(fieldNames.contains(field)) << op.id << ": cli binds unknown field " << field;
                EXPECT_TRUE(cliEntryExists(*cmd, entry)) << op.id << ": no CLI entry " << entry;
            }
            for (const auto& [entry, value] : op.cli->fixed)
                EXPECT_TRUE(cliEntryExists(*cmd, entry)) << op.id << ": no CLI entry " << entry;
        }
        if (op.ws) {
            const auto* cmd = wsCommand(book, op.ws->command);
            ASSERT_NE(cmd, nullptr) << op.id << ": ws command " << op.ws->command << " is not in the ws book";
            for (const auto& [field, pointer] : op.ws->field_to_json) {
                EXPECT_TRUE(fieldNames.contains(field)) << op.id << ": ws binds unknown field " << field;
                ASSERT_TRUE(pointer.starts_with("/")) << op.id;
                EXPECT_TRUE(wsAcceptsMember(*cmd, pointer.substr(1))) << op.id << ": " << op.ws->command
                                                                       << " has no payload member " << pointer;
            }
            for (const auto& [pointer, literal] : op.ws->fixed) {
                EXPECT_TRUE(wsAcceptsMember(*cmd, pointer.substr(1))) << op.id << ": fixed " << pointer;
                EXPECT_TRUE(json::accept(literal)) << op.id << ": fixed " << pointer << " is not JSON";
            }
        }
        if (op.fuse) {
            static const std::set<std::string> kActorOps{"write", "append", "pwrite", "read", "ls", "stat", "mkdir",
                                                         "rmdir", "unlink", "rename", "truncate", "chmod", "rm_rf",
                                                         "cp_tree", "fsync", "hold", "release"};
            EXPECT_TRUE(kActorOps.contains(op.fuse->actor_op)) << op.id << ": not a vh_fs_actor op";
            for (const auto& [field, arg] : op.fuse->field_to_arg)
                EXPECT_TRUE(fieldNames.contains(field)) << op.id << ": fuse binds unknown field " << field;
        }
    }

    // Every ws command that names an operation names one that exists.
    for (const auto& cmd : book)
        if (cmd.operation) {
            EXPECT_TRUE(ids.contains(*cmd.operation)) << cmd.command << " -> " << *cmd.operation;
        }

    for (const auto* id : {"users.create", "users.update", "users.delete", "users.deactivate", "groups.create",
                           "groups.delete", "groups.add_user", "groups.remove_user", "roles.vault.assign",
                           "roles.vault.unassign", "vaults.create", "vaults.delete", "fs.list", "fs.read", "fs.write",
                           "fs.mkdir", "fs.rename", "fs.delete", "fs.copy", "shares.create", "shares.revoke",
                           "auth.login"})
        EXPECT_TRUE(ids.contains(id)) << id;
}

// ---- CLI generators and the TestUsage graph -------------------------------------------------------------------

TEST(UsageContract, CoveredCliCommandsDeclareAGeneratorForEveryValue) {
    const protocols::shell::UsageManager mgr;
    const std::vector<std::vector<std::string>> covered{
        {"user", "create"}, {"user", "delete"}, {"user", "info"}, {"user", "update"},
        {"group", "create"}, {"group", "delete"}, {"group", "info"}, {"group", "update"},
        {"group", "user", "add"}, {"group", "user", "remove"},
        {"vault", "create"}, {"vault", "delete"}, {"vault", "info"}, {"vault", "update"},
        {"vault", "role", "assign"}, {"vault", "role", "unassign"},
        {"role", "admin", "create"}, {"role", "admin", "info"}, {"role", "admin", "update"}, {"role", "admin", "delete"},
        {"role", "vault", "create"}, {"role", "vault", "info"}, {"role", "vault", "update"}, {"role", "vault", "delete"},
    };
    for (const auto& path : covered) {
        const auto cmd = mgr.resolve(path);
        ASSERT_NE(cmd, nullptr) << path.back();
        const auto where = cmd->primary();
        for (const auto& p : cmd->positionals) EXPECT_NE(p.generator, nullptr) << where << " <" << p.label << ">";
        for (const auto& o : cmd->required)
            for (const auto& token : o.value_tokens)
                EXPECT_TRUE(o.generators.contains(token)) << where << " --" << o.label << " <" << token << ">";
        for (const auto& o : cmd->optional)
            for (const auto& token : o.value_tokens)
                EXPECT_TRUE(o.generators.contains(token)) << where << " --" << o.label << " <" << token << ">";
    }

    // The same entry names an admin role under `role admin` and a vault role under `role vault`.
    EXPECT_EQ(resolveCli(mgr, {"role", "admin", "info"})->positionals.at(0).generator->entity, "role.admin");
    EXPECT_EQ(resolveCli(mgr, {"role", "vault", "info"})->positionals.at(0).generator->entity, "role.vault");
    // `vault create` names a new vault; the other vault commands name an existing one.
    EXPECT_TRUE(resolveCli(mgr, {"vault", "create"})->positionals.at(0).generator->fresh);
    EXPECT_EQ(resolveCli(mgr, {"vault", "info"})->positionals.at(0).generator->kind, contract::FieldGen::Kind::Ref);
}

TEST(UsageContract, GeneratorsAreExecutableUnlessTheyNameWorldState) {
    args::Rng rng(42);
    const args::GenContext ctx{"name", "user/create"};
    const auto name = contract::gen::freshName("user_")->executable();
    ASSERT_NE(name, nullptr);
    const auto value = args::to_string_value(name->generate(rng, ctx));
    EXPECT_TRUE(value.starts_with("user_")) << value;
    EXPECT_EQ(value.size(), std::string("user_").size() + 7);
    EXPECT_EQ(contract::gen::ref("user")->executable(), nullptr);
    const auto uid = std::stoll(args::to_string_value(contract::gen::testLinuxId()->executable()->generate(rng, ctx)));
    EXPECT_GE(uid, 2900000000LL);
}

TEST(UsageContract, ExportedTestUsageGraphHasNoDanglingSteps) {
    const auto doc = document();
    std::set<std::string> paths;
    for (const auto& c : doc.at("cli")) {
        std::string p;
        for (const auto& part : c.at("path")) p += (p.empty() ? "" : " ") + part.get<std::string>();
        paths.insert(p);
    }
    int edges = 0;
    for (const auto& c : doc.at("cli")) {
        if (!c.contains("test_usage")) continue;
        for (const auto* phase : {"setup", "lifecycle", "teardown"})
            for (const auto& step : c.at("test_usage").at(phase)) {
                ASSERT_TRUE(step.at("command").is_string()) << c.at("path").dump() << " " << phase
                                                           << ": a step points at a command nobody kept";
                EXPECT_TRUE(paths.contains(step.at("command").get<std::string>())) << step.dump();
                EXPECT_LE(step.at("min").get<int>(), step.at("max").get<int>()) << step.dump();
                ++edges;
            }
    }
    EXPECT_GT(edges, 50);
    // The membership subtree's steps (previously dangling) are present.
    EXPECT_TRUE(paths.contains("group user add"));
}

// ---- meta.contract.get ----------------------------------------------------------------------------------------

TEST(UsageContract, MetaContractGetReturnsTheBuiltContractIdentity) {
    const auto reply = protocols::ws::handler::Meta::contract();
    const auto& id = contract::identity();
    EXPECT_EQ(reply.at("contract_version").get<int>(), contract::kVersion);
    EXPECT_EQ(reply.at("contract_hash").get<std::string>(), id.contract_hash);
    EXPECT_EQ(reply.at("ws_hash").get<std::string>(), id.ws_hash);
    EXPECT_EQ(reply.at("models_hash").get<std::string>(), id.models_hash);
    EXPECT_EQ(id.ws_hash.size(), 64u);
    EXPECT_EQ(id.models_hash.size(), 64u);
    EXPECT_EQ(reply.size(), 4u) << "no other (possibly sensitive) fields: " << reply.dump();
}

// The contract hash identifies the daemon build, so it is not handed to unauthenticated sockets (no version
// fingerprinting before login); a signed-in human gets it like any other read.
TEST(UsageContract, MetaContractGetNeedsASignedInHuman) {
    using Decision = protocols::ws::Router::CommandAuthDecision;
    const auto unauth = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    const auto human = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    identities::UserState state;
    state.name = "contract_reader";
    state.roles.admin = std::make_shared<rbac::role::Admin>();
    human->user = identities::User::detached(4243, std::move(state));

    EXPECT_EQ(protocols::ws::Router::classifyCommand("meta.contract.get", *unauth), Decision::Deny);
    EXPECT_EQ(protocols::ws::Router::classifyCommand("meta.contract.get", *human), Decision::RequireHumanAuth);
}

}
