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
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
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
    doc.erase("contract_hash");
    doc.erase("ws_hash");
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
    EXPECT_EQ(id.ws_hash.size(), 64u);
    EXPECT_EQ(reply.size(), 3u) << "no other (possibly sensitive) fields: " << reply.dump();
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
