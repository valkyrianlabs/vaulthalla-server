// The server-owned contract (core/usage): the ws command book, the operation catalog, the generators on CLI usage
// entries, the exported TestUsage graph, meta.contract.get, and the ws protocol's range and capability registry
// (meta.hello's own suite: test_ws_meta_hello.cpp). DB-free.

#include "CommandUsage.hpp"
#include "Contract.hpp"
#include "UsageManager.hpp"
#include "WsProtocol.hpp"
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
#include <regex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace vh::test_usage_contract {

using json = nlohmann::json;
using protocols::shell::CommandUsage;

// Built once (~0.25 s each at -O0); DocumentIsDeterministicAndCarriesItsOwnHashes builds it again itself.
const json& document() {
    static const json doc = json::parse(contract::document());
    return doc;
}

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

// Scoped devices: every ws command says what it does, from the one table, and the router reads the same.
TEST(UsageContract, EveryWsCommandDeclaresAnEffect) {
    const auto table = contract::effectTable();
    std::set<std::string> named;
    for (const auto& row : table) EXPECT_TRUE(named.insert(row.command).second) << row.command << " twice";
    std::size_t reads = 0, destructive = 0;
    for (const auto& c : contract::ws::commands()) {
        EXPECT_TRUE(c.effect == "read" || c.effect == "write" || c.effect == "destructive")
            << c.command << " declares no effect (core/usage/src/contract/ws/effects.cpp)";
        EXPECT_EQ(contract::ws::effectOf(c.command), c.effect) << c.command;
        reads += c.effect == "read";
        destructive += c.effect == "destructive";
    }
    EXPECT_EQ(named.size(), contract::ws::commands().size()) << "the table names a command the book lacks, or misses one";
    EXPECT_GT(reads, 100u);
    EXPECT_GT(destructive, 10u);
    EXPECT_FALSE(contract::ws::effectOf("no.such.command"));
    // A few the scope rule leans on.
    EXPECT_EQ(contract::ws::effectOf("fs.dir.list"), "read");
    EXPECT_EQ(contract::ws::effectOf("fs.download.chunk"), "read");
    EXPECT_EQ(contract::ws::effectOf("fs.upload.start"), "write");
    EXPECT_EQ(contract::ws::effectOf("fs.entry.delete"), "destructive");
    EXPECT_EQ(contract::ws::effectOf("storage.vault.remove"), "destructive");
    EXPECT_EQ(contract::ws::effectOf("device.revoke"), "destructive");
    EXPECT_EQ(contract::ws::effectOf("stats.vault"), "read");
}

TEST(UsageContract, WsBookCoversTheEngineAndConsoleCommands) {
    const auto book = contract::ws::commands();
    for (const auto* name : {"auth.login", "auth.logout", "auth.refresh", "auth.isAuthenticated", "auth.register",
                             "auth.user.update", "auth.user.delete", "group.add", "group.remove", "group.member.add",
                             "group.member.remove", "role.vault.assign", "role.vault.unassign", "storage.vault.add",
                             "storage.vault.remove", "fs.dir.list", "fs.dir.create", "fs.entry.delete",
                             "fs.entry.rename", "fs.entry.copy", "fs.entry.move", "fs.upload.start",
                             "share.link.create", "share.link.revoke", "meta.contract.get", "meta.hello"})
        EXPECT_NE(wsCommand(book, name), nullptr) << name;

    for (const auto& cmd : book) {
        EXPECT_FALSE(cmd.description.empty()) << cmd.command;
        EXPECT_TRUE(cmd.input == "payload" || cmd.input == "none" || cmd.input == "token") << cmd.command;
        EXPECT_TRUE(cmd.auth == "human" || cmd.auth == "session" || cmd.auth == "share" || cmd.auth == "public" ||
                    cmd.auth == "pairing" || cmd.auth == "device" || cmd.auth == "pending" ||
                    cmd.auth == "enrollment" || cmd.auth == "peer" || cmd.auth == "peer_pairing")
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
        {"peer.mirror.log response.groups[].rows[].state", "a replication log row's state document (design/peers/mirror.md \"State documents\"), carried verbatim and hashed by its canonical encoding (mirror/Hash.hpp), never read by the contract"},
        {"peer.mirror.log response.part.rows[].state", "a replication log row's state document, as in groups[].rows[].state"},
        {"peer.mirror.tree response.items[].state", "a baseline entry's state document, the same documents the replication log carries"},
        {"mirror.takeover response.detail", "a take over's record of its fork base (its own digest, whether it is the fork point's, the copy's state before): shown verbatim, never read by the contract"},
        {"mirror.switch response.detail", "what the other server last said of a planned switch (its prepare's answer), or why the switch ended: shown verbatim, never read by the contract"},
        {"peer.mirror.tree response.vault", "the vault's document (vh_mirror_vault_state) as of the baseline, recorded by the mirror verbatim"},
        {"cloud.storage.status response.billing", "the account's billing summary as the service last answered GET /v1/billing, passed through for display"},
        {"cloud.storage.status response.ejection", "the account's ejection progress as the service reports it in GET /v1/storage, passed through for display"},
        {"CloudStorageStatus.billing", "the account's billing summary as the service last answered GET /v1/billing, passed through for display"},
        {"CloudStorageStatus.ejection", "the account's ejection progress as the service reports it in GET /v1/storage, passed through for display"},
        {"SessionUser.vault_roles", "the {} alternative: Auth::sessionUser keeps the empty object User sends for a user without vault roles"},
        {"ShareLink.metadata", "the link creator's free-form metadata, returned parsed"},
        {"SharePublicLink.metadata", "the link creator's free-form metadata, returned parsed"},
        {"SyncEvent.s3_price_breakdown", "price-estimate line items as the pricing engine (or the remote price bot) returned them, stored verbatim per sync run"},
        {"UpstreamAuditEntry.detail", "free-form per audit action (what the action recorded); {raw} when the stored text is not JSON"},
        {"User.vault_roles", "the {} alternative: identities::to_json(User) sends an empty object instead of [] for a user without vault roles"},
        {"share.link.create payload.metadata", "the object alternative: the link creator's free-form metadata, stored as given"},
        {"share.link.update payload.metadata", "the object alternative: the link creator's free-form metadata, stored as given"},
        {"vault.recover payload.kit", "the customer's recovery kit (vh.recovery-kit v1, design spec 03 §5.3) as a whole document: vl::keykit::parseKit reads it, never the contract"},
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
    // pairing's, the vault key commands' D4 channel refusals (a session that isn't a paired device's), meta.hello's
    // protocol_unsupported (no protocol version in common) and auth.login's already_signed_in (#354).
    static const std::map<std::string, std::set<std::string>> kRefusedCodes{
        {"no_pairing_window", {}}, {"rate_limited", {"auth.mfa.verify", "auth.passkey.options"}},
        {"device_unknown", {}},
        {"export_requires_device", {"vault.keys.export", "vault.keys.export.confirm"}},
        {"import_requires_device", {"vault.keys.import"}},
        {"recipient_requires_device", {"vault.keys.recipients.add", "vault.keys.recipients.revoke"}},
        // design/cloud/key-manager.md: the account recovery key's confirmation and the policy's own grants.
        {"cloud_key_requires_device", {"cloud.key.confirm"}}, {"cloud_key_mismatch", {"cloud.key.confirm"}},
        {"cloud_account_key_tampered", {"cloud.key.confirm"}},
        {"recovery_policy_account_managed", {"vault.keys.recipients.revoke"}},
        // design/cloud/managed-remotes.md: managed storage.
        {"managed_vault_account_key", {"vault.keys.recipients.revoke"}},
        {"managed_storage_unavailable", {"cloud.storage.switch"}},
        {"cloud_unreachable", {"cloud.storage.billing.handoff"}}, {"cloud_refused", {"cloud.storage.billing.handoff"}},
        // #371: vault.recover's D4 refusal and the restore's own refusals (vault::recover::Refusal, ops Refused).
        {"recover_requires_device", {"vault.recover"}}, {"salvage_required", {"vault.recover"}},
        {"rollback", {"vault.recover"}}, {"fork", {"vault.recover"}}, {"kit_vault_mismatch", {"vault.recover"}},
        {"export_vault_mismatch", {"vault.recover"}}, {"recovery_material_mismatch", {"vault.recover"}},
        {"no_key_material", {"vault.recover"}}, {"vault_unknown", {"vault.recover"}},
        {"protocol_unsupported", {"meta.hello"}},
        // Spec 06 §7: a bucket that can't hold an encrypting (opaque_v1) vault, and a probe without a verdict.
        {"bucket_capability_insufficient", {"storage.vault.add", "storage.vault.update", "vault.remote.attach"}},
        {"bucket_probe_failed", {"vault.storage.probe", "vault.remote.attach"}},
        // design/storage/attach-remote.md: the attach's preconditions (vault::remote::Refusal, ops Refused).
        {"key_rotation_running", {"vault.remote.attach", "vault.remote.detach"}},
        {"key_salvage_running", {"vault.remote.attach", "vault.remote.detach"}},
        {"legacy_content", {"vault.remote.attach", "vault.remote.detach"}},
        {"key_version_missing", {"vault.remote.attach", "vault.remote.detach"}},
        // The detach's own preconditions (vault::remote::detach::requireVaultReady).
        {"attach_running", {"vault.remote.detach"}}, {"layout_migration_running", {"vault.remote.detach"}},
        {"event_sync_active", {"vault.remote.detach"}}, {"sync_conflicts_open", {"vault.remote.detach"}},
        {"key_version_unattested", {"vault.remote.attach"}}, {"recovery_material_missing", {"vault.remote.attach"}},
        {"bucket_listing_failed", {"vault.remote.attach"}}, {"bucket_not_empty", {"vault.remote.attach"}},
        {"bucket_holds_this_vault", {"vault.remote.attach"}},
        {"already_signed_in", {"auth.login", "auth.passkey.options", "auth.passkey.login"}},
        // #357: the pending-MFA sign-in and the enrollment commands.
        {"mfa_required", {"auth.login", "auth.mfa.verify"}},
        {"mfa_enrollment_required", {"auth.login"}},
        {"mfa_unavailable", {"auth.login"}},
        {"mfa_invalid", {"auth.mfa.verify"}},
        {"mfa_expired", {"auth.mfa.verify", "auth.mfa.webauthn.register.options", "auth.mfa.webauthn.register.finish",
                         "auth.mfa.totp.enroll.start", "auth.mfa.totp.enroll.confirm",
                         "auth.mfa.recovery.acknowledge"}},
        // #359: step-up (step_up_required: exactly the step-up table's commands, below).
        {"step_up_unavailable", {"auth.stepup.begin"}},
        {"step_up_failed", {"auth.stepup.finish"}},
        {"mfa_last_factor", {"auth.mfa.factor.remove"}},
        // #361: device approvals (the device's side: device.*) and the console's answer.
        {"console_approval_required", {}}, {"approval_key_unavailable", {}},
        {"passkey_required", {"auth.approval.approve"}}, {"approval_failed", {"auth.approval.approve"}},
        // Scoped devices: a scoped device unpairing another, or anyone's scope changed from a device.
        {"device_scope", {"device.revoke", "device.scope.set"}},
        // design/peers/link.md: linked servers (every peer.* command, below).
        {"peers_experimental", {}}, {"peer_forbidden", {}}};
    const auto stepUp = contract::stepUpTable();
    const auto refusedCodeAllowed = [&](const std::string& code, const std::string& command) {
        if (code == "step_up_required")
            return std::ranges::any_of(stepUp, [&](const contract::WsStepUp& r) { return r.command == command; });
        if (code == "rate_limited" && (command == "auth.stepup.begin" || command == "auth.approval.approve"))
            return true;  // the passkey challenge store
        // #360: the recovery cooldown's families (keys, device.trust, identity.admin, secrets, settings), and the
        // device and console approvals that could otherwise make a grant for them.
        if (code == "recovery_cooldown")
            return command == "device.approval.challenge" || command == "device.approval.submit" ||
                   command == "device.approval.request" || command == "auth.approval.approve" ||
                   std::ranges::any_of(stepUp, [&](const contract::WsStepUp& r) {
                       return r.command == command && (r.family == "keys" || r.family == "device.trust" ||
                                                       r.family == "identity.admin" || r.family == "secrets" ||
                                                       r.family == "settings" || r.family == "connector.trust");
                   });
        // Linked servers: the switch and who may link (ops::peers), on every peer.* command; the window's own
        // refusals on the dialling server's side of pairing.
        // Assigning a vault role names a linked server too (migration 162): the same two refusals there.
        if (code == "peers_experimental" || code == "peer_forbidden")
            return command.starts_with("peer.") || command.starts_with("mirror.") || command == "role.vault.assign" ||
                   command == "role.vault.unassign" || command == "storage.vault.remove";
        // Starting a mirror (ops::mirrors, mirror::start): each refusal on the commands that send it.
        static const std::map<std::string, std::set<std::string>> kMirrorCodes{
            {"peer_revoked", {"peer.mirror.offer", "peer.mirror.answer", "peer.mirror.keys", "peer.mirror.begin",
                              "peer.mirror.grant", "peer.mirror.cancel", "peer.mirror.submit", "peer.mirror.detached",
                              "peer.mirror.deleting", "peer.mirror.resync", "peer.mirror.switch.request",
                              "peer.mirror.switch.prepare", "peer.mirror.switch.commit", "peer.mirror.promoted",
                              "peer.mirror.key"}},
            {"mirror_already", {"mirror.add"}}, {"mirror_start_running", {"mirror.add"}},
            {"vault_replicated", {"mirror.add"}}, {"vault_attach_running", {"mirror.add"}},
            {"vault_detach_running", {"mirror.add"}}, {"layout_migration_running", {"mirror.add"}},
            {"key_rotation_running", {"mirror.add"}}, {"key_salvage_running", {"mirror.add"}},
            {"vault_pending_deletion", {"mirror.add"}}, {"vault_unavailable", {"mirror.add"}},
            {"legacy_content", {"mirror.add"}}, {"key_version_missing", {"mirror.add"}},
            {"key_version_unattested", {"mirror.add"}}, {"trashed_without_uid", {"mirror.add"}},
            {"contents_not_held", {"mirror.add"}}, {"peer_not_linked", {"mirror.add", "mirror.mirror_all.set"}},
            {"peer_link_down", {"mirror.add", "mirror.switch"}},
            {"mirror_offer_not_pending", {"mirror.accept", "mirror.decline"}},
            {"mirror_vault_exists", {"mirror.accept", "peer.mirror.keys"}},
            {"mirror_name_taken", {"mirror.accept", "peer.mirror.keys"}},
            {"mirror_no_space", {"mirror.accept", "peer.mirror.keys"}},
            {"history_not_supported", {"mirror.accept", "peer.mirror.keys"}},
            {"mirror_detach_required", {"mirror.cancel"}}, {"mirror_offer_finished", {"mirror.cancel"}},
            {"mirror_keys_refused", {"peer.mirror.keys"}}, {"mirror_key_refused", {"peer.mirror.key"}}, {"mirror_offer_not_accepted", {"peer.mirror.keys"}},
            {"mirror_offer_not_installed", {"peer.mirror.begin"}},
            {"vault_mirrored", {"storage.vault.remove"}}, {"vault_orphaned_copy", {"storage.vault.remove"}},
            {"mirror_copy_choice_required", {"storage.vault.remove"}},
            // A change made on the mirror (wave 4 piece B, mirror::submit).
            {"mirror_not_live", {"peer.mirror.submit", "mirror.switch", "peer.mirror.switch.request",
                                 "peer.mirror.switch.prepare"}}, {"mirror_read_only", {"mirror.held.retry"}},
            {"contents_missing", {"peer.mirror.submit"}},
            // Leaving a mirror (wave 5 piece A, mirror::leave).
            {"mirror_not_held", {"mirror.detach", "mirror.detach.preview", "mirror.versions.set"}},
            {"too_large", {"mirror.held.get"}},
            {"mirror_detached_copy", {"mirror.add", "mirror.accept", "peer.mirror.keys"}},
            // Resync (wave 5 piece B, mirror::resync).
            {"mirror_not_stopped", {"mirror.resync"}}, {"mirror_core_unreachable", {"mirror.resync", "mirror.switch"}},
            {"mirror_core_gone", {"mirror.resync", "mirror.switch"}}, {"mirror_resync_refused", {"mirror.resync"}},
            {"mirror_paused", {"mirror.resync", "peer.mirror.resync"}},
            {"mirror_resync_failed", {"mirror.resync", "peer.mirror.resync"}},
            // The planned switch (wave 5 piece B, mirror::switching).
            {"mirror_switch_running", {"mirror.switch", "peer.mirror.switch.request"}},
            {"mirror_vault_deleting", {"mirror.switch", "peer.mirror.switch.request"}},
            {"mirror_submissions_queued", {"mirror.switch", "peer.mirror.switch.request"}},
            {"mirror_has_remote", {"mirror.switch", "peer.mirror.switch.request"}},
            {"mirror_pending_changes", {"mirror.switch", "peer.mirror.switch.prepare"}},
            {"mirror_contents_missing", {"mirror.switch", "peer.mirror.switch.prepare"}},
            {"mirror_first_copy", {"mirror.switch", "peer.mirror.switch.prepare", "mirror.takeover"}},
            {"mirror_switch_refused", {"mirror.switch"}}, {"mirror_switch_no_role", {"mirror.switch"}}, {"mirror_orphaned", {"mirror.switch", "mirror.takeover"}},
            {"mirror_term_mismatch", {"peer.mirror.switch.prepare"}},
            {"mirror_switch_ended", {"peer.mirror.switch.prepare"}}, {"mirror_ahead", {"peer.mirror.switch.prepare"}},
            {"mirror_digest_mismatch", {"peer.mirror.switch.prepare"}},
            {"mirror_not_prepared", {"peer.mirror.switch.commit"}},
            {"mirror_term_stale", {"peer.mirror.promoted"}},
            // Take over (wave 5 piece B, mirror::takeover).
            {"mirror_not_mirror", {"mirror.takeover"}}, {"mirror_diverged", {"mirror.takeover"}},
            {"mirror_core_reachable", {"mirror.takeover"}}, {"mirror_name_mismatch", {"mirror.takeover"}},
        };
        if (const auto m = kMirrorCodes.find(code); m != kMirrorCodes.end() && m->second.contains(command)) return true;
        if ((code == "no_pairing_window" || code == "rate_limited" || code == "device_unknown") &&
            command.starts_with("peer.pair."))
            return true;
        const auto it = kRefusedCodes.find(code);
        if (it == kRefusedCodes.end()) return false;
        // rate_limited is device pairing's, auth.mfa.verify's and auth.passkey.options'.
        if (code == "rate_limited") return command.starts_with("device.") || it->second.contains(command);
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
    EXPECT_TRUE(document().contains("envelope"));

    // The codes any answer may carry: the generic kinds the handler templates produce and the router's own.
    std::vector<std::string> codes;
    for (const auto& c : frames.error_codes) {
        EXPECT_FALSE(c.description.empty()) << c.code;
        codes.push_back(c.code);
    }
    EXPECT_TRUE(std::ranges::is_sorted(codes));
    EXPECT_EQ(codes, (std::vector<std::string>{"conflict", "denied", "device_scope", "device_unknown", "invalid",
                                               "not_found", "relay_read_only", "unknown_command"}));
    EXPECT_EQ(document().at("envelope").at("error_codes").size(), codes.size());
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
    const auto& doc = document();
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

// ---- ws protocol: range and capabilities ----------------------------------------------------------------------

TEST(UsageContract, TheDocumentPublishesTheProtocolRangeAndCapabilities) {
    const auto& doc = document();
    EXPECT_EQ(contract::kVersion, 3) << "the document gained protocol, capabilities and envelope.error_codes";
    EXPECT_EQ(doc.at("protocol"), (json{{"version", contract::kProtocolVersion}, {"min", contract::kProtocolMin}}));
    EXPECT_EQ(doc.at("protocol").at("version"), 1);
    EXPECT_EQ(doc.at("protocol").at("min"), 1);
    const auto& caps = doc.at("capabilities");
    ASSERT_EQ(caps.size(), contract::capabilities().size());
    std::vector<std::string> names;
    for (const auto& c : caps) {
        EXPECT_EQ(c.size(), 3u) << c.dump();
        names.push_back(c.at("name").get<std::string>());
    }
    EXPECT_EQ(names, contract::capabilityNames());

    // Both are covered by contract_hash (a capability or range change is a new contract).
    auto body = doc;
    body.erase("contract_hash");
    body.erase("ws_hash");
    body.erase("models_hash");
    EXPECT_EQ(contract::sha256Hex(body.dump()), contract::identity().contract_hash);
    body["capabilities"].push_back({{"name", "x.y"}, {"since", "0.0.0"}, {"description", "d"}});
    EXPECT_NE(contract::sha256Hex(body.dump()), contract::identity().contract_hash);
}

TEST(UsageContract, CapabilityNamesAreUniqueSortedAndWellFormed) {
    static const std::regex kName{R"([a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)"};
    static const std::regex kRelease{R"((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))"};
    const auto caps = contract::capabilities();
    ASSERT_GE(caps.size(), 7u);
    const auto names = contract::capabilityNames();
    EXPECT_TRUE(std::ranges::is_sorted(names));
    EXPECT_EQ(std::ranges::adjacent_find(names), names.end()) << "a capability name is declared twice";
    for (const auto& c : caps) {
        EXPECT_TRUE(std::regex_match(c.name, kName)) << c.name << ": dotted lower-case identifiers only";
        EXPECT_TRUE(std::regex_match(c.since, kRelease)) << c.name << " since " << c.since;
        EXPECT_FALSE(c.description.empty()) << c.name;
    }
    // Command presence is not a capability: meta.hello lists the commands.
    const auto book = contract::ws::commands();
    for (const auto& name : names) {
        if (name == "device.server.identity") continue;  // kept by request: the pin over a device session (1.16.0)
        // The normative transfer protocol's name (1.20.0); it also covers members device.pairing.open and
        // device.remote.status gained, which `commands` can't show.
        if (name == "device.endpoints") continue;
        EXPECT_EQ(wsCommand(book, name), nullptr) << name << " is a command name; clients read `commands` for that";
    }
    for (const auto* expected : {"errors.unknown_command_code", "fs.entry.metadata_version", "device.lanes.preview",
                                 "device.lanes.download", "device.lanes.upload", "device.mcp", "device.server.identity"})
        EXPECT_NE(std::ranges::find(names, expected), names.end()) << expected;
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
