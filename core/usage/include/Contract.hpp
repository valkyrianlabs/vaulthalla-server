#pragma once

#include "FieldGen.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

// The server-owned contract: the CLI books (CommandUsage), the ws command book (WsCommandUsage) and the operation
// catalog (OperationSpec), all declared here in the usage module and published by `vh_usage --json`. The web console's
// ws types are generated from it (web/src/util/generated/wsContract.ts), the integration engine reads it, and the
// daemon answers `meta.contract.get` with its identity so a console built against another contract can tell.
namespace vh::contract {

// ---------------------------------------------------------------------------------------------------------------
// ws command book
// ---------------------------------------------------------------------------------------------------------------

// One JSON member of a ws payload, response or model. `types` are JSON types ("string", "integer", "number",
// "boolean", "object", "array", "null"); more than one means either is sent or accepted. An object lists its `fields`,
// names the server `model` it serializes (see WsModel), or, used as a map, gives the shape of every member value in
// `values`. An array gives its `items` type (plus `fields`/`model` for object elements), or the full element shape in
// `element` when that is not a plain type or one model (an array, a union). `one_of` spells out a union member by
// member: each alternative is a nameless WsField (its own types, fields, model, enum ...), and `types` stays their
// union, so a consumer that ignores `one_of` still sees the JSON types. A `partial` object (payloads) is a merge
// patch of its shape: any subset of its members, at any depth.
struct WsField {
    std::string name{};
    std::vector<std::string> types{};
    bool required = true;
    std::string description{};
    std::vector<std::string> enum_values{};   // allowed strings
    std::string items{};                       // array element JSON type
    std::vector<std::string> item_enum{};      // allowed strings for an array of strings
    std::vector<WsField> fields{};             // object members (when the shape is part of the contract)
    std::string model{};                       // named server model for an object or array of objects
    std::optional<std::int64_t> minimum{}, maximum{};
    FieldGenPtr generator{};
    std::vector<WsField> one_of{};             // the union's alternatives (nameless fields)
    std::vector<WsField> values{};             // a map object: the shape of each member value (one element)
    std::vector<WsField> element{};            // an array: the shape of each element when `items` can't say it
    bool partial = false;                      // a merge patch: any subset of the object's members, at any depth

    [[nodiscard]] WsField opt() const { auto c = *this; c.required = false; return c; }
    [[nodiscard]] WsField nullable() const { auto c = *this; c.types.emplace_back("null"); return c; }
    [[nodiscard]] WsField desc(std::string d) const { auto c = *this; c.description = std::move(d); return c; }
    [[nodiscard]] WsField gen(FieldGenPtr g) const { auto c = *this; c.generator = std::move(g); return c; }
    [[nodiscard]] WsField oneOf(std::vector<std::string> v) const { auto c = *this; c.enum_values = std::move(v); return c; }
    [[nodiscard]] WsField min(const std::int64_t v) const { auto c = *this; c.minimum = v; return c; }
    [[nodiscard]] WsField max(const std::int64_t v) const { auto c = *this; c.maximum = v; return c; }
    [[nodiscard]] WsField alternatives(std::vector<WsField> a) const { auto c = *this; c.one_of = std::move(a); return c; }
    [[nodiscard]] WsField patch() const { auto c = *this; c.partial = true; return c; }
};

// A named server model: the JSON one serializer produces (a to_json, an ops JSON function or a handler's builder),
// referenced by WsField::model from the book and from other models. core/tests/unit/contract checks every model
// against its serializer with seeded instances, so a serializer change that isn't declared here fails a test.
struct WsModel {
    std::string name{};         // "User"
    std::string description{};  // what it is and which serializer produces it
    std::vector<WsField> fields{};
};

// An alternative payload/response a command takes in another session mode (e.g. a share-link session).
struct WsVariant {
    std::string mode{};  // "share"
    std::string description{};
    std::vector<WsField> payload{}, response{};
};

// A NeedsConfirmation refusal: the command answered ERROR with data.code `code` because a person must accept
// something first. The client asks (error text), then resends with `accept_field` set: a payload member path, dotted
// for nested members ("provision.accept_adoption"); a boolean flag unless its declaration says otherwise (a token from
// another command). Empty when no resend accepts it (the description says what to do instead, e.g. plan again).
struct WsConfirmation {
    std::string code{};
    std::string accept_field{};
    std::string description{};
};

struct WsCommandUsage {
    std::string command{};      // "fs.dir.list"
    std::string description{};
    // What a session needs before the router runs it: "public" (no session), "session" (any socket, the
    // session-lifecycle set), "human" (a signed-in user with a valid access token, or a paired device's session on
    // the device listener: a device acts as its user), "share" (a share session), "pairing" (the device listener's
    // pairing-only connections, and a paired device's session), "device" (a paired device's own session only).
    std::string auth = "human";
    // Where the handler reads its input: "payload" (the `payload` object), "none" (nothing), "token" (the envelope
    // `token`, payload ignored).
    std::string input = "payload";
    std::vector<WsField> payload{}, response{};
    std::vector<WsVariant> variants{};
    // The refusal kinds it can answer with: the generic "denied", "not_found", "invalid", "conflict" (ERROR with that
    // data.code), "unauthorized" (status UNAUTHORIZED: the router refused) and "error" (ERROR without a code, when
    // the command refuses that way by design, e.g. a failed login); and the ops::Refused codes (ERROR with that
    // data.code) a client acts on where no generic kind says enough: "no_pairing_window", "rate_limited",
    // "device_unknown" (device pairing), "export_requires_device", "import_requires_device" (vault.keys.export,
    // .export.confirm and .import on a session that isn't a paired device's: D4). Exported as `refusal_kinds`; the
    // exported `refusal_codes` is these plus the confirmation codes (the pre-version-2 shape).
    std::vector<std::string> refusal_codes{};
    std::vector<WsConfirmation> confirmations{};
    // Refusals sent without a data.code (classified by message text on the client): a gap to close in core.
    std::vector<std::string> untyped_refusals{};
    std::optional<std::string> operation{};  // OperationSpec id
    // When `data` is one model's JSON as a whole (not wrapped in a member), its name; `response` then lists that
    // model's fields.
    std::optional<std::string> response_model{};
    std::chrono::milliseconds client_timeout{15'000};
};

// The frames every command travels in (the same for all commands; core/include/protocols/ws/Envelope.hpp and the
// handler templates enforce them): the request, the answer, and the frame that answers a message the daemon can't
// route.
struct WsEnvelope {
    std::vector<WsField> request{}, response{}, error_frame{};
};

// ---------------------------------------------------------------------------------------------------------------
// Operation catalog
// ---------------------------------------------------------------------------------------------------------------

// A canonical, surface-independent field of an operation.
struct FieldSpec {
    std::string name{};                 // "name", "role", "vault", "path"
    std::string type{};                 // "string", "uint", "bool", "path", "bytes", "enum", "ref"
    bool required = true;
    std::vector<std::string> enum_values{};
    std::string ref{};                  // for "ref": the entity kind ("user", "vault", ...)
    FieldGenPtr generator{};
    std::string description{};
};

// How canonical fields map onto a CLI command: `usage_path` is the CommandUsage lineage ({"user", "create"}); each
// field names the entry carrying it ("positional:username", "option:role", "optional:email", "flag:disable").
struct CliBinding {
    std::vector<std::string> usage_path{};
    std::map<std::string, std::string> field_to_entry{};
    std::map<std::string, std::string> fixed{};  // entries always passed ("flag:yes" -> "", "flag:local" -> "")
};

struct WsBinding {
    std::string command{};                                // "auth.register"
    std::map<std::string, std::string> field_to_json{};   // "name" -> "/name"
    std::map<std::string, std::string> fixed{};           // JSON pointer -> literal JSON text ("/type" -> "\"local\"")
    std::string id_pointer{};                             // where a created id comes back ("/user/id")
};

// FUSE: the vh_fs_actor request that performs the op (see the harness protocol), with field -> actor argument.
struct FsBinding {
    std::string actor_op{};                               // "write", "read", "ls", "mkdir", "rename", "rm_rf", ...
    std::map<std::string, std::string> field_to_arg{};    // "path" -> "path", "to" -> "to"
};

struct HttpBinding {
    std::string method{};                                 // "GET"
    std::string path{};                                   // "/download/content"
    std::map<std::string, std::string> field_to_param{};  // "vault" -> "query:vault_id"
};

// What one refusal looks like on every surface. `cli_exit` 2 = usage error/refusal, 1 = fault. `ws_code` is the
// data.code (empty: sent without one, the client classifies the text). `errno_name` for FUSE, `http_status` for HTTP.
struct Refusal {
    int cli_exit = 2;
    std::string ws_status = "ERROR";
    std::string ws_code{};
    std::string errno_name{};
    int http_status = 0;
};

struct Effect {
    std::string kind{};    // "create", "update", "delete", "read", "session"
    std::string entity{};  // "user", "group", "vault", "vault_role_assignment", "fs.entry", "share", "session"
};

struct OperationSpec {
    std::string id{};  // "users.create" (matches ops::users::create where an ops:: function exists)
    std::string description{};
    std::vector<FieldSpec> fields{};
    // Permission names (qualified, as in the permission tables) any one of which can allow the op; the oracle reads
    // them as hints, the real decision is RBAC's. "owner" means the vault owner / the actor itself.
    std::vector<std::string> requires_any{};
    Effect effect{};
    std::optional<CliBinding> cli{};
    std::optional<WsBinding> ws{};
    std::optional<FsBinding> fuse{};
    std::optional<HttpBinding> http{};
    std::chrono::milliseconds deadline{15'000};
    std::map<std::string, Refusal> refusals{};  // "denied" | "not_found" | "invalid" | "conflict" | "unauthorized"
};

// ---------------------------------------------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------------------------------------------

namespace ws {
std::vector<WsCommandUsage> commands();
// Every model the book refers to, sorted by name.
std::vector<WsModel> models();
// The declared fields of one model (throws std::out_of_range for an unknown name).
std::vector<WsField> modelFields(const std::string& name);
WsEnvelope envelope();
}

std::vector<OperationSpec> operations();

// Bumped when the JSON document's own shape changes (not when its content does: that is what the hashes are for).
// 2: `models` (+ `models_hash`), WsField `one_of`/`values`/`element`/`partial`, command `response_model`,
//    `refusal_kinds` and `confirmations` (`refusal_codes` stays their union), `envelope`.
inline constexpr int kVersion = 2;

// The whole document: {contract_version, contract_hash, ws_hash, models_hash, cli, ws, models, envelope, operations},
// keys sorted. Hashes are SHA-256 (hex) over the canonical (compact, sorted-key) JSON of {contract_version, cli, ws,
// models, envelope, operations}, of the `ws` array alone and of the `models` array alone.
std::string document(int indent = 2);

struct Identity {
    int version = kVersion;
    std::string contract_hash{};  // the whole document
    std::string ws_hash{};        // the ws book only: what the web console is generated from
    std::string models_hash{};    // the model shapes the book refers to
};

// Computed once per process from the same declarations vh_usage publishes.
const Identity& identity();

std::string sha256Hex(const std::string& data);

}
