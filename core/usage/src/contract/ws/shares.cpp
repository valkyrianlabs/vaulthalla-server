// ws book: share link management (core/src/protocols/ws/handler/share/Links.cpp → share::Manager), the contract
// identity and the protocol handshake (core/src/protocols/ws/handler/Meta.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// One permission override of a share role assignment (parsePermissionOverride in share/Links.cpp).
std::vector<WsField> sharePermissionOverrideFields() {
    return {uinteger("permission_id").opt().nullable().desc("The permission by id; or name it with "
                                                            "permission_qualified (or qualified)."),
            str("permission_qualified").opt().nullable().desc("Qualified permission name."),
            str("qualified").opt().nullable().desc("Alias of permission_qualified."),
            str("effect").opt().oneOf({"allow", "deny"}).desc("Case-insensitive; default allow."),
            str("glob_path").opt().desc("Path glob the override applies to; default \"/\"."),
            str("pattern").opt().desc("Alias of glob_path."),
            boolean("enabled").opt().nullable().desc("Default true.")};
}

// A vault role for the share's principal (parseRoleAssignment in share/Links.cpp): vault_role_id or vault_role_name.
std::vector<WsField> shareRoleAssignmentFields() {
    return {uinteger("vault_role_id").opt().nullable().gen(gen::ref("role.vault", {"id"})),
            str("vault_role_name").opt().nullable(),
            objectArray("permission_overrides", "", sharePermissionOverrideFields()).opt().nullable()};
}

WsField shareLinkObject() { return object("share", "ShareLink"); }

WsField shareLinkId() { return str("id").gen(gen::ref("share", {"id"})).desc("Share link id."); }

// Typed refusals (data.code): share::Manager and the handler refuse with ops::Denied (no permission, sharing off),
// ops::NotFound (no such link) and ops::Invalid (malformed request).
std::vector<std::string> shareLinkRefusals() { return {"denied", "not_found", "invalid", "unauthorized"}; }

const std::vector<std::string>& shareLinkOps() {
    static const std::vector<std::string> ops = {"metadata", "list", "preview", "download", "upload", "mkdir",
                                                 "overwrite"};
    return ops;
}

// allowed_ops: a bitmask or the operation names (parseAllowedOps in share/Links.cpp).
WsField shareLinkAllowedOps() {
    return WsField{.name = "allowed_ops", .types = {"integer", "array"}, .generator = gen::oneOf({"metadata", "list",
                                                                                                "download"})}
        .alternatives({alt({"integer"}).min(0).desc("Bitmask, bit i = the i-th of metadata, list, preview, download, "
                                                     "upload, mkdir, overwrite."),
                       WsField{.types = {"array"}, .items = "string", .item_enum = shareLinkOps()}.desc(
                           "Operation names.")})
        .desc("A bitmask or a list of operation names.");
}

// The members create and update share (update: absent leaves a field alone, null clears an optional one; create:
// null is the same as absent).
std::vector<WsField> shareLinkMutableFields() {
    return {str("name").opt().nullable(),
            str("public_label").opt().nullable(),
            str("description").opt().nullable(),
            anyOf("expires_at", {"string", "integer", "null"})
                .opt()
                .alternatives({alt({"string"}).desc("Timestamp \"YYYY-MM-DD HH:MM:SS\" or ISO-8601, UTC."),
                               alt({"integer"}).desc("Epoch seconds.")})
                .desc("When the link stops working; null: never."),
            uinteger("max_downloads").opt().nullable(),
            uinteger("max_upload_files").opt().nullable(),
            uinteger("max_upload_size_bytes").opt().nullable(),
            uinteger("max_upload_total_bytes").opt().nullable(),
            str("duplicate_policy").opt().nullable().oneOf({"reject", "rename", "overwrite"}),
            strArray("allowed_mime_types").opt().nullable(),
            strArray("blocked_mime_types").opt().nullable(),
            strArray("allowed_extensions").opt().nullable(),
            strArray("blocked_extensions").opt().nullable(),
            anyOf("metadata", {"object", "string"})
                .opt()
                .alternatives({alt({"object"}).desc("Free-form JSON metadata, stored as given."),
                               alt({"string"}).desc("JSON text, stored as-is (text that does not parse reads back as {}).")})
                .desc("The link's free-form metadata; ShareLink.metadata returns it parsed."),
            object("public_role_assignment", "", shareRoleAssignmentFields()).opt().nullable().desc(
                "The vault role every share session gets."),
            objectArray("recipient_role_assignments", "",
                        {str("email"),
                         object("role_assignment", "", shareRoleAssignmentFields()).opt().desc(
                             "The recipient's role (required unless sent as `role`)."),
                         object("role", "", shareRoleAssignmentFields()).opt().desc("Alias of role_assignment.")})
                .opt()
                .nullable()
                .desc("Email-validated recipients with their role; on update, replaces the list.")};
}

}

std::vector<WsCommandUsage> shareCommands() {
    std::vector<WsCommandUsage> out;

    auto createPayload = std::vector<WsField>{
        vaultId(),
        uinteger("root_entry_id").gen(gen::ref("fs.entry", {"id"})),
        str("root_path").gen(gen::ref("fs.entry", {"path"})),
        str("target_type").oneOf({"file", "directory"}),
        str("link_type").oneOf({"download", "upload", "access"}),
        str("access_mode").oneOf({"public", "email_validated"}).gen(gen::constant("public")),
        shareLinkAllowedOps()};
    for (auto& f : shareLinkMutableFields()) createPayload.push_back(std::move(f));
    out.push_back({
        .command = "share.link.create",
        .description = "Create a share link on a file or directory. The public token is returned once.",
        .payload = std::move(createPayload),
        .response = {shareLinkObject(), str("public_token"), str("public_url_path")},
        .refusal_codes = opsRefusals(),
        .operation = "shares.create",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.link.get",
        .description = "One share link the caller may manage (no token material).",
        .payload = {shareLinkId()},
        .response = {shareLinkObject()},
        .refusal_codes = shareLinkRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.link.list",
        .description = "Share links: of one vault (vault_id, needs the vault's share-management permission) or "
                       "created by the caller. offset is turned into a page when limit is given.",
        .payload = {uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"})),
                    str("sort").opt().nullable().desc("A column name."),
                    str("filter").opt().nullable(),
                    uinteger("limit").opt().nullable(),
                    uinteger("page").opt().nullable(),
                    uinteger("offset").opt().nullable(),
                    str("direction").opt().nullable().oneOf({"asc", "desc"}).desc("Case-insensitive.")},
        .response = {objectArray("shares", "ShareLink")},
        .refusal_codes = shareLinkRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    {
        auto payload = std::vector<WsField>{shareLinkId(),
                                            str("link_type").opt().nullable().oneOf({"download", "upload", "access"}),
                                            str("access_mode").opt().nullable().oneOf({"public", "email_validated"}),
                                            shareLinkAllowedOps().opt().nullable()};
        for (auto& f : shareLinkMutableFields()) payload.push_back(std::move(f));
        out.push_back({
            .command = "share.link.update",
            .description = "Patch a share link: absent members are left alone, null clears an optional one. "
                           "recipient_role_assignments (when present) replaces the recipients. vault_id, root_entry_id, "
                           "root_path, target_type, counters and timestamps are immutable (refused).",
            .payload = std::move(payload),
            .response = {shareLinkObject()},
            .refusal_codes = shareLinkRefusals(),
                .client_timeout = kDefaultTimeout,
        });
    }

    out.push_back({
        .command = "share.link.rotate_token",
        .description = "Issue a new public token (returned once); the old URL and every session of the link stop "
                       "working.",
        .payload = {shareLinkId()},
        .response = {shareLinkObject(), str("public_token"), str("public_url_path")},
        .refusal_codes = shareLinkRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.link.revoke",
        .description = "Revoke a share link; its sessions end on their next request.",
        .payload = {str("id").gen(gen::ref("share", {"id"}))},
        .response = {boolean("revoked")},
        .refusal_codes = opsRefusals(),
        .operation = "shares.revoke",
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

std::vector<WsCommandUsage> metaCommands() {
    const auto contractIdentity = [](std::string name) {
        return object(std::move(name), "",
                      {uinteger("contract_version"), str("contract_hash"), str("ws_hash"), str("models_hash")});
    };
    const auto versionText = [](std::string name) {
        return str(std::move(name)).desc("At most 64 printable ASCII characters.");
    };
    return {{
        .command = "meta.hello",
        .description = "The protocol handshake, first thing after connecting (after sign-in on the web socket; "
                       "allowed where meta.contract.get is: signed-in web, paired device and pairing-only sessions, "
                       "never an unauthenticated or share session). The client says what it is and the protocol "
                       "range it speaks; the daemon answers its own name and version, the protocol version this "
                       "session now speaks (the newest both speak; kProtocolMin without a range, as for a session "
                       "that never says hello), its own range, its capabilities, every command it registers and its "
                       "contract identity. No overlap: ERROR protocol_unsupported with data {code, server_min, "
                       "server_max, server_version}. A paired device's client.version refreshes its app_version.",
        .auth = "session",
        .input = "payload",
        .payload = {object("client", "", {versionText("name").opt(), versionText("version").opt()})
                        .opt()
                        .desc("Who is connecting (\"Vaulthalla Desktop\", \"0.4.0\"): kept on the session for "
                              "the logs."),
                    object("protocol", "", {uinteger("min").opt(), uinteger("max").opt()})
                        .opt()
                        .desc("The protocol versions the client speaks; a missing bound is the server's.")},
        .response = {object("server", "", {str("name").oneOf({"vaulthalla"}), str("version")})
                         .desc("The daemon's product version (VH_VERSION)."),
                     object("protocol", "", {uinteger("version"), uinteger("min"), uinteger("max")})
                         .desc("version: what this session speaks from now on; min/max: the daemon's range."),
                     strArray("capabilities").desc("Capability names, sorted (vh_usage --json `capabilities`)."),
                     strArray("commands").desc("Every ws command this daemon registers, sorted."),
                     contractIdentity("contract").desc("What meta.contract.get answers.")},
        .refusal_codes = {"invalid", "protocol_unsupported"},
        .client_timeout = kDefaultTimeout,
    }, {
        .command = "meta.contract.get",
        .description = "The contract this daemon was built from: contract_version, contract_hash (the whole "
                       "document vh_usage --json publishes), ws_hash (the ws command book, what the web console "
                       "is generated from) and models_hash (the model shapes the book refers to). Read-only, no "
                       "secrets; needs a signed-in session (no build fingerprinting before login).",
        .auth = "session",
        .input = "none",
        .response = {uinteger("contract_version"), str("contract_hash"), str("ws_hash"), str("models_hash")},
        .client_timeout = kDefaultTimeout,
    }};
}

}
