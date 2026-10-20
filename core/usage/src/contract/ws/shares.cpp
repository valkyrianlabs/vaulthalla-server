// ws book: share link management (core/src/protocols/ws/handler/share/Links.cpp → share::Manager) and the contract
// identity (core/src/protocols/ws/handler/Meta.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

std::vector<WsField> shareRoleAssignmentFields() {
    return {uinteger("vault_role_id").opt().gen(gen::ref("role.vault", {"id"})),
            str("vault_role_name").opt(),
            objectArray("permission_overrides", "").opt().desc(
                "{permission_id | permission_qualified | qualified, effect, glob_path | pattern, enabled}")};
}

WsField shareLinkObject() { return object("share", "ShareLink"); }

WsField shareLinkId() { return str("id").gen(gen::ref("share", {"id"})).desc("Share link id."); }

// share::Manager refuses with std::runtime_error / std::invalid_argument (no data.code): "Share link not found",
// "Share <op> denied: <reason>", "Missing required share field: ...". Sharing switched off is ops::Denied ("denied").
std::vector<std::string> shareLinkUntypedRefusals() { return {"denied", "not_found", "invalid"}; }

std::vector<std::string> shareLinkRefusals() { return {"denied", "unauthorized"}; }

const std::vector<std::string>& shareLinkOps() {
    static const std::vector<std::string> ops = {"metadata", "list", "preview", "download", "upload", "mkdir",
                                                 "overwrite"};
    return ops;
}

// The members create and update share (update: absent leaves a field alone, null clears an optional one).
std::vector<WsField> shareLinkMutableFields() {
    return {str("name").opt().nullable(),
            str("public_label").opt().nullable(),
            str("description").opt().nullable(),
            anyOf("expires_at", {"string", "integer", "null"}).opt().desc("Timestamp string or epoch seconds; null clears."),
            uinteger("max_downloads").opt().nullable(),
            uinteger("max_upload_files").opt().nullable(),
            uinteger("max_upload_size_bytes").opt().nullable(),
            uinteger("max_upload_total_bytes").opt().nullable(),
            str("duplicate_policy").opt().nullable().oneOf({"reject", "rename", "overwrite"}),
            strArray("allowed_mime_types").opt().nullable(),
            strArray("blocked_mime_types").opt().nullable(),
            strArray("allowed_extensions").opt().nullable(),
            strArray("blocked_extensions").opt().nullable(),
            object("metadata").opt().desc("Free-form JSON object stored with the link."),
            object("public_role_assignment", "", shareRoleAssignmentFields()).opt().nullable(),
            objectArray("recipient_role_assignments", "",
                        {str("email"), object("role_assignment", "", shareRoleAssignmentFields())})
                .opt()
                .nullable()};
}

}

std::vector<WsCommandUsage> shareCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "share.link.create",
        .description = "Create a share link on a file or directory. The public token is returned once.",
        .payload = {vaultId(),
                    uinteger("root_entry_id").gen(gen::ref("fs.entry", {"id"})),
                    str("root_path").gen(gen::ref("fs.entry", {"path"})),
                    str("target_type").oneOf({"file", "directory"}),
                    str("link_type").oneOf({"download", "upload", "access"}),
                    str("access_mode").oneOf({"public", "email_validated"}).gen(gen::constant("public")),
                    WsField{.name = "allowed_ops", .types = {"integer", "array"}, .items = "string", .item_enum = shareLinkOps(),
                            .generator = gen::oneOf({"metadata", "list", "download"})}
                        .desc("A bitmask or a list of operation names."),
                    str("name").opt().nullable(),
                    str("public_label").opt().nullable(),
                    str("description").opt().nullable(),
                    anyOf("expires_at", {"string", "integer", "null"}).opt(),
                    uinteger("max_downloads").opt().nullable(),
                    uinteger("max_upload_files").opt().nullable(),
                    uinteger("max_upload_size_bytes").opt().nullable(),
                    uinteger("max_upload_total_bytes").opt().nullable(),
                    str("duplicate_policy").opt().oneOf({"reject", "rename", "overwrite"}),
                    strArray("allowed_mime_types").opt(),
                    strArray("blocked_mime_types").opt(),
                    strArray("allowed_extensions").opt(),
                    strArray("blocked_extensions").opt(),
                    object("metadata").opt(),
                    object("public_role_assignment", "", shareRoleAssignmentFields()).opt().nullable(),
                    objectArray("recipient_role_assignments", "",
                                {str("email"), object("role_assignment", "", shareRoleAssignmentFields())})
                        .opt()},
        .response = {shareLinkObject(), str("public_token"), str("public_url_path")},
        .refusal_codes = opsRefusals(),
        .untyped_refusals = shareLinkUntypedRefusals(),
        .operation = "shares.create",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.link.get",
        .description = "One share link the caller may manage (no token material).",
        .payload = {shareLinkId()},
        .response = {shareLinkObject()},
        .refusal_codes = shareLinkRefusals(),
        .untyped_refusals = shareLinkUntypedRefusals(),
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
        .untyped_refusals = shareLinkUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    {
        auto payload = std::vector<WsField>{shareLinkId(),
                                            str("link_type").opt().nullable().oneOf({"download", "upload", "access"}),
                                            str("access_mode").opt().nullable().oneOf({"public", "email_validated"}),
                                            WsField{.name = "allowed_ops", .types = {"integer", "array", "null"},
                                                    .required = false, .items = "string",
                                                    .item_enum = shareLinkOps()}
                                                .desc("A bitmask or a list of operation names.")};
        for (auto& f : shareLinkMutableFields()) payload.push_back(std::move(f));
        out.push_back({
            .command = "share.link.update",
            .description = "Patch a share link: absent members are left alone, null clears an optional one. "
                           "recipient_role_assignments (when present) replaces the recipients. vault_id, root_entry_id, "
                           "root_path, target_type, counters and timestamps are immutable (refused).",
            .payload = std::move(payload),
            .response = {shareLinkObject()},
            .refusal_codes = shareLinkRefusals(),
            .untyped_refusals = shareLinkUntypedRefusals(),
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
        .untyped_refusals = shareLinkUntypedRefusals(),
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
    return {{
        .command = "meta.contract.get",
        .description = "The contract this daemon was built from: contract_version, contract_hash (the whole "
                       "document vh_usage --json publishes) and ws_hash (the ws command book, what the web console "
                       "is generated from). Read-only, no secrets; needs a signed-in session (no build "
                       "fingerprinting before login).",
        .auth = "session",
        .input = "none",
        .response = {uinteger("contract_version"), str("contract_hash"), str("ws_hash")},
        .client_timeout = kDefaultTimeout,
    }};
}

}
