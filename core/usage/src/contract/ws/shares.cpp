// ws book: share link management (core/src/protocols/ws/handler/share/Links.cpp) and the contract identity
// (core/src/protocols/ws/handler/Meta.cpp).

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

}

std::vector<WsCommandUsage> shareCommands() {
    std::vector<WsCommandUsage> out;

    const std::vector<std::string> shareOps = {"metadata", "list", "preview", "download", "upload", "mkdir", "overwrite"};

    out.push_back({
        .command = "share.link.create",
        .description = "Create a share link on a file or directory. The public token is returned once.",
        .payload = {vaultId(),
                    uinteger("root_entry_id").gen(gen::ref("fs.entry", {"id"})),
                    str("root_path").gen(gen::ref("fs.entry", {"path"})),
                    str("target_type").oneOf({"file", "directory"}),
                    str("link_type").oneOf({"download", "upload", "access"}),
                    str("access_mode").oneOf({"public", "email_validated"}).gen(gen::constant("public")),
                    WsField{.name = "allowed_ops", .types = {"integer", "array"}, .items = "string", .item_enum = shareOps,
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
        .untyped_refusals = {"invalid"},
        .operation = "shares.create",
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
                       "is generated from). Read-only, no secrets; allowed wherever auth.isAuthenticated is.",
        .auth = "session",
        .input = "none",
        .response = {uinteger("contract_version"), str("contract_hash"), str("ws_hash")},
        .client_timeout = kDefaultTimeout,
    }};
}

}
