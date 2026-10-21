// ws models: link sharing. Share links (core/src/share/Link.cpp toManagementJson / toPublicJson, without token
// material) and the share session's view of entries (core/src/protocols/ws/handler/{fs/Storage,share/Upload}.cpp).

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

std::vector<std::string> shareModelOps() {
    return {"metadata", "list", "preview", "download", "upload", "mkdir", "overwrite"};
}

WsField shareModelAllowedOps() {
    return uinteger("allowed_ops").desc("Bitmask of operations, bit i = the i-th of: " + [] {
        std::string out;
        for (const auto& op : shareModelOps()) out += (out.empty() ? "" : ", ") + op;
        return out;
    }() + ".");
}

WsField shareModelMetadata() {
    return object("metadata").desc("The link's free-form JSON metadata (the creator's; {} when none or unparsable).");
}

}

std::vector<WsModel> shareModels() {
    std::vector<WsModel> out;

    out.push_back(model("ShareLink",
        "A share link as its managers see it: share::Link::toManagementJson() (core/src/share/Link.cpp) without "
        "token_lookup_id, via protocols::ws::handler::share::Links::managementJson.",
        {str("id"),
         uinteger("vault_id"),
         uinteger("root_entry_id"),
         str("root_path").desc("Vault-relative path of the shared file or directory."),
         str("target_type").oneOf({"file", "directory"}),
         str("link_type").oneOf({"download", "upload", "access"}),
         str("access_mode").oneOf({"public", "email_validated"}),
         shareModelAllowedOps(),
         str("name").nullable(),
         str("public_label").nullable(),
         str("description").nullable(),
         uinteger("created_by").desc("User id."),
         uinteger("updated_by").nullable(),
         uinteger("revoked_by").nullable(),
         str("created_at").desc("ISO-8601 UTC."),
         str("updated_at").desc("ISO-8601 UTC."),
         str("expires_at").nullable().desc("ISO-8601 UTC; null: never."),
         str("revoked_at").nullable(),
         str("disabled_at").nullable(),
         str("last_accessed_at").nullable(),
         uinteger("access_count"),
         uinteger("download_count"),
         uinteger("upload_count"),
         uinteger("max_downloads").nullable(),
         uinteger("max_upload_files").nullable(),
         uinteger("max_upload_size_bytes").nullable(),
         uinteger("max_upload_total_bytes").nullable(),
         str("duplicate_policy").oneOf({"reject", "rename", "overwrite"}),
         strArray("allowed_mime_types"),
         strArray("blocked_mime_types"),
         strArray("allowed_extensions"),
         strArray("blocked_extensions"),
         shareModelMetadata()}));

    out.push_back(model("SharePublicLink",
        "A share link's public view, what a share session sees: share::Link::toPublicJson() (core/src/share/Link.cpp) "
        "via protocols::ws::handler::share::Sessions::publicLinkJson.",
        {str("id"),
         str("root_path"),
         str("target_type").oneOf({"file", "directory"}),
         str("link_type").oneOf({"download", "upload", "access"}),
         str("access_mode").oneOf({"public", "email_validated"}),
         shareModelAllowedOps(),
         str("public_label").nullable(),
         str("expires_at").nullable().desc("ISO-8601 UTC; null: never."),
         shareModelMetadata(),
         uinteger("effective_allowed_ops").opt().desc(
             "Once the session is ready: the operations it may actually run (allowed_ops narrowed by the share's "
             "role and the server's policy), as a bitmask like allowed_ops.")}));

    out.push_back(model("ShareEntry",
        "A file or directory inside a share, as the share session sees it (share-relative path, no ownership): "
        "protocols::ws::handler::fs::Storage::shareEntryJson.",
        {uinteger("id"),
         str("name"),
         str("path").desc("Share-relative path (\"/\" is the share root)."),
         str("type").oneOf({"file", "directory"}),
         uinteger("size_bytes"),
         str("created_at").desc("ISO-8601 UTC."),
         str("updated_at").desc("ISO-8601 UTC."),
         uinteger("file_count").opt().desc("Directories."),
         uinteger("subdirectory_count").opt().desc("Directories."),
         str("mime_type").opt().nullable().desc("Files (always sent, null when unknown)."),
         object("preview", "PreviewPlan").opt().desc("Files; the share's capabilities still gate each lane.")}));

    out.push_back(model("ShareUploadedFile",
        "The file a finished share upload created, as the share sees it: "
        "protocols::ws::handler::share::Upload::uploadedFileJson.",
        {uinteger("id"),
         str("name"),
         str("path").desc("Share-relative path."),
         str("type").oneOf({"file"}),
         uinteger("size_bytes"),
         str("mime_type").nullable()}));

    return out;
}

}
