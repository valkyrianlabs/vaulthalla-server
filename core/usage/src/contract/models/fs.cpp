// ws models: fs. Filesystem entries (core/src/fs/model/{Entry,File,Directory,Symlink}.cpp to_json) and the preview
// plan files carry (core/src/preview/Plan.cpp).

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

// fs::model::to_json(Entry): the members every entry serializes, whatever its kind.
std::vector<WsField> fsModelEntryBaseFields() {
    return {
        uinteger("id"),
        str("name"),
        str("path").desc("Vault-relative path."),
        str("abs_path").desc("The entry's path on the Vaulthalla mount (fuse path)."),
        uinteger("size_bytes"),
        boolean("is_hidden"),
        boolean("is_system"),
        str("created_at").desc("ISO-8601 UTC (\"2026-10-20T12:00:00Z\")."),
        str("updated_at").desc("ISO-8601 UTC."),
        integer("parent_id").opt().desc("Absent for the vault root."),
        integer("vault_id").opt(),
        integer("created_by").opt().desc("User id."),
        integer("last_modified_by").opt().desc("User id."),
        integer("owner_uid").opt(),
        integer("group_gid").opt(),
        uinteger("inode").opt(),
        uinteger("mode").opt().desc("POSIX mode bits."),
        str("metadata_version").desc(
            "Opaque version of the entry's own metadata (\"m<id>-<hex16>\"): a hash of vault, parent, name, mode, "
            "owner, group and updated_at, so it changes on rename, move, mode change and any updated_at change and "
            "matches again only for the same metadata. Compare for equality only."),
        str("content_version").opt().desc(
            "Files only: the strong generation ETag GET /download/content serves for the current bytes, exactly "
            "(quotes included; usable as If-Match / If-None-Match / If-Range). Changes on every content write, never "
            "on rename or move."),
    };
}

}

std::vector<WsModel> fsModels() {
    std::vector<WsModel> out;

    out.push_back(model("PreviewPlan",
        "How a file can be consumed, decided by the server (preview::to_json(PreviewPlan), core/src/preview/Plan.cpp).",
        {str("kind").oneOf({"rendered_image", "native_media", "client_model", "text_document", "derived_artifact",
                            "unsupported"}),
         str("renderer").oneOf({"image", "pdf", "svg", "image-native", "video", "audio", "text", "markdown", "model:glb",
                                "model:gltf", "model:stl", "model:obj", "derived:step-glb", "none"})
             .desc("The console renderer that shows the file (none: unsupported)."),
         str("requires").oneOf({"preview", "download"})
             .desc("What the viewer must be allowed: lossy server renders (preview) or the original bytes (download)."),
         boolean("thumbnail").desc("Whether GET /preview can render a thumbnail."),
         strArray("derived").opt().desc("Derived artifact kinds the file can have (first = primary); absent when none.")}));

    auto entry = fsModelEntryBaseFields();
    entry.push_back(str("type").oneOf({"file", "directory", "symlink"}));
    entry.push_back(str("mime_type").opt().nullable().desc("Files (always sent, null when unknown)."));
    entry.push_back(object("preview", "PreviewPlan").opt().desc("Files."));
    entry.push_back(uinteger("file_count").opt().desc("Directories."));
    entry.push_back(uinteger("subdirectory_count").opt().desc("Directories."));
    entry.push_back(str("target").opt().desc("Symlinks: the link target."));
    out.push_back(model("FsEntry",
        "A directory listing's entry: fs::model::to_json(std::vector<std::shared_ptr<Entry>>) dispatches to the File, "
        "Directory or Symlink serializer (core/src/fs/model/*.cpp), so `type` says which members follow.",
        std::move(entry)));

    out.push_back(model("FsChange",
        "One change of fs.changes.list (ops::fs_changes::toJson(Change), core/src/ops/FsChanges.cpp): a journaled entry "
        "mutation (migration 115) as the caller sees it.",
        {uinteger("revision").desc("Commit-ordered; the cursor after this change."),
         str("kind").oneOf({"create", "update", "rename", "move", "delete"})
             .desc("update: content (files), target (symlinks), mode or hidden flag. A rename or move into the "
                   "caller's view reads as create, out of it as delete."),
         uinteger("entry_id").desc("The entry's id (fs_entry.id; stable across rename and move)."),
         str("type").oneOf({"file", "directory", "symlink"}).nullable()
             .desc("null when the entry was in no type table at the time."),
         uinteger("parent_id").nullable().desc("The parent folder's entry id (for delete: where it was)."),
         str("name"),
         str("path").desc("Vault path after the change (for delete: where it was)."),
         str("changed_at").desc("ISO-8601 UTC."),
         str("old_path").opt().desc("rename and move: the vault path before."),
         uinteger("old_parent_id").opt().nullable().desc("rename and move: the parent before.")}));

    out.push_back(model("FsEntryBase",
        "The listed directory or looked-up entry itself (`entry` of fs.dir.list / fs.metadata): fs::model::to_json"
        "(Entry) on the Entry base (core/src/fs/model/Entry.cpp), so it carries no type, mime_type, preview or counts "
        "(a file still carries content_version).",
        fsModelEntryBaseFields()));

    return out;
}

}
