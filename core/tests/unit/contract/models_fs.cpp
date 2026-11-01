// Contract models: fs serializers against their declared shapes (see model_suites.hpp): FsEntry (a listing's
// entries, dispatched to the File / Directory / Symlink serializer), FsEntryBase (the Entry base serializer that
// `entry` of fs.dir.list / fs.metadata goes through), PreviewPlan and FsChange (fs.changes.list).

#include "model_suites.hpp"

#include "fs/model/Directory.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "ops/FsChanges.hpp"

#include <memory>
#include <vector>

namespace vh::test_contract_models_fs {

using json = nlohmann::json;

// Every optional base member set (they are only sent when set).
void fillFsEntry(fs::model::Entry& e, const std::string& name, const std::string& path) {
    e.id = 42;
    e.name = name;
    e.path = path;
    e.fuse_path = "/mnt/vaulthalla/docs" + path;
    e.size_bytes = 1234;
    e.is_hidden = false;
    e.is_system = false;
    e.created_at = 1760000000;
    e.updated_at = 1760003600;
    e.parent_id = 7;
    e.vault_id = 3;
    e.created_by = 1;
    e.last_modified_by = 2;
    e.owner_uid = 1000;
    e.group_gid = 1000;
    e.inode = 99;
    e.mode = 0644;
}

}

namespace vh::test::contract_models {

void checkFsModels(Checker& c) {
    using test_contract_models_fs::fillFsEntry;

    auto file = std::make_shared<fs::model::File>();
    fillFsEntry(*file, "report.pdf", "/docs/report.pdf");
    file->mime_type = "application/pdf";

    auto step = std::make_shared<fs::model::File>();
    fillFsEntry(*step, "part.step", "/docs/part.step");  // a derived artifact kind (PreviewPlan.derived)

    auto bare = std::make_shared<fs::model::File>();  // no optional base member, no MIME type
    bare->id = 9;
    bare->name = "a.bin";
    bare->path = "/a.bin";

    auto dir = std::make_shared<fs::model::Directory>();
    fillFsEntry(*dir, "docs", "/docs");
    dir->file_count = 3;
    dir->subdirectory_count = 1;

    auto link = std::make_shared<fs::model::Symlink>();
    fillFsEntry(*link, "latest", "/docs/latest");
    link->target = "report.pdf";

    const std::vector<std::shared_ptr<fs::model::Entry>> listing{file, step, bare, dir, link};
    for (const auto& entry : json(listing)) c.check(entry, "FsEntry", "fs.dir.list files[] (" + entry.value("name", "") + ")");

    // `entry` is the Entry base serializer whatever the entry's kind.
    c.check(json(static_cast<const fs::model::Entry&>(*dir)), "FsEntryBase", "fs.dir.list entry (directory)");
    c.check(json(static_cast<const fs::model::Entry&>(*file)), "FsEntryBase", "fs.metadata entry (file)");
    c.check(json(static_cast<const fs::model::Entry&>(*bare)), "FsEntryBase", "fs.metadata entry (bare file)");

    db::query::fs::Change created{.revision = 12, .kind = "create", .vault_id = 3, .entry_id = 42, .parent_id = 7,
                                  .entry_type = "file", .name = "report.pdf", .path = "/docs/report.pdf",
                                  .changed_at = 1760000000};
    c.check(ops::fs_changes::toJson(created), "FsChange", "fs.changes.list changes[] (create)");
    auto moved = created;
    moved.kind = "move";
    moved.old_parent_id = 1;
    moved.old_path = "/report.pdf";
    c.check(ops::fs_changes::toJson(moved), "FsChange", "fs.changes.list changes[] (move)");
    auto gone = created;
    gone.kind = "delete";
    gone.entry_type.reset();
    gone.parent_id.reset();
    c.check(ops::fs_changes::toJson(gone), "FsChange", "fs.changes.list changes[] (delete, unknown type)");
}

}
