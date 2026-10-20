// Contract models: share serializers against their declared shapes (see model_suites.hpp): ShareLink (management
// view), SharePublicLink (a share session's view), ShareEntry and ShareUploadedFile, through the handlers' own
// builders.

#include "model_suites.hpp"

#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "protocols/ws/handler/share/Links.hpp"
#include "protocols/ws/handler/share/Sessions.hpp"
#include "protocols/ws/handler/share/Upload.hpp"
#include "share/Link.hpp"
#include "share/Principal.hpp"

namespace vh::test_contract_models_shares {

// A link with every optional member set.
share::Link fullShareLink() {
    share::Link l;
    l.id = "0b9c6a40-5d3e-4a39-9a43-6f1e7f2c1d11";
    l.token_lookup_id = "lookup";
    l.token_hash = {1, 2, 3};
    l.created_by = 1;
    l.updated_by = 2;
    l.revoked_by = 3;
    l.vault_id = 4;
    l.root_entry_id = 5;
    l.root_path = "/docs";
    l.target_type = share::TargetType::Directory;
    l.link_type = share::LinkType::Upload;
    l.access_mode = share::AccessMode::EmailValidated;
    l.allowed_ops = share::bit(share::Operation::List) | share::bit(share::Operation::Upload);
    l.name = "Quarterly";
    l.public_label = "Drop files here";
    l.description = "For the auditors";
    l.expires_at = 1770000000;
    l.revoked_at = 1769000000;
    l.disabled_at = 1768000000;
    l.created_at = 1760000000;
    l.updated_at = 1761000000;
    l.last_accessed_at = 1762000000;
    l.access_count = 10;
    l.download_count = 2;
    l.upload_count = 3;
    l.max_downloads = 100;
    l.max_upload_files = 20;
    l.max_upload_size_bytes = 1 << 20;
    l.max_upload_total_bytes = 1 << 24;
    l.duplicate_policy = share::DuplicatePolicy::Rename;
    l.allowed_mime_types = {"application/pdf"};
    l.blocked_mime_types = {"application/x-msdownload"};
    l.allowed_extensions = {".pdf"};
    l.blocked_extensions = {".exe"};
    l.metadata = R"({"project":"audit"})";
    return l;
}

// The defaults: nothing optional set.
share::Link bareShareLink() {
    share::Link l;
    l.id = "a1";
    l.root_path = "/";
    l.created_at = 1760000000;
    l.updated_at = 1760000000;
    return l;
}

}

namespace vh::test::contract_models {

void checkShareModels(Checker& c) {
    namespace links = test_contract_models_shares;
    using protocols::ws::handler::fs::Storage;
    using protocols::ws::handler::share::Links;
    using protocols::ws::handler::share::Sessions;
    using protocols::ws::handler::share::Upload;

    const auto full = links::fullShareLink();
    const auto bare = links::bareShareLink();
    c.check(Links::managementJson(full), "ShareLink", "share.link.get (every optional member set)");
    c.check(Links::managementJson(bare), "ShareLink", "share.link.get (defaults)");
    c.check(Sessions::publicLinkJson(full, 17u), "SharePublicLink", "share.session.open (ready)");
    c.check(Sessions::publicLinkJson(bare, std::nullopt), "SharePublicLink", "share.session.open (email_required)");

    share::Principal principal;
    principal.root_path = "/docs";

    fs::model::Directory dir;
    dir.id = 5;
    dir.name = "docs";
    dir.path = "/docs";
    dir.file_count = 2;
    dir.subdirectory_count = 1;
    c.check(Storage::shareEntryJson(dir, principal), "ShareEntry", "share.fs.list entry (the share root)");

    fs::model::File file;
    file.id = 6;
    file.name = "part.step";
    file.path = "/docs/cad/part.step";
    file.size_bytes = 4096;
    file.mime_type = "model/step";
    c.check(Storage::shareEntryJson(file, principal), "ShareEntry", "share.fs.list entries[] (file with a MIME type)");
    c.check(Upload::uploadedFileJson(file, principal), "ShareUploadedFile", "share.upload.finish entry");

    fs::model::File untyped;
    untyped.id = 7;
    untyped.name = "blob";
    untyped.path = "/docs/blob";
    c.check(Storage::shareEntryJson(untyped, principal), "ShareEntry", "share.fs.list entries[] (no MIME type)");
    c.check(Upload::uploadedFileJson(untyped, principal), "ShareUploadedFile", "share.upload.finish entry (no MIME)");
}

}
