// ws book: fs.* (core/src/protocols/ws/handler/fs/Storage.cpp; fs.download.* and the share-session forms of
// fs.metadata / fs.list / fs.upload.* are the share handlers' native surface, handler/share/*.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// Typed refusals (data.code): enforcePermission() is ops::Denied, a missing vault or path ops::NotFound, a malformed
// payload ops::Invalid (handler/RequestErrors.hpp); the share-session forms add the share resolvers' kinds.
std::vector<std::string> fsReadRefusals() { return {"unauthorized", "denied", "not_found", "invalid"}; }

std::vector<std::string> fsWriteRefusals() { return {"unauthorized", "denied", "not_found", "conflict", "invalid"}; }

std::vector<WsField> fsListResponse() {
    return {str("vault").desc("The vault's name."), str("path"),
            object("entry", "FsEntryBase").desc("The listed directory itself (Entry base members only)."),
            objectArray("files", "FsEntry")};
}

std::vector<WsField> fsMoveResponse() { return {str("from"), str("to")}; }

std::vector<WsField> fsMovePayload() { return {vaultId(), vaultPath("from"), vaultPath("to")}; }

WsField fsTransferId() { return str("transfer_id").gen(gen::ref("transfer", {"id"}, "own")).desc("From fs.download.start."); }

WsField shareRelativePath() {
    return str("path").opt().desc("Share-relative path (the share root when absent).");
}

}

std::vector<WsCommandUsage> fsCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "fs.dir.create",
        .description = "Create a directory (Touch on the path).",
        .payload = {vaultId(), vaultPath("path")},
        .response = {str("path")},
        .refusal_codes = fsWriteRefusals(),
        .operation = "fs.mkdir",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "fs.dir.list",
        .description = "List a directory (List on the path). Children the caller cannot Lookup are left out, as "
                       "in FUSE readdir, and so is what they hold from child folders' size and counts and the "
                       "folder's own size.",
        .payload = {vaultId(), vaultPath("path").opt().desc("Defaults to \"/\".")},
        .response = fsListResponse(),
        .refusal_codes = fsReadRefusals(),
        .operation = "fs.list",
        .client_timeout = 30s,
    });

    out.push_back({
        .command = "fs.metadata",
        .description = "One entry's metadata (Lookup on the path). A folder's size covers only what the caller can "
                       "Lookup, as in fs.dir.list.",
        .payload = {vaultId(), vaultPath("path").opt().desc("Defaults to \"/\".")},
        .response = {str("vault").desc("The vault's name."), str("path"),
                     object("entry", "FsEntryBase").desc("Entry base members only (no type, mime_type or preview).")},
        .variants = {{.mode = "share",
                      .description = "In a share session: share-relative paths, entries reduced to the share view.",
                      .payload = {vaultId().opt().nullable(), shareRelativePath()},
                      .response = {str("path"), object("entry", "ShareEntry")}}},
        .refusal_codes = fsWriteRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "fs.list",
        .description = "fs.dir.list for console sessions; in a share session the share's view of the directory.",
        .payload = {vaultId(), vaultPath("path").opt().desc("Defaults to \"/\".")},
        .response = fsListResponse(),
        .variants = {{.mode = "share",
                      .description = "In a share session: share-relative paths, entries reduced to the share view.",
                      .payload = {vaultId().opt().nullable(), shareRelativePath()},
                      .response = {str("path"), object("entry", "ShareEntry"), objectArray("files", "ShareEntry")}}},
        .refusal_codes = fsWriteRefusals(),
        .operation = "fs.list",
        .client_timeout = 30s,
    });

    out.push_back({
        .command = "fs.entry.delete",
        .description = "Delete a file or directory tree (Delete on the path).",
        .payload = {vaultId(), vaultPath("path")},
        .response = {str("path")},
        .refusal_codes = fsReadRefusals(),
        .operation = "fs.delete",
        .client_timeout = 180s,
    });

    out.push_back({
        .command = "fs.entry.move",
        .description = "Move an entry: Move on the source; into another folder also Write (files) or Touch "
                       "(directories) at the destination, for the entry and everything it carries.",
        .payload = fsMovePayload(),
        .response = fsMoveResponse(),
        .refusal_codes = fsWriteRefusals(),
        .client_timeout = 180s,
    });

    out.push_back({
        .command = "fs.entry.rename",
        .description = "Rename an entry: Rename on the source; into another folder also Write (files) or Touch "
                       "(directories) at the destination, for the entry and everything it carries.",
        .payload = fsMovePayload(),
        .response = fsMoveResponse(),
        .refusal_codes = fsWriteRefusals(),
        .operation = "fs.rename",
        .client_timeout = 60s,
    });

    out.push_back({
        .command = "fs.entry.copy",
        .description = "Copy an entry or tree: Copy on every source, Read on source files, Write (files) or Touch "
                       "(directories) at each destination, all checked before anything is written.",
        .payload = fsMovePayload(),
        .response = fsMoveResponse(),
        .refusal_codes = fsWriteRefusals(),
        .untyped_refusals = {"conflict"},
        .operation = "fs.copy",
        .client_timeout = 180s,
    });

    out.push_back({
        .command = "fs.changes.list",
        .description = "What changed in a vault since a revision (the change journal, #259), oldest first; for sync "
                       "clients instead of re-listing folders. Needs List on the vault root (storage.vault.accessible"
                       ".list's browse). Only changes to entries the caller can Lookup are returned: a rename or move "
                       "into view reads as create, out of view as delete. Without `since`: the current revision and "
                       "no changes, the anchor to take before enumerating. `expired`: the cursor can't be served "
                       "(retention, an authorization change that can change what the caller sees, or a revision this "
                       "server never handed out): enumerate the vault again and continue from `revision`.",
        .payload = {vaultId(),
                    uinteger("since").opt().nullable().gen(gen::intRange(0, 0))
                        .desc("The revision of the last fs.changes.list answer (or anchor)."),
                    uinteger("limit").opt().gen(gen::intRange(1, 1000))
                        .desc("Changes to read, 1..10000 (default 1000); fewer may be returned after filtering.")},
        .response = {uinteger("vault_id"),
                     uinteger("revision").desc("The cursor for the next call."),
                     objectArray("changes", "FsChange"),
                     boolean("more").desc("More changes follow `revision`: ask again at once."),
                     boolean("expired").desc("Enumerate again; `changes` is empty.")},
        .refusal_codes = {"unauthorized", "denied", "not_found", "invalid"},
        .client_timeout = 30s,
    });

    out.push_back({
        .command = "fs.changes.subscribe",
        .description = "Follow vaults' changes by push (#260): after changes to a followed vault commit, the session "
                       "gets an unsolicited frame {\"command\": \"fs.changed\", \"data\": {\"vault_id\", "
                       "\"revision\"}} (no requestId), coalesced per vault, and calls fs.changes.list from its "
                       "cursor. Accepted for vaults the caller can follow (fs.changes.list's rule), at most 256 per "
                       "session; a vault it can no longer follow is dropped with one last event carrying "
                       "\"subscribed\": false. Events wait while the session is slow to read, coalesced, never queued "
                       "without bound. Subscriptions end with the session.",
        .payload = {intArray("vault_ids").desc("Vault ids to follow (added to what the session follows).")},
        .response = {intArray("vault_ids").desc("Every vault the session follows now, ascending."),
                     objectArray("refused", "", {uinteger("vault_id"),
                                                 str("code").oneOf({"denied", "not_found", "limit"})})
                         .desc("Vaults not followed, and why.")},
        .refusal_codes = {"unauthorized", "denied", "invalid"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "fs.changes.unsubscribe",
        .description = "Stop following vaults by push (fs.changes.subscribe); without vault_ids, all of them.",
        .payload = {intArray("vault_ids").opt().nullable().desc("Absent or null: every vault.")},
        .response = {intArray("vault_ids").desc("What the session still follows.")},
        .refusal_codes = {"unauthorized", "invalid"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "fs.upload.start",
        .description = "Start a chunked ws upload (Write on the path). The console uploads over HTTP instead "
                       "(POST /upload/session); this is the native ws transfer.",
        .payload = {vaultId(), vaultPath("path"), uinteger("size").gen(gen::intRange(0, 65536))},
        .response = {str("upload_id")},
        .variants = {{.mode = "share",
                      .description = "In a share session: the share upload surface (target resolved inside the share).",
                      .payload = {vaultId().opt().nullable(),
                                  shareRelativePath(),
                                  str("filename").opt(),
                                  uinteger("size_bytes").opt(),
                                  uinteger("size").opt(),
                                  str("mime_type").opt().nullable(),
                                  str("duplicate_policy").opt().oneOf({"reject"})},
                      .response = {str("upload_id"), str("transfer_id"), str("path"), str("filename"),
                                   uinteger("size_bytes"), uinteger("chunk_size"), str("duplicate_policy")}}},
        .refusal_codes = fsWriteRefusals(),
        .operation = "fs.write",
        .client_timeout = 30s,
    });

    out.push_back({
        .command = "fs.upload.finish",
        .description = "Finish the session's active ws upload.",
        .payload = {vaultId(), vaultPath("path")},
        .response = {str("path")},
        .variants = {{.mode = "share",
                      .description = "In a share session.",
                      .payload = {str("upload_id").opt(), str("transfer_id").opt()},
                      .response = {str("upload_id"), boolean("complete"), object("entry", "ShareUploadedFile")}}},
        .refusal_codes = fsWriteRefusals(),
        .untyped_refusals = {"conflict"},
        .client_timeout = 180s,
    });

    out.push_back({
        .command = "fs.upload.cancel",
        .description = "Abort the session's active ws upload.",
        .payload = {},
        .response = {boolean("cancelled")},
        .variants = {{.mode = "share",
                      .description = "In a share session.",
                      .payload = {str("upload_id").opt(), str("transfer_id").opt()},
                      .response = {boolean("cancelled"), str("upload_id")}}},
        .refusal_codes = fsWriteRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // fs.download.* is the share download surface: a console session is refused (share mode required).
    out.push_back({
        .command = "fs.download.start",
        .description = "Share sessions only: start a chunked download of a file inside the share.",
        .auth = "share",
        .payload = {shareRelativePath(), vaultId().opt().nullable()},
        .response = {str("transfer_id"), str("filename"), str("path"), uinteger("size_bytes"),
                     str("mime_type").opt().nullable(), uinteger("chunk_size")},
        .refusal_codes = fsWriteRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "fs.download.chunk",
        .description = "Share sessions only: read the next chunk (base64).",
        .auth = "share",
        .payload = {fsTransferId(), uinteger("offset").gen(gen::intRange(0, 0)).desc("Byte offset; next_offset of the previous chunk."),
                    uinteger("length").opt()},
        .response = {str("transfer_id"), uinteger("offset"), uinteger("bytes"), str("data_base64"),
                     uinteger("next_offset"), boolean("complete")},
        .refusal_codes = fsWriteRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "fs.download.cancel",
        .description = "Share sessions only: drop a transfer.",
        .auth = "share",
        .payload = {fsTransferId()},
        .response = {boolean("cancelled"), str("transfer_id")},
        .refusal_codes = fsWriteRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
