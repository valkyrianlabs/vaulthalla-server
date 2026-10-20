// ws book: share sessions: share.session.open, share.email.challenge.*, share.fs.*, share.download.*,
// share.preview.get, share.upload.* (core/src/protocols/ws/handler/share/{Sessions,Filesystem,Download,Preview,
// Upload}.cpp). These are the share page's compatibility surface: paths are vault-relative and "/" (or no path) means
// the share root. The native share-session forms of fs.* take share-relative paths (fs.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// Share manager and target resolver refusals are std::runtime_error / std::invalid_argument (no data.code):
// "Share ... denied: ...", "Share link is inactive", "Share filesystem target not found", "Invalid share session token".
std::vector<std::string> shareSessionUntypedRefusals() { return {"denied", "not_found", "invalid"}; }

// The router refuses these in a console (human) session with UNAUTHORIZED; sharing switched off by the operator is
// ops::Denied ("denied").
std::vector<std::string> shareSessionRefusals() { return {"unauthorized", "denied"}; }

WsField shareSessionCompatPath(std::string what) {
    return str("path").opt().nullable().desc("Vault-relative " + std::move(what) +
                                             " inside the share; absent, null, \"\" or \"/\" is the share root.");
}

WsField shareSessionVaultId() {
    return uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"})).desc("The share's vault (optional).");
}

WsField shareSessionPublicToken() {
    return str("public_token").gen(gen::ref("share", {"public_token"})).desc("The link's public token (from the URL).");
}

WsField shareSessionPublicLink() {
    return object("share", "SharePublicLink").desc("The link's public view (no management fields).");
}

WsField shareSessionTransferId() {
    return str("transfer_id").gen(gen::ref("transfer", {"id"}, "own")).desc("From share.download.start.");
}

WsField shareSessionUploadId(std::string name) {
    return str(std::move(name)).opt().desc("The upload (upload_id and transfer_id are the same id); defaults to the "
                                           "socket's active share upload.");
}

}

std::vector<WsCommandUsage> shareSessionCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    // ---- session bootstrap (public: a socket without a signed-in user) ----
    out.push_back({
        .command = "share.session.open",
        .description = "Open a share session from a public link token. A public link is ready at once (the socket "
                       "switches to share mode); an email-validated link answers email_required with a pending "
                       "session to verify through share.email.challenge.*. Reopening the socket's own ready share "
                       "returns its session.",
        .auth = "public",
        .payload = {shareSessionPublicToken()},
        .response = {str("status").oneOf({"ready", "email_required"}),
                     shareSessionPublicLink().desc("The link's public view; effective_allowed_ops only when ready."),
                     str("session_id"),
                     str("session_token").desc("The share session token (keep it to resume the session).")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.email.challenge.start",
        .description = "Email-validated links: send a one-time code to a recipient email. Identifies the link by "
                       "public_token (opens a pending session) or by session_token (the socket's pending session "
                       "when neither is given). Refused once the session is verified.",
        .auth = "public",
        .payload = {str("email").gen(gen::email()),
                    str("public_token").opt().nullable(),
                    str("session_token").opt().nullable()},
        .response = {str("status").oneOf({"challenge_created"}),
                     shareSessionPublicLink(),
                     str("challenge_id"),
                     str("session_id"),
                     str("session_token").opt().desc("Present when this call opened the session (public_token).")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.email.challenge.confirm",
        .description = "Confirm an email code. When verified the socket switches to share mode (status ready); "
                       "session_id and session_token default to the socket's pending session.",
        .auth = "public",
        .payload = {str("challenge_id").gen(gen::ref("share_challenge", {"id"}, "own")),
                    str("code").gen(gen::pattern("{9}{9}{9}{9}{9}{9}")).desc("The six-digit code from the email."),
                    str("session_id").opt().nullable(),
                    str("session_token").opt().nullable()},
        .response = {str("status").oneOf({"ready", "email_required"}), boolean("verified"), str("session_id")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- reading (share mode) ----
    out.push_back({
        .command = "share.fs.metadata",
        .description = "Share sessions: one entry inside the share, reduced to the share view (Metadata).",
        .auth = "share",
        .payload = {shareSessionCompatPath("path"), shareSessionVaultId()},
        .response = {object("entry", "ShareEntry")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.fs.list",
        .description = "Share sessions: list a directory inside the share (List); entries in the share view.",
        .auth = "share",
        .payload = {shareSessionCompatPath("directory"), shareSessionVaultId()},
        .response = {str("path").desc("Share-relative path of the listed directory."),
                     objectArray("entries", "ShareEntry")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = 30s,
    });

    // ---- downloads (share mode; the bytes are held in memory, at most 64 MiB) ----
    out.push_back({
        .command = "share.download.start",
        .description = "Share sessions: start a chunked download of a file inside the share (Download). At most 4 "
                       "transfers per socket and 64 MiB per file.",
        .auth = "share",
        .payload = {shareSessionCompatPath("file path"), shareSessionVaultId()},
        .response = {str("transfer_id"), str("filename"), str("path").desc("Share-relative path."),
                     uinteger("size_bytes"), str("mime_type").nullable(),
                     uinteger("chunk_size").desc("Suggested chunk length (64 KiB).")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.download.chunk",
        .description = "Share sessions: read the next chunk (base64). offset must be the previous next_offset; the "
                       "target is re-authorized on every chunk and the transfer is dropped on any failure.",
        .auth = "share",
        .payload = {shareSessionTransferId(),
                    uinteger("offset").gen(gen::intRange(0, 0)).desc("Byte offset; next_offset of the previous chunk."),
                    uinteger("length").opt().min(1).desc("Defaults to 64 KiB; at most 256 KiB.")},
        .response = {str("transfer_id"), uinteger("offset"), uinteger("bytes"), str("data_base64"),
                     uinteger("next_offset"), boolean("complete")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "share.download.cancel",
        .description = "Share sessions: drop a download transfer.",
        .auth = "share",
        .payload = {shareSessionTransferId()},
        .response = {boolean("cancelled"), str("transfer_id")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- preview (share mode) ----
    out.push_back({
        .command = "share.preview.get",
        .description = "Share sessions: a JPEG preview of an image or PDF inside the share (Preview), base64. Sources "
                       "over 16 MiB and remote-only bytes are refused; the console uses GET /preview?share=1.",
        .auth = "share",
        .payload = {shareSessionCompatPath("file path"),
                    uinteger("size").opt().min(1).desc("Longest edge in pixels; default 1024, capped at 2048.")},
        .response = {str("path").desc("Share-relative path."), str("filename"), str("source_mime_type"),
                     str("mime_type").oneOf({"image/jpeg"}), uinteger("size_bytes"), str("data_base64")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = 30s,
    });

    // ---- uploads (share mode; bytes follow as binary websocket frames) ----
    out.push_back({
        .command = "share.upload.start",
        .description = "Share sessions: start an upload of a new file into a directory of the share (Upload). The "
                       "bytes follow as binary frames; an existing target is refused (duplicate policy reject).",
        .auth = "share",
        .payload = {shareSessionCompatPath("parent directory"),
                    str("filename").gen(gen::pattern("upload_{a}{a}{a}{9}.txt")).desc("Basename only."),
                    uinteger("size_bytes").opt().desc("Expected size; size_bytes or size is required."),
                    uinteger("size").opt().desc("Alias of size_bytes."),
                    str("mime_type").opt().nullable(),
                    str("duplicate_policy").opt().nullable().oneOf({"reject"}),
                    shareSessionVaultId()},
        .response = {str("upload_id"), str("transfer_id").desc("The same id as upload_id."),
                     str("path").desc("Share-relative path of the new file."), str("filename"),
                     uinteger("size_bytes"), uinteger("chunk_size").desc("Largest binary frame accepted."),
                     str("duplicate_policy").oneOf({"reject"})},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = {"denied", "not_found", "invalid", "conflict"},
        .client_timeout = 30s,
    });

    out.push_back({
        .command = "share.upload.finish",
        .description = "Share sessions: finish an upload after its last binary frame; the target is re-authorized "
                       "and the file created.",
        .auth = "share",
        .payload = {shareSessionUploadId("upload_id"), shareSessionUploadId("transfer_id")},
        .response = {str("upload_id"), boolean("complete"), object("entry", "ShareUploadedFile")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = {"denied", "not_found", "invalid", "conflict"},
        .client_timeout = 180s,
    });

    out.push_back({
        .command = "share.upload.cancel",
        .description = "Share sessions: abort an upload.",
        .auth = "share",
        .payload = {shareSessionUploadId("upload_id"), shareSessionUploadId("transfer_id")},
        .response = {boolean("cancelled"), str("upload_id")},
        .refusal_codes = shareSessionRefusals(),
        .untyped_refusals = shareSessionUntypedRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
