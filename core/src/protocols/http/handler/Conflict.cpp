#include "protocols/http/handler/Handlers.hpp"

#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Conflicts.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/handler/Common.hpp"
#include "protocols/ws/Session.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/ConflictResolver.hpp"

#include <nlohmann/json.hpp>

#include <charconv>

namespace vh::protocols::http::handler {

namespace {

[[nodiscard]] uint32_t conflictIdParam(const access::Params& params) {
    const auto it = params.find("conflict_id");
    if (it == params.end() || it->second.empty()) throw access::BadRequest("Missing required parameter: conflict_id");
    uint32_t value = 0;
    const auto& raw = it->second;
    const auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), value);
    if (ec != std::errc{} || ptr != raw.data() + raw.size()) throw access::BadRequest("Invalid parameter: conflict_id");
    return value;
}

[[nodiscard]] bool remoteSide(const access::Params& params) {
    const auto it = params.find("side");
    if (it == params.end() || it->second == "local") return false;
    if (it->second == "remote") return true;
    throw access::BadRequest("side must be local or remote");
}

void harden(string_response& res, const std::string& mime, const std::string& name, const char* side) {
    res.set(field::content_type, safeContentType(mime, true));
    res.set(field::content_disposition, contentDisposition(true, name.empty() ? "conflict" : name));
    res.set(field::cache_control, "no-store");
    res.set("X-Accel-Buffering", "no");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Content-Security-Policy",
            "sandbox; default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'unsafe-inline'");
    res.set("Cross-Origin-Resource-Policy", "same-origin");
    res.set("X-Vaulthalla-Conflict-Side", side);
}

[[nodiscard]] model::preview::Response tooLarge(const request& req, const uint64_t limit) {
    auto res = jsonError(req, status::payload_too_large, "too_large", "The remote copy is too large to preview");
    std::get<string_response>(res).set("X-Vaulthalla-Limit-Bytes", std::to_string(limit));
    return res;
}

[[nodiscard]] model::preview::Response remote(const request& req, const ops::conflicts::PreviewTarget& t) {
    const auto& recorded = t.record.remote;
    const auto mime = recorded.mime_type.value_or(t.file->mime_type.value_or("application/octet-stream"));
    if (recorded.size_bytes > kConflictPreviewMaxBytes + 16) return tooLarge(req, kConflictPreviewMaxBytes);

    string_response res{status::ok, req.version()};
    res.keep_alive(req.keep_alive());
    harden(res, mime, t.record.name, "remote");
    if (req.method() == verb::head) {
        // Answered from the recorded artifact: a HEAD never contacts the bucket.
        res.content_length(recorded.size_bytes);
        return res;
    }

    std::vector<uint8_t> bytes;
    try {
        bytes = sync::ConflictResolver::fetchRemoteForPreview(t.engine, t.record, kConflictPreviewMaxBytes);
    } catch (const sync::ConflictResolver::ContentTooLarge& e) {
        return tooLarge(req, e.limit);
    } catch (const sync::ConflictStale& e) {
        return jsonError(req, status::conflict, "conflict_changed", e.what());
    } catch (const storage::s3::RequestBudgetExceeded& e) {
        throw storage::ContentUnavailable(e.what());
    } catch (const storage::s3::ObjectNotFound&) {
        return jsonError(req, status::conflict, "conflict_changed", "The remote object no longer exists");
    }
    res.body().assign(bytes.begin(), bytes.end());
    res.prepare_payload();
    return res;
}

[[nodiscard]] model::preview::Response local(const request& req, const ops::conflicts::PreviewTarget& t) {
    const auto file = std::make_shared<fs::model::File>(*t.file);
    const auto generation = storage::generationOf(*file);
    ServeSpec spec;
    spec.size = file->size_bytes;
    spec.etag = generation.etag();
    spec.lastModified = file->updated_at;
    spec.contentType = safeContentType(file->mime_type.value_or("application/octet-stream"), true);
    spec.contentDisposition = contentDisposition(true, file->name.empty() ? "conflict" : file->name);
    spec.cacheControl = "private, max-age=0, must-revalidate, no-transform";
    spec.capOpenEndedRanges = true;
    spec.extraHeaders.emplace_back("X-Vaulthalla-Conflict-Side", "local");
    addOriginalBytesHardening(spec);
    // The local side is what is on this host; it never fetches from the bucket (that would be the other side).
    spec.open = [engine = t.engine, file]() -> std::shared_ptr<storage::PlaintextReader> {
        return engine->openPlaintextReader(file, storage::ReaderOptions{.remote = storage::RemoteFetchPolicy::Off});
    };
    return serve(req, std::move(spec));
}

}

model::preview::Response conflictSide(request&& req) {
    try {
        const auto target = std::string(req.target());
        const auto params = access::parseQuery(target);
        const auto caller = access::authenticate(req, params);
        if (caller.share) throw access::Forbidden("Sync conflicts are not available through share links");
        const auto id = conflictIdParam(params);
        const bool wantsRemote = remoteSide(params);

        ops::conflicts::PreviewTarget t;
        try {
            t = ops::conflicts::previewTarget(caller.session->user, id);
        } catch (const ops::Denied& e) {
            throw access::Forbidden(e.what());
        } catch (const ops::NotFound&) {
            throw access::NotFound("Not found");
        } catch (const ops::Conflict& e) {
            return jsonError(req, status::conflict, "conflict_closed", e.what());
        }
        if (req.method() == verb::get)
            log::Registry::audit()->info("[http] {} previewed the {} side of sync conflict {} ('{}', vault {})",
                                         caller.session->user->name(), wantsRemote ? "remote" : "local", id,
                                         t.record.path, t.record.vault_id);
        return wantsRemote ? remote(req, t) : local(req, t);
    } catch (const std::exception& e) {
        return errorFor(req, e);
    }
}

}
