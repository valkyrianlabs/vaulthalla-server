#include "protocols/http/handler/Common.hpp"

#include "log/Registry.hpp"
#include "mirror/Contents.hpp"
#include "preview/render/Raster.hpp"
#include "preview/render/Service.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/Range.hpp"
#include "storage/PlaintextReader.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>

namespace vh::protocols::http::handler {

namespace {
constexpr uint64_t kInlineRangeCap = 16ull * 1024 * 1024;

[[nodiscard]] std::string_view headerValue(const request& req, const field f) {
    const auto it = req.find(f);
    return it == req.end() ? std::string_view{} : std::string_view(it->value().data(), it->value().size());
}

[[nodiscard]] std::string trimmed(std::string_view v) {
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
    return std::string(v);
}

[[nodiscard]] std::string weakless(std::string tag) {
    if (tag.starts_with("W/")) tag.erase(0, 2);
    return tag;
}
}

model::preview::Response jsonError(const request& req, const status code, const std::string_view errorCode,
                                   const std::string_view message) {
    string_response res{code, req.version()};
    res.set(field::content_type, "application/json");
    res.set(field::cache_control, "no-store");
    res.body() = nlohmann::json{{"error", message}, {"code", errorCode}}.dump();
    res.prepare_payload();
    res.keep_alive(req.keep_alive());
    return res;
}

model::preview::Response errorFor(const request& req, const std::exception& e) {
    if (dynamic_cast<const access::Unauthorized*>(&e)) return jsonError(req, status::unauthorized, "unauthorized", e.what());
    if (dynamic_cast<const access::Forbidden*>(&e)) return jsonError(req, status::forbidden, "denied", e.what());
    if (dynamic_cast<const access::NotFound*>(&e)) return jsonError(req, status::not_found, "not_found", "Not found");
    if (dynamic_cast<const access::BadRequest*>(&e)) return jsonError(req, status::bad_request, "invalid", e.what());
    if (dynamic_cast<const storage::ContentUnavailable*>(&e)) {
        // A mirror's file that has not arrived from its core (design/peers/mirror.md "Contents") says why.
        const auto mirrorCode = ::vh::mirror::contents::reasonCodeIn(e.what());
        auto res = jsonError(req, status::service_unavailable, mirrorCode ? *mirrorCode : "content_unavailable",
                             e.what());
        std::get<string_response>(res).set(field::retry_after, "30");
        return res;
    }
    if (dynamic_cast<const storage::IntegrityError*>(&e)) {
        log::Registry::http()->error("[HttpHandler] Integrity failure serving {}: {}", std::string(req.target()), e.what());
        return jsonError(req, status::internal_server_error, "integrity_failed",
                         "The stored content failed its integrity check");
    }
    if (dynamic_cast<const preview::render::Busy*>(&e)) {
        auto res = jsonError(req, status::service_unavailable, "busy", "Preview rendering is busy; retry shortly");
        std::get<string_response>(res).set(field::retry_after, "2");
        return res;
    }
    if (dynamic_cast<const preview::render::LimitExceeded*>(&e) || dynamic_cast<const std::length_error*>(&e))
        return jsonError(req, status::payload_too_large, "limit_exceeded", e.what());
    if (dynamic_cast<const preview::render::InvalidInput*>(&e))
        return jsonError(req, status::unprocessable_entity, "invalid_input", e.what());

    log::Registry::http()->error("[HttpHandler] {} {} failed: {}", std::string(req.method_string()),
                                 std::string(req.target()), e.what());
    return jsonError(req, status::internal_server_error, "internal", "Internal error");
}

std::string httpDate(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::array<char, 64> buf{};
    const auto n = std::strftime(buf.data(), buf.size(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return {buf.data(), n};
}

bool noneMatchHits(const std::string_view header, const std::string& etag) {
    if (header.empty()) return false;
    if (trimmed(header) == "*") return true;
    std::string_view rest = header;
    while (!rest.empty()) {
        const auto comma = rest.find(',');
        if (weakless(trimmed(rest.substr(0, comma))) == weakless(etag)) return true;
        if (comma == std::string_view::npos) break;
        rest.remove_prefix(comma + 1);
    }
    return false;
}

std::string contentDisposition(const bool inlineDisposition, const std::string& filename) {
    auto value = Router::attachmentContentDisposition(filename);  // "attachment; filename=…; filename*=…"
    if (inlineDisposition) value.replace(0, std::string_view("attachment").size(), "inline");
    return value;
}

std::string safeContentType(const std::string& mime, const bool inlineDisposition) {
    if (mime.empty()) return "application/octet-stream";
    if (!inlineDisposition) return mime;
    if ((mime.starts_with("image/") && mime != "image/svg+xml") || mime.starts_with("video/") ||
        mime.starts_with("audio/"))
        return mime;
    if (mime == "image/svg+xml") return mime;  // rendered by <img>; the CSP below neuters it as a document
    return "application/octet-stream";
}

void addOriginalBytesHardening(ServeSpec& spec) {
    spec.extraHeaders.emplace_back("X-Content-Type-Options", "nosniff");
    spec.extraHeaders.emplace_back(
        "Content-Security-Policy",
        "sandbox; default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'unsafe-inline'");
    spec.extraHeaders.emplace_back("Cross-Origin-Resource-Policy", "same-origin");
}

model::preview::Response serve(const request& req, ServeSpec spec) {
    const bool head = req.method() == verb::head;

    model::preview::StreamResponse res;
    res.version(req.version());
    res.keep_alive(req.keep_alive());
    res.set(field::accept_ranges, "bytes");
    res.set(field::etag, spec.etag);
    if (spec.lastModified > 0) res.set(field::last_modified, httpDate(spec.lastModified));
    res.set(field::cache_control, spec.cacheControl);
    res.set("X-Accel-Buffering", "no");  // never let nginx spool decrypted bytes to its temp files
    for (const auto& [name, value] : spec.extraHeaders) res.set(name, value);
    res.onFinish = std::move(spec.onFinish);

    if (noneMatchHits(headerValue(req, field::if_none_match), spec.etag)) {
        res.result(status::not_modified);
        res.headOnly = true;
        return res;
    }

    res.set(field::content_type, spec.contentType);
    if (!spec.contentDisposition.empty()) res.set(field::content_disposition, spec.contentDisposition);

    uint64_t offset = 0;
    uint64_t length = spec.size;
    bool partial = false;

    if (const auto rangeHeader = headerValue(req, field::range); !rangeHeader.empty()) {
        bool honour = true;
        if (const auto ifRange = trimmed(headerValue(req, field::if_range)); !ifRange.empty()) {
            // Strong ETag comparison only. An HTTP-date validator has one-second resolution, so two writes within a
            // second could splice ranges of different contents: such requests get the full representation.
            honour = ifRange.starts_with("\"") && ifRange == spec.etag;
        }
        const auto parsed = range::parse(rangeHeader);
        if (honour && parsed.spec) {
            const auto resolved = range::resolve(*parsed.spec, spec.size);
            if (!resolved) {
                res.result(status::range_not_satisfiable);
                res.set(field::content_range, range::unsatisfiedContentRange(spec.size));
                res.erase(field::content_disposition);
                res.length = 0;
                return res;
            }
            offset = resolved->first;
            length = resolved->length();
            if (spec.capOpenEndedRanges && !parsed.spec->last && parsed.spec->first)
                length = std::min(length, kInlineRangeCap);
            partial = true;
            res.set(field::content_range, range::contentRange({offset, offset + length - 1}, spec.size));
        }
        // Multi-range and malformed headers are ignored (RFC 9110): the full representation follows.
    }

    res.result(partial ? status::partial_content : status::ok);
    res.offset = offset;
    res.length = length;
    res.headOnly = head;

    if (!head) {
        if (spec.admit && !spec.admit(offset == 0))
            return jsonError(req, status::forbidden, "max_downloads_reached", "This link's download limit was reached");
        if (length > 0) {
            res.reader = spec.open ? spec.open() : nullptr;
            if (!res.reader) throw std::runtime_error("No content reader");
        }
    }
    return res;
}

}
