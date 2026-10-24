#include "protocols/http/Router.hpp"

#include "auth/session/Manager.hpp"
#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "protocols/cookie.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/AccessHooks.hpp"
#include "protocols/http/handler/Handlers.hpp"
#include "protocols/http/upload/Content.hpp"
#include "protocols/http/upload/Coordinator.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "stats/model/CacheStats.hpp"
#include "identities/User.hpp"

#include <nlohmann/json.hpp>
#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace {

[[nodiscard]] bool containsText(const std::string& haystack, const std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

// The basename to offer, UTF-8 kept: control bytes and separators become '_', surrounding whitespace is trimmed.
// Leading dots stay (".env" downloads as ".env"; it used to become "env").
[[nodiscard]] std::string attachmentBasename(std::string value, const std::string& fallback) {
    value = std::filesystem::path(value).filename().string();

    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        if (c < 0x20 || c == 0x7f || c == '\\' || c == '/') out.push_back('_');
        else out.push_back(static_cast<char>(c));
    }

    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.front()))) out.erase(out.begin());
    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.back()))) out.pop_back();
    if (out.empty() || out == "." || out == "..") return fallback;
    return out;
}

// The quoted-string `filename=` fallback for clients without RFC 5987 support: printable ASCII only. Each non-ASCII
// UTF-8 sequence becomes one '_', and so do '"', '\' and ';'.
[[nodiscard]] std::string asciiAttachmentFilename(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (const unsigned char c : name) {
        if (c >= 0x80) {
            if ((c & 0xC0) != 0x80) out.push_back('_');  // a lead byte; continuation bytes add nothing
        } else if (c == '"' || c == '\\' || c == ';') {
            out.push_back('_');
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

// RFC 5987 ext-value: attr-char stays, every other byte is %XX.
[[nodiscard]] std::string rfc5987Encode(const std::string& value) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size() * 3);
    for (const unsigned char c : value) {
        const bool alnum = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        if (alnum || c == '!' || c == '#' || c == '$' || c == '&' || c == '+' || c == '-' || c == '.' ||
            c == '^' || c == '_' || c == '`' || c == '|' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

[[nodiscard]] boost::beast::http::status downloadErrorStatus(const std::exception& e) {
    const std::string message = e.what();
    if (containsText(message, "requires a user session") ||
        containsText(message, "requires a ready share session") ||
        containsText(message, "token") ||
        containsText(message, "Unauthorized"))
        return boost::beast::http::status::unauthorized;
    if (containsText(message, "denied") || containsText(message, "Permission"))
        return boost::beast::http::status::forbidden;
    if (containsText(message, "not found") || containsText(message, "missing") || containsText(message, "moved"))
        return boost::beast::http::status::not_found;
    if (containsText(message, "exceeds") || containsText(message, "limit"))
        return boost::beast::http::status::payload_too_large;
    return boost::beast::http::status::bad_request;
}

[[nodiscard]] nlohmann::json parseJsonBody(const vh::protocols::http::request& req) {
    if (req.body().empty()) return nlohmann::json::object();
    return nlohmann::json::parse(req.body());
}

[[nodiscard]] std::vector<std::string> splitRoutePath(std::string target) {
    const auto query = target.find('?');
    if (query != std::string::npos) target = target.substr(0, query);
    std::vector<std::string> parts;
    std::stringstream stream(target);
    std::string part;
    while (std::getline(stream, part, '/')) {
        if (!part.empty()) parts.push_back(part);
    }
    return parts;
}

}

namespace vh::protocols::http {

using namespace vh::protocols::http::model::preview;

namespace {
std::function<Response(request&&)>& routeOverride() {
    static std::function<Response(request&&)> handler;
    return handler;
}
}

void Router::setRouteOverrideForTesting(std::function<Response(request&&)> handler) {
    routeOverride() = std::move(handler);
}

Response Router::route(request&& req) {
    if (const auto& handler = routeOverride()) return handler(std::move(req));
    const std::string_view target(req.target().data(), req.target().size());

    if (target.starts_with("/upload/text")) return handler::saveText(std::move(req));
    if (target == "/upload/content" || target.starts_with("/upload/content?")) return upload::content::handle(std::move(req));
    if (target.starts_with("/upload")) return handleUpload(std::move(req));
    if (target.starts_with("/preview/batch")) return handlePreviewBatch(std::move(req));

    if (req.method() != verb::get && req.method() != verb::head)
        return makeErrorResponse(req, "Method not allowed", status::method_not_allowed);

    if (target.starts_with("/auth/session")) return handleAuthSession(std::move(req));
    if (target.starts_with("/preview/derived")) return handler::derived(std::move(req));
    if (target.starts_with("/preview")) return handlePreview(std::move(req));
    if (target.starts_with("/download/conflict")) return handler::conflictSide(std::move(req));
    if (target.starts_with("/download")) return handleDownload(std::move(req));

    return makeErrorResponse(req, "Not found", status::not_found);
}

Response Router::handlePreview(request&& req) { return handler::preview(std::move(req)); }
Response Router::handleDownload(request&& req) { return handler::content(std::move(req)); }
Response Router::handlePreviewBatch(request&& req) { return handler::previewBatch(std::move(req)); }

Response Router::handleAuthSession(request&& req) {
    if (vh::config::Registry::get().dev.enabled) return makeJsonResponse(req, nlohmann::json{{"ok", true}});

    try {
        const auto refresh = protocols::extractCookie(req, "refresh");
        if (refresh.empty()) {
            log::Registry::http()->warn("[Router] Refresh token not set");
            return makeErrorResponse(req, "Refresh token not set", status::bad_request);
        }
        const auto session = runtime::Deps::get().sessionManager->validateRawRefreshToken(refresh);

        // Could mint an access token here if we wanted to
        nlohmann::json j{
                    {"ok", true},
                    {"user_id", session->user->id},
                    // {"access_token", access.token},
                    // {"expires_in", access.expires_in}
                };

        return makeJsonResponse(req, j);
    } catch (const std::exception& e) {
        // The reason only: never the cookie value.
        log::Registry::http()->warn("[Router] Invalid refresh token: {}", e.what());
        return makeErrorResponse(req, std::string("Unauthorized: ") + e.what(), status::unauthorized);
    }
}

std::string Router::authenticateRequest(const request& req) {
    if (vh::config::Registry::get().dev.enabled) return "";
    try {
        const auto refresh_token = protocols::extractCookie(req, "refresh");
        runtime::Deps::get().sessionManager->validateRawRefreshToken(refresh_token);
        return "";
    } catch (const std::exception& e) {
        return e.what();
    }
}

void Router::setPreviewSessionResolverForTesting(PreviewSessionResolver resolver) {
    if (!resolver) throw std::invalid_argument("Preview session resolver is required");
    access::hooks::sessionResolver() = std::move(resolver);
    access::clearCachesForTesting();
}

void Router::resetPreviewSessionResolverForTesting() {
    access::hooks::resetSessionResolver();
    access::clearCachesForTesting();
}

void Router::setSharePreviewManagerFactoryForTesting(SharePreviewManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share preview manager factory is required");
    access::hooks::shareManager() = std::move(factory);
    access::clearCachesForTesting();
}

void Router::resetSharePreviewManagerFactoryForTesting() {
    access::hooks::resetShareManager();
    access::clearCachesForTesting();
}

void Router::setSharePreviewResolverFactoryForTesting(SharePreviewResolverFactory factory) {
    if (!factory) throw std::invalid_argument("Share preview resolver factory is required");
    access::hooks::shareResolver() = std::move(factory);
    access::clearCachesForTesting();
}

void Router::resetSharePreviewResolverFactoryForTesting() {
    access::hooks::resetShareResolver();
    access::clearCachesForTesting();
}

void Router::setPreviewEngineResolverForTesting(PreviewEngineResolver resolver) {
    if (!resolver) throw std::invalid_argument("Preview engine resolver is required");
    access::hooks::engineResolver() = std::move(resolver);
}

void Router::resetPreviewEngineResolverForTesting() { access::hooks::resetEngineResolver(); }

Response Router::handleUpload(request&& req) {
    const auto parts = splitRoutePath(std::string(req.target()));

    try {
        if (req.method() == verb::post && parts.size() == 2 && parts[0] == "upload" && parts[1] == "session") {
            auto response = upload::Coordinator::instance().createSession(req, parseJsonBody(req));
            return makeJsonResponse(req, response);
        }

        if (parts.size() >= 2 && parts[0] == "upload") {
            const auto uploadId = parts[1];
            if (req.method() == verb::post && parts.size() == 3 && parts[2] == "finish") {
                auto response = upload::Coordinator::instance().finishSession(req, uploadId);
                return makeJsonResponse(req, response);
            }

            if (req.method() == verb::delete_ && parts.size() == 2) {
                auto response = upload::Coordinator::instance().cancelSession(req, uploadId);
                return makeJsonResponse(req, response);
            }

            if (upload::Coordinator::isUploadFileRequest(req.method(), req.target()))
                return makeErrorResponse(req, "Upload file bodies must be streamed by the HTTP session", status::bad_request);
        }

        return makeErrorResponse(req, "Not found", status::not_found);
    } catch (const std::exception& e) {
        return makeErrorResponse(req, e.what(), downloadErrorStatus(e));
    }
}

Response Router::makeResponse(const request& req, std::vector<uint8_t>&& data,
                                         const std::string& mime_type, const bool cacheHit) {
    const auto size = data.size();
    const auto crc = static_cast<uint32_t>(crc32(0L, data.data(), static_cast<uInt>(data.size())));
    const auto etag = "\"" + std::to_string(size) + "-" + std::to_string(crc) + "\"";

    if (const auto it = req.find(field::if_none_match); it != req.end() && it->value() == etag) {
        string_response res{status::not_modified, req.version()};
        res.set(field::etag, etag);
        res.set(field::cache_control, "private, max-age=0, must-revalidate");
        res.keep_alive(req.keep_alive());
        return res;
    }

    vector_response res{
        std::piecewise_construct,
        std::make_tuple(std::move(data)),
        std::make_tuple(status::ok, req.version())
    };

    res.set(field::content_type, mime_type);
    res.set(field::etag, etag);
    res.set(field::cache_control, "private, max-age=0, must-revalidate");
    res.content_length(size);
    res.keep_alive(req.keep_alive());

    if (cacheHit) runtime::Deps::get().httpCacheStats->record_hit(size);

    return res;
}

Response Router::makeResponse(const request& req, file_body::value_type data,
                                         const std::string& mime_type, const bool cacheHit) {
    const auto size = data.size();

    file_response res{
        std::piecewise_construct,
        std::make_tuple(std::move(data)),
        std::make_tuple(status::ok, req.version())
    };

    res.set(field::content_type, mime_type);
    res.set(field::cache_control, "private, max-age=0, must-revalidate");
    res.content_length(size);
    res.keep_alive(req.keep_alive());

    if (cacheHit) runtime::Deps::get().httpCacheStats->record_hit(size);

    return res;
}

Response Router::makeJsonResponse(const request& req, const nlohmann::json& j) {
    string_response res{status::ok, req.version()};
    res.set(field::content_type, "application/json");
    res.body() = j.dump();
    res.prepare_payload();
    res.keep_alive(req.keep_alive());
    return res;
}

std::string Router::attachmentContentDisposition(const std::string& filename) {
    const auto name = attachmentBasename(filename, "download");
    return "attachment; filename=\"" + asciiAttachmentFilename(name) + "\"; filename*=UTF-8''" + rfc5987Encode(name);
}

Response Router::makeDownloadResponse(
    const request& req,
    std::vector<uint8_t>&& data,
    const std::string& mime_type,
    const std::string& filename
) {
    const auto size = data.size();

    vector_response res{
        std::piecewise_construct,
        std::make_tuple(std::move(data)),
        std::make_tuple(status::ok, req.version())
    };

    res.set(field::content_type, mime_type.empty() ? "application/octet-stream" : mime_type);
    res.set(field::content_disposition, attachmentContentDisposition(filename));
    res.set(field::cache_control, "no-store");
    res.content_length(size);
    res.keep_alive(req.keep_alive());
    return res;
}

Response Router::makeErrorResponse(const request& req,
                                              const std::string& msg,
                                              const status& status) {
    string_response res{status, req.version()};
    res.set(field::content_type, "text/plain");
    res.body() = msg;
    res.prepare_payload();
    return res;
}

}
