#include "protocols/http/handler/Handlers.hpp"

#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "preview/Plan.hpp"
#include "preview/render/Service.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/handler/Common.hpp"
#include "storage/Engine.hpp"
#include "storage/PlaintextReader.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <filesystem>
#include <limits>
#include <unordered_map>
#include <vector>

namespace vh::protocols::http::handler {

namespace {

[[nodiscard]] uint32_t uintParam(const access::Params& params, const std::string& name, const uint32_t fallback) {
    const auto it = params.find(name);
    if (it == params.end() || it->second.empty()) return fallback;
    uint32_t value = 0;
    const auto& raw = it->second;
    // Accept decimals for the legacy `scale`-style callers by truncating; reject garbage.
    const auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), value);
    if (ec == std::errc::result_out_of_range) return std::numeric_limits<uint32_t>::max();
    if (ec != std::errc{} || ptr == raw.data()) throw access::BadRequest("Invalid numeric parameter: " + name);
    return value;
}

[[nodiscard]] std::string percentEncode(const std::string& value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4u]);
            out.push_back(hex[c & 0x0fu]);
        }
    }
    return out;
}

[[nodiscard]] std::string previewUrl(const bool share, const uint32_t vaultId, const std::string& path, const uint32_t size) {
    std::string url = "/preview?";
    if (share) url += "share=1&path=" + percentEncode(path);
    else url += "vault_id=" + std::to_string(vaultId) + "&path=" + percentEncode(path);
    return url + "&size=" + std::to_string(size);
}

[[nodiscard]] uint32_t batchSize(const nlohmann::json& body) {
    uint32_t requested = 128;
    if (body.contains("size") && body.at("size").is_number_unsigned()) requested = body.at("size").get<uint32_t>();
    auto sizes = config::Registry::get().caching.thumbnails.sizes;
    if (sizes.empty()) return preview::render::normalizeSize(requested);
    // The configured thumbnail size closest to the request (ties go up).
    std::ranges::sort(sizes);
    auto best = sizes.front();
    for (const auto candidate : sizes) {
        const auto d = candidate > requested ? candidate - requested : requested - candidate;
        const auto bd = best > requested ? best - requested : requested - best;
        if (d < bd || (d == bd && candidate > best)) best = candidate;
    }
    return best;
}

}

model::preview::Response preview(request&& req) {
    try {
        const auto params = access::parseQuery(std::string(req.target()));
        const auto caller = access::authenticate(req, params);
        const auto target = access::resolve(caller, params, access::Need::Preview, access::Expect::File);
        const auto plan = preview::classify(*target.file);
        if (plan.kind != preview::PreviewKind::RenderedImage)
            return jsonError(req, status::unsupported_media_type, "unsupported",
                             "No server render for this file type; original bytes require download access");

        // `scale` (legacy) is accepted but ignored: output is always fit into `size`.
        const preview::render::Request request{
            .size = preview::render::normalizeSize(uintParam(params, "size", 1024)),
            .page = uintParam(params, "page", 0)
        };
        const auto generation = storage::generationOf(*target.file);
        auto etag = generation.etag();
        etag.insert(etag.size() - 1, "-p" + std::to_string(request.page) + "-s" + std::to_string(request.size));

        if (const auto it = req.find(field::if_none_match); it != req.end() &&
                                                           noneMatchHits({it->value().data(), it->value().size()}, etag)) {
            string_response res{status::not_modified, req.version()};
            res.set(field::etag, etag);
            res.set(field::cache_control, "private, max-age=0, must-revalidate");
            res.keep_alive(req.keep_alive());
            return res;
        }

        auto result = preview::render::render(target.engine, target.file, request);
        if (target.share) (void)access::recordShareAccess(target, "share.preview.http", false, std::nullopt);
        else access::recordHumanAccess(caller, target, "preview");

        const auto size = result.jpeg.size();
        vector_response res{std::piecewise_construct, std::make_tuple(std::move(result.jpeg)),
                            std::make_tuple(status::ok, req.version())};
        res.set(field::content_type, "image/jpeg");
        res.set(field::etag, etag);
        res.set(field::cache_control, "private, max-age=0, must-revalidate");
        res.set("X-Content-Type-Options", "nosniff");
        res.set("X-Accel-Buffering", "no");  // a decrypted render must not land in nginx temp files either
        if (result.pageCount) res.set("X-Vaulthalla-Page-Count", std::to_string(*result.pageCount));
        res.set("X-Vaulthalla-Cache", result.cacheHit ? "hit" : "miss");
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return res;
    } catch (const std::exception& e) {
        return errorFor(req, e);
    }
}

model::preview::Response previewBatch(request&& req) {
    try {
        if (req.method() != verb::post) return jsonError(req, status::method_not_allowed, "invalid", "POST required");
        const auto params = access::parseQuery(std::string(req.target()));
        const auto caller = access::authenticate(req, params);
        const auto body = req.body().empty() ? nlohmann::json::object() : nlohmann::json::parse(req.body());
        if (!body.contains("items") || !body.at("items").is_array())
            throw access::BadRequest("Preview batch requires items array");
        if (body.at("items").size() > 200) throw access::BadRequest("Preview batch is limited to 200 items");
        const auto size = batchSize(body);
        const std::optional<uint32_t> defaultVault = body.contains("vault_id") && body.at("vault_id").is_number_unsigned()
                                                         ? std::make_optional(body.at("vault_id").get<uint32_t>())
                                                         : std::nullopt;

        // Resolve and authorize every item first, then ask the index about all of them at once (per engine): a
        // status check opens and decrypts nothing, and never counts as a cache hit or miss.
        nlohmann::json items = nlohmann::json::array();
        struct Pending {
            std::size_t item;
            std::string path;
            access::Target target;
        };
        std::vector<Pending> pending;
        for (const auto& item : body.at("items")) {
            nlohmann::json out{{"size", size}};
            if (item.contains("key")) out["key"] = item.at("key");
            try {
                const auto path = item.at("path").get<std::string>();
                out["path"] = path;
                access::Params itemParams{{"path", path}};
                if (caller.share) itemParams["share"] = "1";
                else {
                    const auto vaultId = item.contains("vault_id") && item.at("vault_id").is_number_unsigned()
                                             ? item.at("vault_id").get<uint32_t>()
                                             : defaultVault.value_or(0);
                    out["vault_id"] = vaultId;
                    itemParams["vault_id"] = std::to_string(vaultId);
                }
                auto target = access::resolve(caller, itemParams, access::Need::Preview, access::Expect::File);
                if (!preview::classify(*target.file).thumbnail) out["status"] = "unsupported";
                else pending.push_back({items.size(), path, std::move(target)});
            } catch (const access::NotFound&) {
                out["status"] = "missing";
            } catch (const access::Forbidden&) {
                out["status"] = "unsupported";
            } catch (const std::exception& e) {
                out["status"] = "error";
                out["error"] = dynamic_cast<const access::BadRequest*>(&e) ? e.what() : "unavailable";
            }
            items.push_back(std::move(out));
        }

        std::unordered_map<const storage::Engine*, std::vector<std::size_t>> byEngine;
        for (std::size_t i = 0; i < pending.size(); ++i) byEngine[pending[i].target.engine.get()].push_back(i);
        for (const auto& [_, indexes] : byEngine) {
            std::vector<std::shared_ptr<fs::model::File>> files;
            files.reserve(indexes.size());
            for (const auto i : indexes) files.push_back(pending[i].target.file);
            std::vector<preview::render::ThumbnailState> states(indexes.size(), preview::render::ThumbnailState::Missing);
            try {
                states = preview::render::thumbnailStates(pending[indexes.front()].target.engine, files, size);
            } catch (const std::exception& e) {
                log::Registry::http()->debug("[Preview] Thumbnail status unavailable: {}", e.what());
            }
            for (std::size_t n = 0; n < indexes.size(); ++n) {
                const auto& p = pending[indexes[n]];
                auto& out = items[p.item];
                switch (states[n]) {
                    case preview::render::ThumbnailState::Ready:
                        out["status"] = "ready";
                        out["url"] = previewUrl(caller.share, p.target.vaultId, p.path, size);
                        break;
                    case preview::render::ThumbnailState::Failed:
                        out["status"] = "failed";   // invalid or over a limit: asking again won't help
                        break;
                    case preview::render::ThumbnailState::Missing:
                        if (std::error_code ec; p.target.file->size_bytes > 0 &&
                                                !std::filesystem::exists(p.target.file->backing_path, ec)) {
                            out["status"] = "missing";  // remote-only: grid thumbnails never trigger a fetch
                        } else {
                            preview::render::enqueueThumbnails(p.target.engine, p.target.file);
                            out["status"] = "queued";
                        }
                        break;
                }
            }
        }
        return Router::makeJsonResponse(req, {{"items", std::move(items)}, {"size", size}});
    } catch (const nlohmann::json::exception& e) {
        return jsonError(req, status::bad_request, "invalid", e.what());
    } catch (const std::exception& e) {
        return errorFor(req, e);
    }
}

}
