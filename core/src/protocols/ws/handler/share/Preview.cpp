#include "protocols/ws/handler/share/Preview.hpp"

#include "fs/model/File.hpp"
#include "preview/image.hpp"
#include "preview/pdf.hpp"
#include "preview/render/Service.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/TargetResolver.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"

#include <algorithm>
#include <cstring>
#include <optional>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vh::protocols::ws::handler::share {
namespace share_preview_handler_detail {
constexpr uint64_t kMaxPreviewInputBytes = 16u * 1024u * 1024u;
constexpr unsigned kDefaultPreviewSize = 1024;
constexpr unsigned kMaxPreviewSize = 2048;

class DefaultPreviewReader final : public PreviewReader {
public:
    explicit DefaultPreviewReader(SharePreviewEngineResolver resolver) : resolver_(std::move(resolver)) {}

    std::vector<uint8_t> readFile(const vh::share::ResolvedTarget& target) const override {
        if (!target.entry || target.target_type != vh::share::TargetType::File)
            throw std::runtime_error("Share preview target is not a file");

        auto file = std::dynamic_pointer_cast<vh::fs::model::File>(target.entry);
        if (!file) throw std::runtime_error("Share preview target file is unavailable");
        if (file->size_bytes == 0) return {};
        if (file->size_bytes > kMaxPreviewInputBytes)
            throw std::runtime_error("Share preview source exceeds maximum render size");

        const auto engine = resolver_ ? resolver_(target.vault_id)
                                      : runtime::Deps::get().storageManager->getEngine(target.vault_id);
        if (!engine) throw std::runtime_error("Share preview storage engine is unavailable");

        // The local ciphertext copy when there is one; a remote-only file follows preview.media.remote.
        const auto reader = engine->openPlaintextReader(file);
        try {
            return vh::storage::readAll(*reader, kMaxPreviewInputBytes);
        } catch (const std::length_error&) {
            throw std::runtime_error("Share preview source exceeds maximum render size");
        }
    }

private:
    SharePreviewEngineResolver resolver_;
};

[[nodiscard]] std::shared_ptr<vh::share::Manager> defaultManager() {
    return std::make_shared<vh::share::Manager>();
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> defaultResolver() {
    return std::make_shared<vh::share::TargetResolver>();
}

[[nodiscard]] std::shared_ptr<PreviewReader> defaultReader() {
    return std::make_shared<DefaultPreviewReader>(SharePreviewEngineResolver{});
}

[[nodiscard]] Preview::ManagerFactory& managerFactory() {
    static Preview::ManagerFactory factory = defaultManager;
    return factory;
}

[[nodiscard]] Preview::ResolverFactory& resolverFactory() {
    static Preview::ResolverFactory factory = defaultResolver;
    return factory;
}

[[nodiscard]] Preview::ReaderFactory& readerFactory() {
    static Preview::ReaderFactory factory = defaultReader;
    return factory;
}

// Tests inject a reader; production renders through preview::render (gated, cached, encrypted).
[[nodiscard]] bool& readerOverridden() {
    static bool overridden = false;
    return overridden;
}

[[nodiscard]] std::shared_ptr<vh::share::Manager> manager() {
    auto instance = managerFactory()();
    if (!instance) throw std::runtime_error("Share manager is unavailable");
    return instance;
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> resolver() {
    auto instance = resolverFactory()();
    if (!instance) throw std::runtime_error("Share target resolver is unavailable");
    return instance;
}

[[nodiscard]] std::shared_ptr<PreviewReader> reader() {
    auto instance = readerFactory()();
    if (!instance) throw std::runtime_error("Share preview reader is unavailable");
    return instance;
}

[[nodiscard]] const json& objectPayload(const json& payload) {
    if (!payload.is_object()) throw std::invalid_argument("Share preview payload must be an object");
    return payload;
}

void requireShareMode(const std::shared_ptr<Session>& session) {
    if (!session) throw std::runtime_error("Share preview commands require websocket session");
    if (session->user) throw std::runtime_error("Share preview commands require share mode");
    if (!session->isShareMode()) throw std::runtime_error("Share preview commands require verified share mode");
    if (session->shareSessionToken().empty()) throw std::runtime_error("Share session token is missing");
}

[[nodiscard]] std::shared_ptr<vh::share::Principal> refreshPrincipal(
    const std::shared_ptr<Session>& session,
    vh::share::Manager& manager
) {
    auto principal = manager.resolvePrincipal(
        session->shareSessionToken(),
        session->ipAddress.empty() ? std::nullopt : std::make_optional(session->ipAddress),
        session->userAgent.empty() ? std::nullopt : std::make_optional(session->userAgent)
    );
    session->setSharePrincipal(principal, session->shareSessionToken());
    return principal;
}

[[nodiscard]] std::string requestedPath(const json& payload, const vh::share::Principal& principal) {
    if (!payload.contains("path") || payload.at("path").is_null()) return principal.root_path;
    auto path = payload.at("path").get<std::string>();
    if (path == "/") return principal.root_path;
    return path;
}

[[nodiscard]] unsigned previewSize(const json& payload) {
    const auto requested = payload.value("size", kDefaultPreviewSize);
    if (requested == 0) throw std::invalid_argument("Share preview size is required");
    return std::min<unsigned>(requested, kMaxPreviewSize);
}

[[nodiscard]] bool supportedMime(const std::string& mime) {
    return mime.starts_with("image/") || mime == "application/pdf";
}

[[nodiscard]] std::vector<uint8_t> renderPreview(
    const std::vector<uint8_t>& input,
    const std::string& sourceMime,
    const unsigned size
) {
    if (input.empty()) throw std::runtime_error("Share preview source file is empty");
    if (input.size() > kMaxPreviewInputBytes)
        throw std::runtime_error("Share preview source exceeds maximum render size");

    const auto maxSize = std::make_optional(std::to_string(size));
    if (sourceMime.starts_with("image/"))
        return vh::preview::image::resize_and_compress_buffer(input.data(), input.size(), std::nullopt, maxSize);
    if (sourceMime == "application/pdf")
        return vh::preview::pdf::resize_and_compress_buffer(input.data(), input.size(), std::nullopt, maxSize);
    throw std::runtime_error("Unsupported share preview type: " + sourceMime);
}

[[nodiscard]] std::string base64Encode(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return "";
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");

    const auto encodedLen = sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string encoded(encodedLen, '\0');
    sodium_bin2base64(encoded.data(), encoded.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    encoded.resize(std::strlen(encoded.c_str()));
    return encoded;
}

[[nodiscard]] vh::share::ShareAccessAuditTarget auditTarget(const vh::share::ResolvedTarget& target) {
    return {
        .vault_id = target.vault_id,
        .target_entry_id = target.entry ? target.entry->id : target.root_entry_id,
        .target_path = target.vault_path
    };
}
}
namespace preview_detail = share_preview_handler_detail;

std::shared_ptr<PreviewReader> makeDefaultPreviewReader(SharePreviewEngineResolver resolver) {
    return std::make_shared<preview_detail::DefaultPreviewReader>(std::move(resolver));
}

json Preview::get(const json& payload, const std::shared_ptr<Session>& session) {
    preview_detail::requireShareMode(session);
    const auto& body = preview_detail::objectPayload(payload);

    auto mgr = preview_detail::manager();
    auto principal = preview_detail::refreshPrincipal(session, *mgr);
    auto target = preview_detail::resolver()->resolve(*principal, {
        .path = preview_detail::requestedPath(body, *principal),
        .operation = vh::share::Operation::Preview,
        .path_mode = vh::share::TargetPathMode::VaultRelative,
        .expected_target_type = vh::share::TargetType::File
    });

    const auto file = std::dynamic_pointer_cast<vh::fs::model::File>(target.entry);
    if (!file) throw std::runtime_error("Share preview target is not a file");
    if (!file->mime_type) throw std::runtime_error("Share preview target has no mime type");
    if (!preview_detail::supportedMime(*file->mime_type))
        throw std::runtime_error("Unsupported share preview type: " + *file->mime_type);

    const auto size = preview_detail::previewSize(body);
    std::vector<uint8_t> preview;
    if (preview_detail::readerOverridden()) {
        const auto source = preview_detail::reader()->readFile(target);
        preview = preview_detail::renderPreview(source, *file->mime_type, size);
    } else {
        // The same pipeline as GET /preview: the render gate bounds CPU, the encrypted derived cache serves repeats,
        // a known-bad source is refused without decoding it again. Never fetches remote-only bytes for this legacy
        // command (the web console uses GET /preview?share=1).
        const auto engine = runtime::Deps::get().storageManager->getEngine(target.vault_id);
        if (!engine) throw std::runtime_error("Share preview storage engine is unavailable");
        preview = vh::preview::render::render(engine, file, {.size = size, .page = 0},
                                              vh::storage::RemoteFetchPolicy::Off).jpeg;
    }

    mgr->appendAccessAuditEvent(*principal, {
        .event_type = "share.preview.get",
        .target = preview_detail::auditTarget(target),
        .status = vh::share::AuditStatus::Success,
        .bytes_transferred = preview.size(),
        .error_code = std::nullopt,
        .error_message = std::nullopt
    });

    return {
        {"path", target.share_path},
        {"filename", file->name},
        {"source_mime_type", *file->mime_type},
        {"mime_type", "image/jpeg"},
        {"size_bytes", preview.size()},
        {"data_base64", preview_detail::base64Encode(preview)}
    };
}

void Preview::setManagerFactoryForTesting(ManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share manager factory is required");
    preview_detail::managerFactory() = std::move(factory);
}

void Preview::resetManagerFactoryForTesting() {
    preview_detail::managerFactory() = preview_detail::defaultManager;
}

void Preview::setResolverFactoryForTesting(ResolverFactory factory) {
    if (!factory) throw std::invalid_argument("Share target resolver factory is required");
    preview_detail::resolverFactory() = std::move(factory);
}

void Preview::resetResolverFactoryForTesting() {
    preview_detail::resolverFactory() = preview_detail::defaultResolver;
}

void Preview::setReaderFactoryForTesting(ReaderFactory factory) {
    if (!factory) throw std::invalid_argument("Share preview reader factory is required");
    preview_detail::readerFactory() = std::move(factory);
    preview_detail::readerOverridden() = true;
}

void Preview::resetReaderFactoryForTesting() {
    preview_detail::readerFactory() = preview_detail::defaultReader;
    preview_detail::readerOverridden() = false;
}

}
