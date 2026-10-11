#include "protocols/ws/handler/share/Upload.hpp"
#include "ops/Error.hpp"

#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Upload.hpp"
#include "rbac/Actor.hpp"
#include "runtime/Deps.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/Scope.hpp"
#include "share/TargetResolver.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace vh::protocols::ws::handler::share {
namespace share_upload_handler_detail {
constexpr uint64_t kDefaultMaxUploadSize = 64u * 1024u * 1024u;
constexpr uint64_t kMaxChunkSize = 256u * 1024u;

enum class CommandSurface { Compatibility, Native };

class DefaultUploadWriter final : public UploadWriter {
public:
    std::shared_ptr<vh::fs::model::File> createFile(
        const vh::share::ResolvedTarget& parent,
        const std::shared_ptr<vh::identities::User>& user,
        const std::string& finalVaultPath,
        const std::vector<uint8_t>& bytes
    ) const override {
        if (!user) throw std::runtime_error("Share upload file creation requires a link creator user");

        auto engine = runtime::Deps::get().storageManager->getEngine(parent.vault_id);
        if (!engine) throw std::runtime_error("Share upload storage engine is unavailable");
        if (!engine->paths) throw std::runtime_error("Share upload storage paths are unavailable");
        if (bytes.size() > engine->freeSpace())
            throw std::runtime_error("Share upload exceeds available vault storage");

        const auto vaultPath = std::filesystem::path(finalVaultPath);
        const auto fusePath = engine->vaultPathToFusePath(vaultPath);

        return vh::fs::Filesystem::createFile({
            .path = vaultPath,
            .fuse_path = fusePath,
            .buffer = bytes,
            .engine = engine,
            .user = user,
            .overwrite = false
        });
    }
};

[[nodiscard]] std::shared_ptr<vh::share::Manager> defaultManager() {
    return std::make_shared<vh::share::Manager>();
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> defaultResolver() {
    return std::make_shared<vh::share::TargetResolver>();
}

[[nodiscard]] std::shared_ptr<UploadWriter> defaultWriter() {
    return std::make_shared<DefaultUploadWriter>();
}

[[nodiscard]] Upload::ManagerFactory& managerFactory() {
    static Upload::ManagerFactory factory = defaultManager;
    return factory;
}

[[nodiscard]] Upload::ResolverFactory& resolverFactory() {
    static Upload::ResolverFactory factory = defaultResolver;
    return factory;
}

[[nodiscard]] Upload::WriterFactory& writerFactory() {
    static Upload::WriterFactory factory = defaultWriter;
    return factory;
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

[[nodiscard]] std::shared_ptr<UploadWriter> writer() {
    auto instance = writerFactory()();
    if (!instance) throw std::runtime_error("Share upload writer is unavailable");
    return instance;
}

[[nodiscard]] const json& objectPayload(const json& payload) {
    if (!payload.is_object()) throw std::invalid_argument("Share upload payload must be an object");
    return payload;
}

void requireShareMode(const std::shared_ptr<Session>& session) {
    if (!session) throw std::runtime_error("Share upload commands require websocket session");
    if (session->user) throw std::runtime_error("Share upload commands require share mode");
    if (!session->isShareMode()) throw std::runtime_error("Share upload commands require verified share mode");
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

[[nodiscard]] bool hasDuplicateSlash(const std::string_view path) {
    return path.find("//") != std::string_view::npos;
}

[[nodiscard]] std::string requestedPathString(const json& payload) {
    if (!payload.contains("path") || payload.at("path").is_null()) return "/";
    auto path = payload.at("path").get<std::string>();
    if (path.empty()) return "/";
    if (hasDuplicateSlash(path)) throw std::runtime_error("Share upload path contains duplicate slash");
    return path;
}

[[nodiscard]] std::string sanitizeFilename(std::string filename) {
    if (filename.empty()) throw std::invalid_argument("Share upload filename is required");
    if (filename == "." || filename == "..") throw std::invalid_argument("Share upload filename is invalid");
    if (filename.find('/') != std::string::npos || filename.find('\\') != std::string::npos)
        throw std::invalid_argument("Share upload filename must be basename-only");
    if (filename.find('\0') != std::string::npos)
        throw std::invalid_argument("Share upload filename contains invalid byte");
    return filename;
}

[[nodiscard]] std::string requireFilename(const json& payload) {
    return sanitizeFilename(payload.at("filename").get<std::string>());
}

struct UploadTargetRequest {
    std::string parent_path{"/"};
    vh::share::TargetPathMode parent_mode{vh::share::TargetPathMode::VaultRelative};
    std::string filename;
};

[[nodiscard]] UploadTargetRequest uploadTargetRequest(
    const json& payload,
    const vh::share::Principal& principal,
    const CommandSurface surface
) {
    auto path = requestedPathString(payload);
    const bool explicitVaultPath = payload.contains("vault_id") && !payload.at("vault_id").is_null();

    if (surface == CommandSurface::Native) {
        const auto mode = explicitVaultPath
                              ? vh::share::TargetPathMode::VaultRelative
                              : vh::share::TargetPathMode::ShareRelative;
        if (payload.contains("filename") && !payload.at("filename").is_null())
            return {.parent_path = std::move(path), .parent_mode = mode, .filename = requireFilename(payload)};

        const auto fullPath = std::filesystem::path(path);
        auto filename = sanitizeFilename(fullPath.filename().string());
        auto parent = fullPath.parent_path().string();
        if (parent.empty()) parent = "/";
        return {.parent_path = std::move(parent), .parent_mode = mode, .filename = std::move(filename)};
    }

    if (path == "/") path = principal.root_path;
    return {
        .parent_path = std::move(path),
        .parent_mode = vh::share::TargetPathMode::VaultRelative,
        .filename = requireFilename(payload)
    };
}

[[nodiscard]] uint64_t expectedSize(const json& payload) {
    if (payload.contains("size_bytes")) return payload.at("size_bytes").get<uint64_t>();
    return payload.at("size").get<uint64_t>();
}

[[nodiscard]] std::optional<std::string> mimeType(const json& payload) {
    if (!payload.contains("mime_type") || payload.at("mime_type").is_null()) return std::nullopt;
    return payload.at("mime_type").get<std::string>();
}

[[nodiscard]] std::string joinVaultPath(const std::string& parent, const std::string& filename) {
    const auto normalizedParent = vh::share::Scope::normalizeVaultPath(parent);
    if (normalizedParent == "/") return "/" + filename;
    return normalizedParent + "/" + filename;
}

void ensureNoExistingTarget(
    vh::share::TargetResolver& resolver,
    const vh::rbac::Actor& actor,
    const uint32_t vaultId,
    const std::string& finalVaultPath
) {
    try {
        (void)resolver.resolve(actor, {
            .path = finalVaultPath,
            .operation = vh::share::Operation::Upload,
            .path_mode = vh::share::TargetPathMode::VaultRelative,
            .vault_id = vaultId
        });
    } catch (const std::exception& e) {
        const std::string message = e.what();
        if (message.contains("target not found")) return;
        throw;
    }

    const auto principal = actor.sharePrincipal();
    if (!principal) throw std::runtime_error("Share upload actor principal is missing");
    if (principal->grant.duplicate_policy == vh::share::DuplicatePolicy::Reject)
        throw std::runtime_error("Share upload target already exists");
    throw std::runtime_error("Share upload duplicate policy is not supported in this pass");
}

[[nodiscard]] json safeFileJson(const vh::fs::model::File& file, const vh::share::Principal& principal) {
    return {
        {"id", file.id},
        {"name", file.name},
        {"path", vh::share::TargetResolver::shareRelativePath(principal, file.path.string())},
        {"type", "file"},
        {"size_bytes", file.size_bytes},
        {"mime_type", file.mime_type ? json(*file.mime_type) : json(nullptr)}
    };
}

void requireAcceptedDuplicatePolicy(const json& payload) {
    if (!payload.contains("duplicate_policy") || payload.at("duplicate_policy").is_null()) return;
    const auto policy = payload.at("duplicate_policy").get<std::string>();
    if (policy != "reject") throw std::runtime_error("Share upload duplicate policy is not supported in this pass");
}

[[nodiscard]] std::string uploadIdFromPayload(
    const json& payload,
    const std::shared_ptr<Session>& session
) {
    if (payload.contains("upload_id") && !payload.at("upload_id").is_null())
        return payload.at("upload_id").get<std::string>();
    if (payload.contains("transfer_id") && !payload.at("transfer_id").is_null())
        return payload.at("transfer_id").get<std::string>();
    if (session) {
        if (const auto active = session->getUploadHandler()->activeShareUploadId()) return *active;
    }
    throw std::invalid_argument("Share upload id is required");
}

[[nodiscard]] json startImpl(
    const json& payload,
    const std::shared_ptr<Session>& session,
    const CommandSurface surface
) {
    requireShareMode(session);
    const auto& body = objectPayload(payload);
    requireAcceptedDuplicatePolicy(body);

    auto mgr = manager();
    auto principal = refreshPrincipal(session, *mgr);
    const auto actor = session->rbacActor();
    auto resolver = share_upload_handler_detail::resolver();
    auto writer = share_upload_handler_detail::writer();

    auto targetRequest = uploadTargetRequest(body, *principal, surface);
    const auto size = expectedSize(body);
    std::optional<uint32_t> requestedVaultId;
    if (body.contains("vault_id") && !body.at("vault_id").is_null())
        requestedVaultId = body.at("vault_id").get<uint32_t>();

    const auto parent = resolver->resolve(actor, {
        .path = std::move(targetRequest.parent_path),
        .operation = vh::share::Operation::Upload,
        .path_mode = targetRequest.parent_mode,
        .expected_target_type = vh::share::TargetType::Directory,
        .vault_id = requestedVaultId
    });
    const auto filename = std::move(targetRequest.filename);
    const auto finalVaultPath = joinVaultPath(parent.vault_path, filename);
    const auto scope = mgr->authorize(actor, vh::share::Operation::Upload, finalVaultPath,
                                      vh::share::TargetType::File, parent.vault_id);
    if (!scope.allowed) throw vh::ops::Denied("Share upload scope denied: " + scope.reason);

    ensureNoExistingTarget(*resolver, actor, parent.vault_id, finalVaultPath);

    auto started = mgr->startUpload({
        .principal = *principal,
        .target_parent_entry_id = parent.entry->id,
        .target_path = finalVaultPath,
        .original_filename = filename,
        .resolved_filename = filename,
        .expected_size_bytes = size,
        .mime_type = mimeType(body)
    });

    const auto uploadId = started.upload->id;
    const auto shareId = principal->share_id;
    const auto shareSessionId = principal->share_session_id;
    const auto sessionToken = session->shareSessionToken();
    const auto principalSnapshot = *principal;
    const auto parentPath = parent.vault_path;
    const std::weak_ptr<Session> weakSession = session;

    session->getUploadHandler()->startShareUpload({
        .uploadId = uploadId,
        .shareId = shareId,
        .shareSessionId = shareSessionId,
        .websocketSessionUuid = session->uuid,
        .expectedSize = size,
        .maxChunkSize = started.max_chunk_size_bytes ? started.max_chunk_size_bytes : kMaxChunkSize,
        .maxTransferSize = started.max_transfer_size_bytes ? started.max_transfer_size_bytes : kDefaultMaxUploadSize,
        .onChunk = [mgr, sessionToken, uploadId, weakSession](const uint64_t bytes) {
            auto session = weakSession.lock();
            if (!session) throw std::runtime_error("Share upload connection closed");
            auto refreshed = mgr->resolvePrincipal(
                sessionToken,
                session->ipAddress.empty() ? std::nullopt : std::make_optional(session->ipAddress),
                session->userAgent.empty() ? std::nullopt : std::make_optional(session->userAgent)
            );
            session->setSharePrincipal(refreshed, sessionToken);
            (void)session->rbacActor();
            mgr->recordUploadChunk(*refreshed, uploadId, bytes);
        },
        .onFinish = [mgr, resolver, writer, sessionToken, weakSession, uploadId, parentPath, finalVaultPath](
            const std::vector<uint8_t>& bytes
        ) {
            auto session = weakSession.lock();
            if (!session) throw std::runtime_error("Share upload connection closed");
            auto refreshed = mgr->resolvePrincipal(
                sessionToken,
                session->ipAddress.empty() ? std::nullopt : std::make_optional(session->ipAddress),
                session->userAgent.empty() ? std::nullopt : std::make_optional(session->userAgent)
            );
            session->setSharePrincipal(refreshed, sessionToken);
            const auto actor = session->rbacActor();
            auto currentParent = resolver->resolve(actor, {
                .path = parentPath,
                .operation = vh::share::Operation::Upload,
                .path_mode = vh::share::TargetPathMode::VaultRelative,
                .expected_target_type = vh::share::TargetType::Directory
            });
            auto scope = mgr->authorize(actor, vh::share::Operation::Upload, finalVaultPath,
                                        vh::share::TargetType::File, currentParent.vault_id);
            if (!scope.allowed) throw vh::ops::Denied("Share upload scope denied: " + scope.reason);
            ensureNoExistingTarget(*resolver, actor, currentParent.vault_id, finalVaultPath);

            if (refreshed->link_created_by == 0)
                throw std::runtime_error("Share upload link creator user is missing");
            // Attribution only (created_by): an id-only detached user, as before.
            const auto creator = vh::identities::User::detached(refreshed->link_created_by, {});

            auto file = writer->createFile(currentParent, creator, finalVaultPath, bytes);
            if (!file) throw std::runtime_error("Share upload file creation failed");

            mgr->finishUpload({
                .principal = *refreshed,
                .upload_id = uploadId,
                .created_entry_id = file->id,
                .content_hash = file->content_hash.value_or(""),
                .mime_type = file->mime_type
            });
            return file;
        },
        .onCancel = [mgr, principalSnapshot, uploadId] {
            mgr->cancelUpload(principalSnapshot, uploadId);
        },
        .onFail = [mgr, principalSnapshot, uploadId](const std::string& error) {
            try {
                mgr->failUpload(principalSnapshot, uploadId, error);
            } catch (...) {
            }
        }
    });

    return {
        {"upload_id", uploadId},
        {"transfer_id", uploadId},
        {"path", vh::share::TargetResolver::shareRelativePath(*principal, finalVaultPath)},
        {"filename", filename},
        {"size_bytes", size},
        {"chunk_size", started.max_chunk_size_bytes},
        {"duplicate_policy", vh::share::to_string(vh::share::DuplicatePolicy::Reject)}
    };
}

[[nodiscard]] json finishImpl(const json& payload, const std::shared_ptr<Session>& session) {
    requireShareMode(session);
    const auto& body = objectPayload(payload);
    const auto uploadId = uploadIdFromPayload(body, session);

    auto mgr = manager();
    auto principal = refreshPrincipal(session, *mgr);

    try {
        auto file = session->getUploadHandler()->finishShareUpload(uploadId, principal->share_session_id);
        return {
            {"upload_id", uploadId},
            {"complete", true},
            {"entry", safeFileJson(*file, *principal)}
        };
    } catch (const std::exception& e) {
        try {
            mgr->failUpload(*principal, uploadId, e.what());
        } catch (...) {
        }
        throw;
    }
}

[[nodiscard]] json cancelImpl(const json& payload, const std::shared_ptr<Session>& session) {
    requireShareMode(session);
    const auto& body = objectPayload(payload);
    const auto uploadId = uploadIdFromPayload(body, session);

    auto mgr = manager();
    auto principal = refreshPrincipal(session, *mgr);
    session->getUploadHandler()->cancelShareUpload(uploadId, principal->share_session_id);
    return {{"cancelled", true}, {"upload_id", uploadId}};
}
}
namespace up_detail = share_upload_handler_detail;

json Upload::start(const json& payload, const std::shared_ptr<Session>& session) {
    return up_detail::startImpl(payload, session, up_detail::CommandSurface::Compatibility);
}

json Upload::finish(const json& payload, const std::shared_ptr<Session>& session) {
    return up_detail::finishImpl(payload, session);
}

json Upload::cancel(const json& payload, const std::shared_ptr<Session>& session) {
    return up_detail::cancelImpl(payload, session);
}

json Upload::nativeStart(const json& payload, const std::shared_ptr<Session>& session) {
    return up_detail::startImpl(payload, session, up_detail::CommandSurface::Native);
}

json Upload::nativeFinish(const json& payload, const std::shared_ptr<Session>& session) {
    return up_detail::finishImpl(payload, session);
}

json Upload::nativeCancel(const json& payload, const std::shared_ptr<Session>& session) {
    return up_detail::cancelImpl(payload, session);
}

void Upload::setManagerFactoryForTesting(ManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share manager factory is required");
    up_detail::managerFactory() = std::move(factory);
}

void Upload::resetManagerFactoryForTesting() {
    up_detail::managerFactory() = up_detail::defaultManager;
}

void Upload::setResolverFactoryForTesting(ResolverFactory factory) {
    if (!factory) throw std::invalid_argument("Share target resolver factory is required");
    up_detail::resolverFactory() = std::move(factory);
}

void Upload::resetResolverFactoryForTesting() {
    up_detail::resolverFactory() = up_detail::defaultResolver;
}

void Upload::setWriterFactoryForTesting(WriterFactory factory) {
    if (!factory) throw std::invalid_argument("Share upload writer factory is required");
    up_detail::writerFactory() = std::move(factory);
}

void Upload::resetWriterFactoryForTesting() {
    up_detail::writerFactory() = up_detail::defaultWriter;
}

}
