#include "protocols/ws/handler/share/Download.hpp"
#include "protocols/ws/handler/RequestErrors.hpp"
#include "ops/Error.hpp"

#include "fs/model/File.hpp"
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
#include <mutex>
#include <optional>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vh::protocols::ws::handler::share {
namespace share_download_handler_detail {
constexpr uint64_t kDefaultChunkSize = 64u * 1024u;
constexpr uint64_t kMaxChunkSize = 256u * 1024u;
constexpr uint64_t kMaxTransferSize = 64u * 1024u * 1024u;
constexpr uint32_t kMaxActiveTransfers = 128;
constexpr uint32_t kMaxTransfersPerSession = 4;

enum class CommandSurface { Compatibility, Native };

struct TransferContext {
    std::string transfer_id;
    std::string websocket_session_uuid;
    std::string share_id;
    std::string share_session_id;
    uint32_t vault_id{};
    uint32_t target_entry_id{};
    std::string vault_path;
    std::string share_path;
    std::string filename;
    std::optional<std::string> mime_type;
    std::optional<std::string> content_hash;
    std::shared_ptr<const std::vector<uint8_t>> bytes;
    uint64_t bytes_sent{};
    vh::share::Principal principal_snapshot;
};

class DefaultDownloadReader final : public DownloadReader {
public:
    explicit DefaultDownloadReader(ShareEngineResolver resolver) : resolver_(std::move(resolver)) {}

    std::vector<uint8_t> readFile(const vh::share::ResolvedTarget& target) const override {
        if (!target.entry || target.target_type != vh::share::TargetType::File)
            throw vh::ops::Invalid("Share download target is not a file");

        auto file = std::dynamic_pointer_cast<vh::fs::model::File>(target.entry);
        if (!file) throw std::runtime_error("Share download target file is unavailable");
        if (file->size_bytes == 0) return {};
        // Refuse before any read (or remote fetch) rather than after buffering it.
        if (file->size_bytes > kMaxTransferSize)
            throw vh::ops::Invalid("Share download exceeds maximum in-memory transfer size");

        const auto engine = resolver_ ? resolver_(target.vault_id)
                                      : runtime::Deps::get().storageManager->getEngine(target.vault_id);
        if (!engine) throw std::runtime_error("Share download storage engine is unavailable");

        // The local ciphertext copy when there is one; a remote-only file follows preview.media.remote.
        const auto reader = engine->openPlaintextReader(file);
        try {
            return vh::storage::readAll(*reader, kMaxTransferSize);
        } catch (const std::length_error&) {
            throw vh::ops::Invalid("Share download exceeds maximum in-memory transfer size");
        }
    }

private:
    ShareEngineResolver resolver_;
};

std::mutex& transferMutex() {
    static std::mutex mutex;
    return mutex;
}

std::unordered_map<std::string, TransferContext>& transfers() {
    static std::unordered_map<std::string, TransferContext> registry;
    return registry;
}

[[nodiscard]] std::shared_ptr<vh::share::Manager> defaultManager() {
    return std::make_shared<vh::share::Manager>();
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> defaultResolver() {
    return std::make_shared<vh::share::TargetResolver>();
}

[[nodiscard]] std::shared_ptr<DownloadReader> defaultReader() {
    return std::make_shared<DefaultDownloadReader>(ShareEngineResolver{});
}

[[nodiscard]] Download::ManagerFactory& managerFactory() {
    static Download::ManagerFactory factory = defaultManager;
    return factory;
}

[[nodiscard]] Download::ResolverFactory& resolverFactory() {
    static Download::ResolverFactory factory = defaultResolver;
    return factory;
}

[[nodiscard]] Download::ReaderFactory& readerFactory() {
    static Download::ReaderFactory factory = defaultReader;
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

[[nodiscard]] std::shared_ptr<DownloadReader> reader() {
    auto instance = readerFactory()();
    if (!instance) throw std::runtime_error("Share download reader is unavailable");
    return instance;
}

[[nodiscard]] const json& objectPayload(const json& payload) {
    if (!payload.is_object()) throw std::invalid_argument("Share download payload must be an object");
    return payload;
}

void requireShareMode(const std::shared_ptr<Session>& session) {
    if (!session) throw std::runtime_error("Share download commands require websocket session");
    if (session->user) throw vh::ops::Denied("Share download commands require share mode");
    if (!session->isShareMode()) throw vh::ops::Denied("Share download commands require verified share mode");
    if (session->shareSessionToken().empty()) throw vh::ops::Denied("Share session token is missing");
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
    if (hasDuplicateSlash(path)) throw vh::ops::Invalid("Share download path contains duplicate slash");
    return path;
}

struct RequestedDownloadPath {
    std::string path{"/"};
    vh::share::TargetPathMode mode{vh::share::TargetPathMode::VaultRelative};
};

[[nodiscard]] RequestedDownloadPath requestedPath(
    const json& payload,
    const vh::share::Principal& principal,
    const CommandSurface surface
) {
    auto path = requestedPathString(payload);
    if (surface == CommandSurface::Native) {
        const bool explicitVaultPath = payload.contains("vault_id") && !payload.at("vault_id").is_null();
        return {
            .path = std::move(path),
            .mode = explicitVaultPath
                        ? vh::share::TargetPathMode::VaultRelative
                        : vh::share::TargetPathMode::ShareRelative
        };
    }

    if (path == "/") path = principal.root_path;
    return {.path = std::move(path), .mode = vh::share::TargetPathMode::VaultRelative};
}

[[nodiscard]] vh::share::ShareAccessAuditTarget auditTarget(const TransferContext& transfer) {
    return {
        .vault_id = transfer.vault_id,
        .target_entry_id = transfer.target_entry_id,
        .target_path = transfer.vault_path
    };
}

[[nodiscard]] vh::share::ShareAccessAuditTarget auditTarget(const vh::share::ResolvedTarget& target) {
    return {
        .vault_id = target.vault_id,
        .target_entry_id = target.entry ? target.entry->id : target.root_entry_id,
        .target_path = target.vault_path
    };
}

void appendAudit(
    vh::share::Manager& manager,
    const vh::share::Principal& principal,
    std::string eventType,
    vh::share::ShareAccessAuditTarget target,
    const vh::share::AuditStatus status,
    const std::optional<uint64_t> bytes = std::nullopt,
    std::optional<std::string> errorCode = std::nullopt,
    std::optional<std::string> errorMessage = std::nullopt
) {
    manager.appendAccessAuditEvent(principal, {
        .event_type = std::move(eventType),
        .target = std::move(target),
        .status = status,
        .bytes_transferred = bytes,
        .error_code = std::move(errorCode),
        .error_message = std::move(errorMessage)
    });
}

void registerTransfer(TransferContext transfer) {
    std::scoped_lock lock(transferMutex());
    auto& registry = transfers();
    if (registry.size() >= kMaxActiveTransfers)
        throw std::runtime_error("Too many active share download transfers");

    const auto activeForSession = std::ranges::count_if(registry, [&](const auto& item) {
        return item.second.websocket_session_uuid == transfer.websocket_session_uuid;
    });
    if (activeForSession >= kMaxTransfersPerSession)
        throw vh::ops::Conflict("Too many active share download transfers for this session");

    registry.emplace(transfer.transfer_id, std::move(transfer));
}

[[nodiscard]] TransferContext transferForSession(
    const std::string& transferId,
    const std::shared_ptr<Session>& session
) {
    if (transferId.empty()) throw std::invalid_argument("Share download transfer id is required");
    std::scoped_lock lock(transferMutex());
    const auto& registry = transfers();
    const auto it = registry.find(transferId);
    if (it == registry.end()) throw vh::ops::NotFound("Share download transfer not found");
    if (it->second.websocket_session_uuid != session->uuid)
        throw vh::ops::Denied("Share download transfer does not belong to this websocket session");
    if (it->second.share_session_id != session->shareSessionId())
        throw vh::ops::Denied("Share download transfer does not belong to this share session");
    return it->second;
}

void eraseTransfer(const std::string& transferId) {
    std::scoped_lock lock(transferMutex());
    transfers().erase(transferId);
}

struct ChunkResult {
    std::vector<uint8_t> bytes;
    uint64_t next_offset{};
    uint64_t bytes_sent{};
    bool complete{};
};

[[nodiscard]] ChunkResult takeChunk(
    const std::string& transferId,
    const std::shared_ptr<Session>& session,
    const uint64_t offset,
    const uint64_t length
) {
    if (length == 0) throw std::invalid_argument("Share download chunk length is required");
    if (length > kMaxChunkSize) throw vh::ops::Invalid("Share download chunk length exceeds maximum");

    std::scoped_lock lock(transferMutex());
    auto& registry = transfers();
    const auto it = registry.find(transferId);
    if (it == registry.end()) throw vh::ops::NotFound("Share download transfer not found");
    auto& transfer = it->second;
    if (transfer.websocket_session_uuid != session->uuid)
        throw vh::ops::Denied("Share download transfer does not belong to this websocket session");
    if (transfer.share_session_id != session->shareSessionId())
        throw vh::ops::Denied("Share download transfer does not belong to this share session");
    if (!transfer.bytes) throw std::runtime_error("Share download transfer data is unavailable");
    if (offset != transfer.bytes_sent)
        throw vh::ops::Invalid("Share download chunk offset is not the next expected offset");
    if (offset > transfer.bytes->size())
        throw vh::ops::Invalid("Share download chunk range exceeds transfer size");

    const auto remaining = static_cast<uint64_t>(transfer.bytes->size()) - offset;
    const auto actualLength = std::min(length, remaining);

    ChunkResult result;
    result.bytes.insert(result.bytes.end(), transfer.bytes->begin() + static_cast<std::ptrdiff_t>(offset),
                        transfer.bytes->begin() + static_cast<std::ptrdiff_t>(offset + actualLength));
    transfer.bytes_sent += actualLength;
    result.next_offset = transfer.bytes_sent;
    result.bytes_sent = transfer.bytes_sent;
    result.complete = transfer.bytes_sent == transfer.bytes->size();
    if (result.complete) registry.erase(it);
    return result;
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

void revalidateTransferTarget(
    const TransferContext& transfer,
    const vh::rbac::Actor& actor,
    vh::share::TargetResolver& resolver
) {
    const auto principal = actor.sharePrincipal();
    if (!principal) throw std::runtime_error("Share download transfer principal is missing");
    if (principal->share_id != transfer.share_id || principal->share_session_id != transfer.share_session_id)
        throw vh::ops::Denied("Share download transfer principal mismatch");

    const auto target = resolver.resolve(actor, {
        .path = transfer.vault_path,
        .operation = vh::share::Operation::Download,
        .path_mode = vh::share::TargetPathMode::VaultRelative,
        .expected_target_type = vh::share::TargetType::File,
        .vault_id = transfer.vault_id
    });
    if (!target.entry || target.entry->id != transfer.target_entry_id || target.vault_path != transfer.vault_path)
        throw vh::ops::Conflict("Share download target changed");
}

[[nodiscard]] json startImpl(
    const json& payload,
    const std::shared_ptr<Session>& session,
    const CommandSurface surface
) {
    requireShareMode(session);
    const auto& body = objectPayload(payload);
    auto mgr = manager();
    auto principal = refreshPrincipal(session, *mgr);
    const auto actor = session->rbacActor();
    auto resolver = share_download_handler_detail::resolver();
    auto requested = requestedPath(body, *principal, surface);
    std::optional<uint32_t> requestedVaultId;
    if (body.contains("vault_id") && !body.at("vault_id").is_null())
        requestedVaultId = body.at("vault_id").get<uint32_t>();

    auto target = resolver->resolve(actor, {
        .path = std::move(requested.path),
        .operation = vh::share::Operation::Download,
        .path_mode = requested.mode,
        .expected_target_type = vh::share::TargetType::File,
        .vault_id = requestedVaultId
    });

    const auto file = std::dynamic_pointer_cast<vh::fs::model::File>(target.entry);
    if (!file) throw vh::ops::Invalid("Share download target is not a file");

    auto bytes = std::make_shared<std::vector<uint8_t>>(reader()->readFile(target));
    if (bytes->size() > kMaxTransferSize)
        throw vh::ops::Invalid("Share download exceeds maximum in-memory transfer size");

    const auto transferId = Session::generateUUIDv4();
    TransferContext transfer{
        .transfer_id = transferId,
        .websocket_session_uuid = session->uuid,
        .share_id = principal->share_id,
        .share_session_id = principal->share_session_id,
        .vault_id = target.vault_id,
        .target_entry_id = target.entry->id,
        .vault_path = target.vault_path,
        .share_path = target.share_path,
        .filename = file->name,
        .mime_type = file->mime_type,
        .content_hash = file->content_hash,
        .bytes = bytes,
        .principal_snapshot = *principal
    };

    registerTransfer(transfer);
    try {
        appendAudit(*mgr, *principal, "share.download.start", auditTarget(target),
                    vh::share::AuditStatus::Success, 0);
    } catch (...) {
        eraseTransfer(transferId);
        throw;
    }

    return {
        {"transfer_id", transferId},
        {"filename", file->name},
        {"path", target.share_path},
        {"size_bytes", bytes->size()},
        {"mime_type", file->mime_type ? json(*file->mime_type) : json(nullptr)},
        {"chunk_size", kDefaultChunkSize}
    };
}

[[nodiscard]] json chunkImpl(const json& payload, const std::shared_ptr<Session>& session) {
    requireShareMode(session);
    const auto& body = objectPayload(payload);
    if (body.contains("path")) throw vh::ops::Invalid("Share download chunk cannot change path");

    const auto transferId = body.at("transfer_id").get<std::string>();
    const auto offset = body.at("offset").get<uint64_t>();
    const auto length = body.value("length", kDefaultChunkSize);

    auto mgr = manager();
    auto resolver = share_download_handler_detail::resolver();
    auto transfer = transferForSession(transferId, session);

    try {
        auto principal = refreshPrincipal(session, *mgr);
        const auto actor = session->rbacActor();
        revalidateTransferTarget(transfer, actor, *resolver);
        const auto chunk = takeChunk(transferId, session, offset, length);

        if (chunk.complete) {
            mgr->incrementDownloadCount(*principal);
            appendAudit(*mgr, *principal, "share.download.finish", auditTarget(transfer),
                        vh::share::AuditStatus::Success, chunk.bytes_sent);
        }

        return {
            {"transfer_id", transferId},
            {"offset", offset},
            {"bytes", chunk.bytes.size()},
            {"data_base64", base64Encode(chunk.bytes)},
            {"next_offset", chunk.next_offset},
            {"complete", chunk.complete}
        };
    } catch (const std::exception& e) {
        eraseTransfer(transferId);
        appendAudit(*mgr, transfer.principal_snapshot, "share.download.fail", auditTarget(transfer),
                    vh::share::AuditStatus::Failed, transfer.bytes_sent,
                    "share_download_failed", e.what());
        throw;
    }
}

[[nodiscard]] json cancelImpl(const json& payload, const std::shared_ptr<Session>& session) {
    requireShareMode(session);
    const auto& body = objectPayload(payload);
    const auto transferId = body.at("transfer_id").get<std::string>();

    auto mgr = manager();
    auto transfer = transferForSession(transferId, session);
    auto principal = refreshPrincipal(session, *mgr);
    if (principal->share_id != transfer.share_id || principal->share_session_id != transfer.share_session_id)
        throw vh::ops::Denied("Share download transfer principal mismatch");

    eraseTransfer(transferId);
    appendAudit(*mgr, *principal, "share.download.cancel", auditTarget(transfer),
                vh::share::AuditStatus::Success, transfer.bytes_sent);
    return {{"cancelled", true}, {"transfer_id", transferId}};
}
}
namespace dl_detail = share_download_handler_detail;

std::shared_ptr<DownloadReader> makeDefaultDownloadReader(ShareEngineResolver resolver) {
    return std::make_shared<dl_detail::DefaultDownloadReader>(std::move(resolver));
}

json Download::start(const json& payload, const std::shared_ptr<Session>& session) try {
    return dl_detail::startImpl(payload, session, dl_detail::CommandSurface::Compatibility);
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Download::chunk(const json& payload, const std::shared_ptr<Session>& session) try {
    return dl_detail::chunkImpl(payload, session);
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Download::cancel(const json& payload, const std::shared_ptr<Session>& session) try {
    return dl_detail::cancelImpl(payload, session);
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Download::nativeStart(const json& payload, const std::shared_ptr<Session>& session) try {
    return dl_detail::startImpl(payload, session, dl_detail::CommandSurface::Native);
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Download::nativeChunk(const json& payload, const std::shared_ptr<Session>& session) try {
    return dl_detail::chunkImpl(payload, session);
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Download::nativeCancel(const json& payload, const std::shared_ptr<Session>& session) try {
    return dl_detail::cancelImpl(payload, session);
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

void Download::setManagerFactoryForTesting(ManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share manager factory is required");
    dl_detail::managerFactory() = std::move(factory);
}

void Download::resetManagerFactoryForTesting() {
    dl_detail::managerFactory() = dl_detail::defaultManager;
}

void Download::setResolverFactoryForTesting(ResolverFactory factory) {
    if (!factory) throw std::invalid_argument("Share target resolver factory is required");
    dl_detail::resolverFactory() = std::move(factory);
}

void Download::resetResolverFactoryForTesting() {
    dl_detail::resolverFactory() = dl_detail::defaultResolver;
}

void Download::setReaderFactoryForTesting(ReaderFactory factory) {
    if (!factory) throw std::invalid_argument("Share download reader factory is required");
    dl_detail::readerFactory() = std::move(factory);
}

void Download::resetReaderFactoryForTesting() {
    dl_detail::readerFactory() = dl_detail::defaultReader;
}

void Download::resetTransfersForTesting() {
    std::scoped_lock lock(dl_detail::transferMutex());
    dl_detail::transfers().clear();
}

}
