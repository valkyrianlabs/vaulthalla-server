#include "protocols/http/upload/Coordinator.hpp"

#include "auth/session/Manager.hpp"
#include "crypto/util/hash.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "fs/ops/file.hpp"
#include "protocols/http/upload/Staging.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/cookie.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/resolver/Vault.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "runtime/Deps.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/Scope.hpp"
#include "share/TargetResolver.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace vh::protocols::http::upload::detail {
enum class UploadMode { Authenticated, Share };

enum class FileStatus { Pending, Receiving, Complete, Failed };

struct UploadFileState {
    std::string file_id;
    uint32_t vault_id{};
    std::filesystem::path vault_path;
    std::filesystem::path tmp_path;
    std::filesystem::path fuse_from;
    std::filesystem::path fuse_to;
    uint64_t expected_size{};
    uint64_t received_size{};
    std::optional<std::string> mime_type;
    FileStatus status{FileStatus::Pending};
    std::shared_ptr<vh::storage::Engine> engine;

    std::string share_upload_id;
    std::string share_parent_path;
    std::string share_final_path;
    std::string share_original_filename;
    vh::share::Principal share_principal_snapshot;
};

struct UploadSessionState {
    std::string id;
    UploadMode mode{UploadMode::Authenticated};
    uint32_t user_id{};
    std::string share_session_id;
    std::unordered_map<std::string, UploadFileState> files;
    // Both from uploadClock(). last_activity slides on every owned request and every body chunk; the purge reads it
    // under the registry lock only, hence atomic.
    std::chrono::steady_clock::time_point created_at{};
    std::atomic<std::chrono::steady_clock::rep> last_activity{0};
    bool finished{false};
    std::mutex mutex;
};

} // namespace vh::protocols::http::upload::detail

namespace {
using vh::fs::model::PathType;
using vh::protocols::http::request;
using vh::protocols::http::upload::detail::FileStatus;
using vh::protocols::http::upload::detail::UploadFileState;
using vh::protocols::http::upload::detail::UploadMode;
using vh::protocols::http::upload::detail::UploadSessionState;

constexpr uint32_t kMaxHttpUploadFiles = 4096;
constexpr uint64_t kDefaultMaxHttpUploadFileBytes = 8ull * 1024ull * 1024ull * 1024ull;
// Sliding idle TTL: a session expires 30 minutes after its last activity (create, a PUT chunk, finish), not after
// creation, so long uploads on slow links finish. The hard ceiling bounds a session that trickles forever.
constexpr std::chrono::minutes kUploadSessionTtl{30};
constexpr std::chrono::hours kUploadSessionMaxAge{24};

[[nodiscard]] vh::protocols::http::upload::Coordinator::Clock& uploadClockOverride() {
    static vh::protocols::http::upload::Coordinator::Clock value;
    return value;
}

[[nodiscard]] std::chrono::steady_clock::time_point uploadClock() {
    const auto& clock = uploadClockOverride();
    return clock ? clock() : std::chrono::steady_clock::now();
}

void touchUploadSession(UploadSessionState& session) noexcept {
    session.last_activity.store(uploadClock().time_since_epoch().count(), std::memory_order_relaxed);
}

[[nodiscard]] bool uploadSessionExpired(const UploadSessionState& session,
                                        const std::chrono::steady_clock::time_point now) noexcept {
    const std::chrono::steady_clock::time_point lastActivity{
        std::chrono::steady_clock::duration{session.last_activity.load(std::memory_order_relaxed)}};
    return lastActivity < now - kUploadSessionTtl || session.created_at < now - kUploadSessionMaxAge;
}

[[nodiscard]] std::unordered_map<std::string, std::shared_ptr<UploadSessionState>>& sessions() {
    static std::unordered_map<std::string, std::shared_ptr<UploadSessionState>> value;
    return value;
}

[[nodiscard]] std::mutex& sessionsMutex() {
    static std::mutex value;
    return value;
}

[[nodiscard]] bool isShareModeRequestTarget(const std::string_view target) {
    const auto pos = target.find('?');
    if (pos == std::string_view::npos) return false;
    std::stringstream stream{std::string(target.substr(pos + 1))};
    std::string pair;
    while (std::getline(stream, pair, '&')) {
        if (pair == "share=1" || pair == "share=true") return true;
    }
    return false;
}

[[nodiscard]] std::string safeIdComponent(const std::string& value, const std::string_view label) {
    if (value.empty() || value.size() > 96) throw std::invalid_argument("Invalid " + std::string(label));
    for (const unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_') continue;
        throw std::invalid_argument("Invalid " + std::string(label));
    }
    return value;
}

[[nodiscard]] std::vector<std::string> splitTargetPath(std::string_view target) {
    const auto query = target.find('?');
    if (query != std::string_view::npos) target = target.substr(0, query);

    std::vector<std::string> parts;
    std::stringstream stream{std::string(target)};
    std::string part;
    while (std::getline(stream, part, '/')) {
        if (!part.empty()) parts.push_back(part);
    }
    return parts;
}

[[nodiscard]] std::shared_ptr<vh::protocols::ws::Session> defaultSessionResolver(const request& req) {
    if (isShareModeRequestTarget(std::string_view{req.target().data(), req.target().size()})) {
        const auto shareRefresh = vh::protocols::extractCookie(req, "share_refresh");
        if (shareRefresh.empty()) throw std::runtime_error("Share refresh token not set");
        return vh::runtime::Deps::get().sessionManager->validateRawShareRefreshToken(shareRefresh);
    }

    const auto refresh = vh::protocols::extractCookie(req, "refresh");
    if (refresh.empty()) throw std::runtime_error("Refresh token not set");
    return vh::runtime::Deps::get().sessionManager->validateRawRefreshToken(refresh);
}

[[nodiscard]] std::shared_ptr<vh::share::Manager> defaultShareManager() {
    return std::make_shared<vh::share::Manager>();
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> defaultShareResolver() {
    return std::make_shared<vh::share::TargetResolver>();
}

[[nodiscard]] std::shared_ptr<vh::storage::Engine> defaultEngineResolver(const uint32_t vaultId) {
    return vh::runtime::Deps::get().storageManager->getEngine(vaultId);
}

[[nodiscard]] vh::protocols::http::upload::Coordinator::SessionResolver& sessionResolver() {
    static vh::protocols::http::upload::Coordinator::SessionResolver value = defaultSessionResolver;
    return value;
}

[[nodiscard]] vh::protocols::http::upload::Coordinator::ShareManagerFactory& shareManagerFactory() {
    static vh::protocols::http::upload::Coordinator::ShareManagerFactory value = defaultShareManager;
    return value;
}

[[nodiscard]] vh::protocols::http::upload::Coordinator::ShareResolverFactory& shareResolverFactory() {
    static vh::protocols::http::upload::Coordinator::ShareResolverFactory value = defaultShareResolver;
    return value;
}

[[nodiscard]] vh::protocols::http::upload::Coordinator::EngineResolver& engineResolver() {
    static vh::protocols::http::upload::Coordinator::EngineResolver value = defaultEngineResolver;
    return value;
}

[[nodiscard]] std::shared_ptr<vh::share::Manager> shareManager() {
    auto manager = shareManagerFactory()();
    if (!manager) throw std::runtime_error("Share upload manager is unavailable");
    return manager;
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> shareResolver() {
    auto resolver = shareResolverFactory()();
    if (!resolver) throw std::runtime_error("Share upload resolver is unavailable");
    return resolver;
}

[[nodiscard]] std::shared_ptr<vh::storage::Engine> engineFor(const uint32_t vaultId) {
    auto engine = engineResolver()(vaultId);
    if (!engine) throw std::runtime_error("Unknown storage engine");
    if (!engine->paths) throw std::runtime_error("Storage engine paths are unavailable");
    return engine;
}

void enforceHumanWritePermission(
    const std::shared_ptr<vh::protocols::ws::Session>& session,
    const std::shared_ptr<vh::storage::Engine>& engine,
    const std::filesystem::path& vaultPath
) {
    if (!session || !session->user) throw std::runtime_error("Upload requires a user session");
    if (!engine || !engine->vault) throw std::runtime_error("Upload storage engine is unavailable");

    const auto fusePath = engine->vaultPathToFusePath(vaultPath);
    if (!vh::rbac::resolver::Vault::has<vh::rbac::permission::vault::FilesystemAction>({
        .user = session->user,
        .permission = vh::rbac::permission::vault::FilesystemAction::Write,
        .vault_id = engine->vault->id,
        .path = fusePath
    })) throw std::runtime_error("Permission denied");
}

[[nodiscard]] uint64_t fileSizeFromJson(const nlohmann::json& item) {
    if (item.contains("size_bytes")) return item.at("size_bytes").get<uint64_t>();
    return item.at("size").get<uint64_t>();
}

[[nodiscard]] std::optional<std::string> mimeTypeFromJson(const nlohmann::json& item) {
    if (!item.contains("mime_type") || item.at("mime_type").is_null()) return std::nullopt;
    return item.at("mime_type").get<std::string>();
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

[[nodiscard]] std::string joinVaultPath(const std::string& parent, const std::string& filename) {
    const auto normalizedParent = vh::share::Scope::normalizeVaultPath(parent);
    if (normalizedParent == "/") return "/" + filename;
    return normalizedParent + "/" + filename;
}

struct ShareTargetRequest {
    std::string parent_path{"/"};
    vh::share::TargetPathMode parent_mode{vh::share::TargetPathMode::ShareRelative};
    std::string filename;
    std::optional<uint32_t> vault_id;
};

[[nodiscard]] ShareTargetRequest shareTargetRequest(const nlohmann::json& item, const nlohmann::json& payload) {
    std::optional<uint32_t> vaultId;
    if (item.contains("vault_id") && !item.at("vault_id").is_null()) vaultId = item.at("vault_id").get<uint32_t>();
    else if (payload.contains("vault_id") && !payload.at("vault_id").is_null()) vaultId = payload.at("vault_id").get<uint32_t>();

    auto path = item.contains("path") && !item.at("path").is_null()
                    ? item.at("path").get<std::string>()
                    : std::string{"/"};
    if (path.empty()) path = "/";
    if (path.find("//") != std::string::npos) throw std::runtime_error("Share upload path contains duplicate slash");

    const auto mode = vaultId ? vh::share::TargetPathMode::VaultRelative : vh::share::TargetPathMode::ShareRelative;
    if (item.contains("filename") && !item.at("filename").is_null()) {
        return {
            .parent_path = std::move(path),
            .parent_mode = mode,
            .filename = sanitizeFilename(item.at("filename").get<std::string>()),
            .vault_id = vaultId
        };
    }

    const auto fullPath = std::filesystem::path(path);
    auto filename = sanitizeFilename(fullPath.filename().string());
    auto parent = fullPath.parent_path().string();
    if (parent.empty()) parent = "/";
    return {.parent_path = std::move(parent), .parent_mode = mode, .filename = std::move(filename), .vault_id = vaultId};
}

void ensureNoExistingShareTarget(
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

void createEmptyTempFile(const std::filesystem::path& path) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) throw std::runtime_error("Unable to create upload temp file");
}

void cleanupFile(const UploadFileState& file) noexcept {
    std::error_code ec;
    std::filesystem::remove(file.tmp_path, ec);
    try {
        const auto& cache = vh::runtime::Deps::get().fsCache;
        if (cache && cache->entryExists(file.fuse_from)) cache->evictPath(file.fuse_from);
    } catch (...) {
    }
}

void failShareUploadIfNeeded(const UploadFileState& file, const std::string& reason) noexcept {
    if (file.share_upload_id.empty()) return;
    try {
        shareManager()->failUpload(file.share_principal_snapshot, file.share_upload_id, reason);
    } catch (...) {
    }
}

void cancelShareUploadIfNeeded(const UploadFileState& file) noexcept {
    if (file.share_upload_id.empty()) return;
    try {
        shareManager()->cancelUpload(file.share_principal_snapshot, file.share_upload_id);
    } catch (...) {
    }
}

void cleanupSession(
    const std::shared_ptr<UploadSessionState>& session,
    const std::string& shareReason,
    const bool failCompletedShareUploads = false,
    const bool removeTempFiles = true,
    const bool markFilesFailed = false
) noexcept {
    if (!session) return;
    std::scoped_lock lock(session->mutex);
    for (auto& [_, file] : session->files) {
        if (markFilesFailed && file.status != FileStatus::Complete) file.status = FileStatus::Failed;
        if (removeTempFiles) cleanupFile(file);
        if (session->mode == UploadMode::Share && (failCompletedShareUploads || file.status != FileStatus::Complete))
            failShareUploadIfNeeded(file, shareReason);
    }
}

void cleanupExpiredSessionsLocked() noexcept {
    const auto now = uploadClock();
    for (auto it = sessions().begin(); it != sessions().end();) {
        if (it->second && uploadSessionExpired(*it->second, now)) {
            cleanupSession(it->second, "http_upload_expired", true);
            it = sessions().erase(it);
        } else ++it;
    }
}

[[nodiscard]] std::shared_ptr<UploadSessionState> findSession(const std::string& uploadId) {
    std::scoped_lock lock(sessionsMutex());
    cleanupExpiredSessionsLocked();
    const auto it = sessions().find(uploadId);
    if (it == sessions().end()) throw std::runtime_error("Upload session not found");
    return it->second;
}

void verifySessionOwner(
    const UploadSessionState& upload,
    const std::shared_ptr<vh::protocols::ws::Session>& session
) {
    if (upload.mode == UploadMode::Authenticated) {
        if (!session || !session->user) throw std::runtime_error("Upload requires a user session");
        if (session->user->id != upload.user_id) throw std::runtime_error("Upload session owner mismatch");
        return;
    }

    if (!session || !session->isShareMode() || session->user)
        throw std::runtime_error("Upload requires a ready share session");
    if (session->shareSessionId() != upload.share_session_id)
        throw std::runtime_error("Upload share session mismatch");
}

// Only the owning session's requests keep an upload alive.
[[nodiscard]] std::shared_ptr<vh::protocols::ws::Session> resolveAndVerify(
    const request& req,
    UploadSessionState& upload
) {
    auto session = sessionResolver()(req);
    verifySessionOwner(upload, session);
    touchUploadSession(upload);
    return session;
}

[[nodiscard]] std::shared_ptr<vh::share::Principal> refreshSharePrincipal(
    const std::shared_ptr<vh::protocols::ws::Session>& session,
    vh::share::Manager& manager
) {
    if (!session || !session->isShareMode() || session->user)
        throw std::runtime_error("Upload requires a ready share session");
    if (session->shareSessionToken().empty()) throw std::runtime_error("Share session token is missing");
    auto principal = manager.resolvePrincipal(
        session->shareSessionToken(),
        session->ipAddress.empty() ? std::nullopt : std::make_optional(session->ipAddress),
        session->userAgent.empty() ? std::nullopt : std::make_optional(session->userAgent)
    );
    session->setSharePrincipal(principal, session->shareSessionToken());
    return principal;
}

[[nodiscard]] nlohmann::json fileResponseJson(const UploadFileState& file) {
    nlohmann::json out{
        {"file_id", file.file_id},
        {"path", file.vault_path.string()},
        {"size", file.expected_size},
        {"received_size", file.received_size},
        {"complete", file.status == FileStatus::Complete}
    };
    if (!file.share_upload_id.empty()) out["transfer_id"] = file.share_upload_id;
    return out;
}

void runSyncForVaults(const std::set<uint32_t>& vaults) noexcept {
    for (const auto vaultId : vaults) {
        try {
            if (vh::runtime::Deps::get().syncController)
                vh::runtime::Deps::get().syncController->runNow(vaultId);
            else
                vh::log::Registry::sync()->warn("[HttpUpload] Sync controller is unavailable for vault {}", vaultId);
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->error("[HttpUpload] Failed to trigger sync for vault {}: {}", vaultId, e.what());
        } catch (...) {
            vh::log::Registry::sync()->error("[HttpUpload] Failed to trigger sync for vault {}: unknown error", vaultId);
        }
    }
}

void reserveUploadSpace(
    std::unordered_map<uint32_t, uintmax_t>& plannedBytesByVault,
    const uint32_t vaultId,
    const uint64_t size,
    const std::shared_ptr<vh::storage::Engine>& engine,
    const char* message
) {
    const auto requested = static_cast<uintmax_t>(size);
    const auto available = engine ? engine->freeSpace() : 0;
    auto& planned = plannedBytesByVault[vaultId];

    if (requested > available || planned > available - requested)
        throw std::runtime_error(message);

    planned += requested;
}

std::vector<uint8_t> readCompletedUploadFile(const UploadFileState& file) {
    if (!std::filesystem::exists(file.tmp_path))
        throw std::runtime_error("Uploaded temp file is missing: " + file.tmp_path.string());

    const auto actualSize = std::filesystem::file_size(file.tmp_path);
    if (actualSize != file.expected_size)
        throw std::runtime_error("Uploaded temp file size mismatch");

    if (actualSize == 0) return {};
    return vh::fs::ops::readFileToVector(file.tmp_path);
}

std::shared_ptr<vh::fs::model::File> commitCompletedUploadFile(
    const UploadFileState& file,
    const std::shared_ptr<vh::identities::User>& user
) {
    if (!user) throw std::runtime_error("Upload requires a user");

    auto created = vh::fs::Filesystem::createFile({
        .path = file.vault_path,
        .fuse_path = file.fuse_to,
        .buffer = readCompletedUploadFile(file),
        .engine = file.engine,
        .user = user
    });

    std::error_code ec;
    std::filesystem::remove(file.tmp_path, ec);
    if (ec) {
        vh::log::Registry::fs()->warn(
            "[HttpUpload] Failed to remove completed upload temp file {}: {}",
            file.tmp_path.string(),
            ec.message());
    }

    return created;
}

} // namespace

namespace vh::protocols::http::upload {

using detail::FileStatus;
using detail::UploadFileState;
using detail::UploadMode;
using detail::UploadSessionState;

struct Coordinator::FileStream::Impl {
    std::shared_ptr<UploadSessionState> session;
    std::string file_id;
    std::ofstream out;
    std::shared_ptr<vh::share::Manager> manager;
    std::shared_ptr<vh::share::Principal> principal;
    bool finished{false};
    bool failed{false};

    [[nodiscard]] UploadFileState& file() {
        auto it = session->files.find(file_id);
        if (it == session->files.end()) throw std::runtime_error("Upload file not found");
        return it->second;
    }
};

Coordinator::FileStream::FileStream() = default;

Coordinator::FileStream::FileStream(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Coordinator::FileStream::FileStream(FileStream&& other) noexcept : impl_(std::move(other.impl_)) {}

Coordinator::FileStream& Coordinator::FileStream::operator=(FileStream&& other) noexcept {
    if (this == &other) return *this;
    if (impl_ && !impl_->finished && !impl_->failed) fail("http_upload_stream_replaced");
    impl_ = std::move(other.impl_);
    return *this;
}

Coordinator::FileStream::~FileStream() {
    if (impl_ && !impl_->finished && !impl_->failed) fail("http_upload_stream_abandoned");
}

bool Coordinator::FileStream::valid() const noexcept { return static_cast<bool>(impl_); }

void Coordinator::FileStream::write(const void* data, const std::size_t size) {
    if (!impl_) throw std::runtime_error("Upload stream is not open");
    if (impl_->finished || impl_->failed) throw std::runtime_error("Upload stream is already closed");
    if (size == 0) return;
    if (!data) throw std::invalid_argument("Upload stream data is required");

    std::string shareUploadId;
    {
        std::scoped_lock lock(impl_->session->mutex);
        auto& file = impl_->file();
        if (file.status != FileStatus::Receiving) throw std::runtime_error("Upload file is not receiving data");
        if (file.received_size > file.expected_size || size > file.expected_size - file.received_size)
            throw std::runtime_error("Upload exceeds expected size");

        impl_->out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!impl_->out.good()) throw std::runtime_error("Unable to write upload body");
        file.received_size += size;
        shareUploadId = file.share_upload_id;
    }
    touchUploadSession(*impl_->session);

    if (impl_->manager && impl_->principal)
        impl_->manager->recordUploadChunk(*impl_->principal, shareUploadId, size);
}

nlohmann::json Coordinator::FileStream::finish() {
    if (!impl_) throw std::runtime_error("Upload stream is not open");
    if (impl_->finished) return {};
    if (impl_->failed) throw std::runtime_error("Upload stream failed");

    impl_->out.close();
    nlohmann::json response;
    {
        std::scoped_lock lock(impl_->session->mutex);
        auto& file = impl_->file();
        if (file.received_size != file.expected_size) {
            file.status = FileStatus::Failed;
            throw std::runtime_error("Upload size mismatch");
        }
        file.status = FileStatus::Complete;
        response = fileResponseJson(file);
    }
    touchUploadSession(*impl_->session);
    impl_->finished = true;
    return response;
}

void Coordinator::FileStream::fail(std::string reason) noexcept {
    if (!impl_ || impl_->failed || impl_->finished) return;
    impl_->failed = true;
    try {
        if (impl_->out.is_open()) impl_->out.close();
    } catch (...) {
    }

    try {
        std::scoped_lock lock(impl_->session->mutex);
        auto& file = impl_->file();
        if (file.status == FileStatus::Failed) return;
        file.status = FileStatus::Failed;
        cleanupFile(file);
        if (impl_->manager && impl_->principal)
            impl_->manager->failUpload(*impl_->principal, file.share_upload_id, reason);
    } catch (...) {
    }
}

Coordinator& Coordinator::instance() {
    static Coordinator value;
    return value;
}

bool Coordinator::isUploadFileRequest(const boost::beast::http::verb method, const std::string_view target) {
    if (method != boost::beast::http::verb::put) return false;
    const auto parts = splitTargetPath(target);
    return parts.size() == 4 && parts[0] == "upload" && parts[2] == "files";
}

ParsedFileTarget Coordinator::parseUploadFileTarget(const std::string_view target) {
    const auto parts = splitTargetPath(target);
    if (parts.size() != 4 || parts[0] != "upload" || parts[2] != "files")
        throw std::invalid_argument("Invalid upload file route");
    return {
        .upload_id = safeIdComponent(parts[1], "upload id"),
        .file_id = safeIdComponent(parts[3], "file id")
    };
}

nlohmann::json Coordinator::createSession(const request& req, const nlohmann::json& payload) {
    if (!payload.contains("files") || !payload.at("files").is_array())
        throw std::invalid_argument("Upload session requires files array");
    if (payload.at("files").empty()) throw std::invalid_argument("Upload session requires at least one file");
    if (payload.at("files").size() > kMaxHttpUploadFiles) throw std::runtime_error("Upload session has too many files");

    const auto shareMode = isShareModeRequestTarget(std::string_view{req.target().data(), req.target().size()});
    auto session = sessionResolver()(req);

    auto upload = std::make_shared<UploadSessionState>();
    upload->id = vh::protocols::ws::Session::generateUUIDv4();
    upload->mode = shareMode ? UploadMode::Share : UploadMode::Authenticated;
    upload->created_at = uploadClock();
    touchUploadSession(*upload);

    nlohmann::json responseFiles = nlohmann::json::array();
    std::unordered_set<std::string> fileIds;
    std::unordered_set<std::string> targetKeys;

    try {
        if (shareMode) {
            if (!session || !session->isShareMode() || session->user)
                throw std::runtime_error("Upload requires a ready share session");

            auto manager = shareManager();
            auto resolver = shareResolver();
            auto principal = refreshSharePrincipal(session, *manager);
            const auto actor = session->rbacActor();
            upload->share_session_id = principal->share_session_id;
            std::unordered_map<uint32_t, uintmax_t> plannedBytesByVault;

            for (const auto& item : payload.at("files")) {
                const auto fileId = safeIdComponent(
                    item.value("file_id", vh::protocols::ws::Session::generateUUIDv4()),
                    "file id"
                );
                if (!fileIds.insert(fileId).second) throw std::runtime_error("Duplicate upload file id");

                auto targetRequest = shareTargetRequest(item, payload);
                const auto parent = resolver->resolve(actor, {
                    .path = std::move(targetRequest.parent_path),
                    .operation = vh::share::Operation::Upload,
                    .path_mode = targetRequest.parent_mode,
                    .expected_target_type = vh::share::TargetType::Directory,
                    .vault_id = targetRequest.vault_id
                });
                const auto finalVaultPath = joinVaultPath(parent.vault_path, targetRequest.filename);
                const auto targetKey = std::to_string(parent.vault_id) + ":" + finalVaultPath;
                if (!targetKeys.insert(targetKey).second) throw std::runtime_error("Duplicate upload target");

                const auto scope = manager->authorize(
                    actor,
                    vh::share::Operation::Upload,
                    finalVaultPath,
                    vh::share::TargetType::File,
                    parent.vault_id
                );
                if (!scope.allowed) throw std::runtime_error("Share upload scope denied: " + scope.reason);
                ensureNoExistingShareTarget(*resolver, actor, parent.vault_id, finalVaultPath);

                const auto size = fileSizeFromJson(item);
                const auto mime = mimeTypeFromJson(item);
                auto engine = engineFor(parent.vault_id);
                reserveUploadSpace(
                    plannedBytesByVault,
                    parent.vault_id,
                    size,
                    engine,
                    "Share upload exceeds available vault storage");

                const auto vaultPath = std::filesystem::path(finalVaultPath);
                const auto absPath = engine->paths->absPath(vaultPath, PathType::VAULT_ROOT);
                const auto tmpPath = vh::protocols::http::upload::staging::pathFor(absPath, parent.vault_id, ".upload-http-" + upload->id + "-" + fileId + ".part");
                const auto fuseTo = engine->paths->absRelToRoot(absPath, PathType::FUSE_ROOT);
                const auto fuseFrom = engine->paths->absRelToRoot(tmpPath, PathType::FUSE_ROOT);

                auto started = manager->startUpload({
                    .principal = *principal,
                    .target_parent_entry_id = parent.entry ? parent.entry->id : 0,
                    .target_path = finalVaultPath,
                    .original_filename = targetRequest.filename,
                    .resolved_filename = targetRequest.filename,
                    .expected_size_bytes = size,
                    .mime_type = mime
                });

                UploadFileState file{
                    .file_id = fileId,
                    .vault_id = parent.vault_id,
                    .vault_path = vaultPath,
                    .tmp_path = tmpPath,
                    .fuse_from = fuseFrom,
                    .fuse_to = fuseTo,
                    .expected_size = size,
                    .received_size = 0,
                    .mime_type = mime,
                    .status = FileStatus::Pending,
                    .engine = engine,
                    .share_upload_id = started.upload ? started.upload->id : std::string{},
                    .share_parent_path = parent.vault_path,
                    .share_final_path = finalVaultPath,
                    .share_original_filename = targetRequest.filename,
                    .share_principal_snapshot = *principal
                };

                auto [stored, inserted] = upload->files.emplace(fileId, std::move(file));
                if (!inserted) throw std::runtime_error("Duplicate upload file id");
                if (size == 0) {
                    createEmptyTempFile(tmpPath);
                    stored->second.status = FileStatus::Complete;
                }
                responseFiles.push_back(fileResponseJson(stored->second));
            }
        } else {
            if (!session || !session->user) throw std::runtime_error("Upload requires a user session");
            upload->user_id = session->user->id;
            std::unordered_map<uint32_t, uintmax_t> plannedBytesByVault;

            for (const auto& item : payload.at("files")) {
                const auto fileId = safeIdComponent(
                    item.value("file_id", vh::protocols::ws::Session::generateUUIDv4()),
                    "file id"
                );
                if (!fileIds.insert(fileId).second) throw std::runtime_error("Duplicate upload file id");

                const auto vaultId = item.contains("vault_id") && !item.at("vault_id").is_null()
                                         ? item.at("vault_id").get<uint32_t>()
                                         : payload.at("vault_id").get<uint32_t>();
                const auto vaultPath = std::filesystem::path(item.at("path").get<std::string>());
                const auto size = fileSizeFromJson(item);
                if (size > kDefaultMaxHttpUploadFileBytes) throw std::runtime_error("Upload file exceeds maximum size");

                const auto targetKey = std::to_string(vaultId) + ":" + vaultPath.lexically_normal().string();
                if (!targetKeys.insert(targetKey).second) throw std::runtime_error("Duplicate upload target");

                auto engine = engineFor(vaultId);
                enforceHumanWritePermission(session, engine, vaultPath);
                reserveUploadSpace(
                    plannedBytesByVault,
                    vaultId,
                    size,
                    engine,
                    "Upload exceeds available vault storage");

                const auto absPath = engine->paths->absPath(vaultPath, PathType::VAULT_ROOT);
                const auto tmpPath = vh::protocols::http::upload::staging::pathFor(absPath, vaultId, ".upload-http-" + upload->id + "-" + fileId + ".part");
                const auto fuseTo = engine->paths->absRelToRoot(absPath, PathType::FUSE_ROOT);
                const auto fuseFrom = engine->paths->absRelToRoot(tmpPath, PathType::FUSE_ROOT);

                if (vh::runtime::Deps::get().fsCache && vh::runtime::Deps::get().fsCache->entryExists(fuseTo))
                    throw std::runtime_error("Upload target already exists");

                if (const auto err = vh::fs::Filesystem::mkdir({
                        .path = fuseFrom.parent_path(),
                        .engine = engine,
                        .user = session->user
                    }); err)
                    throw std::runtime_error("Failed to create upload parent directory");

                UploadFileState file{
                    .file_id = fileId,
                    .vault_id = vaultId,
                    .vault_path = vaultPath,
                    .tmp_path = tmpPath,
                    .fuse_from = fuseFrom,
                    .fuse_to = fuseTo,
                    .expected_size = size,
                    .received_size = 0,
                    .mime_type = mimeTypeFromJson(item),
                    .status = FileStatus::Pending,
                    .engine = engine,
                    .share_upload_id = {},
                    .share_parent_path = {},
                    .share_final_path = {},
                    .share_original_filename = {},
                    .share_principal_snapshot = {}
                };

                auto [stored, inserted] = upload->files.emplace(fileId, std::move(file));
                if (!inserted) throw std::runtime_error("Duplicate upload file id");
                if (size == 0) {
                    createEmptyTempFile(tmpPath);
                    stored->second.status = FileStatus::Complete;
                }
                responseFiles.push_back(fileResponseJson(stored->second));
            }
        }
    } catch (...) {
        cleanupSession(upload, "http_upload_create_failed", true);
        throw;
    }

    {
        std::scoped_lock lock(sessionsMutex());
        cleanupExpiredSessionsLocked();
        touchUploadSession(*upload);
        sessions().emplace(upload->id, upload);
    }

    return {
        {"upload_id", upload->id},
        {"files", std::move(responseFiles)}
    };
}

Coordinator::FileStream Coordinator::beginFile(const request& req, const std::optional<uint64_t> contentLength) {
    const auto parsed = parseUploadFileTarget(std::string_view{req.target().data(), req.target().size()});
    auto upload = findSession(parsed.upload_id);
    auto session = resolveAndVerify(req, *upload);

    auto impl = std::make_unique<FileStream::Impl>();
    impl->session = upload;
    impl->file_id = parsed.file_id;

    if (upload->mode == UploadMode::Share) {
        impl->manager = shareManager();
        impl->principal = refreshSharePrincipal(session, *impl->manager);
    }

    {
        std::scoped_lock lock(upload->mutex);
        auto it = upload->files.find(parsed.file_id);
        if (it == upload->files.end()) throw std::runtime_error("Upload file not found");
        auto& file = it->second;
        if (file.status == FileStatus::Complete) throw std::runtime_error("Upload file is already complete");
        if (file.status == FileStatus::Receiving) throw std::runtime_error("Upload file is already receiving data");
        if (file.status == FileStatus::Failed) throw std::runtime_error("Upload file has failed");
        if (contentLength && *contentLength != file.expected_size) throw std::runtime_error("Upload size mismatch");

        std::filesystem::create_directories(file.tmp_path.parent_path());
        impl->out.open(file.tmp_path, std::ios::binary | std::ios::trunc);
        if (!impl->out.is_open()) throw std::runtime_error("Unable to open upload temp file");
        file.received_size = 0;
        file.status = FileStatus::Receiving;
    }

    return FileStream(std::move(impl));
}

nlohmann::json Coordinator::finishSession(const request& req, const std::string_view uploadIdView) {
    const auto uploadId = safeIdComponent(std::string(uploadIdView), "upload id");
    auto upload = findSession(uploadId);
    auto session = resolveAndVerify(req, *upload);

    std::vector<UploadFileState> files;
    {
        std::scoped_lock lock(upload->mutex);
        if (upload->finished) throw std::runtime_error("Upload session is already finished");
        for (const auto& [_, file] : upload->files) {
            if (file.status != FileStatus::Complete || file.received_size != file.expected_size)
                throw std::runtime_error("Upload session has incomplete files");
            files.push_back(file);
        }
    }

    std::set<uint32_t> vaults;
    nlohmann::json entries = nlohmann::json::array();
    try {
        if (upload->mode == UploadMode::Authenticated) {
            if (!session || !session->user) throw std::runtime_error("Upload requires a user session");
            for (const auto& file : files) {
                (void)commitCompletedUploadFile(file, session->user);
                vaults.insert(file.vault_id);
                entries.push_back(fileResponseJson(file));
            }
        } else {
            auto manager = shareManager();
            auto resolver = shareResolver();
            auto principal = refreshSharePrincipal(session, *manager);
            const auto actor = session->rbacActor();

            if (principal->link_created_by == 0)
                throw std::runtime_error("Share upload link creator user is missing");
            // Attribution only (created_by): an id-only detached user, as before.
            const auto creator = vh::identities::User::detached(principal->link_created_by, {});

            for (const auto& file : files) {
                auto currentParent = resolver->resolve(actor, {
                    .path = file.share_parent_path,
                    .operation = vh::share::Operation::Upload,
                    .path_mode = vh::share::TargetPathMode::VaultRelative,
                    .expected_target_type = vh::share::TargetType::Directory,
                    .vault_id = file.vault_id
                });
                auto scope = manager->authorize(
                    actor,
                    vh::share::Operation::Upload,
                    file.share_final_path,
                    vh::share::TargetType::File,
                    currentParent.vault_id
                );
                if (!scope.allowed) throw std::runtime_error("Share upload scope denied: " + scope.reason);
                ensureNoExistingShareTarget(*resolver, actor, currentParent.vault_id, file.share_final_path);

                auto created = commitCompletedUploadFile(file, creator);
                manager->finishUpload({
                    .principal = *principal,
                    .upload_id = file.share_upload_id,
                    .created_entry_id = created->id,
                    .content_hash = created->content_hash.value_or(""),
                    .mime_type = created->mime_type
                });
                vaults.insert(file.vault_id);
                entries.push_back({
                    {"file_id", file.file_id},
                    {"transfer_id", file.share_upload_id},
                    {"path", vh::share::TargetResolver::shareRelativePath(*principal, file.share_final_path)},
                    {"entry_id", created->id}
                });
            }
        }
    } catch (const std::exception& e) {
        if (upload->mode == UploadMode::Share) {
            for (const auto& file : files) failShareUploadIfNeeded(file, e.what());
        } else {
            cleanupSession(upload, "http_upload_finish_failed");
        }
        throw;
    }

    {
        std::scoped_lock lock(upload->mutex);
        upload->finished = true;
    }
    cleanupSession(upload, "http_upload_finished", false, false);
    {
        std::scoped_lock lock(sessionsMutex());
        sessions().erase(uploadId);
    }
    runSyncForVaults(vaults);

    return {
        {"upload_id", uploadId},
        {"complete", true},
        {"file_count", files.size()},
        {"files", std::move(entries)}
    };
}

nlohmann::json Coordinator::cancelSession(const request& req, const std::string_view uploadIdView) {
    const auto uploadId = safeIdComponent(std::string(uploadIdView), "upload id");
    std::shared_ptr<UploadSessionState> upload;
    {
        std::scoped_lock lock(sessionsMutex());
        cleanupExpiredSessionsLocked();
        const auto it = sessions().find(uploadId);
        if (it == sessions().end()) return {{"cancelled", true}, {"upload_id", uploadId}};
        upload = it->second;
    }
    auto session = resolveAndVerify(req, *upload);
    (void)session;

    if (upload->mode == UploadMode::Share) {
        std::scoped_lock lock(upload->mutex);
        for (const auto& [_, file] : upload->files) {
            cleanupFile(file);
            cancelShareUploadIfNeeded(file);
        }
    } else {
        cleanupSession(upload, "http_upload_cancelled");
    }

    {
        std::scoped_lock lock(sessionsMutex());
        sessions().erase(uploadId);
    }
    return {{"cancelled", true}, {"upload_id", uploadId}};
}

void Coordinator::abortAll(std::string reason) noexcept {
    if (reason.empty()) reason = "http_upload_aborted";

    std::vector<std::shared_ptr<UploadSessionState>> pending;
    {
        std::scoped_lock lock(sessionsMutex());
        pending.reserve(sessions().size());
        for (auto& [_, session] : sessions()) pending.push_back(std::move(session));
        sessions().clear();
    }

    for (const auto& session : pending)
        cleanupSession(session, reason, true, true, true);
}

void Coordinator::setSessionResolverForTesting(SessionResolver resolver) {
    if (!resolver) throw std::invalid_argument("Upload session resolver is required");
    sessionResolver() = std::move(resolver);
}

void Coordinator::resetSessionResolverForTesting() { sessionResolver() = defaultSessionResolver; }

void Coordinator::setShareManagerFactoryForTesting(ShareManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share upload manager factory is required");
    shareManagerFactory() = std::move(factory);
}

void Coordinator::resetShareManagerFactoryForTesting() { shareManagerFactory() = defaultShareManager; }

void Coordinator::setShareResolverFactoryForTesting(ShareResolverFactory factory) {
    if (!factory) throw std::invalid_argument("Share upload resolver factory is required");
    shareResolverFactory() = std::move(factory);
}

void Coordinator::resetShareResolverFactoryForTesting() { shareResolverFactory() = defaultShareResolver; }

void Coordinator::setEngineResolverForTesting(EngineResolver resolver) {
    if (!resolver) throw std::invalid_argument("Upload engine resolver is required");
    engineResolver() = std::move(resolver);
}

void Coordinator::resetEngineResolverForTesting() { engineResolver() = defaultEngineResolver; }

void Coordinator::setClockForTesting(Clock clock) {
    if (!clock) throw std::invalid_argument("Upload clock is required");
    uploadClockOverride() = std::move(clock);
}

void Coordinator::resetClockForTesting() { uploadClockOverride() = nullptr; }

void Coordinator::clearForTesting() {
    std::scoped_lock lock(sessionsMutex());
    sessions().clear();
}

} // namespace vh::protocols::http::upload
