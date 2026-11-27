#include "protocols/ws/handler/fs/Storage.hpp"
#include "db/query/mirror/Contents.hpp"
#include "protocols/ws/handler/RequestErrors.hpp"
#include "db/encoding/timestamp.hpp"
#include "protocols/ws/Session.hpp"
#include "storage/Manager.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "rbac/Actor.hpp"
#include "rbac/fs/Visibility.hpp"
#include "rbac/role/Vault.hpp"
#include "vault/model/Vault.hpp"
#include "identities/User.hpp"
#include "protocols/ws/handler/fs/Upload.hpp"
#include "protocols/ws/handler/share/Upload.hpp"
#include "storage/Engine.hpp"
#include "runtime/Deps.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/TargetResolver.hpp"
#include "preview/Plan.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace vh::protocols::ws::handler::fs;
using namespace vh::vault::model;
using namespace vh::rbac;
using namespace vh::storage;
using namespace vh::fs;
using namespace vh::fs::model;

namespace {

enum class ShareReadPathStyle { Native, Compatibility };

struct SharePathRequest {
    std::string path{"/"};
    vh::share::TargetPathMode mode{vh::share::TargetPathMode::VaultRelative};
};

struct ShareReadResult {
    std::shared_ptr<vh::share::Principal> principal;
    vh::share::ResolvedTarget target;
    std::vector<std::shared_ptr<vh::fs::model::Entry>> entries;
};

[[nodiscard]] std::shared_ptr<vh::share::Manager> defaultShareManager() {
    return std::make_shared<vh::share::Manager>();
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> defaultShareResolver() {
    return std::make_shared<vh::share::TargetResolver>();
}

[[nodiscard]] Storage::ShareManagerFactory& shareManagerFactory() {
    static Storage::ShareManagerFactory factory = defaultShareManager;
    return factory;
}

[[nodiscard]] Storage::ShareResolverFactory& shareResolverFactory() {
    static Storage::ShareResolverFactory factory = defaultShareResolver;
    return factory;
}

[[nodiscard]] std::shared_ptr<vh::share::Manager> shareManager() {
    auto instance = shareManagerFactory()();
    if (!instance) throw std::runtime_error("Share manager is unavailable");
    return instance;
}

[[nodiscard]] std::shared_ptr<vh::share::TargetResolver> shareResolver() {
    auto instance = shareResolverFactory()();
    if (!instance) throw std::runtime_error("Share target resolver is unavailable");
    return instance;
}

[[nodiscard]] const json& objectPayload(const json& payload) {
    if (!payload.is_object()) throw std::invalid_argument("Filesystem payload must be an object");
    return payload;
}

[[nodiscard]] std::optional<std::string> optionalClientText(const std::string& value) {
    if (value.empty()) return std::nullopt;
    return value;
}

void requireShareMode(const std::shared_ptr<vh::protocols::ws::Session>& session) {
    if (!session) throw std::runtime_error("Share filesystem commands require websocket session");
    if (session->user) throw vh::ops::Denied("Share filesystem commands require share mode");
    if (!session->isShareMode()) throw vh::ops::Denied("Share filesystem commands require verified share mode");
    if (session->shareSessionToken().empty()) throw vh::ops::Denied("Share session token is missing");
}

[[nodiscard]] std::shared_ptr<vh::share::Principal> refreshSharePrincipal(
    const std::shared_ptr<vh::protocols::ws::Session>& session,
    vh::share::Manager& manager
) {
    auto principal = manager.resolvePrincipal(
        session->shareSessionToken(),
        optionalClientText(session->ipAddress),
        optionalClientText(session->userAgent)
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
    if (hasDuplicateSlash(path)) throw vh::ops::Invalid("Share filesystem path contains duplicate slash");
    return path;
}

[[nodiscard]] SharePathRequest requestedSharePath(
    const json& payload,
    const vh::share::Principal& principal,
    const ShareReadPathStyle style
) {
    auto path = requestedPathString(payload);
    if (style == ShareReadPathStyle::Native) {
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

[[nodiscard]] json safeShareEntryJson(
    const vh::fs::model::Entry& entry,
    const vh::share::Principal& principal
) {
    return Storage::shareEntryJson(entry, principal);
}

[[nodiscard]] ShareReadResult shareRead(
    const json& payload,
    const std::shared_ptr<vh::protocols::ws::Session>& session,
    const vh::share::Operation operation,
    const ShareReadPathStyle pathStyle,
    const bool includeChildren
) {
    requireShareMode(session);
    const auto& body = objectPayload(payload);
    auto manager = shareManager();
    auto principal = refreshSharePrincipal(session, *manager);
    const auto actor = session->rbacActor();
    auto resolver = shareResolver();
    auto requested = requestedSharePath(body, *principal, pathStyle);
    std::optional<vh::share::TargetType> expectedTargetType;
    if (operation == vh::share::Operation::List)
        expectedTargetType = vh::share::TargetType::Directory;
    std::optional<uint32_t> requestedVaultId;
    if (body.contains("vault_id") && !body.at("vault_id").is_null())
        requestedVaultId = body.at("vault_id").get<uint32_t>();

    auto target = resolver->resolve(actor, {
        .path = std::move(requested.path),
        .operation = operation,
        .path_mode = requested.mode,
        .expected_target_type = expectedTargetType,
        .vault_id = requestedVaultId
    });

    ShareReadResult result{
        .principal = std::move(principal),
        .target = std::move(target),
        .entries = {}
    };

    if (includeChildren)
        result.entries = resolver->listChildren(actor, result.target);

    return result;
}

[[nodiscard]] json shareMetadataResponse(
    const json& payload,
    const std::shared_ptr<vh::protocols::ws::Session>& session,
    const ShareReadPathStyle pathStyle
) {
    auto result = shareRead(payload, session, vh::share::Operation::Metadata, pathStyle, false);
    return {
        {"path", result.target.share_path},
        {"entry", safeShareEntryJson(*result.target.entry, *result.principal)}
    };
}

[[nodiscard]] json shareListResponse(
    const json& payload,
    const std::shared_ptr<vh::protocols::ws::Session>& session,
    const ShareReadPathStyle pathStyle
) {
    auto result = shareRead(payload, session, vh::share::Operation::List, pathStyle, true);
    json files = json::array();
    for (const auto& entry : result.entries)
        files.push_back(safeShareEntryJson(*entry, *result.principal));

    return {
        {"path", result.target.share_path},
        {"entry", safeShareEntryJson(*result.target.entry, *result.principal)},
        {"files", std::move(files)}
    };
}

}

json Storage::startUpload(const json& payload, const std::shared_ptr<Session>& session) try {
    if (session && session->isShareMode())
        return vh::protocols::ws::handler::share::Upload::nativeStart(payload, session);

    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto path = std::filesystem::path(payload.at("path").get<std::string>());

    // The upload's bytes go through the mount to a staged entry beside the target; ops::fs commits it at the finish.
    const auto engine = vh::ops::fs::authorizeUpload(session ? session->user : nullptr, vaultId, path);

    const auto uploadId = Session::generateUUIDv4();
    const auto absPath = engine->paths->absPath(path, PathType::VAULT_ROOT);
    const auto tmpPath = absPath.parent_path() / (".upload-" + uploadId + ".part");

    session->getUploadHandler()->startUpload({
        .uploadId = uploadId,
        .expectedSize = payload.at("size").get<uint64_t>(),
        .engine = engine,
        .tmpPath = tmpPath,
        .finalPath = absPath,
        .fuseFrom = engine->paths->absRelToRoot(tmpPath, PathType::FUSE_ROOT),
        .fuseTo = engine->paths->absRelToRoot(absPath, PathType::FUSE_ROOT)
    });

    return {{"upload_id", uploadId}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::finishUpload(const json& payload, const std::shared_ptr<Session>& session) try {
    if (session && session->isShareMode())
        return vh::protocols::ws::handler::share::Upload::nativeFinish(payload, session);

    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto path = std::filesystem::path(payload.at("path").get<std::string>());

    (void)vh::ops::fs::authorizeUpload(session ? session->user : nullptr, vaultId, path);
    session->getUploadHandler()->finishUpload();
    return {{"path", path.string()}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::cancelUpload(const json& payload, const std::shared_ptr<Session>& session) try {
    if (session && session->isShareMode())
        return vh::protocols::ws::handler::share::Upload::nativeCancel(payload, session);

    if (!session || !session->user) throw std::runtime_error("Unauthorized");
    session->getUploadHandler()->abortActiveUpload("upload_cancelled");
    return {{"cancelled", true}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::mkdir(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto path = std::filesystem::path(payload.at("path").get<std::string>());

    vh::ops::fs::mkdir(session ? session->user : nullptr, vaultId, path);
    return {{"path", path.string()}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::move(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto from = std::filesystem::path(payload.at("from").get<std::string>());
    const auto to = std::filesystem::path(payload.at("to").get<std::string>());

    vh::ops::fs::move(session ? session->user : nullptr, vaultId, from, to);
    return {
        {"from", from.string()},
        {"to", to.string()}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::rename(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto from = std::filesystem::path(payload.at("from").get<std::string>());
    const auto to = std::filesystem::path(payload.at("to").get<std::string>());

    vh::ops::fs::rename(session ? session->user : nullptr, vaultId, from, to);
    return {
        {"from", from.string()},
        {"to", to.string()}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::copy(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto from = std::filesystem::path(payload.at("from").get<std::string>());
    const auto to = std::filesystem::path(payload.at("to").get<std::string>());

    vh::ops::fs::copy(session ? session->user : nullptr, vaultId, from, to);
    return {
        {"from", from.string()},
        {"to", to.string()}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::metadata(const json& payload, const std::shared_ptr<Session>& session) try {
    if (session && session->isShareMode())
        return shareMetadataResponse(payload, session, ShareReadPathStyle::Native);

    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    auto path = std::filesystem::path(payload.value("path", "/"));
    if (path.empty()) path = std::filesystem::path("/");

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));

    enforcePermission(
        session,
        engine,
        path,
        permission::vault::FilesystemAction::Lookup,
        "Permission denied: User does not have metadata permission for this path in the vault"
    );

    const auto fusePath = engine->vaultPathToFusePath(path);
    if (!Filesystem::exists(fusePath)) throw vh::ops::NotFound("Path does not exist: " + fusePath.string());

    const auto entry = runtime::Deps::get().fsCache->getEntry(fusePath);
    if (!entry) throw vh::ops::NotFound("No entry found for path: " + fusePath.string());

    // A folder's size covers only what the caller can see (#269), as in fs.dir.list (#255): the stored subtree total
    // counts hidden entries too.
    json entryJson = *entry;
    if (const auto totals = vh::rbac::fs::visibility::visibleTotals(session->user, entry))
        entryJson["size_bytes"] = totals->size_bytes;

    return {
        {"vault", engine->vault->name},
        {"path", path.string()},
        {"entry", std::move(entryJson)}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::list(const json& payload, const std::shared_ptr<Session>& session) try {
    if (session && session->isShareMode())
        return shareListResponse(payload, session, ShareReadPathStyle::Native);

    return listDir(payload, session);
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::listDir(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    auto path = std::filesystem::path(payload.value("path", "/"));
    if (path.empty()) path = std::filesystem::path("/");

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));

    enforcePermission(
        session,
        engine,
        path,
        permission::vault::FilesystemAction::List,
        "Permission denied: User does not have list permission for this path in the vault"
    );

    const auto fusePath = engine->vaultPathToFusePath(path);
    if (!Filesystem::exists(fusePath)) throw vh::ops::NotFound("Path does not exist: " + fusePath.string());

    const auto entry = runtime::Deps::get().fsCache->getEntry(fusePath);
    if (!entry) throw vh::ops::NotFound("No entry found for path: " + fusePath.string());

    // Deny means hidden (#170, #255): children the caller cannot Lookup are left out, as FUSE readdir leaves them out
    // (one rule, rbac::fs::visibility), and so is everything they hold from the folder totals.
    const auto& user = session->user;
    const auto entries = vh::rbac::fs::visibility::visibleChildren(user, entry,
                                                                   runtime::Deps::get().fsCache->listDir(entry->id));
    json entryJson = *entry;
    json files = entries;
    // A detached vault's files whose contents never arrived: listed, and said to be missing.
    if (const auto missing = vh::db::query::mirror::PendingContents::missingFileIds(vaultId); !missing.empty())
        for (std::size_t i = 0; i < entries.size(); ++i)
            if (!entries[i]->isDirectory() && !entries[i]->isSymlink() && missing.contains(entries[i]->id))
                files[i]["contents_missing"] = true;
    if (!vh::rbac::fs::visibility::seesWholeSubtree(user, entry)) {
        std::uintmax_t listedSize = 0;
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& child = entries[i];
            if (!child->isDirectory()) {
                listedSize += child->size_bytes;
                continue;
            }
            const auto& dir = static_cast<const vh::fs::model::Directory&>(*child);
            const auto totals = vh::rbac::fs::visibility::visibleTotals(user, child).value_or(
                vh::rbac::fs::visibility::Totals{.size_bytes = dir.size_bytes, .file_count = dir.file_count,
                                                 .subdirectory_count = dir.subdirectory_count});
            files[i]["size_bytes"] = totals.size_bytes;
            files[i]["file_count"] = totals.file_count;
            files[i]["subdirectory_count"] = totals.subdirectory_count;
            listedSize += totals.size_bytes;
        }
        entryJson["size_bytes"] = listedSize;
    }

    return {
        {"vault", engine->vault->name},
        {"path", path.string()},
        {"entry", std::move(entryJson)},
        {"files", std::move(files)}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::remove(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto user = session->user;
    if (!user) throw std::runtime_error("User not authenticated");
    if (user->id == 0) throw std::runtime_error("User not authenticated");

    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto path = std::filesystem::path(payload.at("path").get<std::string>());

    vh::ops::fs::remove(user, vaultId, path);
    return {{"path", path.string()}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::shareEntryJson(const vh::fs::model::Entry& entry, const vh::share::Principal& principal) {
    json out = {
        {"id", entry.id},
        {"name", entry.name},
        {"path", vh::share::TargetResolver::shareRelativePath(principal, entry.path.string())},
        {"type", entry.isDirectory() ? "directory" : "file"},
        {"size_bytes", entry.size_bytes},
        {"created_at", vh::db::encoding::timestampToString(entry.created_at)},
        {"updated_at", vh::db::encoding::timestampToString(entry.updated_at)}
    };

    if (entry.isDirectory()) {
        const auto& dir = static_cast<const vh::fs::model::Directory&>(entry);
        out["file_count"] = dir.file_count;
        out["subdirectory_count"] = dir.subdirectory_count;
    } else {
        const auto& file = static_cast<const vh::fs::model::File&>(entry);
        out["mime_type"] = file.mime_type ? json(*file.mime_type) : json(nullptr);
        // The same server-authoritative plan human listings carry; the share's capabilities still gate each lane.
        out["preview"] = vh::preview::classify(file);
    }
    return out;
}

json Storage::shareCompatibilityMetadata(const json& payload, const std::shared_ptr<Session>& session) try {
    auto response = shareMetadataResponse(payload, session, ShareReadPathStyle::Compatibility);
    return {{"entry", std::move(response.at("entry"))}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Storage::shareCompatibilityList(const json& payload, const std::shared_ptr<Session>& session) try {
    auto response = shareListResponse(payload, session, ShareReadPathStyle::Compatibility);
    return {
        {"path", std::move(response.at("path"))},
        {"entries", std::move(response.at("files"))}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

void Storage::setShareManagerFactoryForTesting(ShareManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share manager factory is required");
    shareManagerFactory() = std::move(factory);
}

void Storage::resetShareManagerFactoryForTesting() {
    shareManagerFactory() = defaultShareManager;
}

void Storage::setShareResolverFactoryForTesting(ShareResolverFactory factory) {
    if (!factory) throw std::invalid_argument("Share target resolver factory is required");
    shareResolverFactory() = std::move(factory);
}

void Storage::resetShareResolverFactoryForTesting() {
    shareResolverFactory() = defaultShareResolver;
}
