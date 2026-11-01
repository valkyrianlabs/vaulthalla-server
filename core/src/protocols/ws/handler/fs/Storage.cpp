#include "protocols/ws/handler/fs/Storage.hpp"
#include "protocols/ws/handler/RequestErrors.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/query/sync/Operation.hpp"
#include "protocols/ws/Session.hpp"
#include "storage/Manager.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "rbac/Actor.hpp"
#include "rbac/fs/Placement.hpp"
#include "rbac/fs/Visibility.hpp"
#include "rbac/role/Vault.hpp"
#include "vault/model/Vault.hpp"
#include "identities/User.hpp"
#include "protocols/ws/handler/fs/Upload.hpp"
#include "protocols/ws/handler/share/Upload.hpp"
#include "storage/Engine.hpp"
#include "runtime/Deps.hpp"
#include "fs/Filesystem.hpp"
#include "sync/Controller.hpp"
#include "fs/cache/Registry.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/TargetResolver.hpp"
#include "sync/model/Operation.hpp"
#include "log/Registry.hpp"
#include "preview/Plan.hpp"
#include "ops/Error.hpp"

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

using SyncOperation = vh::sync::model::Operation;

[[nodiscard]] std::shared_ptr<SyncOperation> startMutationOperation(
    const std::shared_ptr<vh::storage::Engine>& engine,
    const std::filesystem::path& from,
    const std::filesystem::path& to,
    const unsigned int userId,
    const SyncOperation::Op op
) noexcept {
    try {
        if (!engine || !engine->paths) return nullptr;

        const auto fuseFrom = engine->vaultPathToFusePath(from);
        const auto entry = vh::runtime::Deps::get().fsCache->getEntry(fuseFrom);
        if (!entry) return nullptr;

        auto operation = std::make_shared<SyncOperation>(entry, to, userId, op);
        operation->status = SyncOperation::Status::InProgress;
        vh::db::query::sync::Operation::createOperation(operation);
        return operation;
    } catch (const std::exception& e) {
        vh::log::Registry::ws()->warn("[Storage] Failed to record pending filesystem operation: {}", e.what());
        return nullptr;
    } catch (...) {
        vh::log::Registry::ws()->warn("[Storage] Failed to record pending filesystem operation");
        return nullptr;
    }
}

void finishMutationOperation(
    const std::shared_ptr<SyncOperation>& operation,
    const SyncOperation::Status status,
    const std::optional<std::string>& error = std::nullopt
) noexcept {
    if (!operation || operation->id == 0) return;

    try {
        vh::db::query::sync::Operation::markOperationStatus(operation->id, status, error);
    } catch (const std::exception& e) {
        vh::log::Registry::ws()->warn("[Storage] Failed to finish filesystem operation stat {}: {}", operation->id, e.what());
    } catch (...) {
        vh::log::Registry::ws()->warn("[Storage] Failed to finish filesystem operation stat {}", operation->id);
    }
}
}

json Storage::startUpload(const json& payload, const std::shared_ptr<Session>& session) try {
    if (session && session->isShareMode())
        return vh::protocols::ws::handler::share::Upload::nativeStart(payload, session);

    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto path = std::filesystem::path(payload.at("path").get<std::string>());

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("Unknown storage engine");

    const auto uploadId = Session::generateUUIDv4();
    const auto absPath = engine->paths->absPath(path, PathType::VAULT_ROOT);
    const auto tmpPath = absPath.parent_path() / (".upload-" + uploadId + ".part");

    enforcePermission(
        session,
        engine,
        path,
        permission::vault::FilesystemAction::Write,
        "Permission denied: User does not have upload permission for this path in the vault"
    );

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

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("Unknown storage engine");

    enforcePermission(
        session,
        engine,
        path,
        permission::vault::FilesystemAction::Write,
        "Permission denied: User does not have upload permission for this path in the vault"
    );

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

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));

    enforcePermission(
        session,
        engine,
        path,
        permission::vault::FilesystemAction::Touch,
        "Permission denied: User does not have create-directory permission for this path in the vault"
    );

    // The engine refuses both with one untyped error; tell them apart first (same text) so the answer is typed.
    if (Filesystem::exists(engine->vaultPathToFusePath(path)))
        throw vh::ops::Conflict("Failed to create directory: " + path.string());
    if (const auto parent = path.parent_path(); !parent.empty() && !Filesystem::exists(engine->vaultPathToFusePath(parent)))
        throw vh::ops::NotFound("Failed to create directory: " + path.string());

    engine->mkdir(path, session->user);
    runtime::Deps::get().syncController->runNow(vaultId);

    return {{"path", path.string()}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

namespace {

// The folder an entry at `path` (vault-relative) is in; "/" for a top-level entry.
[[nodiscard]] std::filesystem::path parentFolder(const std::filesystem::path& path) {
    auto normal = path.lexically_normal();
    if (!normal.has_filename() && normal.has_relative_path()) normal = normal.parent_path();  // "/a/b/" -> "/a/b"
    const auto parent = normal.parent_path();
    return parent.empty() || parent == normal ? std::filesystem::path("/") : parent;
}

}

// The rule fs.entry.copy applies to every entry it writes, and what fs.dir.create and an upload check: Touch for a
// folder, Write for a file or symlink, judged at the new path, for the entry and (a folder) everything it carries. A
// rename within the entry's own folder adds nothing to that folder, so the source's Move/Rename is enough there, as
// before. Checked before the endpoints are looked up, so a refused caller learns nothing about the destination.
void Storage::enforceCreateAtDestination(const std::shared_ptr<Session>& session,
                                         const std::shared_ptr<Engine>& engine,
                                         const std::filesystem::path& from,
                                         const std::filesystem::path& to) {
    if (parentFolder(from) == parentFolder(to)) return;

    // A missing source is requireTransferEndpoints' not_found.
    const auto source = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(from));
    if (!source) return;

    enforcePermission(session, engine, to, vh::rbac::fs::placement::createAction(*source),
                      "Permission denied: User cannot create " + to.string() + " in the vault");
    if (const auto refused = vh::rbac::fs::placement::firstRefusedDescendant(session->user, source,
                                                                             engine->vaultPathToFusePath(to)))
        throw vh::ops::Denied("Permission denied: User cannot create " +
                              engine->fusePathToVaultPath(*refused).string() + " in the vault");
}

namespace {

// A move/rename/copy whose source or destination folder is missing is a typed not_found for the console (the FUSE
// equivalent is ENOENT), checked after the source permission so nothing is revealed to a caller without it. Before,
// the engine threw an untyped "Failed to rename" error (found by the integration engine, tools/harness).
void requireTransferEndpoints(const std::shared_ptr<Engine>& engine, const std::filesystem::path& from,
                              const std::filesystem::path& to) {
    if (!Filesystem::exists(engine->vaultPathToFusePath(from)))
        throw vh::ops::NotFound("source does not exist: " + from.string());
    auto parent = to.parent_path();
    if (parent.empty()) parent = "/";
    if (!Filesystem::exists(engine->vaultPathToFusePath(parent)))
        throw vh::ops::NotFound("destination folder does not exist: " + parent.string());
}

// The engine reports a taken destination (EEXIST) and a folder moved or copied into itself (EINVAL) with the same
// untyped error as a fault. Once it has failed (nothing changed), tell those refusals apart and rethrow them typed,
// with the engine's text unchanged; anything else (an ops refusal from the copy authorizer included) as it was.
[[noreturn]] void rethrowTransferRefusal(const std::shared_ptr<Engine>& engine, const std::filesystem::path& from,
                                         const std::filesystem::path& to, const std::exception& e) {
    if (dynamic_cast<const vh::ops::Error*>(&e)) throw;
    const auto source = from.lexically_normal().string();
    const auto destination = to.lexically_normal().string();
    if (destination != source && Filesystem::exists(engine->vaultPathToFusePath(to))) throw vh::ops::Conflict(e.what());
    if (destination.starts_with(source.ends_with('/') ? source : source + "/")) throw vh::ops::Invalid(e.what());
    throw;
}

}

json Storage::move(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto from = std::filesystem::path(payload.at("from").get<std::string>());
    const auto to = std::filesystem::path(payload.at("to").get<std::string>());

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));

    enforcePermission(
        session,
        engine,
        from,
        permission::vault::FilesystemAction::Move,
        "Permission denied: User does not have move permission for the source path in the vault"
    );
    enforceCreateAtDestination(session, engine, from, to);
    requireTransferEndpoints(engine, from, to);

    auto operation = startMutationOperation(engine, from, to, session->user->id, SyncOperation::Op::Move);
    try {
        engine->move(from, to, session->user);
        finishMutationOperation(operation, SyncOperation::Status::Success);
    } catch (const std::exception& e) {
        finishMutationOperation(operation, SyncOperation::Status::Failed, e.what());
        rethrowTransferRefusal(engine, from, to, e);
    }
    runtime::Deps::get().syncController->runNow(vaultId);

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

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));

    enforcePermission(
        session,
        engine,
        from,
        permission::vault::FilesystemAction::Rename,
        "Permission denied: User does not have rename permission for the source path in the vault"
    );
    enforceCreateAtDestination(session, engine, from, to);
    requireTransferEndpoints(engine, from, to);

    auto operation = startMutationOperation(engine, from, to, session->user->id, SyncOperation::Op::Rename);
    try {
        engine->rename(from, to, session->user);
        finishMutationOperation(operation, SyncOperation::Status::Success);
    } catch (const std::exception& e) {
        finishMutationOperation(operation, SyncOperation::Status::Failed, e.what());
        rethrowTransferRefusal(engine, from, to, e);
    }
    runtime::Deps::get().syncController->runNow(vaultId);

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

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));

    enforcePermission(
        session,
        engine,
        from,
        permission::vault::FilesystemAction::Copy,
        "Permission denied: User does not have copy permission for the source path in the vault"
    );
    requireTransferEndpoints(engine, from, to);

    // Every copied entry passes the checks a single one would (#167), before anything is written: Copy on the source,
    // Read on a source file (the copy is readable wherever it lands, so it must not route around a download deny),
    // and creating it at the destination: Write for a file or symlink (as an upload), Touch for a folder (as mkdir).
    const auto authorize = [&](const vh::fs::model::Entry& source, const std::filesystem::path& destinationFuse) {
        const auto destination = engine->fusePathToVaultPath(destinationFuse);
        enforcePermission(session, engine, source.path, permission::vault::FilesystemAction::Copy,
                          "Permission denied: User does not have copy permission for " + source.path.string());
        if (!source.isDirectory())
            enforcePermission(session, engine, source.path, permission::vault::FilesystemAction::Read,
                              "Permission denied: User does not have read permission for " + source.path.string());
        enforcePermission(session, engine, destination,
                          source.isDirectory() ? permission::vault::FilesystemAction::Touch
                                               : permission::vault::FilesystemAction::Write,
                          "Permission denied: User cannot create " + destination.string() + " in the vault");
    };

    auto operation = startMutationOperation(engine, from, to, session->user->id, SyncOperation::Op::Copy);
    try {
        engine->copy(from, to, session->user->id, authorize);
        finishMutationOperation(operation, SyncOperation::Status::Success);
    } catch (const std::exception& e) {
        finishMutationOperation(operation, SyncOperation::Status::Failed, e.what());
        rethrowTransferRefusal(engine, from, to, e);
    }
    runtime::Deps::get().syncController->runNow(vaultId);

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

    const auto userId = user->id;
    if (userId == 0) throw std::runtime_error("User not authenticated");

    const auto vaultId = payload.at("vault_id").get<uint32_t>();
    const auto path = std::filesystem::path(payload.at("path").get<std::string>());

    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw vh::ops::NotFound("No storage engine found for vault with ID: " + std::to_string(vaultId));

    enforcePermission(
        session,
        engine,
        path,
        permission::vault::FilesystemAction::Delete,
        "Permission denied: User does not have delete permission for this path in the vault"
    );

    engine->remove(path, userId);
    runtime::Deps::get().syncController->runNow(vaultId);

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
