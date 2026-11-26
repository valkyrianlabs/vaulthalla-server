#include "ops/Fs.hpp"

#include "audit/Trail.hpp"
#include "db/query/sync/Operation.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/http/upload/CreateClaim.hpp"
#include "rbac/fs/Placement.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "sync/model/Operation.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

// Inside vh::ops::fs a bare `fs::` is this namespace: the filesystem layer is always vh::fs, and every other subsystem
// is named from vh:: too (vh::ops has its own audit, config and recovery namespaces).
namespace vh::ops::fs {

namespace {

using EnginePtr = std::shared_ptr<vh::storage::Engine>;
using FsAction = vh::rbac::permission::vault::FilesystemAction;
using SyncOperation = vh::sync::model::Operation;

[[nodiscard]] EnginePtr engineFor(const uint32_t vaultId, const std::string& missing) {
    const auto& manager = vh::runtime::Deps::get().storageManager;
    auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine) throw NotFound(missing);
    return engine;
}

[[nodiscard]] EnginePtr engineFor(const uint32_t vaultId) {
    return engineFor(vaultId, "No storage engine found for vault with ID: " + std::to_string(vaultId));
}

// The filesystem permission `action` at `path` (vault-relative), as the vault's RBAC resolves it.
void require(const Actor& actor, const EnginePtr& engine, const std::filesystem::path& path, const FsAction action,
             const std::string_view error) {
    requireActor(actor);
    if (!engine || !engine->vault) throw std::runtime_error("Internal server error: Storage engine not available");
    if (!vh::rbac::resolver::Vault::has<FsAction>({.user = actor,
                                                   .permission = action,
                                                   .vault_id = engine->vault->id,
                                                   .path = engine->vaultPathToFusePath(path)}))
        throw Denied(std::string(error));
}

[[nodiscard]] bool existsAt(const EnginePtr& engine, const std::filesystem::path& path) {
    return vh::fs::Filesystem::exists(engine->vaultPathToFusePath(path));
}

// File operations go to the audit trail (#323) by entry id: never a file or folder name.
[[nodiscard]] std::optional<uint64_t> entryIdAt(const EnginePtr& engine, const std::filesystem::path& path) {
    try {
        if (const auto entry = vh::runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path)))
            return entry->id;
    } catch (const std::exception&) {}
    return std::nullopt;
}

void auditFs(const Actor& actor, const EnginePtr& engine, const std::string& action, const std::string& verb,
             const std::optional<uint64_t> entryId, nlohmann::json details = nlohmann::json::object()) {
    if (!actor) return;
    vh::audit::record({.action = action, .actor_id = actor->id, .actor = actor->name(), .vault_id = engine->vault->id,
                       .entry_id = entryId, .details = std::move(details)},
                      "[fs] " + actor->name() + " " + verb + " entry " +
                          (entryId ? std::to_string(*entryId) : std::string("?")) + " in vault " +
                          std::to_string(engine->vault->id));
}

void syncSoon(const uint32_t vaultId) {
    vh::runtime::Deps::get().syncController->runNow(vaultId);
}

// The `operations` row of a move, rename or copy: pending while it runs, then its outcome. Best effort: a failure to
// record never fails the operation.
[[nodiscard]] std::shared_ptr<SyncOperation> startOperation(const EnginePtr& engine, const std::filesystem::path& from,
                                                            const std::filesystem::path& to, const unsigned int userId,
                                                            const SyncOperation::Op op) noexcept {
    try {
        if (!engine || !engine->paths) return nullptr;

        const auto entry = vh::runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(from));
        if (!entry) return nullptr;

        auto operation = std::make_shared<SyncOperation>(entry, to, userId, op);
        operation->status = SyncOperation::Status::InProgress;
        vh::db::query::sync::Operation::createOperation(operation);
        return operation;
    } catch (const std::exception& e) {
        vh::log::Registry::fs()->warn("[ops::fs] Failed to record pending filesystem operation: {}", e.what());
        return nullptr;
    } catch (...) {
        vh::log::Registry::fs()->warn("[ops::fs] Failed to record pending filesystem operation");
        return nullptr;
    }
}

void finishOperation(const std::shared_ptr<SyncOperation>& operation, const SyncOperation::Status status,
                     const std::optional<std::string>& error = std::nullopt) noexcept {
    if (!operation || operation->id == 0) return;

    try {
        vh::db::query::sync::Operation::markOperationStatus(operation->id, status, error);
    } catch (const std::exception& e) {
        vh::log::Registry::fs()->warn("[ops::fs] Failed to finish filesystem operation stat {}: {}", operation->id,
                                      e.what());
    } catch (...) {
        vh::log::Registry::fs()->warn("[ops::fs] Failed to finish filesystem operation stat {}", operation->id);
    }
}

// The folder an entry at `path` (vault-relative) is in; "/" for a top-level entry.
[[nodiscard]] std::filesystem::path parentFolder(const std::filesystem::path& path) {
    auto normal = path.lexically_normal();
    if (!normal.has_filename() && normal.has_relative_path()) normal = normal.parent_path();  // "/a/b/" -> "/a/b"
    const auto parent = normal.parent_path();
    return parent.empty() || parent == normal ? std::filesystem::path("/") : parent;
}

// The rule fs.entry.copy applies to every entry it writes, and what fs.dir.create and an upload check: Touch for a
// folder, Write for a file or symlink, judged at the new path, for the entry and (a folder) everything it carries. A
// rename within the entry's own folder adds nothing to that folder, so the source's Move/Rename is enough there, as
// before. Checked before the endpoints are looked up, so a refused caller learns nothing about the destination.
void requireCreateAtDestination(const Actor& actor, const EnginePtr& engine, const std::filesystem::path& from,
                                const std::filesystem::path& to) {
    if (parentFolder(from) == parentFolder(to)) return;

    // A missing source is requireTransferEndpoints' not_found.
    const auto source = vh::runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(from));
    if (!source) return;

    require(actor, engine, to, vh::rbac::fs::placement::createAction(*source),
            "Permission denied: User cannot create " + to.string() + " in the vault");
    if (const auto refused = vh::rbac::fs::placement::firstRefusedDescendant(actor, source,
                                                                             engine->vaultPathToFusePath(to)))
        throw Denied("Permission denied: User cannot create " + engine->fusePathToVaultPath(*refused).string() +
                     " in the vault");
}

// A move/rename/copy whose source or destination folder is missing is a typed not_found (the FUSE equivalent is
// ENOENT), checked after the source permission so nothing is revealed to a caller without it. Before, the engine
// threw an untyped "Failed to rename" error (found by the integration engine, tools/harness).
void requireTransferEndpoints(const EnginePtr& engine, const std::filesystem::path& from,
                              const std::filesystem::path& to) {
    if (!existsAt(engine, from)) throw NotFound("source does not exist: " + from.string());
    auto parent = to.parent_path();
    if (parent.empty()) parent = "/";
    if (!existsAt(engine, parent)) throw NotFound("destination folder does not exist: " + parent.string());
}

// The engine reports a taken destination (EEXIST) and a folder moved or copied into itself (EINVAL) with the same
// untyped error as a fault. Once it has failed (nothing changed), tell those refusals apart and rethrow them typed,
// with the engine's text unchanged; anything else (an ops refusal from the copy authorizer included) as it was.
[[noreturn]] void rethrowTransferRefusal(const EnginePtr& engine, const std::filesystem::path& from,
                                         const std::filesystem::path& to, const std::exception& e) {
    if (dynamic_cast<const Error*>(&e)) throw;
    const auto source = from.lexically_normal().string();
    const auto destination = to.lexically_normal().string();
    if (destination != source && existsAt(engine, to)) throw Conflict(e.what());
    if (destination.starts_with(source.ends_with('/') ? source : source + "/")) throw Invalid(e.what());
    throw;
}

enum class Transfer { Move, Rename };

void transfer(const Actor& actor, const uint32_t vaultId, const std::filesystem::path& from,
              const std::filesystem::path& to, const Transfer kind) {
    requireActor(actor);
    const auto engine = engineFor(vaultId);
    const bool isMove = kind == Transfer::Move;

    require(actor, engine, from, isMove ? FsAction::Move : FsAction::Rename,
            isMove ? "Permission denied: User does not have move permission for the source path in the vault"
                   : "Permission denied: User does not have rename permission for the source path in the vault");
    requireCreateAtDestination(actor, engine, from, to);
    requireTransferEndpoints(engine, from, to);

    const auto entryId = entryIdAt(engine, from);
    auto operation = startOperation(engine, from, to, actor->id,
                                    isMove ? SyncOperation::Op::Move : SyncOperation::Op::Rename);
    try {
        if (isMove) engine->move(from, to, actor);
        else engine->rename(from, to, actor);
        finishOperation(operation, SyncOperation::Status::Success);
        auditFs(actor, engine, isMove ? "fs.move" : "fs.rename", isMove ? "moved" : "renamed", entryId);
    } catch (const std::exception& e) {
        finishOperation(operation, SyncOperation::Status::Failed, e.what());
        rethrowTransferRefusal(engine, from, to, e);
    }
    syncSoon(vaultId);
}

}

void mkdir(const Actor& actor, const uint32_t vaultId, const std::filesystem::path& path) {
    requireActor(actor);
    const auto engine = engineFor(vaultId);

    require(actor, engine, path, FsAction::Touch,
            "Permission denied: User does not have create-directory permission for this path in the vault");

    // The engine refuses both with one untyped error; tell them apart first (same text) so the answer is typed.
    if (existsAt(engine, path)) throw Conflict("Failed to create directory: " + path.string());
    if (const auto parent = path.parent_path(); !parent.empty() && !existsAt(engine, parent))
        throw NotFound("Failed to create directory: " + path.string());

    engine->mkdir(path, actor);
    auditFs(actor, engine, "fs.mkdir", "created folder", entryIdAt(engine, path));
    syncSoon(vaultId);
}

void move(const Actor& actor, const uint32_t vaultId, const std::filesystem::path& from,
          const std::filesystem::path& to) {
    transfer(actor, vaultId, from, to, Transfer::Move);
}

void rename(const Actor& actor, const uint32_t vaultId, const std::filesystem::path& from,
            const std::filesystem::path& to) {
    transfer(actor, vaultId, from, to, Transfer::Rename);
}

void copy(const Actor& actor, const uint32_t vaultId, const std::filesystem::path& from,
          const std::filesystem::path& to) {
    requireActor(actor);
    const auto engine = engineFor(vaultId);

    require(actor, engine, from, FsAction::Copy,
            "Permission denied: User does not have copy permission for the source path in the vault");
    requireTransferEndpoints(engine, from, to);

    // Every copied entry passes the checks a single one would (#167), before anything is written: Copy on the source,
    // Read on a source file (the copy is readable wherever it lands, so it must not route around a download deny),
    // and creating it at the destination: Write for a file or symlink (as an upload), Touch for a folder (as mkdir).
    const auto authorize = [&](const vh::fs::model::Entry& source, const std::filesystem::path& destinationFuse) {
        const auto destination = engine->fusePathToVaultPath(destinationFuse);
        require(actor, engine, source.path, FsAction::Copy,
                "Permission denied: User does not have copy permission for " + source.path.string());
        if (!source.isDirectory())
            require(actor, engine, source.path, FsAction::Read,
                    "Permission denied: User does not have read permission for " + source.path.string());
        require(actor, engine, destination, source.isDirectory() ? FsAction::Touch : FsAction::Write,
                "Permission denied: User cannot create " + destination.string() + " in the vault");
    };

    auto operation = startOperation(engine, from, to, actor->id, SyncOperation::Op::Copy);
    try {
        engine->copy(from, to, actor->id, authorize);
        finishOperation(operation, SyncOperation::Status::Success);
        auditFs(actor, engine, "fs.copy", "copied", entryIdAt(engine, from),
                {{"copy_entry_id", entryIdAt(engine, to).value_or(0)}});
    } catch (const std::exception& e) {
        finishOperation(operation, SyncOperation::Status::Failed, e.what());
        rethrowTransferRefusal(engine, from, to, e);
    }
    syncSoon(vaultId);
}

void remove(const Actor& actor, const uint32_t vaultId, const std::filesystem::path& path) {
    requireActor(actor);
    if (actor->id == 0) throw Denied("not authenticated");
    const auto engine = engineFor(vaultId);

    require(actor, engine, path, FsAction::Delete,
            "Permission denied: User does not have delete permission for this path in the vault");

    const auto removedId = entryIdAt(engine, path);
    engine->remove(path, actor->id);
    auditFs(actor, engine, "fs.delete", "deleted", removedId);
    syncSoon(vaultId);
}

EnginePtr authorizeUpload(const Actor& actor, const uint32_t vaultId, const std::filesystem::path& path) {
    requireActor(actor);
    auto engine = engineFor(vaultId, "Unknown storage engine");
    require(actor, engine, path, FsAction::Write,
            "Permission denied: User does not have upload permission for this path in the vault");
    return engine;
}

void commitStaged(const Actor& actor, const StagedCommit& commit) {
    const auto engine = authorizeUpload(actor, commit.vault_id, commit.path);
    if (const auto err = vh::fs::Filesystem::rename(engine->vaultPathToFusePath(commit.staged),
                                                    engine->vaultPathToFusePath(commit.path), actor, engine);
        err)
        throw std::runtime_error(std::string("Failed to move uploaded file to final location: ") +
                                 std::strerror(err));
}

std::shared_ptr<vh::fs::model::File> commitSealed(const Actor& actor, const SealedCommit& commit) {
    requireActor(actor);
    if (!commit.sealed) throw Invalid("a sealed commit needs its sealed content");
    const auto& path = commit.path;
    if (path.empty() || !path.has_filename() || path.lexically_normal() == "/")
        throw Invalid("a sealed commit needs a file path: " + path.string());

    const auto engine = engineFor(commit.vault_id);
    const bool replace = commit.base.has_value();
    require(actor, engine, path, replace ? FsAction::Overwrite : FsAction::Write,
            replace ? "Permission denied: User does not have overwrite permission for this path in the vault"
                    : "Permission denied: User does not have upload permission for this path in the vault");

    const auto parent = parentFolder(path);
    if (!existsAt(engine, parent)) throw NotFound("destination folder does not exist: " + parent.string());

    const auto fusePath = engine->vaultPathToFusePath(path);
    const auto existing = vh::runtime::Deps::get().fsCache->getEntry(fusePath);
    // Creates of one path commit one at a time, with the HTTP lanes' creates too (same key): the second finds the
    // first's file and is refused, instead of both taking the new-file branch of Filesystem::createFile.
    std::optional<vh::protocols::http::upload::CreateClaim> claim;
    if (!replace) {
        claim.emplace(std::to_string(commit.vault_id) + ":" + path.string());
        if (!claim->held() || existing) throw Conflict("already exists: " + path.string());
    } else {
        if (!existing) throw ContentConflict("The file no longer exists: " + path.string());
        if (!std::dynamic_pointer_cast<vh::fs::model::File>(existing))
            throw Conflict("not a file: " + path.string());
    }

    // overwrite with expected_source_id: a create is "only if nothing is there", a replacement a compare-and-swap.
    const vh::fs::NewFileContext ctx{.path = path,
                                     .fuse_path = fusePath,
                                     .engine = engine,
                                     .user = actor,
                                     .overwrite = true,
                                     .expected_source_id = replace ? *commit.base : std::string{},
                                     .sealed = commit.sealed};
    std::shared_ptr<vh::fs::model::File> committed;
    try {
        committed = vh::fs::Filesystem::createFile(ctx);
    } catch (const vh::fs::ContentConflict& e) {
        if (replace) throw ContentConflict(e.what());
        throw Conflict("already exists: " + path.string());
    } catch (const std::filesystem::filesystem_error& e) {
        if (e.code() == std::errc::file_exists) throw Conflict("not a file: " + path.string());
        if (e.code() == std::errc::no_such_file_or_directory)
            throw NotFound("destination folder does not exist: " + parent.string());
        throw;
    }
    if (!committed) throw std::runtime_error("The commit produced no file: " + path.string());

    auditFs(actor, engine, "fs.commit", replace ? "replaced" : "created", committed->id,
            {{"replaced", replace}});
    syncSoon(commit.vault_id);
    return committed;
}

}
