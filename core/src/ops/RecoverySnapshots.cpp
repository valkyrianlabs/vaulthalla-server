#include "ops/Recovery.hpp"
#include "ops/RecoveryAccess.hpp"

#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "identities/User.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "recovery/local/Points.hpp"
#include "recovery/local/Snapshots.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <filesystem>

// ops::recovery::createSnapshot: the authorizing wrapper around recovery::local::snapshots::create. The rest of
// ops::recovery lives with its owners (policy, points/restore dispatch).
namespace vh::ops::recovery {

namespace {

using SnapshotFsAction = rbac::permission::vault::FilesystemAction;

bool snapshotAllows(const Actor& actor, const storage::Engine& engine, const std::filesystem::path& vaultPath,
                    const SnapshotFsAction action) {
    return rbac::resolver::Vault::has<SnapshotFsAction>({
        .user = actor,
        .permission = action,
        .vault_id = engine.vault->id,
        .path = engine.vaultPathToFusePath(vaultPath)
    });
}

}

PointDetail createSnapshot(const Actor& actor, const uint32_t vaultId, const SnapshotRequest& req) {
    requireActor(actor);
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine || !engine->vault) throw NotFound("vault " + std::to_string(vaultId) + " not found");
    if (req.path.empty() || req.path.front() != '/') throw Invalid("a snapshot path is a vault path starting with '/'");

    // Nothing about the vault's recovery settings or the path's contents is revealed to someone who can't see it.
    const auto root = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(req.path));
    if (!root) {
        // "No such path" only to someone who could see it there (the nearest existing folder lists for them).
        access::Gate gate(actor, engine);
        if (!gate.canRead(gate.existingAncestor(req.path), true))
            throw Denied("permission denied: you can't snapshot " + req.path);
        throw NotFound("no such path in the vault: " + req.path);
    }
    if (!snapshotAllows(actor, *engine, req.path, root->isDirectory() ? SnapshotFsAction::List : SnapshotFsAction::Read))
        throw Denied("permission denied: you can't snapshot " + req.path);

    // Every entry passes before anything is captured: Read + Copy on each file (a snapshot is a copy that can be
    // restored anywhere, so it must not route around a download or copy deny), List on each directory.
    const auto authorize = [&](const fs::model::Entry& entry) {
        if (entry.isSymlink()) return;   // not captured
        if (entry.isDirectory()) {
            if (!snapshotAllows(actor, *engine, entry.path, SnapshotFsAction::List))
                throw Denied("permission denied: snapshot needs list permission on " + entry.path.string());
            return;
        }
        if (!snapshotAllows(actor, *engine, entry.path, SnapshotFsAction::Read))
            throw Denied("permission denied: snapshot needs download permission on " + entry.path.string());
        if (!snapshotAllows(actor, *engine, entry.path, SnapshotFsAction::Copy))
            throw Denied("permission denied: snapshot needs copy permission on " + entry.path.string());
    };

    const auto created = vh::recovery::local::snapshots::create(engine, actor, req.path, req.name, authorize);
    auto detail = vh::recovery::local::points::detail(
        vh::recovery::RecoveryId{.type = vh::recovery::RecoveryId::Type::Snapshot,
                                 .id = static_cast<uint64_t>(created.snapshot_id)});
    if (!detail) throw NotFound("the snapshot was deleted right after it was taken");
    return std::move(*detail);
}

}
