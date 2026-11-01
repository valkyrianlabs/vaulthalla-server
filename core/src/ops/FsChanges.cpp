#include "ops/FsChanges.hpp"

#include "db/encoding/timestamp.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "identities/User.hpp"
#include "rbac/fs/Visibility.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <utility>

namespace vh::ops::fs_changes {

namespace {

using Change = db::query::fs::Change;
using EntryPtr = std::shared_ptr<vh::fs::model::Entry>;
using FsAction = rbac::permission::vault::FilesystemAction;

std::shared_ptr<storage::Engine> engineFor(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    return manager ? manager->getEngine(vaultId) : nullptr;
}

// Lookup on what a change names, judged on a stand-in entry of its type at its path (a deleted entry has no other).
class Visibility {
public:
    Visibility(Actor actor, std::shared_ptr<storage::Engine> engine) : actor_(std::move(actor)), engine_(std::move(engine)) {
        const auto root = runtime::Deps::get().fsCache->getEntry(engine_->vaultPathToFusePath("/"));
        whole_ = root && rbac::fs::visibility::seesWholeSubtree(actor_, root);
    }

    [[nodiscard]] bool sees(const Change& change, const std::string& path, const std::optional<uint32_t> parentId) const {
        if (whole_) return true;
        EntryPtr probe;
        if (change.entry_type == "directory") probe = std::make_shared<vh::fs::model::Directory>();
        else if (change.entry_type == "symlink") probe = std::make_shared<vh::fs::model::Symlink>();
        else probe = std::make_shared<vh::fs::model::File>();
        probe->id = change.entry_id;
        probe->vault_id = static_cast<int32_t>(change.vault_id);
        if (parentId) probe->parent_id = static_cast<int32_t>(*parentId);
        probe->name = std::filesystem::path(path).filename().string();
        probe->path = path;
        probe->fuse_path = engine_->vaultPathToFusePath(path);
        return rbac::fs::visibility::canLookup(actor_, probe);
    }

private:
    Actor actor_;
    std::shared_ptr<storage::Engine> engine_;
    bool whole_{false};
};

}

bool canFollow(const Actor& actor, const uint32_t vaultId) {
    if (!actor) return false;
    const auto engine = engineFor(vaultId);
    if (!engine) return false;
    const rbac::resolver::vault::QuietFilesystemDenials quiet;  // a "no" is an answer here (subscriptions re-check)
    return rbac::resolver::Vault::has<FsAction>(
        {.user = actor, .permission = FsAction::List, .vault_id = vaultId, .path = engine->vaultPathToFusePath("/")});
}

std::vector<Change> visibleTo(const Actor& actor, const uint32_t vaultId, std::vector<Change> changes) {
    const auto engine = engineFor(vaultId);
    if (!engine) return {};
    const Visibility visibility(actor, engine);
    std::vector<Change> out;
    out.reserve(changes.size());
    for (auto& change : changes) {
        const bool now = visibility.sees(change, change.path, change.parent_id);
        if (!change.old_path) {
            if (now) out.push_back(std::move(change));
            continue;
        }
        const bool before = visibility.sees(change, *change.old_path, change.old_parent_id);
        if (!now && !before) continue;
        if (now && !before) change.kind = "create";
        if (!now) {
            change.kind = "delete";
            change.path = *change.old_path;
            change.name = std::filesystem::path(change.path).filename().string();
            change.parent_id = change.old_parent_id;
        }
        if (!now || !before) {
            change.old_path.reset();
            change.old_parent_id.reset();
        }
        out.push_back(std::move(change));
    }
    return out;
}

ListResult list(const Actor& actor, const ListRequest& request) {
    requireActor(actor);
    if (request.limit < 1 || request.limit > kMaxLimit)
        throw Invalid("limit must be between 1 and " + std::to_string(kMaxLimit));
    if (!engineFor(request.vault_id)) throw NotFound("vault " + std::to_string(request.vault_id) + " not found");
    if (!canFollow(actor, request.vault_id)) throw Denied("You may not browse this vault");

    db::query::fs::ChangeLog::sequence();
    ListResult out{.vault_id = request.vault_id};
    if (!request.since) {
        out.revision = db::query::fs::ChangeLog::revision();
        return out;
    }
    auto page = db::query::fs::ChangeLog::list(request.vault_id, actor->id, *request.since, request.limit);
    out.revision = page.revision;
    out.more = page.more;
    out.expired = page.expired;
    out.changes = visibleTo(actor, request.vault_id, std::move(page.changes));
    return out;
}

nlohmann::json toJson(const Change& change) {
    nlohmann::json j = {
        {"revision", change.revision},
        {"kind", change.kind},
        {"entry_id", change.entry_id},
        {"type", change.entry_type ? nlohmann::json(*change.entry_type) : nlohmann::json(nullptr)},
        {"parent_id", change.parent_id ? nlohmann::json(*change.parent_id) : nlohmann::json(nullptr)},
        {"name", change.name},
        {"path", change.path},
        {"changed_at", db::encoding::timestampToString(change.changed_at)},
    };
    if (change.old_path) {
        j["old_path"] = *change.old_path;
        j["old_parent_id"] = change.old_parent_id ? nlohmann::json(*change.old_parent_id) : nlohmann::json(nullptr);
    }
    return j;
}

nlohmann::json toJson(const ListResult& result) {
    auto changes = nlohmann::json::array();
    for (const auto& change : result.changes) changes.push_back(toJson(change));
    return {{"vault_id", result.vault_id},
            {"revision", result.revision},
            {"changes", std::move(changes)},
            {"more", result.more},
            {"expired", result.expired}};
}

}
