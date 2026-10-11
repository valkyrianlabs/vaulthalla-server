#include "ops/Conflicts.hpp"

#include "db/encoding/timestamp.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/model/File.hpp"
#include "identities/Group.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/permission/vault/sync/Action.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

namespace vh::ops::conflicts {

namespace {

using SyncActionPerm = rbac::permission::vault::sync::SyncActionPermissions;
using FsAction = rbac::permission::vault::FilesystemAction;

std::shared_ptr<storage::CloudEngine> cloudEngineFor(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine || !engine->vault || engine->type() != storage::StorageType::Cloud) return nullptr;
    return std::static_pointer_cast<storage::CloudEngine>(engine);
}

bool fsAllows(const Actor& actor, const storage::Engine& engine, const std::string& vaultPath, const FsAction action) {
    return rbac::resolver::Vault::has<FsAction>({
        .user = actor,
        .permission = action,
        .vault_id = engine.vault->id,
        .path = engine.vaultPathToFusePath(vaultPath)
    });
}

std::shared_ptr<fs::model::File> previewFile(const ConflictRecord& r) {
    auto f = std::make_shared<fs::model::File>();
    f->id = r.file_id;
    f->vault_id = r.vault_id;
    f->name = r.name;
    f->path = r.path;
    f->size_bytes = r.local.size_bytes;
    f->mime_type = r.local.mime_type ? r.local.mime_type : r.remote.mime_type;
    return f;
}

nlohmann::json optionalTime(const std::optional<std::time_t>& t) {
    if (!t || *t == 0) return nullptr;
    return db::encoding::timestampToString(*t);
}

template <typename T>
nlohmann::json orNull(const std::optional<T>& v) {
    if (!v) return nullptr;
    return *v;
}

nlohmann::json sideJson(const db::query::sync::ConflictSide& side, const bool remote) {
    return {
        {"size_bytes", side.size_bytes},
        {"mime_type", orNull(side.mime_type)},
        {"content_hash", orNull(side.content_hash)},
        {"modified_at", optionalTime(side.modified_at)},
        {"etag", remote ? orNull(side.etag) : nlohmann::json(nullptr)},
        {"encrypted", remote ? orNull(side.encrypted) : nlohmann::json(nullptr)}
    };
}

ItemResult failure(const uint32_t id, std::string status, std::string message) {
    return {.conflict_id = id, .ok = false, .status = std::move(status), .message = std::move(message)};
}

}

Decision parseDecision(const std::string& value) {
    if (value == "keep_local" || value == "local" || value == "keep-local") return Decision::KeepLocal;
    if (value == "keep_remote" || value == "remote" || value == "keep-remote") return Decision::KeepRemote;
    throw Invalid("resolution must be keep_local or keep_remote");
}

bool canResolveIn(const Actor& actor, const uint32_t vaultId) {
    if (!actor) return false;
    // The owner's self scope and admins' vault globals, through the vault resolver.
    if (rbac::resolver::Vault::has<SyncActionPerm>({
            .user = actor, .permission = SyncActionPerm::ResolveConflicts, .vault_id = vaultId}))
        return true;
    // A vault role on this vault, the account's own or one of its groups'. The vault resolver only reads vault
    // globals for sync permissions, so without this a member could never resolve conflicts in someone else's vault.
    const auto grants = [&](const std::unordered_map<uint32_t, std::shared_ptr<const rbac::role::Vault>>& roles) {
        const auto it = roles.find(vaultId);
        return it != roles.end() && it->second && it->second->sync.action.canResolveConflicts();
    };
    const auto view = actor->authz();
    if (!view.authorizing()) return false;
    if (grants(view.user->roles.vaults)) return true;
    return std::ranges::any_of(view.groups, [&](const auto& group) { return grants(group->roles.vaults); });
}

Summary summary(const Actor& actor) {
    requireActor(actor);
    Summary out;
    for (const auto& [vaultId, count] : db::query::sync::Conflict::openCountsByVault()) {
        const auto engine = cloudEngineFor(vaultId);
        if (!engine || !canResolveIn(actor, vaultId)) continue;
        out.total += count;
        out.vaults.push_back({.vault_id = vaultId, .vault_name = engine->vault->name, .count = count});
    }
    std::ranges::sort(out.vaults, [](const VaultCount& a, const VaultCount& b) {
        return a.vault_name == b.vault_name ? a.vault_id < b.vault_id : a.vault_name < b.vault_name;
    });
    return out;
}

std::vector<ConflictView> list(const Actor& actor, const std::optional<uint32_t> vaultId) {
    requireActor(actor);
    std::optional<std::vector<uint32_t>> scope;
    if (vaultId) {
        if (!db::query::vault::Vault::getVault(*vaultId)) throw NotFound("vault not found: " + std::to_string(*vaultId));
        if (!canResolveIn(actor, *vaultId))
            throw Denied("you do not have permission to resolve sync conflicts in this vault");
        scope = std::vector<uint32_t>{*vaultId};
    }

    std::vector<ConflictView> out;
    std::unordered_map<uint32_t, std::shared_ptr<storage::CloudEngine>> allowed;  // vault -> engine (null: denied)
    for (auto& record : db::query::sync::Conflict::listOpen(scope)) {
        auto it = allowed.find(record.vault_id);
        if (it == allowed.end()) {
            const auto engine = cloudEngineFor(record.vault_id);
            it = allowed.emplace(record.vault_id,
                                 engine && canResolveIn(actor, record.vault_id) ? engine : nullptr).first;
        }
        const auto& engine = it->second;
        if (!engine) continue;
        ConflictView view;
        view.vault_name = engine->vault->name;
        view.can_overwrite = !record.path.empty() && fsAllows(actor, *engine, record.path, FsAction::Overwrite);
        view.preview = preview::classify(*previewFile(record));
        view.record = std::move(record);
        out.push_back(std::move(view));
    }
    return out;
}

ResolveResult resolve(const Actor& actor, const Decision decision, const std::vector<uint32_t>& ids) {
    requireActor(actor);
    if (ids.empty()) throw Invalid("no conflicts to resolve");
    if (ids.size() > kMaxResolveBatch)
        throw Invalid("at most " + std::to_string(kMaxResolveBatch) + " conflicts can be resolved at once");

    ResolveResult out;
    out.decision = decision;
    std::set<uint32_t> seen;
    for (const auto id : ids) {
        if (!seen.insert(id).second) continue;
        ItemResult item;
        try {
            const auto record = db::query::sync::Conflict::get(id);
            if (!record) {
                item = failure(id, "not_found", "no such conflict");
            } else if (!canResolveIn(actor, record->vault_id)) {
                item = failure(id, "denied", "you do not have permission to resolve sync conflicts in this vault");
            } else if (!record->open()) {
                item = failure(id, "conflict", "this conflict was already closed (" + record->resolution + ")");
            } else if (const auto engine = cloudEngineFor(record->vault_id); !engine) {
                item = failure(id, "invalid", "conflicts can only be resolved in remote (S3/R2) vaults");
            } else if (record->path.empty() || !fsAllows(actor, *engine, record->path, FsAction::Overwrite)) {
                item = failure(id, "denied", "you need Overwrite on " + (record->path.empty() ? "the file" : record->path));
            } else {
                vh::sync::ConflictResolver::resolve(engine, *record, decision);
                item = {.conflict_id = id, .ok = true, .status = "resolved", .message = std::nullopt};
                log::Registry::audit()->info("[ops::conflicts] {} resolved sync conflict {} on '{}' in vault {}: {}",
                                             actor->name(), id, record->path, record->vault_id,
                                             vh::sync::toString(decision));
            }
        } catch (const vh::sync::ConflictStale& e) {
            item = failure(id, "conflict", e.what());
        } catch (const storage::ContentUnavailable& e) {
            item = failure(id, "unavailable", e.what());
        } catch (const storage::s3::RequestBudgetExceeded& e) {
            item = failure(id, "unavailable", e.what());
        } catch (const Error& e) {
            item = failure(id, "invalid", e.what());
        } catch (const std::exception& e) {
            log::Registry::sync()->error("[ops::conflicts] Resolving conflict {} failed: {}", id, e.what());
            item = failure(id, "error", e.what());
        }
        if (item.ok) ++out.resolved;
        else ++out.failed;
        out.results.push_back(std::move(item));
    }
    return out;
}

PreviewTarget previewTarget(const Actor& actor, const uint32_t conflictId) {
    requireActor(actor);
    auto record = db::query::sync::Conflict::get(conflictId);
    if (!record) throw NotFound("no such conflict");
    if (!canResolveIn(actor, record->vault_id))
        throw Denied("you do not have permission to resolve sync conflicts in this vault");
    const auto engine = cloudEngineFor(record->vault_id);
    if (!engine) throw NotFound("no such conflict");
    if (record->path.empty() || !fsAllows(actor, *engine, record->path, FsAction::Read))
        throw Denied("you need Read on the file");
    if (!record->open()) throw Conflict("this conflict was already closed (" + record->resolution + ")");
    auto file = db::query::fs::File::getFileById(record->file_id);
    if (!file) throw NotFound("no such conflict");
    return {.record = std::move(*record), .engine = engine, .file = std::move(file)};
}

void to_json(nlohmann::json& j, const ConflictView& view) {
    const auto& r = view.record;
    auto reasons = nlohmann::json::array();
    for (const auto& reason : r.reasons) reasons.push_back({{"code", reason.code}, {"message", reason.message}});
    j = {
        {"id", r.id},
        {"vault_id", r.vault_id},
        {"vault_name", view.vault_name},
        {"file_id", r.file_id},
        {"path", r.path},
        {"name", r.name},
        {"type", r.type},
        {"reasons", reasons},
        {"created_at", optionalTime(r.created_at)},
        {"updated_at", optionalTime(r.updated_at)},
        {"local", sideJson(r.local, false)},
        {"remote", sideJson(r.remote, true)},
        {"can_overwrite", view.can_overwrite},
        {"preview", view.preview}
    };
}

void to_json(nlohmann::json& j, const Summary& summary) {
    auto vaults = nlohmann::json::array();
    for (const auto& v : summary.vaults)
        vaults.push_back({{"vault_id", v.vault_id}, {"vault_name", v.vault_name}, {"count", v.count}});
    j = {{"total", summary.total}, {"vaults", vaults}};
}

void to_json(nlohmann::json& j, const ResolveResult& result) {
    auto items = nlohmann::json::array();
    for (const auto& item : result.results)
        items.push_back({{"conflict_id", item.conflict_id}, {"ok", item.ok}, {"status", item.status},
                         {"message", orNull(item.message)}});
    j = {
        {"resolution", vh::sync::toString(result.decision)},
        {"resolved", result.resolved},
        {"failed", result.failed},
        {"results", items}
    };
}

}
