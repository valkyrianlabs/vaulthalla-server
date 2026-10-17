#include "ops/RecoveryAccess.hpp"

#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "ops/Error.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "vault/model/Vault.hpp"

#include <filesystem>

namespace vh::ops::recovery::access {

std::string normalize(const std::string& path) {
    if (path.empty()) return "/";
    auto p = std::filesystem::path(path).lexically_normal().generic_string();
    if (!p.starts_with('/')) p.insert(p.begin(), '/');
    while (p.size() > 1 && p.ends_with('/')) p.pop_back();
    if (p == "/.." || p.starts_with("/../")) throw Invalid("invalid path: " + path);
    return p;
}

Gate::Gate(Actor actor, std::shared_ptr<storage::Engine> engine)
    : actor_(std::move(actor)), engine_(std::move(engine)) {}

bool Gate::exists(const std::string& vaultPath) const {
    const auto& cache = runtime::Deps::get().fsCache;
    return cache && cache->getEntry(engine_->vaultPathToFusePath(vaultPath)) != nullptr;
}

std::string Gate::existingAncestor(const std::string& vaultPath) const {
    auto path = normalize(vaultPath);
    const auto& cache = runtime::Deps::get().fsCache;
    while (path != "/") {
        path = std::filesystem::path(path).parent_path().generic_string();
        if (path.empty()) path = "/";
        if (const auto e = cache ? cache->getEntry(engine_->vaultPathToFusePath(path)) : nullptr; e && e->isDirectory())
            return path;
    }
    return "/";
}

bool Gate::evaluate(const std::string& vaultPath, const FsAction action, const bool directory) {
    const auto key = std::make_tuple(vaultPath, action, directory);
    if (const auto it = cache_.find(key); it != cache_.end()) return it->second;

    bool ok;
    if (exists(vaultPath)) {
        ok = rbac::resolver::Vault::has<FsAction>({
            .user = actor_, .permission = action, .vault_id = engine_->vault->id,
            .path = engine_->vaultPathToFusePath(vaultPath)});
    } else {
        // Judged as it was: a synthetic entry at the historical path (overrides match it), plus the folder that still
        // exists above it.
        std::shared_ptr<fs::model::Entry> was;
        if (directory) was = std::make_shared<fs::model::Directory>();
        else was = std::make_shared<fs::model::File>();
        was->path = vaultPath;
        was->fuse_path = engine_->vaultPathToFusePath(vaultPath);
        was->vault_id = static_cast<int32_t>(engine_->vault->id);
        const auto dir = existingAncestor(vaultPath);
        ok = rbac::resolver::Vault::has<FsAction>({
                 .user = actor_, .permission = action, .vault_id = engine_->vault->id, .entry = was}) &&
             evaluate(dir, FsAction::Read, true) && evaluate(dir, FsAction::List, true);
    }
    cache_.emplace(key, ok);
    return ok;
}

bool Gate::canRead(const std::string& vaultPath, const bool directory) {
    const auto path = normalize(vaultPath);
    if (const auto& cache = runtime::Deps::get().fsCache) {
        if (const auto e = cache->getEntry(engine_->vaultPathToFusePath(path))) {
            if (e->isDirectory()) return evaluate(path, FsAction::Read, true) && evaluate(path, FsAction::List, true);
            return evaluate(path, FsAction::Read, false);
        }
    }
    return evaluate(path, FsAction::Read, directory) &&
           (!directory || evaluate(path, FsAction::List, true));
}

bool Gate::allows(const std::string& vaultPath, const FsAction action, const bool directory) {
    return evaluate(normalize(vaultPath), action, directory);
}

}
