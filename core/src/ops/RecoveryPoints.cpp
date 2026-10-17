// ops::recovery: recovery points, restore plans and restores across the three backends (local snapshots, local
// versions, provider versions). The backends are trusted primitives (recovery/local, recovery/provider); this file is
// where they meet and the only place they are authorized. See .claude/context/recovery.md.

#include "ops/Recovery.hpp"

#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/recovery/Plan.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/RecoveryJson.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/Vault.hpp"
#include "recovery/local/Points.hpp"
#include "recovery/local/Restore.hpp"
#include "recovery/local/Snapshots.hpp"
#include "recovery/local/Versions.hpp"
#include "recovery/provider/Points.hpp"
#include "recovery/provider/Policy.hpp"
#include "recovery/provider/Restore.hpp"
#include "recovery/provider/Versions.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <map>
#include <set>

namespace vh::ops::recovery {

namespace {

namespace rq = db::query::recovery;
namespace rec = vh::recovery;
namespace prov = vh::recovery::provider;
using FsAction = rbac::permission::vault::FilesystemAction;
using EnginePtr = std::shared_ptr<storage::Engine>;

constexpr std::time_t kPlanLifetimeSeconds = 30 * 60;

EnginePtr rpEngine(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine || !engine->vault) throw NotFound("vault not found: " + std::to_string(vaultId));
    return engine;
}

std::shared_ptr<storage::CloudEngine> rpCloud(const EnginePtr& engine) {
    if (engine->type() != storage::StorageType::Cloud) return nullptr;
    return std::static_pointer_cast<storage::CloudEngine>(engine);
}

std::string rpNormalize(const std::string& path) {
    if (path.empty()) return "/";
    auto p = std::filesystem::path(path).lexically_normal().generic_string();
    if (!p.starts_with('/')) p.insert(p.begin(), '/');
    while (p.size() > 1 && p.ends_with('/')) p.pop_back();
    if (p.find("/../") != std::string::npos || p.ends_with("/..")) throw Invalid("invalid path: " + path);
    return p;
}

std::shared_ptr<fs::model::Entry> rpEntry(const storage::Engine& engine, const std::string& vaultPath) {
    const auto& cache = runtime::Deps::get().fsCache;
    return cache ? cache->getEntry(engine.vaultPathToFusePath(vaultPath)) : nullptr;
}

bool rpHas(const Actor& actor, const storage::Engine& engine, const std::string& vaultPath, const FsAction action) {
    return rbac::resolver::Vault::has<FsAction>({
        .user = actor,
        .permission = action,
        .vault_id = engine.vault->id,
        .path = engine.vaultPathToFusePath(vaultPath)
    });
}

// The nearest existing ancestor directory of a path (the vault root at worst).
std::string rpExistingAncestor(const storage::Engine& engine, std::string path) {
    while (path != "/") {
        path = std::filesystem::path(path).parent_path().generic_string();
        if (path.empty()) path = "/";
        if (const auto e = rpEntry(engine, path); e && e->isDirectory()) return path;
    }
    return "/";
}

// Who may see (and restore from) a point at `vaultPath`: Read on the file (Read + List on a directory). A path that
// no longer exists (deleted files keep their history) is judged like the HTTP lanes judge a missing path: Read + List
// on the nearest existing ancestor directory, i.e. the caller could download that folder.
class Visibility {
public:
    Visibility(Actor actor, EnginePtr engine) : actor_(std::move(actor)), engine_(std::move(engine)) {}

    bool canRead(const std::string& vaultPath) {
        const auto path = rpNormalize(vaultPath);
        if (const auto it = cache_.find(path); it != cache_.end()) return it->second;
        bool ok;
        if (const auto entry = rpEntry(*engine_, path)) {
            ok = rpHas(actor_, *engine_, path, FsAction::Read) &&
                 (!entry->isDirectory() || rpHas(actor_, *engine_, path, FsAction::List));
        } else {
            const auto dir = rpExistingAncestor(*engine_, path);
            ok = rpHas(actor_, *engine_, dir, FsAction::Read) && rpHas(actor_, *engine_, dir, FsAction::List);
        }
        cache_.emplace(path, ok);
        return ok;
    }

private:
    Actor actor_;
    EnginePtr engine_;
    std::map<std::string, bool> cache_;
};

prov::points::RetentionInfo rpRetention(const uint32_t vaultId) {
    try {
        const auto bucket = prov::policy::bucketForVault(vaultId);
        if (!bucket || !bucket->versioning) return {};
        rec::ProviderVersioningState state;
        state.retention_mode = bucket->versioning->retention_mode;
        state.retention_days = bucket->versioning->retention_days;
        // Only what Vaulthalla set is known here; another application's shorter rule is reported by status, and an
        // indefinite choice can't be promised without reading the lifecycle again.
        if (state.retention_mode == "days") state.effective_noncurrent_days = state.retention_days;
        if (state.retention_mode == "indefinite") return {};
        return prov::points::RetentionInfo::from(state);
    } catch (const std::exception&) {
        return {};
    }
}

rec::RecoveryId rpParseId(const std::string& id) {
    try {
        return rec::RecoveryId::parse(id);
    } catch (const std::invalid_argument& e) {
        throw Invalid(e.what());
    }
}

// The vault a recovery id belongs to (NotFound when there is no such point).
uint32_t rpVaultOf(const rec::RecoveryId& id) {
    if (id.type == rec::RecoveryId::Type::ProviderVersion) {
        const auto row = rq::ObjectVersion::get(static_cast<int64_t>(id.id));
        if (!row) throw NotFound("no such recovery point: " + id.str());
        return row->vault_id;
    }
    const auto point = rec::local::points::get(id);
    if (!point) throw NotFound("no such recovery point: " + id.str());
    return point->vault_id;
}

bool rpIsDirectory(const storage::Engine& engine, const std::string& path) {
    if (path == "/") return true;
    const auto e = rpEntry(engine, path);
    return e && e->isDirectory();
}

std::string rpRandomToken() {
    unsigned char raw[16];
    randombytes_buf(raw, sizeof(raw));
    char hex[sizeof(raw) * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), raw, sizeof(raw));
    return hex;
}

bool rpTokenMatches(const std::string& expected, const std::optional<std::string>& given) {
    return given && given->size() == expected.size() &&
           sodium_memcmp(expected.data(), given->data(), expected.size()) == 0;
}

bool rpIsLocalItem(const rec::PlanItem& item) {
    return item.source_id.starts_with("snap-") || item.source_id.starts_with("lv-");
}

void rpRecount(rec::Plan& plan) {
    plan.creates = plan.overwrites = plan.skips = plan.conflicts = plan.removals = plan.unavailable = 0;
    for (const auto& item : plan.items) {
        switch (item.action) {
            case rec::ItemAction::Create: ++plan.creates; break;
            case rec::ItemAction::Overwrite: ++plan.overwrites; break;
            case rec::ItemAction::Skip: ++plan.skips; break;
            case rec::ItemAction::Conflict: ++plan.conflicts; break;
            case rec::ItemAction::Remove: ++plan.removals; break;
            case rec::ItemAction::Unavailable: ++plan.unavailable; break;
        }
    }
}

// The destination permissions a restore of `item` will need (also shown in the plan as blockers).
std::optional<std::string> rpDestinationRefusal(const Actor& actor, const storage::Engine& engine,
                                                const rec::PlanItem& item) {
    const auto& dest = item.destination_path;
    switch (item.action) {
        case rec::ItemAction::Skip:
        case rec::ItemAction::Conflict:
        case rec::ItemAction::Unavailable:
            return std::nullopt;
        case rec::ItemAction::Remove:
            if (!rpHas(actor, engine, dest, FsAction::Delete)) return "you need Delete on " + dest;
            return std::nullopt;
        case rec::ItemAction::Overwrite:
            if (!rpHas(actor, engine, dest, FsAction::Overwrite)) return "you need Overwrite on " + dest;
            return std::nullopt;
        case rec::ItemAction::Create:
            break;
    }
    // A new file (Write at its path) or an empty directory (Touch), plus Touch on every directory restore creates.
    const bool directory = item.method == "none";
    if (!rpHas(actor, engine, dest, directory ? FsAction::Touch : FsAction::Write))
        return std::string("you need ") + (directory ? "Touch" : "Write (upload)") + " on " + dest;
    if (rpIsLocalItem(item)) {
        for (const auto& parent : rec::local::missingParents(engine, item))
            if (!rpHas(actor, engine, parent, FsAction::Touch)) return "you need Touch on " + parent;
    } else {
        auto parent = std::filesystem::path(dest).parent_path().generic_string();
        while (!parent.empty() && parent != "/" && !rpEntry(engine, parent)) {
            if (!rpHas(actor, engine, parent, FsAction::Touch)) return "you need Touch on " + parent;
            parent = std::filesystem::path(parent).parent_path().generic_string();
        }
    }
    return std::nullopt;
}

nlohmann::json rpSummary(const rec::Plan& plan) {
    auto j = nlohmann::json(plan);
    j.erase("items");
    j.erase("token");
    return j;
}

rec::Plan rpPlanFromRow(const rq::PlanRow& row) {
    rec::Plan plan;
    const auto summary = nlohmann::json::parse(row.summary_json);
    plan.id = static_cast<uint64_t>(row.id);
    plan.vault_id = row.vault_id;
    plan.token = row.token;
    plan.source_label = summary.value("source_label", "");
    plan.point_in_time = summary.value("point_in_time", false);
    if (summary.contains("at") && summary["at"].is_number_integer()) plan.at = summary["at"].get<std::time_t>();
    plan.atomic = summary.value("atomic", false);
    plan.consistency_note = summary.value("consistency_note", "");
    plan.destination = row.destination;
    plan.prune = summary.value("prune", false);
    plan.items = planItemsFromJson(nlohmann::json::parse(row.items_json));
    if (summary.contains("estimate")) {
        const auto& e = summary["estimate"];
        plan.estimate.get_requests = e.value("get_requests", 0ull);
        plan.estimate.head_requests = e.value("head_requests", 0ull);
        plan.estimate.put_requests = e.value("put_requests", 0ull);
        plan.estimate.copy_requests = e.value("copy_requests", 0ull);
        plan.estimate.list_requests = e.value("list_requests", 0ull);
        plan.estimate.download_bytes = e.value("download_bytes", 0ull);
        plan.estimate.upload_bytes = e.value("upload_bytes", 0ull);
        if (e.contains("cost") && e["cost"].is_object())
            plan.estimate.cost = rec::Money{.amount = e["cost"].value("amount", ""), .currency = e["cost"].value("currency", "")};
        if (e.contains("unpriced_reason") && e["unpriced_reason"].is_string())
            plan.estimate.unpriced_reason = e["unpriced_reason"].get<std::string>();
    }
    for (const auto& w : summary.value("warnings", std::vector<std::string>{})) plan.warnings.push_back(w);
    for (const auto& b : summary.value("blockers", std::vector<std::string>{})) plan.blockers.push_back(b);
    plan.created_at = row.created_at;
    plan.expires_at = row.expires_at;
    plan.state = row.state;
    if (plan.state == "planned" && std::time(nullptr) > plan.expires_at) plan.state = "expired";
    rpRecount(plan);
    return plan;
}

rq::PlanRow rpOwnPlan(const Actor& actor, const uint64_t planId) {
    const auto row = rq::Plan::get(static_cast<int64_t>(planId));
    // Plans are personal: someone else's plan is as absent as a missing one (no oracle).
    if (!row || !row->created_by || *row->created_by != actor->id) throw NotFound("no such restore plan: " + std::to_string(planId));
    return *row;
}

}

// ---- recovery points -----------------------------------------------------------------------------------------------

std::vector<RecoveryPoint> list(const Actor& actor, const uint32_t vaultId, const ListQuery& query) {
    requireActor(actor);
    const auto engine = rpEngine(vaultId);
    const auto path = query.path ? std::optional(rpNormalize(*query.path)) : std::nullopt;
    Visibility visible(actor, engine);
    if (!visible.canRead(path.value_or("/"))) throw Denied("you cannot read " + path.value_or("/") + " in this vault");

    const auto limit = std::clamp(query.limit, 1u, 1000u);
    std::vector<RecoveryPoint> out;
    if (query.include_snapshots || query.include_versions) {
        for (auto& p : rec::local::points::list(vaultId, {.path = path, .snapshots = query.include_snapshots,
                                                          .versions = query.include_versions, .limit = limit}))
            out.push_back(std::move(p));
    }
    if (query.include_provider) {
        if (const auto cloud = rpCloud(engine)) {
            const auto target = path.value_or("/");
            const bool directory = rpIsDirectory(*engine, target);
            if (query.refresh_provider) {
                const auto prefix = directory ? prov::versions::directoryPrefixOf(target)
                                              : prov::versions::objectKeyOf(target);
                const auto r = prov::versions::refresh(cloud, prefix);
                if (!r.complete && r.stopped_reason)
                    log::Registry::cloud()->info("[recovery] vault {}: version listing of '{}' stopped: {}", vaultId,
                                                 prefix, *r.stopped_reason);
            }
            for (auto& p : prov::points::forPath(cloud, target, directory, rpRetention(vaultId), limit))
                out.push_back(std::move(p));
        }
    }

    std::erase_if(out, [&](const RecoveryPoint& p) { return !visible.canRead(p.path); });
    // A file's history lists its generations (a snapshot's member of that file is the restorable point); the
    // snapshots holding it are directory-level points and would only repeat them.
    if (path && !rpIsDirectory(*engine, *path) &&
        std::ranges::any_of(out, [&](const RecoveryPoint& p) { return p.id.starts_with("lv-") && p.path == *path; }))
        std::erase_if(out, [](const RecoveryPoint& p) { return p.id.starts_with("snap-"); });
    std::ranges::stable_sort(out, [](const RecoveryPoint& a, const RecoveryPoint& b) { return a.created_at > b.created_at; });
    if (out.size() > limit) out.resize(limit);
    return out;
}

PointDetail inspect(const Actor& actor, const std::string& recoveryId) {
    requireActor(actor);
    const auto id = rpParseId(recoveryId);
    const auto vaultId = rpVaultOf(id);
    const auto engine = rpEngine(vaultId);
    Visibility visible(actor, engine);

    PointDetail out;
    if (id.type == rec::RecoveryId::Type::ProviderVersion) {
        const auto cloud = rpCloud(engine);
        const auto point = cloud ? prov::points::byId(cloud, id.id, rpRetention(vaultId)) : std::nullopt;
        if (!point) throw NotFound("no such recovery point: " + recoveryId);
        out.point = *point;
    } else {
        auto detail = rec::local::points::detail(id);
        if (!detail) throw NotFound("no such recovery point: " + recoveryId);
        out = std::move(*detail);
        std::erase_if(out.members, [&](const RecoveryPoint& m) { return !visible.canRead(m.path); });
    }
    if (!visible.canRead(out.point.path)) throw NotFound("no such recovery point: " + recoveryId);
    return out;
}

void deletePoint(const Actor& actor, const std::string& recoveryId, const bool confirm) {
    requireActor(actor);
    const auto id = rpParseId(recoveryId);
    if (id.type == rec::RecoveryId::Type::ProviderVersion)
        throw Invalid("provider versions are kept by the bucket and removed by its retention, not by Vaulthalla");
    const auto vaultId = rpVaultOf(id);
    const auto engine = rpEngine(vaultId);
    const auto point = rec::local::points::get(id);
    if (!point) throw NotFound("no such recovery point: " + recoveryId);
    Visibility visible(actor, engine);
    if (!visible.canRead(point->path)) throw NotFound("no such recovery point: " + recoveryId);

    // Delete on the point's path; a path that is gone is judged on its nearest existing folder.
    const auto path = rpNormalize(point->path);
    const auto target = rpEntry(*engine, path) ? path : rpExistingAncestor(*engine, path);
    if (!rpHas(actor, *engine, target, FsAction::Delete)) throw Denied("you need Delete on " + target);

    if (!confirm)
        throw NeedsConfirmation(POINT_DELETE, "Delete recovery point " + recoveryId + " (" + point->path +
                                              ")? This permanently removes what it retained.");
    if (id.type == rec::RecoveryId::Type::Snapshot) rec::local::snapshots::remove(static_cast<int64_t>(id.id));
    else rec::local::removeVersion(static_cast<int64_t>(id.id));
    log::Registry::audit()->info("[ops::recovery] {} deleted recovery point {} ({}) in vault {}", actor->name(),
                                 recoveryId, point->path, vaultId);
}

// ---- plans ---------------------------------------------------------------------------------------------------------

Plan plan(const Actor& actor, const PlanRequest& req) {
    requireActor(actor);
    const auto destination = req.destination ? std::optional(rpNormalize(*req.destination)) : std::nullopt;

    rec::Plan out;
    EnginePtr engine;
    if (req.recovery_id) {
        const auto id = rpParseId(*req.recovery_id);
        out.vault_id = rpVaultOf(id);
        engine = rpEngine(out.vault_id);
        if (id.type == rec::RecoveryId::Type::ProviderVersion) {
            const auto cloud = rpCloud(engine);
            if (!cloud) throw NotFound("no such recovery point: " + *req.recovery_id);
            const auto row = rq::ObjectVersion::get(static_cast<int64_t>(id.id));
            if (row && req.refresh_provider) {
                // The plan compares against the current version: learn it first (metadata only).
                (void)prov::versions::refresh(cloud, row->object_key, {.max_requests = 2});
            }
            out = prov::planOne(cloud, id.id, destination);
            out.source_label = id.str();
        } else {
            const auto local = rec::local::planFor(id, req.path ? std::optional(rpNormalize(*req.path)) : std::nullopt,
                                                   destination);
            out.vault_id = local.vault_id;
            out.source_label = local.source_label;
            out.atomic = local.atomic;
            out.consistency_note = local.consistency_note;
            out.items = local.items;
            out.warnings = local.warnings;
            out.blockers = local.blockers;
        }
    } else {
        if (!req.vault_id || !req.path || !req.at)
            throw Invalid("a plan needs a recovery_id, or vault_id + path + at for a point in time");
        engine = rpEngine(*req.vault_id);
        const auto cloud = rpCloud(engine);
        if (!cloud)
            throw Invalid("point-in-time restore uses provider versions; in a local vault restore a snapshot or a "
                          "local version");
        const auto path = rpNormalize(*req.path);
        if (req.refresh_provider) {
            const auto prefix = rpIsDirectory(*engine, path) ? prov::versions::directoryPrefixOf(path)
                                                             : prov::versions::objectKeyOf(path);
            const auto r = prov::versions::refresh(cloud, prefix);
            if (!r.complete)
                out.warnings.push_back("the provider's version listing was incomplete (" +
                                       r.stopped_reason.value_or("stopped") + "): the plan may miss versions");
        }
        auto pit = prov::planAt(cloud, path, *req.at, destination, req.prune);
        pit.warnings.insert(pit.warnings.begin(), out.warnings.begin(), out.warnings.end());
        out = std::move(pit);
        out.vault_id = *req.vault_id;
        out.point_in_time = true;
        out.at = req.at;
        out.prune = req.prune;
        if (out.source_label.empty()) out.source_label = path;
    }
    out.vault_id = engine->vault->id;
    out.destination = destination;

    // Sources: the caller must be able to read what it restores. Items it can't read are left out (no oracle about
    // their existence); a single point it can't read is NotFound.
    Visibility visible(actor, engine);
    const auto before = out.items.size();
    std::erase_if(out.items, [&](const rec::PlanItem& item) { return !visible.canRead(item.source_path); });
    if (out.items.empty() && before > 0) {
        if (req.recovery_id) throw NotFound("no such recovery point: " + *req.recovery_id);
        throw Denied("you cannot read anything under " + rpNormalize(*req.path) + " at that time");
    }
    if (out.items.size() < before)
        out.warnings.push_back(std::to_string(before - out.items.size()) +
                               " item(s) you can't read were left out of this plan");

    // Destinations: shown now as blockers, re-checked per item at restore.
    for (const auto& item : out.items)
        if (const auto refusal = rpDestinationRefusal(actor, *engine, item)) out.blockers.push_back(*refusal);
    if (out.consistency_note.empty())
        out.consistency_note = out.atomic ? "A local snapshot, taken in one pass under content locks."
                                          : "Each item is restored on its own; this is not an atomic snapshot.";
    rpRecount(out);

    const auto now = std::time(nullptr);
    out.token = rpRandomToken();
    out.created_at = now;
    out.expires_at = now + kPlanLifetimeSeconds;
    out.state = "planned";
    rq::PlanRow row;
    row.vault_id = out.vault_id;
    row.token = out.token;
    row.source_json = nlohmann::json{{"recovery_id", req.recovery_id ? nlohmann::json(*req.recovery_id) : nullptr},
                                     {"path", req.path ? nlohmann::json(*req.path) : nullptr},
                                     {"at", req.at ? nlohmann::json(*req.at) : nullptr},
                                     {"prune", req.prune}}.dump();
    row.destination = out.destination;
    row.items_json = nlohmann::json(out.items).dump();
    row.summary_json = rpSummary(out).dump();
    row.expires_at = out.expires_at;
    row.created_by = actor->id;
    out.id = static_cast<uint64_t>(rq::Plan::insert(row));
    return out;
}

Plan getPlan(const Actor& actor, const uint64_t planId) {
    requireActor(actor);
    auto out = rpPlanFromRow(rpOwnPlan(actor, planId));
    out.token.clear();   // the token is only handed out when the plan is made
    return out;
}

// ---- restore -------------------------------------------------------------------------------------------------------

RestoreResult restore(const Actor& actor, const RestoreRequest& req) {
    requireActor(actor);
    const auto row = rpOwnPlan(actor, req.plan_id);
    auto plan = rpPlanFromRow(row);
    const auto now = std::time(nullptr);

    if (row.state == "done" && row.result_json) return restoreResultFromJson(nlohmann::json::parse(*row.result_json));
    if (row.state == "failed")
        throw Conflict("restore plan " + std::to_string(req.plan_id) + " failed; make a new plan");
    if (plan.state == "expired")
        throw NeedsConfirmation(PLAN_EXPIRED, "restore plan " + std::to_string(req.plan_id) + " expired: plan again");
    if (!rpTokenMatches(row.token, req.token))
        throw NeedsConfirmation(RESTORE_CONFIRM, "restoring plan " + std::to_string(req.plan_id) + " needs its token: " +
                                                 std::to_string(plan.creates) + " create, " +
                                                 std::to_string(plan.overwrites) + " overwrite, " +
                                                 std::to_string(plan.removals) + " remove");
    if (!plan.blockers.empty()) throw Denied("this plan can't be restored: " + plan.blockers.front());

    const bool unverified = std::ranges::any_of(plan.items, [](const rec::PlanItem& i) {
        return std::ranges::any_of(i.notes, [](const std::string& n) { return n.starts_with("unverified"); });
    });
    if (unverified && !req.accept_unverified)
        throw NeedsConfirmation(UNVERIFIED_VERSION,
                                "some versions in this plan were not written by Vaulthalla (they were found in the "
                                "bucket): restore them only if you trust where they came from");

    const auto engine = rpEngine(plan.vault_id);
    const auto cloud = rpCloud(engine);
    if (!rq::Plan::start(static_cast<int64_t>(plan.id), now))
        throw Conflict("restore plan " + std::to_string(req.plan_id) + " can't be started (state " + row.state + ")");

    // Resume: outcomes already recorded (a crashed or partial run) are kept, and only the rest runs.
    RestoreResult result;
    if (row.result_json) result = restoreResultFromJson(nlohmann::json::parse(*row.result_json));
    result.plan_id = plan.id;
    std::map<std::string, rec::ItemOutcome> finished;
    for (const auto& o : result.items)
        if (o.outcome == "restored" || o.outcome == "skipped" || o.outcome == "removed") finished[o.destination_path] = o;
    result.items.clear();

    Visibility visible(actor, engine);
    for (const auto& item : plan.items) {
        if (const auto it = finished.find(item.destination_path); it != finished.end()) {
            result.items.push_back(it->second);
            continue;
        }
        rec::ItemOutcome o{.destination_path = item.destination_path, .outcome = "failed", .error = std::nullopt};
        try {
            if (!visible.canRead(item.source_path)) {
                o.outcome = "failed";
                o.error = "you can no longer read " + item.source_path;
            } else if (const auto refusal = rpDestinationRefusal(actor, *engine, item)) {
                o.outcome = "failed";
                o.error = *refusal;
            } else if (rpIsLocalItem(item)) {
                o = rec::local::restore(engine, actor, item);
            } else if (!cloud) {
                o.error = "provider versions need an S3 vault";
            } else {
                const auto r = prov::restore(cloud, item, item.destination_source_id,
                                             {.accept_unverified = req.accept_unverified, .user_id = actor->id, .hooks = {}});
                o.outcome = r.outcome;
                o.error = r.error;
            }
        } catch (const prov::PassBusy& e) {
            o.outcome = "failed";
            o.error = std::string("a sync pass is running; restore again shortly (") + e.what() + ")";
        } catch (const prov::UnverifiedVersion& e) {
            o.outcome = "failed";
            o.error = e.what();
        } catch (const std::exception& e) {
            o.outcome = "failed";
            o.error = e.what();
        }
        result.items.push_back(o);
        rq::Plan::saveResult(static_cast<int64_t>(plan.id), nlohmann::json(result).dump());
    }

    result.restored = result.skipped = result.conflicts = result.failed = result.removed = result.unavailable = 0;
    for (const auto& o : result.items) {
        if (o.outcome == "restored") ++result.restored;
        else if (o.outcome == "skipped") ++result.skipped;
        else if (o.outcome == "conflict") ++result.conflicts;
        else if (o.outcome == "removed") ++result.removed;
        else if (o.outcome == "unavailable") ++result.unavailable;
        else ++result.failed;
    }
    const bool clean = result.failed == 0 && result.conflicts == 0;
    const bool nothing = result.restored == 0 && result.removed == 0 && result.skipped == 0;
    result.state = clean ? "done" : (nothing && result.failed > 0 ? "failed" : "partial");
    if (result.unavailable > 0 && result.state == "done") result.state = "partial";
    rq::Plan::finish(static_cast<int64_t>(plan.id), result.state, nlohmann::json(result).dump());
    log::Registry::audit()->info("[ops::recovery] {} restored plan {} ({}) in vault {}: {} restored, {} skipped, "
                                 "{} conflict(s), {} failed, {} removed, {} unavailable",
                                 actor->name(), plan.id, plan.source_label, plan.vault_id, result.restored,
                                 result.skipped, result.conflicts, result.failed, result.removed, result.unavailable);
    return result;
}

}
