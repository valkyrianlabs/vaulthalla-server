// ops::recovery: recovery points, restore plans and restores across the three backends (local snapshots, local
// versions, provider versions). The backends are trusted primitives (recovery/local, recovery/provider); this file is
// where they meet and the only place they are authorized. See .claude/context/recovery.md.

#include "ops/Recovery.hpp"

#include "db/query/recovery/ObjectVersion.hpp"
#include "ops/RecoveryAccess.hpp"
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

std::string rpNormalize(const std::string& path) { return access::normalize(path); }

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

using Visibility = access::Gate;

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

bool rpIsDirectoryItem(const rec::PlanItem& item) { return item.method == "none"; }

// What restoring an item needs on its source: Read (or as it was, for a path that is gone); and Copy when it goes
// somewhere else, since restoring elsewhere makes a copy (the rule createSnapshot applies to every file it keeps).
std::optional<std::string> rpSourceRefusal(Visibility& gate, const rec::PlanItem& item) {
    const bool directory = rpIsDirectoryItem(item);
    if (!gate.canRead(item.source_path, directory)) return "you can't read " + item.source_path;
    if (!directory && item.destination_path != item.source_path &&
        !gate.allows(item.source_path, FsAction::Copy, false))
        return "you need Copy on " + item.source_path + " to restore it to another place";
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
    const auto target = path.value_or("/");
    Visibility gate(actor, engine);
    const auto cloud = query.include_provider ? rpCloud(engine) : nullptr;

    // Nothing is fetched, and no provider request is sent, for someone who can't see the path: as it is, or (gone)
    // as the file or folder it was.
    const bool existing = gate.exists(target);
    const bool directory = existing ? rpIsDirectory(*engine, target) : false;
    if (existing ? !gate.canRead(target, directory) : !(gate.canRead(target, false) || gate.canRead(target, true)))
        throw Denied("you cannot read " + target + " in this vault");

    const auto limit = std::clamp(query.limit, 1u, 1000u);
    std::vector<RecoveryPoint> out;
    if (query.include_snapshots || query.include_versions) {
        for (auto& p : rec::local::points::list(vaultId, {.path = path, .snapshots = query.include_snapshots,
                                                          .versions = query.include_versions, .limit = limit}))
            out.push_back(std::move(p));
    }
    if (cloud) {
        const bool asDirectory = existing ? directory : prov::versions::objectKeyOf(target).empty();
        if (query.refresh_provider) {
            const auto prefix = asDirectory || target == "/" ? prov::versions::directoryPrefixOf(target)
                                                            : prov::versions::objectKeyOf(target);
            const auto r = prov::versions::refresh(cloud, prefix);
            if (!r.complete && r.stopped_reason)
                log::Registry::cloud()->info("[recovery] vault {}: version listing of '{}' stopped: {}", vaultId,
                                             prefix, *r.stopped_reason);
        }
        for (auto& p : prov::points::forPath(cloud, target, asDirectory || target == "/", rpRetention(vaultId), limit))
            out.push_back(std::move(p));
    }

    std::erase_if(out, [&](const RecoveryPoint& p) {
        return !gate.canRead(p.path, p.kind == rec::PointKind::Directory);
    });
    // A file's history lists its generations (a snapshot's member of that file is the restorable point); the
    // snapshots holding it are directory-level points and would only repeat them.
    if (path && !directory &&
        std::ranges::any_of(out, [&](const RecoveryPoint& p) { return p.id.starts_with("lv-") && p.path == *path; }))
        std::erase_if(out, [](const RecoveryPoint& p) { return p.id.starts_with("snap-"); });
    std::ranges::stable_sort(out, [](const RecoveryPoint& a, const RecoveryPoint& b) { return a.created_at > b.created_at; });
    if (out.size() > limit) out.resize(limit);
    return out;
}

namespace {

// The point behind an id, after the caller was found allowed to see it; one NotFound for every refusal before that
// (no such id, another vault, a path the caller can't read), so nothing about it leaks.
struct ResolvedPoint {
    rec::RecoveryId id;
    EnginePtr engine;
    RecoveryPoint point;
};

ResolvedPoint rpResolveVisible(const Actor& actor, const std::string& recoveryId) {
    const auto notFound = [&] { return NotFound("no such recovery point: " + recoveryId); };
    const auto id = rpParseId(recoveryId);
    std::optional<RecoveryPoint> point;
    EnginePtr engine;
    try {
        engine = rpEngine(rpVaultOf(id));
        if (id.type == rec::RecoveryId::Type::ProviderVersion) {
            if (const auto cloud = rpCloud(engine)) point = prov::points::byId(cloud, id.id, rpRetention(engine->vault->id));
        } else {
            point = rec::local::points::get(id);
        }
    } catch (const NotFound&) {
        throw notFound();
    }
    if (!point) throw notFound();
    Visibility gate(actor, engine);
    if (!gate.canRead(point->path, point->kind == rec::PointKind::Directory)) throw notFound();
    return {id, engine, std::move(*point)};
}

}

PointDetail inspect(const Actor& actor, const std::string& recoveryId) {
    requireActor(actor);
    auto resolved = rpResolveVisible(actor, recoveryId);
    Visibility gate(actor, resolved.engine);

    PointDetail out;
    if (resolved.id.type == rec::RecoveryId::Type::ProviderVersion) {
        out.point = std::move(resolved.point);
        return out;
    }
    auto detail = rec::local::points::detail(resolved.id);
    if (!detail) throw NotFound("no such recovery point: " + recoveryId);
    out = std::move(*detail);
    std::erase_if(out.members, [&](const RecoveryPoint& m) {
        return !gate.canRead(m.path, m.kind == rec::PointKind::Directory);
    });
    // "<path>: <reason>": only entries the caller could see.
    std::erase_if(out.skipped, [&](const std::string& s) {
        const auto colon = s.find(": ");
        return colon == std::string::npos || !gate.canRead(s.substr(0, colon));
    });
    return out;
}

void deletePoint(const Actor& actor, const std::string& recoveryId, const bool confirm) {
    requireActor(actor);
    const auto resolved = rpResolveVisible(actor, recoveryId);
    if (resolved.id.type == rec::RecoveryId::Type::ProviderVersion)
        throw Invalid("provider versions are kept by the bucket and removed by its retention, not by Vaulthalla");
    Visibility gate(actor, resolved.engine);

    // Delete on everything the point holds (as it is, or as it was): a snapshot of a folder can't be destroyed by
    // someone a path override keeps from deleting part of it.
    const auto& point = resolved.point;
    if (!gate.allows(point.path, FsAction::Delete, point.kind == rec::PointKind::Directory))
        throw Denied("you need Delete on " + point.path);
    if (resolved.id.type == rec::RecoveryId::Type::Snapshot) {
        std::string after;
        for (;;) {
            const auto page = rec::local::points::detail(resolved.id, after, 500);
            if (!page || page->members.empty()) break;
            for (const auto& m : page->members)
                if (!gate.allows(m.path, FsAction::Delete, false)) throw Denied("you need Delete on " + m.path);
            if (!page->members_truncated) break;
            after = page->members.back().path;
            const auto root = point.path == "/" ? std::string() : point.path;
            if (after.starts_with(root + "/")) after = after.substr(root.size() + 1);
        }
    }

    if (!confirm)
        throw NeedsConfirmation(POINT_DELETE, "Delete recovery point " + recoveryId + " (" + point.path +
                                              ")? This permanently removes what it retained.");
    if (resolved.id.type == rec::RecoveryId::Type::Snapshot) rec::local::snapshots::remove(static_cast<int64_t>(resolved.id.id));
    else rec::local::removeVersion(static_cast<int64_t>(resolved.id.id));
    log::Registry::audit()->info("[ops::recovery] {} deleted recovery point {} ({}) in vault {}", actor->name(),
                                 recoveryId, point.path, resolved.engine->vault->id);
}

// ---- plans ---------------------------------------------------------------------------------------------------------

Plan plan(const Actor& actor, const PlanRequest& req) {
    requireActor(actor);
    const auto destination = req.destination ? std::optional(rpNormalize(*req.destination)) : std::nullopt;

    rec::Plan out;
    EnginePtr engine;
    if (req.recovery_id) {
        // Authorized before anything else happens (no listing request, no plan detail for an unreadable point).
        const auto resolved = rpResolveVisible(actor, *req.recovery_id);
        engine = resolved.engine;
        if (resolved.id.type == rec::RecoveryId::Type::ProviderVersion) {
            const auto cloud = rpCloud(engine);
            const auto row = rq::ObjectVersion::get(static_cast<int64_t>(resolved.id.id));
            if (row && req.refresh_provider) {
                // The plan compares against the current version: learn it first (metadata only).
                (void)prov::versions::refresh(cloud, row->object_key, {.max_requests = 2});
            }
            out = prov::planOne(cloud, resolved.id.id, destination);
            out.source_label = resolved.id.str();
        } else {
            const auto local = rec::local::planFor(resolved.id,
                                                   req.path ? std::optional(rpNormalize(*req.path)) : std::nullopt,
                                                   destination);
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
        const auto path = rpNormalize(*req.path);
        const auto notFound = [&] { return NotFound("nothing to restore at " + path); };
        try {
            engine = rpEngine(*req.vault_id);
        } catch (const NotFound&) {
            throw notFound();
        }
        Visibility gate(actor, engine);
        const bool existing = gate.exists(path);
        if (existing ? !gate.canRead(path, rpIsDirectory(*engine, path))
                     : !(gate.canRead(path, false) || gate.canRead(path, true)))
            throw notFound();
        const auto cloud = rpCloud(engine);
        if (!cloud)
            throw Invalid("point-in-time restore uses provider versions; in a local vault restore a snapshot or a "
                          "local version");
        if (req.refresh_provider) {
            const auto prefix = (!existing || rpIsDirectory(*engine, path)) ? prov::versions::directoryPrefixOf(path)
                                                                             : prov::versions::objectKeyOf(path);
            const auto r = prov::versions::refresh(cloud, prefix);
            if (!r.complete)
                out.warnings.push_back("the provider's version listing was incomplete (" +
                                       r.stopped_reason.value_or("stopped") + "): the plan may miss versions");
        }
        auto pit = prov::planAt(cloud, path, *req.at, destination, req.prune);
        pit.warnings.insert(pit.warnings.begin(), out.warnings.begin(), out.warnings.end());
        out = std::move(pit);
        out.point_in_time = true;
        out.at = req.at;
        out.prune = req.prune;
        if (out.source_label.empty()) out.source_label = path;
    }
    out.vault_id = engine->vault->id;
    out.destination = destination;

    // Items the caller can't read are left out without a trace (no count, no oracle); restoring elsewhere also
    // needs Copy on the source, and destinations need what writing there needs — shown now as blockers and checked
    // again per item at restore.
    Visibility gate(actor, engine);
    std::erase_if(out.items, [&](const rec::PlanItem& item) {
        return !gate.canRead(item.source_path, rpIsDirectoryItem(item));
    });
    for (const auto& item : out.items) {
        if (const auto refusal = rpSourceRefusal(gate, item)) out.blockers.push_back(*refusal);
        else if (const auto dest = rpDestinationRefusal(actor, *engine, item)) out.blockers.push_back(*dest);
    }
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

// Plans are personal (someone else's is NotFound), so the person who made one gets it back with its token: the
// token says "I saw this preview", not who may restore.
Plan getPlan(const Actor& actor, const uint64_t planId) {
    requireActor(actor);
    return rpPlanFromRow(rpOwnPlan(actor, planId));
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

    Visibility gate(actor, engine);
    for (const auto& item : plan.items) {
        if (const auto it = finished.find(item.destination_path); it != finished.end()) {
            result.items.push_back(it->second);
            continue;
        }
        rec::ItemOutcome o{.destination_path = item.destination_path, .outcome = "failed", .error = std::nullopt};
        try {
            if (const auto refusal = rpSourceRefusal(gate, item)) {
                o.error = *refusal;
            } else if (const auto dest = rpDestinationRefusal(actor, *engine, item)) {
                o.error = *dest;
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
