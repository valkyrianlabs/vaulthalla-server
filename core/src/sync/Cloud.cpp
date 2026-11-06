#include "sync/Cloud.hpp"

#include "storage/CloudEngine.hpp"
#include "storage/ScopedS3RequestBudget.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "sync/tasks/Download.hpp"
#include "sync/tasks/Upload.hpp"
#include "sync/tasks/Delete.hpp"
#include "sync/Executor.hpp"

#include "vault/model/Vault.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Path.hpp"
#include "runtime/Deps.hpp"
#include "fs/cache/Registry.hpp"

#include "log/Registry.hpp"

#include "sync/model/Event.hpp"
#include "sync/model/Throughput.hpp"
#include "sync/model/Artifact.hpp"
#include "sync/model/ConflictArtifact.hpp"
#include "sync/model/Conflict.hpp"
#include "sync/model/Baseline.hpp"
#include "db/query/sync/Conflict.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/helpers.hpp"
#include "sync/Planner.hpp"

#include "crypto/id/Generator.hpp"
#include "sync/Controller.hpp"
#include "sync/events/Subscriptions.hpp"
#include "storage/ObjectKeys.hpp"
#include "db/query/sync/ObjectIdentity.hpp"
#include "db/encoding/u8.hpp"

#include <mutex>

#include <optional>
#include <utility>

using namespace vh::sync;
using namespace vh::sync::model;
using namespace std::chrono;
using namespace vh::storage;
using namespace vh::fs::model;
using namespace vh::crypto;


// ##########################################
// ########### FSTask Overrides #############
// ##########################################

namespace {

std::mutex& pendingRemovalsMutex() {
    static std::mutex m;
    return m;
}

Cloud::PendingRemovalsProvider& pendingRemovalsProvider() {
    static Cloud::PendingRemovalsProvider provider;
    return provider;
}

Cloud::EventHooks& eventHooksSlot() {
    static Cloud::EventHooks hooks;
    return hooks;
}

Cloud::EventHooks eventHooks() {
    std::scoped_lock lock(pendingRemovalsMutex());
    return eventHooksSlot();
}

// Releases the vault's pass lease (sync::Controller) when a pass ends, however it ends.
struct PassLease {
    unsigned int vaultId;
    bool held;
    ~PassLease() {
        if (!held) return;
        if (const auto& controller = vh::runtime::Deps::get().syncController) controller->releasePass(vaultId);
    }
};

}

void Cloud::setEventHooks(EventHooks hooks) {
    std::scoped_lock lock(pendingRemovalsMutex());
    eventHooksSlot() = std::move(hooks);
}

void Cloud::setPendingRemovalsProvider(PendingRemovalsProvider provider) {
    std::scoped_lock lock(pendingRemovalsMutex());
    pendingRemovalsProvider() = std::move(provider);
}

void Cloud::loadRemovedKeys() {
    PendingRemovalsProvider provider;
    {
        std::scoped_lock lock(pendingRemovalsMutex());
        provider = pendingRemovalsProvider();
    }
    removedKeys.clear();
    if (provider) removedKeys = provider(vaultId());
    if (scope) removedKeys.insert(scope->removed.begin(), scope->removed.end());
}

Cloud::~Cloud() {
    if (!scope || !passLeaseAdopted_ || ran_) return;
    try {
        if (const auto& controller = runtime::Deps::get().syncController) controller->releasePass(vaultId());
        if (scope->on_finish) scope->on_finish(false, "the scoped sync pass was dropped before it ran");
    } catch (...) {
        // A destructor never throws; the rows are retried by their backoff anyway.
    }
}

void Cloud::operator()() {
    // One pass per vault at a time (#96): a regular pass waits while an event-scoped pass runs, and the reverse.
    // runScoped() takes the lease before it submits a scoped pass; a regular pass takes it here. A regular pass that
    // has to wait says so, and the event applier yields to it.
    ran_ = true;
    const auto& controller = runtime::Deps::get().syncController;
    if (!scope && controller && !controller->tryAcquirePass(vaultId())) {
        controller->markRegularWaiting(vaultId());
        next_run = system_clock::now() + seconds(2);
        requeue();
        return;
    }
    if (!scope && controller) controller->clearRegularWaiting(vaultId());
    const PassLease lease{vaultId(), controller != nullptr};

    startTask();

    std::shared_ptr<CloudEngine> cloud;
    try {
        cloud = cloudEngine();
        const ScopedS3RequestBudget s3Budget(cloud, cloud->remote_policy()->s3_request_budget);

        loadRemovedKeys();

        // A scoped pass reconciles the named keys only: the vault-wide maintenance (at-rest repair, trash purge,
        // key rotation) stays with the regular pass.
        const Stage regularStages[] = {
            {"shared",   [this]{ processSharedOps(); }},
            {"initBins", [this]{ initBins(); }},
            {"sync",     [this]{ sync(); }},
            {"clearBins",[this]{ clearBins(); }},
        };
        const Stage scopedStages[] = {
            {"initBins", [this]{ initScopedBins(); }},
            {"sync",     [this]{ sync(); }},
            {"clearBins",[this]{ clearBins(); }},
        };

        if (scope) runStages(scopedStages);
        else runStages(regularStages);

        const auto s3Metrics = s3Budget.metrics();
        event->applyS3RequestMetrics(s3Metrics);
        if (s3Metrics.budget_exceeded) {
            event->status = Event::Status::STALLED;
            event->stall_reason = s3Metrics.budget_exceeded_reason;
        }
        log::Registry::sync()->info(
            "[CloudSync] S3 counters for vault {}: LIST={} HEAD={} GET={} PUT={} COPY={} DELETE={} downloaded_bytes={}",
            engine->vault->id,
            event->s3_list_requests,
            event->s3_head_requests,
            event->s3_get_requests,
            event->s3_put_requests,
            event->s3_copy_requests,
            event->s3_delete_requests,
            event->s3_downloaded_bytes);
    } catch (const vh::storage::s3::RequestBudgetExceeded& e) {
        if (cloud) event->applyS3RequestMetrics(cloud->s3RequestMetrics());
        event->status = Event::Status::STALLED;
        event->stall_reason = e.what();
    } catch (const SyncStalled& e) {
        if (cloud) event->applyS3RequestMetrics(cloud->s3RequestMetrics());
        event->status = Event::Status::STALLED;
        event->stall_reason = e.what();
        event->error_code.clear();
        event->error_message.clear();
    } catch (const std::exception& e) {
        if (cloud) event->applyS3RequestMetrics(cloud->s3RequestMetrics());
        handleError(fmt::format("[CloudSync] {}", e.what()));
    } catch (...) {
        if (cloud) event->applyS3RequestMetrics(cloud->s3RequestMetrics());
        handleError("[CloudSync] Unknown exception");
    }

    // A full LIST rebuilt the index but the pass stopped before publishing it (failed operations, an error or a stall
    // after initBins): publish it now, as the post-LIST publish did. No-op otherwise.
    if (cloud) cloud->publishPendingRemoteIndexManifest();

    shutdown();

    if (scope && scope->on_finish) {
        const bool ok = event && event->status == Event::Status::SUCCESS && event->num_failed_ops == 0;
        std::string why;
        if (event && !ok) why = !event->stall_reason.empty() ? event->stall_reason : event->error_message;
        if (!ok && why.empty()) why = "scoped sync pass did not complete";
        try {
            scope->on_finish(ok, why);
        } catch (const std::exception& e) {
            log::Registry::sync()->error("[CloudSync] Vault {}: scoped pass completion handler failed: {}", vaultId(), e.what());
        }
    }
}

// ##########################################
// ############# Sync Operations ############
// ##########################################

std::vector<Action> Cloud::planPass(S3CostEstimate* planningNotes) {
    const auto self = std::static_pointer_cast<Cloud>(shared_from_this());
    auto plan = Planner::build(self, cloudEngine()->remote_policy(), planningNotes);
    flushConflictState();
    return plan;
}

void Cloud::sync() {
    const auto self = std::static_pointer_cast<Cloud>(shared_from_this());
    S3CostEstimate planningNotes;
    const auto plan = planPass(&planningNotes);
    auto estimate = Planner::estimateS3Cost(plan, opaque);
    estimate.archive_tier_downloads_skipped = planningNotes.archive_tier_downloads_skipped;
    event->applyS3CostEstimate(estimate);
    const auto priceEstimate = vh::storage::s3::pricing::estimatePlannedS3Sync(*cloudEngine(), estimate);
    const auto budgetPriceEstimate = vh::storage::s3::pricing::estimatePlannedS3Sync(
        *cloudEngine(),
        estimate,
        {.mode = vh::storage::s3::pricing::PriceEstimateMode::BudgetConservative});
    if (priceEstimate.available) {
        event->applyS3PriceEstimate(priceEstimate);
        log::Registry::sync()->info(
            "[CloudSync] S3 price estimate for vault {}: {}",
            engine->vault->id,
            vh::storage::s3::pricing::formatPriceEstimateForLog(priceEstimate));
    } else if (priceEstimate.supported) {
        log::Registry::sync()->warn(
            "[CloudSync] S3 price estimate unavailable for vault {}: {}",
            engine->vault->id,
            vh::storage::s3::pricing::formatPriceEstimateForLog(priceEstimate));
    } else {
        log::Registry::sync()->debug(
            "[CloudSync] S3 price estimate skipped for vault {}: {}",
            engine->vault->id,
            priceEstimate.unavailable_reason);
    }
    if (budgetPriceEstimate.available) {
        event->applyS3BudgetPriceEstimate(budgetPriceEstimate);
        log::Registry::sync()->info(
            "[CloudSync] Budget-safe S3 price estimate for vault {}: {}",
            engine->vault->id,
            vh::storage::s3::pricing::formatPriceEstimateForLog(budgetPriceEstimate));
    } else if (budgetPriceEstimate.supported) {
        log::Registry::sync()->debug(
            "[CloudSync] Budget-safe S3 price estimate unavailable for vault {}: {}",
            engine->vault->id,
            vh::storage::s3::pricing::formatPriceEstimateForLog(budgetPriceEstimate));
    }

    const auto cloud = cloudEngine();
    const auto profile = cloud->s3ProviderProfile();
    const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
    const auto providerKey = costProfileId
        ? *costProfileId
        : (profile ? profile->id() : std::string{"unknown"});
    const bool providerSupported = costProfileId &&
        vh::storage::s3::pricing::isSupportedPriceBudgetProvider(*costProfileId);

    const vh::storage::s3::pricing::PriceBudgetService budgetService;
    vh::storage::s3::pricing::PriceBudgetPreflightRequest budgetRequest{
        .vault_id = engine->vault->id,
        .run_uuid = event->run_uuid,
        .provider_key = providerKey,
        .provider_supported = providerSupported,
        .estimate = budgetPriceEstimate,
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {},
        .gateway_scopes_only = false,
        .synthetic = false,
        .usage_source = {}
    };
    auto budgetDecision = budgetService.preflight(budgetRequest);
    if (!budgetDecision.allowed && budgetService.isLimitOverrideEligible(budgetDecision)) {
        const auto policyIds = budgetService.exceededEnforcePolicyIds(budgetDecision);
        if (const auto consumedOverride = budgetService.consumeApprovedOverride(engine->vault->id, policyIds, event->run_uuid)) {
            log::Registry::sync()->warn(
                "[CloudSync] S3 price budget override {} consumed for vault {} run {}",
                consumedOverride->id,
                engine->vault->id,
                event->run_uuid);
            budgetRequest.override_policy_ids = policyIds;
            budgetDecision = budgetService.preflight(budgetRequest);
        }
    }
    budgetService.recordPreflightNotifications(budgetRequest, budgetDecision);
    for (const auto& warning : budgetDecision.warnings) {
        log::Registry::sync()->warn(
            "[CloudSync] S3 price budget warning for vault {}: {}",
            engine->vault->id,
            warning);
    }
    if (!budgetDecision.allowed) {
        event->status = Event::Status::STALLED;
        event->stall_reason = budgetDecision.reason.empty()
            ? "S3 price budget would be exceeded"
            : budgetDecision.reason;
        log::Registry::sync()->warn(
            "[CloudSync] S3 price budget stalled vault {} before remote operations: {}",
            engine->vault->id,
            event->stall_reason);
        throw SyncStalled(event->stall_reason);
    }

    log::Registry::sync()->info(
        "[CloudSync] Estimated S3 cost pressure for vault {}: LIST={} HEAD={} GET={} PUT={} COPY={} DELETE={} body_download_bytes={} upload_bytes={} index_only_objects={} archive_skipped={}",
        engine->vault->id,
        estimate.list_requests,
        estimate.head_requests,
        estimate.get_requests,
        estimate.put_requests,
        estimate.copy_requests,
        estimate.delete_requests,
        estimate.planned_body_download_bytes,
        estimate.planned_upload_bytes,
        estimate.remote_index_objects,
        estimate.archive_tier_downloads_skipped);
    bool remoteExecutionStarted = false;
    try {
        remoteExecutionStarted = true;
        Executor::run(self, plan);
        event->computeDashboardStats();
        if (event->num_failed_ops == 0)
            cloud->applyRemoteIndexMutation(plan);
        budgetService.commit(
            budgetDecision.reservations,
            budgetPriceEstimate.available
                ? std::make_optional(budgetPriceEstimate.estimated_cost)
                : std::optional<std::string>{});
    } catch (...) {
        // Once the executor starts, remote writes may already have happened; committing
        // the reservation is intentionally conservative for the shared budget ledger.
        if (remoteExecutionStarted) budgetService.commit(budgetDecision.reservations, std::nullopt);
        else budgetService.release(budgetDecision.reservations);
        throw;
    }
}

void Cloud::initBins() {
    const auto cloud = cloudEngine();
    opaque = cloud->opaqueLayout();
    opaqueTally = {};
    const auto policy = cloud->remote_policy();
    const auto hooks = eventHooks();
    const auto vaultId = engine->vault->id;
    // Adoption with events (#96): one full listing after the subscription exists, whatever the index holds.
    const bool baseline = hooks.baselineNeeded && hooks.baselineNeeded(vaultId);
    const bool manifestRefreshed = !baseline && cloud->refreshRemoteIndexFromManifestIfChanged();
    // Recovery recipients (#370): envelopes an enrollment or a rotation couldn't write (the bucket was unreachable).
    try {
        (void)cloud->ensureRecoveryEnvelopes();
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[CloudSync] Vault {}: recovery envelopes not written this pass: {}", vaultId, e.what());
    }
    const auto indexSummary = db::query::sync::RemoteObjectIndex::summaryForVault(vaultId);
    const auto keptFresh = [&] {
        return hooks.indexFresh && policy->max_remote_index_age && hooks.indexFresh(vaultId, *policy->max_remote_index_age);
    };

    if (!baseline && (manifestRefreshed || indexSummary.object_count > 0)) {
        if (!manifestRefreshed && indexSummary.isStale(policy->max_remote_index_age) && !keptFresh()) {
            const auto age = indexSummary.indexed_at
                ? std::to_string(std::time(nullptr) - *indexSummary.indexed_at) + "s old"
                : std::string("missing indexed_at");
            throw SyncStalled(
                "remote index is stale and manifest refresh failed; index is " + age +
                ". Run vault sync reconcile, import S3 Inventory, or ingest S3 events before retrying.");
        }
        s3Map = groupEntriesByPath(db::query::sync::RemoteObjectIndex::listFilesForVault(engine->vault->id));
    } else {
        const auto listStartedAt = std::time(nullptr);
        if (opaque) {
            auto listing = cloud->listOpaqueBucket();
            s3Map = groupEntriesByPath(listing.objects);
            handleForeignObjects(listing.foreign);
        } else {
            s3Map = cloud->getGroupedFilesFromS3();
        }
        db::query::sync::RemoteObjectIndex::replaceFromListObjects(engine->vault->id, uMap2Vector(s3Map));
        // Published once, by this pass's applyRemoteIndexMutation together with what the pass changes (#248: the
        // first pass of a vault used to publish here and again after its uploads); if the pass never gets there,
        // operator() publishes it on the way out.
        cloud->markRemoteIndexRebuilt();
        // Every full listing is the event subscription's new baseline (adoption, lost continuity, or an empty index).
        if (hooks.baselineListed) hooks.baselineListed(vaultId, listStartedAt);
    }
    s3Files = uMap2Vector(s3Map);

    localFiles = db::query::fs::File::listFilesInDir(engine->vault->id);
    localMap = groupEntriesByPath(localFiles);
    if (opaque) keyByObjectUid();
    loadConflictState();

    event->heartbeat();
}

void Cloud::initScopedBins() {
    opaque = cloudEngine()->opaqueLayout();
    opaqueTally = {};
    if (opaque) {
        // opaque_v1: the scope names object keys; the file with that uid is the local side, and foreign keys are
        // reported or imported (an event subscription's foreign_objects).
        std::vector<std::string> foreign;
        for (const auto& key : scope->keys) {
            const auto text = vh::db::encoding::to_utf8_string(key);
            const auto uid = vh::storage::object_keys::uidOfContentKey(text);
            if (!uid) {
                auto bare = std::string_view(text);
                while (bare.starts_with('/')) bare.remove_prefix(1);
                if (vh::storage::object_keys::classify(bare) == vh::storage::object_keys::KeyClass::Foreign)
                    foreign.emplace_back(bare);
                continue;
            }
            if (auto remote = db::query::sync::RemoteObjectIndex::getFile(engine->vault->id, std::filesystem::path(key)))
                s3Map[key] = remote;
            if (auto local = db::query::sync::ObjectIdentity::fileByUid(engine->vault->id, *uid))
                localFiles.push_back(local);
        }
        handleForeignObjects(foreign);
        localMap = groupEntriesByPath(localFiles);
        keyByObjectUid();
        s3Files = uMap2Vector(s3Map);
        loadConflictState();
        log::Registry::sync()->debug("[CloudSync] Vault {}: scoped opaque pass over {} key(s) ({} remote, {} local, {} removed)",
                                     engine->vault->id, scope->keys.size(), s3Map.size(), localMap.size(),
                                     removedKeys.size());
        event->heartbeat();
        return;
    }
    // Only the keys the events named, straight from the index the events were applied to: no LIST, no manifest
    // refresh, no staleness gate (the scope is exactly what the provider just told us changed).
    for (const auto& key : scope->keys) {
        const std::filesystem::path path(key);
        if (auto remote = db::query::sync::RemoteObjectIndex::getFile(engine->vault->id, path)) s3Map[key] = remote;
        if (auto local = db::query::fs::File::getFileByPath(engine->vault->id, path)) localMap[key] = local;
    }
    s3Files = uMap2Vector(s3Map);
    localFiles = uMap2Vector(localMap);
    loadConflictState();
    log::Registry::sync()->debug("[CloudSync] Vault {}: scoped pass over {} key(s) ({} remote, {} local, {} removed)",
                                 engine->vault->id, scope->keys.size(), s3Map.size(), localMap.size(),
                                 removedKeys.size());
    event->heartbeat();
}

void Cloud::keyByObjectUid() {
    namespace keys = vh::storage::object_keys;
    std::unordered_map<std::u8string, std::shared_ptr<File>> locals;
    for (const auto& L : localFiles) {
        if (!L || !L->object_uid) {
            log::Registry::sync()->warn("[CloudSync] Vault {}: file {} has no object uid; it is not synced",
                                        engine->vault->id, L ? L->id : 0);
            continue;
        }
        locals[vh::fs::model::makeAbsolute(keys::contentKey(*L->object_uid)).u8string()] = L;
    }

    const auto trashed = db::query::sync::ObjectIdentity::trashedUids(engine->vault->id);
    std::unordered_map<std::u8string, std::shared_ptr<File>> remotes;
    for (const auto& [key, R] : s3Map) {
        if (!R) continue;
        const auto uid = keys::uidOfContentKey(vh::db::encoding::to_utf8_string(key));
        if (!uid) continue;   // not an o/<uid> row: nothing of this vault's
        const auto local = locals.find(key);
        if (local == locals.end()) {
            if (!trashed.contains(*uid)) ++opaqueTally.orphans;
            continue;
        }
        // Bound: the remote row is this file's object, at the file's path.
        auto bound = std::make_shared<File>(*R);
        bound->object_uid = uid;
        bound->remote_encrypted = true;
        bound->id = local->second->id;
        bound->path = local->second->path;
        bound->name = local->second->name;
        bound->vault_id = local->second->vault_id;
        remotes.emplace(key, std::move(bound));
    }
    if (opaqueTally.orphans)
        log::Registry::sync()->warn("[CloudSync] Vault {}: {} object(s) in o/ that no file names (orphans of an "
                                    "interrupted write, or a restore elsewhere); left alone, never downloaded",
                                    engine->vault->id, opaqueTally.orphans);
    localMap = std::move(locals);
    s3Map = std::move(remotes);
    localFiles = uMap2Vector(localMap);
    s3Files = uMap2Vector(s3Map);
}

void Cloud::handleForeignObjects(const std::vector<std::string>& keys) {
    if (keys.empty()) return;
    const auto vaultId = engine->vault->id;
    if (!vh::sync::events::subscriptions::importsForeignObjects(vaultId)) {
        opaqueTally.foreign_ignored += keys.size();
        log::Registry::sync()->warn("[CloudSync] Vault {}: {} foreign object(s) in the bucket (neither o/ nor "
                                    ".vaulthalla/); ignored and left untouched (foreign_objects = ignore)",
                                    vaultId, keys.size());
        return;
    }
    const auto cloud = cloudEngine();
    for (const auto& key : keys) {
        try {
            if (cloud->importForeignObject(key)) ++opaqueTally.foreign_imported;
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[CloudSync] Vault {}: a foreign object was not imported: {}", vaultId, e.what());
        }
    }
}

void Cloud::clearBins() {
    localFiles.clear();
    s3Files.clear();
    s3Map.clear();
    localMap.clear();
    remoteHashMap.clear();
    removedKeys.clear();
    baselines.clear();
    openConflicts.clear();
    conflictWrites = {};
}

// ##########################################
// ########### File Operations #############
// ##########################################

void Cloud::upload(const std::shared_ptr<File>& file) {
    push(std::make_shared<tasks::Upload>(
        cloudEngine(), file, op(Throughput::Metric::UPLOAD)));
}

void Cloud::download(const std::shared_ptr<File>& file, const bool freeAfterDownload) {
    push(std::make_shared<tasks::Download>(
        cloudEngine(),
        file,
        event->getOrCreateThroughput(Throughput::Metric::DOWNLOAD).newOp(),
        freeAfterDownload));
}

void Cloud::indexRemoteOnly(const std::shared_ptr<File>& file) {
    push(std::make_shared<tasks::Download>(
        cloudEngine(),
        file,
        event->getOrCreateThroughput(Throughput::Metric::INDEX).newOp(),
        true));
}

void Cloud::remove(const std::shared_ptr<File>& file, const tasks::Delete::Type& type) {
    push(std::make_shared<tasks::Delete>(
        cloudEngine(), file, op(Throughput::Metric::DELETE), type));
}

// ##########################################
// ############ Internal Helpers ############
// ##########################################

std::shared_ptr<CloudEngine> Cloud::cloudEngine() const {
    return std::static_pointer_cast<CloudEngine>(engine);
}

std::vector<EntryKey> Cloud::allKeysSorted() const {
    std::vector<EntryKey> keys;
    keys.reserve(localMap.size() + s3Map.size());

    for (const auto& [k, _] : localMap) keys.push_back({k});
    for (const auto& [k, _] : s3Map)    keys.push_back({k});

    std::ranges::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    return keys;
}

void Cloud::ensureDirectoriesFromRemote() {
    for (const auto& dir : cloudEngine()->extractDirectories(uMap2Vector(s3Map))) {
        if (!db::query::fs::Directory::directoryExists(engine->vault->id, dir->path)) {
            dir->parent_id = db::query::fs::Directory::getDirectoryIdByPath(
                engine->vault->id, dir->path.parent_path());

            if (dir->fuse_path.empty())
                dir->fuse_path = engine->paths->absPath(dir->path, PathType::VAULT_ROOT);

            dir->base32_alias = id::Generator({ .namespace_token = dir->name }).generate();
            db::query::fs::Directory::upsertDirectory(dir);
        }

        auto persisted = db::query::fs::Directory::getDirectoryByPath(engine->vault->id, dir->path);
        if (!persisted) continue;
        const auto cache = runtime::Deps::get().fsCache;
        if (!persisted->inode) {
            const auto cachePath = persisted->fuse_path.empty()
                ? engine->paths->absPath(persisted->path, PathType::VAULT_ROOT)
                : persisted->fuse_path;
            persisted->inode = cache->assignInode(cachePath);
            db::query::fs::Directory::upsertDirectory(persisted);
            persisted = db::query::fs::Directory::getDirectoryByPath(engine->vault->id, dir->path);
            if (!persisted) continue;
        }
        std::filesystem::create_directories(persisted->backing_path);
        cache->cacheEntry(persisted);
    }
}

// ##########################################
// ########### Conflict Handling ############
// ##########################################

bool Cloud::hasPotentialConflict(const std::shared_ptr<File>& local,
                                   const std::shared_ptr<File>& upstream,
                                   bool upstream_decryption_failure) {
    if (upstream_decryption_failure) return true;
    if (local->size_bytes != upstream->size_bytes) return true;

    if (local->content_hash && upstream->content_hash &&
        *local->content_hash != *upstream->content_hash)
        return true;

    return false;
}

std::shared_ptr<Conflict> Cloud::maybeBuildConflict(
    const std::shared_ptr<File>& local,
    const std::shared_ptr<File>& upstream) const
{
    if (!hasPotentialConflict(local, upstream, false)) return nullptr;

    auto c = std::make_shared<Conflict>();
    c->failed_to_decrypt_upstream = false; // Planner-time default
    c->artifacts.local = Artifact(local, Artifact::Side::LOCAL);
    c->artifacts.upstream = Artifact(upstream, Artifact::Side::UPSTREAM);
    c->analyze();

    if (c->reasons.empty()) {
        log::Registry::sync()->debug(
            "[SyncTask] hasPotentialConflict() returned true, but no reasons were identified. Possible detection bug.");
        return nullptr;
    }

    c->created_at = system_clock::to_time_t(system_clock::now());
    c->file_id = local->id;
    c->event_id = event->id;

    return c;
}

bool Cloud::handleConflict(const std::shared_ptr<Conflict>& c) {
    const bool ok = engine->sync->resolve_conflict(c);
    if (event) event->conflicts.push_back(c);

    const auto open = openConflicts.find(c->file_id);
    if (ok) {
        c->resolved_at = system_clock::to_time_t(system_clock::now());
        // The policy decided (it is no longer `ask`, or keep_newest found timestamps): close the open row too.
        if (open != openConflicts.end()) closeOpenConflict(c->file_id, c->resolutionToString());
        return false;
    }

    // One open row per file: write it when it is new or a side changed since it was recorded.
    if (open != openConflicts.end()) {
        c->id = open->second.id;
        const auto& L = c->artifacts.local.file;
        const auto& R = c->artifacts.upstream.file;
        const bool same = L && R &&
            db::query::sync::sideMatches(open->second.local, L->content_hash, L->size_bytes, std::nullopt) &&
            db::query::sync::sideMatches(open->second.remote, R->content_hash, R->size_bytes, R->remote_etag);
        if (same) return true;
    }
    conflictWrites.open.push_back(c);
    return true; // unresolved: nothing is planned for the file
}

void Cloud::loadConflictState() {
    baselines = db::query::sync::Conflict::baselinesForVault(engine->vault->id);
    openConflicts = db::query::sync::Conflict::openForVault(engine->vault->id);
    conflictWrites = {};
}

void Cloud::flushConflictState() {
    if (conflictWrites.empty()) return;
    const std::optional<uint32_t> eventId = event && event->id ? std::make_optional(event->id) : std::nullopt;
    db::query::sync::Conflict::applyPass(engine->vault->id, eventId, conflictWrites);
    if (!conflictWrites.open.empty() || !conflictWrites.close.empty())
        log::Registry::sync()->info(
            "[CloudSync] Vault {}: {} conflict(s) recorded or refreshed, {} closed",
            engine->vault->id, conflictWrites.open.size(), conflictWrites.close.size());
    for (const auto& b : conflictWrites.baselines) baselines[b.file_id] = b;
    for (const auto& [fileId, _] : conflictWrites.close) openConflicts.erase(fileId);
    conflictWrites = {};
}

const Baseline* Cloud::baselineFor(const uint32_t fileId) const {
    const auto it = baselines.find(fileId);
    return it == baselines.end() ? nullptr : &it->second;
}

bool Cloud::hasOpenConflict(const uint32_t fileId) const {
    return openConflicts.contains(fileId) &&
           std::ranges::none_of(conflictWrites.close, [&](const auto& c) { return c.first == fileId; });
}

void Cloud::noteInSync(const File& local, const File& remote) {
    if (!local.id) return;
    if (hasOpenConflict(local.id)) closeOpenConflict(local.id, "converged");
    const auto agreed = Baseline::agreed(local, remote);
    if (const auto* current = baselineFor(local.id); current && current->sameAs(agreed)) return;
    conflictWrites.baselines.push_back(agreed);
}

void Cloud::closeOpenConflict(const uint32_t fileId, const std::string& resolution) {
    if (!hasOpenConflict(fileId)) return;
    conflictWrites.close.emplace_back(fileId, resolution);
}

// ##########################################
// ########### Static Helpers ###############
// ##########################################

uintmax_t Cloud::computeReqFreeSpaceForDownload(
    const std::vector<std::shared_ptr<File> >& files) {
    uintmax_t totalSize = 0;
    for (const auto& file : files) totalSize += file->size_bytes;
    return totalSize;
}

std::vector<std::shared_ptr<File>> Cloud::uMap2Vector(
    std::unordered_map<std::u8string, std::shared_ptr<File>>& map)
{
    std::vector<std::shared_ptr<File>> files;
    files.reserve(map.size());

    std::ranges::transform(
        map.begin(), map.end(),
        std::back_inserter(files),
        [](const auto& pair) { return pair.second; });

    return files;
}

std::unordered_map<std::u8string, std::shared_ptr<File>> Cloud::intersect(
    const std::unordered_map<std::u8string, std::shared_ptr<File> >& a,
    const std::unordered_map<std::u8string, std::shared_ptr<File> >& b)
{
    std::unordered_map<std::u8string, std::shared_ptr<File>> result;
    for (const auto& item : a)
        if (b.contains(item.first))
            result.insert(item);

    return result;
}
