#include "sync/Planner.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/Cloud.hpp"
#include "sync/model/helpers.hpp"
#include "sync/model/Conflict.hpp"
#include "sync/model/Baseline.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"

using namespace vh::sync;
using namespace vh::sync::model;
using namespace vh::fs::model;

std::vector<Action> Planner::build(
    const std::shared_ptr<Cloud>& ctx,
    const std::shared_ptr<RemotePolicy>& policy,
    S3CostEstimate* planningNotes)
{
    std::vector<Action> plan;

    if (policy->wantsEnsureDirectories()) {
        plan.push_back({ ActionType::EnsureDirectories, {.rel = u8""}, nullptr, nullptr });
    }

    const auto keys = ctx->allKeysSorted();
    plan.reserve(keys.size() + 8);

    for (const auto& k : keys) {
        std::shared_ptr<File> L;
        std::shared_ptr<File> R;

        if (auto it = ctx->localMap.find(k.rel); it != ctx->localMap.end()) L = it->second;
        if (auto it = ctx->s3Map.find(k.rel);    it != ctx->s3Map.end())    R = it->second;

        if (L && !R) {
            // The remote side of an open conflict went away: there is nothing left to decide between.
            if (ctx->hasOpenConflict(L->id)) ctx->closeOpenConflict(L->id, "superseded");
            // The provider said the object was removed (#96). A listing can't tell a deletion from an absence, an
            // event can: a local copy nobody changed since both sides last agreed follows the deletion; one that
            // changed (or never synced) is kept and uploaded again, as before.
            // (mirror + keep_remote deletes every local leftover below anyway.)
            if (ctx->removedKeys.contains(k.rel) && policy->propagatesRemoteRemoval() && !policy->deleteLocalLeftovers()) {
                const auto* base = ctx->baselineFor(L->id);
                if (base && !localChangedSince(*L, *base)) {
                    plan.push_back({ ActionType::DeleteLocal, k, L, nullptr });
                    continue;
                }
                log::Registry::sync()->info(
                    "[SyncPlanner] '{}' was removed upstream but its local copy changed since the last sync (or was never "
                    "synced); keeping it", L->path.string());
            }
            if (policy->uploadLocalOnly())
                plan.push_back({ ActionType::Upload, k, L, nullptr });
            continue;
        }

        if (!L && R) {
            if (policy->downloadRemoteOnly()) {
                const bool indexOnly = policy->strategy == RemotePolicy::Strategy::Cache;
                if (!indexOnly && R->requiresArchiveRestoreForBodyGet()) {
                    if (planningNotes) ++planningNotes->archive_tier_downloads_skipped;
                    log::Registry::sync()->warn(
                        "[SyncPlanner] Skipping automatic body GET for archived S3 object '{}'",
                        R->path.string());
                    continue;
                }

                plan.push_back({ indexOnly ? ActionType::IndexRemoteOnly : ActionType::Download, k, nullptr, R, indexOnly });
            }
            continue;
        }

        if (L && R) {
            // An event said the object was overwritten by someone else (#96). A local copy unchanged since both sides
            // last agreed takes the new object; a changed one goes through the conflict path below as a two-sided
            // change (the baseline alone can miss a same-size overwrite of an object Vaulthalla uploaded).
            if (ctx->scope && ctx->scope->changed.contains(k.rel) && !ctx->hasOpenConflict(L->id)) {
                const auto* base = ctx->baselineFor(L->id);
                if (base && !localChangedSince(*L, *base)) {
                    if (R->requiresArchiveRestoreForBodyGet()) {
                        if (planningNotes) ++planningNotes->archive_tier_downloads_skipped;
                        continue;
                    }
                    plan.push_back({ ActionType::Download, k, L, R });
                    continue;
                }
            }

            // Fast-path skip if equal content (let ctx decide via hashes, remoteHashMap, etc.)
            if (*L == *R) {
                ctx->noteInSync(*L, *R);
                continue;
            }

            if (!Cloud::hasPotentialConflict(L, R, false)) {
                // Same content (size and hash agree, or no hash to disagree): both sides are in sync for conflict
                // purposes. An open conflict on it converged on its own. Metadata-only differences still go through
                // decideForBoth below, as before.
                ctx->noteInSync(*L, *R);
            } else {
                // Compared with what both sides were at their last sync (#187). Neither side changed since: nothing
                // to transfer under any policy (#190). files.content_hash hashes the sealed bytes, so a file this
                // vault downloaded never hash-matches the object it came from, and keep_* would fetch it every pass.
                auto divergence = ctx->hasOpenConflict(L->id) ? Divergence::Unknown
                                                              : classify(*L, *R, ctx->baselineFor(L->id));
                // The remote side changed (an event said so): a local-only reading is really both sides.
                if (ctx->scope && ctx->scope->changed.contains(k.rel) && divergence == Divergence::LocalOnly)
                    divergence = Divergence::Both;
                if (divergence == Divergence::InSync) continue;

                // Under `ask`, only a change on both sides is a conflict. A change on one side syncs in that
                // direction; a file with an open conflict waits for its decision. keep_* settle any real difference.
                if (policy->conflict_policy == RemotePolicy::ConflictPolicy::Ask && !ctx->hasOpenConflict(L->id)) {
                    switch (divergence) {
                    case Divergence::InSync:
                        continue;
                    case Divergence::LocalOnly:
                        plan.push_back({ ActionType::Upload, k, L, R });
                        continue;
                    case Divergence::RemoteOnly:
                        if (R->requiresArchiveRestoreForBodyGet()) {
                            if (planningNotes) ++planningNotes->archive_tier_downloads_skipped;
                            log::Registry::sync()->warn(
                                "[SyncPlanner] Skipping automatic body GET for archived S3 object '{}'",
                                R->path.string());
                            continue;
                        }
                        plan.push_back({ ActionType::Download, k, L, R });
                        continue;
                    case Divergence::Both:
                    case Divergence::Unknown:
                        break;
                    }
                }

                // Conflict check lives in ctx (since it needs hashes/mtimes/last_success_at/etc.)
                if (auto c = ctx->maybeBuildConflict(L, R)) {
                    if (ctx->handleConflict(c)) continue; // unresolved: recorded once, the file waits

                    // auto-resolved => planner needs to translate resolution into an action
                    switch (c->resolution) {
                    case Conflict::Resolution::KEPT_LOCAL:
                        plan.push_back({ ActionType::Upload, k, L, R });
                        break;
                    case Conflict::Resolution::KEPT_REMOTE:
                        plan.push_back({ ActionType::Download, k, L, R });
                        break;
                    // TODO: finishing handling Resolution cases (e.g. KEPT_BOTH, etc.)
                    default:
                        break;
                    }
                    continue;
                }
            }

            // Non-conflict decision: by strategy/policy
            if (auto a = policy->decideForBoth(L, R)) {
                if (*a == ActionType::Download && R->requiresArchiveRestoreForBodyGet()) {
                    if (planningNotes) ++planningNotes->archive_tier_downloads_skipped;
                    log::Registry::sync()->warn(
                        "[SyncPlanner] Skipping automatic body GET for archived S3 object '{}'",
                        R->path.string());
                    continue;
                }
                plan.push_back({ *a, k, L, R });
            }
        }
    }

    if (policy->deleteRemoteLeftovers())
        for (auto& [rel, r] : ctx->s3Map)
            if (!ctx->localMap.contains(rel))
                plan.push_back({ ActionType::DeleteRemote, {rel}, nullptr, r });

    if (policy->deleteLocalLeftovers())
        for (auto& [rel, l] : ctx->localMap)
            if (!ctx->s3Map.contains(rel))
                plan.push_back({ ActionType::DeleteLocal, {rel}, l, nullptr });

    policy->preflightSpaceForPlan(ctx, plan);
    return plan;
}

S3CostEstimate Planner::estimateS3Cost(const std::vector<Action>& plan) {
    S3CostEstimate estimate;
    bool mutatesRemoteIndex = false;

    for (const auto& action : plan) {
        switch (action.type) {
        case ActionType::Upload:
            ++estimate.put_requests;
            if (action.local) estimate.planned_upload_bytes += action.local->size_bytes;
            mutatesRemoteIndex = true;
            break;
        case ActionType::Download:
            ++estimate.get_requests;
            estimate.head_requests += 2;
            if (action.remote) estimate.planned_body_download_bytes += action.remote->size_bytes;
            else if (action.local) estimate.planned_body_download_bytes += action.local->size_bytes;
            break;
        case ActionType::IndexRemoteOnly:
            ++estimate.remote_index_objects;
            break;
        case ActionType::DeleteRemote:
            ++estimate.delete_requests;
            mutatesRemoteIndex = true;
            break;
        case ActionType::EnsureDirectories:
        case ActionType::DeleteLocal:
            break;
        }
    }

    if (mutatesRemoteIndex) {
        ++estimate.put_requests;
        estimate.head_requests += 2;
    }

    return estimate;
}
