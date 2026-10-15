#include "sync/events/Applier.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/u8.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "db/query/upstream/WriteIntent.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/S3Vault.hpp"

#include <algorithm>
#include <map>

namespace vh::sync::events {

namespace {

namespace amodel = storage::upstream::model;
using InboxRow = amodel::InboxEvent;

constexpr unsigned int kApplyBatch = 500;
constexpr unsigned int kScheduleBatch = 1000;
constexpr std::time_t kProtectedRetrySeconds = 600;

std::string unquote(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    return etag;
}

// a is newer than (or as new as) b, for two events of one key.
bool newerOrEqual(const InboxRow& a, const InboxRow& b) {
    if (a.sequencer && b.sequencer && !a.sequencer->empty() && !b.sequencer->empty())
        return db::query::sync::s3SequencerIsNewerOrEqual(a.sequencer, b.sequencer);
    if (a.event_time != b.event_time) return a.event_time > b.event_time;
    return a.id >= b.id;
}

std::u8string scopeKey(const std::string& objectKey) {
    return fs::model::makeAbsolute(objectKey).u8string();
}

std::shared_ptr<storage::CloudEngine> cloudEngineFor(const uint32_t vaultId) {
    const auto& storage = runtime::Deps::get().storageManager;
    const auto engine = storage ? storage->getEngine(vaultId) : nullptr;
    if (!engine || engine->type() != storage::StorageType::Cloud) return nullptr;
    return std::static_pointer_cast<storage::CloudEngine>(engine);
}

std::time_t passBackoff(const unsigned int attempts) {
    const auto exp = std::min(attempts, 6u);
    return std::min<std::time_t>(600, std::time_t{10} << exp);
}

}

Applier::Applier() : Applier(Hooks{}) {}

Applier::Applier(Hooks hooks) : hooks_(std::move(hooks)) {
    if (!hooks_.tryAcquirePass)
        hooks_.tryAcquirePass = [](const uint32_t v) {
            const auto& c = runtime::Deps::get().syncController;
            return !c || c->tryAcquirePass(v);
        };
    if (!hooks_.releasePass)
        hooks_.releasePass = [](const uint32_t v) {
            if (const auto& c = runtime::Deps::get().syncController) c->releasePass(v);
        };
    if (!hooks_.runScoped)
        hooks_.runScoped = [](const uint32_t v, std::shared_ptr<model::PassScope> scope) {
            const auto& c = runtime::Deps::get().syncController;
            if (!c) return Controller::ScopedResult::NoEngine;
            return c->runScoped(v, std::move(scope));
        };
}

Applier::Outcome Applier::applyVault(const uint32_t vaultId) {
    Outcome out;
    const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
    if (sub && (sub->baseline_state == amodel::BaselineState::Pending ||
                sub->baseline_state == amodel::BaselineState::Running)) {
        out.held = true;   // adoption: events wait for the first full listing
        return out;
    }

    const auto rows = db::query::upstream::Inbox::claimForVault(vaultId, kApplyBatch);
    out.claimed = rows.size();
    if (!rows.empty()) {
        std::vector<int64_t> ids;
        for (const auto& r : rows) ids.push_back(r.id);

        const auto engine = cloudEngineFor(vaultId);
        if (!engine) {
            db::query::upstream::Inbox::markSkipped(ids, "vault is not active (no S3 storage engine)", amodel::InboxOrigin::Unknown);
            out.skipped = rows.size();
            return out;
        }
        const auto s3 = std::static_pointer_cast<vault::model::S3Vault>(engine->vault);
        const auto key = engine->s3ApiKey();
        if (key && storage::upstream::guard::isProtected(storage::upstream::identityFor(*key, s3->bucket))) {
            // Never touched, never lost: the rows wait for an unprotect.
            const auto retry = std::time(nullptr) + kProtectedRetrySeconds;
            for (const auto id : ids) db::query::upstream::Inbox::markFailed(id, "bucket is protected", retry);
            if (sub) db::query::upstream::Subscription::setState(sub->id, amodel::SubscriptionState::Failed, "bucket is protected");
            out.failed = rows.size();
            return out;
        }
        if (!hooks_.tryAcquirePass(vaultId)) {
            out.busy = true;
            return out;
        }
        struct Lease {
            const Hooks& hooks;
            uint32_t vault;
            ~Lease() { hooks.releasePass(vault); }
        } lease{hooks_, vaultId};

        std::optional<storage::ScopedS3RequestUsageCapture> capture;
        const auto meter = [&] {
            if (!capture) capture.emplace(*engine, engine->remote_policy()->s3_request_budget);
        };

        // Rows arrive ordered by key, then provider order: group them.
        std::map<std::string, std::vector<const InboxRow*>> byKey;
        for (const auto& r : rows) byKey[r.object_key].push_back(&r);

        for (const auto& [objectKey, group] : byKey) {
            const InboxRow* latest = group.front();
            for (const auto* r : group)
                if (newerOrEqual(*r, *latest)) latest = r;
            try {

                // Older events of the key: superseded. Each still consumes a matching write intent of ours, so a
                // stale intent can never claim a later external event.
                for (const auto* r : group) {
                    if (r == latest) continue;
                    const bool self = db::query::upstream::WriteIntent::consumeMatching(
                        vaultId, objectKey, r->kind == amodel::InboxKind::Removed ? amodel::WriteOp::Delete : amodel::WriteOp::Put,
                        r->size_bytes, r->event_time);
                    db::query::upstream::Inbox::markSkipped({r->id}, "superseded by a newer event for the key",
                                                            self ? amodel::InboxOrigin::Self : amodel::InboxOrigin::External);
                    ++out.skipped;
                }

                if (sub && sub->baseline_started_at &&
                    latest->event_time + kBaselineSkewSeconds < *sub->baseline_started_at) {
                    db::query::upstream::Inbox::markSkipped({latest->id}, "superseded by the baseline listing",
                                                            amodel::InboxOrigin::Unknown);
                    ++out.skipped;
                    continue;
                }

                // An older event that arrives after a newer one was already settled (a create delayed past its
                // delete): the inbox remembers the key's history even when the index row is gone.
                if (const auto newest = db::query::upstream::Inbox::latestForKey(vaultId, objectKey);
                    newest && newest->id != latest->id && newest->state != amodel::InboxState::Pending &&
                    !newerOrEqual(*latest, *newest)) {
                    db::query::upstream::Inbox::markSkipped({latest->id}, "stale: a newer event for the key was already handled",
                                                            amodel::InboxOrigin::Unknown);
                    ++out.skipped;
                    continue;
                }

                const auto indexed = db::query::sync::RemoteObjectIndex::getFile(vaultId, objectKey);
                if (latest->sequencer && indexed && indexed->remote_sequencer &&
                    !db::query::sync::s3SequencerIsNewerOrEqual(latest->sequencer, indexed->remote_sequencer)) {
                    db::query::upstream::Inbox::markSkipped({latest->id}, "stale: the index holds a newer event",
                                                            amodel::InboxOrigin::Unknown);
                    ++out.skipped;
                    continue;
                }

                if (latest->kind == amodel::InboxKind::Created) {
                    const bool self = db::query::upstream::WriteIntent::consumeMatching(
                        vaultId, objectKey, amodel::WriteOp::Put, latest->size_bytes, latest->event_time);
                    if (self) {
                        // Our own upload: keep the row Vaulthalla wrote (with its encryption metadata), learn the ETag.
                        if (indexed) {
                            if (latest->etag) indexed->remote_etag = latest->etag;
                            if (latest->sequencer) indexed->remote_sequencer = latest->sequencer;
                            if (latest->version_id) indexed->remote_version_id = latest->version_id;
                            db::query::sync::RemoteObjectIndex::upsertFile(vaultId, indexed, "event");
                        }
                        db::query::upstream::Inbox::markSkipped({latest->id}, "self: Vaulthalla's own write",
                                                                amodel::InboxOrigin::Self);
                        ++out.self;
                        continue;
                    }
                    if (indexed && indexed->remote_etag && latest->etag &&
                        unquote(*indexed->remote_etag) == unquote(*latest->etag)) {
                        db::query::upstream::Inbox::markSkipped({latest->id}, "unchanged: the index already has this object",
                                                                amodel::InboxOrigin::External);
                        ++out.skipped;
                        continue;
                    }
                    if (sub && sub->foreign_objects == amodel::ForeignObjects::Ignore && !indexed &&
                        !db::query::fs::File::getFileByPath(vaultId, fs::model::makeAbsolute(objectKey))) {
                        // A new object nobody in this vault knows: only Vaulthalla-written objects are imported.
                        meter();
                        const auto head = engine->headRemoteObject(objectKey);
                        if (!head || !head->encrypted) {
                            db::query::upstream::Inbox::markSkipped(
                                {latest->id}, head ? "foreign object ignored (no Vaulthalla metadata)" : "object vanished",
                                amodel::InboxOrigin::External);
                            ++out.skipped;
                            continue;
                        }
                    }
                    auto file = std::make_shared<fs::model::File>(objectKey, latest->size_bytes.value_or(0),
                                                                  std::make_optional(latest->event_time));
                    file->remote_etag = latest->etag;
                    file->remote_sequencer = latest->sequencer;
                    file->remote_version_id = latest->version_id;
                    db::query::sync::RemoteObjectIndex::upsertEventFile(vaultId, file);
                    out.index_changed = true;
                    db::query::upstream::Inbox::markApplied({latest->id}, amodel::InboxOrigin::External);
                    ++out.applied;
                } else {
                    const bool self = db::query::upstream::WriteIntent::consumeMatching(
                        vaultId, objectKey, amodel::WriteOp::Delete, std::nullopt, latest->event_time);
                    if (self) {
                        // The pass that deleted it already took it off the index.
                        db::query::upstream::Inbox::markSkipped({latest->id}, "self: Vaulthalla's own delete",
                                                                amodel::InboxOrigin::Self);
                        ++out.self;
                        continue;
                    }
                    db::query::sync::RemoteObjectIndex::deleteEventKey(vaultId, objectKey, latest->sequencer);
                    if (indexed) out.index_changed = true;
                    db::query::upstream::Inbox::markApplied({latest->id}, amodel::InboxOrigin::External);
                    ++out.applied;
                }
            } catch (const storage::s3::RequestBudgetExceeded& e) {
                // Left pending: the next batch gets a fresh budget window.
                log::Registry::sync()->warn("[UpstreamEvents] Vault {}: request budget stopped event apply: {}", vaultId, e.what());
                break;
            } catch (const storage::upstream::BucketProtected&) {
                throw;
            } catch (const std::exception& e) {
                // The key's newest row is retried (older ones were settled as superseded above).
                db::query::upstream::Inbox::markFailed(latest->id, e.what(),
                                                       std::time(nullptr) + passBackoff(latest->attempts));
                ++out.failed;
                log::Registry::sync()->warn("[UpstreamEvents] Vault {}: applying events for '{}' failed: {}", vaultId,
                                            objectKey, e.what());
            }
        }

        // The index manifest follows the index while the lease is held, so a regular pass never reloads a manifest
        // that predates these events (it would resurrect deleted objects).
        if (out.index_changed) {
            try {
                meter();
                engine->publishRemoteIndexManifestWithRetry();
            } catch (const std::exception& e) {
                log::Registry::sync()->warn("[UpstreamEvents] Vault {}: index manifest not republished after events: {}",
                                            vaultId, e.what());
            }
        }
    }

    schedule(vaultId, out);
    return out;
}

void Applier::schedule(const uint32_t vaultId, Outcome& out) {
    const auto rows = db::query::upstream::Inbox::listApplied(vaultId, kScheduleBatch);
    if (rows.empty()) return;

    auto scope = std::make_shared<model::PassScope>();
    std::map<std::string, const InboxRow*> latest;
    unsigned int attempts = 0;
    for (const auto& r : rows) {
        scope->inbox_ids.push_back(r.id);
        attempts = std::max(attempts, r.attempts);
        auto& slot = latest[r.object_key];
        if (!slot || newerOrEqual(r, *slot)) slot = &r;
    }
    for (const auto& [objectKey, r] : latest) {
        const auto key = scopeKey(objectKey);
        scope->keys.insert(key);
        if (r->kind == amodel::InboxKind::Removed) scope->removed.insert(key);
        else scope->changed.insert(key);
    }

    const auto ids = scope->inbox_ids;
    scope->on_finish = [vaultId, ids, attempts](const bool ok, const std::string& error) {
        try {
            if (ok) {
                db::query::upstream::Inbox::markDone(ids);
            } else if (attempts + 1 >= kMaxPassAttempts) {
                for (const auto id : ids) db::query::upstream::Inbox::markFailed(id, error, std::nullopt);
            } else {
                db::query::upstream::Inbox::requeueApplied(vaultId, ids, std::time(nullptr) + passBackoff(attempts), error);
            }
        } catch (const std::exception& e) {
            log::Registry::sync()->error("[UpstreamEvents] Vault {}: could not settle {} event(s): {}", vaultId, ids.size(), e.what());
        }
    };

    switch (hooks_.runScoped(vaultId, scope)) {
    case Controller::ScopedResult::Started:
        out.pass_started = true;
        break;
    case Controller::ScopedResult::Busy:
        out.busy = true;
        break;
    case Controller::ScopedResult::Disabled:
        db::query::upstream::Inbox::markSkipped(ids, "sync disabled: the index was updated, nothing transferred",
                                                amodel::InboxOrigin::External);
        break;
    case Controller::ScopedResult::NoEngine:
        for (const auto id : ids) db::query::upstream::Inbox::markFailed(id, "vault has no S3 storage engine", std::nullopt);
        break;
    }
}

std::unordered_set<std::u8string> Applier::pendingRemovals(const uint32_t vaultId) {
    std::unordered_set<std::u8string> keys;
    db::Transactions::exec("upstream::Applier::pendingRemovals", [&](pqxx::work& txn) {
        const auto res = txn.exec("SELECT DISTINCT object_key FROM upstream_event_inbox "
                                  "WHERE vault_id = $1 AND state = 'applied' AND kind = 'removed'",
                                  pqxx::params{vaultId});
        for (const auto& row : res) keys.insert(scopeKey(row["object_key"].as<std::string>()));
    });
    return keys;
}

void Applier::onBaselineListed(const uint32_t vaultId, const std::time_t listStartedAt) {
    const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
    if (!sub || (sub->baseline_state != amodel::BaselineState::Pending &&
                 sub->baseline_state != amodel::BaselineState::Running))
        return;
    db::query::upstream::Subscription::setBaseline(sub->id, amodel::BaselineState::Done, listStartedAt);
    log::Registry::sync()->info("[UpstreamEvents] Vault {}: baseline listing done; held events are applied next", vaultId);
}

bool Applier::baselineNeeded(const uint32_t vaultId) {
    const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
    return sub && sub->state == amodel::SubscriptionState::Active &&
           (sub->baseline_state == amodel::BaselineState::Pending || sub->baseline_state == amodel::BaselineState::Running);
}

bool Applier::indexKeptFresh(const uint32_t vaultId, const std::chrono::seconds maxAge) {
    const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
    if (!sub || sub->state != amodel::SubscriptionState::Active || !sub->channel_id) return false;
    if (sub->baseline_state == amodel::BaselineState::Pending || sub->baseline_state == amodel::BaselineState::Running)
        return false;
    const auto channel = db::query::upstream::Channel::get(*sub->channel_id);
    if (!channel || !channel->last_success_at) return false;
    return std::time(nullptr) - *channel->last_success_at <= maxAge.count();
}

}
