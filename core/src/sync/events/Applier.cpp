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
#include "sync/model/RemoteManifest.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/S3Vault.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace vh::sync::events {

namespace {

namespace amodel = storage::upstream::model;
using InboxRow = amodel::InboxEvent;

constexpr unsigned int kApplyBatch = 500;
constexpr unsigned int kScheduleBatch = 1000;
constexpr std::time_t kProtectedRetrySeconds = 600;

std::string applierUnquote(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    return etag;
}

int64_t eventMs(const InboxRow& r) { return r.event_time_ms.value_or(static_cast<int64_t>(r.event_time) * 1000); }

bool hasSequencer(const InboxRow& r) { return r.sequencer && !r.sequencer->empty(); }

// Two events of one key that nothing orders: no pair of sequencers, the same millisecond.
bool tied(const InboxRow& a, const InboxRow& b) {
    return !(hasSequencer(a) && hasSequencer(b)) && eventMs(a) == eventMs(b);
}

// a is newer than (or as new as) b, for two events of one key. Sequencers when both have one (AWS: left-pad, then
// compare), else event time in milliseconds. A true tie between a create and a removal favours the removal: the
// removal path confirms with a HEAD whether the object exists, so the tie is decided by the provider, not by arrival.
bool newerOrEqual(const InboxRow& a, const InboxRow& b) {
    if (hasSequencer(a) && hasSequencer(b)) return db::query::sync::s3SequencerIsNewerOrEqual(a.sequencer, b.sequencer);
    if (eventMs(a) != eventMs(b)) return eventMs(a) > eventMs(b);
    if (a.kind != b.kind) return a.kind == amodel::InboxKind::Removed;
    return a.id >= b.id;
}

amodel::WriteOp opOf(const InboxRow& r) {
    return r.kind == amodel::InboxKind::Removed ? amodel::WriteOp::Delete : amodel::WriteOp::Put;
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

// What one HEAD says the object is now, as an index row.
std::shared_ptr<fs::model::File> fileFromHead(const std::string& objectKey, const storage::CloudEngine::RemoteObjectHead& head) {
    auto file = std::make_shared<fs::model::File>(objectKey, head.content_length.value_or(0),
                                                  std::make_optional(std::time(nullptr)));
    if (!head.etag.empty()) file->remote_etag = head.etag;
    file->remote_encrypted = head.encrypted;
    if (head.encrypted && !head.iv_b64.empty()) {
        file->encryption_iv = head.iv_b64;
        file->encrypted_with_key_version = head.key_version;
    }
    file->content_hash = head.content_hash;
    return file;
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
    if (!hooks_.regularWaiting)
        hooks_.regularWaiting = [](const uint32_t v) {
            const auto& c = runtime::Deps::get().syncController;
            return c && c->regularWaiting(v);
        };
    if (!hooks_.shouldStop) hooks_.shouldStop = [] { return false; };
}

Applier::Outcome Applier::applyVault(const uint32_t vaultId) {
    Outcome out;
    const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
    if (sub && (sub->baseline_state == amodel::BaselineState::Pending ||
                sub->baseline_state == amodel::BaselineState::Running)) {
        out.held = true;   // adoption or lost continuity: events wait for the next full listing
        return out;
    }
    // A regular pass is waiting for the lease: let it have it (uploads, trash purge and rotation run there).
    if (hooks_.regularWaiting(vaultId)) {
        out.busy = true;
        return out;
    }

    const auto engine = cloudEngineFor(vaultId);
    if (!engine) {
        const auto rows = db::query::upstream::Inbox::claimForVault(vaultId, kApplyBatch);
        std::vector<int64_t> ids;
        for (const auto& r : rows) ids.push_back(r.id);
        db::query::upstream::Inbox::markSkipped(ids, "vault is not active (no S3 storage engine)", amodel::InboxOrigin::Unknown);
        out.claimed = out.skipped = rows.size();
        return out;
    }
    const auto s3 = std::static_pointer_cast<vault::model::S3Vault>(engine->vault);
    const auto key = engine->s3ApiKey();
    if (key && storage::upstream::guard::isProtected(storage::upstream::identityFor(*key, s3->bucket))) {
        // Never touched, never lost: the rows wait for an unprotect.
        const auto rows = db::query::upstream::Inbox::claimForVault(vaultId, kApplyBatch);
        const auto retry = std::time(nullptr) + kProtectedRetrySeconds;
        for (const auto& r : rows) db::query::upstream::Inbox::markFailed(r.id, "bucket is protected", retry);
        if (sub && !rows.empty())
            db::query::upstream::Subscription::setState(sub->id, amodel::SubscriptionState::Failed, "bucket is protected");
        out.claimed = out.failed = rows.size();
        return out;
    }

    // The lease first, then the batch: two appliers (the service and a manual ingest) can never work the same rows.
    if (!hooks_.tryAcquirePass(vaultId)) {
        out.busy = true;
        return out;
    }
    bool stopped = false;
    {
        struct Lease {
            const Hooks& hooks;
            uint32_t vault;
            ~Lease() { hooks.releasePass(vault); }
        } lease{hooks_, vaultId};

        const auto rows = db::query::upstream::Inbox::claimForVault(vaultId, kApplyBatch);
        out.claimed = rows.size();

        std::optional<storage::ScopedS3RequestUsageCapture> capture;
        const auto meter = [&] {
            if (!capture) capture.emplace(*engine, engine->remote_policy()->s3_request_budget);
        };

        // Rows arrive ordered by key, then provider order: group them.
        std::map<std::string, std::vector<const InboxRow*>> byKey;
        for (const auto& r : rows) byKey[r.object_key].push_back(&r);

        for (const auto& [objectKey, group] : byKey) {
            if (hooks_.shouldStop()) {
                stopped = true;   // rows not reached stay pending for the next start
                break;
            }

            std::vector<int64_t> groupIds;
            for (const auto* r : group) groupIds.push_back(r->id);

            // Vaulthalla's own index manifest: never an object of the vault, and republishing it after "applying" its
            // own notification would feed itself forever.
            if (model::remote_manifest::isVaulthallaManifestKey(objectKey)) {
                db::query::upstream::Inbox::markSkipped(groupIds, "Vaulthalla's index manifest", amodel::InboxOrigin::Self);
                out.skipped += group.size();
                continue;
            }

            const InboxRow* latest = group.front();
            for (const auto* r : group)
                if (newerOrEqual(*r, *latest)) latest = r;
            std::set<int64_t> settled;
            try {
                // A removal is only believed once the provider confirms the object is gone (a forged or misordered
                // notification must not delete anything). Still there: the newest create of the batch wins instead,
                // or, without one, the index learns the object from the HEAD.
                if (latest->kind == amodel::InboxKind::Removed &&
                    !db::query::upstream::Inbox::settleOwnWrite(latest->id, vaultId, objectKey, amodel::WriteOp::Delete,
                                                                std::nullopt, latest->event_time, std::nullopt,
                                                                "self: Vaulthalla's own delete")) {
                    meter();
                    if (const auto head = engine->headRemoteObjectStrict(objectKey)) {
                        db::query::upstream::Inbox::markSkipped({latest->id}, "removal not confirmed: the object still exists",
                                                                amodel::InboxOrigin::External);
                        ++out.skipped;
                        settled.insert(latest->id);
                        const InboxRow* create = nullptr;
                        for (const auto* r : group)
                            if (r->kind == amodel::InboxKind::Created && (!create || newerOrEqual(*r, *create))) create = r;
                        if (create) {
                            latest = create;
                        } else {
                            const auto indexed = db::query::sync::RemoteObjectIndex::getFile(vaultId, objectKey);
                            if (!indexed || !indexed->remote_etag ||
                                applierUnquote(*indexed->remote_etag) != applierUnquote(head->etag)) {
                                db::query::sync::RemoteObjectIndex::upsertEventFile(vaultId, fileFromHead(objectKey, *head));
                                out.index_changed = true;
                            }
                            for (const auto* r : group)
                                if (!settled.contains(r->id)) {
                                    db::query::upstream::Inbox::markSkipped({r->id}, "superseded by a newer event for the key",
                                                                            amodel::InboxOrigin::External);
                                    ++out.skipped;
                                }
                            continue;
                        }
                    }
                } else if (latest->kind == amodel::InboxKind::Removed) {
                    // Our own delete: the pass that issued it already took it off the index.
                    settled.insert(latest->id);
                    ++out.self;
                    for (const auto* r : group)
                        if (!settled.contains(r->id)) {
                            if (!db::query::upstream::Inbox::settleOwnWrite(r->id, vaultId, objectKey, opOf(*r), r->size_bytes,
                                                                             r->event_time, r->etag,
                                                                             "self: superseded by a newer event for the key"))
                                db::query::upstream::Inbox::markSkipped({r->id}, "superseded by a newer event for the key",
                                                                        amodel::InboxOrigin::External);
                            ++out.skipped;
                        }
                    continue;
                }

                // Older events of the key: superseded. Each still consumes a matching write intent of ours (in the same
                // transaction as its settlement), so a stale intent can never claim a later external event.
                for (const auto* r : group) {
                    if (r == latest || settled.contains(r->id)) continue;
                    if (!db::query::upstream::Inbox::settleOwnWrite(r->id, vaultId, objectKey, opOf(*r), r->size_bytes,
                                                                     r->event_time, r->etag,
                                                                     "self: superseded by a newer event for the key"))
                        db::query::upstream::Inbox::markSkipped({r->id}, "superseded by a newer event for the key",
                                                                amodel::InboxOrigin::External);
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
                // delete): the inbox remembers the key's history even when the index row is gone. A true tie is not
                // stale: the removal side is confirmed by HEAD, the create side by the transfer.
                if (const auto newest = db::query::upstream::Inbox::latestForKey(vaultId, objectKey);
                    newest && newest->id != latest->id && newest->state != amodel::InboxState::Pending &&
                    !tied(*latest, *newest) && !newerOrEqual(*latest, *newest)) {
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
                    if (db::query::upstream::Inbox::settleOwnWrite(latest->id, vaultId, objectKey, amodel::WriteOp::Put,
                                                                   latest->size_bytes, latest->event_time, latest->etag,
                                                                   "self: Vaulthalla's own write")) {
                        // Our own upload: keep the row Vaulthalla wrote (with its encryption metadata), learn the ETag.
                        if (indexed) {
                            if (latest->etag) indexed->remote_etag = latest->etag;
                            if (latest->sequencer) indexed->remote_sequencer = latest->sequencer;
                            if (latest->version_id) indexed->remote_version_id = latest->version_id;
                            db::query::sync::RemoteObjectIndex::upsertFile(vaultId, indexed, "event");
                        }
                        ++out.self;
                        continue;
                    }
                    if (indexed && indexed->remote_etag && latest->etag &&
                        applierUnquote(*indexed->remote_etag) == applierUnquote(*latest->etag)) {
                        db::query::upstream::Inbox::markSkipped({latest->id}, "unchanged: the index already has this object",
                                                                amodel::InboxOrigin::External);
                        ++out.skipped;
                        continue;
                    }
                    if (sub && sub->foreign_objects == amodel::ForeignObjects::Ignore && !indexed &&
                        !db::query::fs::File::getFileByPath(vaultId, fs::model::makeAbsolute(objectKey))) {
                        // A new object nobody in this vault knows: only Vaulthalla-written objects are imported.
                        meter();
                        const auto head = engine->headRemoteObjectStrict(objectKey);
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
                    // A removal the HEAD above confirmed.
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
        // that predates these events (it would resurrect deleted objects). Only when a row really changed.
        if (out.index_changed && !stopped && !hooks_.shouldStop()) {
            try {
                meter();
                engine->publishRemoteIndexManifestWithRetry();
            } catch (const std::exception& e) {
                log::Registry::sync()->warn("[UpstreamEvents] Vault {}: index manifest not republished after events: {}",
                                            vaultId, e.what());
            }
        }
    }

    if (!stopped && !hooks_.shouldStop()) schedule(vaultId, out);
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
    if (!sub) return;
    // Every full listing is the subscription's new baseline (continuity is measured from it), whether it was
    // requested (adoption, lost continuity) or just happened.
    const bool held = sub->baseline_state == amodel::BaselineState::Pending ||
                      sub->baseline_state == amodel::BaselineState::Running;
    db::query::upstream::Subscription::setBaseline(sub->id, held ? amodel::BaselineState::Done : sub->baseline_state,
                                                   listStartedAt);
    if (held)
        log::Registry::sync()->info("[UpstreamEvents] Vault {}: baseline listing done; held events are applied next", vaultId);
}

bool Applier::baselineNeeded(const uint32_t vaultId) {
    const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
    return sub && sub->state == amodel::SubscriptionState::Active &&
           (sub->baseline_state == amodel::BaselineState::Pending || sub->baseline_state == amodel::BaselineState::Running);
}

namespace {

// When the subscription's view of the bucket was last complete: its last full listing, else when it went live.
std::time_t continuitySince(const amodel::Subscription& sub) {
    if (sub.baseline_started_at) return *sub.baseline_started_at;
    if (sub.activated_at) return *sub.activated_at;
    return sub.created_at;
}

bool continuityLost(const amodel::Subscription& sub, const amodel::Channel& channel) {
    return channel.continuity_broken_at && *channel.continuity_broken_at >= continuitySince(sub);
}

}

bool Applier::indexKeptFresh(const uint32_t vaultId, const std::chrono::seconds maxAge) {
    const auto sub = db::query::upstream::Subscription::getLiveForVault(vaultId);
    if (!sub || sub->state != amodel::SubscriptionState::Active || !sub->channel_id) return false;
    if (sub->baseline_state == amodel::BaselineState::Pending || sub->baseline_state == amodel::BaselineState::Running)
        return false;
    const auto channel = db::query::upstream::Channel::get(*sub->channel_id);
    if (!channel || !channel->last_success_at) return false;
    if (continuityLost(*sub, *channel)) return false;
    if (channel->dlq_depth && *channel->dlq_depth > 0) return false;
    return std::time(nullptr) - *channel->last_success_at <= maxAge.count();
}

size_t Applier::checkContinuity() {
    size_t reset = 0;
    for (const auto& sub : db::query::upstream::Subscription::listByState(amodel::SubscriptionState::Active)) {
        if (!sub.vault_id || !sub.channel_id) continue;
        if (sub.baseline_state == amodel::BaselineState::Pending || sub.baseline_state == amodel::BaselineState::Running)
            continue;
        const auto channel = db::query::upstream::Channel::get(*sub.channel_id);
        if (!channel || !continuityLost(sub, *channel)) continue;
        db::query::upstream::Subscription::setBaseline(sub.id, amodel::BaselineState::Pending, std::nullopt);
        ++reset;
        log::Registry::sync()->warn(
            "[UpstreamEvents] Vault {}: event stream may have lost messages ({}); events are held until the bucket is "
            "listed again", *sub.vault_id, channel->continuity_note.value_or("continuity lost"));
        if (const auto& controller = runtime::Deps::get().syncController)
            (void)controller->runNow(*sub.vault_id, 3);
    }
    return reset;
}

}
