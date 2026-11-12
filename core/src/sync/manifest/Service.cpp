#include "sync/manifest/Service.hpp"

#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "log/Registry.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "vault/EncryptionManager.hpp"

#include <fmt/format.h>

namespace vh::sync::manifest {

Service::Service(const uint32_t vaultId, const Uid& vaultUid, std::shared_ptr<ObjectStore> store,
                 std::shared_ptr<vault::EncryptionManager> keys)
    : vaultId_(vaultId), vaultUid_(vaultUid), store_(std::move(store)), keys_(std::move(keys)) {
    if (!store_ || !keys_) throw std::invalid_argument("manifest::Service needs a store and the vault's keys");
}

crypto::vhf1::KeyLookup Service::keyLookup() const {
    return [keys = keys_](const uint32_t version) -> crypto::SecretKeyPtr {
        try {
            return keys->historicalKeySnapshot(version);
        } catch (const std::exception&) {
            return nullptr;  // not held: KeyUnavailable for the reader
        }
    };
}

std::optional<Known> Service::known() const {
    const auto state = db::query::sync::Manifest::state(vaultId_);
    if (!state.epoch || !state.root_sha256) return std::nullopt;
    return Known{*state.epoch, *state.root_sha256, state.root_version_id};
}

namespace service_detail {

bool versionLog(const ObjectStore& store) { return store.mode() == storage::s3::WriteCapability::VersionLog; }

std::optional<SettledWindow> settledOf(const db::query::sync::Manifest::State& state) {
    if (!state.root_version_id || !state.base_version_id) return std::nullopt;
    return SettledWindow{*state.base_version_id, *state.root_version_id, state.settle_window};
}

bool refusal(const ChainError code) {
    return code == ChainError::Rollback || code == ChainError::Fork || code == ChainError::OrderViolation ||
           code == ChainError::Superseded || code == ChainError::PublishModeMismatch;
}

}

void Service::refused(const ChainRejected& e, const uint64_t epoch, const std::string& rootSha256) {
    const auto reason = std::string(chainErrorName(e.code()));
    log::Registry::cloud()->error("[manifest] Vault {}: refused the bucket's manifest root ({}); the database keeps its "
                                  "state and nothing is published over it",
                                  vaultId_, e.what());
    if (db::query::sync::Manifest::recordRefused(vaultId_, reason, epoch, rootSha256))
        notifyRefusedRoot(vaultId_, e.code(), epoch, rootSha256, known());
}

PublishReport Service::publish() {
    std::scoped_lock lock(mutex_);
    return publishLocked(db::query::sync::Manifest::collect(vaultId_));
}

std::optional<PublishReport> Service::publishIfChanged() {
    std::scoped_lock lock(mutex_);
    auto produced = db::query::sync::Manifest::collect(vaultId_);
    const auto knownState = known();
    if (cache_.base && cache_.last_produced && knownState && cache_.base->known == *knownState &&
        *cache_.last_produced == produced)
        return std::nullopt;
    return publishLocked(produced);
}

PublishReport Service::publishLocked(const Content& produced) {
    namespace d = service_detail;
    const auto current = keys_->currentKey();
    const auto state = db::query::sync::Manifest::state(vaultId_);
    const auto knownState = known();
    PublishOptions options;
    options.now = isoTime(std::time(nullptr));
    options.self_node = produced.producer.node_id;
    options.own_epoch = state.own_epoch;
    options.settled = d::settledOf(state);
    try {
        auto report = manifest::publish(*store_, vaultUid_, keyLookup(), {current.version, current.key}, produced,
                                        knownState, cache_, options);
        db::query::sync::Manifest::recordRoot(
            vaultId_, {.epoch = report.published.known.epoch, .root_sha256 = report.published.known.root_sha256,
                       .etag = report.published.etag, .sids = report.published.sids(),
                       .version_id = report.settled.version_id, .base_version_id = report.settled.base_version_id,
                       .settle_window = report.settled.window, .own = true});
        if (report.lost)
            log::Registry::cloud()->info("[manifest] Vault {}: another writer's root won {} round(s) of this publish; "
                                         "merged onto it (spec 06 §5.2)",
                                         vaultId_, report.lost);
        if (!report.repaired.empty())
            log::Registry::cloud()->info("[manifest] Vault {}: deleted {} stray root version(s) above the head",
                                         vaultId_, report.repaired.size());
        if (!report.ahead.empty())
            log::Registry::cloud()->warn("[manifest] Vault {}: {} authentic root version(s) of a higher epoch sit above "
                                         "the root just published; left in place, the next read judges them",
                                         vaultId_, report.ahead.size());
        if (report.gap)
            log::Registry::cloud()->warn("[manifest] Vault {}: another writer published several roots since epoch {} "
                                         "(gap); merged and continued at epoch {}",
                                         vaultId_, knownState ? knownState->epoch : 0, report.published.known.epoch);
        if (report.root_rebuilt)
            log::Registry::cloud()->warn("[manifest] Vault {}: the bucket's manifest root was missing or unreadable; "
                                         "rebuilt from the database at epoch {}",
                                         vaultId_, report.published.known.epoch);
        return report;
    } catch (const ChainRejected& e) {
        if (d::refusal(e.code())) refused(e, e.epoch(), e.rootSha256());
        cache_ = {};
        throw;
    }
}

std::optional<Acceptance> Service::verifyRemoteVersionLog() {
    namespace d = service_detail;
    const auto state = db::query::sync::Manifest::state(vaultId_);
    // A pass that changed nothing still costs one HEAD: the settled head is the current version until someone writes.
    if (state.etag && state.epoch && state.root_sha256)
        if (const auto etag = store_->headEtag(std::string(kRootKey)); etag && *etag == *state.etag)
            return Acceptance{*state.epoch, *state.root_sha256, false};
    const std::optional<Known> knownState = state.epoch && state.root_sha256
        ? std::make_optional(Known{*state.epoch, *state.root_sha256, state.root_version_id})
        : std::nullopt;
    LoadOptions options;
    options.known = knownState;
    options.root_cache = &cache_.roots;
    options.settled = d::settledOf(state);
    try {
        auto loaded = load(*store_, vaultUid_, keyLookup(), options);
        std::vector<std::string> sids;
        for (const auto& s : loaded.root.segments) sids.push_back(s.sid);
        for (const auto& s : loaded.root.snapshots) sids.push_back(s.sid);
        if (!knownState || loaded.known() != *knownState) {
            checkHeadForWriter(loaded.root, loaded.acceptance.root_sha256, *store_, db::query::device::Devices::nodeId(),
                               state.own_epoch);
            db::query::sync::Manifest::recordRoot(
                vaultId_, {.epoch = loaded.acceptance.epoch, .root_sha256 = loaded.acceptance.root_sha256,
                           .etag = loaded.etag, .sids = sids, .version_id = loaded.version_id,
                           .base_version_id = loaded.base_version_id, .settle_window = loaded.settle_window,
                           .own = false});
            cache_.base.reset();
        } else if (loaded.version_id && loaded.version_id != state.root_version_id) {
            // The same root, found by its hash (a state from before migration 137, or recorded by a restore).
            db::query::sync::Manifest::recordRoot(
                vaultId_, {.epoch = loaded.acceptance.epoch, .root_sha256 = loaded.acceptance.root_sha256,
                           .etag = loaded.etag, .sids = sids,
                           .version_id = loaded.version_id, .base_version_id = loaded.base_version_id,
                           .settle_window = loaded.settle_window, .own = false});
        }
        // Repair (spec 06 §5.4): versions newer than the head that aren't on the chain.
        for (const auto& id : loaded.strays) {
            try {
                store_->removeVersion(std::string(kRootKey), id);
            } catch (const std::exception& e) {
                log::Registry::cloud()->warn("[manifest] Vault {}: a stray root version was not deleted: {}", vaultId_,
                                             e.what());
            }
        }
        if (!loaded.strays.empty())
            log::Registry::cloud()->info("[manifest] Vault {}: deleted {} stray root version(s) above the head",
                                         vaultId_, loaded.strays.size());
        return loaded.acceptance;
    } catch (const ChainRejected& e) {
        if (d::refusal(e.code())) refused(e, e.epoch(), e.rootSha256());
        cache_ = {};
        throw;
    } catch (const NoUsableRoot&) {
        return std::nullopt;
    }
}

std::optional<Acceptance> Service::verifyRemote() {
    std::scoped_lock lock(mutex_);
    const auto state = db::query::sync::Manifest::state(vaultId_);
    if (service_detail::versionLog(*store_)) return verifyRemoteVersionLog();
    // A pass that changed nothing costs one HEAD of the root (spec 01 §5): its ETag still the one we recorded.
    if (state.etag && state.epoch && state.root_sha256)
        if (const auto etag = store_->headEtag(std::string(kRootKey)); etag && *etag == *state.etag)
            return Acceptance{*state.epoch, *state.root_sha256, false};
    auto obj = store_->get(std::string(kRootKey));
    if (!obj) return std::nullopt;
    if (state.etag && obj->etag && *state.etag == *obj->etag && state.epoch && state.root_sha256)
        return Acceptance{*state.epoch, *state.root_sha256, false};
    const std::optional<Known> knownState =
        state.epoch && state.root_sha256 ? std::make_optional(Known{*state.epoch, *state.root_sha256}) : std::nullopt;
    try {
        // A full load: it authenticates the segments the new root pins and walks a gap through retained roots.
        auto loaded = load(*store_, vaultUid_, keyLookup(), {knownState, true, std::move(obj)});
        if (!knownState || loaded.known() != *knownState) {
            // spec 06 §5.5, both modes: a head that excludes this server after its last own root stops it here.
            checkHeadForWriter(loaded.root, loaded.acceptance.root_sha256, *store_, db::query::device::Devices::nodeId(),
                               state.own_epoch);
            std::vector<std::string> sids;
            for (const auto& s : loaded.root.segments) sids.push_back(s.sid);
            for (const auto& s : loaded.root.snapshots) sids.push_back(s.sid);
            db::query::sync::Manifest::recordRoot(vaultId_, loaded.acceptance.epoch, loaded.acceptance.root_sha256,
                                                  loaded.etag, sids);
            cache_.base.reset();
        }
        return loaded.acceptance;
    } catch (const ChainRejected& e) {
        if (service_detail::refusal(e.code())) refused(e, e.epoch(), e.rootSha256());
        cache_ = {};
        throw;
    } catch (const NoUsableRoot&) {
        return std::nullopt;
    }
}

std::optional<GcReport> Service::collectGarbageIfDue(const std::time_t now) {
    std::scoped_lock lock(mutex_);
    const auto state = db::query::sync::Manifest::state(vaultId_);
    if (!state.epoch) return std::nullopt;  // nothing published yet
    if (state.gc_at && now - *state.gc_at < 24 * 60 * 60) return std::nullopt;
    GcReport report;
    if (service_detail::versionLog(*store_)) {
        const UnreferencedClock clock{
            .first = [&](const std::string& sid) { return db::query::sync::Manifest::firstUnreferenced(vaultId_, sid); },
            .forget = [&](const std::string& sid) { db::query::sync::Manifest::forgetUnreferenced(vaultId_, sid); }};
        report = collectGarbageVersionLog(*store_, db::query::sync::Manifest::retainedSids(vaultId_), now, clock);
        if (state.root_version_id) {
            const auto janitor = collectRootVersions(*store_, vaultUid_, keyLookup(), cache_.roots,
                                                     *state.root_version_id, now);
            if (!janitor.deleted.empty())
                log::Registry::cloud()->info("[manifest] Vault {}: deleted {} superseded root version(s)", vaultId_,
                                             janitor.deleted.size());
        }
    } else {
        report = collectGarbage(*store_, db::query::sync::Manifest::retainedSids(vaultId_), now);
    }
    db::query::sync::Manifest::markCollected(vaultId_);
    if (!report.deleted.empty())
        log::Registry::cloud()->info("[manifest] Vault {}: collected {} superseded segment(s)", vaultId_,
                                     report.deleted.size());
    return report;
}

void notifyRefusedRoot(const uint32_t vaultId, const ChainError reason, const uint64_t epoch,
                       const std::string& rootSha256, const std::optional<Known>& known) {
    const auto what = std::string(chainErrorName(reason));
    const auto knownText = known ? fmt::format("epoch {} (root {})", known->epoch, known->root_sha256)
                                 : std::string("no recorded root");
    std::string summary;
    switch (reason) {
    case ChainError::Rollback:
        summary = fmt::format("The bucket of vault {} presents manifest root epoch {}, older than the newest root this "
                              "server recorded ({}). Someone with write access to the bucket may have replaced it with "
                              "an older, authentic state.",
                              vaultId, epoch, knownText);
        break;
    case ChainError::OrderViolation:
        summary = fmt::format("The bucket of vault {} now lists a manifest root version between a root this server had "
                              "settled ({}) and its predecessor. The provider's version order changed after the fact, "
                              "so two writers may each believe they published epoch {}.",
                              vaultId, knownText, epoch);
        break;
    case ChainError::Superseded:
        summary = fmt::format("The manifest root epoch {} (root {}) of vault {} names other servers as its writers, "
                              "not this one, after this server's last own root ({}). The vault was restored or taken "
                              "over elsewhere.",
                              epoch, rootSha256, vaultId, knownText);
        break;
    case ChainError::PublishModeMismatch:
        summary = fmt::format("The manifest root epoch {} (root {}) of vault {} was published by another server in "
                              "another publish mode than this bucket's (conditional or version_log).",
                              epoch, rootSha256, vaultId);
        break;
    default:
        summary = fmt::format("The bucket of vault {} presents manifest root epoch {} (root {}) that does not continue "
                              "the chain this server recorded ({}). Another writer may be publishing to the same "
                              "bucket, or the bucket was altered.",
                              vaultId, epoch, rootSha256, knownText);
    }
    const auto action = std::string(
        "The server refused the root, keeps its database state and publishes nothing over it. Check who else writes "
        "to this bucket (another server, a restore) before changing anything.");

    notifications::OperatorNotification n;
    n.eventKey = "manifest_" + what;
    n.eventType = "security";
    n.severity = "critical";
    n.recipientGroup = "security";
    n.fingerprint = fmt::format("manifest:{}:{}:{}", vaultId, what, rootSha256);
    n.rendered.subject = fmt::format("[Vaulthalla] Manifest {} refused for vault {}", what, vaultId);
    n.rendered.text = summary + "\n\n" + action + "\n";
    n.rendered.html = "<p>" + summary + "</p><p>" + action + "</p>";
    n.tags = {{"event_type", "security"}, {"severity", "critical"}, {"security_event", "manifest_" + what},
              {"vault_id", std::to_string(vaultId)}};
    if (!notifications::OperatorNotificationBus::instance().enqueue(std::move(n)))
        log::Registry::cloud()->warn("[manifest] Dropped the manifest {} alert for vault {}: the queue is full", what,
                                     vaultId);
}

}
