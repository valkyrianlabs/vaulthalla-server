#include "sync/manifest/Service.hpp"

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
    return Known{*state.epoch, *state.root_sha256};
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
    const auto produced = db::query::sync::Manifest::collect(vaultId_);
    const auto current = keys_->currentKey();
    const auto knownState = known();
    PublishOptions options;
    options.now = isoTime(std::time(nullptr));
    try {
        auto report = manifest::publish(*store_, vaultUid_, keyLookup(), {current.version, current.key}, produced,
                                        knownState, cache_, options);
        db::query::sync::Manifest::recordRoot(vaultId_, report.published.known.epoch,
                                              report.published.known.root_sha256, report.published.etag,
                                              report.published.sids());
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
        if (e.code() == ChainError::Rollback || e.code() == ChainError::Fork) refused(e, e.epoch(), e.rootSha256());
        cache_ = {};
        throw;
    }
}

std::optional<Acceptance> Service::verifyRemote() {
    std::scoped_lock lock(mutex_);
    const auto state = db::query::sync::Manifest::state(vaultId_);
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
            std::vector<std::string> sids;
            for (const auto& s : loaded.root.segments) sids.push_back(s.sid);
            for (const auto& s : loaded.root.snapshots) sids.push_back(s.sid);
            db::query::sync::Manifest::recordRoot(vaultId_, loaded.acceptance.epoch, loaded.acceptance.root_sha256,
                                                  loaded.etag, sids);
            cache_.base.reset();
        }
        return loaded.acceptance;
    } catch (const ChainRejected& e) {
        if (e.code() == ChainError::Rollback || e.code() == ChainError::Fork) refused(e, e.epoch(), e.rootSha256());
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
    auto report = collectGarbage(*store_, db::query::sync::Manifest::retainedSids(vaultId_), now);
    db::query::sync::Manifest::markCollected(vaultId_);
    if (!report.deleted.empty())
        log::Registry::cloud()->info("[manifest] Vault {}: collected {} superseded segment(s)", vaultId_,
                                     report.deleted.size());
    return report;
}

void notifyRefusedRoot(const uint32_t vaultId, const ChainError reason, const uint64_t epoch,
                       const std::string& rootSha256, const std::optional<Known>& known) {
    const bool rollback = reason == ChainError::Rollback;
    const auto what = rollback ? std::string("rollback") : std::string("fork");
    const auto knownText = known ? fmt::format("epoch {} (root {})", known->epoch, known->root_sha256)
                                 : std::string("no recorded root");
    const auto summary = rollback
        ? fmt::format("The bucket of vault {} presents manifest root epoch {}, older than the newest root this server "
                      "recorded ({}). Someone with write access to the bucket may have replaced it with an older, "
                      "authentic state.",
                      vaultId, epoch, knownText)
        : fmt::format("The bucket of vault {} presents manifest root epoch {} (root {}) that does not continue the "
                      "chain this server recorded ({}). Another writer may be publishing to the same bucket, or the "
                      "bucket was altered.",
                      vaultId, epoch, rootSha256, knownText);
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
