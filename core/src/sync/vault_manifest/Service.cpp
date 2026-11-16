#include "sync/vault_manifest/Service.hpp"

#include "crypto/SecretKey.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/ManifestApply.hpp"
#include "log/Registry.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "vault/EncryptionManager.hpp"

#include <fmt/format.h>
#include <paths.h>

#include <cstdlib>
#include <set>
#include <filesystem>
#include <string_view>

namespace vh::sync::vault_manifest {

namespace service_detail {

// The session's memory in PostgreSQL: one vault's rows of remote_manifest_state, remote_manifest_root and
// remote_manifest_gc.
class DatabaseState final : public vl::vaultfmt::manifest::StateStore {
public:
    explicit DatabaseState(const uint32_t vaultId) : vaultId_(vaultId) {}

    vl::vaultfmt::manifest::ChainState state() override { return db::query::sync::Manifest::state(vaultId_); }
    void recordRoot(const vl::vaultfmt::manifest::RootRecord& record) override {
        db::query::sync::Manifest::recordRoot(vaultId_, record);
    }
    std::optional<vl::vaultfmt::manifest::BaseCopy> base() override { return db::query::sync::Manifest::base(vaultId_); }
    void markApplying(const uint64_t epoch, const std::string& rootSha256) override {
        db::query::sync::Manifest::markApplying(vaultId_, epoch, rootSha256);
    }
    void notePublishing(const std::string& rootSha256, const vl::vaultfmt::manifest::BaseCopy& pending) override {
        db::query::sync::Manifest::notePublishing(vaultId_, rootSha256, pending);
    }
    std::optional<vl::vaultfmt::manifest::BaseCopy> pendingBase(const std::string& rootSha256) override {
        return db::query::sync::Manifest::pendingBase(vaultId_, rootSha256);
    }
    bool recordRefused(const std::string& reason, const uint64_t epoch, const std::string& rootSha256) override {
        return db::query::sync::Manifest::recordRefused(vaultId_, reason, epoch, rootSha256);
    }
    std::set<std::string> retainedSids() override { return db::query::sync::Manifest::retainedSids(vaultId_); }
    void markCollected() override { db::query::sync::Manifest::markCollected(vaultId_); }
    std::time_t firstUnreferenced(const std::string& sid) override {
        return db::query::sync::Manifest::firstUnreferenced(vaultId_, sid);
    }
    void forgetUnreferenced(const std::string& sid) override {
        db::query::sync::Manifest::forgetUnreferenced(vaultId_, sid);
    }

private:
    uint32_t vaultId_;
};

vl::vaultfmt::vhf1::KeyLookup lookupOf(std::shared_ptr<vault::EncryptionManager> keys) {
    return [keys = std::move(keys)](const uint32_t version) -> vl::vaultfmt::vhf1::KeyPtr {
        try {
            return keys->historicalKeySnapshot(version);
        } catch (const std::exception&) {
            return nullptr;  // not held: KeyUnavailable for the reader
        }
    };
}

// Both or nothing: the session is never built without the bucket or the vault's keys.
std::shared_ptr<vl::vaultfmt::manifest::ObjectStore> required(std::shared_ptr<vl::vaultfmt::manifest::ObjectStore> store,
                                                const std::shared_ptr<vault::EncryptionManager>& keys) {
    if (!store || !keys) throw std::invalid_argument("vault_manifest::Service needs a store and the vault's keys");
    return store;
}

vl::vaultfmt::manifest::SessionHost hostOf(const uint32_t vaultId, const std::shared_ptr<vault::EncryptionManager>& keys) {
    vl::vaultfmt::manifest::SessionHost host;
    host.collect = [vaultId] { return db::query::sync::Manifest::collect(vaultId); };
    host.currentKey = [keys] {
        const auto current = keys->currentKey();
        return vl::vaultfmt::manifest::SealingKey{current.version, current.key};
    };
    host.keys = lookupOf(keys);
    host.nodeId = [] { return db::query::device::Devices::nodeId(); };
    host.vaultId = vaultId;
    if (paths::testMode) {
        // The Tier B mirror drill (tools/harness/vhh/drill_mirror.py) only, never a packaged daemon: an installed service
        // refuses test mode (runtime::test_instance). A file `crash-after-root-put` in VH_TEST_FAULT_DIR ends the process
        // between a root's PUT and its record, once.
        host.afterRootPut = [] {
            const char* dir = std::getenv("VH_TEST_FAULT_DIR");
            if (!dir) return;
            const auto trigger = std::filesystem::path(dir) / "crash-after-root-put";
            std::error_code ec;
            if (std::filesystem::remove(trigger, ec)) std::_Exit(137);
        };
    }
    host.now = [] { return std::time(nullptr); };
    host.alert = [vaultId](const vl::vaultfmt::manifest::Refusal& r) {
        notifyRefusedRoot(vaultId, r.reason, r.epoch, r.root_sha256, r.known);
    };
    host.note = [vaultId](const vl::vaultfmt::manifest::Notice level, const std::string& message) {
        const auto log = log::Registry::cloud();
        switch (level) {
        case vl::vaultfmt::manifest::Notice::Info: log->info("[manifest] Vault {}: {}", vaultId, message); break;
        case vl::vaultfmt::manifest::Notice::Warning: log->warn("[manifest] Vault {}: {}", vaultId, message); break;
        case vl::vaultfmt::manifest::Notice::Error: log->error("[manifest] Vault {}: {}", vaultId, message); break;
        }
    };
    return host;
}

}

Service::Service(const uint32_t vaultId, const vl::vaultfmt::manifest::Uid& vaultUid, std::shared_ptr<vl::vaultfmt::manifest::ObjectStore> store,
                 std::shared_ptr<vault::EncryptionManager> keys)
    : vaultId_(vaultId), vaultUid_(vaultUid), keys_(std::move(keys)), store_(service_detail::required(store, keys_)),
      session_(vaultUid, store_,
               std::make_shared<service_detail::DatabaseState>(vaultId), service_detail::hostOf(vaultId, keys_)) {}

vl::vaultfmt::vhf1::KeyLookup Service::keyLookup() const { return service_detail::lookupOf(keys_); }

template <typename F>
auto Service::publishRounds(F&& once) -> decltype(once()) {
    for (unsigned round = 1;; ++round) {
        try {
            return once();
        } catch (const vl::vaultfmt::manifest::HeadMoved& e) {
            if (round >= kPublishRounds)
                throw vl::vaultfmt::manifest::PublishConflict(
                    fmt::format("manifest publish conflict after {} rounds of applying another writer's root", round));
            log::Registry::cloud()->info("[manifest] Vault {}: {}; applying it before publishing", vaultId_, e.what());
            (void)applyRemote();
        }
    }
}

vl::vaultfmt::manifest::PublishReport Service::publish() {
    return publishRounds([&] { return session_.publish(); });
}

std::optional<vl::vaultfmt::manifest::PublishReport> Service::publishIfChanged() {
    return publishRounds([&] { return session_.publishIfChanged(); });
}

std::optional<vl::vaultfmt::manifest::RemoteHead> Service::verifyRemote() { return session_.verifyRemote(); }

std::optional<ApplyReport> Service::applyRemote(const ApplyOptions& options) {
    // One apply per vault at a time: a pass and a publish meeting HeadMoved on another thread both come here.
    std::scoped_lock lock(applyMutex_);
    (void)finishDeferred(vaultId_, options);
    auto verified = session_.verifyRemote();
    if (verified && verified->own_unexplained)
        throw ApplyStopped(fmt::format("the bucket's root of epoch {} names this server and vault as its producer but is "
                                       "not a root this server published on its recorded one: another installation "
                                       "may be publishing under this server's identity (a cloned database)",
                                       verified->epoch));
    if (!verified || !verified->head) return std::nullopt;
    auto withStore = options;
    if (!withStore.store) withStore.store = store_.get();
    auto report = apply(vaultId_, vaultUid_, keyLookup(), *verified->head, db::query::device::Devices::nodeId(), withStore);
    if (report.recorded) session_.applied();
    return report;
}

std::size_t Service::collectSharedOrphans(const std::time_t now, const std::time_t grace,
                                         const std::function<void(const std::string&)>& beforeDelete) {
    const auto due = db::query::sync::ManifestApply::purgedLocallyBefore(vaultId_, now - grace);
    if (due.empty()) return 0;
    std::scoped_lock lock(applyMutex_);   // no apply in between
    const auto state = db::query::sync::Manifest::state(vaultId_);
    if (!state.epoch || !state.root_sha256 || !state.etag || state.applying_epoch) return 0;
    const auto stillHead = [&] {
        const auto etag = store_->headEtag(std::string(vl::vaultfmt::manifest::kRootKey));
        return etag && *etag == *state.etag;
    };
    if (!stillHead()) return 0;   // a newer root: the next pass applies it first
    const auto copy = db::query::sync::Manifest::base(vaultId_);
    if (!copy) return 0;
    const auto known = vl::vaultfmt::manifest::openBaseCopy(*copy, vaultUid_, keyLookup(), {*state.epoch, *state.root_sha256});
    if (!known) return 0;   // nothing to prove the head doesn't name them with
    std::set<std::string> named;
    for (const auto& e : known->entries) named.insert(e.uid);
    for (const auto& d : db::query::sync::ManifestApply::deferred(vaultId_)) named.insert(d.uid);
    for (const auto& sha : state.publishing_roots)
        if (const auto pending = db::query::sync::Manifest::pendingBase(vaultId_, sha))
            if (const auto root = [&]() -> std::optional<vl::vaultfmt::manifest::RootDocument> {
                    try {
                        return vl::vaultfmt::manifest::openRoot(pending->root, vaultUid_, keyLookup());
                    } catch (const std::exception&) {
                        return std::nullopt;
                    }
                }())
                if (const auto c = vl::vaultfmt::manifest::openBaseCopy(*pending, vaultUid_, keyLookup(), {root->epoch, sha}))
                    for (const auto& e : c->entries) named.insert(e.uid);
    std::size_t deleted = 0;
    for (const auto& key : due) {
        const auto uid = vl::vaultfmt::manifest::uidOfObjectKey(key);
        if (!uid) continue;
        if (named.contains(vl::vaultfmt::manifest::uidText(*uid))) {
            db::query::sync::ManifestApply::dropPurgedLocally(vaultId_, key);   // named again: live, not ours to delete
            continue;
        }
        if (beforeDelete) beforeDelete(key);
        if (!stillHead()) break;   // another writer published meanwhile: judged again after the next apply
        store_->remove(key);
        db::query::sync::ManifestApply::dropPurgedLocally(vaultId_, key);
        ++deleted;
    }
    if (deleted)
        log::Registry::cloud()->info("[manifest] Vault {}: deleted {} object(s) of trash purged here {} day(s) ago that "
                                     "no root names",
                                     vaultId_, deleted, grace / 86400);
    return deleted;
}

std::optional<vl::vaultfmt::manifest::GcReport> Service::collectGarbageIfDue(const std::time_t now) {
    return session_.collectGarbageIfDue(now);
}

void notifyRefusedRoot(const uint32_t vaultId, const vl::vaultfmt::manifest::ChainError reason, const uint64_t epoch,
                       const std::string& rootSha256, const std::optional<vl::vaultfmt::manifest::Known>& known) {
    const auto what = std::string(vl::vaultfmt::manifest::chainErrorName(reason));
    const auto knownText = known ? fmt::format("epoch {} (root {})", known->epoch, known->root_sha256)
                                 : std::string("no recorded root");
    std::string summary;
    switch (reason) {
    case vl::vaultfmt::manifest::ChainError::Rollback:
        summary = fmt::format("The bucket of vault {} presents manifest root epoch {}, older than the newest root this "
                              "server recorded ({}). Someone with write access to the bucket may have replaced it with "
                              "an older, authentic state.",
                              vaultId, epoch, knownText);
        break;
    case vl::vaultfmt::manifest::ChainError::OrderViolation:
        summary = fmt::format("The bucket of vault {} now lists a manifest root version between a root this server had "
                              "settled ({}) and its predecessor. The provider's version order changed after the fact, "
                              "so two writers may each believe they published epoch {}.",
                              vaultId, knownText, epoch);
        break;
    case vl::vaultfmt::manifest::ChainError::Superseded:
        summary = fmt::format("The manifest root epoch {} (root {}) of vault {} names other servers as its writers, "
                              "not this one, after this server's last own root ({}). The vault was restored or taken "
                              "over elsewhere.",
                              epoch, rootSha256, vaultId, knownText);
        break;
    case vl::vaultfmt::manifest::ChainError::PublishModeMismatch:
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
