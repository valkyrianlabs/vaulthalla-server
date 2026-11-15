#include "sync/vault_manifest/Service.hpp"

#include "crypto/SecretKey.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "log/Registry.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "vault/EncryptionManager.hpp"

#include <fmt/format.h>

namespace vh::sync::vault_manifest {

namespace service_detail {

// The session's memory in PostgreSQL: one vault's rows of remote_manifest_state, remote_manifest_root and
// remote_manifest_gc.
class DatabaseState final : public manifest::StateStore {
public:
    explicit DatabaseState(const uint32_t vaultId) : vaultId_(vaultId) {}

    manifest::ChainState state() override { return db::query::sync::Manifest::state(vaultId_); }
    void recordRoot(const manifest::RootRecord& record) override {
        db::query::sync::Manifest::recordRoot(vaultId_, record);
    }
    std::optional<manifest::BaseCopy> base() override { return db::query::sync::Manifest::base(vaultId_); }
    void markApplying(const uint64_t epoch, const std::string& rootSha256) override {
        db::query::sync::Manifest::markApplying(vaultId_, epoch, rootSha256);
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

crypto::vhf1::KeyLookup lookupOf(std::shared_ptr<vault::EncryptionManager> keys) {
    return [keys = std::move(keys)](const uint32_t version) -> crypto::vhf1::KeyPtr {
        try {
            return keys->historicalKeySnapshot(version);
        } catch (const std::exception&) {
            return nullptr;  // not held: KeyUnavailable for the reader
        }
    };
}

// Both or nothing: the session is never built without the bucket or the vault's keys.
std::shared_ptr<manifest::ObjectStore> required(std::shared_ptr<manifest::ObjectStore> store,
                                                const std::shared_ptr<vault::EncryptionManager>& keys) {
    if (!store || !keys) throw std::invalid_argument("vault_manifest::Service needs a store and the vault's keys");
    return store;
}

manifest::SessionHost hostOf(const uint32_t vaultId, const std::shared_ptr<vault::EncryptionManager>& keys) {
    manifest::SessionHost host;
    host.collect = [vaultId] { return db::query::sync::Manifest::collect(vaultId); };
    host.currentKey = [keys] {
        const auto current = keys->currentKey();
        return manifest::SealingKey{current.version, current.key};
    };
    host.keys = lookupOf(keys);
    host.nodeId = [] { return db::query::device::Devices::nodeId(); };
    host.now = [] { return std::time(nullptr); };
    host.alert = [vaultId](const manifest::Refusal& r) {
        notifyRefusedRoot(vaultId, r.reason, r.epoch, r.root_sha256, r.known);
    };
    host.note = [vaultId](const manifest::Notice level, const std::string& message) {
        const auto log = log::Registry::cloud();
        switch (level) {
        case manifest::Notice::Info: log->info("[manifest] Vault {}: {}", vaultId, message); break;
        case manifest::Notice::Warning: log->warn("[manifest] Vault {}: {}", vaultId, message); break;
        case manifest::Notice::Error: log->error("[manifest] Vault {}: {}", vaultId, message); break;
        }
    };
    return host;
}

}

Service::Service(const uint32_t vaultId, const manifest::Uid& vaultUid, std::shared_ptr<manifest::ObjectStore> store,
                 std::shared_ptr<vault::EncryptionManager> keys)
    : vaultId_(vaultId), vaultUid_(vaultUid), keys_(std::move(keys)),
      session_(vaultUid, service_detail::required(std::move(store), keys_),
               std::make_shared<service_detail::DatabaseState>(vaultId), service_detail::hostOf(vaultId, keys_)) {}

crypto::vhf1::KeyLookup Service::keyLookup() const { return service_detail::lookupOf(keys_); }

template <typename F>
auto Service::publishRounds(F&& once) -> decltype(once()) {
    for (unsigned round = 1;; ++round) {
        try {
            return once();
        } catch (const manifest::HeadMoved& e) {
            if (round >= kPublishRounds)
                throw manifest::PublishConflict(
                    fmt::format("manifest publish conflict after {} rounds of applying another writer's root", round));
            log::Registry::cloud()->info("[manifest] Vault {}: {}; applying it before publishing", vaultId_, e.what());
            (void)applyRemote();
        }
    }
}

manifest::PublishReport Service::publish() {
    return publishRounds([&] { return session_.publish(); });
}

std::optional<manifest::PublishReport> Service::publishIfChanged() {
    return publishRounds([&] { return session_.publishIfChanged(); });
}

std::optional<manifest::RemoteHead> Service::verifyRemote() { return session_.verifyRemote(); }

std::optional<ApplyReport> Service::applyRemote(const ApplyOptions& options) {
    (void)finishDeferred(vaultId_, options);
    auto verified = session_.verifyRemote();
    if (!verified || !verified->head) return std::nullopt;
    auto report = apply(vaultId_, vaultUid_, keyLookup(), *verified->head, db::query::device::Devices::nodeId(), options);
    if (report.recorded) session_.applied();
    return report;
}

std::optional<manifest::GcReport> Service::collectGarbageIfDue(const std::time_t now) {
    return session_.collectGarbageIfDue(now);
}

void notifyRefusedRoot(const uint32_t vaultId, const manifest::ChainError reason, const uint64_t epoch,
                       const std::string& rootSha256, const std::optional<manifest::Known>& known) {
    const auto what = std::string(manifest::chainErrorName(reason));
    const auto knownText = known ? fmt::format("epoch {} (root {})", known->epoch, known->root_sha256)
                                 : std::string("no recorded root");
    std::string summary;
    switch (reason) {
    case manifest::ChainError::Rollback:
        summary = fmt::format("The bucket of vault {} presents manifest root epoch {}, older than the newest root this "
                              "server recorded ({}). Someone with write access to the bucket may have replaced it with "
                              "an older, authentic state.",
                              vaultId, epoch, knownText);
        break;
    case manifest::ChainError::OrderViolation:
        summary = fmt::format("The bucket of vault {} now lists a manifest root version between a root this server had "
                              "settled ({}) and its predecessor. The provider's version order changed after the fact, "
                              "so two writers may each believe they published epoch {}.",
                              vaultId, knownText, epoch);
        break;
    case manifest::ChainError::Superseded:
        summary = fmt::format("The manifest root epoch {} (root {}) of vault {} names other servers as its writers, "
                              "not this one, after this server's last own root ({}). The vault was restored or taken "
                              "over elsewhere.",
                              epoch, rootSha256, vaultId, knownText);
        break;
    case manifest::ChainError::PublishModeMismatch:
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
