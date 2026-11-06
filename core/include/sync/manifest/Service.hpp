#pragma once

#include "sync/manifest/Publisher.hpp"
#include "vault/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

// Manifest v2 for one opaque_v1 vault, the way the daemon runs it (spec 03 §3.4, §4.1): publish what the database
// holds (db::query::sync::Manifest::collect) on top of the bucket's root, record the chain position in
// remote_manifest_state, verify roots other writers published, refuse and alert on a rollback or fork, and collect
// superseded segments once a day. CloudEngine owns one per opaque_v1 vault, in place of the index-v1.json manifest.
//
// A refused root (rollback, fork) leaves the database untouched and is recorded in remote_manifest_state; the
// operator is notified once per refused root (operator_notification event "manifest_rollback" / "manifest_fork",
// security, critical). Nothing is published over it until the bucket's root is one the chain rules accept again.
namespace vh::sync::manifest {

class Service {
public:
    Service(uint32_t vaultId, const Uid& vaultUid, std::shared_ptr<ObjectStore> store,
            std::shared_ptr<vault::EncryptionManager> keys);

    // Collects, publishes, records. Rethrows ChainRejected (after recording and alerting), PublishConflict and the
    // store's errors.
    PublishReport publish();
    // publish() unless the database holds exactly what this service's last publish produced and the bucket's root is
    // still that publish (a sync pass that changed nothing writes nothing, spec 01 §5): nullopt then.
    std::optional<PublishReport> publishIfChanged();

    // Checks the bucket's current root against remote_manifest_state without loading segments: one GET of the root
    // when its ETag moved. An accepted newer root (another writer) becomes the known state; nullopt when there is no
    // root or it doesn't authenticate (the next publish rebuilds it). Rethrows ChainRejected after recording and
    // alerting.
    std::optional<Acceptance> verifyRemote();

    // GC when the last one was more than a day ago (remote_manifest_state.gc_at); nullopt when not due.
    std::optional<GcReport> collectGarbageIfDue(std::time_t now = std::time(nullptr));

    [[nodiscard]] crypto::vhf1::KeyLookup keyLookup() const;

private:
    void refused(const ChainRejected& e, uint64_t epoch, const std::string& rootSha256);
    PublishReport publishLocked(const Content& produced);
    [[nodiscard]] std::optional<Known> known() const;

    uint32_t vaultId_;
    Uid vaultUid_;
    std::shared_ptr<ObjectStore> store_;
    std::shared_ptr<vault::EncryptionManager> keys_;
    std::mutex mutex_;
    PublisherCache cache_;
};

// The operator alert for a refused root. Exposed for tests.
void notifyRefusedRoot(uint32_t vaultId, ChainError reason, uint64_t epoch, const std::string& rootSha256,
                       const std::optional<Known>& known);

}
