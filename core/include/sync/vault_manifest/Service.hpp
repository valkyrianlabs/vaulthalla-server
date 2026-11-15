#pragma once

#include "sync/manifest/Session.hpp"
#include "sync/vault_manifest/Applier.hpp"
#include "vault/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

// Manifest v2 for one opaque_v1 vault, the way the daemon runs it: sync::manifest::Session (the logic: publish, verify,
// refuse, repair, collect) wired to this server. The session's state is PostgreSQL (remote_manifest_state and the
// root history, db::query::sync::Manifest), its content is what the database holds
// (db::query::sync::Manifest::collect), its keys are the vault's EncryptionManager, its writer identity is
// db::query::device::Devices::nodeId(), its notices go to the cloud log and a refused root to the operators.
// CloudEngine owns one per opaque_v1 vault, in place of the index-v1.json manifest.
//
// A refused root (rollback, fork) leaves the database untouched and is recorded in remote_manifest_state; the
// operator is notified once per refused root (operator_notification event "manifest_rollback" / "manifest_fork",
// security, critical). Nothing is published over it until the bucket's root is one the chain rules accept again.
//
// This namespace is the server's; sync::manifest holds only what the shared format library will (#443).
namespace vh::sync::vault_manifest {

class Service {
public:
    Service(uint32_t vaultId, const manifest::Uid& vaultUid, std::shared_ptr<manifest::ObjectStore> store,
            std::shared_ptr<vault::EncryptionManager> keys);

    // Collects, publishes, records. When the bucket's head is not the recorded root (another writer published, or won
    // a round) the head is applied first (applyRemote) and the publish runs again, at most kPublishRounds times
    // (spec 06 I7), then PublishConflict. Rethrows ChainRejected (after recording and alerting), ApplyStopped,
    // ApplyIncomplete (an apply skipped a change: nothing is published from a partial state) and the store's errors.
    manifest::PublishReport publish();
    static constexpr unsigned kPublishRounds = 4;
    // publish() unless the database holds exactly what this service's last publish produced and the bucket's root is
    // still that publish (a sync pass that changed nothing writes nothing, spec 01 §5): nullopt then.
    std::optional<manifest::PublishReport> publishIfChanged();

    // Checks the bucket's current root against remote_manifest_state: one HEAD while its ETag is the recorded one.
    // A head that is not the recorded root comes back loaded in RemoteHead::head, unrecorded (applyRemote applies and
    // records it). nullopt when there is no root or it doesn't authenticate (the next publish rebuilds it). Rethrows
    // ChainRejected after recording and alerting.
    std::optional<manifest::RemoteHead> verifyRemote();

    // A pass's remote step (design/sync/manifest-applier.md, items 4 and 5): entries deferred while their file was
    // open are finished once it closed, then the head is verified and, when it moved, applied (Applier.hpp). nullopt
    // when nothing was applied; a solo vault's pass costs its one HEAD. Rethrows ChainRejected and ApplyStopped.
    std::optional<ApplyReport> applyRemote(const ApplyOptions& options = {});

    // GC when the last one was more than a day ago (remote_manifest_state.gc_at); nullopt when not due.
    std::optional<manifest::GcReport> collectGarbageIfDue(std::time_t now = std::time(nullptr));

    [[nodiscard]] crypto::vhf1::KeyLookup keyLookup() const;

private:
    template <typename F>
    auto publishRounds(F&& once) -> decltype(once());

    // Serializes applyRemote (a pass, and a publish on another thread that met HeadMoved). Taken before the
    // session's mutex, never while it is held (the session releases it before HeadMoved reaches publishRounds); held
    // only on sync and publish paths, never in a FUSE callback or ws handler.
    std::mutex applyMutex_;
    uint32_t vaultId_;
    manifest::Uid vaultUid_;
    std::shared_ptr<vault::EncryptionManager> keys_;
    manifest::Session session_;
};

// The operator alert for a refused root. Exposed for tests.
void notifyRefusedRoot(uint32_t vaultId, manifest::ChainError reason, uint64_t epoch, const std::string& rootSha256,
                       const std::optional<manifest::Known>& known);

}
