#pragma once

#include <vl/vaultfmt/manifest/Session.hpp>
#include "sync/vault_manifest/Applier.hpp"
#include "vault/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <memory>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

// Manifest v2 for one opaque_v1 vault, the way the daemon runs it: vl::vaultfmt::manifest::Session (the logic: publish, verify,
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
// This namespace is the server's; the Session and the format are vl-vaultfmt's (vl::vaultfmt::manifest, #443).
namespace vh::sync::vault_manifest {

// This server's writer revision (vl-vaultfmt's writer floor; Applier.hpp, kWriterFloorStop): the manifest members
// db::query::sync::Manifest::collect round-trips. A root whose writer_floor is above it is neither applied nor published
// over. It stays at the library's baseline, and this server's roots need no floor (SessionHost::writerFloor 0). Raise it
// here only in the same change as the migration that stores every member the new revision adds (and collect and the
// applier carrying them); declaring a revision whose members this database drops is the loss the floor exists to stop.
inline constexpr uint32_t kWriterRevision = vl::vaultfmt::manifest::kBaselineWriterRevision;

class Service {
public:
    // `writerRevision`: kWriterRevision; tests stand in a server of another revision (an upgraded or a downgraded one).
    Service(uint32_t vaultId, const vl::vaultfmt::manifest::Uid& vaultUid, std::shared_ptr<vl::vaultfmt::manifest::ObjectStore> store,
            std::shared_ptr<vault::EncryptionManager> keys, uint32_t writerRevision = kWriterRevision);

    // Collects, publishes, records. When the bucket's head is not the recorded root (another writer published, or won
    // a round) the head is applied first (applyRemote) and the publish runs again, at most kPublishRounds times
    // (spec 06 I7), then PublishConflict. Rethrows ChainRejected (after recording and alerting), ApplyStopped,
    // ApplyIncomplete (an apply skipped a change: nothing is published from a partial state), WriterFloorRefused (the
    // root it would build on needs a newer Vaulthalla: nothing written, recorded and alerted once as
    // manifest_writer_floor; a stall, never retried here) and the store's errors. A publish that succeeds clears a
    // recorded manifest_writer_floor stop.
    vl::vaultfmt::manifest::PublishReport publish();
    static constexpr unsigned kPublishRounds = 4;
    // publish() unless the database holds exactly what this service's last publish produced and the bucket's root is
    // still that publish (a sync pass that changed nothing writes nothing, spec 01 §5): nullopt then.
    std::optional<vl::vaultfmt::manifest::PublishReport> publishIfChanged();

    // Checks the bucket's current root against remote_manifest_state: one HEAD while its ETag is the recorded one.
    // A head that is not the recorded root comes back loaded in RemoteHead::head, unrecorded (applyRemote applies and
    // records it). nullopt when there is no root or it doesn't authenticate (the next publish rebuilds it). Rethrows
    // ChainRejected after recording and alerting.
    std::optional<vl::vaultfmt::manifest::RemoteHead> verifyRemote();

    // A pass's remote step (design/sync/manifest-applier.md, items 4 and 5): entries deferred while their file was
    // open are finished once it closed, then the head is verified and, when it moved, applied (Applier.hpp). nullopt
    // when nothing was applied; a solo vault's pass costs its one HEAD. Rethrows ChainRejected and ApplyStopped (a head
    // above this server's writer revision stops before reconcile: manifest_writer_floor).
    std::optional<ApplyReport> applyRemote(const ApplyOptions& options = {});

    // Shared-vault trash this server purged locally (migration 148): each object older than `grace` is deleted from the
    // bucket when the recorded root is still the bucket's head (HEAD, again right before each DELETE), and neither it,
    // a deferred entry nor a pending own root names the object (live, trashed or as history); one named again is
    // forgotten (it is live). Never an object this server didn't purge. `beforeDelete` is a test hook. How many were
    // deleted.
    std::size_t collectSharedOrphans(std::time_t now, std::time_t grace = kSharedOrphanGrace,
                                     const std::function<void(const std::string& key)>& beforeDelete = {});
    static constexpr std::time_t kSharedOrphanGrace = 7 * 24 * 60 * 60;

    // GC when the last one was more than a day ago (remote_manifest_state.gc_at); nullopt when not due.
    std::optional<vl::vaultfmt::manifest::GcReport> collectGarbageIfDue(std::time_t now = std::time(nullptr));

    [[nodiscard]] vl::vaultfmt::vhf1::KeyLookup keyLookup() const;

private:
    template <typename F>
    auto publishRounds(F&& once) -> decltype(once());
    // A publish met WriterFloorRefused: the root whose floor binds is recorded as the stop and alerted once.
    void noteFloorRefused(const vl::vaultfmt::manifest::WriterFloorRefused& e);

    // Serializes applyRemote (a pass, and a publish on another thread that met HeadMoved). Taken before the
    // session's mutex, never while it is held (the session releases it before HeadMoved reaches publishRounds); held
    // only on sync and publish paths, never in a FUSE callback or ws handler.
    std::mutex applyMutex_;
    uint32_t vaultId_;
    uint32_t writerRevision_;
    vl::vaultfmt::manifest::Uid vaultUid_;
    std::shared_ptr<vault::EncryptionManager> keys_;
    std::shared_ptr<vl::vaultfmt::manifest::ObjectStore> store_;
    vl::vaultfmt::manifest::Session session_;
};

// The operator alert for a refused root. Exposed for tests.
void notifyRefusedRoot(uint32_t vaultId, vl::vaultfmt::manifest::ChainError reason, uint64_t epoch, const std::string& rootSha256,
                       const std::optional<vl::vaultfmt::manifest::Known>& known);

}
