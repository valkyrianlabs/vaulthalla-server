#pragma once

#include <vl/vaultfmt/manifest/Reconcile.hpp>
#include <vl/vaultfmt/manifest/Reader.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

// The per-vault manifest applier (design/sync/manifest-applier.md, work items 4 and 5): takes another writer's
// canonical root (the head verifyRemote returned) into this server's database, FUSE view, cache and change journal.
//
//   1. entries deferred by an earlier apply whose file closed since are finished (finishDeferred);
//   2. base = the local base copy of `known` (openBaseCopy); none usable (a state from before migration 145, or one an
//      attach-remote cutover or a restore recorded): no base, so the merge is a union and deletes nothing;
//   3. reconcile(base, head, collect()) (sync/manifest/Reconcile.hpp); key problems or a head that didn't load
//      completely stop here (ApplyStopped: the pass stalls, nothing is written);
//   4. remote_manifest_state.applying_* := the head, then the plan, one short transaction per operation, each a
//      compare-and-set on what `ours` held, with the cache, backing-file and derived-artifact work after its commit and
//      through the same calls local writes use where they exist (Filesystem::rename / remove, Engine::removeLocally);
//   5. when no operation was skipped, the head is recorded with its base copy in the last transaction (clearing
//      applying_*) and `manifest.applied` is audited. A skipped operation (a local write since collect) leaves applying_*
//      set: nothing is published from the partial state, and the next pass applies the head again from a fresh collect.
//
// Decided outcomes that are not skips: a content replacement or delete of a file whose local copy has a change not yet
// uploaded writes only the index row (the planner's two-sided path decides it); a file with an open working copy is
// deferred (manifest_apply_deferred, migration 146; the collector reports the incoming value meanwhile).
//
// Runs on the sync pass's thread under the pass lease, never in a FUSE callback or ws handler; no transaction spans a
// network request (the head and its segments were fetched before).
namespace vh::sync::vault_manifest {

// The pass stalls: theirs names a key version this server doesn't hold or holds with another key check, or the head
// didn't load completely (a segment from an older root or blind: applying it would delete what it lost).
class ApplyStopped : public std::runtime_error {
public:
    explicit ApplyStopped(const std::string& message) : std::runtime_error(message) {}
};

// The apply stops at this root for `reason` (manifest_key_missing, manifest_key_mismatch, manifest_head_incomplete,
// manifest_mirror_shared, manifest_writer_floor): recorded in manifest_apply_report.stopped_* (shown as
// last_apply.stopped by storage.vault.get and `vh vault sync info`), the operator alerted once per root and reason
// (manifest_apply_stopped), then ApplyStopped(why). Nothing is written to the vault's rows. The next apply that records
// a root clears it.
[[noreturn]] void stopAt(uint32_t vaultId, uint64_t epoch, const std::string& rootSha256, const std::string& producer,
                         const std::string& reason, const std::string& why);

// The writer floor (vl-vaultfmt docs/engine.md, "The writer floor"; design/core/vault-format-library.md decision 7): a
// root whose writer_floor is above this server's writer revision was written by a newer Vaulthalla. It is never applied
// (its members this database doesn't store would be dropped, and a later publish would carry the loss) and never
// published over (vl::vaultfmt::manifest::WriterFloorRefused, before any PUT): the vault stalls until this server is
// upgraded.
inline constexpr const char* kWriterFloorStop = "manifest_writer_floor";
// The operator's message for it.
[[nodiscard]] std::string writerFloorMessage(uint64_t epoch, uint32_t floor, uint32_t revision);

// Other writers' recovery envelope kids are carried into this server's roots (design: "Foreign envelopes"): a head
// naming several writers is applied. What still refuses one: a vault on the mirror strategy (it deletes remote objects
// its database doesn't hold), and every refusal the join will add (design item 6).
inline constexpr bool kCarriesForeignEnvelopes = true;

struct ApplyOptions {
    std::function<bool(uint64_t inode)> isOpen{};                  // default: fuse::WorkingCopies
    std::function<void(const vl::vaultfmt::manifest::Op& op)> beforeOp{};         // tests: a local write or a crash before an op
    vl::vaultfmt::manifest::ObjectStore* store{};                                // the bucket (other writers' envelopes); the service's
};

struct ApplyReport {
    uint64_t epoch{};
    std::string root_sha256;
    std::string producer;                 // the head's producing node
    bool recorded{false};                 // `known` is the head now
    bool union_base{false};               // no usable base copy: merged without one (nothing deleted)
    std::size_t applied{}, skipped{}, deferred{}, kept{};
    std::vector<vl::vaultfmt::manifest::Conflict> conflicts;
    std::vector<std::string> notes;
};

[[nodiscard]] ApplyReport apply(uint32_t vaultId, const vl::vaultfmt::manifest::Uid& vaultUid, const vl::vaultfmt::vhf1::KeyLookup& keys,
                                const vl::vaultfmt::manifest::Loaded& head, const std::string& selfNode,
                                const ApplyOptions& options = {});

// Entries deferred while their file was open whose file is closed now: applied when the local copy is the one the
// deferral saw, handed to the planner as a two-sided change when the close sealed new bytes. How many were finished.
std::size_t finishDeferred(uint32_t vaultId, const ApplyOptions& options = {});

}
