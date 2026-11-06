#pragma once

#include "crypto/secrets/Versioned.hpp"
#include "ops/Error.hpp"

#include <chrono>
#include <ctime>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Versioned master-secret rewrap (#352 for vault_master, #353 for ak_master and s3gw_master; design/sealing/
// master-secrets.md §6; migrations 121, 122). Replaces a data-wrapping master without touching what its rows protect:
// only the wraps change (never a file body, never an upstream credential's value).
//
//   slot           rows rewrapped                                           verified against
//   vault_master   vault_keys, vault_keys_trashed, vault_deletion_key       the old unwrap and the key check (113)
//   ak_master      api_keys: the S3 secret and the provider token (if any)  the old unwrap
//   s3gw_master    s3_gateway_credentials: the credential secret            the old unwrap
//
//   rotate     stage: seal <slot>.v<N+1> beside the current master, then write the new wrap of every row into its
//              *_next columns, in batched transactions (resumable: a rerun continues where a crash stopped);
//              verify: unwrap every staged row under the new master and compare it with the row under the current
//              one (and the vault key check); any mismatch aborts before anything switches;
//              switch: one transaction (the slot's tables locked against writes) stages what changed meanwhile,
//              verifies every row again, moves the wraps into place and keeps the old ones in *_prev, and records
//              version = N+1 with a recovery window. A crash on either side of its commit is consistent: each row
//              names the master that wraps it.
//   rollback   while staging: discard the staged wraps and the new master. Inside the window: put the retained wraps
//              back (rows changed during the window are rewrapped under the previous master), verified first, and
//              delete the new master.
//   finalize   ends the window (by hand, or when it expires: expireIfDue): verifies every row under the current
//              master, clears the retained wraps, then deletes the previous master.
//
// One operation runs at a time per slot in this process. Every refusal is a Refused (nothing changed by it); anything
// else is a fault, after which the state is still consistent and the operation can be run again.
namespace vh::crypto::secrets::rewrap {

using Slot = versioned::Slot;
// Refusals are ops::Refused (a typed refusal: a transaction it leaves rolls back quietly). Codes: window_open,
// no_window, unreadable_rows, mismatch, previous_unavailable, current_unavailable, verification_failed.
using Refused = ops::Refused;

inline constexpr std::chrono::seconds kDefaultWindow{std::chrono::hours(24 * 7)};
inline constexpr unsigned int kDefaultBatch = 200;

struct State {
    unsigned int version{1};
    unsigned int highest_version{1};
    std::optional<unsigned int> staging_version{};
    std::optional<std::time_t> staging_started_at{};
    std::optional<unsigned int> previous_version{};
    std::optional<std::time_t> switched_at{};
    std::optional<std::time_t> window_until{};
    std::vector<unsigned int> discard_versions{};
};
[[nodiscard]] State state(Slot slot);

struct Status {
    Slot slot{Slot::VaultMaster};
    State state{};
    unsigned int rows{};                              // every dependent row (all of the slot's tables)
    std::map<unsigned int, unsigned int> by_master{};  // rows per master_version
    unsigned int staged{};                            // rows with a staged wrap for staging_version
    unsigned int retained{};                          // rows with a retained wrap for previous_version
    bool current_sealed{false}, staging_sealed{false}, previous_sealed{false};  // the slot is on this host
};
[[nodiscard]] Status status(Slot slot);

struct Options {
    std::chrono::seconds window{kDefaultWindow};
    unsigned int batch{kDefaultBatch};
};

struct RotateResult {
    unsigned int from{}, to{};
    unsigned int rows{};            // rows switched
    unsigned int staged_now{};      // rows this run staged in batches (the rest were staged by an interrupted run)
    unsigned int caught_up{};       // rows that changed after staging, staged inside the switch
    unsigned int batches{};
    bool resumed{false};            // an interrupted staging was continued
    std::time_t window_until{};
};
// Refuses window_open (finalize or roll back the last rotation first), unreadable_rows (a row doesn't unwrap under
// its master: restore or re-enter it first; nothing is staged), mismatch / verification_failed (a staged wrap is not
// the row's secret; the bad staged wraps are dropped and nothing switched).
RotateResult rotate(Slot slot, const Options& options = {});

struct RollbackResult {
    enum class Kind { AbandonedStaging, Reverted } kind{Kind::Reverted};
    unsigned int from{}, to{};   // AbandonedStaging: from = the discarded staging version, to = current
    unsigned int rows{};         // rows restored from their retained wrap
    unsigned int rewrapped{};    // rows changed during the window, rewrapped under the previous master
};
// Refuses no_window (nothing staged and no window), previous_unavailable (the previous master no longer unseals:
// finalize instead), current_unavailable (rows changed during the window need the current master, which is gone).
RollbackResult rollback(Slot slot);

struct FinalizeResult {
    bool finalized{false};             // false: no window, or not due (expireIfDue)
    std::optional<unsigned int> previous{};
    unsigned int rows{};
    std::vector<unsigned int> deleted{};  // master versions whose sealed slot was deleted
};
// Refuses verification_failed (a row doesn't unwrap under the current master, or doesn't match its key check: the
// window stays open; nothing is deleted).
FinalizeResult finalize(Slot slot);
// The automatic end of a slot's window: finalize() once window_until has passed (and pending slot deletions of an
// interrupted finalize or rollback). Never throws; a refusal is audited and retried 10 minutes later.
FinalizeResult expireIfDue(Slot slot, std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
// expireIfDue for every slot (the vault retention loop calls it).
void expireAllIfDue(std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

// Tests: called at every crash point ("staging_recorded", "sealed", "batch", "verified", "switched",
// "rollback_committed", "finalize_committed") of every slot; throwing from it simulates a crash there. nullptr turns
// it off.
using CrashHook = std::function<void(std::string_view point)>;
void setCrashHookForTesting(CrashHook hook);

}
