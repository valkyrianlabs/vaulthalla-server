#pragma once

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

// Versioned vault_master rewrap (#352, design/sealing/master-secrets.md §6, migration 120). Replaces the vault master
// that wraps every vault key version without touching a single file body: only the wraps change.
//
//   rotate     stage: seal vault_master.v<N+1> beside the current master, then write the new wrap of every row of
//              vault_keys, vault_keys_trashed and vault_deletion_key into its *_next columns, in batched
//              transactions (resumable: a rerun continues where a crash stopped);
//              verify: unwrap every staged row under the new master and compare it with the row under the current
//              one and with its recorded key check (migration 113); any mismatch aborts before anything switches;
//              switch: one transaction (key tables locked against writes) stages what changed meanwhile, verifies
//              every row again, moves the wraps into place and keeps the old ones in *_prev, and records
//              version = N+1 with a recovery window. A crash on either side of its commit is consistent: each row
//              names the master that wraps it.
//   rollback   while staging: discard the staged wraps and the new master. Inside the window: put the retained wraps
//              back (rows changed during the window are rewrapped under the previous master), verified first, and
//              delete the new master.
//   finalize   ends the window (by hand, or when it expires: expireIfDue): verifies every row under the current
//              master, clears the retained wraps, then deletes the previous master.
//
// Only one operation runs at a time in this process. Every refusal is a Refused (nothing changed by it); anything
// else is a fault, after which the state is still consistent and the operation can be run again.
namespace vh::vault::master::rewrap {

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
[[nodiscard]] State state();

struct Status {
    State state{};
    unsigned int rows{};                              // every vault key row (all three tables)
    std::map<unsigned int, unsigned int> by_master{};  // rows per master_version
    unsigned int staged{};                            // rows with a staged wrap for staging_version
    unsigned int retained{};                          // rows with a retained wrap for previous_version
    bool current_sealed{false}, staging_sealed{false}, previous_sealed{false};  // the slot is on this host
};
[[nodiscard]] Status status();

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
// its master: import that vault's keys first; nothing is staged), mismatch / verification_failed (a staged wrap is
// not the row's key; the bad staged wraps are dropped and nothing switched).
RotateResult rotate(const Options& options = {});

struct RollbackResult {
    enum class Kind { AbandonedStaging, Reverted } kind{Kind::Reverted};
    unsigned int from{}, to{};   // AbandonedStaging: from = the discarded staging version, to = current
    unsigned int rows{};         // rows restored from their retained wrap
    unsigned int rewrapped{};    // rows changed during the window, rewrapped under the previous master
};
// Refuses no_window (nothing staged and no window), previous_unavailable (the previous master no longer unseals:
// finalize instead), current_unavailable (rows changed during the window need the current master, which is gone:
// import those vaults' keys first).
RollbackResult rollback();

struct FinalizeResult {
    bool finalized{false};             // false: no window, or not due (expireIfDue)
    std::optional<unsigned int> previous{};
    unsigned int rows{};
    std::vector<unsigned int> deleted{};  // master versions whose sealed slot was deleted
};
// Refuses verification_failed (a row doesn't unwrap under the current master or doesn't match its key check: the
// window stays open; nothing is deleted).
FinalizeResult finalize();
// The automatic end of the window: finalize() once window_until has passed (and pending slot deletions of an
// interrupted finalize or rollback). Never throws; a refusal is logged and retried later. Called from the vault
// retention loop.
FinalizeResult expireIfDue(std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

// Tests: called at every crash point ("staging_recorded", "sealed", "batch", "verified", "switched",
// "rollback_committed", "finalize_committed"); throwing from it simulates a crash there. nullptr turns it off.
using CrashHook = std::function<void(std::string_view point)>;
void setCrashHookForTesting(CrashHook hook);

}
