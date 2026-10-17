#pragma once

#include "recovery/Fwd.hpp"
#include "recovery/Model.hpp"
#include "storage/Fwd.hpp"
#include "storage/s3/RequestUsage.hpp"

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Restore plans and version-aware restore of provider object versions (pv-<id>). Raw and unauthorized: ops::recovery
// owns RBAC, plan tokens and outcomes per plan; these work per item. See .claude/context/recovery.md,
// "Provider versioning".
namespace vh::recovery::provider {

// A sync pass (or the event applier) holds the vault's pass lease: retry later. Nothing was sent or changed.
class PassBusy final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The version was not written by Vaulthalla (origin 'observed'): the caller must ask for
// ops::recovery::UNVERIFIED_VERSION and repeat with RestoreOptions::accept_unverified. Nothing was sent.
class UnverifiedVersion final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ---- plans ---------------------------------------------------------------------------------------------------------

// One version restored to `destination` (default: its own path) as a plan item (no request is sent):
//   unavailable   delete marker, gone, archived class, key version not held
//   skip          the destination already is this version (same key and current, or same IV + key version)
//   conflict      the destination is a directory, has an open sync conflict, or holds local changes not uploaded yet
//   overwrite     destination exists (destination_source_id = its generation, the CAS for restore)
//   create        destination doesn't exist
// method provider_copy when a CopyObject can do it (same object key, sealed under the current key or plaintext in a
// vault that stores plaintext upstream, ≤ 5 GiB), else provider_transfer (GET + re-seal + PUT). Unknown metadata
// (an observed version) plans a copy; restore decides after its HEAD. Origin other than 'vaulthalla' adds the note
// "unverified".
[[nodiscard]] PlanItem planFor(const std::shared_ptr<storage::CloudEngine>& engine,
                               const db::query::recovery::ObjectVersionRow& version,
                               const std::optional<std::filesystem::path>& destination = std::nullopt);

// Point in time under `path` (a file or a directory, vault path): per object the newest version with
// LastModified ≤ at (index only: refresh it first). A delete marker or no version at `at` means absent: an existing
// destination is removed only with prune (action remove), otherwise kept and counted in a warning. destination
// re-roots the restored paths. Plan.atomic is false and consistency_note says it is a reconstruction from
// per-object timestamps. Totals and the request estimate are filled; id/token/state are the dispatcher's.
[[nodiscard]] Plan planAt(const std::shared_ptr<storage::CloudEngine>& engine, const std::filesystem::path& path,
                          std::time_t at, const std::optional<std::filesystem::path>& destination = std::nullopt,
                          bool prune = false, unsigned int limit = 100000);

// A plan for one version (planFor + totals + estimate).
[[nodiscard]] Plan planOne(const std::shared_ptr<storage::CloudEngine>& engine, uint64_t versionRowId,
                           const std::optional<std::filesystem::path>& destination = std::nullopt);

// ---- restore -------------------------------------------------------------------------------------------------------

struct RestoreHooks {
    // The vault's pass lease (default: runtime::Deps syncController; no controller = no contention).
    std::function<bool(uint32_t)> tryAcquirePass;
    std::function<void(uint32_t)> releasePass;
};

struct RestoreOptions {
    bool accept_unverified{false};          // UNVERIFIED_VERSION accepted
    std::optional<uint32_t> user_id;        // who the restore is recorded as (default: the vault owner)
    RestoreHooks hooks{};
};

struct RestoreOutcome {
    std::string outcome;                    // restored | skipped | conflict | failed | removed | unavailable
    std::optional<std::string> error;       // why (failed/conflict/unavailable/skipped)
    std::string method{"none"};             // provider_copy | provider_transfer | local_remove | none
    bool retryable{false};                  // failed for a transient reason (budget, outage): the same item may run again
    bool provider_changed{false};           // a new current version was written upstream
    std::optional<std::string> new_version_id, new_etag;
    std::vector<std::string> notes;
    // What was sent upstream (source "recovery_restore"): the usage ledger's version_restore_requests/bytes input.
    storage::s3::S3GatewayUpstreamUsage usage{};
};

// Restores one plan item: takes the vault's pass lease (PassBusy when taken), re-checks the destination against
// expectedDestinationSourceId (CAS; also re-checked before anything is committed locally), HEADs the version, then a
// provider copy or a bounded transfer exactly per recovery.md, and reconciles local state before releasing the lease
// so the next pass sees both sides agree and uploads nothing. Throws PassBusy / UnverifiedVersion /
// std::invalid_argument (not a pv- item of this vault); every other failure is an outcome.
[[nodiscard]] RestoreOutcome restore(const std::shared_ptr<storage::CloudEngine>& engine, const PlanItem& item,
                                     const std::optional<std::string>& expectedDestinationSourceId,
                                     const RestoreOptions& options = {});

}
