#pragma once

#include "ops/Actor.hpp"
#include "recovery/Model.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// File recovery, shared by `vh snapshot …`, `vh recovery …`, `vh vault recovery …` and the ws recovery.* /
// vault.recovery.* commands. The only authorizing boundary for recovery; see .claude/context/recovery.md.
//
// Who (all through the existing resolvers; no recovery-specific permission bits):
//   status, costs                      vault sync.config.view-equivalent: what reads a vault's sync settings and
//                                      stats.vault.pricing (owner, or admin with vault view + view_stats)
//   update (mode, quotas, alert,
//           local versioning)          vault sync.config.edit
//   provider versioning enable,
//   retention, suspend, adopt bound    + admin.upstream.configure + key Consume; bucket managed or adopted (adoption of
//                                      the vault's own bucket: + admin.upstream.provision); never a protected bucket
//   list, inspect                      filesystem Read on the point's path (List for directories); points the actor
//                                      can't read are omitted from lists and NotFound on inspect (no oracle)
//   createSnapshot                     Read + Copy on every file, List on every directory of the subtree
//   deletePoint                        filesystem Delete on the point's path (snapshots, local versions only)
//   plan                               Read on every source; restore re-checks:
//   restore                            Overwrite on each existing destination file, Write (upload) at the parent of
//                                      each new file, Touch for new directories, Delete for prune removals
// Recovery never bypasses protection locks (storage::upstream::guard on every provider request) or file RBAC.
namespace vh::ops::recovery {

using vh::recovery::Backend;
using vh::recovery::CostReport;
using vh::recovery::Disclosure;
using vh::recovery::LocalVersioningPolicy;
using vh::recovery::Mode;
using vh::recovery::Plan;
using vh::recovery::ProviderRetention;
using vh::recovery::RecoveryPoint;
using vh::recovery::RestoreResult;
using vh::recovery::Status;

// NeedsConfirmation codes.
inline constexpr const char* VERSIONING_DISCLOSURE = "recovery_versioning_disclosure";  // no/expired disclosure token
inline constexpr const char* VERSIONING_UNPRICED = "recovery_versioning_unpriced";       // costs can't be estimated
inline constexpr const char* RETENTION_SHORTEN = "recovery_retention_shorten";           // deletes history sooner
inline constexpr const char* VERSIONING_SUSPEND = "recovery_versioning_suspend";
inline constexpr const char* BUCKET_ADOPTION = "upstream_adoption";                      // = ops::upstream
inline constexpr const char* POINT_DELETE = "recovery_point_delete";
inline constexpr const char* RESTORE_CONFIRM = "recovery_restore";                       // no/expired plan token
inline constexpr const char* UNVERIFIED_VERSION = "recovery_unverified_version";         // not written by Vaulthalla

// ---- policy --------------------------------------------------------------------------------------------------------

// refreshProvider: re-read the bucket's versioning/lifecycle/object-lock state (one admin round trip) instead of the
// last recorded one.
[[nodiscard]] Status status(const Actor& actor, uint32_t vaultId, bool refreshProvider = false);

struct Update {
    std::optional<Mode> mode{};
    std::optional<ProviderRetention> provider_retention{};
    std::optional<uint64_t> snapshot_quota_bytes{};      // 0 = no snapshot quota
    std::optional<std::string> cost_alert_monthly{};     // decimal amount in the catalog currency; "" = clear
    std::optional<LocalVersioningPolicy> local_versioning{};
    std::optional<std::string> disclosure_token{};       // from versioningDisclosure()
    bool accept_unpriced = false;                        // VERSIONING_UNPRICED
    bool accept_retention_shortening = false;            // RETENTION_SHORTEN
    bool accept_adoption = false;                        // BUCKET_ADOPTION (the vault's own unmanaged bucket)
};

// Mode → provider_versioning: provider must support it (AWS S3 today; R2 refused), key admin-enabled, bucket
// managed/adopted (or adopted now with accept_adoption), never protected; a valid disclosure token for this vault,
// bucket, retention and actor; enables bucket versioning only if it isn't already enabled, re-reads it, and records the
// propagation window. Mode away from provider_versioning never suspends bucket versioning (suspendVersioning does).
// A retention change that shortens history needs accept_retention_shortening, including from automation.
[[nodiscard]] Status update(const Actor& actor, uint32_t vaultId, const Update& req);

// The cost disclosure for enabling provider versioning with `retention` (default: the bucket's current Vaulthalla
// retention, else none chosen → scenarios only). Read-only; at most one admin inspect and no object requests.
[[nodiscard]] Disclosure versioningDisclosure(const Actor& actor, uint32_t vaultId,
                                              const std::optional<ProviderRetention>& retention = std::nullopt);

// Suspends future versioning on the bucket (PutBucketVersioning Suspended). Existing versions are kept; nothing is
// deleted. NeedsConfirmation{VERSIONING_SUSPEND} unless confirm.
[[nodiscard]] Status suspendVersioning(const Actor& actor, uint32_t vaultId, bool confirm);

// The ongoing recovery cost panel (and, before activation, the same figures the disclosure shows).
[[nodiscard]] CostReport costs(const Actor& actor, uint32_t vaultId);

// ---- recovery points -----------------------------------------------------------------------------------------------

struct ListQuery {
    std::optional<std::string> path{};     // vault path; a directory lists points under it, a file its history
    bool refresh_provider = false;         // ListObjectVersions for the path (metadata only, request-budgeted)
    bool include_snapshots = true, include_versions = true, include_provider = true;
    unsigned int limit = 200;
};

[[nodiscard]] std::vector<RecoveryPoint> list(const Actor& actor, uint32_t vaultId, const ListQuery& query = {});

struct PointDetail {
    RecoveryPoint point;
    std::vector<RecoveryPoint> members;    // snapshot: its file generations (first page); otherwise empty
    bool members_truncated = false;
    std::optional<std::string> created_by;
    std::vector<std::string> skipped;      // snapshot: entries not captured (symlinks, unreadable, …) and why
};

[[nodiscard]] PointDetail inspect(const Actor& actor, const std::string& recoveryId);

struct SnapshotRequest {
    std::string path;                      // vault path of a file or directory
    std::optional<std::string> name{};
};

// Needs mode local_snapshots. Counts against the snapshot quota and the vault quota (physical, deduplicated bytes).
[[nodiscard]] PointDetail createSnapshot(const Actor& actor, uint32_t vaultId, const SnapshotRequest& req);

// Snapshots and local versions only (provider versions are the provider's: retention removes them). A version still
// pending upstream can't be deleted (Conflict). NeedsConfirmation{POINT_DELETE} unless confirm.
void deletePoint(const Actor& actor, const std::string& recoveryId, bool confirm);

// ---- restore -------------------------------------------------------------------------------------------------------

struct PlanRequest {
    std::optional<std::string> recovery_id{};   // a point to restore, or:
    std::optional<uint32_t> vault_id{};          // point in time: vault + path + at
    std::optional<std::string> path{};
    std::optional<std::time_t> at{};
    std::optional<std::string> destination{};    // alternate root (vault path); default: original paths
    bool prune = false;                          // point in time: also remove files that did not exist at `at`
    bool refresh_provider = true;                // point in time over provider versions: list them first
};

// Read-only (provider: ListObjectVersions/HEAD metadata only, request-budgeted). The plan and its token are stored
// for 30 minutes.
[[nodiscard]] Plan plan(const Actor& actor, const PlanRequest& req);
[[nodiscard]] Plan getPlan(const Actor& actor, uint64_t planId);

struct RestoreRequest {
    uint64_t plan_id{};
    std::optional<std::string> token{};          // NeedsConfirmation{RESTORE_CONFIRM} without a valid one
    bool accept_unverified = false;              // UNVERIFIED_VERSION: provider versions Vaulthalla didn't write
};

// Re-authorizes every item, then restores each one as a new current generation (CAS against the planned destination
// generation: a destination that changed since the plan is a `conflict` outcome, never overwritten). Resumable: a
// plan left `running` (crash) or `partial` can be restored again; finished items are skipped.
[[nodiscard]] RestoreResult restore(const Actor& actor, const RestoreRequest& req);

}
