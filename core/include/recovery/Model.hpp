#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// File recovery (local snapshots, local versioning, provider-native object versioning): the shared model every
// backend presents. The implementations stay separate (recovery/local, recovery/provider); ops::recovery is the one
// authorizing boundary and the only place they meet. See .claude/context/recovery.md.
namespace vh::recovery {

// The vault-level preference. Local versioning is a separate, orthogonal harness (LocalVersioningPolicy).
enum class Mode { Off, LocalSnapshots, ProviderVersioning };
[[nodiscard]] std::string to_string(Mode m);                  // off | local_snapshots | provider_versioning
[[nodiscard]] Mode modeFromString(const std::string& s);      // also accepts "local-snapshots"/"provider-versioning";
                                                              // throws std::invalid_argument

enum class Backend { LocalSnapshot, LocalVersion, ProviderVersion };
[[nodiscard]] std::string to_string(Backend b);               // local_snapshot | local_version | provider_version

enum class PointKind { File, Directory };
[[nodiscard]] std::string to_string(PointKind k);             // file | directory

// Stable, typed recovery identities:
//   snap-<recovery_snapshot.id>          a whole snapshot (file or directory tree)
//   lv-<file_versions.id>                one retained local generation (a snapshot member or a local version)
//   pv-<upstream_object_version.id>      one provider object version or delete marker
struct RecoveryId {
    enum class Type { Snapshot, LocalGeneration, ProviderVersion };
    Type type{Type::Snapshot};
    uint64_t id{};
    [[nodiscard]] std::string str() const;
    // Throws std::invalid_argument on anything else (ops turn it into Invalid).
    [[nodiscard]] static RecoveryId parse(const std::string& s);
    bool operator==(const RecoveryId&) const = default;
};

// A decimal amount as a string (never a binary float) in an ISO currency. Unknown money is std::nullopt, never "0".
struct Money {
    std::string amount;
    std::string currency;
};

struct EncryptionContext {
    bool encrypted{false};
    unsigned int key_version{};            // 0 when not encrypted
    bool key_available{false};             // the vault still holds this key version (current, rotating or retired)
    bool key_current{false};
};

struct Retention {
    // snapshot (kept until deleted) | keep_last:<n> | max_age_days:<n> | provider_days:<n> | indefinite | unknown
    std::string policy;
    std::optional<std::time_t> expires_at;  // when known
    std::optional<std::string> note;
};

struct RecoveryPoint {
    std::string id;                        // RecoveryId::str()
    Backend backend{Backend::LocalSnapshot};
    uint32_t vault_id{};
    std::string path;                      // vault path at the time the point was taken
    std::optional<uint32_t> original_entry_id;
    PointKind kind{PointKind::File};
    std::optional<std::string> name;       // snapshots
    std::time_t created_at{};              // when the point came to exist (snapshot taken; generation retained;
                                           // provider version written)
    std::optional<std::time_t> valid_from; // the content was current from … (local versions; provider versions)
    std::optional<std::time_t> valid_until;
    std::optional<uint64_t> size_bytes;    // plaintext size where known
    std::optional<std::string> content_hash;
    EncryptionContext encryption;
    Retention retention;
    std::optional<Money> estimated_monthly_cost;
    bool is_current{false};                // provider: the latest version
    bool is_delete_marker{false};
    std::optional<std::string> origin;     // provider: vaulthalla | observed
    std::optional<std::string> reason;     // local versions: overwrite | truncate | delete | download | restore | conflict
    std::optional<std::string> upstream_state;   // local versions: none | pending | sent | skipped
    std::optional<std::string> storage_class;
    std::optional<uint64_t> file_count;    // snapshots / directory points
    bool restorable{true};
    std::optional<std::string> unavailable_reason;   // archived tier, key missing, delete marker, …
};

// ---- restore plans -------------------------------------------------------------------------------------------------

enum class ItemAction { Create, Overwrite, Skip, Conflict, Remove, Unavailable };
[[nodiscard]] std::string to_string(ItemAction a);   // create | overwrite | skip | conflict | remove | unavailable

struct PlanItem {
    std::string source_id;                 // lv-… / pv-…
    std::string source_path;
    std::string destination_path;
    ItemAction action{ItemAction::Create};
    std::optional<uint64_t> size_bytes;
    // The destination generation the plan was made against (storage::Generation::sourceId()), for a CAS at restore.
    std::optional<std::string> destination_source_id;
    // local_copy | local_reseal | provider_copy | provider_transfer | none
    std::string method;
    std::vector<std::string> notes;
};

struct RequestEstimate {
    uint64_t get_requests{}, head_requests{}, put_requests{}, copy_requests{}, list_requests{};
    uint64_t download_bytes{}, upload_bytes{};
    std::optional<Money> cost;             // nullopt + unpriced_reason when it can't be priced
    std::optional<std::string> unpriced_reason;
};

struct Plan {
    uint64_t id{};
    uint32_t vault_id{};
    std::string token;                     // pass to restore; bound to plan + actor
    std::string source_label;              // what was chosen ("snap-12", "pv-40", "/docs at 2026-10-01T12:00Z")
    bool point_in_time{false};
    std::optional<std::time_t> at;
    // true only for a local snapshot (taken in one pass under content locks). A provider point-in-time plan is a
    // reconstruction from per-object version timestamps and is never presented as an atomic snapshot.
    bool atomic{false};
    std::string consistency_note;
    std::optional<std::string> destination;   // alternate destination root; nullopt = original paths
    bool prune{false};                         // point-in-time: remove files that did not exist at `at`
    std::vector<PlanItem> items;
    uint64_t creates{}, overwrites{}, skips{}, conflicts{}, removals{}, unavailable{};
    RequestEstimate estimate;
    std::vector<std::string> warnings;
    std::vector<std::string> blockers;     // non-empty: restore refused
    std::time_t created_at{}, expires_at{};
    std::string state;                     // planned | running | done | partial | failed | expired
};

struct ItemOutcome {
    std::string destination_path;
    std::string outcome;                   // restored | skipped | conflict | failed | removed | unavailable
    std::optional<std::string> error;
};

struct RestoreResult {
    uint64_t plan_id{};
    std::string state;                     // done | partial | failed
    std::vector<ItemOutcome> items;
    uint64_t restored{}, skipped{}, conflicts{}, failed{}, removed{}, unavailable{};
};

// ---- policy and status ---------------------------------------------------------------------------------------------

// Provider noncurrent-version retention: days or indefinite. Never a hidden default.
struct ProviderRetention {
    bool indefinite{false};
    unsigned int days{};                   // 1..36500 when !indefinite
    [[nodiscard]] std::string str() const; // "30d" | "indefinite"
    // "30", "30d", "90d", "365d", "indefinite"; throws std::invalid_argument.
    [[nodiscard]] static ProviderRetention parse(const std::string& s);
    bool operator==(const ProviderRetention&) const = default;
};

struct LocalVersioningPolicy {
    bool enabled{false};
    std::optional<unsigned int> keep_last;       // per file
    std::optional<unsigned int> max_age_days;
    std::optional<uint64_t> quota_bytes;         // physical bytes of local versions
};

// A change to the local versioning policy: absent = unchanged; for the limits 0 = no limit.
struct LocalVersioningPatch {
    std::optional<bool> enabled;
    std::optional<unsigned int> keep_last;
    std::optional<unsigned int> max_age_days;
    std::optional<uint64_t> quota_bytes;
    [[nodiscard]] bool empty() const { return !enabled && !keep_last && !max_age_days && !quota_bytes; }
};

struct ProviderVersioningState {
    bool supported{false};
    std::string unsupported_reason;
    std::optional<std::string> provider, bucket, region, storage_class;
    std::string bucket_state{"unknown"};         // managed | adopted | unmanaged | protected | unknown
    std::string status{"unknown"};               // unversioned | enabled | suspended | unknown
    bool enabled_by_vaulthalla{false};
    std::optional<std::time_t> enabled_at, settles_at, checked_at;
    bool settled{false};                         // enabled and past the provider's propagation period
    std::optional<bool> object_lock, mfa_delete;
    std::string retention_mode{"unset"};         // unset | days | indefinite (what Vaulthalla set)
    std::optional<unsigned int> retention_days;
    // Other applications' lifecycle rules that expire noncurrent versions (id: days), and the shortest that applies.
    std::vector<std::string> foreign_noncurrent_rules;
    std::optional<unsigned int> effective_noncurrent_days;
    std::vector<std::string> warnings;
};

struct Backlog {
    uint64_t pending_versions{}, pending_bytes{};
    std::optional<std::time_t> oldest_pending_at;
    uint64_t failing{};                          // pending with at least one failed attempt
    std::optional<std::string> last_error;
};

struct StoreUsage {
    uint64_t count{};
    uint64_t stored_bytes{};                     // physical (deduplicated) bytes on disk
    uint64_t plaintext_bytes{};
};

struct Status {
    uint32_t vault_id{};
    Mode mode{Mode::Off};
    std::optional<uint64_t> snapshot_quota_bytes;
    std::optional<Money> cost_alert_monthly;
    LocalVersioningPolicy local_versioning;
    ProviderVersioningState provider;
    StoreUsage snapshots, versions;
    Backlog backlog;
    std::vector<unsigned int> retained_key_versions;   // key versions recoverable data still needs
    std::vector<std::string> warnings;
};

// ---- costs ---------------------------------------------------------------------------------------------------------

// A labelled amount: expected value plus an uncertainty range when the input is thin.
struct CostFigure {
    std::optional<Money> expected;               // nullopt: not estimable (see reason)
    std::optional<Money> low, high;
    std::string basis;                           // observed | scenario | illustrative
    std::optional<std::string> reason;
};

struct AccumulationPoint {
    unsigned int month{};                        // months after activation (1..12)
    uint64_t noncurrent_bytes{};
    CostFigure monthly_cost;
};

struct RetentionScenario {
    std::string retention;                       // "30d" | "90d" | "365d" | "indefinite"
    uint64_t steady_noncurrent_bytes{};          // indefinite: after 12 months
    CostFigure monthly_cost;
    std::vector<std::string> notes;              // minimum durations, early deletion, …
};

struct Assumption {
    std::string kind;                            // observed | illustrative | provider_rule
    std::string text;
};

struct CostReport {
    uint32_t vault_id{};
    // pre_activation: what enabling would add (pre_activation_monthly, scenarios). active: the bucket versions for this
    // vault (current_month_to_date, current_month_projected, projected_monthly).
    std::string phase{"pre_activation"};
    bool priced{false};                          // a verified-or-labelled catalog profile priced the storage class
    std::optional<std::string> unpriced_reason;
    std::optional<std::string> provider, bucket, region, storage_class, currency;
    struct Catalog {
        std::optional<std::string> version, source;
        bool verified{false};
        bool stale{false};
        std::optional<uint64_t> age_seconds;
        std::optional<std::string> note;         // e.g. "no public key configured: signature not verified"
    } catalog;
    std::string confidence{"none"};              // high | medium | low | none
    std::vector<std::string> confidence_reasons;
    struct Observation {
        uint32_t window_days{};                  // days with usage measurements
        std::optional<std::string> first_day, last_day;
        bool sufficient{false};                  // ≥ 7 measured days
        uint64_t put_requests{}, copy_requests{}, delete_requests{}, get_requests{}, list_requests{};
        uint64_t first_put_objects{}, overwrite_objects{}, deleted_objects{};
        uint64_t overwritten_bytes{}, deleted_bytes{}, uploaded_bytes{};
        std::string overwritten_bytes_per_day{"0"};   // decimal string
    } observation;
    struct Current {
        uint64_t objects{}, bytes{};             // current objects (remote index)
        std::optional<Money> monthly_storage;    // context only: never part of the versioning surcharge
    } current;
    struct History {
        uint64_t known_noncurrent_versions{}, known_noncurrent_bytes{}, delete_markers{};
        uint64_t unknown_size_versions{};
        // Versions that existed before Vaulthalla monitored the bucket and haven't been inventoried.
        bool unaccounted_history{true};
        std::optional<std::time_t> inventoried_at;
    } history;
    CostFigure pre_activation_monthly;           // incremental monthly cost if enabled now (steady state)
    CostFigure current_month_to_date;            // after activation: accrued this month
    CostFigure current_month_projected;          // after activation: this calendar month in total
    CostFigure projected_monthly;                // at the observed write rate, steady state under the chosen retention
    std::vector<AccumulationPoint> accumulation; // historical storage growth, 12 months
    std::vector<RetentionScenario> scenarios;    // 30d, 90d, 365d, indefinite
    CostFigure recovery_per_gb;                  // restore by transfer (GET + PUT + bytes) per GB
    CostFigure recovery_per_object;              // restore by provider copy, per object
    std::vector<std::string> unmodeled;          // account-level and other costs not in these figures
    std::vector<Assumption> assumptions;
    std::optional<std::string> retention;        // the retention the figures assume
    struct Alert {
        std::optional<Money> threshold;
        bool exceeded{false};
    } alert;
    std::time_t computed_at{};
};

// What a person must see and accept before provider versioning is enabled.
struct Disclosure {
    CostReport report;
    std::vector<std::string> consequences;       // irreversible enable, propagation delay, retention deletes, …
    std::vector<std::string> required_acknowledgements;   // NeedsConfirmation codes the enable will ask for
    std::string token;                           // pass to ops::recovery::update(disclosure_token)
    std::time_t expires_at{};
};

}
