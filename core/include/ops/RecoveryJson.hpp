#pragma once

#include "ops/Recovery.hpp"

#include <nlohmann/json_fwd.hpp>

// One JSON representation of file recovery, shared by the ws handlers, `vh snapshot|recovery … --json` and the stored
// restore plans. Field names are the struct member names; optionals are null; times are ISO-8601 UTC strings
// (db::encoding::timestampToString), a time that was never set (0) is null; Money is {amount, currency} with the amount
// a decimal string (never a JSON number); enums are their to_string() text.
namespace vh::recovery {

void to_json(nlohmann::json& j, Mode v);
void to_json(nlohmann::json& j, Backend v);
void to_json(nlohmann::json& j, PointKind v);
void to_json(nlohmann::json& j, ItemAction v);
void to_json(nlohmann::json& j, const RecoveryId& v);        // its str(): "snap-1" | "lv-2" | "pv-3"
void to_json(nlohmann::json& j, const Money& v);
void to_json(nlohmann::json& j, const EncryptionContext& v);
void to_json(nlohmann::json& j, const Retention& v);
void to_json(nlohmann::json& j, const RecoveryPoint& v);
void to_json(nlohmann::json& j, const PlanItem& v);
void to_json(nlohmann::json& j, const RequestEstimate& v);
void to_json(nlohmann::json& j, const Plan& v);
void to_json(nlohmann::json& j, const ItemOutcome& v);
void to_json(nlohmann::json& j, const RestoreResult& v);
void to_json(nlohmann::json& j, const ProviderRetention& v);  // {indefinite, days (null when indefinite), value: "30d"}
void to_json(nlohmann::json& j, const LocalVersioningPolicy& v);
void to_json(nlohmann::json& j, const ProviderVersioningState& v);
void to_json(nlohmann::json& j, const Backlog& v);
void to_json(nlohmann::json& j, const StoreUsage& v);
void to_json(nlohmann::json& j, const Status& v);
void to_json(nlohmann::json& j, const CostFigure& v);
void to_json(nlohmann::json& j, const AccumulationPoint& v);
void to_json(nlohmann::json& j, const RetentionScenario& v);
void to_json(nlohmann::json& j, const Assumption& v);
void to_json(nlohmann::json& j, const CostReport::Catalog& v);
void to_json(nlohmann::json& j, const CostReport::Observation& v);
void to_json(nlohmann::json& j, const CostReport::Current& v);
void to_json(nlohmann::json& j, const CostReport::History& v);
void to_json(nlohmann::json& j, const CostReport::Alert& v);
void to_json(nlohmann::json& j, const CostReport& v);
void to_json(nlohmann::json& j, const Disclosure& v);

// create | overwrite | skip | conflict | remove | unavailable; throws std::invalid_argument.
[[nodiscard]] ItemAction itemActionFromString(const std::string& s);

}

namespace vh::ops::recovery {

void to_json(nlohmann::json& j, const PointDetail& v);

// Readers for request objects (ws payloads; the CLI builds them from options). Unknown members are ignored; a member
// of the wrong type or out of range is ops::Invalid; null or absent keeps the default.
//   provider_retention: "30d" | "30" | "indefinite" | 30 | {indefinite, days}
//   cost_alert_monthly: a decimal string ("12.50", up to 12 integer and 8 fraction digits) or "" (clear); never a number
//   at: ISO-8601 UTC ("2026-10-01T12:00:00Z") or epoch seconds
[[nodiscard]] Update updateFromJson(const nlohmann::json& j);
[[nodiscard]] ListQuery listQueryFromJson(const nlohmann::json& j);
[[nodiscard]] SnapshotRequest snapshotRequestFromJson(const nlohmann::json& j);
[[nodiscard]] PlanRequest planRequestFromJson(const nlohmann::json& j);
[[nodiscard]] RestoreRequest restoreRequestFromJson(const nlohmann::json& j);
[[nodiscard]] LocalVersioningPolicy localVersioningPolicyFromJson(const nlohmann::json& j);
// Patch reader: an absent member is unchanged; null or 0 clears a limit.
[[nodiscard]] vh::recovery::LocalVersioningPatch localVersioningPatchFromJson(const nlohmann::json& j);
[[nodiscard]] ProviderRetention providerRetentionFromJson(const nlohmann::json& j);

// Stored plan items / results read back (recovery_plan.items, .result), as to_json wrote them.
[[nodiscard]] std::vector<vh::recovery::PlanItem> planItemsFromJson(const nlohmann::json& j);
[[nodiscard]] vh::recovery::RestoreResult restoreResultFromJson(const nlohmann::json& j);

}
