// ws models: file recovery (recovery.* / vault.recovery.*). Serializers: core/src/ops/RecoveryJson.cpp (to_json for the
// vh::recovery model, core/include/recovery/Model.hpp, and ops::recovery::PointDetail). Times are ISO-8601 UTC strings
// ("2026-10-01T12:00:00Z", db::encoding::timestampToString), null when unknown or never set; money is RecoveryMoney
// (a decimal string amount, never a JSON number), null when it can't be estimated.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField recTime(std::string name) {
    return str(std::move(name)).nullable().desc("ISO-8601 UTC time (\"2026-10-01T12:00:00Z\"); null when unknown.");
}

WsField recMoney(std::string name) { return object(std::move(name), "RecoveryMoney").nullable(); }

WsField recFigure(std::string name) { return object(std::move(name), "RecoveryCostFigure"); }

}

std::vector<WsModel> recoveryModels() {
    std::vector<WsModel> out;

    out.push_back(model("RecoveryMoney", "An amount of money (to_json(recovery::Money)).",
        {str("amount").desc("Decimal string (\"12.50\"), never a JSON number."), str("currency").desc("ISO currency.")}));

    out.push_back(model("RecoveryEncryption", "How a recovery point's content is encrypted (to_json(EncryptionContext)).",
        {boolean("encrypted"), uinteger("key_version").desc("0 when not encrypted."),
         boolean("key_available").desc("The vault still holds this key version."), boolean("key_current")}));

    out.push_back(model("RecoveryRetention", "How long a recovery point is kept (to_json(recovery::Retention)).",
        {str("policy").desc("snapshot | keep_last:<n> | max_age_days:<n> | provider_days:<n> | indefinite | unknown."),
         recTime("expires_at"), str("note").nullable()}));

    out.push_back(model("RecoveryPoint",
        "One recovery point: a local snapshot, a retained local version or a provider object version "
        "(to_json(recovery::RecoveryPoint)).",
        {str("id").desc("snap-<id> (snapshot), lv-<id> (local generation) or pv-<id> (provider version)."),
         str("backend").oneOf({"local_snapshot", "local_version", "provider_version"}),
         uinteger("vault_id"),
         str("path").desc("Vault path when the point was taken."),
         uinteger("original_entry_id").nullable(),
         str("kind").oneOf({"file", "directory"}),
         str("name").nullable().desc("Snapshots."),
         recTime("created_at").desc("When the point came to exist; null when unknown."),
         recTime("valid_from").desc("The content was current from (local and provider versions)."),
         recTime("valid_until"),
         uinteger("size_bytes").nullable().desc("Plaintext size where known."),
         str("content_hash").nullable(),
         object("encryption", "RecoveryEncryption"),
         object("retention", "RecoveryRetention"),
         recMoney("estimated_monthly_cost"),
         boolean("is_current").desc("Provider: the latest version."),
         boolean("is_delete_marker"),
         str("origin").nullable().desc("Provider: vaulthalla | observed."),
         str("reason").nullable().desc("Local versions: overwrite | truncate | delete | download | restore | conflict."),
         str("upstream_state").nullable().desc("Local versions: none | pending | sent | skipped."),
         str("storage_class").nullable(),
         uinteger("file_count").nullable().desc("Snapshots and directory points."),
         boolean("restorable"),
         str("unavailable_reason").nullable()}));

    out.push_back(model("RecoveryPointDetail",
        "One recovery point with its details (to_json(ops::recovery::PointDetail)).",
        {object("point", "RecoveryPoint"),
         objectArray("members", "RecoveryPoint").desc("A snapshot's file generations (first page); otherwise empty."),
         boolean("members_truncated"),
         str("created_by").nullable(),
         strArray("skipped").desc("A snapshot's entries that were not captured, and why.")}));

    out.push_back(model("RecoveryPlanItem", "One item of a restore plan (to_json(recovery::PlanItem)).",
        {str("source_id").desc("lv-<id> / pv-<id>."), str("source_path"), str("destination_path"),
         str("action").oneOf({"create", "overwrite", "skip", "conflict", "remove", "unavailable"}),
         uinteger("size_bytes").nullable(),
         str("destination_source_id").nullable().desc("The destination generation the plan was made against."),
         str("method").desc("local_copy | local_reseal | provider_copy | provider_transfer | none."),
         strArray("notes")}));

    out.push_back(model("RecoveryRequestEstimate",
        "The provider requests and transfer a restore plan needs (to_json(recovery::RequestEstimate)).",
        {uinteger("get_requests"), uinteger("head_requests"), uinteger("put_requests"), uinteger("copy_requests"),
         uinteger("list_requests"), uinteger("download_bytes"), uinteger("upload_bytes"),
         recMoney("cost").desc("null when it can't be priced (see unpriced_reason)."),
         str("unpriced_reason").nullable()}));

    out.push_back(model("RecoveryPlan",
        "A restore plan: per-item preview, counts, estimate, warnings, blockers and the token recovery.restore takes "
        "(to_json(recovery::Plan)).",
        {uinteger("id"), uinteger("vault_id"),
         str("token").desc("Pass to recovery.restore; bound to the plan and the actor."),
         str("source_label").desc("What was chosen (\"snap-12\", \"/docs at 2026-10-01T12:00:00Z\")."),
         boolean("point_in_time"),
         recTime("at"),
         boolean("atomic").desc("true only for a local snapshot; a provider point-in-time plan is a reconstruction."),
         str("consistency_note"),
         str("destination").nullable().desc("Alternate destination root; null restores to the original paths."),
         boolean("prune"),
         objectArray("items", "RecoveryPlanItem"),
         uinteger("creates"), uinteger("overwrites"), uinteger("skips"), uinteger("conflicts"), uinteger("removals"),
         uinteger("unavailable"),
         object("estimate", "RecoveryRequestEstimate"),
         strArray("warnings"),
         strArray("blockers").desc("Non-empty: the restore is refused."),
         recTime("created_at"), recTime("expires_at"),
         str("state").desc("planned | running | done | partial | failed | expired.")}));

    out.push_back(model("RecoveryItemOutcome", "What happened to one restore item (to_json(recovery::ItemOutcome)).",
        {str("destination_path"),
         str("outcome").desc("restored | skipped | conflict | failed | removed | unavailable."),
         str("error").nullable()}));

    out.push_back(model("RecoveryRestoreResult", "The result of running a restore plan (to_json(RestoreResult)).",
        {uinteger("plan_id"), str("state").desc("done | partial | failed."),
         objectArray("items", "RecoveryItemOutcome"), uinteger("restored"), uinteger("skipped"),
         uinteger("conflicts"), uinteger("failed"), uinteger("removed"), uinteger("unavailable")}));

    out.push_back(model("RecoveryLocalVersioningPolicy",
        "A vault's local versioning policy (to_json(recovery::LocalVersioningPolicy)).",
        {boolean("enabled"), uinteger("keep_last").nullable().desc("Per file; null = no limit."),
         uinteger("max_age_days").nullable(), uinteger("quota_bytes").nullable()}));

    out.push_back(model("RecoveryProviderVersioningState",
        "The vault bucket's provider versioning state (to_json(recovery::ProviderVersioningState)).",
        {boolean("supported"), str("unsupported_reason"),
         str("provider").nullable(), str("bucket").nullable(), str("region").nullable(),
         str("storage_class").nullable(),
         str("bucket_state").desc("managed | adopted | unmanaged | protected | unknown."),
         str("status").desc("unversioned | enabled | suspended | unknown."),
         boolean("enabled_by_vaulthalla"),
         recTime("enabled_at"), recTime("settles_at"), recTime("checked_at"),
         boolean("settled").desc("Enabled and past the provider's propagation period."),
         boolean("object_lock").nullable(), boolean("mfa_delete").nullable(),
         str("retention_mode").desc("unset | days | indefinite (what Vaulthalla set)."),
         uinteger("retention_days").nullable(),
         strArray("foreign_noncurrent_rules").desc("Other applications' noncurrent-expiry rules (\"id: days\")."),
         uinteger("effective_noncurrent_days").nullable(),
         strArray("warnings")}));

    out.push_back(model("RecoveryBacklog",
        "Local versions waiting to reach the provider (to_json(recovery::Backlog)).",
        {uinteger("pending_versions"), uinteger("pending_bytes"), recTime("oldest_pending_at"),
         uinteger("failing").desc("Pending with at least one failed attempt."), str("last_error").nullable()}));

    out.push_back(model("RecoveryStoreUsage", "Local recovery store usage (to_json(recovery::StoreUsage)).",
        {uinteger("count"), uinteger("stored_bytes").desc("Physical (deduplicated) bytes on disk."),
         uinteger("plaintext_bytes")}));

    out.push_back(model("RecoveryStatus", "A vault's recovery settings and state (to_json(recovery::Status)).",
        {uinteger("vault_id"),
         str("mode").oneOf({"off", "local_snapshots", "provider_versioning"}),
         uinteger("snapshot_quota_bytes").nullable(),
         recMoney("cost_alert_monthly"),
         object("local_versioning", "RecoveryLocalVersioningPolicy"),
         object("provider", "RecoveryProviderVersioningState"),
         object("snapshots", "RecoveryStoreUsage"),
         object("versions", "RecoveryStoreUsage"),
         object("backlog", "RecoveryBacklog"),
         intArray("retained_key_versions").desc("Key versions recoverable data still needs."),
         strArray("warnings")}));

    out.push_back(model("RecoveryCostFigure",
        "A labelled amount with an uncertainty range (to_json(recovery::CostFigure)).",
        {recMoney("expected").desc("null: not estimable (see reason)."), recMoney("low"), recMoney("high"),
         str("basis").desc("observed | scenario | illustrative."), str("reason").nullable()}));

    out.push_back(model("RecoveryAccumulationPoint",
        "Noncurrent storage growth one month after activation (to_json(recovery::AccumulationPoint)).",
        {uinteger("month").desc("Months after activation (1..12)."), uinteger("noncurrent_bytes"),
         recFigure("monthly_cost")}));

    out.push_back(model("RecoveryRetentionScenario",
        "The steady-state cost under one retention (to_json(recovery::RetentionScenario)).",
        {str("retention").desc("\"30d\" | \"90d\" | \"365d\" | \"indefinite\"."), uinteger("steady_noncurrent_bytes"),
         recFigure("monthly_cost"), strArray("notes")}));

    out.push_back(model("RecoveryAssumption", "One assumption behind the cost figures (to_json(recovery::Assumption)).",
        {str("kind").desc("observed | illustrative | provider_rule."), str("text")}));

    out.push_back(model("RecoveryCostCatalog",
        "The price catalog the figures come from (to_json(CostReport::Catalog)).",
        {str("version").nullable(), str("source").nullable(), boolean("verified"), boolean("stale"),
         uinteger("age_seconds").nullable(), str("note").nullable()}));

    out.push_back(model("RecoveryCostObservation",
        "Measured usage the figures are based on (to_json(CostReport::Observation)).",
        {uinteger("window_days"), str("first_day").nullable(), str("last_day").nullable(),
         boolean("sufficient").desc("At least 7 measured days."),
         uinteger("put_requests"), uinteger("copy_requests"), uinteger("delete_requests"), uinteger("get_requests"),
         uinteger("list_requests"), uinteger("first_put_objects"), uinteger("overwrite_objects"),
         uinteger("deleted_objects"), uinteger("overwritten_bytes"), uinteger("deleted_bytes"),
         uinteger("uploaded_bytes"), str("overwritten_bytes_per_day").desc("Decimal string.")}));

    out.push_back(model("RecoveryCostCurrent", "The vault's current objects (to_json(CostReport::Current)).",
        {uinteger("objects"), uinteger("bytes"),
         recMoney("monthly_storage").desc("Context only: never part of the versioning surcharge.")}));

    out.push_back(model("RecoveryCostHistory", "Noncurrent history known in the bucket (to_json(CostReport::History)).",
        {uinteger("known_noncurrent_versions"), uinteger("known_noncurrent_bytes"), uinteger("delete_markers"),
         uinteger("unknown_size_versions"),
         boolean("unaccounted_history").desc("Versions from before monitoring that haven't been inventoried."),
         recTime("inventoried_at")}));

    out.push_back(model("RecoveryCostAlert", "The vault's monthly cost alert (to_json(CostReport::Alert)).",
        {recMoney("threshold"), boolean("exceeded")}));

    out.push_back(model("RecoveryCostReport",
        "A vault's recovery cost panel: versioning surcharge, recovery operations, ranges, basis and catalog "
        "freshness (to_json(recovery::CostReport)). Unknown money is null, never zero.",
        {uinteger("vault_id"),
         str("phase").desc("pre_activation | active."),
         boolean("priced"),
         str("unpriced_reason").nullable(),
         str("provider").nullable(), str("bucket").nullable(), str("region").nullable(),
         str("storage_class").nullable(), str("currency").nullable(),
         object("catalog", "RecoveryCostCatalog"),
         str("confidence").desc("high | medium | low | none."),
         strArray("confidence_reasons"),
         object("observation", "RecoveryCostObservation"),
         object("current", "RecoveryCostCurrent"),
         object("history", "RecoveryCostHistory"),
         recFigure("pre_activation_monthly"), recFigure("current_month_to_date"),
         recFigure("current_month_projected"), recFigure("projected_monthly"),
         objectArray("accumulation", "RecoveryAccumulationPoint"),
         objectArray("scenarios", "RecoveryRetentionScenario"),
         recFigure("recovery_per_gb"), recFigure("recovery_per_object"),
         strArray("unmodeled"),
         objectArray("assumptions", "RecoveryAssumption"),
         str("retention").nullable().desc("The retention the figures assume."),
         object("alert", "RecoveryCostAlert"),
         recTime("computed_at")}));

    out.push_back(model("RecoveryDisclosure",
        "What a person must see and accept before provider versioning is enabled (to_json(recovery::Disclosure)).",
        {object("report", "RecoveryCostReport"),
         strArray("consequences"),
         strArray("required_acknowledgements").desc("NeedsConfirmation codes the enable will ask for."),
         str("token").desc("vault.recovery.update's disclosure_token."),
         recTime("expires_at")}));

    return out;
}

}
