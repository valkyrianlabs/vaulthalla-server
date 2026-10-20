// Contract models: recovery serializers (core/src/ops/RecoveryJson.cpp) against their declared shapes (see
// model_suites.hpp). Every model is serialized fully populated (every optional set) and empty (optionals unset, times
// never set), so both the values and the nulls are checked.

#include "model_suites.hpp"

#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace vh::test_contract_models_recovery {

using json = nlohmann::json;
namespace rc = vh::recovery;

constexpr std::time_t kWhen = 1790000000;  // 2026-09-21

rc::Money money(const std::string& amount) { return {.amount = amount, .currency = "USD"}; }

rc::RecoveryPoint fullPoint() {
    return {.id = "pv-40",
            .backend = rc::Backend::ProviderVersion,
            .vault_id = 3,
            .path = "/docs/a.txt",
            .original_entry_id = 17,
            .kind = rc::PointKind::File,
            .name = "before cleanup",
            .created_at = kWhen,
            .valid_from = kWhen - 3600,
            .valid_until = kWhen,
            .size_bytes = 2048,
            .content_hash = "blake2b:00ff",
            .encryption = {.encrypted = true, .key_version = 2, .key_available = true, .key_current = false},
            .retention = {.policy = "provider_days:30", .expires_at = kWhen + 86400, .note = "bucket lifecycle"},
            .estimated_monthly_cost = money("0.0001"),
            .is_current = false,
            .is_delete_marker = false,
            .origin = "vaulthalla",
            .reason = "overwrite",
            .upstream_state = "sent",
            .storage_class = "STANDARD",
            .file_count = 1,
            .restorable = true,
            .unavailable_reason = "archived tier"};
}

rc::CostFigure fullFigure() {
    return {.expected = money("1.20"), .low = money("0.90"), .high = money("1.60"), .basis = "observed",
            .reason = "thin observation window"};
}

rc::CostReport fullReport() {
    rc::CostReport r;
    r.vault_id = 3;
    r.phase = "active";
    r.priced = true;
    r.unpriced_reason = "no catalog profile";
    r.provider = "aws";
    r.bucket = "vh-test";
    r.region = "us-east-2";
    r.storage_class = "STANDARD";
    r.currency = "USD";
    r.catalog = {.version = "2026-10-01", .source = "price-bot", .verified = true, .stale = false, .age_seconds = 600,
                 .note = "signed"};
    r.confidence = "medium";
    r.confidence_reasons = {"7 measured days"};
    r.observation.window_days = 7;
    r.observation.first_day = "2026-09-14";
    r.observation.last_day = "2026-09-20";
    r.observation.sufficient = true;
    r.observation.put_requests = 10;
    r.observation.overwritten_bytes_per_day = "1024.5";
    r.current = {.objects = 5, .bytes = 4096, .monthly_storage = money("0.01")};
    r.history = {.known_noncurrent_versions = 2, .known_noncurrent_bytes = 1024, .delete_markers = 1,
                 .unknown_size_versions = 0, .unaccounted_history = false, .inventoried_at = kWhen};
    r.pre_activation_monthly = fullFigure();
    r.current_month_to_date = fullFigure();
    r.current_month_projected = fullFigure();
    r.projected_monthly = fullFigure();
    r.accumulation = {{.month = 1, .noncurrent_bytes = 1024, .monthly_cost = fullFigure()}};
    r.scenarios = {{.retention = "30d", .steady_noncurrent_bytes = 2048, .monthly_cost = fullFigure(),
                    .notes = {"30-day minimum storage duration"}}};
    r.recovery_per_gb = fullFigure();
    r.recovery_per_object = fullFigure();
    r.unmodeled = {"account-level requests"};
    r.assumptions = {{.kind = "observed", .text = "write rate of the last 7 days"}};
    r.retention = "30d";
    r.alert = {.threshold = money("25.00"), .exceeded = true};
    r.computed_at = kWhen;
    return r;
}

rc::Status fullStatus() {
    rc::Status s;
    s.vault_id = 3;
    s.mode = rc::Mode::ProviderVersioning;
    s.snapshot_quota_bytes = 1 << 20;
    s.cost_alert_monthly = money("25.00");
    s.local_versioning = {.enabled = true, .keep_last = 5, .max_age_days = 30, .quota_bytes = 1 << 30};
    s.provider.supported = true;
    s.provider.unsupported_reason = "";
    s.provider.provider = "aws";
    s.provider.bucket = "vh-test";
    s.provider.region = "us-east-2";
    s.provider.storage_class = "STANDARD";
    s.provider.bucket_state = "managed";
    s.provider.status = "enabled";
    s.provider.enabled_by_vaulthalla = true;
    s.provider.enabled_at = kWhen;
    s.provider.settles_at = kWhen + 900;
    s.provider.checked_at = kWhen + 60;
    s.provider.settled = true;
    s.provider.object_lock = false;
    s.provider.mfa_delete = false;
    s.provider.retention_mode = "days";
    s.provider.retention_days = 30;
    s.provider.foreign_noncurrent_rules = {"expire-old: 90"};
    s.provider.effective_noncurrent_days = 30;
    s.provider.warnings = {"propagating"};
    s.snapshots = {.count = 2, .stored_bytes = 100, .plaintext_bytes = 90};
    s.versions = {.count = 3, .stored_bytes = 300, .plaintext_bytes = 280};
    s.backlog = {.pending_versions = 1, .pending_bytes = 64, .oldest_pending_at = kWhen, .failing = 1,
                 .last_error = "upstream unreachable"};
    s.retained_key_versions = {1, 2};
    s.warnings = {"key version 1 retired"};
    return s;
}

}

namespace vh::test::contract_models {

void checkRecoveryModels(Checker& c) {
    namespace t = vh::test_contract_models_recovery;
    namespace rc = vh::recovery;
    using json = nlohmann::json;

    // Points and their details.
    const auto point = t::fullPoint();
    c.check(json(point), "RecoveryPoint", "a provider version with every optional member set");
    c.check(json(rc::RecoveryPoint{}), "RecoveryPoint", "a point with nothing optional set");
    vh::ops::recovery::PointDetail detail{.point = point, .members = {point, rc::RecoveryPoint{}},
                                          .members_truncated = true, .created_by = "admin",
                                          .skipped = {"/docs/link: symlink"}};
    c.check(json(detail), "RecoveryPointDetail", "a snapshot detail with members");
    c.check(json(vh::ops::recovery::PointDetail{}), "RecoveryPointDetail", "a detail without members");

    // Restore plans and results.
    rc::Plan plan;
    plan.id = 9;
    plan.vault_id = 3;
    plan.token = "tok";
    plan.source_label = "/docs at 2026-09-21T00:00:00Z";
    plan.point_in_time = true;
    plan.at = t::kWhen;
    plan.consistency_note = "reconstructed per object";
    plan.destination = "/restored";
    plan.prune = true;
    plan.items = {{.source_id = "pv-40", .source_path = "/docs/a.txt", .destination_path = "/restored/docs/a.txt",
                   .action = rc::ItemAction::Overwrite, .size_bytes = 2048, .destination_source_id = "g-7",
                   .method = "provider_copy", .notes = {"overwrites the current file"}},
                  {.source_id = "lv-2", .source_path = {}, .destination_path = {}, .action = rc::ItemAction::Create,
                   .size_bytes = {}, .destination_source_id = {}, .method = "none", .notes = {}}};
    plan.creates = 1;
    plan.estimate = {.get_requests = 1, .copy_requests = 1, .download_bytes = 2048, .cost = t::money("0.0004"),
                     .unpriced_reason = "partially priced"};
    plan.warnings = {"provider point in time is not atomic"};
    plan.blockers = {"key version 1 missing"};
    plan.created_at = t::kWhen;
    plan.expires_at = t::kWhen + 1800;
    plan.state = "planned";
    c.check(json(plan), "RecoveryPlan", "a point-in-time plan to an alternate destination");
    c.check(json(rc::Plan{}), "RecoveryPlan", "an empty plan");

    rc::RestoreResult result{.plan_id = 9, .state = "partial",
                             .items = {{.destination_path = "/restored/docs/a.txt", .outcome = "failed",
                                        .error = "destination changed"},
                                       {.destination_path = "/restored/docs/b.txt", .outcome = "restored", .error = {}}},
                             .restored = 1, .failed = 1};
    c.check(json(result), "RecoveryRestoreResult", "a partial restore");

    // Vault status and policy.
    c.check(json(t::fullStatus()), "RecoveryStatus", "a provider-versioning vault with every optional set");
    c.check(json(rc::Status{}), "RecoveryStatus", "a vault with recovery off");

    // Costs and the disclosure.
    c.check(json(t::fullReport()), "RecoveryCostReport", "an active, priced cost report");
    c.check(json(rc::CostReport{}), "RecoveryCostReport", "an unpriced pre-activation report");
    rc::Disclosure disclosure{.report = t::fullReport(),
                              .consequences = {"versioning can be suspended, never turned off"},
                              .required_acknowledgements = {"recovery_versioning_disclosure"},
                              .token = "disclosure-token",
                              .expires_at = t::kWhen + 600};
    c.check(json(disclosure), "RecoveryDisclosure", "a disclosure");
    c.check(json(rc::Disclosure{}), "RecoveryDisclosure", "an empty disclosure");
}

}
