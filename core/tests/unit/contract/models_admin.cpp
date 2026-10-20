// Contract models: admin serializers against their declared shapes (see model_suites.hpp): the S3 price budget
// to_json functions, price estimates (with a real LocalEstimator breakdown), the settings document and the operator
// email delivery history.

#include "model_suites.hpp"

#include "config/Config.hpp"
#include "email/DeliveryHistory.hpp"
#include "protocols/ws/handler/Email.hpp"
#include "storage/s3/pricing/LocalEstimator.hpp"
#include "storage/s3/pricing/PriceBotModels.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <utility>
#include <vector>

namespace vh::test_contract_models_admin {

using json = nlohmann::json;
using test::contract_models::Checker;
namespace pricing = storage::s3::pricing;

// ---- price budgets ----------------------------------------------------------------------------------------------

pricing::PriceBudgetPolicy fullPolicy() {
    pricing::PriceBudgetPolicy p;
    p.id = 7;
    p.scope = pricing::PriceBudgetScope::GatewayCredentialVault;
    p.provider_key = "aws-s3";
    p.vault_id = 3;
    p.gateway_credential_id = 11;
    p.mode = pricing::PriceBudgetMode::Enforce;
    p.max_run_cost = "1.00000000";
    p.max_daily_cost = "2.50000000";
    p.max_monthly_cost = "40.00000000";
    p.max_catalog_age_seconds = 3600;
    return p;
}

pricing::PriceBudgetPolicy barePolicy() {
    pricing::PriceBudgetPolicy p;
    p.id = 1;
    p.scope = pricing::PriceBudgetScope::Global;
    p.max_catalog_age_seconds.reset();
    p.is_active = false;
    return p;
}

pricing::PriceBudgetWindowCheck windowCheck(const bool limited) {
    pricing::PriceBudgetWindowCheck c;
    c.policy_id = 7;
    c.scope = pricing::PriceBudgetScope::Vault;
    c.mode = pricing::PriceBudgetMode::Warn;
    c.window = pricing::PriceBudgetWindow::Monthly;
    if (limited) {
        c.limit = "40.00000000";
        c.exceeded = true;
    }
    return c;
}

pricing::PriceBudgetDecision blockedDecision() {
    pricing::PriceBudgetDecision d;
    d.allowed = false;
    d.warnings = {"monthly budget exceeded"};
    d.exceeded_policy_id = 7;
    d.exceeded_scope = "vault";
    d.limit = "40.00000000";
    d.used_before = "39.00000000";
    d.remaining_before = "1.00000000";
    d.requested = "2.00000000";
    d.currency = "USD";
    d.reason = "monthly limit";
    d.policies = {fullPolicy()};
    d.checks = {windowCheck(true), windowCheck(false)};
    d.blocking_checks = {windowCheck(true)};
    d.blocking_policy_ids = {7};
    d.primary_blocking_check = windowCheck(true);
    d.primary_blocking_scope = "vault";
    d.primary_blocking_window = "monthly";
    return d;
}

pricing::PriceBudgetLedgerEntry ledgerEntry(const bool full) {
    pricing::PriceBudgetLedgerEntry e;
    e.id = 5;
    e.policy_id = 7;
    e.run_uuid = "run-1";
    e.vault_id = 3;
    e.provider_key = "aws-s3";
    e.window = pricing::PriceBudgetWindow::Daily;
    e.window_start = "2026-10-20 00:00:00";
    e.window_end = "2026-10-21 00:00:00";
    e.reserved_cost = "0.10000000";
    e.status = "reserved";
    e.created_at = "2026-10-20 10:00:00";
    if (full) {
        e.gateway_credential_id = 11;
        e.request_uuid = "req-1";
        e.operation = "PutObject";
        e.object_key = "docs/a.txt";
        e.estimated_cost = "0.10000000";
        e.usage_source = "gateway";
        e.synthetic = true;
        e.committed_cost = "0.09000000";
        e.status = "committed";
    }
    return e;
}

pricing::PriceBudgetNotification notification(const bool full) {
    pricing::PriceBudgetNotification n;
    n.id = 9;
    n.type = "budget_exceeded";
    n.severity = "warning";
    n.title = "Budget exceeded";
    n.message = "The vault's monthly budget was exceeded.";
    n.created_at = "2026-10-20 10:00:00";
    if (full) {
        n.scope = "vault";
        n.vault_id = 3;
        n.provider_key = "aws-s3";
        n.policy_id = 7;
        n.run_uuid = "run-1";
        n.metadata = {{"limit", "40.00000000"}};
        n.acknowledged_at = "2026-10-20 11:00:00";
        n.acknowledged_by = 1;
        n.expires_at = "2026-10-27 10:00:00";
    }
    return n;
}

pricing::PriceBudgetOverride budgetOverride(const bool full) {
    pricing::PriceBudgetOverride o;
    o.id = 4;
    o.vault_id = 3;
    o.policy_ids = {7};
    o.expires_at = "2026-10-20 10:30:00";
    o.created_at = "2026-10-20 10:00:00";
    if (full) {
        o.run_uuid = "run-1";
        o.requested_by = 2;
        o.approved_by = 1;
        o.status = "approved";
        o.reason = "one large import";
        o.estimated_cost = "3.00000000";
        o.decided_at = "2026-10-20 10:05:00";
        o.used_at = "2026-10-20 10:10:00";
    }
    return o;
}

pricing::PriceBudgetTrendStats trend(const bool full) {
    pricing::PriceBudgetTrendStats t;
    t.scope = "vault";
    t.policy_id = 7;
    t.window_type = "monthly";
    t.window_start = "2026-10-01 00:00:00";
    t.window_end = "2026-11-01 00:00:00";
    t.percent_used = 42.5;
    if (full) {
        t.provider_key = "aws-s3";
        t.vault_id = 3;
        t.gateway_credential_id = 11;
        t.limit = "40.00000000";
        t.remaining = "23.00000000";
        t.projected_window_cost = "35.00000000";
        t.projected_overage = "0.00000000";
        t.predicted_exhaustion_at = "2026-10-29 00:00:00";
        t.warnings = {"projection is low confidence"};
    }
    return t;
}

void checkBudgets(Checker& c) {
    c.check(json(fullPolicy()), "PriceBudgetPolicy", "gateway credential vault policy, every limit set");
    c.check(json(barePolicy()), "PriceBudgetPolicy", "inactive global policy without limits");
    c.check(json(windowCheck(true)), "PriceBudgetWindowCheck", "exceeded limited window");
    c.check(json(windowCheck(false)), "PriceBudgetWindowCheck", "unlimited window");
    c.check(json(blockedDecision()), "PriceBudgetDecision", "blocked decision");
    c.check(json(pricing::PriceBudgetDecision{}), "PriceBudgetDecision", "default allowed decision");
    c.check(json(ledgerEntry(true)), "PriceBudgetLedgerEntry", "committed gateway ledger row");
    c.check(json(ledgerEntry(false)), "PriceBudgetLedgerEntry", "reserved sync ledger row");
    c.check(json(notification(true)), "PriceBudgetNotification", "acknowledged vault alert");
    c.check(json(notification(false)), "PriceBudgetNotification", "open alert without scope");
    c.check(json(pricing::PriceBudgetNotificationSummary{.open_count = 3, .worst_severity = "critical"}),
            "PriceBudgetNotificationSummary", "open alerts");
    c.check(json(pricing::PriceBudgetNotificationSummary{}), "PriceBudgetNotificationSummary", "nothing open");
    c.check(json(budgetOverride(true)), "PriceBudgetOverride", "approved and used override");
    c.check(json(budgetOverride(false)), "PriceBudgetOverride", "requested override");
    c.check(json(trend(true)), "PriceBudgetTrendStats", "limited monthly window with projection");
    c.check(json(trend(false)), "PriceBudgetTrendStats", "unlimited window");

    pricing::PriceBudgetDashboardStats dashboard;
    dashboard.active_policies = 2;
    dashboard.current_monthly_spend = "17.00000000";
    dashboard.projected_monthly_spend = "35.00000000";
    dashboard.trends = {trend(true)};
    dashboard.active_notifications = {notification(false)};
    dashboard.recent_overrides = {budgetOverride(false)};
    c.check(json(dashboard), "PriceBudgetDashboardStats", "dashboard with a monthly window");
    c.check(json(pricing::PriceBudgetDashboardStats{}), "PriceBudgetDashboardStats", "dashboard without monthly budget");
}

// ---- price estimates ----------------------------------------------------------------------------------------------

// A rating profile with no meters and a minimum monthly charge: LocalEstimator adds a real "minimum_monthly"
// breakdown line (makeBreakdown) and an unknown.
json minimumMonthlyProfile() {
    return {
        {"schema_version", "1.0"},
        {"kind", "vaulthalla.rating_profile"},
        {"profile_id", "aws-s3/us-east-1/standard"},
        {"catalog_version", "fixture-catalog"},
        {"provider", {{"id", "aws-s3"}, {"display_name", "aws-s3"}, {"api_family", "s3-compatible"}}},
        {"scope", {{"region", "us-east-1"}, {"storage_class", "standard"}, {"currency", "USD"}}},
        {"confidence", {{"level", "high"}, {"score", "0.90"}, {"reasons", json::array()}, {"unknowns", json::array()}}},
        {"operation_map", json::object()},
        {"meters", json::object()},
        {"storage_rules", json::array()},
        {"provenance", {{"minimum_monthly_usd", "1.00"}}},
        {"integrity", {{"content_sha256", ""}, {"signature_alg", "Ed25519"}, {"signature_ref", ""}}}
    };
}

void checkEstimates(Checker& c) {
    const pricing::PriceProfileTarget target{.provider = "aws-s3", .region = "us-east-1", .storage_class = "standard"};
    const auto profile = pricing::RatingProfile::parse(minimumMonthlyProfile());
    const auto estimate = pricing::LocalEstimator{}.estimate(profile, pricing::UsageInput{});

    // The fields reportFromEstimate (PriceEstimate.cpp) copies from a catalog estimate.
    pricing::PriceEstimateReport report;
    report.available = true;
    report.supported = true;
    report.target = target;
    report.estimated_cost = estimate.estimated_cost;
    report.currency = estimate.currency;
    report.price_profile_id = profile.profile_id;
    report.catalog_version = profile.catalog_version;
    report.catalog_source = "cache";
    report.catalog_verified = true;
    report.catalog_age_seconds = 120;
    report.confidence_level = profile.confidence_level;
    report.estimate_mode = estimate.estimate_mode;
    report.free_tier_policy = estimate.free_tier_policy;
    report.free_tiers_applied = estimate.free_tiers_applied;
    report.unknowns = estimate.unknowns;
    report.breakdown = estimate.breakdown;
    c.check(json(report), "PriceEstimateReport", "local catalog estimate with a minimum monthly line");
    c.check(json(pricing::PriceEstimateReport::unavailable(target, "catalog unreachable")), "PriceEstimateReport",
            "unavailable estimate");
    c.check(json(pricing::PriceEstimateReport::unsupported("pricing disabled")), "PriceEstimateReport",
            "unsupported provider");
}

// ---- settings -----------------------------------------------------------------------------------------------------

void checkSettings(Checker& c) {
    config::Config cfg;
    c.check(json(cfg), "Settings", "built-in defaults");

    // Every optional member set (placeholder values only; no secrets are part of the settings document).
    cfg.pricing.storage_rates_api.signature_public_key_path = "/etc/vaulthalla/pricing.pub";
    cfg.pricing.storage_rates_api.fallback_artifact_base_urls = {"https://rates.example.com"};
    cfg.email.provider = config::EmailProviderKind::Ses;
    cfg.email.reply_to = "Ops <ops@example.com>";
    cfg.email.base_url = "https://vault.example.com";
    cfg.email.ses.endpoint = "https://email.us-east-1.example.com";
    cfg.operator_emails.recipients.alerts = {"ops@example.com"};
    cfg.operator_emails.recipients.weekly = {"ops@example.com"};
    cfg.operator_emails.recipients.security = {"security@example.com"};
    c.check(json(cfg), "Settings", "every optional member set");
}

// ---- operator email -----------------------------------------------------------------------------------------------

void checkEmail(Checker& c) {
    email::DeliveryRecord sent;
    sent.id = 12;
    sent.eventKey = "health:critical";
    sent.eventType = "health";
    sent.severity = "critical";
    sent.provider = "ses";
    sent.subject = "Vaulthalla health is critical";
    sent.recipientGroup = "alerts";
    sent.recipientCount = 2;
    sent.providerMessageId = "msg-1";
    sent.status = "sent";
    sent.fingerprint = "health:critical:1";
    sent.firstSeenAt = 1'790'000'000;
    sent.lastSeenAt = 1'790'000'060;
    sent.sentAt = 1'790'000'061;
    sent.createdAt = 1'790'000'000;
    c.check(protocols::ws::handler::Email::deliveryRecordJson(sent), "EmailDeliveryRecord", "sent alert");

    email::DeliveryRecord failed = sent;
    failed.recipientGroup.reset();
    failed.providerMessageId.reset();
    failed.sentAt.reset();
    failed.status = "failed";
    failed.errorSummary = "provider ses failed (HTTP 500)";
    c.check(protocols::ws::handler::Email::deliveryRecordJson(failed), "EmailDeliveryRecord", "failed send");
}

}

namespace vh::test::contract_models {

void checkAdminModels(Checker& c) {
    test_contract_models_admin::checkBudgets(c);
    test_contract_models_admin::checkEstimates(c);
    test_contract_models_admin::checkSettings(c);
    test_contract_models_admin::checkEmail(c);
}

}
