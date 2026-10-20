// ws book: pricing.* — S3 price budgets (core/src/protocols/ws/handler/Pricing.cpp → ops::pricing for policies,
// ledger and status; storage::s3::pricing::PriceBudgetService for preflight, overrides and notifications).
// Shapes: core/src/storage/s3/pricing/PriceBudget.cpp (to_json), PriceBotModels.cpp (PriceEstimateReport).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

const std::vector<std::string>& pricingScopes() {
    static const std::vector<std::string> scopes{"global", "provider", "vault", "gateway_credential",
                                                 "gateway_credential_vault"};
    return scopes;
}

WsField pricingScope() {
    return str("scope").oneOf(pricingScopes()).desc(
        "Policy scope. gateway_credential / gateway_credential_vault are the S3 gateway's credential budgets "
        "(ops::s3_gateway rules).");
}

WsField pricingVaultFilter() { return uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"})); }

WsField pricingCredentialFilter() {
    return uinteger("gateway_credential_id").opt().nullable().gen(gen::ref("s3_gateway_credential", {"id"}));
}

WsField pricingLimit(const char* fallback) {
    return uinteger("limit").opt().desc(std::string("Rows to return, clamped to 1..500 (default ") + fallback + ").");
}

std::vector<std::string> pricingRefusals() { return {"denied", "invalid", "not_found", "conflict", "unauthorized"}; }

WsCommandUsage pricingCommand(std::string name, std::string description, std::vector<WsField> payload,
                              std::vector<WsField> response, std::vector<std::string> refusalCodes,
                              std::vector<std::string> untyped = {},
                              const std::chrono::milliseconds timeout = kDefaultTimeout) {
    return {.command = std::move(name),
            .description = std::move(description),
            .payload = std::move(payload),
            .response = std::move(response),
            .refusal_codes = std::move(refusalCodes),
            .untyped_refusals = std::move(untyped),
            .client_timeout = timeout};
}

}

std::vector<WsCommandUsage> pricingCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    // ---- policies (ops::pricing) ----
    out.push_back(pricingCommand("pricing.budget.policy.list",
        "S3 price budget policies the caller may see: super admins every one; others the policies of vaults they can "
        "view and of gateway credentials they own. vault_id needs view access to that vault.",
        {pricingVaultFilter(), pricingCredentialFilter(),
         boolean("include_inactive").opt().desc("Include disabled policies (default true).")},
        {objectArray("policies", "PriceBudgetPolicy")}, pricingRefusals()));

    out.push_back(pricingCommand("pricing.budget.policy.upsert",
        "Create or replace the policy of a scope. global/provider: super admins; vault: vault Edit on an S3 vault; "
        "gateway scopes: admin.s3_gateway.manage_budgets. Costs are decimal strings (up to 8 fractional digits).",
        {pricingScope(),
         str("provider_key").opt().nullable().desc("provider scope: aws-s3 or cloudflare-r2."),
         pricingVaultFilter().desc("vault and gateway_credential_vault scopes."),
         pricingCredentialFilter().desc("Gateway scopes."),
         str("mode").opt().nullable().oneOf({"off", "report", "warn", "enforce"}).desc(
             "Default report (gateway scopes: enforce)."),
         str("currency").opt().nullable().desc("3-8 alphanumeric characters; default USD."),
         str("max_run_cost").opt().nullable(),
         str("max_daily_cost").opt().nullable(),
         str("max_monthly_cost").opt().nullable(),
         boolean("require_verified_catalog").opt().desc("Default true."),
         boolean("allow_stale_catalog").opt().desc("Default false."),
         WsField{.name = "max_catalog_age_seconds", .types = {"integer", "null"}, .required = false,
                 .minimum = 1}.desc("Default 43200.")},
        {object("policy", "PriceBudgetPolicy")}, pricingRefusals(), {"invalid"}));

    out.push_back(pricingCommand("pricing.budget.policy.disable",
        "Disable the policy of a scope (same authority as upsert). disabled is false when there was nothing to "
        "disable.",
        {pricingScope(), str("provider_key").opt().nullable(), pricingVaultFilter(), pricingCredentialFilter()},
        {boolean("disabled")}, pricingRefusals(), {"invalid"}));

    out.push_back(pricingCommand("pricing.budget.ledger.list",
        "Reservation ledger rows, newest first. Non super admins must name a vault they can view or a gateway "
        "credential they own.",
        {pricingVaultFilter(), pricingCredentialFilter(), pricingLimit("50")},
        {objectArray("ledger", "PriceBudgetLedgerEntry")}, pricingRefusals()));

    out.push_back(pricingCommand("pricing.budget.status",
        "Policies, ledger, trends, open notifications and overrides for a vault, a credential, or (super admins) the "
        "whole system.",
        {pricingVaultFilter(), pricingCredentialFilter(), pricingLimit("20").desc("Ledger rows, 1..500 (default 20)."),
         boolean("include_inactive").opt().desc("Include disabled policies (default true).")},
        {objectArray("policies", "PriceBudgetPolicy"), objectArray("ledger", "PriceBudgetLedgerEntry"),
         objectArray("trends", "PriceBudgetTrendStats"), objectArray("notifications", "PriceBudgetNotification"),
         objectArray("overrides", "PriceBudgetOverride")},
        pricingRefusals()));

    // ---- preflight and overrides (PriceBudgetService) ----
    out.push_back(pricingCommand("pricing.budget.preflight",
        "Dry-run budget decision for the next sync of an S3 vault: plans the sync from the remote index (refused when "
        "it is missing or stale) and prices it. Needs view access to the vault's budgets.",
        {vaultId(), str("run_uuid").opt().desc("Default \"web-preflight\".")},
        {object("decision", "PriceBudgetDecision"), object("estimate", "PriceEstimateReport"),
         object("plan", "", {uinteger("upload"), uinteger("download"), uinteger("index_remote_only"),
                             uinteger("delete_remote"), uinteger("delete_local")})
             .desc("Planned action counts.")},
        {"denied", "unauthorized"}, {"invalid"}, 60s));

    out.push_back(pricingCommand("pricing.budget.override.request",
        "Ask for a one-time override of exceeded enforce policies on a vault (vault sync Trigger permission).",
        {vaultId(),
         WsField{.name = "policy_ids", .types = {"array"}, .items = "integer",
                 .generator = gen::ref("price_budget_policy", {"id"})}
             .desc("The policies to override; an empty list is refused."),
         str("run_uuid").opt().nullable(),
         str("reason").opt().nullable(),
         str("estimated_cost").opt().nullable().desc("Decimal string."),
         str("currency").opt().desc("Default USD."),
         uinteger("ttl_minutes").opt().desc("Default 30.")},
        {object("override", "PriceBudgetOverride")}, {"denied", "unauthorized"}, {"invalid"}));

    out.push_back(pricingCommand("pricing.budget.override.approve",
        "Approve a pending override (super admins). A bare `id` is refused: send override_id.",
        {uinteger("override_id").min(1).gen(gen::ref("price_budget_override", {"id"}))},
        {object("override", "PriceBudgetOverride")}, {"denied", "invalid", "unauthorized"}, {"conflict"}));

    out.push_back(pricingCommand("pricing.budget.override.deny",
        "Deny a pending override (super admins). A bare `id` is refused: send override_id.",
        {uinteger("override_id").min(1).gen(gen::ref("price_budget_override", {"id"})),
         str("reason").opt().nullable()},
        {object("override", "PriceBudgetOverride")}, {"denied", "invalid", "unauthorized"}, {"conflict"}));

    out.push_back(pricingCommand("pricing.budget.override.list",
        "Overrides, newest first. Super admins see all (or one vault's); others must name a vault they can view.",
        {pricingVaultFilter(), pricingLimit("50"), boolean("include_expired").opt().desc("Default false.")},
        {objectArray("overrides", "PriceBudgetOverride")}, {"denied", "unauthorized"}, {"invalid"}));

    // ---- operator notifications ----
    out.push_back(pricingCommand("pricing.notifications.list",
        "Cost alerts (operator notifications) the caller can see, newest first. summary always covers every OPEN "
        "alert in the same scope, whatever limit and include_acknowledged are.",
        {pricingVaultFilter(), pricingLimit("50"), boolean("include_acknowledged").opt().desc("Default false.")},
        {objectArray("notifications", "PriceBudgetNotification"), object("summary", "PriceBudgetNotificationSummary")},
        {"denied", "unauthorized"}));

    out.push_back(pricingCommand("pricing.notifications.ack",
        "Acknowledge a cost alert. Non super admins must send the alert's vault_id and be able to view it. A bare "
        "`id` is refused: send notification_id.",
        {uinteger("notification_id").min(1).gen(gen::ref("price_budget_notification", {"id"})),
         pricingVaultFilter()},
        {object("notification", "PriceBudgetNotification")}, {"denied", "invalid", "unauthorized"},
        {"invalid", "not_found"}));

    return out;
}

}
