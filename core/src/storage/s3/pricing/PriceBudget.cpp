#include "storage/s3/pricing/PriceBudget.hpp"

#include "config/Registry.hpp"
#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "email/RenderedEmail.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "ops/Error.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <array>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <cctype>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace vh::storage::s3::pricing {
namespace {

using Decimal = boost::multiprecision::cpp_dec_float_50;

constexpr const char* kBudgetMode = "budget_conservative";
constexpr const char* kBudgetFreeTierPolicy = "ignore_account_wide_free_tiers";
constexpr const char* kLedgerReserved = "reserved";
constexpr const char* kLedgerCommitted = "committed";
constexpr const char* kStaleReservationAge = "24 hours";

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

std::string optionalSql(pqxx::work& txn, const std::optional<std::string>& value) {
    return value && !value->empty() ? txn.quote(*value) : std::string{"NULL"};
}

std::string optionalUintSql(const std::optional<std::uint32_t>& value) {
    return value ? std::to_string(*value) : std::string{"NULL"};
}

std::string optionalInt64Sql(const std::optional<std::int64_t>& value) {
    return value ? std::to_string(*value) : std::string{"NULL"};
}

std::string optionalNumericSql(pqxx::work& txn, const std::optional<std::string>& value) {
    return value && !value->empty() ? txn.quote(*value) + "::numeric" : std::string{"NULL"};
}

std::optional<std::string> optionalString(pqxx::row_ref row, const char* column) {
    const auto field = row[column];
    if (field.is_null()) return std::nullopt;
    return field.as<std::string>();
}

std::optional<std::uint32_t> optionalUInt(pqxx::row_ref row, const char* column) {
    const auto field = row[column];
    if (field.is_null()) return std::nullopt;
    return field.as<std::uint32_t>();
}

std::optional<std::int64_t> optionalInt64(pqxx::row_ref row, const char* column) {
    const auto field = row[column];
    if (field.is_null()) return std::nullopt;
    return field.as<std::int64_t>();
}

Decimal budgetDecimalFromString(const std::string& value) {
    return Decimal(value.empty() ? "0" : value);
}

std::string budgetFormatDecimal(const Decimal& value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(8) << (value == Decimal("0") ? Decimal("0") : value);
    auto text = out.str();
    if (text == "-0.00000000") return "0.00000000";
    return text;
}

PriceBudgetPolicy policyFromRow(pqxx::row_ref row) {
    PriceBudgetPolicy policy;
    policy.id = row["id"].as<std::uint32_t>();
    policy.scope = priceBudgetScopeFromString(row["scope"].as<std::string>());
    policy.provider_key = optionalString(row, "provider_key");
    policy.vault_id = optionalUInt(row, "vault_id");
    policy.gateway_credential_id = optionalUInt(row, "gateway_credential_id");
    policy.mode = priceBudgetModeFromString(row["mode"].as<std::string>());
    policy.currency = row["currency"].as<std::string>();
    policy.max_run_cost = optionalString(row, "max_run_cost");
    policy.max_daily_cost = optionalString(row, "max_daily_cost");
    policy.max_monthly_cost = optionalString(row, "max_monthly_cost");
    policy.require_verified_catalog = row["require_verified_catalog"].as<bool>();
    policy.allow_stale_catalog = row["allow_stale_catalog"].as<bool>();
    policy.max_catalog_age_seconds = optionalInt64(row, "max_catalog_age_seconds");
    policy.is_active = row["is_active"].as<bool>();
    return policy;
}

PriceBudgetLedgerEntry ledgerFromRow(pqxx::row_ref row) {
    PriceBudgetLedgerEntry entry;
    entry.id = row["id"].as<std::uint32_t>();
    entry.policy_id = row["policy_id"].as<std::uint32_t>();
    entry.run_uuid = row["run_uuid"].as<std::string>();
    entry.vault_id = row["vault_id"].as<std::uint32_t>();
    entry.gateway_credential_id = optionalUInt(row, "gateway_credential_id");
    entry.request_uuid = optionalString(row, "request_uuid");
    entry.operation = optionalString(row, "operation");
    entry.object_key = optionalString(row, "object_key");
    entry.estimated_cost = optionalString(row, "estimated_cost");
    entry.usage_source = optionalString(row, "usage_source");
    entry.synthetic = row["synthetic"].as<bool>();
    entry.provider_key = row["provider_key"].as<std::string>();
    entry.currency = row["currency"].as<std::string>();
    entry.window = priceBudgetWindowFromString(row["window_type"].as<std::string>());
    entry.window_start = row["window_start"].as<std::string>();
    entry.window_end = row["window_end"].as<std::string>();
    entry.reserved_cost = row["reserved_cost"].as<std::string>();
    entry.committed_cost = optionalString(row, "committed_cost");
    entry.status = row["status"].as<std::string>();
    entry.created_at = row["created_at"].as<std::string>();
    return entry;
}

nlohmann::json jsonFromField(pqxx::row_ref row, const char* column, nlohmann::json fallback) {
    const auto field = row[column];
    if (field.is_null()) return fallback;
    try {
        return nlohmann::json::parse(field.as<std::string>());
    } catch (...) {
        return fallback;
    }
}

std::vector<std::uint32_t> uintVectorFromJson(const nlohmann::json& payload) {
    std::vector<std::uint32_t> out;
    if (!payload.is_array()) return out;
    for (const auto& item : payload) {
        if (item.is_number_unsigned()) out.push_back(item.get<std::uint32_t>());
        else if (item.is_number_integer() && item.get<std::int64_t>() >= 0)
            out.push_back(static_cast<std::uint32_t>(item.get<std::int64_t>()));
    }
    return out;
}

std::string jsonSql(pqxx::work& txn, const nlohmann::json& value) {
    return txn.quote(value.dump()) + "::jsonb";
}

std::string optionalJsonSql(pqxx::work& txn, const nlohmann::json& value) {
    return value.is_null() ? std::string{"NULL"} : jsonSql(txn, value);
}

std::string uintVectorJsonSql(pqxx::work& txn, const std::vector<std::uint32_t>& values) {
    nlohmann::json payload = nlohmann::json::array();
    for (const auto value : values) payload.push_back(value);
    return jsonSql(txn, payload);
}

PriceBudgetNotification notificationFromRow(pqxx::row_ref row) {
    PriceBudgetNotification notification;
    notification.id = row["id"].as<std::uint32_t>();
    notification.type = row["type"].as<std::string>();
    notification.severity = row["severity"].as<std::string>();
    notification.title = row["title"].as<std::string>();
    notification.message = row["message"].as<std::string>();
    notification.scope = optionalString(row, "scope");
    notification.vault_id = optionalUInt(row, "vault_id");
    notification.provider_key = optionalString(row, "provider_key");
    notification.policy_id = optionalUInt(row, "policy_id");
    notification.run_uuid = optionalString(row, "run_uuid");
    notification.metadata = jsonFromField(row, "metadata", nlohmann::json::object());
    notification.acknowledged_at = optionalString(row, "acknowledged_at");
    notification.acknowledged_by = optionalUInt(row, "acknowledged_by");
    notification.created_at = row["created_at"].as<std::string>();
    notification.expires_at = optionalString(row, "expires_at");
    return notification;
}

PriceBudgetOverride overrideFromRow(pqxx::row_ref row) {
    PriceBudgetOverride overrideRequest;
    overrideRequest.id = row["id"].as<std::uint32_t>();
    overrideRequest.run_uuid = optionalString(row, "run_uuid");
    overrideRequest.vault_id = row["vault_id"].as<std::uint32_t>();
    overrideRequest.requested_by = optionalUInt(row, "requested_by");
    overrideRequest.approved_by = optionalUInt(row, "approved_by");
    overrideRequest.status = row["status"].as<std::string>();
    overrideRequest.reason = optionalString(row, "reason");
    overrideRequest.scope = row["scope"].as<std::string>();
    overrideRequest.policy_ids = uintVectorFromJson(jsonFromField(row, "policy_ids", nlohmann::json::array()));
    overrideRequest.estimated_cost = optionalString(row, "estimated_cost");
    overrideRequest.currency = row["currency"].as<std::string>();
    overrideRequest.expires_at = row["expires_at"].as<std::string>();
    overrideRequest.created_at = row["created_at"].as<std::string>();
    overrideRequest.decided_at = optionalString(row, "decided_at");
    overrideRequest.used_at = optionalString(row, "used_at");
    return overrideRequest;
}

std::optional<std::string> limitForWindow(const PriceBudgetPolicy& policy, const PriceBudgetWindow window) {
    switch (window) {
    case PriceBudgetWindow::PerRun:
        return policy.max_run_cost;
    case PriceBudgetWindow::Daily:
        return policy.max_daily_cost;
    case PriceBudgetWindow::Monthly:
        return policy.max_monthly_cost;
    }
    return std::nullopt;
}

std::vector<PriceBudgetWindow> configuredWindows(const PriceBudgetPolicy& policy) {
    std::vector<PriceBudgetWindow> windows;
    if (policy.max_run_cost) windows.push_back(PriceBudgetWindow::PerRun);
    if (policy.max_daily_cost) windows.push_back(PriceBudgetWindow::Daily);
    if (policy.max_monthly_cost) windows.push_back(PriceBudgetWindow::Monthly);
    if (windows.empty()) windows.push_back(PriceBudgetWindow::PerRun);
    return windows;
}

std::string windowStartExpr(const PriceBudgetWindow window) {
    switch (window) {
    case PriceBudgetWindow::PerRun:
        return "CURRENT_TIMESTAMP";
    case PriceBudgetWindow::Daily:
        return "date_trunc('day', CURRENT_TIMESTAMP)";
    case PriceBudgetWindow::Monthly:
        return "date_trunc('month', CURRENT_TIMESTAMP)";
    }
    return "CURRENT_TIMESTAMP";
}

std::string windowEndExpr(const PriceBudgetWindow window) {
    switch (window) {
    case PriceBudgetWindow::PerRun:
        return "CURRENT_TIMESTAMP + interval '1 second'";
    case PriceBudgetWindow::Daily:
        return "date_trunc('day', CURRENT_TIMESTAMP) + interval '1 day'";
    case PriceBudgetWindow::Monthly:
        return "date_trunc('month', CURRENT_TIMESTAMP) + interval '1 month'";
    }
    return "CURRENT_TIMESTAMP + interval '1 second'";
}

std::string activeLedgerCostSql() {
    return "COALESCE(committed_cost, reserved_cost)";
}

std::string usedForWindow(pqxx::work& txn, const PriceBudgetPolicy& policy, const PriceBudgetWindow window) {
    if (window == PriceBudgetWindow::PerRun) return "0.00000000";

    const auto sql =
        "SELECT COALESCE(SUM(" + activeLedgerCostSql() + "), 0)::numeric(20,8)::text AS used "
        "FROM s3_price_budget_ledger "
        "WHERE policy_id = " + std::to_string(policy.id) + " "
        "AND window_type = " + txn.quote(toString(window)) + " "
        "AND window_start = " + windowStartExpr(window) + " "
        "AND status IN (" + txn.quote(kLedgerReserved) + ", " + txn.quote(kLedgerCommitted) + ")";
    const auto result = txn.exec(sql);
    if (result.empty()) return "0.00000000";
    return result.one_row_ref()["used"].as<std::string>();
}

std::string policyWhereClause(
    pqxx::work& txn,
    const std::uint32_t vaultId,
    const std::string& providerKey,
    const bool providerSupported,
    const std::optional<std::uint32_t>& gatewayCredentialId,
    const bool includeInactive,
    const bool gatewayScopesOnly = false) {
    (void)providerSupported;
    std::string where = includeInactive ? "TRUE" : "is_active = TRUE AND mode <> 'off'";
    where += " AND (";
    bool appended = false;
    const auto appendClause = [&](const std::string& clause) {
        if (appended) where += " OR ";
        where += clause;
        appended = true;
    };
    if (!gatewayScopesOnly) {
        appendClause("scope = 'global'");
        appendClause("(scope = 'provider' AND provider_key = " + txn.quote(providerKey) + ")");
        appendClause("(scope = 'vault' AND vault_id = " + std::to_string(vaultId) +
            " AND (provider_key IS NULL OR provider_key = " + txn.quote(providerKey) + "))");
    }
    if (gatewayCredentialId) {
        appendClause("(scope = 'gateway_credential' AND gateway_credential_id = " +
            std::to_string(*gatewayCredentialId) +
            " AND (provider_key IS NULL OR provider_key = " + txn.quote(providerKey) + "))");
        appendClause("(scope = 'gateway_credential_vault' AND gateway_credential_id = " +
            std::to_string(*gatewayCredentialId) +
            " AND vault_id = " + std::to_string(vaultId) +
            " AND (provider_key IS NULL OR provider_key = " + txn.quote(providerKey) + "))");
    }
    if (!appended) where += "FALSE";
    where += ")";
    return where;
}

std::string policyIdentityWhere(
    pqxx::work& txn,
    const PriceBudgetScope scope,
    const std::optional<std::string>& providerKey,
    const std::optional<std::uint32_t>& vaultId,
    const std::optional<std::uint32_t>& gatewayCredentialId) {
    switch (scope) {
    case PriceBudgetScope::Global:
        return "scope = 'global'";
    case PriceBudgetScope::Provider:
        if (!providerKey) throw std::invalid_argument("provider budget requires provider key");
        return "scope = 'provider' AND provider_key = " + txn.quote(*providerKey);
    case PriceBudgetScope::Vault:
        if (!vaultId) throw std::invalid_argument("vault budget requires vault id");
        return "scope = 'vault' AND vault_id = " + std::to_string(*vaultId) +
            " AND " + (providerKey
                ? "provider_key = " + txn.quote(*providerKey)
                : std::string{"provider_key IS NULL"});
    case PriceBudgetScope::GatewayCredential:
        if (!gatewayCredentialId) throw std::invalid_argument("gateway credential budget requires gateway credential id");
        return "scope = 'gateway_credential' AND gateway_credential_id = " + std::to_string(*gatewayCredentialId) +
            " AND " + (providerKey
                ? "provider_key = " + txn.quote(*providerKey)
                : std::string{"provider_key IS NULL"});
    case PriceBudgetScope::GatewayCredentialVault:
        if (!gatewayCredentialId) throw std::invalid_argument("gateway credential vault budget requires gateway credential id");
        if (!vaultId) throw std::invalid_argument("gateway credential vault budget requires vault id");
        return "scope = 'gateway_credential_vault' AND gateway_credential_id = " + std::to_string(*gatewayCredentialId) +
            " AND vault_id = " + std::to_string(*vaultId) +
            " AND " + (providerKey
                ? "provider_key = " + txn.quote(*providerKey)
                : std::string{"provider_key IS NULL"});
    }
    return "FALSE";
}

std::string scopeLabel(const PriceBudgetPolicy& policy) {
    auto label = toString(policy.scope);
    if (policy.provider_key) label += ":" + *policy.provider_key;
    if (policy.gateway_credential_id) label += ":credential:" + std::to_string(*policy.gateway_credential_id);
    if (policy.vault_id) label += ":" + std::to_string(*policy.vault_id);
    return label;
}

void appendWarning(PriceBudgetDecision& decision, const PriceBudgetPolicy& policy, std::string warning) {
    decision.warnings.push_back("policy " + std::to_string(policy.id) + " (" + scopeLabel(policy) + "): " + std::move(warning));
}

void setBlocked(
    PriceBudgetDecision& decision,
    const PriceBudgetPolicy& policy,
    std::string reason,
    const std::optional<PriceBudgetWindowCheck>& check = std::nullopt) {
    if (decision.stalled) return;
    decision.allowed = false;
    decision.stalled = true;
    decision.exceeded_policy_id = policy.id;
    decision.exceeded_scope = scopeLabel(policy);
    decision.currency = policy.currency;
    decision.reason = std::move(reason);
    if (check) {
        decision.limit = check->limit.value_or("");
        decision.remaining_before = check->remaining_before;
        decision.requested = check->requested;
    }
}

void validatePolicyForWrite(const PriceBudgetPolicy& policy) {
    if (!isValidPriceBudgetCurrency(policy.currency))
        throw std::invalid_argument("invalid currency: " + policy.currency);

    for (const auto& value : {policy.max_run_cost, policy.max_daily_cost, policy.max_monthly_cost}) {
        if (value && !isValidPriceBudgetDecimal(*value))
            throw std::invalid_argument("invalid budget decimal: " + *value);
    }

    if (policy.scope == PriceBudgetScope::Global && (policy.provider_key || policy.vault_id || policy.gateway_credential_id))
        throw std::invalid_argument("global price budget cannot include provider_key, vault_id, or gateway_credential_id");
    if (policy.scope == PriceBudgetScope::Provider && (!policy.provider_key || policy.vault_id || policy.gateway_credential_id))
        throw std::invalid_argument("provider price budget requires provider_key and no vault_id or gateway_credential_id");
    if (policy.scope == PriceBudgetScope::Vault && (!policy.vault_id || policy.gateway_credential_id))
        throw std::invalid_argument("vault price budget requires vault_id");
    if (policy.scope == PriceBudgetScope::GatewayCredential &&
        (!policy.gateway_credential_id || policy.vault_id || !policy.max_monthly_cost))
        throw std::invalid_argument("gateway credential price budget requires gateway_credential_id, monthly cost, and no vault_id");
    if (policy.scope == PriceBudgetScope::GatewayCredentialVault &&
        (!policy.gateway_credential_id || !policy.vault_id || !policy.max_monthly_cost))
        throw std::invalid_argument("gateway credential vault price budget requires gateway_credential_id, vault_id, and monthly cost");
}

std::vector<std::uint32_t> reservationIds(const std::vector<PriceBudgetReservation>& reservations) {
    std::vector<std::uint32_t> ids;
    ids.reserve(reservations.size());
    for (const auto& reservation : reservations)
        if (reservation.id != 0) ids.push_back(reservation.id);
    return ids;
}

std::string idsSql(const std::vector<std::uint32_t>& ids) {
    std::ostringstream out;
    out << "(";
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i > 0) out << ",";
        out << ids[i];
    }
    out << ")";
    return out.str();
}

bool estimateCanBeReserved(const PriceEstimateReport& estimate) {
    return estimate.available &&
        estimate.estimate_mode == kBudgetMode &&
        estimate.free_tier_policy == kBudgetFreeTierPolicy &&
        !estimate.estimated_cost.empty() &&
        !estimate.currency.empty();
}

bool containsId(const std::vector<std::uint32_t>& values, const std::uint32_t id) {
    return std::ranges::find(values, id) != values.end();
}

bool isLimitExceededReason(const std::string& reason) {
    return reason.rfind("S3 price budget exceeded", 0) == 0;
}

bool isGatewayCredentialScope(const PriceBudgetScope scope) {
    return scope == PriceBudgetScope::GatewayCredential ||
        scope == PriceBudgetScope::GatewayCredentialVault;
}

int windowPriority(const PriceBudgetWindow window) {
    switch (window) {
    case PriceBudgetWindow::Monthly:
        return 0;
    case PriceBudgetWindow::Daily:
        return 1;
    case PriceBudgetWindow::PerRun:
        return 2;
    }
    return 3;
}

Decimal remainingForSort(const PriceBudgetWindowCheck& check) {
    if (check.remaining_before.empty()) return Decimal("0");
    return budgetDecimalFromString(check.remaining_before);
}

bool isGatewaySpecificScope(const PriceBudgetScope scope) {
    return scope == PriceBudgetScope::GatewayCredential ||
           scope == PriceBudgetScope::GatewayCredentialVault;
}

bool primaryBlockingLess(
    const PriceBudgetWindowCheck& a,
    const PriceBudgetWindowCheck& b,
    const bool preferGatewayCredentialVault) {
    const auto aWindow = windowPriority(a.window);
    const auto bWindow = windowPriority(b.window);
    if (aWindow != bWindow) return aWindow < bWindow;

    if (preferGatewayCredentialVault &&
        isGatewaySpecificScope(a.scope) &&
        isGatewaySpecificScope(b.scope) &&
        a.scope != b.scope) {
        return a.scope == PriceBudgetScope::GatewayCredentialVault;
    }

    const auto aRemaining = remainingForSort(a);
    const auto bRemaining = remainingForSort(b);
    if (aRemaining != bRemaining) return aRemaining < bRemaining;

    return a.policy_id < b.policy_id;
}

void finalizeBlockingDecision(PriceBudgetDecision& decision) {
    if (decision.blocking_checks.empty()) return;

    std::set<std::uint32_t> policyIds;
    bool hasGatewayCredential = false;
    bool hasGatewayCredentialVault = false;
    for (const auto& check : decision.blocking_checks) {
        policyIds.insert(check.policy_id);
        if (check.scope == PriceBudgetScope::GatewayCredential) hasGatewayCredential = true;
        if (check.scope == PriceBudgetScope::GatewayCredentialVault) hasGatewayCredentialVault = true;
    }
    decision.blocking_policy_ids = {policyIds.begin(), policyIds.end()};

    const bool preferGatewayCredentialVault = hasGatewayCredentialVault && !hasGatewayCredential;
    const auto primary = std::min_element(
        decision.blocking_checks.begin(),
        decision.blocking_checks.end(),
        [&](const auto& a, const auto& b) {
            return primaryBlockingLess(a, b, preferGatewayCredentialVault);
        });
    if (primary == decision.blocking_checks.end()) return;

    decision.primary_blocking_check = *primary;
    decision.primary_blocking_scope = toString(primary->scope);
    decision.primary_blocking_window = toString(primary->window);
    decision.allowed = false;
    decision.stalled = true;
    decision.exceeded_policy_id = primary->policy_id;
    decision.exceeded_scope = decision.primary_blocking_scope;
    decision.limit = primary->limit.value_or("");
    decision.used_before = primary->used_before;
    decision.remaining_before = primary->remaining_before;
    decision.requested = primary->requested;
    decision.currency = primary->currency;
    decision.reason = "S3 price budget exceeded for " + decision.primary_blocking_window +
        " " + decision.primary_blocking_scope +
        " policy " + std::to_string(primary->policy_id);
}

struct VaultBudgetContext {
    bool is_s3{false};
    std::string provider_key{"unknown"};
    bool provider_supported{false};
};

std::optional<VaultBudgetContext> vaultBudgetContext(pqxx::work& txn, const std::uint32_t vaultId) {
    const auto rows = txn.exec(
        "SELECT v.type, ak.provider "
        "FROM vault v "
        "LEFT JOIN s3 ON s3.vault_id = v.id "
        "LEFT JOIN api_keys ak ON ak.id = s3.api_key_id "
        "WHERE v.id = " + std::to_string(vaultId) + " LIMIT 1");
    if (rows.empty()) return std::nullopt;

    VaultBudgetContext context;
    if (rows.one_row_ref()["type"].as<std::string>() != "s3") return context;

    context.is_s3 = true;
    try {
        const auto providerText = optionalString(rows.one_row_ref(), "provider").value_or("Other");
        const auto profile = provider::resolve(vault::model::s3_provider_from_string(providerText));
        const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
        context.provider_key = costProfileId ? *costProfileId : (profile ? profile->id() : std::string{"unknown"});
        context.provider_supported = costProfileId && isSupportedPriceBudgetProvider(*costProfileId);
    } catch (...) {
        context.provider_key = "generic-s3-compatible";
        context.provider_supported = false;
    }
    return context;
}

std::string statsPolicyWhereClause(
    pqxx::work& txn,
    const std::optional<std::uint32_t>& vaultId,
    const std::optional<std::uint32_t>& gatewayCredentialId) {
    if (!vaultId) {
        auto where = std::string{"is_active = TRUE AND mode <> 'off'"};
        if (gatewayCredentialId) {
            where += " AND ("
                "scope = 'gateway_credential' OR "
                "scope = 'gateway_credential_vault') "
                "AND gateway_credential_id = " + std::to_string(*gatewayCredentialId);
        }
        return where;
    }

    const auto context = vaultBudgetContext(txn, *vaultId);
    if (!context || !context->is_s3) return "FALSE";

    auto where = policyWhereClause(
        txn,
        *vaultId,
        context->provider_key,
        context->provider_supported,
        gatewayCredentialId,
        false);
    if (!gatewayCredentialId) {
        where = "(" + where + ") OR (is_active = TRUE AND mode <> 'off' "
            "AND scope = 'gateway_credential_vault' "
            "AND vault_id = " + std::to_string(*vaultId) + " "
            "AND (provider_key IS NULL OR provider_key = " + txn.quote(context->provider_key) + "))";
    }
    return where;
}

std::string scopedLedgerFilter(
    const std::optional<std::uint32_t>& vaultId,
    const std::optional<std::uint32_t>& gatewayCredentialId) {
    std::string filter;
    if (vaultId) filter += "AND vault_id = " + std::to_string(*vaultId) + " ";
    if (gatewayCredentialId) filter += "AND gateway_credential_id = " + std::to_string(*gatewayCredentialId) + " ";
    return filter;
}

std::string notificationTypeForPricingEvaluationIssue(const std::string& reason) {
    const auto lowered = lower(reason);
    if (lowered.find("provider is unsupported") != std::string::npos ||
        lowered.find("provider has no price") != std::string::npos)
        return "pricing.provider_unsupported";
    if (lowered.find("verified pricing catalog") != std::string::npos)
        return "pricing.catalog_unverified";
    if (lowered.find("catalog is stale") != std::string::npos ||
        lowered.find("stale pricing catalog") != std::string::npos)
        return "pricing.catalog_stale";
    return "pricing.catalog_unverified";
}

std::string notificationTitleForType(const std::string& type) {
    if (type == "budget.sync_blocked") return "S3 price budget blocked sync";
    if (type == "budget.warn_threshold") return "S3 price budget warning";
    if (type == "budget.override_requested") return "S3 price budget override requested";
    if (type == "budget.override_approved") return "S3 price budget override approved";
    if (type == "budget.override_denied") return "S3 price budget override denied";
    if (type == "budget.override_used") return "S3 price budget override used";
    if (type == "budget.policy_changed") return "S3 price budget policy changed";
    if (type == "budget.predicted_overage") return "S3 price budget projected overage";
    if (type == "pricing.catalog_stale") return "S3 pricing catalog is stale";
    if (type == "pricing.catalog_unverified") return "S3 pricing catalog is unverified";
    if (type == "pricing.provider_unsupported") return "S3 pricing provider is unsupported";
    return "S3 pricing budget event";
}

bool shouldEmailBudgetNotification(const PriceBudgetNotification& notification) {
    if (notification.type == "budget.override_requested") return true;
    if (notification.type == "budget.sync_blocked" && notification.severity == "critical") return true;
    if (notification.type == "budget.predicted_overage" && notification.severity == "critical") return true;
    return false;
}

std::string notificationFingerprint(const PriceBudgetNotification& notification) {
    std::ostringstream out;
    out << notification.type
        << "|vault:" << (notification.vault_id ? std::to_string(*notification.vault_id) : std::string{"all"})
        << "|policy:" << (notification.policy_id ? std::to_string(*notification.policy_id) : std::string{"none"});
    if (notification.run_uuid) out << "|run:" << *notification.run_uuid;
    if (notification.metadata.is_object() && notification.metadata.contains("alert_key"))
        out << "|alert:" << notification.metadata.value("alert_key", "");
    return out.str();
}

email::RenderedEmail renderBudgetNotificationEmail(const PriceBudgetNotification& notification) {
    std::ostringstream html;
    html << "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;color:#172033;"
         << "font-family:Inter,Segoe UI,Arial,sans-serif;\">"
         << "<div style=\"max-width:680px;margin:0 auto;padding:32px 20px;\">"
         << "<div style=\"background:#ffffff;border:1px solid #d9e1ec;border-radius:8px;overflow:hidden;\">"
         << "<div style=\"background:#172033;color:#ffffff;padding:20px 24px;\">"
         << "<div style=\"font-size:13px;text-transform:uppercase;color:#a7b5c8;\">Vaulthalla cost control</div>"
         << "<h1 style=\"margin:8px 0 0;font-size:24px;line-height:1.25;\">" << notification.title << "</h1>"
         << "</div><div style=\"padding:24px;\">"
         << "<p style=\"margin:0 0 18px;font-size:15px;line-height:1.6;\">" << notification.message << "</p>"
         << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px;\">"
         << "<tr><td style=\"padding:8px 0;color:#5a6778;width:140px;\">Severity</td><td style=\"font-weight:600;\">" << notification.severity << "</td></tr>"
         << "<tr><td style=\"padding:8px 0;color:#5a6778;\">Type</td><td style=\"font-weight:600;\">" << notification.type << "</td></tr>";
    if (notification.vault_id)
        html << "<tr><td style=\"padding:8px 0;color:#5a6778;\">Vault</td><td style=\"font-weight:600;\">" << *notification.vault_id << "</td></tr>";
    if (notification.policy_id)
        html << "<tr><td style=\"padding:8px 0;color:#5a6778;\">Policy</td><td style=\"font-weight:600;\">" << *notification.policy_id << "</td></tr>";
    if (notification.run_uuid)
        html << "<tr><td style=\"padding:8px 0;color:#5a6778;\">Run</td><td style=\"font-weight:600;\">" << *notification.run_uuid << "</td></tr>";
    html << "</table></div></div></div></body></html>";

    std::ostringstream text;
    text << "[Vaulthalla] " << notification.title << "\n\n"
         << notification.message << "\n\n"
         << "Severity: " << notification.severity << "\n"
         << "Type: " << notification.type << "\n";
    if (notification.vault_id) text << "Vault: " << *notification.vault_id << "\n";
    if (notification.policy_id) text << "Policy: " << *notification.policy_id << "\n";
    if (notification.run_uuid) text << "Run: " << *notification.run_uuid << "\n";

    return {
        .subject = "[Vaulthalla] " + notification.title,
        .html = html.str(),
        .text = text.str()
    };
}

void enqueueBudgetNotificationEmail(const PriceBudgetNotification& notification) {
    if (!shouldEmailBudgetNotification(notification)) return;
    (void)notifications::OperatorNotificationBus::instance().enqueue({
        .eventKey = notification.type,
        .eventType = "cost_control",
        .severity = notification.severity,
        .recipientGroup = "alerts",
        .explicitRecipients = {},
        .fingerprint = notificationFingerprint(notification),
        .rendered = renderBudgetNotificationEmail(notification),
        .tags = {{"event_type", "cost_control"}, {"severity", notification.severity}}
    });
}

nlohmann::json preflightMetadata(const PriceBudgetPreflightRequest& request, const PriceBudgetDecision& decision) {
    nlohmann::json metadata = {
        {"provider_key", request.provider_key},
        {"provider_supported", request.provider_supported},
        {"gateway_credential_id", request.gateway_credential_id ? nlohmann::json(*request.gateway_credential_id) : nlohmann::json(nullptr)},
        {"request_uuid", request.request_uuid},
        {"operation", request.operation},
        {"object_key", request.object_key ? nlohmann::json(*request.object_key) : nlohmann::json(nullptr)},
        {"gateway_scopes_only", request.gateway_scopes_only},
        {"synthetic", request.synthetic},
        {"usage_source", request.usage_source ? nlohmann::json(*request.usage_source) : nlohmann::json(nullptr)},
        {"estimated_cost", request.estimate.estimated_cost},
        {"currency", request.estimate.currency},
        {"catalog_verified", request.estimate.catalog_verified},
        {"catalog_stale", request.estimate.stale},
        {"catalog_age_seconds", request.estimate.catalog_age_seconds ? nlohmann::json(*request.estimate.catalog_age_seconds) : nlohmann::json(nullptr)},
        {"confidence", request.estimate.confidence_level},
        {"reason", decision.reason}
    };
    metadata["checks"] = decision.checks;
    metadata["blocking_checks"] = decision.blocking_checks;
    metadata["blocking_policy_ids"] = decision.blocking_policy_ids;
    metadata["primary_blocking_scope"] = decision.primary_blocking_scope;
    metadata["primary_blocking_window"] = decision.primary_blocking_window;
    metadata["primary_blocking_check"] = decision.primary_blocking_check
        ? nlohmann::json(*decision.primary_blocking_check)
        : nlohmann::json(nullptr);
    return metadata;
}

PriceBudgetNotification makeDecisionNotification(
    const PriceBudgetPreflightRequest& request,
    const PriceBudgetDecision& decision,
    std::string type,
    std::string severity,
    std::string message,
    std::optional<std::uint32_t> policyId = std::nullopt) {
    PriceBudgetNotification notification;
    notification.type = std::move(type);
    notification.severity = std::move(severity);
    notification.title = notificationTitleForType(notification.type);
    notification.message = std::move(message);
    notification.scope = decision.exceeded_scope.empty() ? std::optional<std::string>{} : std::make_optional(decision.exceeded_scope);
    notification.vault_id = request.vault_id;
    notification.provider_key = request.provider_key;
    notification.policy_id = policyId ? policyId : decision.exceeded_policy_id;
    notification.run_uuid = request.run_uuid.empty() ? std::optional<std::string>{} : std::make_optional(request.run_uuid);
    notification.metadata = preflightMetadata(request, decision);
    return notification;
}

// operator_notification.severity values (094 CHECK) by rank; the SQL summary and the C++ merge both rank from here.
constexpr std::array<std::pair<std::string_view, int>, 4> kNotificationSeverityRanks{{
    {"info", 1},
    {"warning", 2},
    {"error", 3},
    {"critical", 4},
}};

std::string notificationSeverityRankSql() {
    std::string sql = "CASE severity";
    for (const auto& [name, rank] : kNotificationSeverityRanks)
        sql += " WHEN '" + std::string(name) + "' THEN " + std::to_string(rank);
    return sql + " ELSE 0 END";
}

} // namespace

std::string toString(const PriceBudgetMode mode) {
    switch (mode) {
    case PriceBudgetMode::Off:
        return "off";
    case PriceBudgetMode::Report:
        return "report";
    case PriceBudgetMode::Warn:
        return "warn";
    case PriceBudgetMode::Enforce:
        return "enforce";
    }
    return "off";
}

std::string toString(const PriceBudgetScope scope) {
    switch (scope) {
    case PriceBudgetScope::Global:
        return "global";
    case PriceBudgetScope::Provider:
        return "provider";
    case PriceBudgetScope::Vault:
        return "vault";
    case PriceBudgetScope::GatewayCredential:
        return "gateway_credential";
    case PriceBudgetScope::GatewayCredentialVault:
        return "gateway_credential_vault";
    }
    return "vault";
}

std::string toString(const PriceBudgetWindow window) {
    switch (window) {
    case PriceBudgetWindow::PerRun:
        return "per_run";
    case PriceBudgetWindow::Daily:
        return "daily";
    case PriceBudgetWindow::Monthly:
        return "monthly";
    }
    return "per_run";
}

PriceBudgetMode priceBudgetModeFromString(const std::string_view value) {
    const auto normalized = lower(std::string(value));
    if (normalized == "off") return PriceBudgetMode::Off;
    if (normalized == "report") return PriceBudgetMode::Report;
    if (normalized == "warn" || normalized == "warning") return PriceBudgetMode::Warn;
    if (normalized == "enforce" || normalized == "enforced") return PriceBudgetMode::Enforce;
    throw std::invalid_argument("unknown price budget mode: " + normalized);
}

PriceBudgetScope priceBudgetScopeFromString(const std::string_view value) {
    const auto normalized = lower(std::string(value));
    if (normalized == "global") return PriceBudgetScope::Global;
    if (normalized == "provider") return PriceBudgetScope::Provider;
    if (normalized == "vault") return PriceBudgetScope::Vault;
    if (normalized == "gateway_credential" || normalized == "gateway-credential")
        return PriceBudgetScope::GatewayCredential;
    if (normalized == "gateway_credential_vault" || normalized == "gateway-credential-vault")
        return PriceBudgetScope::GatewayCredentialVault;
    throw std::invalid_argument("unknown price budget scope: " + normalized);
}

PriceBudgetWindow priceBudgetWindowFromString(const std::string_view value) {
    const auto normalized = lower(std::string(value));
    if (normalized == "per_run" || normalized == "run") return PriceBudgetWindow::PerRun;
    if (normalized == "daily" || normalized == "day") return PriceBudgetWindow::Daily;
    if (normalized == "monthly" || normalized == "month") return PriceBudgetWindow::Monthly;
    throw std::invalid_argument("unknown price budget window: " + normalized);
}

int priceBudgetNotificationSeverityRank(const std::string_view severity) {
    for (const auto& [name, rank] : kNotificationSeverityRanks)
        if (name == severity) return rank;
    return 0;
}

void mergePriceBudgetNotificationSummary(PriceBudgetNotificationSummary& into, const PriceBudgetNotificationSummary& add) {
    into.open_count += add.open_count;
    if (!add.worst_severity) return;
    if (!into.worst_severity
        || priceBudgetNotificationSeverityRank(*add.worst_severity) > priceBudgetNotificationSeverityRank(*into.worst_severity))
        into.worst_severity = add.worst_severity;
}

bool isSupportedPriceBudgetProvider(const std::string_view providerKey) {
    static const std::unordered_set<std::string> supported{"aws-s3", "cloudflare-r2"};
    return supported.contains(std::string(providerKey));
}

bool isValidPriceBudgetDecimal(const std::string_view value) {
    const auto text = trim(std::string(value));
    if (text.empty() || text.front() == '-') return false;

    bool dot = false;
    bool digit = false;
    std::size_t fractional = 0;
    for (const char ch : text) {
        if (ch >= '0' && ch <= '9') {
            digit = true;
            if (dot) ++fractional;
            continue;
        }
        if (ch == '.' && !dot) {
            dot = true;
            continue;
        }
        return false;
    }

    if (!digit || fractional > 8) return false;
    try {
        return budgetDecimalFromString(text) >= Decimal("0");
    } catch (...) {
        return false;
    }
}

bool isValidPriceBudgetCurrency(const std::string_view value) {
    if (value.size() < 3 || value.size() > 8) return false;
    return std::ranges::all_of(value, [](const unsigned char c) {
        return std::isalnum(c) != 0;
    });
}

std::string normalizePriceBudgetCurrency(std::string value) {
    value = trim(std::move(value));
    std::ranges::transform(value, value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return value;
}

std::string formatPriceBudgetDecisionForDryRun(const PriceBudgetDecision& decision) {
    std::ostringstream out;
    out << "  Price budget decision:\n"
        << "    Applicable policies: " << decision.policies.size() << "\n"
        << "    Result: " << (decision.allowed ? (decision.warnings.empty() ? "pass" : "warn") : "fail") << "\n";

    if (!decision.reason.empty())
        out << "    Reason: " << decision.reason << "\n";
    if (!decision.warnings.empty()) {
        out << "    Warnings:\n";
        for (const auto& warning : decision.warnings) out << "      - " << warning << "\n";
    }
    if (!decision.checks.empty()) {
        out << "    Budget windows:\n";
        for (const auto& check : decision.checks) {
            out << "      - policy " << check.policy_id
                << " " << toString(check.scope)
                << " " << toString(check.window)
                << ": requested " << check.requested << " " << check.currency;
            if (check.limit) {
                out << ", remaining before " << check.remaining_before
                    << ", limit " << *check.limit
                    << (check.exceeded ? " (exceeded)" : "");
            } else {
                out << ", no limit";
            }
            out << "\n";
        }
    }
    out << "    Enforcement would stall: " << (decision.stalled ? "yes" : "no");
    return out.str();
}

std::string formatGatewayBudgetDenialForS3(
    const PriceBudgetDecision& decision,
    const PriceBudgetPreflightRequest& request) {
    const auto check = decision.primary_blocking_check;
    const auto scope = !decision.primary_blocking_scope.empty()
        ? decision.primary_blocking_scope
        : (!decision.exceeded_scope.empty() ? decision.exceeded_scope : std::string{"unknown"});
    const auto policyId = check
        ? check->policy_id
        : decision.exceeded_policy_id.value_or(0);
    const auto window = check
        ? toString(check->window)
        : (!decision.primary_blocking_window.empty() ? decision.primary_blocking_window : std::string{"unknown"});
    const auto limit = check
        ? check->limit.value_or("")
        : decision.limit;
    const auto usedBefore = check
        ? check->used_before
        : decision.used_before;
    const auto remaining = check
        ? check->remaining_before
        : decision.remaining_before;
    const auto requested = check
        ? check->requested
        : decision.requested;
    const auto currency = check
        ? check->currency
        : decision.currency;

    std::ostringstream out;
    out << (request.synthetic
            ? "S3 gateway synthetic local budget exceeded: "
            : "S3 gateway price budget exceeded: ")
        << "scope=" << scope
        << ", policy_id=" << policyId
        << ", window=" << window
        << ", limit=" << limit
        << ", used_before=" << usedBefore
        << ", remaining=" << remaining
        << ", requested=" << requested
        << ", currency=" << currency
        << ", provider_key=" << request.provider_key
        << ", vault_id=" << request.vault_id
        << ", gateway_credential_id=" << (request.gateway_credential_id ? std::to_string(*request.gateway_credential_id) : std::string{"none"})
        << ", operation=" << request.operation
        << ", request_uuid=" << request.request_uuid;
    return out.str();
}

PriceBudgetDecision PriceBudgetService::preflight(const PriceBudgetPreflightRequest& request) const {
    return db::Transactions::exec("PriceBudgetService::preflight", [&](pqxx::work& txn) {
        PriceBudgetDecision decision;

        txn.exec(
            "UPDATE s3_price_budget_ledger "
            "SET status = 'expired', updated_at = CURRENT_TIMESTAMP "
            "WHERE status = 'reserved' "
            "AND created_at < CURRENT_TIMESTAMP - interval '" + std::string(kStaleReservationAge) + "'");

        const auto policySql =
            "SELECT * FROM s3_price_budget_policy WHERE " +
            policyWhereClause(
                txn,
                request.vault_id,
                request.provider_key,
                request.provider_supported,
                request.gateway_credential_id,
                false,
                request.gateway_scopes_only) +
            " ORDER BY id FOR UPDATE";
        const auto policies = txn.exec(policySql);
        for (const auto& row : policies) decision.policies.push_back(policyFromRow(row));
        if (decision.policies.empty()) return decision;

        const bool canReserve = estimateCanBeReserved(request.estimate);
        std::set<std::uint32_t> reservablePolicyIds;
        for (const auto& policy : decision.policies) {
            const auto mode = policy.mode;
            if (mode == PriceBudgetMode::Off) continue;

            auto policyIssue = std::optional<std::string>{};
            if (!request.provider_supported && policy.scope != PriceBudgetScope::Global &&
                !(request.synthetic && isGatewayCredentialScope(policy.scope)))
                policyIssue = "price budget cannot be evaluated: provider is unsupported for local S3 pricing";
            else if (!request.estimate.supported)
                policyIssue = "price budget cannot be evaluated: " + request.estimate.unavailable_reason;
            else if (!request.estimate.available)
                policyIssue = "price budget cannot be evaluated: " + request.estimate.unavailable_reason;
            else if (request.estimate.estimate_mode != kBudgetMode ||
                     request.estimate.free_tier_policy != kBudgetFreeTierPolicy)
                policyIssue = "price budget cannot be evaluated from a non-budget-conservative estimate";
            else if (policy.require_verified_catalog && !request.estimate.catalog_verified)
                policyIssue = "price budget cannot be evaluated: verified pricing catalog is required";
            else if (request.estimate.stale && !policy.allow_stale_catalog)
                policyIssue = "price budget cannot be evaluated: pricing catalog is stale";
            else if (request.estimate.stale && policy.allow_stale_catalog &&
                     policy.max_catalog_age_seconds && request.estimate.catalog_age_seconds &&
                     *request.estimate.catalog_age_seconds > *policy.max_catalog_age_seconds)
                policyIssue = "price budget cannot be evaluated: stale pricing catalog is older than policy max age";
            else if (normalizePriceBudgetCurrency(request.estimate.currency) != normalizePriceBudgetCurrency(policy.currency))
                policyIssue = "price budget currency mismatch: estimate is " + request.estimate.currency +
                    ", policy is " + policy.currency;

            if (policyIssue) {
                if (mode == PriceBudgetMode::Enforce) setBlocked(decision, policy, *policyIssue);
                else appendWarning(decision, policy, *policyIssue);
                continue;
            }

            if (!canReserve) {
                if (mode == PriceBudgetMode::Enforce)
                    setBlocked(decision, policy, "price budget cannot be evaluated");
                else appendWarning(decision, policy, "price budget cannot be evaluated");
                continue;
            }

            reservablePolicyIds.insert(policy.id);
            const auto requested = budgetDecimalFromString(request.estimate.estimated_cost);
            for (const auto window : configuredWindows(policy)) {
                PriceBudgetWindowCheck check;
                check.policy_id = policy.id;
                check.scope = policy.scope;
                check.mode = mode;
                check.window = window;
                check.currency = policy.currency;
                check.limit = limitForWindow(policy, window);
                check.used_before = usedForWindow(txn, policy, window);
                check.requested = budgetFormatDecimal(requested);

                if (check.limit) {
                    const auto limit = budgetDecimalFromString(*check.limit);
                    const auto used = budgetDecimalFromString(check.used_before);
                    check.remaining_before = budgetFormatDecimal(limit - used);
                    check.exceeded = used + requested > limit;
                } else {
                    check.remaining_before = "";
                }

                decision.checks.push_back(check);
                if (!check.exceeded) continue;

                if (mode == PriceBudgetMode::Enforce) {
                    if (containsId(request.override_policy_ids, policy.id)) {
                        appendWarning(
                            decision,
                            policy,
                            "S3 price budget exceedance for " + toString(window) +
                                " was allowed by an approved single-run override");
                        continue;
                    }
                    decision.blocking_checks.push_back(check);
                } else if (mode == PriceBudgetMode::Warn) {
                    appendWarning(
                        decision,
                        policy,
                        "S3 price budget would exceed " + toString(window) +
                            " limit " + *check.limit + " " + policy.currency +
                            " with request " + check.requested);
                }
            }
        }

        finalizeBlockingDecision(decision);
        if (decision.stalled || request.dry_run || !canReserve) return decision;

        for (const auto& policy : decision.policies) {
            if (policy.mode == PriceBudgetMode::Off) continue;
            if (!reservablePolicyIds.contains(policy.id)) continue;
            if (normalizePriceBudgetCurrency(request.estimate.currency) != normalizePriceBudgetCurrency(policy.currency))
                continue;
            for (const auto window : configuredWindows(policy)) {
                const auto insertSql =
                    "INSERT INTO s3_price_budget_ledger "
                    "(policy_id, run_uuid, vault_id, gateway_credential_id, request_uuid, operation, object_key, "
                    "usage_source, synthetic, provider_key, currency, window_type, window_start, window_end, reserved_cost, estimated_cost, status) "
                    "VALUES (" +
                    std::to_string(policy.id) + ", " +
                    txn.quote(request.run_uuid) + ", " +
                    std::to_string(request.vault_id) + ", " +
                    optionalUintSql(request.gateway_credential_id) + ", " +
                    optionalSql(txn, request.request_uuid.empty()
                        ? std::optional<std::string>{}
                        : std::make_optional(request.request_uuid)) + ", " +
                    optionalSql(txn, request.operation.empty()
                        ? std::optional<std::string>{}
                        : std::make_optional(request.operation)) + ", " +
                    optionalSql(txn, request.object_key) + ", " +
                    optionalSql(txn, request.usage_source) + ", " +
                    std::string(request.synthetic ? "TRUE" : "FALSE") + ", " +
                    txn.quote(request.provider_key) + ", " +
                    txn.quote(policy.currency) + ", " +
                    txn.quote(toString(window)) + ", " +
                    windowStartExpr(window) + ", " +
                    windowEndExpr(window) + ", " +
                    txn.quote(request.estimate.estimated_cost) + "::numeric, " +
                    txn.quote(request.estimate.estimated_cost) + "::numeric, 'reserved') "
                    "RETURNING id";
                const auto inserted = txn.exec(insertSql);
                if (inserted.empty()) throw std::runtime_error("failed to create S3 price budget reservation");
                decision.reservations.push_back({
                    .id = inserted.one_row_ref()["id"].as<std::uint32_t>(),
                    .policy_id = policy.id,
                    .window = window
                });
            }
        }

        return decision;
    });
}

bool PriceBudgetService::isLimitOverrideEligible(const PriceBudgetDecision& decision) const {
    return decision.stalled && isLimitExceededReason(decision.reason) && !exceededEnforcePolicyIds(decision).empty();
}

std::vector<std::uint32_t> PriceBudgetService::exceededEnforcePolicyIds(const PriceBudgetDecision& decision) const {
    if (!decision.blocking_policy_ids.empty()) return decision.blocking_policy_ids;
    std::set<std::uint32_t> ids;
    for (const auto& check : decision.checks) {
        if (check.exceeded && check.mode == PriceBudgetMode::Enforce)
            ids.insert(check.policy_id);
    }
    if (ids.empty() && decision.exceeded_policy_id && isLimitExceededReason(decision.reason))
        ids.insert(*decision.exceeded_policy_id);
    return {ids.begin(), ids.end()};
}

std::optional<PriceBudgetOverride> PriceBudgetService::consumeApprovedOverride(
    const std::uint32_t vaultId,
    const std::vector<std::uint32_t>& policyIds,
    const std::optional<std::string>& runUuid) const {
    if (policyIds.empty()) return std::nullopt;
    expireOverrides();

    auto consumed = db::Transactions::exec("PriceBudgetService::consumeApprovedOverride", [&](pqxx::work& txn) -> std::optional<PriceBudgetOverride> {
        auto where =
            "vault_id = " + std::to_string(vaultId) + " "
            "AND status = 'approved' "
            "AND scope = 'single_run' "
            "AND expires_at > CURRENT_TIMESTAMP "
            "AND policy_ids @> " + uintVectorJsonSql(txn, policyIds) + " "
            "AND policy_ids <@ " + uintVectorJsonSql(txn, policyIds) + " ";
        if (runUuid && !runUuid->empty())
            where += "AND (run_uuid IS NULL OR run_uuid = " + txn.quote(*runUuid) + ") ";

        const auto selected = txn.exec(
            "SELECT * FROM s3_price_budget_override "
            "WHERE " + where +
            "ORDER BY expires_at ASC, id ASC LIMIT 1 FOR UPDATE");
        if (selected.empty()) return std::nullopt;

        const auto id = selected.one_row_ref()["id"].as<std::uint32_t>();
        std::string update =
            "UPDATE s3_price_budget_override "
            "SET status = 'used', used_at = CURRENT_TIMESTAMP";
        if (runUuid && !runUuid->empty())
            update += ", run_uuid = COALESCE(run_uuid, " + txn.quote(*runUuid) + ")";
        update += " WHERE id = " + std::to_string(id) + " RETURNING *";

        const auto updated = txn.exec(update);
        if (updated.empty()) throw std::runtime_error("failed to consume S3 price budget override");
        return overrideFromRow(updated.one_row_ref());
    });

    if (consumed) {
        PriceBudgetNotification notification;
        notification.type = "budget.override_used";
        notification.severity = "info";
        notification.title = notificationTitleForType(notification.type);
        notification.message = "Approved S3 price budget override was consumed by a sync run.";
        notification.scope = "single_run";
        notification.vault_id = consumed->vault_id;
        notification.policy_id = policyIds.empty() ? std::optional<std::uint32_t>{} : std::make_optional(policyIds.front());
        notification.run_uuid = runUuid;
        notification.metadata = {
            {"override_id", consumed->id},
            {"policy_ids", policyIds}
        };
        (void)createNotification(std::move(notification));
    }

    return consumed;
}

void PriceBudgetService::recordPreflightNotifications(
    const PriceBudgetPreflightRequest& request,
    const PriceBudgetDecision& decision) const {
    if (request.dry_run || decision.policies.empty()) return;

    if (decision.stalled) {
        const auto overLimit = isLimitExceededReason(decision.reason);
        const auto type = overLimit
            ? std::string{"budget.sync_blocked"}
            : notificationTypeForPricingEvaluationIssue(decision.reason);
        const auto message = decision.reason.empty()
            ? std::string{"S3 price budget enforcement stalled this sync before remote work."}
            : decision.reason;
        (void)createNotification(makeDecisionNotification(request, decision, type, "critical", message));
    }

    for (const auto& warning : decision.warnings) {
        const auto type = warning.find("would exceed") != std::string::npos ||
                          warning.find("exceedance") != std::string::npos
            ? std::string{"budget.warn_threshold"}
            : notificationTypeForPricingEvaluationIssue(warning);
        PriceBudgetDecision warningDecision = decision;
        warningDecision.reason = warning;
        (void)createNotification(makeDecisionNotification(request, warningDecision, type, "warning", warning));
    }
}

void PriceBudgetService::commit(
    const std::vector<PriceBudgetReservation>& reservations,
    const std::optional<std::string>& finalCost) const {
    const auto ids = reservationIds(reservations);
    if (ids.empty()) return;
    if (finalCost && !isValidPriceBudgetDecimal(*finalCost))
        throw std::invalid_argument("invalid committed S3 price budget decimal: " + *finalCost);

    db::Transactions::exec("PriceBudgetService::commit", [&](pqxx::work& txn) {
        const auto committed = finalCost
            ? txn.quote(*finalCost) + "::numeric"
            : std::string{"reserved_cost"};
        txn.exec(
            "UPDATE s3_price_budget_ledger "
            "SET status = 'committed', committed_cost = " + committed + ", updated_at = CURRENT_TIMESTAMP "
            "WHERE id IN " + idsSql(ids) + " AND status = 'reserved'");
    });
}

void PriceBudgetService::release(const std::vector<PriceBudgetReservation>& reservations) const {
    const auto ids = reservationIds(reservations);
    if (ids.empty()) return;

    db::Transactions::exec("PriceBudgetService::release", [&](pqxx::work& txn) {
        txn.exec(
            "UPDATE s3_price_budget_ledger "
            "SET status = 'released', updated_at = CURRENT_TIMESTAMP "
            "WHERE id IN " + idsSql(ids) + " AND status = 'reserved'");
    });
}

void PriceBudgetService::expireStaleReservations() const {
    db::Transactions::exec("PriceBudgetService::expireStaleReservations", [](pqxx::work& txn) {
        txn.exec(
            "UPDATE s3_price_budget_ledger "
            "SET status = 'expired', updated_at = CURRENT_TIMESTAMP "
            "WHERE status = 'reserved' "
            "AND created_at < CURRENT_TIMESTAMP - interval '" + std::string(kStaleReservationAge) + "'");
    });
}

void PriceBudgetService::expireOverrides() const {
    db::Transactions::exec("PriceBudgetService::expireOverrides", [](pqxx::work& txn) {
        txn.exec(
            "UPDATE s3_price_budget_override "
            "SET status = 'expired', decided_at = COALESCE(decided_at, CURRENT_TIMESTAMP) "
            "WHERE status IN ('requested', 'approved') "
            "AND expires_at <= CURRENT_TIMESTAMP");
    });
}

std::vector<PriceBudgetPolicy> PriceBudgetService::listPolicies(const bool includeInactive) const {
    return db::Transactions::exec("PriceBudgetService::listPolicies", [&](pqxx::work& txn) {
        const auto sql = std::string("SELECT * FROM s3_price_budget_policy ") +
            (includeInactive ? "" : "WHERE is_active = TRUE ") +
            "ORDER BY scope, provider_key NULLS FIRST, vault_id NULLS FIRST, id";
        const auto result = txn.exec(sql);
        return db::mapRows(result, policyFromRow);
    });
}

PriceBudgetPolicy PriceBudgetService::upsertPolicy(PriceBudgetPolicy policy) const {
    validatePolicyForWrite(policy);
    policy.currency = normalizePriceBudgetCurrency(policy.currency);

    auto saved = db::Transactions::exec("PriceBudgetService::upsertPolicy", [&](pqxx::work& txn) {
        const auto identity = policyIdentityWhere(
            txn,
            policy.scope,
            policy.provider_key,
            policy.vault_id,
            policy.gateway_credential_id);
        const auto existing = txn.exec("SELECT id FROM s3_price_budget_policy WHERE " + identity + " LIMIT 1");

        std::string sql;
        if (existing.empty()) {
            sql =
                "INSERT INTO s3_price_budget_policy "
                "(scope, provider_key, vault_id, gateway_credential_id, mode, currency, max_run_cost, max_daily_cost, max_monthly_cost, "
                "require_verified_catalog, allow_stale_catalog, max_catalog_age_seconds, is_active) VALUES (" +
                txn.quote(toString(policy.scope)) + ", " +
                optionalSql(txn, policy.provider_key) + ", " +
                optionalUintSql(policy.vault_id) + ", " +
                optionalUintSql(policy.gateway_credential_id) + ", " +
                txn.quote(toString(policy.mode)) + ", " +
                txn.quote(policy.currency) + ", " +
                optionalNumericSql(txn, policy.max_run_cost) + ", " +
                optionalNumericSql(txn, policy.max_daily_cost) + ", " +
                optionalNumericSql(txn, policy.max_monthly_cost) + ", " +
                std::string(policy.require_verified_catalog ? "TRUE" : "FALSE") + ", " +
                std::string(policy.allow_stale_catalog ? "TRUE" : "FALSE") + ", " +
                optionalInt64Sql(policy.max_catalog_age_seconds) + ", TRUE) RETURNING *";
        } else {
            sql =
                "UPDATE s3_price_budget_policy SET "
                "mode = " + txn.quote(toString(policy.mode)) + ", "
                "currency = " + txn.quote(policy.currency) + ", "
                "max_run_cost = " + optionalNumericSql(txn, policy.max_run_cost) + ", "
                "max_daily_cost = " + optionalNumericSql(txn, policy.max_daily_cost) + ", "
                "max_monthly_cost = " + optionalNumericSql(txn, policy.max_monthly_cost) + ", "
                "require_verified_catalog = " + std::string(policy.require_verified_catalog ? "TRUE" : "FALSE") + ", "
                "allow_stale_catalog = " + std::string(policy.allow_stale_catalog ? "TRUE" : "FALSE") + ", "
                "max_catalog_age_seconds = " + optionalInt64Sql(policy.max_catalog_age_seconds) + ", "
                "is_active = TRUE "
                "WHERE id = " + std::to_string(existing.one_row_ref()["id"].as<std::uint32_t>()) + " RETURNING *";
        }

        const auto result = txn.exec(sql);
        if (result.empty()) throw std::runtime_error("failed to upsert S3 price budget policy");
        return policyFromRow(result.one_row_ref());
    });

    PriceBudgetNotification notification;
    notification.type = "budget.policy_changed";
    notification.severity = saved.mode == PriceBudgetMode::Enforce ? "warning" : "info";
    notification.title = notificationTitleForType(notification.type);
    notification.message = "S3 price budget policy " + std::to_string(saved.id) + " was saved.";
    notification.scope = toString(saved.scope);
    notification.vault_id = saved.vault_id;
    notification.provider_key = saved.provider_key;
    notification.policy_id = saved.id;
    notification.metadata = {
        {"mode", toString(saved.mode)},
        {"currency", saved.currency},
        {"gateway_credential_id", saved.gateway_credential_id ? nlohmann::json(*saved.gateway_credential_id) : nlohmann::json(nullptr)}
    };
    (void)createNotification(std::move(notification));

    return saved;
}

bool PriceBudgetService::disablePolicy(
    const PriceBudgetScope scope,
    const std::optional<std::string>& providerKey,
    const std::optional<std::uint32_t>& vaultId,
    const std::optional<std::uint32_t>& gatewayCredentialId) const {
    auto disabledId = db::Transactions::exec("PriceBudgetService::disablePolicy", [&](pqxx::work& txn) -> std::optional<std::uint32_t> {
        const auto identity = policyIdentityWhere(txn, scope, providerKey, vaultId, gatewayCredentialId);
        const auto result = txn.exec(
            "UPDATE s3_price_budget_policy "
            "SET is_active = FALSE, mode = 'off' "
            "WHERE " + identity + " RETURNING id");
        if (result.empty()) return std::nullopt;
        return result.one_row_ref()["id"].as<std::uint32_t>();
    });
    if (disabledId) {
        PriceBudgetNotification notification;
        notification.type = "budget.policy_changed";
        notification.severity = "info";
        notification.title = notificationTitleForType(notification.type);
        notification.message = "S3 price budget policy " + std::to_string(*disabledId) + " was disabled.";
        notification.scope = toString(scope);
        notification.vault_id = vaultId;
        notification.provider_key = providerKey;
        notification.policy_id = *disabledId;
        notification.metadata = {
            {"mode", "off"},
            {"gateway_credential_id", gatewayCredentialId ? nlohmann::json(*gatewayCredentialId) : nlohmann::json(nullptr)}
        };
        (void)createNotification(std::move(notification));
    }
    return disabledId.has_value();
}

std::vector<PriceBudgetLedgerEntry> PriceBudgetService::listLedger(
    const std::uint32_t limit,
    const std::optional<std::uint32_t>& vaultId,
    const std::optional<std::uint32_t>& gatewayCredentialId) const {
    return db::Transactions::exec("PriceBudgetService::listLedger", [&](pqxx::work& txn) {
        const auto safeLimit = std::max<std::uint32_t>(1, std::min<std::uint32_t>(limit, 1000));
        auto sql = std::string{"SELECT * FROM s3_price_budget_ledger "};
        std::vector<std::string> filters;
        if (vaultId) filters.push_back("vault_id = " + std::to_string(*vaultId));
        if (gatewayCredentialId) filters.push_back("gateway_credential_id = " + std::to_string(*gatewayCredentialId));
        if (!filters.empty()) {
            sql += "WHERE ";
            for (std::size_t i = 0; i < filters.size(); ++i) {
                if (i > 0) sql += " AND ";
                sql += filters[i];
            }
            sql += " ";
        }
        sql += "ORDER BY created_at DESC, id DESC LIMIT " + std::to_string(safeLimit);
        const auto result = txn.exec(sql);
        return db::mapRows(result, ledgerFromRow);
    });
}

PriceBudgetNotification PriceBudgetService::createNotification(PriceBudgetNotification notification) const {
    if (notification.title.empty()) notification.title = notificationTitleForType(notification.type);
    if (notification.metadata.is_null()) notification.metadata = nlohmann::json::object();

    auto saved = db::Transactions::exec("PriceBudgetService::createNotification", [&](pqxx::work& txn) {
        const auto sql =
            "INSERT INTO operator_notification "
            "(type, severity, title, message, scope, vault_id, provider_key, policy_id, run_uuid, metadata, expires_at) "
            "VALUES (" +
            txn.quote(notification.type) + ", " +
            txn.quote(notification.severity) + ", " +
            txn.quote(notification.title) + ", " +
            txn.quote(notification.message) + ", " +
            optionalSql(txn, notification.scope) + ", " +
            optionalUintSql(notification.vault_id) + ", " +
            optionalSql(txn, notification.provider_key) + ", " +
            optionalUintSql(notification.policy_id) + ", " +
            optionalSql(txn, notification.run_uuid) + ", " +
            optionalJsonSql(txn, notification.metadata) + ", " +
            optionalSql(txn, notification.expires_at) + ") RETURNING *";
        const auto result = txn.exec(sql);
        if (result.empty()) throw std::runtime_error("failed to create operator notification");
        return notificationFromRow(result.one_row_ref());
    });

    enqueueBudgetNotificationEmail(saved);
    return saved;
}

std::vector<PriceBudgetNotification> PriceBudgetService::listNotifications(
    const std::uint32_t limit,
    const std::optional<std::uint32_t>& vaultId,
    const bool includeAcknowledged) const {
    return db::Transactions::exec("PriceBudgetService::listNotifications", [&](pqxx::work& txn) {
        const auto safeLimit = std::max<std::uint32_t>(1, std::min<std::uint32_t>(limit, 500));
        auto where = std::string{"WHERE (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) "};
        if (!includeAcknowledged) where += "AND acknowledged_at IS NULL ";
        if (vaultId) where += "AND vault_id = " + std::to_string(*vaultId) + " ";
        const auto result = txn.exec(
            "SELECT * FROM operator_notification " + where +
            "ORDER BY created_at DESC, id DESC LIMIT " + std::to_string(safeLimit));
        return db::mapRows(result, notificationFromRow);
    });
}

std::vector<PriceBudgetNotificationVaultSummary> PriceBudgetService::summarizeOpenNotifications(
    const std::optional<std::uint32_t>& vaultId) const {
    return db::Transactions::exec("PriceBudgetService::summarizeOpenNotifications", [&](pqxx::work& txn) {
        // Same open-row predicate as listNotifications(includeAcknowledged = false).
        auto where = std::string{"WHERE acknowledged_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) "};
        if (vaultId) where += "AND vault_id = " + std::to_string(*vaultId) + " ";
        const auto result = txn.exec(
            "SELECT vault_id, COUNT(*) AS open_count, "
            "(ARRAY_AGG(severity ORDER BY " + notificationSeverityRankSql() + " DESC, created_at DESC, id DESC))[1] "
            "AS worst_severity "
            "FROM operator_notification " + where +
            "GROUP BY vault_id");
        std::vector<PriceBudgetNotificationVaultSummary> groups;
        groups.reserve(result.size());
        for (const auto& row : result)
            groups.push_back({
                .vault_id = optionalUInt(row, "vault_id"),
                .summary = {
                    .open_count = row["open_count"].as<std::uint32_t>(),
                    .worst_severity = optionalString(row, "worst_severity")
                }
            });
        return groups;
    });
}

PriceBudgetNotification PriceBudgetService::acknowledgeNotification(
    const std::uint32_t notificationId,
    const std::uint32_t userId) const {
    return db::Transactions::exec("PriceBudgetService::acknowledgeNotification", [&](pqxx::work& txn) {
        const auto result = txn.exec(
            "UPDATE operator_notification "
            "SET acknowledged_at = CURRENT_TIMESTAMP, acknowledged_by = " + std::to_string(userId) + " "
            "WHERE id = " + std::to_string(notificationId) + " RETURNING *");
        if (result.empty()) throw ::vh::ops::NotFound("operator notification not found");
        return notificationFromRow(result.one_row_ref());
    });
}

PriceBudgetOverride PriceBudgetService::requestOverride(const PriceBudgetOverrideRequest& request) const {
    if (request.vault_id == 0) throw ::vh::ops::Invalid("override request requires vault_id");
    if (request.requested_by == 0) throw ::vh::ops::Invalid("override request requires requested_by");
    if (request.policy_ids.empty()) throw ::vh::ops::Invalid("override request requires policy_ids");
    if (request.estimated_cost && !isValidPriceBudgetDecimal(*request.estimated_cost))
        throw ::vh::ops::Invalid("invalid override estimated cost: " + *request.estimated_cost);
    const auto ttlMinutes = std::clamp<std::uint32_t>(request.ttl_minutes == 0 ? 30 : request.ttl_minutes, 1, 120);
    const auto currency = normalizePriceBudgetCurrency(request.currency.empty() ? "USD" : request.currency);
    if (!isValidPriceBudgetCurrency(currency)) throw ::vh::ops::Invalid("invalid override currency: " + currency);

    auto saved = db::Transactions::exec("PriceBudgetService::requestOverride", [&](pqxx::work& txn) {
        const auto result = txn.exec(
            "INSERT INTO s3_price_budget_override "
            "(run_uuid, vault_id, requested_by, status, reason, scope, policy_ids, estimated_cost, currency, expires_at) "
            "VALUES (" +
            optionalSql(txn, request.run_uuid) + ", " +
            std::to_string(request.vault_id) + ", " +
            std::to_string(request.requested_by) + ", "
            "'requested', " +
            optionalSql(txn, request.reason) + ", "
            "'single_run', " +
            uintVectorJsonSql(txn, request.policy_ids) + ", " +
            optionalNumericSql(txn, request.estimated_cost) + ", " +
            txn.quote(currency) + ", "
            "CURRENT_TIMESTAMP + interval '" + std::to_string(ttlMinutes) + " minutes') "
            "RETURNING *");
        if (result.empty()) throw std::runtime_error("failed to request S3 price budget override");
        return overrideFromRow(result.one_row_ref());
    });

    PriceBudgetNotification notification;
    notification.type = "budget.override_requested";
    notification.severity = "warning";
    notification.title = notificationTitleForType(notification.type);
    notification.message = "A single-run S3 price budget override was requested.";
    notification.scope = "single_run";
    notification.vault_id = saved.vault_id;
    notification.policy_id = saved.policy_ids.empty() ? std::optional<std::uint32_t>{} : std::make_optional(saved.policy_ids.front());
    notification.run_uuid = saved.run_uuid;
    notification.metadata = {
        {"override_id", saved.id},
        {"requested_by", saved.requested_by ? nlohmann::json(*saved.requested_by) : nlohmann::json(nullptr)},
        {"policy_ids", saved.policy_ids},
        {"estimated_cost", saved.estimated_cost ? nlohmann::json(*saved.estimated_cost) : nlohmann::json(nullptr)},
        {"currency", saved.currency},
        {"reason", saved.reason ? nlohmann::json(*saved.reason) : nlohmann::json(nullptr)}
    };
    (void)createNotification(std::move(notification));

    return saved;
}

PriceBudgetOverride PriceBudgetService::approveOverride(const std::uint32_t overrideId, const std::uint32_t approvedBy) const {
    expireOverrides();
    auto saved = db::Transactions::exec("PriceBudgetService::approveOverride", [&](pqxx::work& txn) {
        const auto result = txn.exec(
            "UPDATE s3_price_budget_override "
            "SET status = 'approved', approved_by = " + std::to_string(approvedBy) + ", decided_at = CURRENT_TIMESTAMP "
            "WHERE id = " + std::to_string(overrideId) + " "
            "AND status = 'requested' "
            "AND expires_at > CURRENT_TIMESTAMP "
            "RETURNING *");
        if (result.empty()) throw ::vh::ops::Conflict("S3 price budget override is not pending or has expired");
        return overrideFromRow(result.one_row_ref());
    });

    PriceBudgetNotification notification;
    notification.type = "budget.override_approved";
    notification.severity = "info";
    notification.title = notificationTitleForType(notification.type);
    notification.message = "A single-run S3 price budget override was approved.";
    notification.scope = "single_run";
    notification.vault_id = saved.vault_id;
    notification.policy_id = saved.policy_ids.empty() ? std::optional<std::uint32_t>{} : std::make_optional(saved.policy_ids.front());
    notification.run_uuid = saved.run_uuid;
    notification.metadata = {{"override_id", saved.id}, {"approved_by", approvedBy}, {"policy_ids", saved.policy_ids}};
    (void)createNotification(std::move(notification));

    return saved;
}

PriceBudgetOverride PriceBudgetService::denyOverride(
    const std::uint32_t overrideId,
    const std::uint32_t deniedBy,
    std::optional<std::string> reason) const {
    expireOverrides();
    auto saved = db::Transactions::exec("PriceBudgetService::denyOverride", [&](pqxx::work& txn) {
        const auto result = txn.exec(
            "UPDATE s3_price_budget_override "
            "SET status = 'denied', approved_by = " + std::to_string(deniedBy) + ", "
            "reason = COALESCE(" + optionalSql(txn, reason) + ", reason), "
            "decided_at = CURRENT_TIMESTAMP "
            "WHERE id = " + std::to_string(overrideId) + " "
            "AND status = 'requested' "
            "RETURNING *");
        if (result.empty()) throw ::vh::ops::Conflict("S3 price budget override is not pending");
        return overrideFromRow(result.one_row_ref());
    });

    PriceBudgetNotification notification;
    notification.type = "budget.override_denied";
    notification.severity = "info";
    notification.title = notificationTitleForType(notification.type);
    notification.message = "A single-run S3 price budget override was denied.";
    notification.scope = "single_run";
    notification.vault_id = saved.vault_id;
    notification.policy_id = saved.policy_ids.empty() ? std::optional<std::uint32_t>{} : std::make_optional(saved.policy_ids.front());
    notification.run_uuid = saved.run_uuid;
    notification.metadata = {{"override_id", saved.id}, {"denied_by", deniedBy}, {"policy_ids", saved.policy_ids}};
    (void)createNotification(std::move(notification));

    return saved;
}

std::vector<PriceBudgetOverride> PriceBudgetService::listOverrides(
    const std::uint32_t limit,
    const std::optional<std::uint32_t>& vaultId,
    const bool includeExpired) const {
    expireOverrides();
    return db::Transactions::exec("PriceBudgetService::listOverrides", [&](pqxx::work& txn) {
        const auto safeLimit = std::max<std::uint32_t>(1, std::min<std::uint32_t>(limit, 500));
        auto where = std::string{"WHERE TRUE "};
        if (!includeExpired) where += "AND status <> 'expired' ";
        if (vaultId) where += "AND vault_id = " + std::to_string(*vaultId) + " ";
        const auto result = txn.exec(
            "SELECT * FROM s3_price_budget_override " + where +
            "ORDER BY created_at DESC, id DESC LIMIT " + std::to_string(safeLimit));
        return db::mapRows(result, overrideFromRow);
    });
}

std::vector<PriceBudgetTrendStats> PriceBudgetService::trendStats(
    const std::optional<std::uint32_t>& vaultId,
    const std::optional<std::uint32_t>& gatewayCredentialId) const {
    std::vector<PriceBudgetNotification> pendingNotifications;

    auto trends = db::Transactions::exec("PriceBudgetService::trendStats", [&](pqxx::work& txn) {
        auto policySql = "SELECT * FROM s3_price_budget_policy WHERE " +
            statsPolicyWhereClause(txn, vaultId, gatewayCredentialId) + " ORDER BY id";
        const auto ledgerScopeFilter = scopedLedgerFilter(vaultId, gatewayCredentialId);

        const auto policyRows = txn.exec(policySql);
        std::vector<PriceBudgetTrendStats> out;

        const auto avgForDays = [&](const PriceBudgetPolicy& policy, const PriceBudgetWindow window, const std::uint32_t days) {
            const auto result = txn.exec(
                "SELECT COALESCE(AVG(day_total), 0)::numeric(20,8)::text AS avg_daily, COUNT(*)::int AS sample_days "
                "FROM ("
                "SELECT date_trunc('day', created_at) AS day, SUM(COALESCE(committed_cost, reserved_cost)) AS day_total "
                "FROM s3_price_budget_ledger "
                "WHERE policy_id = " + std::to_string(policy.id) + " "
                "AND window_type = " + txn.quote(toString(window)) + " "
                "AND status IN ('reserved', 'committed') "
                + ledgerScopeFilter +
                "AND created_at >= CURRENT_TIMESTAMP - interval '" + std::to_string(days) + " days' "
                "GROUP BY 1"
                ") daily");
            if (result.empty()) return std::pair<std::string, std::uint32_t>{"0.00000000", 0};
            const auto row = result.one_row_ref();
            return std::pair<std::string, std::uint32_t>{
                row["avg_daily"].as<std::string>(),
                row["sample_days"].as<std::uint32_t>()
            };
        };

        const auto maybeExhaustionAt = [&](const Decimal& total, const Decimal& limit, const Decimal& dailyRate) -> std::optional<std::string> {
            if (dailyRate <= Decimal("0") || total >= limit) return std::nullopt;
            const auto seconds = (limit - total) / dailyRate * Decimal("86400");
            if (seconds <= Decimal("0")) return std::nullopt;
            std::ostringstream intervalSeconds;
            intervalSeconds << std::fixed << std::setprecision(0) << seconds;
            const auto result = txn.exec(
                "SELECT (CURRENT_TIMESTAMP + (" + txn.quote(intervalSeconds.str()) + " || ' seconds')::interval)::text AS ts");
            if (result.empty()) return std::nullopt;
            return result.one_row_ref()["ts"].as<std::string>();
        };

        const auto insertAlertState = [&](const PriceBudgetTrendStats& trend, const std::string& alertKey) {
            const auto result = txn.exec(
                "INSERT INTO s3_price_budget_alert_state (policy_id, alert_key, window_type, window_start) "
                "VALUES (" + std::to_string(trend.policy_id) + ", " +
                txn.quote(alertKey) + ", " +
                txn.quote(trend.window_type) + ", " +
                txn.quote(trend.window_start) + "::timestamptz) "
                "ON CONFLICT (policy_id, alert_key, window_type, window_start) DO NOTHING "
                "RETURNING id");
            return !result.empty();
        };

        const auto queueAlert = [&](const PriceBudgetTrendStats& trend, const std::string& alertKey, const std::string& severity, const std::string& message) {
            if (!insertAlertState(trend, alertKey)) return;
            PriceBudgetNotification notification;
            notification.type = alertKey == "projected_overage" ? "budget.predicted_overage" : "budget.warn_threshold";
            notification.severity = severity;
            notification.title = notificationTitleForType(notification.type);
            notification.message = message;
            notification.scope = trend.scope;
            notification.vault_id = trend.vault_id;
            notification.provider_key = trend.provider_key;
            notification.policy_id = trend.policy_id;
            notification.metadata = {
                {"alert_key", alertKey},
                {"window_type", trend.window_type},
                {"window_start", trend.window_start},
                {"limit", trend.limit ? nlohmann::json(*trend.limit) : nlohmann::json(nullptr)},
                {"total_cost", trend.total_cost},
                {"projected_window_cost", trend.projected_window_cost ? nlohmann::json(*trend.projected_window_cost) : nlohmann::json(nullptr)},
                {"percent_used", trend.percent_used},
                {"confidence", trend.confidence}
            };
            pendingNotifications.push_back(std::move(notification));
        };

        for (const auto& policyRow : policyRows) {
            const auto policy = policyFromRow(policyRow);
            for (const auto window : {PriceBudgetWindow::Daily, PriceBudgetWindow::Monthly}) {
                const auto limit = limitForWindow(policy, window);
                if (!limit) continue;

                const auto current = txn.exec(
                    "SELECT (" + windowStartExpr(window) + ")::text AS window_start, "
                    "(" + windowEndExpr(window) + ")::text AS window_end, "
                    "COALESCE(SUM(CASE WHEN status = 'committed' THEN COALESCE(committed_cost, reserved_cost) ELSE 0 END), 0)::numeric(20,8)::text AS committed_cost, "
                    "COALESCE(SUM(CASE WHEN status = 'reserved' THEN reserved_cost ELSE 0 END), 0)::numeric(20,8)::text AS reserved_cost, "
                    "COALESCE(SUM(COALESCE(committed_cost, reserved_cost)), 0)::numeric(20,8)::text AS total_cost, "
                    "EXTRACT(EPOCH FROM (" + windowEndExpr(window) + " - CURRENT_TIMESTAMP))::double precision AS remaining_seconds, "
                    "EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - " + windowStartExpr(window) + "))::double precision AS elapsed_seconds "
                    "FROM s3_price_budget_ledger "
                    "WHERE policy_id = " + std::to_string(policy.id) + " "
                    "AND window_type = " + txn.quote(toString(window)) + " "
                    "AND window_start = " + windowStartExpr(window) + " "
                    + ledgerScopeFilter +
                    "AND status IN ('reserved', 'committed')");
                if (current.empty()) continue;
                const auto row = current.one_row_ref();

                const auto [avg7, days7] = avgForDays(policy, window, 7);
                const auto [avg30, days30] = avgForDays(policy, window, 30);

                PriceBudgetTrendStats trend;
                trend.scope = toString(policy.scope);
                trend.provider_key = policy.provider_key;
                trend.vault_id = policy.vault_id;
                trend.gateway_credential_id = policy.gateway_credential_id;
                trend.policy_id = policy.id;
                trend.currency = policy.currency;
                trend.window_type = toString(window);
                trend.window_start = row["window_start"].as<std::string>();
                trend.window_end = row["window_end"].as<std::string>();
                trend.committed_cost = row["committed_cost"].as<std::string>();
                trend.reserved_cost = row["reserved_cost"].as<std::string>();
                trend.total_cost = row["total_cost"].as<std::string>();
                trend.limit = limit;
                trend.recent_daily_average = avg7;
                trend.recent_7d_average = avg7;
                trend.recent_30d_average = avg30;
                trend.confidence = days7 >= 7 ? "high" : days7 >= 2 ? "medium" : "low";

                const auto total = budgetDecimalFromString(trend.total_cost);
                const auto limitDecimal = budgetDecimalFromString(*limit);
                const auto avgDaily = budgetDecimalFromString(avg7);
                trend.remaining = budgetFormatDecimal(limitDecimal - total);
                if (limitDecimal > Decimal("0"))
                    trend.percent_used = (total / limitDecimal).convert_to<double>();

                const auto remainingSeconds = row["remaining_seconds"].as<double>();
                const auto elapsedSeconds = std::max(1.0, row["elapsed_seconds"].as<double>());
                Decimal projected = total;
                if (window == PriceBudgetWindow::Monthly) {
                    const auto daysRemaining = Decimal(std::max(0.0, std::ceil(remainingSeconds / 86400.0)));
                    projected = total + (avgDaily * daysRemaining);
                } else {
                    if (elapsedSeconds >= 3600.0)
                        projected = total * Decimal("86400") / Decimal(elapsedSeconds);
                    else if (avgDaily > Decimal("0"))
                        projected = std::max(total, avgDaily);
                }
                trend.projected_window_cost = budgetFormatDecimal(projected);
                if (projected > limitDecimal) {
                    trend.projected_overage = budgetFormatDecimal(projected - limitDecimal);
                    trend.predicted_exhaustion_at = maybeExhaustionAt(total, limitDecimal, avgDaily);
                    trend.warnings.push_back("Projected " + trend.window_type + " cost exceeds configured limit.");
                }

                if (trend.percent_used >= 0.90) {
                    queueAlert(
                        trend,
                        "usage_90",
                        "critical",
                        "S3 price budget is at or above 90% of its " + trend.window_type + " limit.");
                } else if (trend.percent_used >= 0.75) {
                    queueAlert(
                        trend,
                        "usage_75",
                        "warning",
                        "S3 price budget is at or above 75% of its " + trend.window_type + " limit.");
                } else if (trend.percent_used >= 0.50) {
                    queueAlert(
                        trend,
                        "usage_50",
                        "info",
                        "S3 price budget is at or above 50% of its " + trend.window_type + " limit.");
                }
                if (trend.projected_overage) {
                    const auto severity = trend.percent_used >= 0.90 ? "critical" : "warning";
                    queueAlert(
                        trend,
                        "projected_overage",
                        severity,
                        "S3 price budget is projected to exceed its " + trend.window_type + " limit.");
                }

                out.push_back(std::move(trend));
            }
        }

        return out;
    });

    for (auto& notification : pendingNotifications)
        (void)createNotification(std::move(notification));

    return trends;
}

PriceBudgetDashboardStats PriceBudgetService::dashboardStats(const std::optional<std::uint32_t>& vaultId) const {
    PriceBudgetDashboardStats stats;
    stats.trends = trendStats(vaultId);
    if (!stats.trends.empty()) stats.currency = stats.trends.front().currency;

    for (const auto& trend : stats.trends) {
        if (trend.window_type != "monthly") continue;
        stats.current_monthly_spend = budgetFormatDecimal(
            budgetDecimalFromString(stats.current_monthly_spend.value_or("0")) + budgetDecimalFromString(trend.total_cost));
        if (trend.projected_window_cost)
            stats.projected_monthly_spend = budgetFormatDecimal(
                budgetDecimalFromString(stats.projected_monthly_spend.value_or("0")) +
                budgetDecimalFromString(*trend.projected_window_cost));
    }

    auto summary = db::Transactions::exec("PriceBudgetService::dashboardStats", [&](pqxx::work& txn) {
        auto vaultFilter = std::string{};
        if (vaultId) vaultFilter = " AND vault_id = " + std::to_string(*vaultId) + " ";

        nlohmann::json result;
        result["active_policies"] = txn.exec(
            "SELECT COUNT(*) AS c FROM s3_price_budget_policy "
            "WHERE " + statsPolicyWhereClause(txn, vaultId, std::nullopt))
            .one_row_ref()["c"].as<std::uint32_t>();
        result["blocked_syncs_24h"] = txn.exec(
            "SELECT COUNT(*) AS c FROM sync_event "
            "WHERE status = 'stalled' "
            "AND stall_reason ILIKE '%price budget%' "
            "AND timestamp_begin >= CURRENT_TIMESTAMP - interval '24 hours'" + vaultFilter)
            .one_row_ref()["c"].as<std::uint32_t>();
        result["warning_notifications"] = txn.exec(
            "SELECT COUNT(*) AS c FROM operator_notification "
            "WHERE acknowledged_at IS NULL AND severity = 'warning' "
            "AND type LIKE 'budget.%'" + vaultFilter)
            .one_row_ref()["c"].as<std::uint32_t>();
        result["critical_notifications"] = txn.exec(
            "SELECT COUNT(*) AS c FROM operator_notification "
            "WHERE acknowledged_at IS NULL AND severity = 'critical' "
            "AND type LIKE 'budget.%'" + vaultFilter)
            .one_row_ref()["c"].as<std::uint32_t>();
        result["unacknowledged_notifications"] = txn.exec(
            "SELECT COUNT(*) AS c FROM operator_notification "
            "WHERE acknowledged_at IS NULL "
            "AND (type LIKE 'budget.%' OR type LIKE 'pricing.%')" + vaultFilter)
            .one_row_ref()["c"].as<std::uint32_t>();
        result["pending_overrides"] = txn.exec(
            "SELECT COUNT(*) AS c FROM s3_price_budget_override "
            "WHERE status = 'requested' "
            "AND expires_at > CURRENT_TIMESTAMP" + vaultFilter)
            .one_row_ref()["c"].as<std::uint32_t>();
        return result;
    });

    stats.active_policies = summary["active_policies"].get<std::uint32_t>();
    stats.blocked_syncs_24h = summary["blocked_syncs_24h"].get<std::uint32_t>();
    stats.warning_notifications = summary["warning_notifications"].get<std::uint32_t>();
    stats.critical_notifications = summary["critical_notifications"].get<std::uint32_t>();
    stats.unacknowledged_notifications = summary["unacknowledged_notifications"].get<std::uint32_t>();
    stats.pending_overrides = summary["pending_overrides"].get<std::uint32_t>();
    stats.active_notifications = listNotifications(20, vaultId, false);
    stats.recent_overrides = listOverrides(20, vaultId, true);
    return stats;
}

void to_json(nlohmann::json& j, const PriceBudgetPolicy& policy) {
    j = {
        {"id", policy.id},
        {"scope", toString(policy.scope)},
        {"provider_key", policy.provider_key ? nlohmann::json(*policy.provider_key) : nlohmann::json(nullptr)},
        {"vault_id", policy.vault_id ? nlohmann::json(*policy.vault_id) : nlohmann::json(nullptr)},
        {"gateway_credential_id", policy.gateway_credential_id ? nlohmann::json(*policy.gateway_credential_id) : nlohmann::json(nullptr)},
        {"mode", toString(policy.mode)},
        {"currency", policy.currency},
        {"max_run_cost", policy.max_run_cost ? nlohmann::json(*policy.max_run_cost) : nlohmann::json(nullptr)},
        {"max_daily_cost", policy.max_daily_cost ? nlohmann::json(*policy.max_daily_cost) : nlohmann::json(nullptr)},
        {"max_monthly_cost", policy.max_monthly_cost ? nlohmann::json(*policy.max_monthly_cost) : nlohmann::json(nullptr)},
        {"require_verified_catalog", policy.require_verified_catalog},
        {"allow_stale_catalog", policy.allow_stale_catalog},
        {"max_catalog_age_seconds", policy.max_catalog_age_seconds ? nlohmann::json(*policy.max_catalog_age_seconds) : nlohmann::json(nullptr)},
        {"is_active", policy.is_active}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetWindowCheck& check) {
    j = {
        {"policy_id", check.policy_id},
        {"scope", toString(check.scope)},
        {"mode", toString(check.mode)},
        {"window", toString(check.window)},
        {"currency", check.currency},
        {"limit", check.limit ? nlohmann::json(*check.limit) : nlohmann::json(nullptr)},
        {"used_before", check.used_before},
        {"remaining_before", check.remaining_before},
        {"requested", check.requested},
        {"exceeded", check.exceeded}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetDecision& decision) {
    j = {
        {"allowed", decision.allowed},
        {"stalled", decision.stalled},
        {"warnings", decision.warnings},
        {"exceeded_policy_id", decision.exceeded_policy_id ? nlohmann::json(*decision.exceeded_policy_id) : nlohmann::json(nullptr)},
        {"exceeded_scope", decision.exceeded_scope},
        {"limit", decision.limit},
        {"used_before", decision.used_before},
        {"remaining_before", decision.remaining_before},
        {"requested", decision.requested},
        {"currency", decision.currency},
        {"reason", decision.reason},
        {"policies", decision.policies},
        {"checks", decision.checks},
        {"blocking_checks", decision.blocking_checks},
        {"blocking_policy_ids", decision.blocking_policy_ids},
        {"primary_blocking_check", decision.primary_blocking_check ? nlohmann::json(*decision.primary_blocking_check) : nlohmann::json(nullptr)},
        {"primary_blocking_scope", decision.primary_blocking_scope},
        {"primary_blocking_window", decision.primary_blocking_window}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetLedgerEntry& entry) {
    j = {
        {"id", entry.id},
        {"policy_id", entry.policy_id},
        {"run_uuid", entry.run_uuid},
        {"vault_id", entry.vault_id},
        {"gateway_credential_id", entry.gateway_credential_id ? nlohmann::json(*entry.gateway_credential_id) : nlohmann::json(nullptr)},
        {"request_uuid", entry.request_uuid ? nlohmann::json(*entry.request_uuid) : nlohmann::json(nullptr)},
        {"operation", entry.operation ? nlohmann::json(*entry.operation) : nlohmann::json(nullptr)},
        {"object_key", entry.object_key ? nlohmann::json(*entry.object_key) : nlohmann::json(nullptr)},
        {"estimated_cost", entry.estimated_cost ? nlohmann::json(*entry.estimated_cost) : nlohmann::json(nullptr)},
        {"usage_source", entry.usage_source ? nlohmann::json(*entry.usage_source) : nlohmann::json(nullptr)},
        {"synthetic", entry.synthetic},
        {"provider_key", entry.provider_key},
        {"currency", entry.currency},
        {"window", toString(entry.window)},
        {"window_start", entry.window_start},
        {"window_end", entry.window_end},
        {"reserved_cost", entry.reserved_cost},
        {"committed_cost", entry.committed_cost ? nlohmann::json(*entry.committed_cost) : nlohmann::json(nullptr)},
        {"status", entry.status},
        {"created_at", entry.created_at}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetNotification& notification) {
    j = {
        {"id", notification.id},
        {"type", notification.type},
        {"severity", notification.severity},
        {"title", notification.title},
        {"message", notification.message},
        {"scope", notification.scope ? nlohmann::json(*notification.scope) : nlohmann::json(nullptr)},
        {"vault_id", notification.vault_id ? nlohmann::json(*notification.vault_id) : nlohmann::json(nullptr)},
        {"provider_key", notification.provider_key ? nlohmann::json(*notification.provider_key) : nlohmann::json(nullptr)},
        {"policy_id", notification.policy_id ? nlohmann::json(*notification.policy_id) : nlohmann::json(nullptr)},
        {"run_uuid", notification.run_uuid ? nlohmann::json(*notification.run_uuid) : nlohmann::json(nullptr)},
        {"metadata", notification.metadata.is_null() ? nlohmann::json::object() : notification.metadata},
        {"acknowledged_at", notification.acknowledged_at ? nlohmann::json(*notification.acknowledged_at) : nlohmann::json(nullptr)},
        {"acknowledged_by", notification.acknowledged_by ? nlohmann::json(*notification.acknowledged_by) : nlohmann::json(nullptr)},
        {"created_at", notification.created_at},
        {"expires_at", notification.expires_at ? nlohmann::json(*notification.expires_at) : nlohmann::json(nullptr)}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetNotificationSummary& summary) {
    j = {
        {"open_count", summary.open_count},
        {"worst_severity", summary.worst_severity ? nlohmann::json(*summary.worst_severity) : nlohmann::json(nullptr)}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetOverride& budgetOverride) {
    j = {
        {"id", budgetOverride.id},
        {"run_uuid", budgetOverride.run_uuid ? nlohmann::json(*budgetOverride.run_uuid) : nlohmann::json(nullptr)},
        {"vault_id", budgetOverride.vault_id},
        {"requested_by", budgetOverride.requested_by ? nlohmann::json(*budgetOverride.requested_by) : nlohmann::json(nullptr)},
        {"approved_by", budgetOverride.approved_by ? nlohmann::json(*budgetOverride.approved_by) : nlohmann::json(nullptr)},
        {"status", budgetOverride.status},
        {"reason", budgetOverride.reason ? nlohmann::json(*budgetOverride.reason) : nlohmann::json(nullptr)},
        {"scope", budgetOverride.scope},
        {"policy_ids", budgetOverride.policy_ids},
        {"estimated_cost", budgetOverride.estimated_cost ? nlohmann::json(*budgetOverride.estimated_cost) : nlohmann::json(nullptr)},
        {"currency", budgetOverride.currency},
        {"expires_at", budgetOverride.expires_at},
        {"created_at", budgetOverride.created_at},
        {"decided_at", budgetOverride.decided_at ? nlohmann::json(*budgetOverride.decided_at) : nlohmann::json(nullptr)},
        {"used_at", budgetOverride.used_at ? nlohmann::json(*budgetOverride.used_at) : nlohmann::json(nullptr)}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetTrendStats& stats) {
    j = {
        {"scope", stats.scope},
        {"provider_key", stats.provider_key ? nlohmann::json(*stats.provider_key) : nlohmann::json(nullptr)},
        {"vault_id", stats.vault_id ? nlohmann::json(*stats.vault_id) : nlohmann::json(nullptr)},
        {"gateway_credential_id", stats.gateway_credential_id ? nlohmann::json(*stats.gateway_credential_id) : nlohmann::json(nullptr)},
        {"policy_id", stats.policy_id},
        {"currency", stats.currency},
        {"window_type", stats.window_type},
        {"window_start", stats.window_start},
        {"window_end", stats.window_end},
        {"committed_cost", stats.committed_cost},
        {"reserved_cost", stats.reserved_cost},
        {"total_cost", stats.total_cost},
        {"limit", stats.limit ? nlohmann::json(*stats.limit) : nlohmann::json(nullptr)},
        {"remaining", stats.remaining ? nlohmann::json(*stats.remaining) : nlohmann::json(nullptr)},
        {"percent_used", stats.percent_used},
        {"projected_window_cost", stats.projected_window_cost ? nlohmann::json(*stats.projected_window_cost) : nlohmann::json(nullptr)},
        {"projected_overage", stats.projected_overage ? nlohmann::json(*stats.projected_overage) : nlohmann::json(nullptr)},
        {"predicted_exhaustion_at", stats.predicted_exhaustion_at ? nlohmann::json(*stats.predicted_exhaustion_at) : nlohmann::json(nullptr)},
        {"confidence", stats.confidence},
        {"recent_daily_average", stats.recent_daily_average},
        {"recent_7d_average", stats.recent_7d_average},
        {"recent_30d_average", stats.recent_30d_average},
        {"warnings", stats.warnings}
    };
}

void to_json(nlohmann::json& j, const PriceBudgetDashboardStats& stats) {
    j = {
        {"active_policies", stats.active_policies},
        {"blocked_syncs_24h", stats.blocked_syncs_24h},
        {"warning_notifications", stats.warning_notifications},
        {"critical_notifications", stats.critical_notifications},
        {"unacknowledged_notifications", stats.unacknowledged_notifications},
        {"pending_overrides", stats.pending_overrides},
        // null when no monthly budget window (or projection) exists: not measured, never a fake "0.00000000" (#160).
        {"current_monthly_spend", stats.current_monthly_spend ? nlohmann::json(*stats.current_monthly_spend) : nlohmann::json(nullptr)},
        {"projected_monthly_spend", stats.projected_monthly_spend ? nlohmann::json(*stats.projected_monthly_spend) : nlohmann::json(nullptr)},
        {"currency", stats.currency},
        {"trends", stats.trends},
        {"active_notifications", stats.active_notifications},
        {"recent_overrides", stats.recent_overrides}
    };
}

} // namespace vh::storage::s3::pricing
