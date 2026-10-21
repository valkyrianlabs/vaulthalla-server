#include "protocols/ws/handler/Pricing.hpp"
#include "ops/Error.hpp"

#include "db/query/fs/File.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "ops/Pricing.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/permission/vault/sync/Action.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "sync/Cloud.hpp"
#include "sync/Planner.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <stdexcept>

namespace vh::protocols::ws::handler {
namespace {

using vh::storage::s3::pricing::PriceBudgetNotificationSummary;
using vh::storage::s3::pricing::PriceBudgetScope;
using vh::storage::s3::pricing::PriceBudgetService;
using vh::storage::s3::pricing::mergePriceBudgetNotificationSummary;
using vh::storage::s3::pricing::priceBudgetModeFromString;
using vh::storage::s3::pricing::priceBudgetScopeFromString;

// Pricing payloads name an override, a notification, a vault and policies; a bare `id` would have to mean one of
// them by command, so each command reads only its explicit field and refuses `id` (#184, the #165 rule).
std::uint32_t requiredPricingRefId(const json& payload, const char* field) {
    if (!payload.is_object()) throw ::vh::ops::Invalid(std::string(field) + " is required");
    if (payload.contains("id"))
        throw ::vh::ops::Invalid(std::string("bare 'id' is not accepted by pricing commands; send '") + field + "'");
    const auto it = payload.find(field);
    if (it == payload.end() || !it->is_number_unsigned()) throw ::vh::ops::Invalid(std::string(field) + " is required");
    const auto value = it->get<std::uint64_t>();
    if (value == 0 || value > std::numeric_limits<std::uint32_t>::max())
        throw ::vh::ops::Invalid(std::string(field) + " is out of range");
    return static_cast<std::uint32_t>(value);
}

std::optional<std::uint32_t> optionalVaultId(const json& payload) {
    if (!payload.is_object() || !payload.contains("vault_id") || payload.at("vault_id").is_null()) return std::nullopt;
    return payload.at("vault_id").get<std::uint32_t>();
}

std::optional<std::string> optionalStringPayload(const json& payload, const char* key) {
    if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    const auto value = payload.at(key).get<std::string>();
    return value.empty() ? std::optional<std::string>{} : std::make_optional(value);
}

std::optional<std::uint32_t> optionalUIntPayload(const json& payload, const char* key) {
    if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    return payload.at(key).get<std::uint32_t>();
}

std::uint32_t limitFromPayload(const json& payload, const std::uint32_t fallback = 50) {
    if (!payload.is_object()) return fallback;
    return std::clamp<std::uint32_t>(payload.value("limit", fallback), 1, 500);
}

bool canViewVaultBudget(const std::shared_ptr<Session>& session, const std::uint32_t vaultId) {
    if (!session || !session->user) return false;
    if (session->user->isSuperAdmin()) return true;
    try {
        if (vh::db::query::vault::Vault::getVaultOwnerId(vaultId) == session->user->id) return true;
    } catch (const std::exception&) {
        return false;
    }
    if (!runtime::Deps::get().storageManager) return false;
    return vh::rbac::resolver::Admin::has<vh::rbac::permission::admin::VaultPermissions>({
        .user = session->user,
        .permissions = {
            vh::rbac::permission::admin::VaultPermissions::View,
            vh::rbac::permission::admin::VaultPermissions::ViewStats
        },
        .vault_id = vaultId
    });
}

void requireVaultBudgetView(const std::shared_ptr<Session>& session, const std::uint32_t vaultId) {
    if (!canViewVaultBudget(session, vaultId))
        throw vh::ops::Denied("You do not have permission to view S3 price budget data for this vault.");
}

void requireSuperAdmin(const std::shared_ptr<Session>& session, const char* message) {
    if (!session->user || !session->user->isSuperAdmin()) throw vh::ops::Denied(message);
}

// An unknown scope is the caller's mistake: the parser's std::invalid_argument becomes a typed refusal.
PriceBudgetScope pricingScopeFromPayload(const json& payload) {
    try {
        return priceBudgetScopeFromString(payload.at("scope").get<std::string>());
    } catch (const std::invalid_argument& e) {
        throw ::vh::ops::Invalid(e.what());
    }
}

// The payload as ops::pricing's request and filter.
vh::ops::pricing::PolicySpec specFromPayload(const json& payload) {
    vh::ops::pricing::PolicySpec spec{
        .scope = pricingScopeFromPayload(payload),
        .provider_key = optionalStringPayload(payload, "provider_key"),
        .vault_id = optionalUIntPayload(payload, "vault_id"),
        .gateway_credential_id = optionalUIntPayload(payload, "gateway_credential_id"),
        .mode = optionalStringPayload(payload, "mode"),
        .currency = optionalStringPayload(payload, "currency"),
        .max_run_cost = optionalStringPayload(payload, "max_run_cost"),
        .max_daily_cost = optionalStringPayload(payload, "max_daily_cost"),
        .max_monthly_cost = optionalStringPayload(payload, "max_monthly_cost")
    };
    if (payload.contains("require_verified_catalog")) spec.require_verified_catalog = payload.at("require_verified_catalog").get<bool>();
    if (payload.contains("allow_stale_catalog")) spec.allow_stale_catalog = payload.at("allow_stale_catalog").get<bool>();
    if (payload.contains("max_catalog_age_seconds") && !payload.at("max_catalog_age_seconds").is_null())
        spec.max_catalog_age_seconds = payload.at("max_catalog_age_seconds").get<std::int64_t>();
    return spec;
}

vh::ops::pricing::Filter filterFromPayload(const json& payload) {
    if (!payload.is_object()) return {};
    return {.vault_id = optionalVaultId(payload), .gateway_credential_id = optionalUIntPayload(payload, "gateway_credential_id"),
            .include_inactive = payload.value("include_inactive", true)};
}

std::vector<std::uint32_t> policyIdsFromPayload(const json& payload) {
    std::vector<std::uint32_t> ids;
    if (!payload.contains("policy_ids") || !payload.at("policy_ids").is_array()) return ids;
    for (const auto& item : payload.at("policy_ids")) ids.push_back(item.get<std::uint32_t>());
    return ids;
}

std::shared_ptr<vh::storage::CloudEngine> requireCloudEngine(const std::uint32_t vaultId) {
    const auto engine = vh::runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine) throw ::vh::ops::NotFound("Vault engine is not available.");
    if (engine->type() != vh::storage::StorageType::Cloud)
        throw ::vh::ops::Invalid("S3 price budget preflight is only available for S3 vaults.");
    return std::static_pointer_cast<vh::storage::CloudEngine>(engine);
}

json buildPreflight(const json& payload) {
    const auto vaultId = payload.at("vault_id").get<std::uint32_t>();
    const auto cloud = requireCloudEngine(vaultId);
    const auto policy = cloud->remote_policy();
    const auto summary = vh::db::query::sync::RemoteObjectIndex::summaryForVault(vaultId);
    if (summary.object_count == 0)
        throw ::vh::ops::Conflict("No remote index is available for S3 price budget preflight.");
    if (summary.isStale(policy->max_remote_index_age))
        throw ::vh::ops::Conflict("Remote index is stale; refresh it before S3 price budget preflight.");

    auto ctx = std::make_shared<vh::sync::Cloud>(cloud);
    ctx->event = std::make_shared<vh::sync::model::Event>();
    ctx->event->vault_id = vaultId;
    ctx->event->run_uuid = payload.value("run_uuid", "web-preflight");
    ctx->localFiles = vh::db::query::fs::File::listFilesInDir(vaultId);
    ctx->localMap = vh::fs::model::groupEntriesByPath(ctx->localFiles);
    ctx->s3Files = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    ctx->s3Map = vh::fs::model::groupEntriesByPath(ctx->s3Files);

    vh::sync::model::S3CostEstimate planningNotes;
    const auto plan = vh::sync::Planner::build(ctx, policy, &planningNotes);
    auto estimate = vh::sync::Planner::estimateS3Cost(plan);
    estimate.archive_tier_downloads_skipped = planningNotes.archive_tier_downloads_skipped;
    const auto budgetPriceEstimate = vh::storage::s3::pricing::estimatePlannedS3Sync(
        *cloud,
        estimate,
        {.mode = vh::storage::s3::pricing::PriceEstimateMode::BudgetConservative});

    const auto profile = cloud->s3ProviderProfile();
    const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
    const auto providerKey = costProfileId ? *costProfileId : (profile ? profile->id() : std::string{"unknown"});
    const bool providerSupported = costProfileId &&
        vh::storage::s3::pricing::isSupportedPriceBudgetProvider(*costProfileId);

    const auto decision = PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = ctx->event->run_uuid,
        .provider_key = providerKey,
        .provider_supported = providerSupported,
        .estimate = budgetPriceEstimate,
        .dry_run = true,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {},
        .gateway_scopes_only = false,
        .synthetic = false,
        .usage_source = {}
    });

    return {
        {"decision", decision},
        {"estimate", budgetPriceEstimate},
        {"plan", {
            {"upload", std::ranges::count_if(plan, [](const auto& action) { return action.type == vh::sync::model::ActionType::Upload; })},
            {"download", std::ranges::count_if(plan, [](const auto& action) { return action.type == vh::sync::model::ActionType::Download; })},
            {"index_remote_only", std::ranges::count_if(plan, [](const auto& action) { return action.type == vh::sync::model::ActionType::IndexRemoteOnly; })},
            {"delete_remote", std::ranges::count_if(plan, [](const auto& action) { return action.type == vh::sync::model::ActionType::DeleteRemote; })},
            {"delete_local", std::ranges::count_if(plan, [](const auto& action) { return action.type == vh::sync::model::ActionType::DeleteLocal; })}
        }}
    };
}

} // namespace

json Pricing::policyList(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"policies", vh::ops::pricing::listPolicies(session->user, filterFromPayload(payload))}};
}

json Pricing::policyUpsert(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"policy", vh::ops::pricing::upsertPolicy(session->user, specFromPayload(payload))}};
}

json Pricing::policyDisable(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"disabled", vh::ops::pricing::disablePolicy(
        session->user,
        pricingScopeFromPayload(payload),
        optionalStringPayload(payload, "provider_key"),
        optionalUIntPayload(payload, "vault_id"),
        optionalUIntPayload(payload, "gateway_credential_id"))}};
}

json Pricing::ledgerList(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"ledger", vh::ops::pricing::ledger(session->user, filterFromPayload(payload), limitFromPayload(payload))}};
}

json Pricing::status(const json& payload, const std::shared_ptr<Session>& session) {
    const auto status = vh::ops::pricing::status(session->user, filterFromPayload(payload), limitFromPayload(payload, 20));
    return {
        {"policies", status.policies},
        {"ledger", status.ledger},
        {"trends", status.trends},
        {"notifications", status.notifications},
        {"overrides", status.overrides}
    };
}

json Pricing::preflight(const json& payload, const std::shared_ptr<Session>& session) {
    const auto vaultId = payload.at("vault_id").get<std::uint32_t>();
    requireVaultBudgetView(session, vaultId);
    return buildPreflight(payload);
}

json Pricing::overrideRequest(const json& payload, const std::shared_ptr<Session>& session) {
    const auto vaultId = payload.at("vault_id").get<std::uint32_t>();
    if (!vh::rbac::resolver::Vault::has<vh::rbac::permission::vault::sync::SyncActionPermissions>({
        .user = session->user,
        .permission = vh::rbac::permission::vault::sync::SyncActionPermissions::Trigger,
        .vault_id = vaultId
    })) throw vh::ops::Denied("You do not have permission to request a budget override for this vault.");

    return {{"override", PriceBudgetService{}.requestOverride({
        .run_uuid = optionalStringPayload(payload, "run_uuid"),
        .vault_id = vaultId,
        .requested_by = session->user->id,
        .reason = optionalStringPayload(payload, "reason"),
        .policy_ids = policyIdsFromPayload(payload),
        .estimated_cost = optionalStringPayload(payload, "estimated_cost"),
        .currency = payload.value("currency", "USD"),
        .ttl_minutes = payload.value("ttl_minutes", 30u)
    })}};
}

json Pricing::overrideApprove(const json& payload, const std::shared_ptr<Session>& session) {
    requireSuperAdmin(session, "Only super-admins may approve S3 price budget overrides.");
    return {{"override", PriceBudgetService{}.approveOverride(requiredPricingRefId(payload, "override_id"), session->user->id)}};
}

json Pricing::overrideDeny(const json& payload, const std::shared_ptr<Session>& session) {
    requireSuperAdmin(session, "Only super-admins may deny S3 price budget overrides.");
    return {{"override", PriceBudgetService{}.denyOverride(
        requiredPricingRefId(payload, "override_id"),
        session->user->id,
        optionalStringPayload(payload, "reason"))}};
}

json Pricing::overrideList(const json& payload, const std::shared_ptr<Session>& session) {
    const auto body = payload.is_object() ? payload : json::object();
    auto vaultId = optionalVaultId(body);
    if (!session->user->isSuperAdmin()) {
        if (!vaultId) throw vh::ops::Invalid("Vault-scoped override access requires vault_id.");
        requireVaultBudgetView(session, *vaultId);
    } else if (vaultId) {
        requireVaultBudgetView(session, *vaultId);
    }
    return {{"overrides", PriceBudgetService{}.listOverrides(limitFromPayload(body), vaultId, body.value("include_expired", false))}};
}

json Pricing::notificationsList(const json& payload, const std::shared_ptr<Session>& session) {
    const auto body = payload.is_object() ? payload : json::object();
    auto vaultId = optionalVaultId(body);
    const auto limit = limitFromPayload(body);
    const auto includeAcknowledged = body.value("include_acknowledged", false);
    PriceBudgetService service;

    // `summary` always describes the OPEN alerts the caller can see (same scoping as the rows), computed by one
    // aggregate query instead of from the returned page, so `limit` never hides the count or the worst severity.
    PriceBudgetNotificationSummary summary;

    if (!session->user->isSuperAdmin()) {
        if (!vaultId) {
            auto notifications = service.listNotifications(500, std::nullopt, includeAcknowledged);
            std::erase_if(notifications, [&](const auto& notification) {
                return !notification.vault_id || !canViewVaultBudget(session, *notification.vault_id);
            });
            if (notifications.size() > limit) notifications.resize(limit);
            for (const auto& group : service.summarizeOpenNotifications())
                if (group.vault_id && canViewVaultBudget(session, *group.vault_id))
                    mergePriceBudgetNotificationSummary(summary, group.summary);
            return {{"notifications", notifications}, {"summary", summary}};
        }
        requireVaultBudgetView(session, *vaultId);
    } else if (vaultId) {
        requireVaultBudgetView(session, *vaultId);
    }
    for (const auto& group : service.summarizeOpenNotifications(vaultId))
        mergePriceBudgetNotificationSummary(summary, group.summary);
    return {{"notifications", service.listNotifications(limit, vaultId, includeAcknowledged)}, {"summary", summary}};
}

json Pricing::notificationsAck(const json& payload, const std::shared_ptr<Session>& session) {
    const auto id = requiredPricingRefId(payload, "notification_id");
    const auto vaultId = optionalVaultId(payload);
    PriceBudgetService service;

    if (!session->user->isSuperAdmin()) {
        if (!vaultId) throw vh::ops::Invalid("Vault-scoped notification acknowledgement requires vault_id.");
        requireVaultBudgetView(session, *vaultId);
        const auto visible = service.listNotifications(500, vaultId, true);
        if (std::ranges::none_of(visible, [id](const auto& notification) { return notification.id == id; }))
            throw vh::ops::NotFound("Operator notification is not visible for this vault.");
    }

    return {{"notification", service.acknowledgeNotification(id, session->user->id)}};
}

}
