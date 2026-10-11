#include "protocols/ws/handler/vault/Vaults.hpp"
#include "vault/model/APIKey.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "vault/model/Vault.hpp"
#include "vault/model/S3Vault.hpp"
#include "sync/model/Policy.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "db/query/vault/Vault.hpp"
#include "db/query/sync/Policy.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/identities/User.hpp"
#include "db/encoding/interval.hpp"
#include "storage/Manager.hpp"
#include "storage/Engine.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "protocols/ws/Session.hpp"
#include "ops/Vaults.hpp"
#include "config/util.hpp"
#include "db/encoding/timestamp.hpp"
#include "vault/model/Deletion.hpp"
#include "runtime/Deps.hpp"
#include "sync/Controller.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "rbac/permission/admin/Vaults.hpp"

#include <nlohmann/json.hpp>
#include <boost/algorithm/string.hpp>

#include <chrono>
#include <mutex>
#include <sstream>
#include <unordered_map>

using namespace vh::protocols::ws::handler;
using namespace vh::vault::model;
using namespace vh::storage;
using namespace vh::sync::model;
using namespace vh::rbac;
using json = nlohmann::json;

namespace {
    std::optional<std::string> optionalString(const json& payload, const char* key) {
        if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
        const auto value = payload.at(key).get<std::string>();
        return value.empty() ? std::optional<std::string>{} : std::make_optional(value);
    }

    std::chrono::seconds parsePolicyInterval(const json& value) {
        if (value.is_number_integer()) return Policy::clampInterval(std::chrono::seconds(value.get<int64_t>()));
        if (!value.is_string()) throw std::runtime_error("sync.interval must be a string or number of seconds");

        const auto raw = value.get<std::string>();
        try {
            return Policy::clampInterval(vh::db::encoding::parseSyncInterval(raw));
        } catch (const std::exception&) {
            std::chrono::seconds total{0};
            std::stringstream ss(raw);
            std::string token;
            bool sawToken = false;
            while (ss >> token) {
                if (token == "0s" || token == "0m" || token == "0h" || token == "0d") continue;
                total += vh::db::encoding::parseSyncInterval(token);
                sawToken = true;
            }
            if (!sawToken) throw;
            return Policy::clampInterval(total);
        }
    }

    std::optional<uint64_t> parseBudgetValue(const json& value) {
        if (value.is_null()) return std::nullopt;
        if (!value.is_number_unsigned() && !value.is_number_integer())
            throw std::runtime_error("S3 request budget values must be numbers or null");
        if (value.is_number_integer() && value.get<int64_t>() < 0)
            throw std::runtime_error("S3 request budget values cannot be negative");
        return value.get<uint64_t>();
    }

    std::optional<std::optional<uint64_t>> budgetField(const json& budget, const char* key) {
        if (!budget.contains(key)) return std::nullopt;
        return parseBudgetValue(budget.at(key));
    }

    // The ws sync object (a patch: absent keys stay as they are) in the shared op's terms.
    vh::ops::vaults::SyncPatch syncPatchFromPayload(const json& sync) {
        vh::ops::vaults::SyncPatch patch;
        if (!sync.is_object()) return patch;
        if (sync.contains("interval")) patch.interval = parsePolicyInterval(sync.at("interval"));
        if (sync.contains("enabled")) patch.enabled = sync.at("enabled").get<bool>();
        if (sync.contains("strategy")) patch.strategy = sync.at("strategy").get<std::string>();
        if (sync.contains("conflict_policy")) patch.conflict_policy = sync.at("conflict_policy").get<std::string>();
        if (sync.contains("max_remote_index_age_seconds")) {
            const auto& v = sync.at("max_remote_index_age_seconds");
            if (v.is_null()) patch.max_remote_index_age = std::optional<std::chrono::seconds>{};
            else {
                const auto seconds = v.get<int64_t>();
                if (seconds < 0) throw std::runtime_error("sync.max_remote_index_age_seconds cannot be negative");
                patch.max_remote_index_age = std::optional<std::chrono::seconds>{std::chrono::seconds(seconds)};
            }
        }
        if (sync.contains("s3_request_budget")) {
            const auto& budget = sync.at("s3_request_budget");
            if (!budget.is_object()) throw std::runtime_error("sync.s3_request_budget must be an object");
            patch.s3_budget.list = budgetField(budget, "list_requests");
            patch.s3_budget.head = budgetField(budget, "head_requests");
            patch.s3_budget.get = budgetField(budget, "get_requests");
            patch.s3_budget.put = budgetField(budget, "put_requests");
            patch.s3_budget.copy = budgetField(budget, "copy_requests");
            patch.s3_budget.del = budgetField(budget, "delete_requests");
            patch.s3_budget.downloaded_bytes = budgetField(budget, "downloaded_bytes");
        }
        return patch;
    }

    template<class T>
    std::optional<T> vaultPayloadField(const json& payload, const char* key) {
        if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
        return payload.at(key).get<T>();
    }

    bool vaultPayloadAcceptsWaiver(const json& payload) {
        return payload.value("accept_encryption_waiver", false);
    }

    json vaultDetailsJson(const vh::ops::vaults::Details& details) {
        json out;
        if (details.vault->type == VaultType::S3) {
            out = *std::static_pointer_cast<S3Vault>(details.vault);
            if (const auto remote = std::dynamic_pointer_cast<RemotePolicy>(details.sync)) out["sync"] = *remote;
        } else out = *details.vault;
        out["owner"] = details.owner_name;
        return out;
    }
}

json Vaults::add(const json &payload, const std::shared_ptr<Session> &session) {
    const auto typeName = boost::algorithm::to_lower_copy(payload.at("type").get<std::string>());
    if (typeName != "local" && typeName != "s3") throw std::runtime_error("Unsupported vault type: " + typeName);
    const auto type = typeName == "s3" ? VaultType::S3 : VaultType::Local;

    vh::ops::vaults::Create req{
        .name = payload.at("name").get<std::string>(),
        .type = type,
        .owner_id = vaultPayloadField<uint32_t>(payload, "owner_id"),
        .description = payload.value("description", std::string{}),
        .quota = payload.value("quota", static_cast<uintmax_t>(0)),
        .slug = payload.value("slug", std::string{}),
        .fuse_name = optionalString(payload, "fuse_name"),
        .s3 = std::nullopt,
        // Older clients put sync settings at the top level of an S3 add.
        .sync = syncPatchFromPayload(payload.contains("sync") ? payload.at("sync") : (type == VaultType::S3 ? payload : json::object())),
        .accept_waiver = vaultPayloadAcceptsWaiver(payload)
    };
    if (type == VaultType::S3)
        req.s3 = vh::ops::vaults::S3Spec{
            .api_key_id = payload.at("api_key_id").get<unsigned int>(),
            .bucket = payload.at("bucket").get<std::string>(),
            .storage_tier = vaultPayloadField<std::string>(payload, "storage_tier_id"),
            .encrypt_upstream = vaultPayloadField<bool>(payload, "encrypt_upstream")
        };

    const auto vault = vh::ops::vaults::create(session->user, req);
    return {{"vault", *vault}};
}

json Vaults::update(const json &payload, const std::shared_ptr<Session> &session) {
    const auto id = payload.at("id").get<unsigned int>();
    if (payload.contains("type")) {
        const auto current = vh::ops::vaults::get(session->user, id).vault->type;
        if (from_string(payload.at("type").get<std::string>()) != current)
            throw std::runtime_error("A vault's type cannot be changed");
    }

    vh::ops::vaults::Update req{
        .id = id,
        .name = vaultPayloadField<std::string>(payload, "name"),
        .description = vaultPayloadField<std::string>(payload, "description"),
        .quota = vaultPayloadField<uintmax_t>(payload, "quota"),
        .owner_id = vaultPayloadField<uint32_t>(payload, "owner_id"),
        .slug = vaultPayloadField<std::string>(payload, "slug"),
        .fuse_name = payload.contains("fuse_name") ? std::optional<std::optional<std::string>>(optionalString(payload, "fuse_name"))
                                                   : std::nullopt,
        .is_active = vaultPayloadField<bool>(payload, "is_active"),
        .api_key_id = vaultPayloadField<unsigned int>(payload, "api_key_id"),
        .bucket = vaultPayloadField<std::string>(payload, "bucket"),
        .storage_tier = payload.contains("storage_tier_id")
            ? std::optional<std::optional<std::string>>(vaultPayloadField<std::string>(payload, "storage_tier_id"))
            : std::nullopt,
        .encrypt_upstream = vaultPayloadField<bool>(payload, "encrypt_upstream"),
        .sync = syncPatchFromPayload(payload.contains("sync") ? payload.at("sync") : json::object()),
        .accept_waiver = vaultPayloadAcceptsWaiver(payload)
    };
    const auto vault = vh::ops::vaults::update(session->user, req);
    return {{"vault", *vault}};
}

json Vaults::remove(const json &payload, const std::shared_ptr<Session> &session) {
    const auto deletion = vh::ops::vaults::remove(session->user, {
        .id = payload.at("id").get<unsigned int>(),
        .now = payload.value("now", false),
        .delete_upstream = vaultPayloadField<bool>(payload, "delete_upstream"),
        .confirm_now = payload.value("confirm_now", false),
        .accept_key_loss = payload.value("accept_key_loss", false)
    });
    return {{"deletion", deletion ? json(*deletion) : json(nullptr)}};
}

json Vaults::removalPlan(const json &payload, const std::shared_ptr<Session> &session) {
    const auto plan = vh::ops::vaults::removalPlan(session->user, payload.at("id").get<unsigned int>());
    return {{"plan", {
        {"vault_id", plan.vault->id},
        {"name", plan.vault->name},
        {"type", to_string(plan.vault->type)},
        {"provider", plan.provider.empty() ? json(nullptr) : json(plan.provider)},
        {"bucket", plan.bucket.empty() ? json(nullptr) : json(plan.bucket)},
        {"encrypted_upstream", plan.encrypted_upstream},
        {"key_version", plan.key_version},
        {"key_exported", plan.keyExported()},
        {"key_exported_at", plan.key_exported_at ? json(vh::db::encoding::timestampToString(*plan.key_exported_at)) : json(nullptr)},
        {"retention_window", vh::config::durationToString(plan.retention_window)},
        {"retention_window_seconds", plan.retention_window.count()},
        {"key_retention_window", vh::config::durationToString(plan.key_retention_window)},
        {"key_retention_window_seconds", plan.key_retention_window.count()},
        {"export_command", plan.export_command}
    }}};
}

json Vaults::listDeleted(const std::shared_ptr<Session> &session) {
    return {{"deleted", json(vh::ops::vaults::listDeleted(session->user))}};
}

json Vaults::restore(const json &payload, const std::shared_ptr<Session> &session) {
    const auto vault = vh::ops::vaults::restore(session->user, payload.at("id").get<unsigned int>());
    return {{"vault", *vault}};
}

json Vaults::get(const json &payload, const std::shared_ptr<Session> &session) {
    return {{"vault", vaultDetailsJson(vh::ops::vaults::get(session->user, payload.at("id").get<unsigned int>()))}};
}

json Vaults::list(const std::shared_ptr<Session> &session) {
    // Each row also carries the owner's name (as storage.vault.get does), so a list needs no per-owner user lookup,
    // which a caller allowed to see a vault may not be allowed to make (#161).
    json rows = vh::ops::vaults::list(session->user);
    std::unordered_map<uint32_t, std::string> owners;
    for (auto& row : rows) {
        const auto ownerId = row.at("owner_id").get<uint32_t>();
        auto it = owners.find(ownerId);
        if (it == owners.end()) {
            const auto owner = vh::identities::manager().user(ownerId);
            // Same as storage.vault.get: an owner that no longer resolves is "".
            it = owners.emplace(ownerId, owner ? owner->name() : std::string{}).first;
        }
        row["owner"] = it->second;
    }
    return json{{"vaults", std::move(rows)}};
}

json Vaults::sync(const json &payload, const std::shared_ptr<Session> &session) {
    const auto started = vh::ops::vaults::triggerSync(session->user, payload.at("id").get<unsigned int>());
    return {{"status", started == vh::ops::vaults::SyncStart::Started ? "started" : "rerun_queued"}};
}
