#pragma once

#include "sync/model/Policy.hpp"
#include "db/Fwd.hpp"
#include "sync/model/Action.hpp"
#include "storage/s3/Controller.hpp"
#include "fs/Fwd.hpp"
#include "sync/Fwd.hpp"

#include <string>
#include <optional>
#include <chrono>
#include <nlohmann/json_fwd.hpp>
#include <memory>

namespace vh::sync::model {

enum class S3BudgetPreset {
    Conservative,
    Balanced,
    Bulk,
    Unlimited
};

[[nodiscard]] vh::storage::s3::S3RequestBudget s3RequestBudgetForPreset(S3BudgetPreset preset);
[[nodiscard]] S3BudgetPreset s3BudgetPresetFromString(const std::string& str);
[[nodiscard]] std::string to_string(S3BudgetPreset preset);
[[nodiscard]] bool s3BudgetIsUnlimited(const vh::storage::s3::S3RequestBudget& budget);
[[nodiscard]] std::string s3BudgetPresetName(const vh::storage::s3::S3RequestBudget& budget);
[[nodiscard]] std::optional<std::chrono::seconds> remoteIndexAgeFromString(const std::string& str);

struct RemotePolicy final : public Policy {
    enum class Strategy { Cache, Sync, Mirror };

    enum class ConflictPolicy {
        KeepLocal,
        KeepRemote,
        KeepNewest,
        Ask
    };

    Strategy strategy{Strategy::Cache};
    ConflictPolicy conflict_policy{ConflictPolicy::KeepLocal};
    vh::storage::s3::S3RequestBudget s3_request_budget{};
    std::optional<std::chrono::seconds> max_remote_index_age{std::chrono::hours(24)};

    RemotePolicy();
    ~RemotePolicy() override = default;
    explicit RemotePolicy(pqxx::row_ref row);

    void rehash_config() override;
    [[nodiscard]] bool resolve_conflict(const std::shared_ptr<Conflict>& conflict) const override;

    [[nodiscard]] bool wantsEnsureDirectories() const;
    [[nodiscard]] bool downloadRemoteOnly() const;
    [[nodiscard]] bool uploadLocalOnly() const;
    [[nodiscard]] bool deleteRemoteLeftovers() const;
    // An upstream removal the provider notified (#96) removes a local copy unchanged since both sides last agreed,
    // except under mirror + keep_local, where the local side is authoritative and the object is uploaded again.
    [[nodiscard]] bool propagatesRemoteRemoval() const;
    [[nodiscard]] bool deleteLocalLeftovers() const;
    [[nodiscard]] std::optional<ActionType> decideForBoth(const std::shared_ptr<fs::model::File>& L, const std::shared_ptr<fs::model::File>& R) const;
    void preflightSpaceForPlan(const std::weak_ptr<sync::Cloud>& ctx, const std::vector<Action>& plan) const;
};

void to_json(nlohmann::json& j, const RemotePolicy& s);
void from_json(const nlohmann::json& j, RemotePolicy& s);

std::string to_string(const RemotePolicy::Strategy& s);
std::string to_string(const RemotePolicy::ConflictPolicy& cp);

RemotePolicy::Strategy strategyFromString(const std::string& str);
RemotePolicy::ConflictPolicy rsConflictPolicyFromString(const std::string& str);

std::string to_string(const std::shared_ptr<RemotePolicy>& sync);

}
