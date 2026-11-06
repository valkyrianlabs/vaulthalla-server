#pragma once

#include "ops/Actor.hpp"
#include "vault/MasterRewrap.hpp"

#include <chrono>
#include <optional>

#include <nlohmann/json_fwd.hpp>

// `vh secret master status|rotate|finalize|rollback` (#352): the versioned vault_master rewrap
// (vault/MasterRewrap.hpp). Super admins only; every attempt is audited (secrets.master.*), refusals and failures
// included. Rotate, finalize and rollback need an explicit confirmation (NeedsConfirmation codes
// vault_master_rotate, vault_master_finalize, vault_master_rollback): the CLI asks, or takes --yes.
namespace vh::ops::vault_master {

[[nodiscard]] vault::master::rewrap::Status status(const Actor& actor);

struct RotateRequest {
    std::optional<std::chrono::seconds> window{};  // the recovery window (default 7 days)
    std::optional<unsigned int> batch{};           // rows per staging transaction
    bool confirmed{false};
};
[[nodiscard]] vault::master::rewrap::RotateResult rotate(const Actor& actor, const RotateRequest& request);
[[nodiscard]] vault::master::rewrap::FinalizeResult finalize(const Actor& actor, bool confirmed);
[[nodiscard]] vault::master::rewrap::RollbackResult rollback(const Actor& actor, bool confirmed);

[[nodiscard]] nlohmann::json toJson(const vault::master::rewrap::Status& status);
[[nodiscard]] nlohmann::json toJson(const vault::master::rewrap::RotateResult& result);
[[nodiscard]] nlohmann::json toJson(const vault::master::rewrap::FinalizeResult& result);
[[nodiscard]] nlohmann::json toJson(const vault::master::rewrap::RollbackResult& result);

}
