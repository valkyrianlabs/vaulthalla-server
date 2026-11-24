#pragma once

#include "nlohmann/json_fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <memory>

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct S3Gateway {
    static json status(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsCreate(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsList(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsRevoke(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsScopeUpdate(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsUpstreamSet(const json& payload, const std::shared_ptr<Session>& session);
    static json upstreamProfilesList(const json& payload, const std::shared_ptr<Session>& session);
    static json upstreamProfilesCreate(const json& payload, const std::shared_ptr<Session>& session);
    static json upstreamProfilesUpdate(const json& payload, const std::shared_ptr<Session>& session);
    static json upstreamProfilesDelete(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsDefaultRoleGet(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsDefaultRoleSet(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsDefaultRoleClear(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsSelectedVaultsList(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsSelectedVaultsReplace(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsSelectedVaultsAdd(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsSelectedVaultsRemove(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsDefaultRoleOverridesList(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsDefaultRoleOverridesAdd(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsDefaultRoleOverridesRemove(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsRolesList(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsRolesAssign(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsRolesRevoke(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsRoleOverridesList(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsRoleOverridesAdd(const json& payload, const std::shared_ptr<Session>& session);
    static json credentialsRoleOverridesRemove(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketsList(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketsBind(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketsUnbind(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketsCreateLocal(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketsCreateRemoteCache(const json& payload, const std::shared_ptr<Session>& session);
    static json budgetPolicyList(const json& payload, const std::shared_ptr<Session>& session);
    static json budgetPolicyUpsert(const json& payload, const std::shared_ptr<Session>& session);
    static json budgetPolicyDisable(const json& payload, const std::shared_ptr<Session>& session);
    static json budgetLedgerList(const json& payload, const std::shared_ptr<Session>& session);
    static json budgetStatus(const json& payload, const std::shared_ptr<Session>& session);
};

} // namespace vh::protocols::ws::handler
