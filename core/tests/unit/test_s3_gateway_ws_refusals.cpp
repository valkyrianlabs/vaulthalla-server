// s3.gateway.* request refusals the ws handler raises itself (before any ops:: call) answer a typed data.code with
// their message unchanged. DB-free: each case is refused while parsing the payload.

#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/S3Gateway.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <string>

namespace vh::test_s3_gateway_ws_refusals {

using json = nlohmann::json;
using Handler = protocols::ws::handler::S3Gateway;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;

SessionPtr humanSession() {
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    identities::UserState state;
    state.name = "gw_refusal_reader";
    state.roles.admin = std::make_shared<rbac::role::Admin>();
    session->user = identities::User::detached(4251, std::move(state));
    return session;
}

// The ws reply the handler templates would send for what `call` throws.
protocols::ws::core::ErrorReply refusal(const std::function<json(const json&, const SessionPtr&)>& call,
                                        const json& payload) {
    try {
        (void)call(payload, humanSession());
    } catch (...) {
        return protocols::ws::core::describeCurrentError();
    }
    ADD_FAILURE() << "the request was not refused: " << payload.dump();
    return {};
}

void expectRefusal(const protocols::ws::core::ErrorReply& reply, const std::string& code, const std::string& message) {
    EXPECT_EQ(reply.data.value("code", ""), code) << reply.message;
    EXPECT_EQ(reply.message, message);
}

TEST(S3GatewayWsRefusals, MissingVaultIsInvalid) {
    expectRefusal(refusal(Handler::bucketsBind, json{{"bucket_name", "photos"}}), "invalid",
                  "vault_id or vault_name is required");
}

TEST(S3GatewayWsRefusals, MissingUpstreamKeyIsNotFound) {
    expectRefusal(refusal(Handler::bucketsCreateRemoteCache, json{{"upstream_bucket", "b"}}), "not_found",
                  "Upstream API key not found.");
}

TEST(S3GatewayWsRefusals, BudgetCredentialAndScopeAreInvalid) {
    expectRefusal(refusal(Handler::budgetPolicyDisable, json{{"scope", "gateway_credential"}}), "invalid",
                  "gateway_credential_id is required");
    expectRefusal(refusal(Handler::budgetPolicyUpsert, json{{"scope", "gateway_credential"}}), "invalid",
                  "gateway_credential_id is required");
    expectRefusal(refusal(Handler::budgetPolicyUpsert, json{{"scope", "vault"}, {"gateway_credential_id", 3}}),
                  "invalid", "S3 gateway budget endpoints only manage gateway credential budget policies.");
}

}
