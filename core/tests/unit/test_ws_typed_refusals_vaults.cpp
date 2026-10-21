// Typed ws refusals (vaults, API keys, account updates): a request refused for its own input answers data.code
// "invalid" (ops::Invalid through core::describeCurrentError) with the message it always had. DB-free: every case
// is refused before the handler reaches an op or the database.

#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "protocols/ws/handler/vault/APIKeys.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <string>

namespace vh::test_ws_typed_refusals_vaults {

using json = nlohmann::json;
using protocols::ws::core::ErrorReply;

// What the ws handler template answers for whatever `call` throws.
ErrorReply replyFor(const std::function<void()>& call) {
    try {
        call();
    } catch (...) {
        return protocols::ws::core::describeCurrentError();
    }
    ADD_FAILURE() << "the request was not refused";
    return {};
}

void expectInvalid(const ErrorReply& reply, const std::string& message) {
    EXPECT_EQ(reply.data, (json{{"code", "invalid"}})) << reply.message;
    EXPECT_EQ(reply.message, message);
}

using protocols::ws::handler::APIKeys;
using protocols::ws::handler::Vaults;

TEST(WsTypedRefusalsVaults, UnsupportedVaultTypeIsInvalid) {
    expectInvalid(replyFor([] { (void)Vaults::add({{"name", "v"}, {"type", "FTP"}}, nullptr); }),
                  "Unsupported vault type: ftp");
}

TEST(WsTypedRefusalsVaults, MalformedSyncPatchIsInvalid) {
    const auto add = [](json sync) {
        return replyFor([&] { (void)Vaults::add({{"name", "v"}, {"type", "local"}, {"sync", std::move(sync)}}, nullptr); });
    };
    expectInvalid(add({{"interval", true}}), "sync.interval must be a string or number of seconds");
    expectInvalid(add({{"interval", "5x"}}), "vault sync update: --interval must be a valid time unit (s, m, h, d)");
    expectInvalid(add({{"max_remote_index_age_seconds", -1}}), "sync.max_remote_index_age_seconds cannot be negative");
    expectInvalid(add({{"s3_request_budget", 5}}), "sync.s3_request_budget must be an object");
    expectInvalid(add({{"s3_request_budget", {{"list_requests", "many"}}}}),
                  "S3 request budget values must be numbers or null");
    expectInvalid(add({{"s3_request_budget", {{"get_requests", -3}}}}), "S3 request budget values cannot be negative");

    // storage.vault.update parses the same patch before calling the op.
    expectInvalid(replyFor([] { (void)Vaults::update({{"id", 1}, {"sync", {{"interval", "abc"}}}}, nullptr); }),
                  "vault sync update: --interval must be a positive integer");
}

TEST(WsTypedRefusalsVaults, UnknownApiKeyProviderIsInvalid) {
    expectInvalid(replyFor([] {
                      (void)APIKeys::add({{"name", "k"}, {"provider", "Nope"}, {"access_key", "a"},
                                          {"secret_access_key", "s"}, {"endpoint", "https://e"}},
                                         nullptr);
                  }),
                  "Invalid S3Provider string: Nope");
}

TEST(WsTypedRefusalsVaults, UnsupportedUserUpdateFieldsAreInvalid) {
    const auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    identities::UserState state;
    state.name = "typed_refusal_actor";
    state.roles.admin = std::make_shared<rbac::role::Admin>();
    session->user = identities::User::detached(4244, std::move(state));

    expectInvalid(replyFor([&] { (void)protocols::ws::handler::Auth::updateUser({{"protected", true}}, session); }),
                  "Unsupported field in user update");
    expectInvalid(replyFor([&] { (void)protocols::ws::handler::Auth::updateUser({{"password", "x"}}, session); }),
                  "Use auth.user.change_password to change or reset a password");
}

}
