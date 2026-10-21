// The settings, email and pricing ws handlers answer refusals with a typed data.code (ops::Error through
// handler_templates.hpp), keeping their message text. DB-free: every case is refused before a query.

#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/Email.hpp"
#include "protocols/ws/handler/Pricing.hpp"
#include "protocols/ws/handler/Settings.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace vh::test_ws_admin_refusals {

using json = nlohmann::json;
using protocols::ws::Session;

std::shared_ptr<Session> sessionAs(const std::uint32_t id, rbac::role::Admin role) {
    auto session = std::make_shared<Session>(std::make_shared<protocols::ws::Router>());
    identities::UserState state;
    state.name = "refusal_user_" + std::to_string(id);
    state.roles.admin = std::make_shared<rbac::role::Admin>(std::move(role));
    session->user = identities::User::detached(id, std::move(state));
    return session;
}

std::shared_ptr<Session> superAdmin() { return sessionAs(1, rbac::role::Admin::SuperAdmin(1)); }

std::shared_ptr<Session> plainUser() { return sessionAs(4242, rbac::role::Admin::None()); }

// What the ws error response carries for the refusal `call` throws: {code (or "" without one), message}.
std::pair<std::string, std::string> refusal(const std::function<void()>& call) {
    try {
        call();
    } catch (...) {
        const auto reply = protocols::ws::core::describeCurrentError();
        const auto code = reply.data.is_object() ? reply.data.value("code", std::string{}) : std::string{};
        return {code, reply.message};
    }
    ADD_FAILURE() << "the call was not refused";
    return {};
}

using Refusal = std::pair<std::string, std::string>;

TEST(WsAdminRefusals, SettingsUpdateRefusesANonObjectAsInvalid) {
    using protocols::ws::handler::Settings;
    EXPECT_EQ(refusal([] { (void)Settings::update(json::array(), superAdmin()); }),
              Refusal("invalid", "settings.update expects an object of settings sections"));
}

TEST(WsAdminRefusals, EmailMalformedPayloadsAreInvalid) {
    using protocols::ws::handler::Email;
    EXPECT_EQ(refusal([] { (void)Email::updateConfig(json::array(), superAdmin()); }),
              Refusal("invalid", "email.config.update payload must be an object"));
    EXPECT_EQ(refusal([] { (void)Email::setProviderSecret(json::array(), superAdmin()); }),
              Refusal("invalid", "email.provider.secret.set payload must be an object"));
    EXPECT_EQ(refusal([] { (void)Email::testSend(json::array(), superAdmin()); }),
              Refusal("invalid", "email.test.send payload must be an object"));
    // The super-admin gate is checked first and was already typed.
    EXPECT_EQ(refusal([] { (void)Email::updateConfig(json::array(), plainUser()); }).first, "denied");
}

TEST(WsAdminRefusals, PricingUnknownScopeIsInvalid) {
    using protocols::ws::handler::Pricing;
    EXPECT_EQ(refusal([] { (void)Pricing::policyUpsert({{"scope", "planet"}}, superAdmin()); }),
              Refusal("invalid", "unknown price budget scope: planet"));
    EXPECT_EQ(refusal([] { (void)Pricing::policyDisable({{"scope", "planet"}}, superAdmin()); }),
              Refusal("invalid", "unknown price budget scope: planet"));
}

TEST(WsAdminRefusals, PricingVaultScopedReadsWithoutAVaultAreInvalid) {
    using protocols::ws::handler::Pricing;
    EXPECT_EQ(refusal([] { (void)Pricing::overrideList(json::object(), plainUser()); }),
              Refusal("invalid", "Vault-scoped override access requires vault_id."));
    EXPECT_EQ(refusal([] { (void)Pricing::notificationsAck({{"notification_id", 3u}}, plainUser()); }),
              Refusal("invalid", "Vault-scoped notification acknowledgement requires vault_id."));
}

}
