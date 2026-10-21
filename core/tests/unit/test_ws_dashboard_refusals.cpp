// dashboard.preferences.*: an invalid key, payload or layout is a typed refusal (ops::Invalid → data.code
// "invalid") with the message the validation always had. Every case is refused before a database transaction opens,
// so the suite is DB-free.

#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/dashboard/Preferences.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <string>
#include <utility>

namespace vh::test_ws_dashboard_refusals {

using json = nlohmann::json;
using Prefs = protocols::ws::handler::dashboard::Preferences;

std::shared_ptr<protocols::ws::Session> signedIn() {
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    identities::UserState state;
    state.name = "dashboard_refusals";
    state.roles.admin = std::make_shared<rbac::role::Admin>();
    session->user = identities::User::detached(4244, std::move(state));
    return session;
}

// Runs `call`, which must refuse with ops::Invalid carrying `message`; the ws error reply then has data.code
// "invalid".
template<class Fn>
void expectInvalid(Fn&& call, const std::string& message) {
    try {
        call();
        ADD_FAILURE() << "expected a refusal: " << message;
    } catch (const ops::Invalid& e) {
        EXPECT_EQ(std::string(e.what()), message);
        const auto reply = protocols::ws::core::describeCurrentError();
        EXPECT_EQ(reply.data.value("code", ""), "invalid") << message;
        EXPECT_EQ(reply.message, message);
    } catch (const std::exception& e) {
        ADD_FAILURE() << "untyped refusal: " << e.what();
    }
}

const std::string kLongKey(65, 'k');

TEST(WsDashboardRefusals, UpdatePayloadAndLayoutRefusalsAreTyped) {
    const auto session = signedIn();
    expectInvalid([&] { Prefs::update(json::array(), session); },
                  "Dashboard preference update payload must be an object.");
    expectInvalid([&] { Prefs::update(json::object(), session); }, "Dashboard preference update requires a layout.");
    expectInvalid([&] { Prefs::update(json{{"layout", "tiles"}}, session); },
                  "Dashboard preference layout must be an object.");
    expectInvalid([&] { Prefs::update(json{{"layout", {{"cards", {{{"size", "2x1"}}}}}}}, session); },
                  "Dashboard layout card id is required.");
    expectInvalid([&] { Prefs::update(json{{"layout", {{"cards", {{{"id", "a"}, {"order", -1}}}}}}}, session); },
                  "Dashboard layout card order is out of range.");
    expectInvalid([&] { Prefs::update(json{{"preference_key", kLongKey}, {"layout", json::object()}}, session); },
                  "Dashboard preference key is too long.");
}

TEST(WsDashboardRefusals, KeyRefusalsAreTypedOnGetAndReset) {
    const auto session = signedIn();
    expectInvalid([&] { Prefs::get(json{{"preference_key", kLongKey}}, session); },
                  "Dashboard preference key is too long.");
    expectInvalid([&] { Prefs::reset(json{{"preference_key", kLongKey}}, session); },
                  "Dashboard preference key is too long.");

    // A non-string key fails reading the payload: still a refusal, with nlohmann's message.
    std::string typeError;
    try {
        (void)json{{"preference_key", 7}}.value("preference_key", std::string{});
    } catch (const json::type_error& e) {
        typeError = e.what();
    }
    ASSERT_FALSE(typeError.empty());
    expectInvalid([&] { Prefs::get(json{{"preference_key", 7}}, session); }, typeError);
}

}
