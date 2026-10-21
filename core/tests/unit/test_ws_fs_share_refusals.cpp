// fs.* / share.* refusals carry a typed data.code (ops::Error kinds through core::describeCurrentError) with their
// message text unchanged: malformed requests at the ws boundary, and the share resolvers' refusals. DB-free; the
// handler-level cases are in test_ws_share_{links,sessions}.cpp.

#include "ops/Error.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/RequestErrors.hpp"
#include "share/Link.hpp"
#include "share/Principal.hpp"
#include "share/PrincipalResolver.hpp"
#include "share/Session.hpp"
#include "share/TargetResolver.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <stdexcept>
#include <string>

namespace vh::test_ws_fs_share_refusals {

using nlohmann::json;

// What the ws answer for `fn`'s exception carries: {code or "", message}.
std::pair<std::string, std::string> wsRefusal(const std::function<void()>& fn) {
    try {
        fn();
    } catch (...) {
        const auto reply = protocols::ws::core::describeCurrentError();
        return {reply.data.is_object() ? reply.data.value("code", "") : "", reply.message};
    }
    ADD_FAILURE() << "no exception";
    return {};
}

// As a handler's function-try-block runs it.
void throughHandlerBoundary(const std::function<void()>& fn) {
    try {
        fn();
    } catch (...) {
        protocols::ws::handler::rethrowRequestErrorsAsInvalid();
    }
}

TEST(WsFsShareRefusals, MalformedRequestsAnswerInvalidWithTheirText) {
    const auto missing = wsRefusal([] {
        throughHandlerBoundary([] { (void)json{{"path", "/"}}.at("vault_id"); });
    });
    EXPECT_EQ(missing.first, "invalid");
    EXPECT_NE(missing.second.find("vault_id"), std::string::npos) << missing.second;

    const auto wrongType = wsRefusal([] {
        throughHandlerBoundary([] { (void)json{{"vault_id", "x"}}.at("vault_id").get<uint32_t>(); });
    });
    EXPECT_EQ(wrongType.first, "invalid");

    EXPECT_EQ(wsRefusal([] {
        throughHandlerBoundary([] { throw std::invalid_argument("Missing required share field: root_path"); });
    }), std::make_pair(std::string("invalid"), std::string("Missing required share field: root_path")));
}

TEST(WsFsShareRefusals, OtherErrorsCrossTheBoundaryUnchanged) {
    EXPECT_EQ(wsRefusal([] { throughHandlerBoundary([] { throw ops::Denied("Permission denied: nope"); }); }),
              std::make_pair(std::string("denied"), std::string("Permission denied: nope")));
    EXPECT_EQ(wsRefusal([] { throughHandlerBoundary([] { throw ops::NotFound("Path does not exist: /x"); }); }),
              std::make_pair(std::string("not_found"), std::string("Path does not exist: /x")));
    // A fault stays a fault: no code.
    EXPECT_EQ(wsRefusal([] { throughHandlerBoundary([] { throw std::runtime_error("Share manager is unavailable"); }); }),
              std::make_pair(std::string(), std::string("Share manager is unavailable")));
}

TEST(WsFsShareRefusals, ShareResolverRefusalsAreTyped) {
    share::Principal principal;
    principal.root_path = "/docs";
    EXPECT_EQ(wsRefusal([&] { (void)share::TargetResolver::shareRelativePath(principal, "/other/a.txt"); }),
              std::make_pair(std::string("denied"), std::string("Share filesystem target escapes share root")));

    share::Link link;
    link.id = "link-1";
    link.created_at = link.updated_at = 1000;
    link.revoked_at = 1500;
    share::Session session;
    session.id = "session-1";
    session.share_id = "link-1";
    session.expires_at = 5000;
    EXPECT_EQ(wsRefusal([&] { (void)share::PrincipalResolver::resolve(link, session, std::time_t{2000}); }),
              std::make_pair(std::string("denied"), std::string("share principal resolution failed: share inactive")));
}

}
