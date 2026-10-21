// The ws envelope: how frames the router can't take are answered (parse_error with error + requestId). DB-free.

#include "protocols/ws/Envelope.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

namespace vh::test_ws_envelope {

using json = nlohmann::json;
namespace envelope = protocols::ws::envelope;

TEST(WsEnvelope, UnroutableFramesAreNamedAndAnsweredWithTheirRequestId) {
    EXPECT_TRUE(envelope::problem(json::array()));
    EXPECT_TRUE(envelope::problem(json{{"requestId", "r"}}));
    EXPECT_TRUE(envelope::problem(json{{"command", 3}}));
    EXPECT_TRUE(envelope::problem(json{{"command", ""}}));
    EXPECT_TRUE(envelope::problem(json{{"command", "auth.login"}, {"token", 5}}));
    EXPECT_FALSE(envelope::problem(json{{"command", "auth.login"}, {"token", nullptr}}));
    EXPECT_FALSE(envelope::problem(json{{"command", "fs.dir.list"}, {"payload", {{"vault_id", 1}}}, {"token", "t"}}));

    EXPECT_EQ(envelope::requestId(json{{"requestId", "abc"}}), "abc");
    EXPECT_EQ(envelope::requestId(json{{"requestId", 12}}), 12);
    EXPECT_TRUE(envelope::requestId(json{{"requestId", 1.5}}).is_null());
    EXPECT_TRUE(envelope::requestId(json::array()).is_null());

    const auto answer = envelope::parseError("A message needs a non-empty string 'command'", "r-3");
    EXPECT_EQ(answer.at("command"), "error");
    EXPECT_EQ(answer.at("status"), "parse_error");
    EXPECT_EQ(answer.at("requestId"), "r-3");
    EXPECT_EQ(answer.at("error"), answer.at("message")) << "error carries the text; message stays for old clients";
    EXPECT_FALSE(envelope::parseError("not JSON").contains("requestId"));

    const auto internal = envelope::internalError();
    EXPECT_EQ(internal.at("status"), "internal_error");
    EXPECT_TRUE(internal.at("error").is_string());
}

}
