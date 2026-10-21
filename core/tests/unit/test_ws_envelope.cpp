// The ws envelope: what answers look like (requestId echo, empty data omitted, faults as ERROR answers to the
// request's own command) and how unroutable frames are answered (parse_error with error + requestId). DB-free.

#include "protocols/ws/Envelope.hpp"
#include "protocols/ws/model/Response.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

namespace vh::test_ws_envelope {

using json = nlohmann::json;
using protocols::ws::model::Response;
namespace envelope = protocols::ws::envelope;

TEST(WsEnvelope, AnswersEchoAStringOrIntegerRequestIdAndOmitEmptyData) {
    auto ok = Response::SUCCESS("fs.dir.list", json{{"command", "fs.dir.list"}, {"requestId", "r-1"}}, json::object())
                  .frame();
    EXPECT_EQ(ok.at("command"), "fs.dir.list.response");
    EXPECT_EQ(ok.at("status"), "OK");
    EXPECT_EQ(ok.at("requestId"), "r-1");
    EXPECT_FALSE(ok.contains("data")) << "empty data is omitted; clients read a missing data as {}";

    const auto numbered = Response::SUCCESS("x", json{{"requestId", 7}}, json{{"a", 1}}).frame();
    EXPECT_EQ(numbered.at("requestId"), 7);
    EXPECT_EQ(numbered.at("data"), (json{{"a", 1}}));

    // A requestId that isn't a string or an integer is not echoed (it used to throw while answering).
    EXPECT_FALSE(Response::SUCCESS("x", json{{"requestId", json::object()}}, json{{"a", 1}}).frame().contains("requestId"));
}

TEST(WsEnvelope, InternalFaultsAreErrorAnswersToTheRequestsOwnCommand) {
    const auto fault = Response::INTERNAL_ERROR("storage.vault.list", json{{"requestId", "r-2"}}, "boom").frame();
    EXPECT_EQ(fault.at("command"), "storage.vault.list.response");
    EXPECT_EQ(fault.at("status"), "ERROR");
    EXPECT_EQ(fault.at("requestId"), "r-2");
    EXPECT_FALSE(fault.contains("data")) << "a fault carries no data.code";
    EXPECT_NE(fault.at("error").get<std::string>().find("boom"), std::string::npos);

    for (const auto status : {protocols::ws::model::Status::OK, protocols::ws::model::Status::ERROR,
                              protocols::ws::model::Status::UNAUTHORIZED})
        EXPECT_NE(protocols::ws::model::to_string(status), "UNKNOWN");
}

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
