// vh-test-tier: db-only
// `vh cloud link|status|unlink` through ops::cloud, against a fake Vaulthalla Cloud (the http transport seam): the
// link request's proof, the signed claim, the signed status and unlink requests, each verified with the public key the
// request registered, as the cloud verifies them. Also who may run it, denial and expiry, and an unreachable cloud.
#include "../helpers/db_suite.hpp"
#include "cloud/Identity.hpp"
#include "cloud/Signing.hpp"
#include "config/Registry.hpp"
#include "db/query/cloud/Link.hpp"
#include "ops/Cloud.hpp"
#include "ops/Error.hpp"
#include "storage/s3/curl/Http.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <map>
#include <string>
#include <vector>

namespace vh::test_cloud_link {

namespace http = vh::storage::s3::curl::http;
namespace oc = vh::ops::cloud;
using nlohmann::json;

// What the cloud does with each request, enough to check the server's side of the protocol.
struct FakeCloud {
    std::string publicKey;  // base64url, from the link request
    std::string requestId = "0123456789abcdefghjkmnpqrs";
    std::string installation = "kceypk9vfn5tv6yx5c6qpfebdm";
    std::string claimAnswer = "pending";
    bool reachable = true;
    bool revoked = false;
    std::vector<std::string> calls;  // "METHOD path"

    static std::vector<uint8_t> unb64(const std::string& s) {
        std::vector<uint8_t> out(s.size());
        std::size_t len = 0;
        if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &len, nullptr,
                              sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
            return {};
        out.resize(len);
        return out;
    }
    bool verifies(const std::string& message, const std::string& signature) const {
        const auto sig = unb64(signature), pk = unb64(publicKey);
        return sig.size() == 64 && pk.size() == 32 &&
               crypto_sign_verify_detached(sig.data(), reinterpret_cast<const unsigned char*>(message.data()),
                                           message.size(), pk.data()) == 0;
    }
    static std::string header(const http::Request& r, const std::string& name) {
        for (const auto& [k, v] : r.headers)
            if (k == name) return v;
        return {};
    }
    // The VHC1 checks of the cloud's accounts::authenticate (without the clock and nonce store).
    bool signedByUs(const http::Request& r, const std::string& path) const {
        const auto auth = header(r, "Authorization");
        const auto field = [&](const std::string& k) {
            const auto at = auth.find(k + "=");
            if (at == std::string::npos) return std::string();
            const auto end = auth.find(',', at);
            return auth.substr(at + k.size() + 1, end == std::string::npos ? std::string::npos : end - at - k.size() - 1);
        };
        if (!auth.starts_with("VHC1-Ed25519 ") || field("Installation") != installation) return false;
        if (header(r, "X-VHC-Content-SHA256") != cloud::sha256Hex(r.body)) return false;
        const cloud::SignedFields f{.method = r.method, .path = path, .query = "", .host = "api.vaulthalla.test",
                                    .installation = installation, .timestamp = std::stoll(field("Timestamp")),
                                    .nonce = field("Nonce"), .body_sha256 = cloud::sha256Hex(r.body)};
        return verifies(cloud::stringToSign(f), field("Signature"));
    }

    http::Response operator()(const http::Request& r) {
        const auto prefix = std::string("https://api.vaulthalla.test");
        const auto path = r.url.substr(prefix.size());
        calls.push_back(r.method + " " + path);
        http::Response res;
        if (!reachable || !r.url.starts_with(prefix)) {
            res.transport_ok = false;
            res.transport_error = "Couldn't connect to server";
            return res;
        }
        const auto reply = [&](const long status, const json& body) {
            res.status = status;
            res.body = body.is_null() ? "" : body.dump();
            return res;
        };
        const auto body = r.body.empty() ? json() : json::parse(r.body);
        if (r.method == "POST" && path == "/v1/link-requests") {
            publicKey = body.at("public_key");
            const std::string proof = "vhc-link-request-v1\n" + publicKey + "\n" + body.at("name").get<std::string>() +
                                      "\n" + body.at("kind").get<std::string>();
            if (body.at("kind") != "server" || !verifies(proof, body.at("proof")))
                return reply(400, {{"error", {{"code", "invalid_argument"}, {"message", "bad proof"}}}});
            return reply(201, {{"request_id", requestId}, {"user_code", "WXYZ-1234"}, {"expires_at", 4102444800}});
        }
        if (r.method == "POST" && path == "/v1/link-requests/" + requestId + "/claim") {
            const auto message = "vhc-link-claim-v1\n" + requestId + "\n" + std::to_string(body.at("timestamp").get<int64_t>());
            if (!verifies(message, body.at("signature")))
                return reply(401, {{"error", {{"code", "unauthenticated"}, {"message", "bad claim"}}}});
            if (claimAnswer == "linked") return reply(200, {{"status", "linked"}, {"installation_id", installation}, {"account_id", 7}});
            return reply(200, {{"status", claimAnswer}});
        }
        if (path == "/v1/installation" && (r.method == "GET" || r.method == "DELETE")) {
            if (revoked || !signedByUs(r, path))
                return reply(401, {{"error", {{"code", "unauthenticated"}, {"message", "request signature rejected"}}}});
            if (r.method == "DELETE") {
                revoked = true;
                return reply(204, nullptr);
            }
            return reply(200, {{"id", installation}, {"account_id", 7}, {"kind", "server"}});
        }
        return reply(404, {{"error", {{"code", "not_found"}, {"message", "no route"}}}});
    }
};

class CloudLinkDbTest : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() { (void)setUpDbSuite("cloud_link"); }
    static void TearDownTestSuite() { tearDownDbSuite(); }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        previousEndpoint_ = config::Registry::get().cloud.endpoint;
        auto cfg = config::Registry::get();
        cfg.cloud.endpoint = "https://api.vaulthalla.test";
        config::Registry::set(cfg);
        http::setTransportForTesting([this](const http::Request& r) { return cloud_(r); });
        db::query::cloud::Link::clear();
        cloud::identity::destroy();
    }
    void TearDown() override {
        if (!IsSkipped()) {
            http::setTransportForTesting(std::nullopt);
            db::query::cloud::Link::clear();
            cloud::identity::destroy();
            auto cfg = config::Registry::get();
            cfg.cloud.endpoint = previousEndpoint_;
            config::Registry::set(cfg);
        }
        Suite::TearDown();
    }

    FakeCloud cloud_;
    std::string previousEndpoint_;
};

TEST_F(CloudLinkDbTest, LinksAfterApprovalAndSignsEveryLaterRequest) {
    EXPECT_EQ(oc::status(superUser).state, "unlinked");
    const auto started = oc::startLink(superUser, oc::Channel::Cli, std::string("home server"));
    EXPECT_EQ(started.user_code, "WXYZ-1234");
    EXPECT_EQ(started.name, "home server");
    EXPECT_EQ(started.fingerprint.size(), 19u);
    EXPECT_EQ(oc::status(superUser).state, "pending");
    ASSERT_TRUE(cloud::identity::load().has_value()) << "the identity key is sealed while a request is pending";

    EXPECT_EQ(oc::claimLink(superUser, oc::Channel::Cli).status, "pending");
    cloud_.claimAnswer = "linked";
    const auto claimed = oc::claimLink(superUser, oc::Channel::Cli);
    EXPECT_EQ(claimed.status, "linked");
    EXPECT_EQ(claimed.installation_id, cloud_.installation);
    EXPECT_EQ(claimed.account_id, 7);
    EXPECT_THROW((void)oc::startLink(superUser, oc::Channel::Cli, std::nullopt), ops::Conflict) << "already linked";

    const auto s = oc::status(superUser);
    EXPECT_EQ(s.state, "linked");
    EXPECT_EQ(s.cloud, "ok") << s.cloud_detail.value_or("");  // a signed GET the fake verified
    EXPECT_EQ(s.fingerprint, started.fingerprint);

    const auto u = oc::unlink(superUser, oc::Channel::Cli, false);
    EXPECT_EQ(u.was, "linked");
    EXPECT_TRUE(u.cloud_revoked);
    EXPECT_TRUE(cloud_.revoked);
    EXPECT_EQ(oc::status(superUser).state, "unlinked");
    EXPECT_FALSE(cloud::identity::load().has_value()) << "unlinking destroys the sealed key";
    EXPECT_EQ(cloud_.calls, (std::vector<std::string>{"POST /v1/link-requests",
                                                      "POST /v1/link-requests/" + cloud_.requestId + "/claim",
                                                      "POST /v1/link-requests/" + cloud_.requestId + "/claim",
                                                      "GET /v1/installation", "DELETE /v1/installation"}));
}

TEST_F(CloudLinkDbTest, DeniedAndExpiredRequestsLeaveNothingBehind) {
    (void)oc::startLink(superUser, oc::Channel::Cli, std::nullopt);
    cloud_.claimAnswer = "denied";
    EXPECT_EQ(oc::claimLink(superUser, oc::Channel::Cli).status, "denied");
    EXPECT_EQ(oc::status(superUser).state, "unlinked");
    EXPECT_FALSE(cloud::identity::load().has_value());
    EXPECT_THROW((void)oc::claimLink(superUser, oc::Channel::Cli), ops::NotFound);

    (void)oc::startLink(superUser, oc::Channel::Cli, std::nullopt);
    // A second request replaces the first, with a new key.
    const auto firstKey = cloud_.publicKey;
    (void)oc::startLink(superUser, oc::Channel::Cli, std::nullopt);
    EXPECT_NE(cloud_.publicKey, firstKey);
    cloud_.claimAnswer = "expired";
    EXPECT_EQ(oc::claimLink(superUser, oc::Channel::Cli).status, "expired");
    EXPECT_EQ(oc::status(superUser).state, "unlinked");
}

TEST_F(CloudLinkDbTest, OnlyASuperAdminAtTheTerminal) {
    EXPECT_THROW((void)oc::startLink(superUser, oc::Channel::Agent, std::nullopt), ops::Denied);
    EXPECT_THROW((void)oc::unlink(superUser, oc::Channel::Agent, true), ops::Denied);
    EXPECT_THROW((void)oc::startLink(nullptr, oc::Channel::Cli, std::nullopt), ops::Denied);
    EXPECT_THROW((void)oc::startLink(superUser, oc::Channel::Cli, std::string("bad\nname")), ops::Invalid);
    EXPECT_TRUE(cloud_.calls.empty()) << "nothing reached the cloud";
}

TEST_F(CloudLinkDbTest, AnUnreachableCloudKeepsTheLinkUnlessForced) {
    (void)oc::startLink(superUser, oc::Channel::Cli, std::nullopt);
    cloud_.claimAnswer = "linked";
    (void)oc::claimLink(superUser, oc::Channel::Cli);
    cloud_.reachable = false;
    EXPECT_EQ(oc::status(superUser).cloud, "unreachable");
    try {
        (void)oc::unlink(superUser, oc::Channel::Cli, false);
        FAIL() << "unlink without the cloud's confirmation";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "cloud_unreachable");
    }
    EXPECT_EQ(oc::status(superUser).state, "linked");
    const auto u = oc::unlink(superUser, oc::Channel::Cli, true);
    EXPECT_FALSE(u.cloud_revoked);
    EXPECT_EQ(oc::status(superUser).state, "unlinked");

    // A link request the cloud can't take leaves no key behind.
    try {
        (void)oc::startLink(superUser, oc::Channel::Cli, std::nullopt);
        FAIL();
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "cloud_unreachable");
    }
    EXPECT_FALSE(cloud::identity::load().has_value());
}

TEST_F(CloudLinkDbTest, AServerRevokedOnVaulthallaCloudSaysSo) {
    (void)oc::startLink(superUser, oc::Channel::Cli, std::nullopt);
    cloud_.claimAnswer = "linked";
    (void)oc::claimLink(superUser, oc::Channel::Cli);
    cloud_.revoked = true;
    EXPECT_EQ(oc::status(superUser).cloud, "revoked");
    // Unlinking still works: the cloud already refuses the key.
    EXPECT_EQ(oc::unlink(superUser, oc::Channel::Cli, false).was, "linked");
}

}
