// Backblaze B2 read keys for vault read grants (B2Admin::createReadKey / deleteReadKey), DB-free: every request goes
// through curl::http's test transport, which answers like B2's native API (b2api v4) would and records what was sent.
//  - b2_create_key asks for exactly listBuckets, listFiles and readFiles, on exactly the vault's bucket (by its id);
//  - a parent key without writeKeys is refused before any key is requested, saying so;
//  - deleting calls b2_delete_key with the key id; a refusal is an error (the caller keeps the grant incomplete);
//  - no secret (the account key, its authorization token, the new key) reaches an error message;
//  - AWS S3 and Cloudflare R2 answer "not supported for this provider yet" with nothing sent.

#include "storage/s3/curl/Http.hpp"
#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_read_grants_b2 {

namespace admin = storage::s3::provider::admin;
namespace http = storage::s3::curl::http;
using vault::model::APIKey;
using vault::model::S3Provider;

constexpr const char* kRgB2KeyId = "0041234567890ab0000000001";
constexpr const char* kRgB2Secret = "K004ParentApplicationKeySecret0001";
constexpr const char* kRgB2Token = "4_002TokenForTheAccount0123456789";
constexpr const char* kRgB2NewSecret = "K004NewReadOnlyKeySecretValue9999";
constexpr const char* kRgApiUrl = "https://api004.backblazeb2.com";

std::shared_ptr<APIKey> rgB2Key() {
    return std::make_shared<APIKey>(1, "b2-admin", S3Provider::BackblazeB2, kRgB2KeyId, kRgB2Secret, "us-west-004",
                                    "https://s3.us-west-004.backblazeb2.com");
}

http::Response rgRespond(const long status, const std::string& body) {
    http::Response r;
    r.status = status;
    r.body = body;
    return r;
}

nlohmann::json rgAuthorize(const std::vector<std::string>& capabilities) {
    return {{"accountId", "acct0123"},
            {"authorizationToken", kRgB2Token},
            {"apiInfo", {{"storageApi", {{"apiUrl", kRgApiUrl},
                                         {"s3ApiUrl", "https://s3.us-west-004.backblazeb2.com"},
                                         {"allowed", {{"capabilities", capabilities}, {"buckets", nullptr}}}}}}}};
}

class ReadGrantsB2 : public ::testing::Test {
protected:
    std::vector<http::Request> sent;
    std::vector<std::string> parentCapabilities{"listKeys", "writeKeys", "deleteKeys", "listBuckets", "listFiles",
                                                "readFiles", "writeFiles"};
    bool deleteFails = false;

    void SetUp() override {
        storage::upstream::guard::setForTesting({});
        http::setTransportForTesting([this](const http::Request& r) { return answer(r); });
    }

    void TearDown() override {
        http::setTransportForTesting(std::nullopt);
        storage::upstream::guard::clearForTesting();
    }

    http::Response answer(const http::Request& r) {
        sent.push_back(r);
        if (r.url == admin::B2Admin::kAuthorizeUrl) return rgRespond(200, rgAuthorize(parentCapabilities).dump());
        if (r.url == std::string(kRgApiUrl) + "/b2api/v4/b2_list_buckets") {
            const auto body = nlohmann::json::parse(r.body);
            if (body.value("bucketName", "") != "vault-bucket-1")
                return rgRespond(200, R"({"buckets": []})");
            return rgRespond(200, R"({"buckets": [{"bucketId": "4a48fe8875c6214145260818", "bucketName": "vault-bucket-1",
                                                   "bucketType": "allPrivate"}]})");
        }
        if (r.url == std::string(kRgApiUrl) + "/b2api/v4/b2_create_key")
            return rgRespond(200, nlohmann::json{{"applicationKeyId", "004a0b1c2d3e4f50000000099"},
                                                 {"applicationKey", kRgB2NewSecret},
                                                 {"keyName", nlohmann::json::parse(r.body).value("keyName", "")},
                                                 {"capabilities", nlohmann::json::parse(r.body)["capabilities"]}}
                                      .dump());
        if (r.url == std::string(kRgApiUrl) + "/b2api/v4/b2_delete_key") {
            if (deleteFails)
                return rgRespond(500, R"({"status": 500, "code": "internal_error", "message": "try again"})");
            return rgRespond(200, R"({"applicationKeyId": "004a0b1c2d3e4f50000000099"})");
        }
        return rgRespond(404, R"({"status": 404, "code": "not_found", "message": "no such call"})");
    }

    [[nodiscard]] std::vector<http::Request> to(const std::string& api) const {
        std::vector<http::Request> out;
        for (const auto& r : sent)
            if (r.url.ends_with("/" + api)) out.push_back(r);
        return out;
    }

    static std::string header(const http::Request& r, const std::string& name) {
        for (const auto& [k, v] : r.headers)
            if (k == name) return v;
        return {};
    }
};

TEST_F(ReadGrantsB2, CreateKeyAsksForTheReadOnlyCapabilitiesOnTheOneBucket) {
    admin::B2Admin b2(rgB2Key());
    EXPECT_TRUE(b2.supportsReadKeys());
    const auto key = b2.createReadKey({.bucket = "vault-bucket-1", .key_name = "vh-read-abc"});

    ASSERT_EQ(to("b2_create_key").size(), 1u);
    const auto body = nlohmann::json::parse(to("b2_create_key")[0].body);
    EXPECT_EQ(body["capabilities"], nlohmann::json::array({"listBuckets", "listFiles", "readFiles"}))
        << "exactly the read-only capabilities: never listAllBucketNames, write, delete or key capabilities";
    EXPECT_EQ(body["bucketIds"], nlohmann::json::array({"4a48fe8875c6214145260818"})) << "exactly the vault's bucket";
    EXPECT_FALSE(body.contains("bucketId"));
    EXPECT_EQ(body["accountId"], "acct0123");
    EXPECT_EQ(body["keyName"], "vh-read-abc");
    EXPECT_FALSE(body.contains("validDurationInSeconds"));
    EXPECT_FALSE(body.contains("namePrefix"));
    EXPECT_EQ(header(to("b2_create_key")[0], "Authorization"), kRgB2Token);

    // The bucket was looked up by name in the same account.
    ASSERT_EQ(to("b2_list_buckets").size(), 1u);
    EXPECT_EQ(nlohmann::json::parse(to("b2_list_buckets")[0].body),
              (nlohmann::json{{"accountId", "acct0123"}, {"bucketName", "vault-bucket-1"}}));
    // b2_authorize_account with HTTP Basic over the parent key.
    ASSERT_EQ(sent.front().url, admin::B2Admin::kAuthorizeUrl);
    EXPECT_TRUE(header(sent.front(), "Authorization").starts_with("Basic "));

    EXPECT_EQ(key.key_id, "004a0b1c2d3e4f50000000099");
    EXPECT_EQ(key.secret, kRgB2NewSecret);
    EXPECT_EQ(key.bucket_id, "4a48fe8875c6214145260818");
    EXPECT_EQ(key.endpoint, "https://s3.us-west-004.backblazeb2.com");
    EXPECT_EQ(key.region, "us-west-004");
    EXPECT_EQ(key.capabilities, admin::kReadKeyCapabilities());
}

TEST_F(ReadGrantsB2, AParentKeyWithoutWriteKeysIsRefusedBeforeAnyKeyIsRequested) {
    parentCapabilities = {"listBuckets", "listFiles", "readFiles", "writeFiles"};
    admin::B2Admin b2(rgB2Key());
    try {
        (void)b2.createReadKey({.bucket = "vault-bucket-1", .key_name = "vh-read-abc"});
        ADD_FAILURE() << "created a key without writeKeys";
    } catch (const admin::CapabilityMissing& e) {
        EXPECT_EQ(e.capability, "writeKeys");
        EXPECT_NE(std::string(e.what()).find("writeKeys"), std::string::npos) << e.what();
    }
    EXPECT_TRUE(to("b2_create_key").empty());
    EXPECT_TRUE(to("b2_list_buckets").empty());
}

TEST_F(ReadGrantsB2, ABucketTheKeyDoesNotSeeIsRefused) {
    admin::B2Admin b2(rgB2Key());
    EXPECT_THROW((void)b2.createReadKey({.bucket = "another-bucket", .key_name = "vh-read-abc"}), admin::ProviderError);
    EXPECT_TRUE(to("b2_create_key").empty());
    EXPECT_THROW((void)b2.createReadKey({.bucket = "vault-bucket-1", .key_name = "bad name!"}), std::invalid_argument);
}

TEST_F(ReadGrantsB2, AProtectedBucketGetsNoKey) {
    storage::upstream::guard::setForTesting(
        {{.provider = "backblaze-b2", .account_ref = std::string("s3.us-west-004.backblazeb2.com"), .bucket = "vault-bucket-1"}});
    admin::B2Admin b2(rgB2Key());
    EXPECT_THROW((void)b2.createReadKey({.bucket = "vault-bucket-1", .key_name = "vh-read-abc"}),
                 storage::upstream::BucketProtected);
    EXPECT_TRUE(sent.empty());
}

TEST_F(ReadGrantsB2, DeleteKeyCallsB2DeleteKeyAndAFailureIsAnError) {
    admin::B2Admin b2(rgB2Key());
    b2.deleteReadKey("004a0b1c2d3e4f50000000099");
    ASSERT_EQ(to("b2_delete_key").size(), 1u);
    EXPECT_EQ(nlohmann::json::parse(to("b2_delete_key")[0].body),
              (nlohmann::json{{"applicationKeyId", "004a0b1c2d3e4f50000000099"}}));

    deleteFails = true;
    try {
        b2.deleteReadKey("004a0b1c2d3e4f50000000099");
        ADD_FAILURE() << "a failed delete reported success";
    } catch (const admin::ProviderError& e) {
        const std::string what = e.what();
        EXPECT_EQ(what.find(kRgB2Token), std::string::npos) << what;
        EXPECT_EQ(what.find(kRgB2Secret), std::string::npos) << what;
        EXPECT_NE(what.find("b2_delete_key"), std::string::npos) << what;
    }
}

TEST_F(ReadGrantsB2, NoSecretReachesAnError) {
    // Authorization refused, with the provider echoing what it got.
    http::setTransportForTesting([this](const http::Request& r) {
        sent.push_back(r);
        return rgRespond(401, std::string(R"({"status": 401, "code": "unauthorized", "message": "bad key )") + kRgB2Secret +
                                  " " + kRgB2KeyId + R"("})");
    });
    admin::B2Admin b2(rgB2Key());
    try {
        (void)b2.createReadKey({.bucket = "vault-bucket-1", .key_name = "vh-read-abc"});
        ADD_FAILURE() << "an unauthorized key created a key";
    } catch (const admin::ProviderError& e) {
        EXPECT_EQ(std::string(e.what()).find(kRgB2Secret), std::string::npos) << e.what();
    }
}

TEST_F(ReadGrantsB2, OtherProvidersAreNotSupportedYetAndSendNothing) {
    auto aws = std::make_shared<APIKey>(1, "aws", S3Provider::AWS, "AKIAEXAMPLEEXAMPLE00", "AwsSecret0123456789abcdef",
                                        "us-east-2", "https://s3.us-east-2.amazonaws.com");
    aws->provider_account_id = "111122223333";
    admin::AwsAdmin a(aws);
    EXPECT_FALSE(a.supportsReadKeys());
    try {
        (void)a.createReadKey({.bucket = "bucket-1", .key_name = "vh-read-abc"});
        ADD_FAILURE();
    } catch (const admin::CapabilityMissing& e) {
        EXPECT_NE(std::string(e.what()).find("not supported for this provider yet"), std::string::npos);
    }
    EXPECT_THROW(a.deleteReadKey("x"), admin::CapabilityMissing);
    auto r2 = std::make_shared<APIKey>(1, "r2", S3Provider::CloudflareR2, "0123456789abcdef0123456789abcdef",
                                       "r2secret", "wnam", "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com");
    admin::R2Admin r(r2);
    EXPECT_FALSE(r.supportsReadKeys());
    EXPECT_THROW((void)r.createReadKey({.bucket = "bucket-1", .key_name = "vh-read-abc"}), admin::CapabilityMissing);
    EXPECT_TRUE(sent.empty());
}

}
