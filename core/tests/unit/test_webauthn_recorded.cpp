// Ceremonies recorded from a real browser (#355): Chrome's virtual authenticator through the CDP WebAuthn domain
// (core/test-assets/webauthn/chrome-virtual-authenticator.json, tools/dev/record-webauthn-fixtures.mjs). Each one is
// the browser's own L3 JSON (PublicKeyCredential.toJSON()), decoded by wire:: and verified end to end: ES256, EdDSA
// and RS256 platform credentials, a synced (BE = BS = 1) passkey, a non-discoverable security key without a
// userHandle, and an assertion made without user verification, which must refuse.

#include "auth/webauthn/Base64Url.hpp"
#include "auth/webauthn/Verifier.hpp"
#include "auth/webauthn/Wire.hpp"
#include "webauthn/Fixtures.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>

namespace vh::test_webauthn {

TEST(WebAuthnRecordedChrome, BrowserCeremoniesVerifyEndToEnd) {
    std::ifstream in(std::filesystem::path(VH_TEST_ASSETS_DIR) / "webauthn" / "chrome-virtual-authenticator.json");
    const auto doc = nlohmann::json::parse(in);
    const wa::RelyingParty rp{doc.at("rp_id").get<std::string>(), {doc.at("origin").get<std::string>()}, {}};
    ASSERT_EQ(doc.at("fixtures").size(), 6u);
    for (const auto& f : doc.at("fixtures")) {
        SCOPED_TRACE(f.at("name").get<std::string>());
        const auto challenge = [&](const char* ceremony) {
            return *wa::base64urlDecode(f.at(ceremony).at("challenge").get<std::string>());
        };
        const auto reg = wa::wire::parseRegistration(f.at("registration").at("response").dump());
        ASSERT_TRUE(reg) << "the browser's RegistrationResponseJSON decodes";
        EXPECT_FALSE(reg->transports.empty());
        MemoryCredentials credentials;
        const auto registered = wa::verifyRegistration(rp, challenge("registration"), *reg, credentials);
        ASSERT_TRUE(registered) << wa::toString(registered.failure);
        EXPECT_EQ(static_cast<int>(registered.value->algorithm), f.at("alg").get<int>());
        EXPECT_TRUE(registered.value->userVerified);
        const auto handle = *wa::base64urlDecode(f.at("user_handle").get<std::string>());
        credentials.store(*registered.value, 7, handle);

        const auto assertion = wa::wire::parseAssertion(f.at("assertion").at("response").dump());
        ASSERT_TRUE(assertion) << "the browser's AuthenticationResponseJSON decodes";
        const auto expected = f.at("assertion").at("expect").get<std::string>();
        const auto mfa = wa::verifyAssertion(rp, challenge("assertion"), *assertion, credentials,
                                             {"s", wa::Purpose::Mfa, 7, {}});
        EXPECT_EQ(std::string(wa::toString(mfa.failure)), expected);
        if (expected != "none") continue;
        EXPECT_EQ(mfa.value->userId, 7);
        EXPECT_TRUE(mfa.value->storeSignCount) << "the virtual authenticator counts";
        if (assertion->userHandle) {
            const auto login = wa::verifyAssertion(rp, challenge("assertion"), *assertion, credentials,
                                                   {"s", wa::Purpose::Login, std::nullopt, {}});
            EXPECT_TRUE(login) << wa::toString(login.failure);
        }
        const auto other = wa::verifyAssertion({"example.test", {doc.at("origin").get<std::string>()}, {}},
                                               challenge("assertion"), *assertion, credentials,
                                               {"s", wa::Purpose::Mfa, 7, {}});
        EXPECT_EQ(other.failure, wa::Failure::RpIdHashMismatch);
    }
}

}
