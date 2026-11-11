// Vaulthalla Cloud's request signatures (VHC1-Ed25519) and endpoint rules, DB-free. The vector is the cloud's
// (valkyrianlabs/vaulthalla-cloud docs/design/installation-requests.md, "Test vector"), computed there independently
// of any C++; the cloud's own RequestSignature.MatchesTheDocumentedVector checks the same values.
#include "cloud/Client.hpp"
#include "cloud/Signing.hpp"

#include <gtest/gtest.h>

#include <array>
#include <stdexcept>

namespace vh::test_cloud_signing {

std::array<uint8_t, 32> vectorSeed() {
    std::array<uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(0x20 + i);
    return seed;
}

TEST(CloudSigning, MatchesTheCloudsDocumentedVector) {
    const auto seed = vectorSeed();
    EXPECT_EQ(cloud::base64url(cloud::publicKeyOf(seed)), "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc");
    const std::string body = R"({"vault":"kceypk9vfn5tv6yx5c6qpfebdm"})";
    const cloud::SignedFields f{.method = "POST",
                                .path = "/v1/recovery/vaults/a%20b",
                                .query = "x=1&y",
                                .host = "api.vaulthalla.cloud",
                                .installation = "kceypk9vfn5tv6yx5c6qpfebdm",
                                .timestamp = 1793664000,
                                .nonce = "AAECAwQFBgcICQoLDA0ODw",
                                .body_sha256 = cloud::sha256Hex(body)};
    EXPECT_EQ(f.body_sha256, "c4293fac1f2924f97ffec5da0d43fe15fccb05f3275b033d295aa78c815dd567");
    EXPECT_EQ(cloud::sha256Hex(cloud::stringToSign(f)), "2bd1a0d0d0a4d8c2d694b793fe564018ac7b95e9a2d1306dbb1c4768017edd40");
    const auto h = cloud::sign(f, seed);
    EXPECT_EQ(h.authorization,
              "VHC1-Ed25519 Installation=kceypk9vfn5tv6yx5c6qpfebdm, Timestamp=1793664000, Nonce=AAECAwQFBgcICQoLDA0ODw, "
              "Signature=l-5sKNw58kNGX8pbTqy9HQgb97rosBuDb4RwLqIWcEILgRqpVIwEHCKsJVhIYNti5-MlBZeYWGDRLikjEPtPCQ");
    EXPECT_EQ(h.content_sha256, f.body_sha256);
}

TEST(CloudSigning, FingerprintsAndNoncesHaveTheCloudsShape) {
    // The first 8 bytes of SHA-256(public key), as the cloud's linking lookup shows them.
    const auto pk = cloud::publicKeyOf(vectorSeed());
    const auto hex = cloud::sha256Hex(std::string_view(reinterpret_cast<const char*>(pk.data()), pk.size()));
    EXPECT_EQ(cloud::fingerprint(pk), hex.substr(0, 4) + "-" + hex.substr(4, 4) + "-" + hex.substr(8, 4) + "-" +
                                          hex.substr(12, 4));
    const auto n = cloud::newNonce();
    EXPECT_EQ(n.size(), 22u);  // 16 bytes, base64url without padding
    EXPECT_NE(n, cloud::newNonce());
    EXPECT_THROW((void)cloud::publicKeyOf(std::array<uint8_t, 16>{}), std::invalid_argument);
}

TEST(CloudEndpoint, IsHttpsOrLoopbackHttpAndSignsTheHostAsSent) {
    auto e = cloud::endpoint("https://API.vaulthalla.cloud:443/");
    EXPECT_EQ(e.base, "https://api.vaulthalla.cloud");
    EXPECT_EQ(e.host, "api.vaulthalla.cloud");
    e = cloud::endpoint("https://staging.vaulthalla.cloud:8443");
    EXPECT_EQ(e.host, "staging.vaulthalla.cloud:8443");
    e = cloud::endpoint("http://127.0.0.1:8085");
    EXPECT_EQ(e.host, "127.0.0.1:8085");
    EXPECT_EQ(cloud::endpoint("http://localhost").host, "localhost");
    EXPECT_EQ(cloud::endpoint("http://[::1]:9").host, "[::1]:9");
    for (const auto* bad : {"http://api.vaulthalla.cloud", "http://localhost.evil.test", "https://x/v1", "https://u@x",
                            "x", "https://", "ws://localhost"})
        EXPECT_THROW((void)cloud::endpoint(bad), std::invalid_argument) << bad;
}

}
