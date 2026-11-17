// The golden vectors are shared: design/encryption/vectors/ (this repository: the spec's own copy, with the vhf1 and
// manifest sections) and vl-keykit's vectors/ (the KEV1, recovery seed and uid codecs this server links, also what
// Vaulthalla Desktop tests against). Both are verbatim copies of one generator's output, so they must stay byte for
// byte identical: a vector or generator change lands here first, then in vl-keykit, then in subprojects/vl-keykit.wrap.
#include "../helpers/bytes.hpp"

#include <vl/keykit/account_key.hpp>
#include <vl/keykit/kev1.hpp>
#include <vl/keykit/recovery_policy.hpp>
#include <vl/keykit/seed.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>

namespace vh::test_keykit_vectors {

TEST(KeykitVectors, TheLibrarysCopyIsThisRepositorysVectors) {
    const std::filesystem::path ours(VH_TEST_VECTORS_DIR), theirs(VH_TEST_KEYKIT_VECTORS_DIR);
    if (theirs.empty()) GTEST_SKIP() << "vl-keykit is a system library here, not the pinned subproject";
    for (const auto* name : {"vectors.json", "vh_crypto_vectors.py", "key_provenance.json", "key_provenance_vectors.py"}) {
        SCOPED_TRACE(name);
        EXPECT_EQ(vh::test::bin::slurpText(ours / name), vh::test::bin::slurpText(theirs / name));
    }
}

// The library is the one these vectors describe: one positive KEV1 and seed vector through the linked code.
TEST(KeykitVectors, TheLinkedLibraryReproducesThem) {
    const auto& v = vh::test::bin::goldenVectors().at("kev1").at("positive").at(0);
    const auto hex = [&](const char* k) { return vh::test::bin::fromHex(v.at(k).get<std::string>()); };
    vl::keykit::kev1::VaultUid uid{};
    const auto u = hex("vault_uid_hex");
    std::copy(u.begin(), u.end(), uid.begin());
    const auto suite = static_cast<vl::keykit::kev1::Suite>(v.at("suite").get<uint16_t>());
    const auto env = vl::keykit::kev1::wrap(hex("vault_key_hex"), suite, v.at("key_version").get<uint32_t>(), uid,
                                            hex("recipient_pk_hex"), hex("ephemeral_sk_hex"));
    EXPECT_EQ(vh::test::bin::toHex(env), v.at("envelope_hex").get<std::string>());

    const auto& s = vh::test::bin::goldenVectors().at("recovery_seed").at("positive").at(0);
    const auto seed = vl::keykit::RecoverySeed::parse(s.at("seed_text").get<std::string>());
    EXPECT_EQ(vh::test::bin::toHex(seed.x25519PublicKey()), s.at("x25519_pk_hex").get<std::string>());
}

// vl-keykit 0.2.0's account key vectors (vectors/vhc.json, shared with vaulthalla-cloud and Desktop) through the
// linked library, the way ops::cloud_keys uses it: the chain verifies, the fingerprints are the vectors', and every
// chain negative fails with its error.
TEST(KeykitVectors, TheAccountKeyChainVectorsVerifyThroughTheLinkedLibrary) {
    const std::filesystem::path theirs(VH_TEST_KEYKIT_VECTORS_DIR);
    if (theirs.empty()) GTEST_SKIP() << "vl-keykit is a system library here, not the pinned subproject";
    namespace account = vl::keykit::account;
    const auto doc = nlohmann::json::parse(vh::test::bin::slurpText(theirs / "vhc.json"));
    const auto& ak = doc.at("account_key");
    const auto publicId = ak.at("public_id").get<std::string>();
    const auto signedOf = [](const nlohmann::json& e) {
        account::SignedStatement s{.statement = e.at("statement").get<std::string>(), .signature = {},
                                   .previous_signature = std::nullopt};
        const auto sig = vh::test::bin::fromHex(e.at("signature_hex").get<std::string>());
        std::copy(sig.begin(), sig.end(), s.signature.begin());
        if (!e.at("previous_signature_hex").is_null()) {
            account::Signature prev{};
            const auto p = vh::test::bin::fromHex(e.at("previous_signature_hex").get<std::string>());
            std::copy(p.begin(), p.end(), prev.begin());
            s.previous_signature = prev;
        }
        return s;
    };
    std::vector<account::SignedStatement> chain;
    for (const auto& g : ak.at("generations")) {
        chain.push_back(signedOf(g));
        const auto verified = account::verifyChain(chain, publicId);
        EXPECT_EQ(account::fingerprintText(verified.back().fingerprint), g.at("fingerprint_text").get<std::string>());
        EXPECT_EQ(account::linkName(verified.back().link), g.at("link").get<std::string>());
    }
    for (const auto& n : ak.at("chain_negative")) {
        SCOPED_TRACE(n.at("name").get<std::string>());
        std::vector<account::SignedStatement> bad;
        for (const auto& e : n.at("chain")) bad.push_back(signedOf(e));
        try {
            (void)account::verifyChain(bad, publicId);
            ADD_FAILURE() << "verified";
        } catch (const account::Error& e) {
            EXPECT_EQ(account::errorCodeName(e.code()), n.at("error").get<std::string>());
        }
    }
}

}
