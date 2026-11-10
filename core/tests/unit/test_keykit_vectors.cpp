// The golden vectors are shared: design/encryption/vectors/ (this repository: the spec's own copy, with the vhf1 and
// manifest sections) and vl-keykit's vectors/ (the KEV1, recovery seed and uid codecs this server links, also what
// Vaulthalla Desktop tests against). Both are verbatim copies of one generator's output, so they must stay byte for
// byte identical: a vector or generator change lands here first, then in vl-keykit, then in subprojects/vl-keykit.wrap.
#include "../helpers/bytes.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/seed.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <string>

namespace vh::test_keykit_vectors {

TEST(KeykitVectors, TheLibrarysCopyIsThisRepositorysVectors) {
    const std::filesystem::path ours(VH_TEST_VECTORS_DIR), theirs(VH_TEST_KEYKIT_VECTORS_DIR);
    if (theirs.empty()) GTEST_SKIP() << "vl-keykit is a system library here, not the pinned subproject";
    for (const auto* name : {"vectors.json", "vh_crypto_vectors.py"}) {
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

}
