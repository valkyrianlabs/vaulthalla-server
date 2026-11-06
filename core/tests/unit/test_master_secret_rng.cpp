// #318: KeyProvider generated the host's master secrets (vault_master, master, ak_master, s3gw_master, psql,
// key_attest, device_tls) byte by byte from std::random_device, whose source is implementation-defined. They now come
// from libsodium's CSPRNG like every other key. Existing sealed secrets are untouched: only generation changed.

#include "crypto/secrets/KeyProvider.hpp"
#include "fs/ops/file.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::test_master_secret_rng {

using crypto::secrets::KeyProvider;

TEST(MasterSecretRng, SecretsAreFullLengthAndDistinct) {
    std::set<std::vector<uint8_t>> seen;
    for (int i = 0; i < 256; ++i) {
        const auto secret = KeyProvider::generateMasterSecret();
        ASSERT_EQ(secret.size(), 32u);
        EXPECT_TRUE(seen.emplace(secret.bytes().begin(), secret.bytes().end()).second) << "duplicate master secret";
    }
    EXPECT_EQ(KeyProvider::generateMasterSecret(64).size(), 64u);
    EXPECT_THROW((void)KeyProvider::generateMasterSecret(0), std::invalid_argument);
}

// Not a randomness test suite, only a guard against a gross regression (a truncated or constant source): over 64 KiB
// every byte value appears and none dominates.
TEST(MasterSecretRng, BytesCoverTheWholeRange) {
    std::array<std::size_t, 256> counts{};
    for (int i = 0; i < 2048; ++i) {
        const auto secret = KeyProvider::generateMasterSecret();
        for (const auto b : secret.bytes()) ++counts[b];
    }
    const auto [minIt, maxIt] = std::ranges::minmax_element(counts);
    EXPECT_GT(*minIt, 0u);
    EXPECT_LT(*maxIt, 2048u * 32u / 256u * 2u);  // under twice the expected 256 per value
}

TEST(MasterSecretRng, TempSuffixesUseTheCharsetAndDoNotRepeat) {
    std::set<std::string> seen;
    for (int i = 0; i < 1000; ++i) {
        const auto suffix = fs::ops::generate_random_suffix(12);
        ASSERT_EQ(suffix.size(), 12u);
        EXPECT_TRUE(std::ranges::all_of(suffix, [](const unsigned char c) { return std::isalnum(c) != 0; })) << suffix;
        EXPECT_TRUE(seen.insert(suffix).second);
    }
}

}
