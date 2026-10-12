// The integration harness's seed derivation (core/tests/integrations/include/seed/H64.hpp) must equal the Python
// engine's (tools/harness/vhh/seeds.py), so a seed printed by either tier reproduces the same choices. The vectors
// below were produced by vhh.seeds.h64 / fmt_seed; regenerate them from Python, never from this implementation.

#include "../integrations/include/seed/H64.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

namespace vh::test_integration_seed_h64 {

using vh::test::integration::seed::fmtSeed;
using vh::test::integration::seed::h64;
using vh::test::integration::seed::parseSeed;

TEST(IntegrationSeedH64, MatchesPythonVectors) {
    EXPECT_EQ(fmtSeed(h64()), "0xb4b2797457a0a6e4");
    EXPECT_EQ(fmtSeed(h64(std::string_view(""))), "0x9e08cc502f2f844e");
    EXPECT_EQ(fmtSeed(h64(0, "test", 0)), "0x5d8b19b036b720b8");
    EXPECT_EQ(fmtSeed(h64(12345, "Seed Users:user/create", 3)), "0x96315e83b1cb7abf");
    EXPECT_EQ(fmtSeed(h64(UINT64_MAX, "op", 7, 42)), "0x69da9d47befc8023");
    EXPECT_EQ(fmtSeed(h64(0x0123456789abcdefULL, "stage:Assign", 0)), "0x09311d9b7f40756c");
    EXPECT_EQ(fmtSeed(h64("\xc3\xa9")), "0x8a804f6a1f7206ec");  // "é" as UTF-8
    EXPECT_EQ(fmtSeed(h64(std::string_view("\x00\xff\x10", 3))), "0x312762edd40b3b76");
}

TEST(IntegrationSeedH64, IntegersHashAsDecimalText) {
    // Python hashes str(part): 0 and "0" are the same part.
    EXPECT_EQ(fmtSeed(h64(0)), "0x264f8885952b58a3");
    EXPECT_EQ(h64(0), h64("0"));
    EXPECT_EQ(h64(42u), h64(static_cast<uint64_t>(42)));
    EXPECT_NE(h64("ab", "c"), h64("a", "bc"));  // the length prefix separates parts
}

TEST(IntegrationSeedH64, BlockBoundaries) {
    // One part plus its 4-byte length: 127, 128 (exactly one BLAKE2b block) and 129 bytes, then several blocks.
    EXPECT_EQ(fmtSeed(h64(std::string(123, 'x'))), "0xcb3f68e84a37017f");
    EXPECT_EQ(fmtSeed(h64(std::string(124, 'x'))), "0x6e2b7596fc854a11");
    EXPECT_EQ(fmtSeed(h64(std::string(125, 'x'))), "0x42690209f2e47193");
    EXPECT_EQ(fmtSeed(h64(std::string(200, 'a'), std::string(300, 'b'))), "0x1f431a5931854cff");
    EXPECT_EQ(fmtSeed(h64(std::string(1000, 'a'))), "0x7acaa60c32a77de4");
}

TEST(IntegrationSeedH64, ParseAndFormatSeeds) {
    EXPECT_EQ(parseSeed("42"), 42u);
    EXPECT_EQ(parseSeed("0xDEADbeef"), 3735928559u);
    EXPECT_EQ(parseSeed("0xffffffffffffffff"), UINT64_MAX);
    EXPECT_EQ(parseSeed(fmtSeed(0x0123456789abcdefULL)), 0x0123456789abcdefULL);
    EXPECT_EQ(fmtSeed(1), "0x0000000000000001");
    EXPECT_FALSE(parseSeed("").has_value());
    EXPECT_FALSE(parseSeed("0x").has_value());
    EXPECT_FALSE(parseSeed("12a").has_value());
    EXPECT_FALSE(parseSeed("-1").has_value());
    EXPECT_FALSE(parseSeed("18446744073709551616").has_value());  // 2^64
    EXPECT_FALSE(parseSeed("0x10000000000000000").has_value());
}

}
