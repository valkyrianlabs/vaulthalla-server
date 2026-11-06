// #366 (WS1-a): object uids, their database form and their text form (design/encryption/01-provider-blind-storage.md
// §4.1). The base32 cases are design/encryption/vectors/vectors.json `object_ids`, the reference implementation's.

#include "crypto/id/ObjectUid.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>

#include <set>
#include <stdexcept>
#include <string>

namespace vh::test_object_uid {

using crypto::id::Base32Error;
using crypto::id::ObjectUid;

ObjectUid fromHex(const std::string& hex) {
    ObjectUid uid{};
    for (std::size_t i = 0; i < uid.size(); ++i) uid[i] = static_cast<uint8_t>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    return uid;
}

TEST(ObjectUid, Base32MatchesTheVectors) {
    const struct { const char* hex; const char* b32; } cases[] = {
        {"00000000000000000000000000000000", "00000000000000000000000000"},
        {"ffffffffffffffffffffffffffffffff", "zzzzzzzzzzzzzzzzzzzzzzzzzw"},
        {"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d", "kceypk9vfn5tv6yx5c6qpfebdm"},
        {"5648f1a2b3c4d5e6f708192a3b4c5d6e", "as4f38nkrkaydxr834n3pk2xdr"},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.b32);
        EXPECT_EQ(crypto::id::toBase32(fromHex(c.hex)), c.b32);
        const auto decoded = crypto::id::fromBase32(c.b32);
        ASSERT_TRUE(decoded);
        EXPECT_EQ(*decoded, fromHex(c.hex));
    }
}

TEST(ObjectUid, Base32DecoderAcceptsOneSpellingPerId) {
    const struct { const char* text; Base32Error error; } cases[] = {
        {"KCEYPK9VFN5TV6YX5C6QPFEBDM", Base32Error::BadSymbol},     // upper case is not canonical
        {"kceypk9vfn5tv6yx5c6qpfebdi", Base32Error::BadSymbol},     // i, l, o, u are not symbols
        {"kceypk9vfn5tv6yx5c6qpfebd", Base32Error::BadLength},      // 25 symbols
        {"kceypk9vfn5tv6yx5c6qpfebdn", Base32Error::NonCanonical},  // padding bits must be zero
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.text);
        Base32Error error{};
        EXPECT_FALSE(crypto::id::fromBase32(c.text, &error));
        EXPECT_EQ(error, c.error);
    }
    EXPECT_EQ(crypto::id::to_string(Base32Error::NonCanonical), "non_canonical");
}

TEST(ObjectUid, UuidFormRoundTripsAndRefusesOtherText) {
    const auto uid = fromHex("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d");
    EXPECT_EQ(crypto::id::toUuid(uid), "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d");
    EXPECT_EQ(crypto::id::fromUuid("9B1DEB4D-3B7D-4BAD-9BDD-2B0D7B3DCB6D"), uid);
    for (const auto* bad : {"", "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d", "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6",
                            "9b1deb4d-3b7d-4bad-9bdd_2b0d7b3dcb6d", "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6g"})
        EXPECT_THROW((void)crypto::id::fromUuid(bad), std::invalid_argument) << bad;
}

TEST(ObjectUid, NewUidsAreRawRandomBytes) {
    std::set<ObjectUid> seen;
    bool versionNibbleVaries = false;
    for (int i = 0; i < 64; ++i) {
        const auto uid = crypto::id::newObjectUid();
        EXPECT_TRUE(seen.insert(uid).second);
        if ((uid[6] >> 4) != 4) versionNibbleVaries = true;
    }
    EXPECT_TRUE(versionNibbleVaries) << "no UUID version bits: 128 random bits";
}

TEST(StorageLayout, NamesRoundTripAndNewVaultsNeverStartOpaque) {
    using vault::model::StorageLayout;
    for (const auto layout : {StorageLayout::Transparent, StorageLayout::PathV0, StorageLayout::OpaqueV1})
        EXPECT_EQ(vault::model::storageLayoutFromString(vault::model::to_string(layout)), layout);
    EXPECT_THROW((void)vault::model::storageLayoutFromString("opaque"), std::invalid_argument);
    EXPECT_EQ(vault::model::layoutFor(true), StorageLayout::PathV0);
    EXPECT_EQ(vault::model::layoutFor(false), StorageLayout::Transparent);
    EXPECT_EQ(vault::model::describe(StorageLayout::OpaqueV1), "opaque (v1)");
}

}
