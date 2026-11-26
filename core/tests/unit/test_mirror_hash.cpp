// The entry hash and the running digest of a mirrored vault (mirror/Hash.hpp, design/peers/mirror.md "Parity"). DB-free:
// the fixed test vector every implementation (the core, the mirror, Desktop tooling) must reproduce, and the digest's
// arithmetic. MirrorReplicationLogDbTest checks PostgreSQL's vh_mirror_state_hash against the same vector.

#include "mirror/Hash.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

namespace vh::test_mirror_hash {

using json = nlohmann::json;

json vectorState() {
    return json::parse(R"({"v":1,"uid":"0f8fad5b-d9cb-469f-a165-70867728950e","type":"file",
        "parent":"7c9e6679-7425-40de-944b-e07fc1f90ae7","name":"Résumé.txt","mode":420,"hidden":false,
        "owner_uid":1000,"owner_gid":1000,"created_at":1732540000123456,"modified_at":1732540100654321,
        "created_by":{"node":"node-a","id":3},"modified_by":{"node":"node-b","id":7},"size":5,"content_hash":"ab12",
        "mime":"text/plain","generation":"AAAA","key_version":2,"content_format":"vhf1"})");
}

TEST(MirrorEntryHash, MatchesTheFixedTestVector) {
    EXPECT_EQ(mirror::toHex(mirror::entryHash(vectorState())),
              "c3cd6e5ea36d18109bdc5878a6ce1bcc6ea5e8325b3b78e5cb186ba636cae95d");
}

TEST(MirrorEntryHash, EncodesEveryFieldInOrderWithByteLengths) {
    const auto encoded = mirror::canonicalEncoding(vectorState());
    EXPECT_TRUE(encoded.starts_with("vh.mirror.entry/1\nv=1:1\nuid=36:0f8fad5b-d9cb-469f-a165-70867728950e\n"));
    // A length in bytes, not characters: "Résumé.txt" is 12 bytes of UTF-8.
    EXPECT_NE(encoded.find("\nname=12:Résumé.txt\n"), std::string::npos);
    EXPECT_NE(encoded.find("\nhidden=5:false\n"), std::string::npos);
    EXPECT_NE(encoded.find("\ncreated_by.node=6:node-a\ncreated_by.id=1:3\n"), std::string::npos);
    EXPECT_NE(encoded.find("\ntarget=-\ntrashed.path=-\n"), std::string::npos);
    EXPECT_TRUE(encoded.ends_with("trashed.by.id=-\n"));
    std::size_t lines = 0;
    for (const auto c : encoded) lines += c == '\n';
    EXPECT_EQ(lines, 1 + mirror::kEntryHashFields.size());
}

TEST(MirrorEntryHash, OnlyReplicatedFieldsCountAndNullIsAbsent) {
    auto state = vectorState();
    const auto base = mirror::entryHash(state);

    auto extra = state;
    extra["path"] = "/somewhere/else";   // not a replicated field
    EXPECT_EQ(mirror::entryHash(extra), base);

    auto nulled = state;
    nulled["target"] = nullptr;          // null is the same as absent
    EXPECT_EQ(mirror::entryHash(nulled), base);

    for (const auto* field : {"name", "mode", "modified_at", "generation", "key_version"}) {
        auto changed = state;
        changed.erase(field);
        EXPECT_NE(mirror::entryHash(changed), base) << field;
    }
    auto moved = state;
    moved["modified_by"]["id"] = 8;
    EXPECT_NE(mirror::entryHash(moved), base);
    // An empty string is a value, not an absence.
    auto empty = state;
    empty["generation"] = "";
    EXPECT_NE(mirror::entryHash(empty), mirror::entryHash([&] { auto s = state; s.erase("generation"); return s; }()));
}

TEST(MirrorDigest, IsAPerWordSumModuloTwoToTheSixtyFour) {
    mirror::Digest d;
    EXPECT_EQ(d.hex(), std::string(64, '0'));
    mirror::Hash ones{};
    ones.fill(0xff);
    mirror::Hash two{};
    two[31] = 2;
    d.add(ones);
    d.add(two);
    // The same value PostgreSQL's vh_mirror_digest gives for these two hashes.
    EXPECT_EQ(d.hex(), "ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000001");
    EXPECT_EQ(d.entries, 2);

    // Order does not matter, and a removal undoes an addition.
    mirror::Digest e;
    e.add(two);
    e.add(ones);
    EXPECT_EQ(d, e);
    d.remove(ones);
    d.remove(two);
    EXPECT_EQ(d, mirror::Digest{});
    EXPECT_EQ(mirror::Digest::fromBytes(e.bytes(), e.entries), e);
    EXPECT_EQ(mirror::hashFromHex(mirror::toHex(ones)), ones);
    EXPECT_THROW((void)mirror::hashFromHex("00"), std::invalid_argument);
}

}
