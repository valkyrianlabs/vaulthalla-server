// The golden vectors are shared: design/encryption/vectors/ (this repository: the spec's own copy) and vl-vaultfmt's
// vectors/ (the VHF1 and manifest code this server links, whose own suites read them). Both are verbatim copies of one
// generator's output, so they must stay byte for byte identical: a vhf1 or manifest vector change lands in vl-vaultfmt
// with its code, then here with the wrap bump (design/core/vault-format-library.md, decision 2), as
// test_keykit_vectors.cpp holds vl-keykit's copy to this one.
#include "../helpers/bytes.hpp"

#include <vl/vaultfmt/manifest/Objects.hpp>
#include <vl/vaultfmt/manifest/Publisher.hpp>
#include <vl/vaultfmt/vhf1/Reader.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <memory>
#include <string>

namespace vh::test_vaultfmt_vectors {

TEST(VaultfmtVectors, TheLibrarysCopyIsThisRepositorysVectors) {
    const std::filesystem::path ours(VH_TEST_VECTORS_DIR), theirs(VH_TEST_VAULTFMT_VECTORS_DIR);
    if (theirs.empty()) GTEST_SKIP() << "vl-vaultfmt is a system library here, not the pinned subproject";
    for (const auto* name : {"vectors.json", "vh_crypto_vectors.py", "writer_floor.json", "writer_floor_vectors.py"}) {
        SCOPED_TRACE(name);
        EXPECT_EQ(vh::test::bin::slurpText(ours / name), vh::test::bin::slurpText(theirs / name));
    }
}

// The library is the one these vectors describe: a VHF1 object and the manifest's epoch-1 root through the linked code.
TEST(VaultfmtVectors, TheLinkedLibraryReproducesThem) {
    namespace vhf1 = vl::vaultfmt::vhf1;
    const auto& doc = vh::test::bin::goldenVectors();
    const auto keyOf = [&](const uint32_t v) -> vhf1::KeyPtr {
        const auto& keys = doc.at("conventions").at("keys");
        if (!keys.contains(std::to_string(v))) return nullptr;
        return std::make_shared<const vhf1::Key>(vh::test::bin::fromHex(keys.at(std::to_string(v)).get<std::string>()));
    };
    const auto uid = [](const std::string& hex) {
        vhf1::Uid u{};
        const auto b = vh::test::bin::fromHex(hex);
        std::copy(b.begin(), b.end(), u.begin());
        return u;
    };
    for (const auto& v : doc.at("vhf1").at("positive")) {
        if (!v.contains("object_hex")) continue;
        SCOPED_TRACE(v.at("name").get<std::string>());
        const auto& p = v.at("params");
        const auto plaintext = vhf1::open(vh::test::bin::fromHex(v.at("object_hex").get<std::string>()),
                                          {static_cast<vhf1::Kind>(p.at("kind").get<int>()),
                                           uid(p.at("vault_uid_hex").get<std::string>()),
                                           uid(p.at("object_uid_hex").get<std::string>()), std::nullopt},
                                          keyOf);
        EXPECT_EQ(vh::test::bin::toHex(plaintext.span()), v.at("plaintext_hex").get<std::string>());
    }
    const auto vault = uid(doc.at("vhf1").at("positive").at(0).at("params").at("vault_uid_hex").get<std::string>());
    for (const auto& o : doc.at("manifest").at("objects")) {
        if (o.at("name") != "root_epoch_1") continue;
        const auto root = vl::vaultfmt::manifest::openRoot(vh::test::bin::fromHex(o.at("object_hex").get<std::string>()),
                                                           vault, keyOf);
        EXPECT_EQ(root.epoch, 1u);
    }
}

// The writer floor's vectors (vl-vaultfmt's writer_floor.json, copied here beside vectors.json): every root's floor as
// the linked library reads it, whether this server's writer revision may publish over it, and the decision table.
TEST(VaultfmtVectors, TheWriterFloorVectorsAreTheLinkedLibrarysRules) {
    namespace vhf1 = vl::vaultfmt::vhf1;
    namespace mf = vl::vaultfmt::manifest;
    const auto doc = nlohmann::json::parse(
        vh::test::bin::slurpText(std::filesystem::path(VH_TEST_VECTORS_DIR) / "writer_floor.json"));
    const auto& keys = vh::test::bin::goldenVectors().at("conventions").at("keys");
    const auto keyOf = [&](const uint32_t v) -> vhf1::KeyPtr {
        if (!keys.contains(std::to_string(v))) return nullptr;
        return std::make_shared<const vhf1::Key>(vh::test::bin::fromHex(keys.at(std::to_string(v)).get<std::string>()));
    };
    vhf1::Uid vault{};
    const auto vb = vh::test::bin::fromHex(doc.at("vault_uid_hex").get<std::string>());
    std::copy(vb.begin(), vb.end(), vault.begin());
    ASSERT_EQ(doc.at("roots").size(), 3u);
    for (const auto& r : doc.at("roots")) {
        SCOPED_TRACE(r.at("name").get<std::string>());
        const auto root = mf::openRoot(vh::test::bin::fromHex(r.at("object_hex").get<std::string>()), vault, keyOf);
        const auto floor = r.at("writer_floor").get<uint32_t>();
        EXPECT_EQ(mf::writerFloorOf(root), floor);
        EXPECT_EQ(root.writer_floor.has_value(), floor != 0) << "absent means 0, and 0 is never written";
        if (floor > mf::kBaselineWriterRevision) EXPECT_THROW(mf::checkWriterFloor(root, mf::kBaselineWriterRevision),
                                                              mf::WriterFloorRefused);
        else EXPECT_NO_THROW(mf::checkWriterFloor(root, mf::kBaselineWriterRevision));
    }
    ASSERT_FALSE(doc.at("decisions").empty());
    for (const auto& d : doc.at("decisions")) {
        SCOPED_TRACE(d.dump());
        const auto base = std::max(d.at("base_floor").get<uint32_t>(), d.at("recorded_floor").get<uint32_t>());
        const auto revision = d.at("revision").get<uint32_t>(), needs = d.at("needs").get<uint32_t>();
        const auto& expect = d.at("expect");
        if (expect.contains("error")) {
            const auto error = expect.at("error").get<std::string>();
            if (error == "invalid_argument") EXPECT_THROW((void)mf::nextWriterFloor(base, revision, needs), std::invalid_argument);
            else EXPECT_THROW((void)mf::nextWriterFloor(base, revision, needs), mf::WriterFloorRefused) << error;
        } else {
            const auto got = mf::nextWriterFloor(base, revision, needs);
            if (expect.at("writer_floor").is_null()) EXPECT_EQ(got, 0u);
            else EXPECT_EQ(got, expect.at("writer_floor").get<uint32_t>());
        }
    }
}

}
