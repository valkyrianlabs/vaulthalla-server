// KEV1 key envelopes, the recovery seed and the recovery kit (crypto::kev1, crypto::recovery; spec
// design/encryption/03-metadata-recovery.md §5) against the golden vectors in design/encryption/vectors/vectors.json:
// every `kev1` and `recovery_seed` vector is exercised (positives byte for byte, negatives by their first failing check).
#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/recovery/Kev1.hpp"
#include "crypto/recovery/Kit.hpp"
#include "crypto/recovery/Seed.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

namespace vh::crypto::test_kev1 {

namespace {

using Json = nlohmann::json;
using Bytes = std::vector<uint8_t>;

const Json& vectors() {
    static const Json doc = [] {
        const auto path = std::filesystem::path(VH_TEST_VECTORS_DIR) / "vectors.json";
        std::ifstream in(path);
        if (!in) throw std::runtime_error("missing golden vectors: " + path.string());
        return Json::parse(in);
    }();
    return doc;
}

Bytes hex(const std::string& text) {
    Bytes out(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<uint8_t>(std::stoul(text.substr(2 * i, 2), nullptr, 16));
    return out;
}

std::string toHex(const std::span<const uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const auto b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 15]);
    }
    return out;
}

kev1::VaultUid uidOf(const std::string& text) {
    const auto b = hex(text);
    kev1::VaultUid u{};
    std::copy(b.begin(), b.end(), u.begin());
    return u;
}

std::string str(const Json& j) { return j.get<std::string>(); }

kev1::Suite suiteOf(const Json& j) { return static_cast<kev1::Suite>(j.get<uint16_t>()); }

}

TEST(Kev1Vectors, PositiveEnvelopesAreReproducedAndUnwrap) {
    const auto& positives = vectors().at("kev1").at("positive");
    ASSERT_GE(positives.size(), 3u);
    for (const auto& v : positives) {
        SCOPED_TRACE(v.at("name").get<std::string>());
        const auto suite = suiteOf(v.at("suite"));
        const auto key = std::make_shared<const SecretKey>(hex(v.at("vault_key_hex")));
        const auto rpk = hex(v.at("recipient_pk_hex"));
        EXPECT_EQ(toHex(kev1::publicKeyOf(suite, hex(v.at("recipient_sk_hex")))), str(v.at("recipient_pk_hex")));
        EXPECT_EQ(toHex(kev1::recipientId(rpk)), str(v.at("recipient_id_hex")));

        const auto env = kev1::wrap(*key, suite, v.at("key_version").get<uint32_t>(), uidOf(v.at("vault_uid_hex")),
                                    rpk, hex(v.at("ephemeral_sk_hex")));
        EXPECT_EQ(toHex(env), str(v.at("envelope_hex")));
        EXPECT_EQ(kev1::objectKey(kev1::kid(env)), str(v.at("object_key")));

        const auto out = kev1::unwrap(hex(v.at("envelope_hex")), hex(v.at("recipient_sk_hex")), suite,
                                      uidOf(v.at("vault_uid_hex")));
        EXPECT_EQ(out.key_version, v.at("key_version").get<uint32_t>());
        EXPECT_EQ(toHex(out.key->bytes()), str(v.at("vault_key_hex")));

        const auto h = kev1::inspect(env);
        EXPECT_EQ(h.purpose, kev1::kPurposeVaultKey);
        EXPECT_EQ(h.recipient_class, kev1::kClassCustomer);
        EXPECT_EQ(toHex(h.recipient_id), str(v.at("recipient_id_hex")));
    }
}

TEST(Kev1Vectors, NegativeEnvelopesFailAtTheirFirstCheck) {
    const auto& negatives = vectors().at("kev1").at("negative");
    ASSERT_GE(negatives.size(), 9u);
    for (const auto& n : negatives) {
        SCOPED_TRACE(n.at("name").get<std::string>());
        try {
            (void)kev1::unwrap(hex(n.at("envelope_hex")), hex(n.at("recipient_sk_hex")), suiteOf(n.at("suite_expected")),
                               uidOf(n.at("vault_uid_hex")));
            ADD_FAILURE() << "accepted";
        } catch (const kev1::Error& e) {
            EXPECT_EQ(kev1::errorCodeName(e.code()), n.at("expect").at("error").get<std::string>());
        }
    }
}

TEST(Kev1Vectors, FreshEnvelopesRoundTripAndNeverRepeat) {
    const auto key = SecretKey::random();
    const auto seed = recovery::RecoverySeed::generate();
    const auto rpk = seed.x25519PublicKey();
    const auto sk = seed.x25519SecretKey();
    const kev1::VaultUid uid = id::newObjectUid();
    const auto a = kev1::wrap(*key, kev1::Suite::X25519, 7, uid, rpk);
    const auto b = kev1::wrap(*key, kev1::Suite::X25519, 7, uid, rpk);
    EXPECT_EQ(a.size(), 150u);
    EXPECT_NE(a, b);  // a fresh ephemeral key per envelope
    EXPECT_NE(kev1::kid(a), kev1::kid(b));
    const auto out = kev1::unwrap(a, sk.bytes(), kev1::Suite::X25519, uid);
    EXPECT_EQ(out.key_version, 7u);
    EXPECT_EQ(sodium_memcmp(out.key->bytes().data(), key->bytes().data(), 32), 0);
    EXPECT_THROW((void)kev1::wrap(*key, kev1::Suite::X25519, 0, uid, rpk), std::invalid_argument);
    EXPECT_THROW((void)kev1::wrap(*key, kev1::Suite::X25519, 1, uid, Bytes(31, 1)), std::invalid_argument);
}

// Spec 03 §5.7: every envelope written now is class 0 / purpose 1; a reserved class or purpose is refused by the reader
// and reported as one a restore skips (never fatal), alongside envelopes addressed to someone else.
TEST(Kev1ReservedFields, ReservedClassesAndPurposesAreRefusedAndSkippable) {
    std::set<std::string> seen;
    for (const auto& n : vectors().at("kev1").at("negative")) {
        const auto name = n.at("name").get<std::string>();
        if (name != "reserved_recipient_class" && name != "reserved_purpose_threshold_share" &&
            name != "reserved_nonzero" && name != "wrong_recipient")
            continue;
        seen.insert(name);
        try {
            (void)kev1::inspect(hex(n.at("envelope_hex")));
            if (name != "wrong_recipient") ADD_FAILURE() << name << " passed inspect";
        } catch (const kev1::Error& e) {
            EXPECT_EQ(kev1::skippedByRestore(e.code()), name != "reserved_nonzero") << name;
        }
    }
    EXPECT_EQ(seen.size(), 4u);
    EXPECT_TRUE(kev1::skippedByRestore(kev1::ErrorCode::RecipientMismatch));
    EXPECT_FALSE(kev1::skippedByRestore(kev1::ErrorCode::WrapAuthFailed));
    EXPECT_FALSE(kev1::skippedByRestore(kev1::ErrorCode::VaultMismatch));

    const auto key = SecretKey::random();
    const auto seed = recovery::RecoverySeed::generate();
    const auto env = kev1::wrap(*key, kev1::Suite::X25519, 1, id::newObjectUid(), seed.x25519PublicKey());
    EXPECT_EQ(env[12], 1);  // purpose: a whole vault key version
    EXPECT_EQ(env[13], 0);  // recipient_class: customer-controlled
}

TEST(RecoverySeedVectors, SeedsDeriveTheDocumentedKeys) {
    const auto& positives = vectors().at("recovery_seed").at("positive");
    ASSERT_GE(positives.size(), 2u);
    for (const auto& s : positives) {
        SCOPED_TRACE(s.at("seed_text").get<std::string>());
        const auto seed = recovery::RecoverySeed::parse(s.at("seed_text").get<std::string>());
        EXPECT_EQ(toHex(seed.bytes()), str(s.at("seed_hex")));
        EXPECT_EQ(seed.text(), str(s.at("seed_text")));
        EXPECT_EQ(toHex(seed.x25519SecretKey().bytes()), str(s.at("x25519_sk_hex")));
        EXPECT_EQ(toHex(seed.x25519PublicKey()), str(s.at("x25519_pk_hex")));
        EXPECT_EQ(toHex(kev1::recipientId(seed.x25519PublicKey())), str(s.at("recipient_id_hex")));
        EXPECT_EQ(toHex(seed.ed25519Seed().bytes()), str(s.at("ed25519_seed_hex")));
        EXPECT_EQ(toHex(seed.ed25519PublicKey()), str(s.at("ed25519_pk_hex")));
        EXPECT_EQ(recovery::RecoverySeed::fromBytes(hex(s.at("seed_hex"))).text(), str(s.at("seed_text")));
    }
    // Display grouping is cosmetic.
    const auto text = positives.at(0).at("seed_text").get<std::string>();
    std::string grouped;
    for (std::size_t i = 0; i < text.size(); ++i) grouped += (i && i % 5 == 0 ? "-" : "") + std::string(1, static_cast<char>(std::toupper(static_cast<unsigned char>(text[i]))));
    EXPECT_EQ(recovery::RecoverySeed::parse(grouped).text(), text);
}

TEST(RecoverySeedVectors, NegativeSeedsAreRefused) {
    for (const auto& s : vectors().at("recovery_seed").at("negative")) {
        try {
            (void)recovery::RecoverySeed::parse(s.at("seed_text").get<std::string>());
            ADD_FAILURE() << "accepted " << s.at("seed_text");
        } catch (const recovery::SeedError& e) {
            EXPECT_EQ(e.code(), s.at("error").get<std::string>());
        }
    }
    EXPECT_THROW((void)recovery::RecoverySeed::parse("148hr6b6azfczjm7b2hs4x7hn0"), recovery::SeedError);
    EXPECT_THROW((void)recovery::RecoverySeed::parse("148hr6b6azfczjm7b2hs4x7hnuj"), recovery::SeedError);
}

TEST(RecoveryKit, RoundTripsAndRefusesWhatIsNotAKit) {
    const auto seedText = vectors().at("recovery_seed").at("positive").at(0).at("seed_text").get<std::string>();
    const auto uid = id::newObjectUid();
    const Json doc = {{"type", "vh.recovery-kit"}, {"v", 1}, {"recovery_seed", seedText},
                      {"vaults", {{{"vault_uid", id::toBase32(uid)},
                                   {"origin", {{"node_id", "00000000-0000-4000-8000-000000000001"}, {"vault_id", 42}}},
                                   {"attestation_public_keys",
                                    {{{"key_id", 3}, {"public_key", "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHd2GZBJVMbg="}}}},
                                   {"checkpoint", {{"epoch", 812}, {"root_sha256", std::string(64, 'a')}}},
                                   {"future_member", true}}}},
                      {"unknown", "ignored"}};
    const auto kit = recovery::parseKit(doc);
    EXPECT_EQ(kit.seed.text(), seedText);
    ASSERT_EQ(kit.vaults.size(), 1u);
    ASSERT_NE(kit.find(uid), nullptr);
    EXPECT_EQ(kit.vaults[0].origin_vault_id, 42u);
    ASSERT_EQ(kit.vaults[0].attestation_public_keys.size(), 1u);
    EXPECT_EQ(kit.vaults[0].attestation_public_keys[0].public_key.size(), 32u);
    const auto again = recovery::parseKit(recovery::toJson(kit));
    EXPECT_EQ(again.vaults, kit.vaults);
    EXPECT_EQ(again.seed.text(), seedText);

    const auto refused = [&](Json j, const std::string& code) {
        try {
            (void)recovery::parseKit(j);
            ADD_FAILURE() << "accepted " << j.dump();
        } catch (const recovery::KitError& e) {
            EXPECT_EQ(e.code(), code) << j.dump();
        }
    };
    auto j = doc;
    j["type"] = "vh.manifest.root";
    refused(j, "bad_kit");
    j = doc;
    j["v"] = 2;
    refused(j, "unsupported_version");
    j = doc;
    j["recovery_seed"] = seedText.substr(0, 26) + (seedText[26] == 'j' ? "k" : "j");
    refused(j, "bad_check");
    j = doc;
    j["vaults"][0]["attestation_public_keys"][0]["public_key"] = "AAAA";
    refused(j, "bad_kit");
    j = doc;
    j["vaults"].push_back(j["vaults"][0]);
    refused(j, "bad_kit");
}

}
