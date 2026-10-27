// The device pairing protocol's byte-level rules (docs/pairing.md in valkyrianlabs/vaulthalla-desktop, "the spec"): every test
// vector of §8, which Desktop's VHIdentityTests assert too, so both sides compute the same commitments, codes and
// rotation messages. Also the encodings, number-matching code input, device names and the server identity.

#include "device/Crypto.hpp"
#include "device/Device.hpp"
#include "device/ServerIdentity.hpp"
#include "log/AuditOrigin.hpp"

#include <gtest/gtest.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <numeric>
#include <thread>
#include <string>
#include <vector>

namespace vh::test_device_crypto {

namespace crypto = vh::device::crypto;
using crypto::Hash;

Hash countingFrom(const uint8_t first) {
    Hash h{};
    std::iota(h.begin(), h.end(), first);
    return h;
}

std::vector<uint8_t> unhex(const std::string& hex) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

const Hash kServerSpki = countingFrom(0x00);
const Hash kDeviceSpki = countingFrom(0x20);
const Hash kNonceDevice = countingFrom(0x40);
const Hash kNonceServer = countingFrom(0x60);

TEST(DeviceCryptoVectors, Commitment) {
    EXPECT_EQ(crypto::toHex(crypto::commitment(kDeviceSpki, kNonceDevice)),
              "eed843e2020fa269fbad8e1f326b441a7800a93bd5d985e1ee85920e7b853d32");
}

TEST(DeviceCryptoVectors, SasDigestAndCode) {
    const auto digest = crypto::sasDigest(kServerSpki, kDeviceSpki, kNonceDevice, kNonceServer);
    EXPECT_EQ(crypto::toHex(digest), "3ac2baf6c86830f39f539abce1130191e6a25b766f5ac20510f27a6b7a238fc1");
    EXPECT_EQ(crypto::sasCode(digest), "680179");
    EXPECT_EQ(crypto::displayCode(crypto::sasCode(digest)), "680 179");
}

TEST(DeviceCryptoVectors, SasCodeKeepsLeadingZeros) {
    auto nonceServer = kNonceServer;
    nonceServer[31] = 0x04;
    const auto digest = crypto::sasDigest(kServerSpki, kDeviceSpki, kNonceDevice, nonceServer);
    EXPECT_EQ(crypto::toHex(digest), "7daab695a6774e806a8f4efc05043896c83fb49c93ea9587596bd98412068267");
    EXPECT_EQ(crypto::sasCode(digest), "022592");
}

TEST(DeviceCryptoVectors, SpkiOfTheP256Generator) {
    const auto point = unhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb"
                             "4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    const auto key = crypto::p256KeyFromPoint(point);
    ASSERT_TRUE(key);
    // §1: the 26-byte prefix followed by the uncompressed point.
    auto expectedDer = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    expectedDer.insert(expectedDer.end(), point.begin(), point.end());
    EXPECT_EQ(key->spkiDer, expectedDer);
    EXPECT_EQ(crypto::toHex(key->spkiSha256), "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3");
    // Not on the curve: refused.
    auto bad = point;
    bad[64] ^= 0x01;
    EXPECT_FALSE(crypto::p256KeyFromPoint(bad));
}

// §4: the rotation message, the spec's signature verified (ECDSA is randomized: never compare signature bytes), and
// a signature made here from the test key verified the same way.
TEST(DeviceCryptoVectors, RotationProof) {
    const auto newSpki = crypto::hashFromHex("c5a4bd12f47b9e4a810de5de3dc0b906e20e710dfcfd344e8f934b47b6df4fe1");
    ASSERT_TRUE(newSpki);
    const auto message = crypto::rotationMessage(*newSpki, kServerSpki, 1790000000);
    EXPECT_EQ(message.size(), 91u);
    EXPECT_EQ(crypto::toHex(message),
              "76682d6465766963652d726f746174652d7631"
              "c5a4bd12f47b9e4a810de5de3dc0b906e20e710dfcfd344e8f934b47b6df4fe1"
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
              "000000006ab13b80");

    const auto oldPoint = unhex("04cb6cf2c3631fb1cd0931b5f154f8f255592fbcb76c96ec1a68f80dd0f1510393b0ff71f18a3c3dd81af6"
                                "ff0311d2ef98b664b8437b5ebf80aa4beb29649bb58a");
    const auto oldKey = crypto::p256KeyFromPoint(oldPoint);
    ASSERT_TRUE(oldKey);
    const auto signature = unhex("30440220768b64330311652f611615e15e6260f1bd4bc913557e19aaa5a45a4f16fde190"
                                 "02201daae21d09e5a1f87521471195900aa3be36b3fba00e654966453018ccf80205");
    EXPECT_TRUE(crypto::verifyEcdsaP256Sha256(oldKey->spkiDer, message, signature));

    // Bound to the node and to the time: the same proof for another server key or another timestamp fails.
    EXPECT_FALSE(crypto::verifyEcdsaP256Sha256(oldKey->spkiDer, crypto::rotationMessage(*newSpki, kDeviceSpki, 1790000000),
                                               signature));
    EXPECT_FALSE(crypto::verifyEcdsaP256Sha256(oldKey->spkiDer, crypto::rotationMessage(*newSpki, kServerSpki, 1790000001),
                                               signature));

    // The private scalar is SHA-256("vh-rotation-test-key") mod n; its public point is the spec's.
    const std::string seed = "vh-rotation-test-key";
    const auto digest = crypto::sha256(std::span(reinterpret_cast<const uint8_t*>(seed.data()), seed.size()));
    BIGNUM* d = BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr);
    BIGNUM* n = nullptr;
    BN_hex2bn(&n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    BN_CTX* ctx = BN_CTX_new();
    BN_mod(d, d, n, ctx);
    std::vector<uint8_t> scalar(32);
    BN_bn2binpad(d, scalar.data(), 32);
    BN_free(d);
    BN_free(n);
    BN_CTX_free(ctx);
    const auto identity = vh::device::ServerIdentity::fromPrivateScalar(scalar, {});
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(identity->key(), &der);
    const std::vector<uint8_t> spkiDer(der, der + len);
    OPENSSL_free(der);
    EXPECT_EQ(spkiDer, oldKey->spkiDer);

    EVP_MD_CTX* md = EVP_MD_CTX_new();
    std::size_t sigLen = 0;
    ASSERT_EQ(EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, identity->key()), 1);
    ASSERT_EQ(EVP_DigestSign(md, nullptr, &sigLen, message.data(), message.size()), 1);
    std::vector<uint8_t> ours(sigLen);
    ASSERT_EQ(EVP_DigestSign(md, ours.data(), &sigLen, message.data(), message.size()), 1);
    ours.resize(sigLen);
    EVP_MD_CTX_free(md);
    EXPECT_TRUE(crypto::verifyEcdsaP256Sha256(oldKey->spkiDer, message, ours));
}

TEST(DeviceCryptoEncodings, HexAndBase64) {
    EXPECT_EQ(crypto::toHex(std::vector<uint8_t>{0x00, 0xab, 0xff}), "00abff");
    EXPECT_TRUE(crypto::hashFromHex(std::string(64, 'A')));
    EXPECT_FALSE(crypto::hashFromHex(std::string(63, 'a')));
    EXPECT_FALSE(crypto::hashFromHex(std::string(63, 'a') + "g"));

    for (const std::string text : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
        const std::vector<uint8_t> bytes(text.begin(), text.end());
        const auto encoded = crypto::toBase64(bytes);
        const auto decoded = crypto::fromBase64(encoded);
        ASSERT_TRUE(decoded) << text;
        EXPECT_EQ(*decoded, bytes) << text;
    }
    EXPECT_EQ(crypto::toBase64(std::vector<uint8_t>{'f', 'o'}), "Zm8=");
    EXPECT_FALSE(crypto::fromBase64("Zm8"));      // padding required
    EXPECT_FALSE(crypto::fromBase64("Zm=8"));     // '=' only at the end
    EXPECT_FALSE(crypto::fromBase64("Zm8 "));     // no whitespace
    EXPECT_FALSE(crypto::fromBase64("Zm-_"));     // standard alphabet only
}

TEST(DeviceCryptoEncodings, CodesAsPeopleTypeThem) {
    EXPECT_EQ(crypto::normalizeCode("482913"), "482913");
    EXPECT_EQ(crypto::normalizeCode("482 913"), "482913");
    EXPECT_EQ(crypto::normalizeCode("482-913"), "482913");
    EXPECT_FALSE(crypto::normalizeCode("48291"));
    EXPECT_FALSE(crypto::normalizeCode("4829134"));
    EXPECT_FALSE(crypto::normalizeCode("48291a"));
    for (int i = 0; i < 50; ++i) {
        const auto code = crypto::randomCode();
        EXPECT_EQ(code.size(), 6u);
        EXPECT_TRUE(crypto::normalizeCode(code));
    }
    EXPECT_TRUE(crypto::constantTimeEqual(std::string_view{"680179"}, std::string_view{"680179"}));
    EXPECT_FALSE(crypto::constantTimeEqual(std::string_view{"680179"}, std::string_view{"680178"}));
    EXPECT_FALSE(crypto::constantTimeEqual(std::string_view{"68017"}, std::string_view{"680179"}));
}

TEST(DeviceNames, NormalizedAndBounded) {
    EXPECT_EQ(vh::device::normalizeDeviceName("  Cooper's MacBook Pro "), "Cooper's MacBook Pro");
    EXPECT_EQ(vh::device::normalizeDeviceName("Mac de Zoë"), "Mac de Zoë");
    EXPECT_FALSE(vh::device::normalizeDeviceName("   "));
    EXPECT_FALSE(vh::device::normalizeDeviceName("bad\nname"));
    EXPECT_FALSE(vh::device::normalizeDeviceName("bad\x7fname"));
    EXPECT_FALSE(vh::device::normalizeDeviceName("bad\xc2\x85name"));  // C1 control
    EXPECT_FALSE(vh::device::normalizeDeviceName("bad\xffname"));      // not UTF-8
    EXPECT_TRUE(vh::device::normalizeDeviceName(std::string(64, 'x')));
    EXPECT_FALSE(vh::device::normalizeDeviceName(std::string(65, 'x')));
    std::string accents;
    for (int i = 0; i < 64; ++i) accents += "é";  // 64 code points, 128 bytes
    EXPECT_TRUE(vh::device::normalizeDeviceName(accents));
}

// §2: the server certificate carries the key; the pin is the key's SPKI hash, so a certificate re-issued for the same
// key (lost file) keeps the pin and another key changes it.
TEST(DeviceServerIdentity, CertificateFollowsTheKey) {
    const auto first = vh::device::ServerIdentity::generate();
    EXPECT_TRUE(first->certificateIsNew());
    const auto pub = crypto::p256KeyOf(first->certificate());
    ASSERT_TRUE(pub);
    EXPECT_EQ(pub->spkiSha256, first->spkiSha256());
    EXPECT_EQ(X509_get_ext_by_NID(first->certificate(), NID_ext_key_usage, -1) >= 0, true);

    auto scalar = first->privateScalar();
    const auto again = vh::device::ServerIdentity::fromPrivateScalar(scalar, first->certificatePem());
    EXPECT_FALSE(again->certificateIsNew()) << "the stored certificate is reused";
    EXPECT_EQ(again->certificatePem(), first->certificatePem());
    EXPECT_EQ(again->spkiSha256(), first->spkiSha256());

    const auto lostFile = vh::device::ServerIdentity::fromPrivateScalar(scalar, {});
    EXPECT_TRUE(lostFile->certificateIsNew());
    EXPECT_EQ(lostFile->spkiSha256(), first->spkiSha256()) << "same key, same pin";

    const auto other = vh::device::ServerIdentity::generate();
    const auto mismatched = vh::device::ServerIdentity::fromPrivateScalar(scalar, other->certificatePem());
    EXPECT_TRUE(mismatched->certificateIsNew()) << "a certificate for another key is never used";
    EXPECT_EQ(mismatched->spkiSha256(), first->spkiSha256());
    EXPECT_NE(other->spkiSha256(), first->spkiSha256());

    EXPECT_THROW((void)vh::device::ServerIdentity::fromPrivateScalar(std::vector<uint8_t>(32, 0), {}), std::runtime_error);
    EXPECT_THROW((void)vh::device::ServerIdentity::fromPrivateScalar(std::vector<uint8_t>(31, 1), {}), std::runtime_error);
}

// Audit lines written while a paired device's command runs end with " [via device <id>]" (the router sets the origin
// around the handler); origins nest and end with their scope.
TEST(DeviceAuditOrigin, ScopedAndNested) {
    EXPECT_EQ(vh::log::AuditOrigin::current(), nullptr);
    {
        const vh::log::AuditOrigin outer("device 0123456789abcdef");
        ASSERT_NE(vh::log::AuditOrigin::current(), nullptr);
        EXPECT_EQ(*vh::log::AuditOrigin::current(), "device 0123456789abcdef");
        {
            const vh::log::AuditOrigin inner("device fedcba9876543210");
            EXPECT_EQ(*vh::log::AuditOrigin::current(), "device fedcba9876543210");
        }
        EXPECT_EQ(*vh::log::AuditOrigin::current(), "device 0123456789abcdef");
        std::thread([] { EXPECT_EQ(vh::log::AuditOrigin::current(), nullptr) << "per thread"; }).join();
    }
    EXPECT_EQ(vh::log::AuditOrigin::current(), nullptr);
}

}
