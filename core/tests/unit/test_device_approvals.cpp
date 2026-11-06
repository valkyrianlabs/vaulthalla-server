// Device approvals (#361; MFA design note sections 6.2, 6.3 and 6.5, decision D6), DB-free: the canonical payload
// vector shared with vaulthalla-desktop (core/test-assets/device/approval-vectors.json, its negatives one field each,
// a signature by another key, the inputs that make no payload), the approval key's one SPKI encoding, the router
// (device approval commands only on a paired device's session, console approvals never on one), what may satisfy a
// device session's step-up (an approval key only for D6's families, a console approval for any, the connection itself
// never), and the contract entries. The DB-backed half is test_device_approvals_db.cpp.
#include "Contract.hpp"
#include "auth/approval/Approvals.hpp"
#include "auth/mfa/Recovery.hpp"
#include "auth/stepup/StepUp.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace vh::auth::approval::test_device_approvals {

using json = nlohmann::json;
namespace crypto = vh::device::crypto;
using Decision = protocols::ws::Router::CommandAuthDecision;

json vectors() {
    std::ifstream in(std::filesystem::path(VH_TEST_ASSETS_DIR) / "device" / "approval-vectors.json");
    if (!in) throw std::runtime_error("approval-vectors.json is missing");
    return json::parse(in);
}

std::vector<uint8_t> b64(const json& v) { return *crypto::fromBase64(v.get<std::string>()); }

std::vector<uint8_t> unhex(const std::string& hex) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

std::optional<std::vector<uint8_t>> payloadOf(const json& f) {
    return crypto::approvalMessage(f.at("node_id").get<std::string>(),
                                   *crypto::hashFromHex(f.at("server_spki_sha256").get<std::string>()),
                                   *crypto::hashFromHex(f.at("approving_device_spki_sha256").get<std::string>()),
                                   *crypto::hashFromHex(f.at("challenge").get<std::string>()),
                                   f.at("family").get<std::string>(), f.at("target").get<std::string>(),
                                   f.at("expires_at").get<uint64_t>());
}

// The vector Desktop computes the same way in Swift (vaulthalla-desktop #47).
TEST(DeviceApprovalVectors, TheCanonicalPayloadAndItsSignature) {
    const auto doc = vectors();
    const auto spki = b64(doc.at("approval_key").at("spki_der_b64"));
    const auto key = crypto::p256KeyFromSpki(spki);
    ASSERT_TRUE(key) << "the vector's approval key is the protocol's one SPKI encoding";
    EXPECT_EQ(doc.at("approval_key").at("spki_sha256"), crypto::toHex(key->spkiSha256));

    const auto& pos = doc.at("positive");
    const auto payload = payloadOf(pos.at("fields"));
    ASSERT_TRUE(payload);
    EXPECT_EQ(pos.at("payload_hex"), crypto::toHex(*payload));
    EXPECT_EQ(pos.at("payload_b64"), crypto::toBase64(*payload));
    const auto signature = b64(pos.at("signature_der_b64"));
    EXPECT_TRUE(crypto::verifyEcdsaP256Sha256(spki, *payload, signature));

    ASSERT_GE(doc.at("negative").size(), 7u);
    std::set<std::string> names;
    for (const auto& n : doc.at("negative")) {
        names.insert(n.at("name").get<std::string>());
        const auto p = payloadOf(n.at("fields"));
        ASSERT_TRUE(p) << n.at("name");
        EXPECT_EQ(n.at("payload_hex"), crypto::toHex(*p)) << n.at("name");
        EXPECT_FALSE(crypto::verifyEcdsaP256Sha256(spki, *p, signature)) << n.at("name") << " verified";
    }
    for (const auto* name : {"wrong_node_id", "wrong_server_spki_sha256", "wrong_approving_device_spki_sha256",
                             "wrong_challenge", "wrong_family", "wrong_target", "wrong_expires_at"})
        EXPECT_TRUE(names.contains(name)) << name;

    const auto& wrong = doc.at("wrong_key");
    EXPECT_TRUE(crypto::verifyEcdsaP256Sha256(b64(wrong.at("spki_der_b64")), *payload,
                                              b64(wrong.at("signature_der_b64"))));
    EXPECT_FALSE(crypto::verifyEcdsaP256Sha256(spki, *payload, b64(wrong.at("signature_der_b64"))))
        << "another key's signature";
    for (const auto& n : doc.at("no_payload")) EXPECT_FALSE(payloadOf(n.at("fields"))) << n.at("name");

    // The layout, spelled out once more by hand: domain, separators, the three digests, the 64-bit big-endian expiry.
    const auto& f = pos.at("fields");
    std::vector<uint8_t> manual;
    const auto add = [&](const std::string& s) { manual.insert(manual.end(), s.begin(), s.end()); };
    add("vh-device-approval-v1");
    manual.push_back(0);
    add(f.at("node_id").get<std::string>());
    manual.push_back(0);
    for (const auto* k : {"server_spki_sha256", "approving_device_spki_sha256", "challenge"}) {
        const auto bytes = unhex(f.at(k).get<std::string>());
        manual.insert(manual.end(), bytes.begin(), bytes.end());
    }
    add(f.at("family").get<std::string>());
    manual.push_back(0);
    add(f.at("target").get<std::string>());
    manual.push_back(0);
    const auto expires = f.at("expires_at").get<uint64_t>();
    for (int shift = 56; shift >= 0; shift -= 8) manual.push_back(static_cast<uint8_t>(expires >> shift));
    EXPECT_EQ(manual, *payload);
}

TEST(DeviceApprovalKeys, OnlyTheProtocolsOneP256SpkiEncoding) {
    const auto spki = b64(vectors().at("approval_key").at("spki_der_b64"));
    ASSERT_EQ(spki.size(), 91u);
    EXPECT_TRUE(crypto::p256KeyFromSpki(spki));
    auto truncated = spki;
    truncated.pop_back();
    EXPECT_FALSE(crypto::p256KeyFromSpki(truncated));
    auto trailing = spki;
    trailing.push_back(0);
    EXPECT_FALSE(crypto::p256KeyFromSpki(trailing));
    auto offCurve = spki;
    offCurve.back() ^= 0x01;
    EXPECT_FALSE(crypto::p256KeyFromSpki(offCurve)) << "a point off the curve";
    auto otherCurve = spki;
    otherCurve[20] ^= 0x01;  // inside the curve OID
    EXPECT_FALSE(crypto::p256KeyFromSpki(otherCurve));
    EXPECT_FALSE(crypto::p256KeyFromSpki({}));

    // A compressed point (59 bytes) is the same key in another encoding: not accepted.
    EVP_PKEY* raw = nullptr;
    const unsigned char* p = spki.data();
    raw = d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size()));
    ASSERT_TRUE(raw);
    EVP_PKEY_set_utf8_string_param(raw, "point-format", "compressed");
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(raw, &der);
    const std::vector<uint8_t> compressed(der, der + std::max(len, 0));
    OPENSSL_free(der);
    EVP_PKEY_free(raw);
    EXPECT_NE(compressed.size(), spki.size());
    EXPECT_FALSE(crypto::p256KeyFromSpki(compressed));
}

// ── the router ─────────────────────────────────────────────────────────────────────────────────────────────────────

std::shared_ptr<identities::User> detachedAdmin(const uint32_t id) {
    identities::UserState state;
    state.name = "approvals-" + std::to_string(id);
    state.roles.admin = std::make_shared<rbac::role::Admin>();
    return identities::User::detached(id, std::move(state));
}

std::shared_ptr<protocols::ws::Session> deviceSession(const uint32_t userId, const uint8_t fill = 0x31) {
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spki.fill(fill);
    peer->spkiHex = crypto::toHex(peer->spki);
    peer->address = "127.0.0.1";
    peer->deviceRowId = 1;
    return protocols::ws::Session::devicePrincipal(std::move(peer), detachedAdmin(userId), [] {});
}

TEST(DeviceApprovalRouting, DeviceCommandsOnlyOnADeviceAndConsoleApprovalsNeverOnOne) {
    const auto device = deviceSession(5101);
    const auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = detachedAdmin(5102);
    for (const auto* cmd : {"device.approval.challenge", "device.approval.submit", "device.approval.request",
                            "device.approval.status", "device.approval.key.register"}) {
        EXPECT_EQ(protocols::ws::Router::classifyCommand(cmd, *device), Decision::Allow) << cmd;
        EXPECT_EQ(protocols::ws::Router::classifyCommand(cmd, *web), Decision::Deny) << cmd << " on a console";
    }
    for (const auto* cmd : {"auth.approval.list", "auth.approval.approve", "auth.approval.deny"}) {
        EXPECT_EQ(protocols::ws::Router::classifyCommand(cmd, *device), Decision::Deny)
            << cmd << ": a device never answers an approval request, its own or another's";
        EXPECT_EQ(protocols::ws::Router::classifyCommand(cmd, *web), Decision::RequireHumanAuth) << cmd;
    }
    EXPECT_EQ(protocols::ws::Router::classifyCommand("device.pairing.pending", *device), Decision::Allow)
        << "an already-paired Desktop approves a new one (design 8.4)";
    // Handlers refuse it too (no router in between).
    EXPECT_THROW((void)approval::list(device), ops::Denied);
    EXPECT_THROW((void)approval::approve(device, json{{"approval_id", "x"}}), ops::Denied);
    EXPECT_THROW((void)approval::request(web, stepup::Family::Settings, std::nullopt, "x"), ops::Refused);
    EXPECT_THROW((void)approval::challenge(web, stepup::Family::Keys, "t"), ops::Refused);
    device->close();
}

// ── what satisfies a device session's step-up ─────────────────────────────────────────────────────────────────────

TEST(DeviceApprovalGrants, AnApprovalKeyOnlyForD6FamiliesAConsoleApprovalForAnyTheConnectionNever) {
    using namespace std::chrono_literals;
    // DB-free: no account is in a recovery cooldown (#360 checks it before any grant).
    const auth::mfa::recovery::CooldownSourceForTesting noCooldown([](uint32_t) { return std::nullopt; });
    const auto device = deviceSession(5103);
    const auto now = std::chrono::system_clock::now();
    const auto grant = [&](const stepup::Family f, std::string_view method, std::optional<std::string> target) {
        device->stepUp().addGrant({.user_id = device->user->id, .refresh_jti = {}, .family = f,
                                   .target = stepup::targetBound(f) ? std::move(target) : std::nullopt,
                                   .method = std::string(method), .expires_at = now + 5min});
    };
    const stepup::Scope scope(device);
    ASSERT_EQ(scope.channel(), stepup::Channel::Device);

    // Nothing: refused, and the refusal says how a device can get it approved.
    try {
        stepup::require(stepup::Family::Settings);
        ADD_FAILURE() << "a device stepped up by connecting";
    } catch (const ops::StepUpRequired& e) {
        EXPECT_EQ(e.methods, std::vector<std::string>{"console_approval"});
    }

    // An approval-key grant serves keys and device.trust (D6) ...
    grant(stepup::Family::DeviceTrust, stepup::kDeviceApprovalMethod, "device.pairing.approve:r:k:c");
    EXPECT_NO_THROW(stepup::require(stepup::Family::DeviceTrust, std::string("device.pairing.approve:r:k:c")));
    // ... and never another family, whatever a grant says.
    grant(stepup::Family::Settings, stepup::kDeviceApprovalMethod, std::nullopt);
    EXPECT_THROW(stepup::require(stepup::Family::Settings), ops::StepUpRequired);
    grant(stepup::Family::DataDestroy, stepup::kDeviceApprovalMethod, "storage.vault.remove:1");
    EXPECT_THROW(stepup::require(stepup::Family::DataDestroy, std::string("storage.vault.remove:1")),
                 ops::StepUpRequired);
    // A console approval (a person's passkey) may approve any family.
    grant(stepup::Family::Settings, stepup::kConsoleApprovalMethod, std::nullopt);
    EXPECT_NO_THROW(stepup::require(stepup::Family::Settings));
    grant(stepup::Family::DataDestroy, stepup::kConsoleApprovalMethod, "storage.vault.remove:2");
    EXPECT_NO_THROW(stepup::require(stepup::Family::DataDestroy, std::string("storage.vault.remove:2")));
    // A grant with any other method (a client claiming "touch_id", a web method) never counts on a device.
    grant(stepup::Family::Keys, "touch_id", "vault.keys.import:3");
    EXPECT_THROW(stepup::require(stepup::Family::Keys, std::string("vault.keys.import:3")), ops::StepUpRequired);
    grant(stepup::Family::Keys, "webauthn", "vault.keys.import:4");
    EXPECT_THROW(stepup::require(stepup::Family::Keys, std::string("vault.keys.import:4")), ops::StepUpRequired);
    device->close();
}

// ── the contract ───────────────────────────────────────────────────────────────────────────────────────────────────

TEST(DeviceApprovalContract, TheCommandsAreBookedWhereTheyRun) {
    std::map<std::string, contract::WsCommandUsage> book;
    for (auto& c : contract::ws::commands()) book.emplace(c.command, c);
    for (const auto* cmd : {"device.approval.challenge", "device.approval.submit", "device.approval.request",
                            "device.approval.status", "device.approval.key.register"}) {
        ASSERT_TRUE(book.contains(cmd)) << cmd;
        EXPECT_EQ(book.at(cmd).auth, "device") << cmd;
    }
    for (const auto* cmd : {"auth.approval.list", "auth.approval.approve", "auth.approval.deny"}) {
        ASSERT_TRUE(book.contains(cmd)) << cmd;
        EXPECT_EQ(book.at(cmd).auth, "human") << cmd;
    }
    EXPECT_EQ(book.at("device.approval.key.register").step_up, "device.trust")
        << "registering an approval key is a person's device.trust approval";
    const auto& challengeFamilies =
        std::ranges::find(book.at("device.approval.challenge").payload, "family", &contract::WsField::name)->enum_values;
    for (const auto f : stepup::kFamilies)
        EXPECT_EQ(std::ranges::find(challengeFamilies, std::string(stepup::to_string(f))) != challengeFamilies.end(),
                  stepup::deviceApprovalMaySatisfy(f))
            << "the book's approval-key families are D6's: " << stepup::to_string(f);
    const auto& request = book.at("device.pair.request").payload;
    const auto key = std::ranges::find(request, "approval_key", &contract::WsField::name);
    ASSERT_NE(key, request.end());
    EXPECT_FALSE(key->required) << "additive: a Desktop without an approval key pairs as before";
}

}
