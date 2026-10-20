// The pairing state machine (docs/pairing.md §3) on its own, with an injected clock: windows, commit-then-reveal,
// number matching, the limits, expiry and what device.pair.status reports. DB-free: the devices row is ops::devices'.

#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "ops/Error.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <set>
#include <string>

namespace vh::test_device_pairing {

namespace crypto = vh::device::crypto;
using vh::device::Pairing;
using vh::device::PairingClock;
using vh::device::Peer;
using vh::device::RequestState;
using namespace std::chrono_literals;

constexpr uint32_t kOwner = 7;
constexpr uint32_t kOther = 8;

// A prvalue (Peer holds an atomic, so it is not copyable).
Peer peer(const uint8_t tag, const std::string& address = "192.0.2.10") {
    crypto::Hash spki{};
    spki.fill(tag);
    return Peer{.spki = spki, .spkiHex = crypto::toHex(spki), .address = address};
}

std::string refusalCode(const std::function<void()>& fn) {
    try {
        fn();
    } catch (const ops::Refused& e) {
        return e.code;
    } catch (const ops::NotFound&) {
        return "not_found";
    } catch (const ops::Invalid&) {
        return "invalid";
    } catch (const ops::Conflict&) {
        return "conflict";
    }
    return "";
}

class DevicePairing : public ::testing::Test {
protected:
    void SetUp() override { Pairing::instance().resetForTesting(); }
    void TearDown() override { Pairing::instance().resetForTesting(); }

    Pairing& pairing = Pairing::instance();
    PairingClock::time_point t0 = PairingClock::now();
    crypto::Hash server = crypto::randomNonce();

    // request + confirm; returns the request id.
    std::string confirmed(const Peer& p, const PairingClock::time_point at) {
        const auto nonce = crypto::randomNonce();
        const auto receipt = pairing.request(p, {.name = "Mac", .platform = "macOS", .app_version = "1.0",
                                                 .commitment = crypto::commitment(p.spki, nonce)}, at);
        (void)pairing.confirm(p, receipt.request_id, nonce, server, at);
        return receipt.request_id;
    }
};

TEST_F(DevicePairing, NoWindowNoRequest) {
    const auto p = peer(1);
    EXPECT_EQ(refusalCode([&] {
        (void)pairing.request(p, {.name = "Mac", .platform = "macOS", .commitment = crypto::randomNonce()}, t0);
    }), "no_pairing_window");
}

TEST_F(DevicePairing, OneWindowPerNodeOwnedByItsOpener) {
    const auto w = pairing.open(kOwner, t0);
    EXPECT_EQ(w.owner_id, kOwner);
    EXPECT_EQ(w.expires_at - w.opened_at, 600);
    EXPECT_EQ(refusalCode([&] { (void)pairing.open(kOther, t0 + 1s); }), "conflict");
    // Reopening extends the owner's window.
    const auto extended = pairing.open(kOwner, t0 + 5min);
    EXPECT_EQ(extended.opened_at, w.opened_at);
    EXPECT_GT(extended.expires_at, w.expires_at);
    // Another user can't close it; the owner (or a super admin: `any`) can.
    EXPECT_FALSE(pairing.close(kOther, false, t0 + 6min));
    EXPECT_TRUE(pairing.close(kOther, true, t0 + 6min));
    EXPECT_FALSE(pairing.window(t0 + 6min));
    EXPECT_NO_THROW((void)pairing.open(kOther, t0 + 6min));
    // It expires on its own after 10 minutes.
    EXPECT_FALSE(pairing.window(t0 + 17min));
}

TEST_F(DevicePairing, CommitThenRevealThenNumberMatching) {
    (void)pairing.open(kOwner, t0);
    const auto device = peer(1);
    const auto nonceDevice = crypto::randomNonce();
    const auto receipt = pairing.request(device, {.name = "Studio Mac", .platform = "macOS", .app_version = "1.2.0",
                                                  .commitment = crypto::commitment(device.spki, nonceDevice)}, t0);
    EXPECT_EQ(receipt.request_id.size(), 16u);
    EXPECT_LE(receipt.expires_at, PairingClock::to_time_t(t0 + 5min));

    // Not visible to the owner until confirmed, and the status says pending.
    EXPECT_TRUE(pairing.pending(kOwner, t0).empty());
    EXPECT_EQ(pairing.status(device, receipt.request_id, t0).state, RequestState::AwaitingConfirm);
    EXPECT_EQ(vh::device::to_string(RequestState::AwaitingConfirm), "pending");

    // Another key can't confirm or read it.
    const auto intruder = peer(2);
    EXPECT_EQ(refusalCode([&] { (void)pairing.confirm(intruder, receipt.request_id, nonceDevice, server, t0); }),
              "not_found");
    EXPECT_EQ(refusalCode([&] { (void)pairing.status(intruder, receipt.request_id, t0); }), "not_found");

    (void)pairing.confirm(device, receipt.request_id, nonceDevice, server, t0 + 1s);
    const auto expected = crypto::sasCode(crypto::sasDigest(server, device.spki, nonceDevice, receipt.nonce_server));
    EXPECT_EQ(pairing.codeForTesting(receipt.request_id), expected);

    const auto list = pairing.pending(kOwner, t0 + 2s);
    ASSERT_EQ(list.size(), 1u);
    const auto& r = list.front();
    EXPECT_EQ(r.name, "Studio Mac");
    EXPECT_EQ(r.source_ip, "192.0.2.10");
    EXPECT_EQ(r.device_id, device.spkiHex);
    // Three distinct six-digit codes, exactly one of them the SAS; the same three on every read.
    const std::set<std::string> distinct(r.code_choices.begin(), r.code_choices.end());
    EXPECT_EQ(distinct.size(), 3u);
    EXPECT_EQ(std::ranges::count(r.code_choices, expected), 1);
    EXPECT_EQ(pairing.pending(kOwner, t0 + 3s).front().code_choices, r.code_choices);
    EXPECT_TRUE(pairing.pending(kOther, t0 + 3s).empty()) << "only the window's owner sees its requests";

    // Only its owner approves it.
    EXPECT_EQ(refusalCode([&] { (void)pairing.beginApproval(kOther, r.request_id, expected, t0 + 4s); }), "not_found");
    const auto claim = pairing.beginApproval(kOwner, r.request_id, crypto::displayCode(expected), t0 + 4s);
    EXPECT_EQ(claim.device_id, device.spkiHex);
    EXPECT_EQ(claim.owner_id, kOwner);
    EXPECT_EQ(pairing.status(device, r.request_id, t0 + 4s).state, RequestState::Approving);
    pairing.finishApproval(r.request_id, 42, t0 + 5s);
    const auto status = pairing.status(device, r.request_id, t0 + 6s);
    EXPECT_EQ(status.state, RequestState::Approved);
    EXPECT_EQ(status.device_row_id, 42u);
    EXPECT_EQ(status.device_id, device.spkiHex);
    EXPECT_TRUE(pairing.pending(kOwner, t0 + 6s).empty());
}

TEST_F(DevicePairing, AWrongNonceDeletesTheRequest) {
    (void)pairing.open(kOwner, t0);
    const auto device = peer(1);
    const auto receipt = pairing.request(device, {.name = "Mac", .platform = "macOS",
                                                  .commitment = crypto::commitment(device.spki, crypto::randomNonce())},
                                         t0);
    EXPECT_EQ(refusalCode([&] { (void)pairing.confirm(device, receipt.request_id, crypto::randomNonce(), server, t0); }),
              "invalid");
    EXPECT_EQ(refusalCode([&] { (void)pairing.status(device, receipt.request_id, t0); }), "not_found");
}

TEST_F(DevicePairing, AnyWrongCodeDenies) {
    (void)pairing.open(kOwner, t0);
    const auto device = peer(1);
    const auto id = confirmed(device, t0);
    const auto real = *pairing.codeForTesting(id);
    const auto choices = pairing.pending(kOwner, t0).front().code_choices;
    const auto decoy = *std::ranges::find_if(choices, [&](const auto& c) { return c != real; });

    EXPECT_EQ(refusalCode([&] { (void)pairing.beginApproval(kOwner, id, decoy, t0 + 1s); }), "invalid");
    EXPECT_EQ(pairing.status(device, id, t0 + 2s).state, RequestState::Denied);
    EXPECT_EQ(refusalCode([&] { (void)pairing.beginApproval(kOwner, id, real, t0 + 3s); }), "not_found")
        << "a denied request can't be approved afterwards";

    // Malformed input is a wrong code too.
    const auto id2 = confirmed(peer(2), t0 + 4s);
    EXPECT_EQ(refusalCode([&] { (void)pairing.beginApproval(kOwner, id2, "12345", t0 + 5s); }), "invalid");
    EXPECT_EQ(pairing.status(peer(2), id2, t0 + 5s).state, RequestState::Denied);

    // And the owner can deny outright.
    const auto id3 = confirmed(peer(3), t0 + 6s);
    pairing.deny(kOwner, id3, t0 + 7s);
    EXPECT_EQ(pairing.status(peer(3), id3, t0 + 7s).state, RequestState::Denied);
}

TEST_F(DevicePairing, RequestsExpire) {
    (void)pairing.open(kOwner, t0);
    const auto device = peer(1);
    const auto id = confirmed(device, t0);
    EXPECT_EQ(pairing.status(device, id, t0 + 4min).state, RequestState::Pending);
    EXPECT_EQ(pairing.status(device, id, t0 + 5min + 1s).state, RequestState::Expired) << "5 minutes after confirm";

    // Closing the window expires its requests.
    const auto id2 = confirmed(peer(2), t0 + 6min);
    EXPECT_TRUE(pairing.close(kOwner, false, t0 + 6min + 1s));
    EXPECT_EQ(pairing.status(peer(2), id2, t0 + 6min + 2s).state, RequestState::Expired);
    EXPECT_EQ(refusalCode([&] { (void)pairing.beginApproval(kOwner, id2, "000000", t0 + 6min + 3s); }), "not_found");
}

TEST_F(DevicePairing, ARequestNeverOutlivesItsWindow) {
    (void)pairing.open(kOwner, t0);
    const auto device = peer(1);
    const auto id = confirmed(device, t0 + 8min);
    EXPECT_EQ(pairing.status(device, id, t0 + 9min).state, RequestState::Pending);
    EXPECT_EQ(pairing.status(device, id, t0 + 10min + 1s).state, RequestState::Expired);
}

TEST_F(DevicePairing, OneLiveRequestPerKey) {
    (void)pairing.open(kOwner, t0);
    const auto device = peer(1);
    const auto first = confirmed(device, t0);
    const auto second = confirmed(device, t0 + 1s);
    EXPECT_NE(first, second);
    EXPECT_EQ(pairing.status(device, first, t0 + 2s).state, RequestState::Expired) << "replaced";
    EXPECT_EQ(pairing.pending(kOwner, t0 + 2s).size(), 1u);
}

TEST_F(DevicePairing, LimitsPerWindowAndPerAddress) {
    (void)pairing.open(kOwner, t0);
    for (uint8_t i = 1; i <= 5; ++i) (void)confirmed(peer(i, "192.0.2." + std::to_string(i)), t0);
    EXPECT_EQ(refusalCode([&] { (void)confirmed(peer(6, "192.0.2.6"), t0); }), "rate_limited") << "5 per window";

    pairing.resetForTesting();
    (void)pairing.open(kOwner, t0);
    for (uint8_t i = 1; i <= 10; ++i) {
        // Each new request of the same key replaces the last, so the window cap never bites here.
        const auto p = peer(1, "198.51.100.1");
        EXPECT_NO_THROW((void)pairing.request(p, {.name = "Mac", .platform = "macOS", .commitment = crypto::randomNonce()},
                                              t0 + std::chrono::seconds(i)))
            << i;
    }
    EXPECT_EQ(refusalCode([&] {
        (void)pairing.request(peer(1, "198.51.100.1"), {.name = "Mac", .platform = "macOS",
                                                         .commitment = crypto::randomNonce()}, t0 + 20s);
    }), "rate_limited") << "10 per minute per address";
    EXPECT_NO_THROW((void)pairing.request(peer(1, "198.51.100.1"), {.name = "Mac", .platform = "macOS",
                                                                     .commitment = crypto::randomNonce()},
                                          t0 + 75s))
        << "a minute later";
}

}
