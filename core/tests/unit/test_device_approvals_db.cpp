// vh-test-tier: db-only
// Device approvals (#361; MFA design note sections 6.1-6.3, 6.5 and 8.4, decision D6), DB-backed, through the real
// ws handlers under the router's step-up scope:
//   - pairing approved from a paired device with its approval key (the 8.4 walkthrough), from the console and from the
//     CLI, the new device's approval key registered with it;
//   - the approval key's challenge refusing every mismatch (node, server key, device, family, target, expiry, another
//     key), a reused challenge, another session's, a revoked key, and families outside D6;
//   - console approvals: a passkey with user verification only (TOTP and passwords refused, an account without a
//     passkey refused), the push, the grant on the asking session only, deny, the rate limits;
//   - an approval key registered later through a console approval, once;
//   - the audit events;
//   - table-driven over the contract: every command a paired device may run that has no step_up annotation never
//     answers step_up_required (Desktop's routine traffic never prompts).
// DB-free half: test_device_approvals.cpp.
#include "../helpers/db_suite.hpp"
#include "../helpers/web_session.hpp"
#include "Contract.hpp"
#include "audit/Trail.hpp"
#include "auth/approval/Approvals.hpp"
#include "db/query/device/ApprovalKey.hpp"
#include "device/Pairing.hpp"
#include "device/ServerIdentity.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/handler/Devices.hpp"
#include "runtime/Deps.hpp"
#include "sync/Controller.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace vh::auth::approval::test_device_approvals_db {

using namespace vh::test::web;
using SysClock = std::chrono::system_clock;
namespace crypto = vh::device::crypto;
namespace h = protocols::ws::handler;
namespace tw = vh::test_webauthn;
using stepup::Family;
using stepup::Scope;

class DeviceApprovalsDb : public vh::test::db::Suite {
protected:
    AuthRuntime auth_{{.level = mfa::policy::Level::Optional}};
    std::shared_ptr<const vh::device::ServerIdentity> previousIdentity;
    inline static std::shared_ptr<sync::Controller> previousController;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("device_approvals")) return;
        protocols::device::endpoints::clearNodeIdForTesting();
        audit::Trail::instance()->resetForTesting();
        // Every ws command runs against the suite's real engines: fs writes ask the sync controller for an early pass
        // (an unstarted one just queues it).
        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        previousIdentity = vh::device::currentServerIdentity();
        vh::device::setCurrentServerIdentity(vh::device::ServerIdentity::generate());
        vh::device::Pairing::instance().resetForTesting();
        resetForTesting();
        setPushForTesting({});
    }

    void TearDown() override {
        if (skipTests) return;
        setPushForTesting({});
        resetForTesting();
        vh::device::Pairing::instance().resetForTesting();
        vh::device::setCurrentServerIdentity(previousIdentity);
    }

    // A signed-in console session (aal 1, an old sign-in: it never stands in for a step-up).
    static SessionPtr console(const UserPtr& user) {
        auto s = connect({}, "approvals-browser");
        s->setAuthenticatedUser(user);
        sessions().promote(s);
        s->tokens->refreshToken->authTime = SysClock::now() - std::chrono::hours(2);
        return s;
    }

    // A pairing request from a new device, confirmed: what the window's owner sees.
    struct NewDevice {
        std::shared_ptr<vh::device::Peer> peer;
        std::string request_id;
        std::string code;
    };
    static NewDevice newDeviceRequest(const std::optional<std::string>& approvalKeyB64) {
        auto peer = std::make_shared<vh::device::Peer>();
        peer->spki = crypto::randomNonce();
        peer->spkiHex = crypto::toHex(peer->spki);
        peer->address = "192.0.2.20";
        const auto nonce = crypto::randomNonce();
        const auto receipt = ops::devices::pairRequest(
            *peer, {.name = "New Mac", .platform = "macOS", .app_version = "1.0",
                    .commitment = crypto::toHex(crypto::commitment(peer->spki, nonce)), .approval_key = approvalKeyB64});
        (void)ops::devices::pairConfirm(*peer, receipt.request_id, crypto::toHex(nonce));
        return {.peer = peer, .request_id = receipt.request_id,
                .code = *vh::device::Pairing::instance().codeForTesting(receipt.request_id)};
    }

    // The canonical payload of a challenge answer, with one field replaced.
    struct PayloadFields {
        std::string node;
        crypto::Hash server, device, challenge;
        std::string family, target;
        uint64_t expires{};
    };
    static PayloadFields fieldsOf(const json& c, const vh::device::Peer& peer) {
        return {.node = protocols::device::endpoints::nodeId(),
                .server = vh::device::currentServerIdentity()->spkiSha256(),
                .device = peer.spki,
                .challenge = *crypto::hashFromHex(c.at("challenge").get<std::string>()),
                .family = c.at("family").get<std::string>(),
                .target = c.at("target").get<std::string>(),
                .expires = c.at("expires_at").get<uint64_t>()};
    }
    static std::vector<uint8_t> payloadOf(const PayloadFields& f) {
        return *crypto::approvalMessage(f.node, f.server, f.device, f.challenge, f.family, f.target, f.expires);
    }

    // A person approving `approvalId` on `web` with their passkey.
    static Answer consoleApprove(const SessionPtr& web, tw::Authenticator& a, const std::string& approvalId,
                                 const uint8_t flags = tw::flags::UP | tw::flags::UV) {
        const auto begun = run(web, [&] { return h::Approvals::approve(json{{"approval_id", approvalId}}, web); });
        if (!begun.ok) return begun;
        const auto credential = tw::assertionJson(a, begun.data.at("webauthn").at("publicKey"), flags);
        return run(web, [&] {
            return h::Approvals::approve(json{{"approval_id", approvalId}, {"credential", credential}}, web);
        });
    }

    // The audit trail's actions for `userId` since `afterSeq`, as "action/outcome".
    static std::vector<std::string> auditActions(const uint32_t userId, const std::string& like, const int64_t afterSeq = 0) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("approvals audit", [&](pqxx::work& txn) {
            std::vector<std::string> out;
            for (const auto& r : txn.exec("SELECT action, outcome FROM audit_event WHERE actor_id = $1 AND action LIKE $2 "
                                          "AND seq > $3 ORDER BY seq",
                                          pqxx::params{userId, like, afterSeq}))
                out.push_back(r[0].as<std::string>() + "/" + r[1].as<std::string>());
            return out;
        });
    }
};

// Design 8.4: a new Mac approved from a paired Mac. The paired Mac sees the request, the person picks the code, the
// approval key signs the challenge bound to request + new key + code, and the new device is paired with its own
// approval key.
TEST_F(DeviceApprovalsDb, APairedDeviceApprovesANewOneWithItsApprovalKey) {
    const auto owner = newUser("unprivileged");
    const ApprovalKey ak1, ak2;
    const auto paired = pairedDevice(owner, &ak1);
    const auto& a = paired.session;

    ASSERT_TRUE(run(a, [&] { return h::Devices::pairingOpen(a); }).ok) << "the paired Mac opens the window";
    const auto incoming = newDeviceRequest(ak2.spkiB64());

    const auto pending = run(a, [&] { return h::Devices::pairingPending(a); });
    ASSERT_TRUE(pending.ok) << pending.code << " " << pending.message;
    ASSERT_EQ(pending.data.at("requests").size(), 1u);
    EXPECT_EQ(pending.data.at("requests")[0].at("approval_key_present"), true);
    EXPECT_EQ(pending.data.at("requests")[0].at("device_id"), incoming.peer->spkiHex);

    const auto approveIt = [&] {
        return h::Devices::pairingApprove(json{{"request_id", incoming.request_id}, {"code", incoming.code}}, a);
    };
    const auto refused = run(a, approveIt);
    ASSERT_EQ(refused.code, "step_up_required") << "a paired device's mTLS session is never a person's approval";
    EXPECT_EQ(refused.data.at("family"), "device.trust");
    EXPECT_EQ(refused.data.at("methods"), json::array({"device_approval", "console_approval"}));
    const auto target = refused.data.at("target").get<std::string>();
    EXPECT_TRUE(target.starts_with("device.pairing.approve:" + incoming.request_id + ":" + incoming.peer->spkiHex + ":"));

    // The challenge's payload is the canonical one for this node, server key, device, family and target.
    const auto c = run(a, [&] {
        return h::Approvals::challenge(json{{"family", "device.trust"}, {"target", target}}, a);
    });
    ASSERT_TRUE(c.ok) << c.code << " " << c.message;
    EXPECT_EQ(*crypto::fromBase64(c.data.at("payload_b64").get<std::string>()), payloadOf(fieldsOf(c.data, *paired.peer)));
    EXPECT_LE(c.data.at("expires_at").get<int64_t>(),
              std::chrono::duration_cast<std::chrono::seconds>(SysClock::now().time_since_epoch()).count() + 120);
    const auto submitted = run(a, [&] {
        return h::Approvals::submit(
            json{{"challenge_id", c.data.at("challenge_id")},
                 {"signature_b64", crypto::toBase64(ak1.sign(*crypto::fromBase64(c.data.at("payload_b64").get<std::string>())))}},
            a);
    });
    ASSERT_TRUE(submitted.ok) << submitted.code << " " << submitted.message;
    EXPECT_EQ(submitted.data.at("target"), target);

    const auto approved = run(a, approveIt);
    ASSERT_TRUE(approved.ok) << approved.code << " " << approved.message;
    const auto newRow = approved.data.at("device").at("id").get<uint32_t>();
    const auto key = db::query::device::ApprovalKeys::forDevice(newRow);
    ASSERT_TRUE(key) << "the new device is paired with its approval key";
    EXPECT_EQ(key->registered_via, "pairing");
    EXPECT_EQ(key->spki_sha256, ak2.spkiHex());
    EXPECT_EQ(key->public_key_spki, ak2.spki());
    EXPECT_TRUE(a->stepUp().grants().empty()) << "the single-use grant is spent";
    EXPECT_EQ(ops::devices::pairStatus(*incoming.peer, incoming.request_id).state,
              vh::device::RequestState::Approved);
    EXPECT_EQ(auditActions(owner->id, "device.approval.%"),
              (std::vector<std::string>{"device.approval.submit/success", "device.approval.key.register/success"}));
}

// The other two ways (design 6.5): the console (a passkey or password + TOTP step-up: here its grant) and the local
// CLI, exempt as a host action. Both register the request's approval key; a request without one pairs as before.
TEST_F(DeviceApprovalsDb, PairingFromTheConsoleAndTheCliRegistersTheApprovalKey) {
    const auto owner = newUser("unprivileged");
    const auto web = console(owner);
    const ApprovalKey k1, k2;

    (void)ops::devices::openWindow(owner);
    const auto fromConsole = newDeviceRequest(k1.spkiB64());
    const auto approveOnWeb = [&] {
        return h::Devices::pairingApprove(json{{"request_id", fromConsole.request_id}, {"code", fromConsole.code}}, web);
    };
    const auto refused = run(web, approveOnWeb);
    ASSERT_EQ(refused.code, "step_up_required");
    web->stepUp().addGrant({.user_id = owner->id, .refresh_jti = web->tokens->refreshToken->jti,
                            .family = Family::DeviceTrust, .target = refused.data.at("target").get<std::string>(),
                            .method = "webauthn", .expires_at = SysClock::now() + std::chrono::minutes(5)});
    const auto approved = run(web, approveOnWeb);
    ASSERT_TRUE(approved.ok) << approved.code << " " << approved.message;
    const auto k1Row = db::query::device::ApprovalKeys::forDevice(approved.data.at("device").at("id").get<uint32_t>());
    ASSERT_TRUE(k1Row);
    EXPECT_EQ(k1Row->spki_sha256, k1.spkiHex());

    // `vh device pair` / `vh device approve` on the node: the host account is the trust anchor (design 5.6).
    (void)ops::devices::openWindow(owner);
    const auto fromCli = newDeviceRequest(k2.spkiB64());
    const auto cliDevice = [&] {
        const Scope host(stepup::Channel::Host);
        return ops::devices::approve(owner, fromCli.request_id, fromCli.code);
    }();
    const auto k2Row = db::query::device::ApprovalKeys::forDevice(cliDevice.id);
    ASSERT_TRUE(k2Row);
    EXPECT_EQ(k2Row->registered_via, "pairing");

    (void)ops::devices::openWindow(owner);
    const auto withoutKey = newDeviceRequest(std::nullopt);
    const auto plain = [&] {
        const Scope host(stepup::Channel::Host);
        return ops::devices::approve(owner, withoutKey.request_id, withoutKey.code);
    }();
    EXPECT_FALSE(db::query::device::ApprovalKeys::forDevice(plain.id)) << "an approval key is optional";

    // What a request may carry: a key nobody here has, never the connection's own key.
    (void)ops::devices::openWindow(owner);
    EXPECT_THROW((void)newDeviceRequest(k1.spkiB64()), ops::Conflict) << "a known approval key";
    EXPECT_THROW((void)newDeviceRequest(std::string("not base64!")), ops::Invalid);
    EXPECT_THROW((void)newDeviceRequest(crypto::toBase64(std::vector<uint8_t>(91, 0x30))), ops::Invalid);
    auto self = std::make_shared<vh::device::Peer>();
    const ApprovalKey own;
    self->spki = crypto::sha256(own.spki());
    self->spkiHex = crypto::toHex(self->spki);
    self->address = "192.0.2.21";
    const auto nonce = crypto::randomNonce();
    EXPECT_THROW((void)ops::devices::pairRequest(*self, {.name = "Mac", .platform = "macOS",
                                                          .commitment = crypto::toHex(crypto::commitment(self->spki, nonce)),
                                                          .approval_key = own.spkiB64()}),
                 ops::Invalid)
        << "the approval key is a second key";
}

// The approval key's challenge: single use, bound to this session, the family and the target, and a signature over
// exactly the canonical payload by the device's live key. Every other answer is refused and leaves no grant.
TEST_F(DeviceApprovalsDb, AnApprovalKeySignatureMustMatchEverythingOnce) {
    const auto owner = newUser("unprivileged");
    const ApprovalKey key, other;
    const auto paired = pairedDevice(owner, &key);
    const auto& s = paired.session;
    const std::string target = "vault.keys.import:5";
    const auto noGrant = [&] {
        const Scope scope(s);
        EXPECT_THROW(stepup::require(Family::Keys, target), ops::StepUpRequired);
    };

    using Edit = std::function<void(PayloadFields&)>;
    const std::vector<std::pair<std::string, Edit>> mismatches{
        {"node", [](PayloadFields& f) { f.node += "x"; }},
        {"server key", [](PayloadFields& f) { f.server[0] ^= 1; }},
        {"device", [](PayloadFields& f) { f.device[0] ^= 1; }},
        {"family", [](PayloadFields& f) { f.family = "device.trust"; }},
        {"target", [](PayloadFields& f) { f.target = "vault.keys.import:6"; }},
        {"expiry", [](PayloadFields& f) { f.expires += 60; }},
        {"challenge", [](PayloadFields& f) { f.challenge[31] ^= 1; }},
    };
    for (const auto& [what, edit] : mismatches) {
        const auto answer = approveWithKey(s, key, "keys", target, [&, &edit = edit](const json& c, std::vector<uint8_t>) {
            auto f = fieldsOf(c, *paired.peer);
            edit(f);
            return payloadOf(f);
        });
        EXPECT_EQ(answer.code, "invalid") << "a payload with another " << what;
        noGrant();
    }
    // Another key's signature over the right payload.
    EXPECT_EQ(approveWithKey(s, other, "keys", target).code, "invalid");
    noGrant();

    // A challenge is spent by its first answer and answers only its own session.
    const auto c = run(s, [&] { return h::Approvals::challenge(json{{"family", "keys"}, {"target", target}}, s); });
    ASSERT_TRUE(c.ok) << c.message;
    const json answer{{"challenge_id", c.data.at("challenge_id")},
                      {"signature_b64", crypto::toBase64(key.sign(*crypto::fromBase64(c.data.at("payload_b64").get<std::string>())))}};
    const auto again = reconnect(paired, owner);
    EXPECT_EQ(run(again, [&] { return h::Approvals::submit(answer, again); }).code, "not_found")
        << "another session of the same device";
    const auto otherDevice = pairedDevice(owner, &other);
    EXPECT_EQ(run(otherDevice.session, [&] { return h::Approvals::submit(answer, otherDevice.session); }).code,
              "not_found")
        << "another device";
    ASSERT_TRUE(run(s, [&] { return h::Approvals::submit(answer, s); }).ok) << "still the asking session's";
    EXPECT_EQ(run(s, [&] { return h::Approvals::submit(answer, s); }).code, "not_found") << "reused";
    {
        const Scope scope(s);
        EXPECT_NO_THROW(stepup::require(Family::Keys, target));
        EXPECT_THROW(stepup::require(Family::Keys, std::string("vault.keys.import:7")), ops::StepUpRequired)
            << "another target";
    }
    noGrant();  // single use
    {
        const Scope scope(again);
        EXPECT_THROW(stepup::require(Family::Keys, target), ops::StepUpRequired) << "never on another session";
    }

    // D6: the approval key approves keys and device.trust only.
    for (const auto* family : {"settings", "identity.admin", "data.destroy", "secrets", "account.credentials"})
        EXPECT_EQ(run(s, [&] {
                      return h::Approvals::challenge(json{{"family", family}, {"target", "storage.vault.remove:1"}}, s);
                  }).code,
                  "console_approval_required")
            << family;
    EXPECT_EQ(run(s, [&] { return h::Approvals::challenge(json{{"family", "keys"}}, s); }).code, "invalid")
        << "keys is target-bound";

    // A revoked key: an open challenge can't be answered, and no new one is issued.
    const auto open = run(s, [&] { return h::Approvals::challenge(json{{"family", "keys"}, {"target", target}}, s); });
    ASSERT_TRUE(open.ok);
    ASSERT_TRUE(db::query::device::ApprovalKeys::revoke(paired.row.id));
    EXPECT_EQ(run(s, [&] {
                  return h::Approvals::submit(
                      json{{"challenge_id", open.data.at("challenge_id")},
                           {"signature_b64",
                            crypto::toBase64(key.sign(*crypto::fromBase64(open.data.at("payload_b64").get<std::string>())))}},
                      s);
              }).code,
              "approval_key_unavailable");
    EXPECT_EQ(approveWithKey(s, key, "keys", target).code, "approval_key_unavailable");
    noGrant();
    {
        const Scope scope(s);
        try {
            stepup::require(Family::Keys, target);
        } catch (const ops::StepUpRequired& e) {
            EXPECT_EQ(e.methods, std::vector<std::string>{"console_approval"}) << "without a live key";
        }
    }

    // A device without a key, and revoking a device revokes its key.
    const auto keyless = pairedDevice(owner);
    EXPECT_EQ(approveWithKey(keyless.session, key, "keys", target).code, "approval_key_unavailable");
    ASSERT_TRUE(db::query::device::ApprovalKeys::forDevice(otherDevice.row.id)->revoked_at == std::nullopt);
    (void)ops::devices::revoke(owner, std::to_string(otherDevice.row.id));
    EXPECT_TRUE(db::query::device::ApprovalKeys::forDevice(otherDevice.row.id)->revoked());

    const auto actions = auditActions(owner->id, "device.approval.submit");
    EXPECT_EQ(std::ranges::count(actions, "device.approval.submit/success"), 1);
    EXPECT_GE(std::ranges::count(actions, "device.approval.submit/failure"), 8);
    EXPECT_GE(std::ranges::count(actions, "device.approval.submit/denied"), 1);
}

// Design 6.3: a device asks, a person approves in the console with a passkey (UV) and nothing else, and the grant
// lands on the session that asked.
TEST_F(DeviceApprovalsDb, AConsoleApprovalTakesAPasskeyAndLandsOnTheAskingSession) {
    const auto owner = newUser("unprivileged");
    tw::Authenticator passkey;
    enrollPasskey(owner, passkey);
    const auto web = console(owner);
    const auto stranger = console(newUser("unprivileged"));
    const auto paired = pairedDevice(owner);
    const auto& d = paired.session;

    std::vector<std::pair<SessionPtr, json>> pushed;
    setPushForTesting([&](const SessionPtr& to, const json& event) { pushed.emplace_back(to, event); });

    const auto asked = run(d, [&] {
        return h::Approvals::request(json{{"family", "settings"}, {"summary", "Change sharing settings"}}, d);
    });
    ASSERT_TRUE(asked.ok) << asked.code << " " << asked.message;
    const auto id = asked.data.at("approval_id").get<std::string>();
    EXPECT_EQ(asked.data.at("state"), "pending");
    EXPECT_TRUE(asked.data.at("target").is_null()) << "settings is family-wide";

    // The push went to the owner's console session only (not the device, not another account).
    ASSERT_EQ(pushed.size(), 1u);
    EXPECT_EQ(pushed[0].first, web);
    EXPECT_EQ(pushed[0].second.at("command"), "auth.approval.pending");
    EXPECT_EQ(pushed[0].second.at("data").at("approval_id"), id);
    EXPECT_EQ(pushed[0].second.at("data").at("device").at("id"), paired.row.id);

    const auto listed = run(web, [&] { return h::Approvals::list(web); });
    ASSERT_TRUE(listed.ok);
    ASSERT_EQ(listed.data.at("approvals").size(), 1u);
    EXPECT_EQ(listed.data.at("approvals")[0].at("summary"), "Change sharing settings");
    EXPECT_TRUE(run(stranger, [&] { return h::Approvals::list(stranger); }).data.at("approvals").empty());
    EXPECT_EQ(run(stranger, [&] { return h::Approvals::approve(json{{"approval_id", id}}, stranger); }).code, "not_found");

    // Never a TOTP code, a password, or the device itself.
    for (const auto& other : {json{{"approval_id", id}, {"method", "totp"}, {"code", "123456"}},
                              json{{"approval_id", id}, {"code", "123456"}},
                              json{{"approval_id", id}, {"method", "password_totp"}, {"password", kPassword},
                                   {"code", "123456"}}})
        EXPECT_EQ(run(web, [&] { return h::Approvals::approve(other, web); }).code, "invalid") << other.dump();
    EXPECT_EQ(run(d, [&] { return h::Approvals::approve(json{{"approval_id", id}}, d); }).code, "denied");
    // An assertion without user verification.
    EXPECT_EQ(consoleApprove(web, passkey, id, tw::flags::UP).code, "approval_failed");
    {
        const auto status = run(d, [&] { return h::Approvals::status(json{{"approval_id", id}}, d); });
        EXPECT_EQ(status.data.at("state"), "pending");
        const Scope scope(d);
        EXPECT_THROW(stepup::require(Family::Settings), ops::StepUpRequired);
    }

    const auto approved = consoleApprove(web, passkey, id);
    ASSERT_TRUE(approved.ok) << approved.code << " " << approved.message;
    EXPECT_EQ(approved.data.at("approval").at("state"), "approved");

    // Another session of the device can't collect it; the asking one does, once.
    const auto other = reconnect(paired, owner);
    EXPECT_EQ(run(other, [&] { return h::Approvals::status(json{{"approval_id", id}}, other); }).code, "not_found");
    const auto status = run(d, [&] { return h::Approvals::status(json{{"approval_id", id}}, d); });
    ASSERT_TRUE(status.ok);
    EXPECT_EQ(status.data.at("state"), "approved");
    {
        const Scope scope(d);
        EXPECT_NO_THROW(stepup::require(Family::Settings)) << "the console approval's grant";
    }
    {
        const Scope scope(other);
        EXPECT_THROW(stepup::require(Family::Settings), ops::StepUpRequired);
    }
    EXPECT_EQ(d->stepUp().grants().size(), 1u);
    (void)run(d, [&] { return h::Approvals::status(json{{"approval_id", id}}, d); });
    EXPECT_EQ(d->stepUp().grants().size(), 1u) << "one grant per approval";
    EXPECT_EQ(run(web, [&] { return h::Approvals::approve(json{{"approval_id", id}}, web); }).code, "not_found")
        << "already answered";

    // Deny.
    const auto second = run(d, [&] {
        return h::Approvals::request(json{{"family", "data.destroy"}, {"target", "storage.vault.remove:3"},
                                          {"summary", "Remove a vault"}}, d);
    });
    ASSERT_TRUE(second.ok);
    const auto secondId = second.data.at("approval_id").get<std::string>();
    EXPECT_EQ(run(d, [&] { return h::Approvals::request(json{{"family", "data.destroy"}, {"summary", "x"}}, d); }).code,
              "invalid")
        << "data.destroy is target-bound";
    ASSERT_TRUE(run(web, [&] { return h::Approvals::deny(json{{"approval_id", secondId}}, web); }).ok);
    EXPECT_EQ(run(d, [&] { return h::Approvals::status(json{{"approval_id", secondId}}, d); }).data.at("state"),
              "denied");
    {
        const Scope scope(d);
        EXPECT_THROW(stepup::require(Family::DataDestroy, std::string("storage.vault.remove:3")), ops::StepUpRequired);
    }

    // An account without a passkey can't approve (it does the action in the console instead).
    const auto totpOnly = newUser("unprivileged");
    const auto totpWeb = console(totpOnly);
    const auto totpDevice = pairedDevice(totpOnly);
    const auto third = run(totpDevice.session, [&] {
        return h::Approvals::request(json{{"family", "settings"}, {"summary", "Settings"}}, totpDevice.session);
    });
    ASSERT_TRUE(third.ok);
    EXPECT_EQ(run(totpWeb, [&] { return h::Approvals::approve(json{{"approval_id", third.data.at("approval_id")}}, totpWeb); }).code,
              "passkey_required");

    EXPECT_EQ(auditActions(owner->id, "auth.approval.%"),
              (std::vector<std::string>{"auth.approval.request/info", "auth.approval.approve/denied",
                                        "auth.approval.approve/denied", "auth.approval.approve/denied",
                                        "auth.approval.approve/failure", "auth.approval.approve/success",
                                        "auth.approval.request/info", "auth.approval.deny/success"}));
}

TEST_F(DeviceApprovalsDb, ConsoleApprovalRequestsAreRateLimitedPerDevice) {
    const auto owner = newUser("unprivileged");
    const auto web = console(owner);
    const auto paired = pairedDevice(owner);
    const auto& d = paired.session;
    const auto ask = [&] {
        return run(d, [&] { return h::Approvals::request(json{{"family", "settings"}, {"summary", "Settings"}}, d); });
    };
    std::vector<std::string> ids;
    for (std::size_t i = 0; i < kMaxOpenPerDevice; ++i) {
        const auto a = ask();
        ASSERT_TRUE(a.ok) << i << " " << a.message;
        ids.push_back(a.data.at("approval_id").get<std::string>());
    }
    EXPECT_EQ(ask().code, "rate_limited") << "at most 3 open per device";
    const auto elsewhere = pairedDevice(owner);
    EXPECT_TRUE(run(elsewhere.session, [&] {
                    return h::Approvals::request(json{{"family", "settings"}, {"summary", "x"}}, elsewhere.session);
                }).ok)
        << "the limit is per device";
    // Answered requests free a slot, up to 10 an hour.
    std::size_t made = kMaxOpenPerDevice;
    while (made < kMaxPerHourPerDevice) {
        ASSERT_TRUE(run(web, [&] { return h::Approvals::deny(json{{"approval_id", ids.back()}}, web); }).ok);
        ids.pop_back();
        const auto a = ask();
        ASSERT_TRUE(a.ok) << made << " " << a.message;
        ids.push_back(a.data.at("approval_id").get<std::string>());
        ++made;
    }
    ASSERT_TRUE(run(web, [&] { return h::Approvals::deny(json{{"approval_id", ids.back()}}, web); }).ok);
    EXPECT_EQ(ask().code, "rate_limited") << "at most 10 an hour";
}

// An already-paired Desktop registers its approval key once, approved by a person in the console.
TEST_F(DeviceApprovalsDb, AnApprovalKeyIsRegisteredLaterThroughAConsoleApproval) {
    const auto owner = newUser("unprivileged");
    tw::Authenticator passkey;
    enrollPasskey(owner, passkey);
    const auto web = console(owner);
    const auto paired = pairedDevice(owner);
    const auto& d = paired.session;
    const ApprovalKey key, second;

    const auto registerIt = [&](const ApprovalKey& k) {
        return run(d, [&] { return h::Approvals::keyRegister(json{{"public_key_spki_b64", k.spkiB64()}}, d); });
    };
    const auto refused = registerIt(key);
    ASSERT_EQ(refused.code, "step_up_required") << refused.message;
    EXPECT_EQ(refused.data.at("family"), "device.trust");
    EXPECT_EQ(refused.data.at("target"),
              "device.approval.key.register:" + std::to_string(paired.row.id) + ":" + key.spkiHex());
    EXPECT_EQ(refused.data.at("methods"), json::array({"console_approval"})) << "no key yet to approve with";

    const auto asked = run(d, [&] {
        return h::Approvals::request(json{{"family", "device.trust"}, {"target", refused.data.at("target")},
                                          {"summary", "Register this Mac's approval key"}}, d);
    });
    ASSERT_TRUE(asked.ok) << asked.message;
    const auto id = asked.data.at("approval_id").get<std::string>();
    ASSERT_TRUE(consoleApprove(web, passkey, id).ok);
    EXPECT_EQ(registerIt(key).code, "step_up_required") << "the grant is collected by status first";
    ASSERT_TRUE(run(d, [&] { return h::Approvals::status(json{{"approval_id", id}}, d); }).ok);
    EXPECT_EQ(registerIt(second).code, "step_up_required") << "the approval names exactly one key";
    // ... which didn't spend it: the target differs.
    const auto registered = registerIt(key);
    ASSERT_TRUE(registered.ok) << registered.code << " " << registered.message;
    const auto row = db::query::device::ApprovalKeys::forDevice(paired.row.id);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->registered_via, "console_approval");
    EXPECT_EQ(registerIt(second).code, "conflict") << "once per device";

    // And now it approves with it.
    ASSERT_TRUE(approveWithKey(d, key, "keys", "vault.keys.import:1").ok);
}

// Design 5.4/6.1, table-driven over the contract: every command a paired device's session may run that carries no
// step_up annotation never answers step_up_required. Each runs through the daemon's router on a device session of a
// super admin (so RBAC lets it as far as it goes) with a payload made from its contract fields; the trail's
// auth.stepup.required events (every step-up refusal writes one) must not grow. The annotated commands are the
// control: the same probe sees them asking.
TEST_F(DeviceApprovalsDb, ADeviceSessionNeverPromptsForARoutineCommand) {
    const auto admin = newUser("super_admin");
    const auto paired = pairedDevice(admin);
    auto router = std::make_shared<protocols::ws::Router>();
    protocols::ws::Handler::registerAllHandlers(router);

    // What would end this device session or reach outside the test (writes the daemon's config file, closes the
    // session); each is exempt from a step-up by design, said here so nothing goes unexamined.
    const std::map<std::string, std::string> skipped{
        {"device.revoke", "revokes the device (and ends this session); revocation is never stepped up"},
        {"device.remote.disable", "writes the daemon's config file; turning remote off is never stepped up"},
        {"auth.logout", "a device has no sign-out (the router refuses it)"},
        {"stats.vault", "runs on the stats thread pool, which this test process doesn't start; a read"},
        {"storage.vault.sync", "starts the vault's sync engine, which this test process doesn't run; routine sync"},
    };

    const auto renderPattern = [](const std::string& pattern) {
        std::string out;
        for (std::size_t i = 0; i < pattern.size(); ++i) {
            if (pattern[i] == '{' && i + 2 < pattern.size() && pattern[i + 2] == '}') {
                const char c = pattern[i + 1];
                out.push_back(c == 'a' ? 'a' : c == 'A' ? 'A' : c == '9' ? '1' : 'x');
                i += 2;
            } else {
                out.push_back(pattern[i]);
            }
        }
        return out;
    };
    std::function<json(const contract::WsField&)> value = [&](const contract::WsField& f) -> json {
        const auto type = f.types.empty() ? std::string("string") : f.types.front();
        if (!f.enum_values.empty()) return f.enum_values.front();
        if (f.generator) {
            const auto& g = *f.generator;
            using K = contract::FieldGen::Kind;
            std::string text;
            switch (g.kind) {
                case K::Const: text = g.values.empty() ? "" : g.values.front(); break;
                case K::OneOf: text = g.values.empty() ? "" : g.values.front(); break;
                case K::IntRange: return g.min;
                case K::Bool: return false;
                case K::Email: text = "probe@example.com"; break;
                case K::Pattern:
                case K::Path: text = renderPattern(g.pattern); break;
                case K::Bytes: text = "probe"; break;
                case K::Ref: text = "1"; break;
            }
            if (type == "integer" || type == "number") {
                try {
                    return std::stoll(text);
                } catch (...) {
                    return 1;
                }
            }
            if (type == "boolean") return text == "true";
            if (type == "object" || type == "array") {
                try {
                    return json::parse(text);
                } catch (...) {
                }
            } else {
                return text;
            }
        }
        if (type == "integer" || type == "number") return f.minimum.value_or(1) > 0 ? f.minimum.value_or(1) : 1;
        if (type == "boolean") return false;
        if (type == "array") return json::array();
        if (type == "null") return nullptr;
        if (type == "object") {
            json o = json::object();
            for (const auto& member : f.fields)
                if (member.required) o[member.name] = value(member);
            return o;
        }
        return "probe";
    };

    const auto refusals = [&] {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("stepup refusals", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = 'auth.stepup.required' AND actor_id = $1",
                            pqxx::params{admin->id})
                .one_field_ref()
                .as<int64_t>();
        });
    };

    std::set<std::string> annotated;
    for (const auto& r : contract::stepUpTable()) annotated.insert(r.command);
    std::vector<std::string> routine;
    for (const auto& c : contract::ws::commands()) {
        if (protocols::ws::Router::classifyCommand(c.command, *paired.session) !=
            protocols::ws::Router::CommandAuthDecision::Allow)
            continue;
        if (annotated.contains(c.command)) continue;
        ASSERT_FALSE(c.step_up) << c.command;
        if (skipped.contains(c.command)) continue;
        routine.push_back(c.command);
    }
    ASSERT_GE(routine.size(), 150u) << "the device-allowed set shrank: is the router refusing devices?";
    for (const auto* cmd : {"device.pairing.pending", "device.approval.request", "fs.dir.list", "vault.keys.status",
                            "device.endpoints", "meta.hello"})
        EXPECT_TRUE(std::ranges::find(routine, std::string(cmd)) != routine.end()) << cmd;

    std::vector<json> answers;
    paired.session->setSendSinkForTesting([&](const json& frame) { answers.push_back(frame); });
    // The router's answer to `c` with a payload made from its contract fields.
    const auto send = [&](const contract::WsCommandUsage& c) -> json {
        json payload = json::object();
        for (const auto& f : c.payload)
            if (f.required) payload[f.name] = value(f);
        answers.clear();
        router->routeMessage(json{{"command", c.command}, {"requestId", "probe-" + c.command},
                                  {"payload", std::move(payload)}},
                             paired.session);
        return answers.empty() ? json(nullptr) : answers.back();
    };
    const auto codeOf = [](const json& frame) {
        return frame.is_object() && frame.contains("data") && frame.at("data").is_object()
                   ? frame.at("data").value("code", std::string{})
                   : std::string{};
    };

    const auto before = refusals();
    std::map<std::string, contract::WsCommandUsage> book;
    for (auto& c : contract::ws::commands()) book.emplace(c.command, c);
    for (const auto& cmd : routine) {
        const auto answer = send(book.at(cmd));
        EXPECT_FALSE(answer.is_null()) << cmd << " was not answered";
        EXPECT_NE(codeOf(answer), "step_up_required") << cmd << " asked a paired device for a step-up";
        EXPECT_NE(answer.value("status", std::string{}), "UNAUTHORIZED") << cmd << " was refused to the device";
        ASSERT_FALSE(paired.session->closing()) << cmd << " ended the device session";
    }
    EXPECT_EQ(refusals(), before) << "a step-up refusal was audited for a routine command";

    // The control: an annotated command does ask (the probe sees it), here device.pairing.approve on a real request.
    (void)ops::devices::openWindow(admin);
    const auto incoming = newDeviceRequest(std::nullopt);
    answers.clear();
    router->routeMessage(json{{"command", "device.pairing.approve"}, {"requestId", "probe-control"},
                              {"payload", {{"request_id", incoming.request_id}, {"code", incoming.code}}}},
                         paired.session);
    ASSERT_FALSE(answers.empty());
    EXPECT_EQ(codeOf(answers.back()), "step_up_required") << "the probe can't see a step-up refusal";
    EXPECT_EQ(refusals(), before + 1) << "nor its audit event";
}

}
