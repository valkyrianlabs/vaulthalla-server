// The server's end of the Vaulthalla Cloud relay, DB-free (design/cloud/relay.md): the frames as the relay sends them,
// the browser ticket re-check (another server's ticket, another account's, an expired one, one signed by an unknown
// key, a server ticket, an extra claim, a replayed jti), the browser's key proof inside the stream (the right key, a
// key that isn't the ticket's, a proof made for another TLS session, a proof replayed against a new challenge, a
// malformed record), the failure limiter, and the read-only capability set: every registered ws command is walked on a
// relayed device session and everything outside the reviewed read-only set is refused relay_read_only.

#include "cloud/RelayProtocol.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "../helpers/relay_browser.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <vl/keykit/base64url.hpp>

#include <set>
#include <string>

namespace vh::test_cloud_relay_protocol {

namespace relay = cloud::relay;
using json = nlohmann::json;

constexpr const char* kAccount = "0b5f6d2e-8c1a-4b7e-9f00-1234567890ab";
constexpr const char* kDeployment = "d3p1qymnt00000000000000000";
constexpr const char* kAudience = "relay-1";

std::span<const uint8_t> bytesOf(const std::string& s) { return {reinterpret_cast<const uint8_t*>(s.data()), s.size()}; }

// The daemon's side: an Ed25519 ticket key that signs tickets the way the cloud's relay::issue does.
struct TicketSigner {
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    TicketSigner() { crypto_sign_keypair(pk.data(), sk.data()); }
    [[nodiscard]] relay::TicketKey key() const {
        relay::TicketKey k{};
        std::ranges::copy(pk, k.begin());
        return k;
    }
    [[nodiscard]] std::string sign(const json& claims) const {
        const auto c = vl::keykit::base64UrlEncode(bytesOf(claims.dump()));
        const auto input = "vhc-relay-ticket-v1\n" + c;
        std::array<uint8_t, crypto_sign_BYTES> sig{};
        crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const unsigned char*>(input.data()), input.size(), sk.data());
        return "vhr1." + c + "." + vl::keykit::base64UrlEncode(sig);
    }
};

std::string randomJti() {
    std::array<uint8_t, 16> b{};
    randombytes_buf(b.data(), b.size());
    return vl::keykit::base64UrlEncode(b);
}

json browserClaims(const std::string& spki, const int64_t now) {
    return {{"typ", "browser"}, {"aud", kAudience}, {"acct", kAccount}, {"dep", kDeployment}, {"iat", now},
            {"exp", now + 60}, {"jti", randomJti()}, {"renew", 600}, {"kid", "k3ymd00000000000000000000g"},
            {"spki", spki},
            {"lim", {{"stream_bytes", 2147483648LL}, {"day_bytes", 10737418240LL}, {"day_used", 0}, {"day", "2026-11-15"}}}};
}

int64_t now() { return std::time(nullptr); }

relay::BrowserTicketCheck check(const std::string& ticket, const TicketSigner& signer, const int64_t at = now()) {
    const std::vector<relay::TicketKey> keys{signer.key()};
    return relay::verifyBrowserTicket(ticket, keys, kAudience, kAccount, kDeployment, at);
}

// ---- frames ---------------------------------------------------------------------------------------------------------

TEST(CloudRelayFrames, DecodeWhatTheRelaySendsAndNothingElse) {
    const auto open = relay::encodeForTesting({.type = relay::FrameType::Open, .stream = 7, .payload = {'{', '}'}, .credit = 0});
    const auto f = relay::decode(open);
    ASSERT_TRUE(f);
    EXPECT_EQ(f->type, relay::FrameType::Open);
    EXPECT_EQ(f->stream, 7u);
    const auto c = relay::decode(relay::credit(9, 65536));
    ASSERT_TRUE(c);
    EXPECT_EQ(c->credit, 65536u);
    EXPECT_FALSE(relay::decode(relay::credit(9, 0))) << "a zero credit";
    EXPECT_FALSE(relay::decode(relay::data(0, bytesOf("x")))) << "stream 0";
    EXPECT_FALSE(relay::decode(relay::control(relay::FrameType::Ticket, "vhr1.x"))) << "the relay never sends TICKET";
    EXPECT_FALSE(relay::decode(relay::control(relay::FrameType::Challenge, "short"))) << "a challenge is 32 bytes";
    std::vector<uint8_t> big(relay::kMaxData + 1, 'a');
    EXPECT_FALSE(relay::decode(relay::data(3, big))) << "DATA over 64 KiB";
    big.resize(relay::kMaxData);
    EXPECT_TRUE(relay::decode(relay::data(3, big)));
    EXPECT_EQ(relay::closeCode(relay::Reason::Refused), 4007);
    EXPECT_EQ(relay::reasonOfCode(4001), relay::Reason::Unauthorized);
    EXPECT_EQ(relay::reasonOfCode(1000), relay::Reason::Done);
    EXPECT_EQ(relay::toString(relay::Reason::Budget), "budget");
    EXPECT_FALSE(relay::reasonOfCode(4011));
}

// ---- the browser ticket ---------------------------------------------------------------------------------------------

TEST(CloudRelayTickets, TheServerReChecksEveryBrowserTicket) {
    const TicketSigner signer;
    const auto spki = std::string(64, 'a');
    const auto good = check(signer.sign(browserClaims(spki, now())), signer);
    ASSERT_TRUE(good.ok());
    EXPECT_EQ(good.ticket->spki_sha256, spki);

    auto claims = browserClaims(spki, now());
    claims["dep"] = "an0therdep10yment000000000";
    EXPECT_EQ(check(signer.sign(claims), signer).refusal, relay::TicketRefusal::WrongDeployment) << "another server's";
    claims = browserClaims(spki, now());
    claims["acct"] = "ffffffff-8c1a-4b7e-9f00-1234567890ab";
    EXPECT_EQ(check(signer.sign(claims), signer).refusal, relay::TicketRefusal::WrongAccount);
    EXPECT_EQ(check(signer.sign(browserClaims(spki, now() - 120)), signer).refusal, relay::TicketRefusal::Expired);
    EXPECT_EQ(check(signer.sign(browserClaims(spki, now() + 120)), signer).refusal, relay::TicketRefusal::NotYetValid);
    const TicketSigner stranger;
    EXPECT_EQ(check(stranger.sign(browserClaims(spki, now())), signer).refusal, relay::TicketRefusal::BadSignature)
        << "signed by a key the ticket answer didn't list";
    claims = browserClaims(spki, now());
    claims["typ"] = "server";
    EXPECT_EQ(check(signer.sign(claims), signer).refusal, relay::TicketRefusal::WrongType);
    claims = browserClaims(spki, now());
    claims["aud"] = "relay-2";
    EXPECT_EQ(check(signer.sign(claims), signer).refusal, relay::TicketRefusal::WrongAudience);
    claims = browserClaims(spki, now());
    claims["admin"] = true;
    EXPECT_EQ(check(signer.sign(claims), signer).refusal, relay::TicketRefusal::Malformed) << "no other claims";
    claims = browserClaims(spki, now());
    claims["exp"] = now() + 3600;
    EXPECT_EQ(check(signer.sign(claims), signer).refusal, relay::TicketRefusal::Malformed) << "longer than 300 s";
    claims = browserClaims("ABC", now());
    EXPECT_EQ(check(signer.sign(claims), signer).refusal, relay::TicketRefusal::Malformed);

    // A tampered body fails the signature before it is parsed.
    auto ticket = signer.sign(browserClaims(spki, now()));
    ticket[10] = ticket[10] == 'A' ? 'B' : 'A';
    EXPECT_NE(check(ticket, signer).refusal, relay::TicketRefusal::WrongDeployment);
    EXPECT_FALSE(check(ticket, signer).ok());
    EXPECT_FALSE(check("not a ticket", signer).ok());
}

TEST(CloudRelayTickets, AJtiIsSpentOnceUntilItsTicketExpires) {
    relay::JtiLedger ledger;
    const auto jti = randomJti();
    EXPECT_TRUE(ledger.spend(jti, now() + 60, now()));
    EXPECT_FALSE(ledger.spend(jti, now() + 60, now())) << "a replayed ticket";
    EXPECT_TRUE(ledger.spend(randomJti(), now() + 60, now()));
    EXPECT_TRUE(ledger.spend(jti, now() + 200, now() + 100)) << "forgotten once its ticket expired (and refused then)";
    EXPECT_EQ(relay::unverifiedJti(TicketSigner{}.sign({{"jti", jti}})), jti);
}

// ---- the key proof --------------------------------------------------------------------------------------------------

struct ProofFixture {
    test::relay::BrowserKey key;
    std::vector<uint8_t> nonce = std::vector<uint8_t>(32, 0x11);
    std::vector<uint8_t> exporter = std::vector<uint8_t>(32, 0x22);
    std::string jti = randomJti();

    [[nodiscard]] std::vector<uint8_t> record(const test::relay::BrowserKey& signer, const std::string& j,
                                              const std::vector<uint8_t>& n, const std::vector<uint8_t>& e) const {
        std::vector<uint8_t> out{relay::kProofVersion};
        const auto spki = signer.publicKey().spkiDer;
        out.insert(out.end(), spki.begin(), spki.end());
        const auto sig = signer.signRaw(relay::proofMessage(j, n, e));
        out.insert(out.end(), sig.begin(), sig.end());
        return out;
    }
};

TEST(CloudRelayProof, TheBrowserProvesTheTicketsKeyBoundToThisTlsSession) {
    const ProofFixture f;
    EXPECT_EQ(relay::proofMessage("j", f.nonce, f.exporter),
              "vhc-relay-browser-proof-v1\nj\n" + vl::keykit::base64UrlEncode(f.nonce) + "\n" +
                  vl::keykit::base64UrlEncode(f.exporter));
    const auto good = relay::verifyProof(f.record(f.key, f.jti, f.nonce, f.exporter), f.key.spkiHex(), f.jti, f.nonce, f.exporter);
    ASSERT_TRUE(good.ok());
    EXPECT_EQ(vh::device::crypto::toHex(good.key->spkiSha256), f.key.spkiHex());
    EXPECT_EQ(good.key->spkiDer.size(), relay::kSpkiBytes);

    // Another key than the ticket names, even with a valid signature of its own.
    const test::relay::BrowserKey other;
    EXPECT_EQ(relay::verifyProof(f.record(other, f.jti, f.nonce, f.exporter), f.key.spkiHex(), f.jti, f.nonce, f.exporter).refusal,
              relay::ProofRefusal::KeyMismatch);
    // A proof made in another TLS session (its exporter) can't be carried into this one.
    const std::vector<uint8_t> otherSession(32, 0x23);
    EXPECT_EQ(relay::verifyProof(f.record(f.key, f.jti, f.nonce, otherSession), f.key.spkiHex(), f.jti, f.nonce, f.exporter).refusal,
              relay::ProofRefusal::BadSignature);
    // A proof replayed against a new challenge (another nonce).
    const std::vector<uint8_t> newNonce(32, 0x12);
    EXPECT_EQ(relay::verifyProof(f.record(f.key, f.jti, f.nonce, f.exporter), f.key.spkiHex(), f.jti, newNonce, f.exporter).refusal,
              relay::ProofRefusal::BadSignature);
    // Made for another ticket.
    EXPECT_EQ(relay::verifyProof(f.record(f.key, randomJti(), f.nonce, f.exporter), f.key.spkiHex(), f.jti, f.nonce, f.exporter).refusal,
              relay::ProofRefusal::BadSignature);
    // Malformed: short, another version byte, a signature of zeros.
    auto rec = f.record(f.key, f.jti, f.nonce, f.exporter);
    EXPECT_EQ(relay::verifyProof(std::span(rec).first(100), f.key.spkiHex(), f.jti, f.nonce, f.exporter).refusal,
              relay::ProofRefusal::Malformed);
    rec[0] = 2;
    EXPECT_EQ(relay::verifyProof(rec, f.key.spkiHex(), f.jti, f.nonce, f.exporter).refusal, relay::ProofRefusal::Malformed);
    rec[0] = 1;
    std::fill(rec.end() - 64, rec.end(), 0);
    EXPECT_EQ(relay::verifyProof(rec, f.key.spkiHex(), f.jti, f.nonce, f.exporter).refusal, relay::ProofRefusal::BadSignature);
    EXPECT_FALSE(relay::rawSignatureToDer(std::vector<uint8_t>(63, 1)));
}

TEST(CloudRelayProof, FailuresAreLimitedPerKeyAndInAll) {
    relay::FailureLimiter limiter;
    const int64_t t = 1'800'000'000;
    for (unsigned i = 0; i < relay::FailureLimiter::kPerKey; ++i) {
        EXPECT_TRUE(limiter.allowed("a", t));
        limiter.fail("a", t);
    }
    EXPECT_FALSE(limiter.allowed("a", t)) << "this key, this minute";
    EXPECT_TRUE(limiter.allowed("b", t));
    EXPECT_TRUE(limiter.allowed("a", t + 60)) << "the next minute";
    for (unsigned i = 0; i < relay::FailureLimiter::kTotal; ++i) limiter.fail("", t + 60);
    EXPECT_FALSE(limiter.allowed("c", t + 60)) << "every key, once the total is reached";
}

// ---- the read-only capability set -----------------------------------------------------------------------------------

std::shared_ptr<identities::User> superAdmin() {
    identities::UserState state;
    state.name = "relay-owner";
    state.roles.admin = std::make_shared<rbac::role::Admin>();
    return identities::User::detached(9301, std::move(state));
}

std::shared_ptr<protocols::ws::Session> deviceSession(const bool relayed, const bool pairedViaRelay) {
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spki.fill(relayed ? 0x41 : 0x42);
    peer->spkiHex = vh::device::crypto::toHex(peer->spki);
    peer->address = "203.0.113.9";
    peer->deviceRowId = relayed ? 41 : 42;
    peer->relayed = relayed;
    peer->pairedViaRelay = pairedViaRelay;
    return protocols::ws::Session::devicePrincipal(std::move(peer), superAdmin(), [] {});
}

// What a relayed session may run, reviewed one by one: none of them changes anything the server stores (a download
// and a change subscription live in the session).
const std::set<std::string>& reviewedReadOnly() {
    static const std::set<std::string> commands{
        "meta.hello", "meta.contract.get", "storage.vault.list", "storage.vault.accessible.list", "storage.vault.get",
        "fs.list", "fs.dir.list", "fs.metadata", "fs.download.start", "fs.download.chunk", "fs.download.cancel",
        "fs.changes.list", "fs.changes.subscribe", "fs.changes.unsubscribe", "device.list"};
    return commands;
}

TEST(CloudRelayReadOnly, EveryCommandOutsideTheReadOnlySetIsRefusedOnARelayedSession) {
    auto router = std::make_shared<protocols::ws::Router>();
    protocols::ws::Handler::registerAllHandlers(router);
    const auto commands = router->commands();
    ASSERT_GT(commands.size(), 200u);
    using Decision = protocols::ws::Router::CommandAuthDecision;
    const auto relayed = deviceSession(true, true);
    const auto relayPairedOnTheListener = deviceSession(false, true);
    const auto desktop = deviceSession(false, false);
    std::size_t allowed = 0;
    for (const auto& command : commands) {
        const auto decision = protocols::ws::Router::classifyCommand(command, *relayed);
        if (reviewedReadOnly().contains(command)) {
            EXPECT_EQ(decision, Decision::Allow) << command;
            ++allowed;
        } else {
            // Every mutating command (and every read outside browsing) is refused before its handler runs, even for a
            // super admin.
            EXPECT_TRUE(decision == Decision::DenyReadOnly || decision == Decision::Deny) << command;
        }
        EXPECT_EQ(protocols::ws::Router::classifyCommand(command, *relayPairedOnTheListener), decision)
            << command << ": a relay-paired device is held to the same set on any connection";
        if (!reviewedReadOnly().contains(command))
            EXPECT_EQ(protocols::ws::Router::isRelayedReadCommand(command), false) << command;
    }
    EXPECT_EQ(allowed, reviewedReadOnly().size()) << "every reviewed command is registered";
    // A paired Desktop is not narrowed.
    EXPECT_EQ(protocols::ws::Router::classifyCommand("fs.entry.delete", *desktop), Decision::Allow);
    EXPECT_EQ(protocols::ws::Router::classifyCommand("fs.entry.delete", *relayed), Decision::DenyReadOnly);
    for (const auto* mutating : {"fs.upload.start", "fs.dir.create", "fs.entry.move", "vault.keys.export",
                                 "vault.keys.export.confirm", "device.pairing.approve", "device.revoke",
                                 "device.identity.rotate", "device.endpoints", "device.approval.challenge",
                                 "device.approval.submit", "device.approval.key.register", "cloud.relay.enable",
                                 "settings.update", "share.link.create", "auth.user.update"})
        EXPECT_EQ(protocols::ws::Router::classifyCommand(mutating, *relayed), Decision::DenyReadOnly) << mutating;
    // An unregistered command is refused too (the allowlist, not a denylist).
    EXPECT_EQ(protocols::ws::Router::classifyCommand("fs.entry.purge_everything", *relayed), Decision::DenyReadOnly);
    (void)runtime::Deps::releaseSessions();  // the device principals joined the session manager
}

}
