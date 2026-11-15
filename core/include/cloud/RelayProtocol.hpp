#pragma once

#include "device/Crypto.hpp"

#include <array>
#include <cstdint>
#include <ctime>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The server's end of the Vaulthalla Cloud relay protocol (design/cloud/relay.md; the cloud's docs/design/relay.md,
// "As built", is normative for the wire and the tickets). Pure functions and two small in-memory guards; the
// connection itself is cloud/RelayService, the relayed streams the device listener (protocols/device/Relayed).
namespace vh::cloud::relay {

// ---- frames (one binary WebSocket message each, on the server's connection) -------------------------------------
//   type:u8 [stream:u32 big-endian, for types 0x10-0x13] payload
enum class FrameType : uint8_t {
    Ticket = 0x01,     // server -> relay, first: the ticket's text
    Challenge = 0x02,  // relay -> server: 32 random bytes
    Proof = 0x03,      // server -> relay: Ed25519 signature of connectMessage(jti, challenge)
    Welcome = 0x04,    // relay -> server: JSON
    Renew = 0x05,      // server -> relay: a newer ticket
    Renewed = 0x06,    // relay -> server: JSON {"renew_by"}
    Open = 0x10,       // relay -> server, stream: JSON {"ticket", "remote"}
    Data = 0x11,       // both, stream: 1 to kMaxData bytes
    Credit = 0x12,     // both, stream: u32 big-endian > 0
    Close = 0x13,      // both, stream: the reason's name
};

inline constexpr std::size_t kMaxData = 64 * 1024;
inline constexpr std::size_t kMaxMessage = kMaxData + 5;
inline constexpr std::size_t kChallengeBytes = 32;
inline constexpr std::size_t kMaxTicketBytes = 2048;

struct Frame {
    FrameType type{};
    uint32_t stream{};
    std::vector<uint8_t> payload{};
    uint32_t credit{};
    [[nodiscard]] std::string text() const { return {payload.begin(), payload.end()}; }
};

// Structural checks as the relay makes them (a type the relay sends the server, a stream id where one belongs and
// never 0, DATA of 1 to kMaxData bytes, CREDIT of exactly 4 bytes and more than 0, CHALLENGE of 32). nullopt otherwise.
[[nodiscard]] std::optional<Frame> decode(std::span<const uint8_t> message);
[[nodiscard]] std::vector<uint8_t> control(FrameType type, std::span<const uint8_t> payload);
[[nodiscard]] std::vector<uint8_t> control(FrameType type, std::string_view payload);
[[nodiscard]] std::vector<uint8_t> data(uint32_t stream, std::span<const uint8_t> bytes);
[[nodiscard]] std::vector<uint8_t> credit(uint32_t stream, uint32_t bytes);
[[nodiscard]] std::vector<uint8_t> closeStream(uint32_t stream, std::string_view reason);
// For tests and fakes: the relay's side of the same encoding.
[[nodiscard]] std::vector<uint8_t> encodeForTesting(const Frame& frame);

// "vhc-relay-connect-v1\n" + jti + "\n" + base64url(challenge): what PROOF signs.
[[nodiscard]] std::string connectMessage(std::string_view jti, std::span<const uint8_t> challenge);

// The relay's close codes (WebSocket close of the server connection) and stream CLOSE reason names.
enum class Reason : uint8_t { Done, Protocol, Unauthorized, Superseded, Renew, Idle, Limit, Offline, Refused, Lifetime,
                              Shutdown, Budget };
[[nodiscard]] std::string_view toString(Reason r) noexcept;
[[nodiscard]] std::optional<Reason> reasonOfCode(uint16_t code) noexcept;
[[nodiscard]] uint16_t closeCode(Reason r) noexcept;

// ---- tickets -------------------------------------------------------------------------------------------------------

using TicketKey = std::array<uint8_t, 32>;  // an Ed25519 public key the daemon signs tickets with

struct BrowserTicket {
    std::string audience, account, deployment, jti, key_id, spki_sha256;
    int64_t issued_at = 0, expires_at = 0, renew = 0;
    uint64_t stream_bytes = 0;
};

enum class TicketRefusal { Malformed, BadSignature, WrongType, WrongAudience, WrongAccount, WrongDeployment, Expired,
                           NotYetValid, Replayed };
[[nodiscard]] std::string_view toString(TicketRefusal r) noexcept;

struct BrowserTicketCheck {
    std::optional<BrowserTicket> ticket{};
    TicketRefusal refusal{TicketRefusal::Malformed};
    [[nodiscard]] bool ok() const noexcept { return ticket.has_value(); }
};

// What the server checks of each OPEN's browser ticket: one of `keys` signed it (over "vhc-relay-ticket-v1\n" + c),
// its claims are exactly the browser set, `typ` browser, `aud` the relay this server is admitted to, `acct` and `dep`
// this server's own link, valid at `now` (iat - 30 s to before exp, at most 300 s long). The jti is the caller's
// (JtiLedger). Never throws.
[[nodiscard]] BrowserTicketCheck verifyBrowserTicket(std::string_view text, std::span<const TicketKey> keys,
                                                     std::string_view audience, std::string_view account,
                                                     std::string_view deployment, int64_t now) noexcept;

// The claims of a ticket, unverified: the server reads its own ticket's jti for the PROOF. nullopt when malformed.
[[nodiscard]] std::optional<std::string> unverifiedJti(std::string_view ticket);

// jti spent once at the server (the relay spends it once too): each kept until its ticket's exp. Bounded: past
// kMaxEntries live entries everything is refused (fails closed) until some expire.
class JtiLedger {
public:
    static constexpr std::size_t kMaxEntries = 100000;
    // True the first time a jti is seen before `expiresAt`; false for a replay (or a full ledger).
    [[nodiscard]] bool spend(const std::string& jti, int64_t expiresAt, int64_t now);
    void clear();

private:
    std::mutex mutex_;
    std::map<std::string, int64_t> seen_;
};

// ---- the browser's key proof inside the relayed TLS stream (option (c)) ---------------------------------------------
//
// After the inner TLS handshake (the browser authenticates the server by its pin and presents no certificate):
//   server -> browser   kProofVersion ‖ nonce[32]                                          (33 bytes)
//   browser -> server   kProofVersion ‖ spki[91] ‖ signature[64]                           (156 bytes)
// spki: the browser key's SubjectPublicKeyInfo DER (WebCrypto exportKey("spki") of a P-256 key: 91 bytes); signature:
// ECDSA P-256 / SHA-256 in WebCrypto's raw r ‖ s form over proofMessage(jti, nonce, exporter), where exporter is the
// TLS 1.3 exporter (RFC 8446 7.5) with label kExporterLabel, no context (an empty one is the same in TLS 1.3), 32 bytes.
// Then the listener's HTTP request (/ws or a lane), unchanged.
inline constexpr uint8_t kProofVersion = 1;
inline constexpr std::size_t kNonceBytes = 32;
inline constexpr std::size_t kExporterBytes = 32;
inline constexpr std::size_t kSpkiBytes = 91;
inline constexpr std::size_t kRawSignatureBytes = 64;
inline constexpr std::size_t kChallengeRecordBytes = 1 + kNonceBytes;
inline constexpr std::size_t kProofRecordBytes = 1 + kSpkiBytes + kRawSignatureBytes;
inline constexpr std::string_view kExporterLabel = "EXPORTER-vhc-relay-browser-v1";

// "vhc-relay-browser-proof-v1\n" + jti + "\n" + base64url(nonce) + "\n" + base64url(exporter)
[[nodiscard]] std::string proofMessage(std::string_view jti, std::span<const uint8_t> nonce,
                                       std::span<const uint8_t> exporter);
[[nodiscard]] std::array<uint8_t, kChallengeRecordBytes> challengeRecord(std::span<const uint8_t, kNonceBytes> nonce);

enum class ProofRefusal { Malformed, KeyMismatch, BadSignature };
[[nodiscard]] std::string_view toString(ProofRefusal r) noexcept;

struct ProofCheck {
    std::optional<device::crypto::PublicKey> key{};
    ProofRefusal refusal{ProofRefusal::Malformed};
    [[nodiscard]] bool ok() const noexcept { return key.has_value(); }
};

// The browser's proof record against the ticket's spki_sha256 (hex), the ticket's jti, the nonce this server sent and
// this TLS session's exporter. Never throws.
[[nodiscard]] ProofCheck verifyProof(std::span<const uint8_t> record, std::string_view expectedSpkiHex,
                                     std::string_view jti, std::span<const uint8_t> nonce,
                                     std::span<const uint8_t> exporter) noexcept;

// ECDSA raw r ‖ s (64 bytes) as a DER Ecdsa-Sig-Value; nullopt for anything else.
[[nodiscard]] std::optional<std::vector<uint8_t>> rawSignatureToDer(std::span<const uint8_t> raw);

// Failed proofs and refused tickets: at most kPerKey a minute per browser key hash and kTotal a minute in all. Past
// either, OPENs for that key (or every OPEN) are refused until the minute is over.
class FailureLimiter {
public:
    static constexpr unsigned kPerKey = 5;
    static constexpr unsigned kTotal = 30;
    [[nodiscard]] bool allowed(const std::string& key, int64_t now);
    void fail(const std::string& key, int64_t now);
    void clear();

private:
    void rollLocked(int64_t now);
    std::mutex mutex_;
    int64_t minute_ = 0;
    unsigned total_ = 0;
    std::map<std::string, unsigned> perKey_;
};

}
