#include "cloud/RelayProtocol.hpp"

#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <sodium.h>
#include <vl/keykit/base64url.hpp>

#include <algorithm>
#include <set>

namespace vh::cloud::relay {

namespace {

using json = nlohmann::json;

constexpr std::string_view kTicketPrefix = "vhr1.";
constexpr std::string_view kTicketContext = "vhc-relay-ticket-v1\n";
constexpr std::string_view kConnectContext = "vhc-relay-connect-v1\n";
constexpr std::string_view kProofContext = "vhc-relay-browser-proof-v1\n";
constexpr int64_t kClockSkew = 30;
constexpr int64_t kMaxTicketLifetime = 300;
constexpr std::array<std::string_view, 12> kReasonNames{"done", "protocol", "unauthorized", "superseded", "renew",
                                                        "idle", "limit", "offline", "refused", "lifetime",
                                                        "shutdown", "budget"};

std::span<const uint8_t> bytesOf(const std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

bool hasStream(const FrameType t) {
    return t == FrameType::Open || t == FrameType::Data || t == FrameType::Credit || t == FrameType::Close;
}

void putU32(std::vector<uint8_t>& out, const uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void setU32(uint8_t* at, const uint32_t v) {
    at[0] = static_cast<uint8_t>(v >> 24);
    at[1] = static_cast<uint8_t>(v >> 16);
    at[2] = static_cast<uint8_t>(v >> 8);
    at[3] = static_cast<uint8_t>(v);
}

uint32_t getU32(const std::span<const uint8_t> b) {
    return static_cast<uint32_t>(b[0]) << 24 | static_cast<uint32_t>(b[1]) << 16 | static_cast<uint32_t>(b[2]) << 8 |
           static_cast<uint32_t>(b[3]);
}

bool isHex64(const std::string_view s) {
    return s.size() == 64 && std::ranges::all_of(s, [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

bool isUuid(const std::string_view s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

// The cloud's random ids: 128 bits as 26 symbols of lower-case Crockford base32, the 2 padding bits zero.
constexpr std::string_view kB32 = "0123456789abcdefghjkmnpqrstvwxyz";
bool isRandomId(const std::string_view s) {
    if (s.size() != 26 || !std::ranges::all_of(s, [](const char c) { return kB32.find(c) != std::string_view::npos; }))
        return false;
    return (kB32.find(s.back()) & 0x3) == 0;
}

bool text(const json& j, const char* key, std::string& out) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return false;
    out = it->get<std::string>();
    return true;
}

bool natural(const json& j, const char* key, const uint64_t max, uint64_t& out) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_number_integer()) return false;
    if (it->is_number_unsigned()) out = it->get<uint64_t>();
    else {
        const auto v = it->get<int64_t>();
        if (v < 0) return false;
        out = static_cast<uint64_t>(v);
    }
    return out <= max;
}

bool onlyKeys(const json& j, const std::set<std::string>& keys) {
    return std::ranges::all_of(j.items(), [&](const auto& kv) { return keys.contains(kv.key()); });
}

BrowserTicketCheck refuse(const TicketRefusal r) { return {.ticket = std::nullopt, .refusal = r}; }

}

// ---- frames -----------------------------------------------------------------------------------------------------------

std::optional<Frame> decode(const std::span<const uint8_t> m) {
    if (m.empty() || m.size() > kMaxMessage) return std::nullopt;
    Frame f;
    f.type = static_cast<FrameType>(m[0]);
    switch (f.type) {
        case FrameType::Challenge:
        case FrameType::Welcome:
        case FrameType::Renewed:
        case FrameType::Open:
        case FrameType::Data:
        case FrameType::Credit:
        case FrameType::Close: break;
        default: return std::nullopt;  // TICKET, PROOF and RENEW never come from the relay
    }
    auto rest = m.subspan(1);
    if (hasStream(f.type)) {
        if (rest.size() < 4) return std::nullopt;
        f.stream = getU32(rest);
        if (f.stream == 0) return std::nullopt;
        rest = rest.subspan(4);
    }
    if (f.type == FrameType::Credit) {
        if (rest.size() != 4) return std::nullopt;
        f.credit = getU32(rest);
        if (f.credit == 0) return std::nullopt;
        return f;
    }
    if (f.type == FrameType::Data && (rest.empty() || rest.size() > kMaxData)) return std::nullopt;
    if (f.type == FrameType::Challenge && rest.size() != kChallengeBytes) return std::nullopt;
    if (rest.empty()) return std::nullopt;
    f.payload.assign(rest.begin(), rest.end());
    return f;
}

// The frame builders below size each frame once and fill it in place: GCC 14 at -O3 reported reserve() followed by
// push_back() on these vectors as freeing a non-heap pointer (-Wfree-nonheap-object, a false positive that failed the
// -Werror package build).
std::vector<uint8_t> encodeForTesting(const Frame& f) {
    const bool stream = hasStream(f.type), credit = f.type == FrameType::Credit;
    std::vector<uint8_t> out(1 + (stream ? 4 : 0) + (credit ? 4 : f.payload.size()));
    out[0] = static_cast<uint8_t>(f.type);
    std::size_t at = 1;
    if (stream) {
        setU32(out.data() + at, f.stream);
        at += 4;
    }
    if (credit) setU32(out.data() + at, f.credit);
    else std::ranges::copy(f.payload, out.begin() + static_cast<std::ptrdiff_t>(at));
    return out;
}

std::vector<uint8_t> control(const FrameType type, const std::span<const uint8_t> payload) {
    std::vector<uint8_t> out(1 + payload.size());
    out[0] = static_cast<uint8_t>(type);
    std::ranges::copy(payload, out.begin() + 1);
    return out;
}

std::vector<uint8_t> control(const FrameType type, const std::string_view payload) { return control(type, bytesOf(payload)); }

std::vector<uint8_t> data(const uint32_t stream, const std::span<const uint8_t> bytes) {
    std::vector<uint8_t> out(5 + bytes.size());
    out[0] = static_cast<uint8_t>(FrameType::Data);
    setU32(out.data() + 1, stream);
    std::ranges::copy(bytes, out.begin() + 5);
    return out;
}

std::vector<uint8_t> credit(const uint32_t stream, const uint32_t bytes) {
    std::vector<uint8_t> out{static_cast<uint8_t>(FrameType::Credit)};
    putU32(out, stream);
    putU32(out, bytes);
    return out;
}

std::vector<uint8_t> closeStream(const uint32_t stream, const std::string_view reason) {
    std::vector<uint8_t> out{static_cast<uint8_t>(FrameType::Close)};
    putU32(out, stream);
    out.insert(out.end(), reason.begin(), reason.end());
    return out;
}

std::string connectMessage(const std::string_view jti, const std::span<const uint8_t> challenge) {
    return std::string(kConnectContext) + std::string(jti) + "\n" + vl::keykit::base64UrlEncode(challenge);
}

std::string_view toString(const Reason r) noexcept { return kReasonNames[static_cast<std::size_t>(r)]; }

std::optional<Reason> reasonOfCode(const uint16_t code) noexcept {
    if (code == 1000) return Reason::Done;
    if (code >= 4000 && code < 4000 + kReasonNames.size() - 1) return static_cast<Reason>(code - 4000 + 1);
    return std::nullopt;
}

uint16_t closeCode(const Reason r) noexcept {
    return r == Reason::Done ? 1000 : static_cast<uint16_t>(4000 + static_cast<unsigned>(r) - 1);
}

// ---- tickets ----------------------------------------------------------------------------------------------------------

std::string_view toString(const TicketRefusal r) noexcept {
    switch (r) {
        case TicketRefusal::Malformed: return "malformed";
        case TicketRefusal::BadSignature: return "bad_signature";
        case TicketRefusal::WrongType: return "wrong_type";
        case TicketRefusal::WrongAudience: return "wrong_audience";
        case TicketRefusal::WrongAccount: return "wrong_account";
        case TicketRefusal::WrongDeployment: return "wrong_deployment";
        case TicketRefusal::Expired: return "expired";
        case TicketRefusal::NotYetValid: return "not_yet_valid";
        case TicketRefusal::Replayed: return "replayed";
    }
    return "malformed";
}

BrowserTicketCheck verifyBrowserTicket(const std::string_view text_, const std::span<const TicketKey> keys,
                                       const std::string_view audience, const std::string_view account,
                                       const std::string_view deployment, const int64_t now) noexcept {
    try {
        if (text_.size() > kMaxTicketBytes || !text_.starts_with(kTicketPrefix)) return refuse(TicketRefusal::Malformed);
        const auto rest = text_.substr(kTicketPrefix.size());
        const auto dot = rest.find('.');
        if (dot == std::string_view::npos || rest.find('.', dot + 1) != std::string_view::npos)
            return refuse(TicketRefusal::Malformed);
        const auto c = rest.substr(0, dot);
        const auto sig = vl::keykit::base64UrlDecode(rest.substr(dot + 1));
        const auto claims = vl::keykit::base64UrlDecode(c);
        if (!sig || sig->size() != crypto_sign_BYTES || !claims) return refuse(TicketRefusal::Malformed);
        // The signature first: nothing unsigned is parsed past its base64.
        const auto input = std::string(kTicketContext) + std::string(c);
        const bool signedByKnownKey = std::ranges::any_of(keys, [&](const TicketKey& k) {
            return crypto_sign_verify_detached(sig->data(), reinterpret_cast<const unsigned char*>(input.data()),
                                               input.size(), k.data()) == 0;
        });
        if (!signedByKnownKey) return refuse(TicketRefusal::BadSignature);

        const auto j = json::parse(claims->begin(), claims->end(), nullptr, false);
        if (j.is_discarded() || !j.is_object()) return refuse(TicketRefusal::Malformed);
        BrowserTicket t;
        std::string typ;
        uint64_t iat = 0, exp = 0, renew = 0;
        if (!text(j, "typ", typ)) return refuse(TicketRefusal::Malformed);
        if (typ != "browser") return refuse(TicketRefusal::WrongType);
        if (!onlyKeys(j, {"typ", "aud", "acct", "dep", "iat", "exp", "jti", "renew", "kid", "spki", "lim"}) ||
            !text(j, "aud", t.audience) || !text(j, "acct", t.account) || !text(j, "dep", t.deployment) ||
            !text(j, "jti", t.jti) || !text(j, "kid", t.key_id) || !text(j, "spki", t.spki_sha256) ||
            !natural(j, "iat", 1ULL << 40, iat) || !natural(j, "exp", 1ULL << 40, exp) ||
            !natural(j, "renew", 86400, renew))
            return refuse(TicketRefusal::Malformed);
        const auto jti = vl::keykit::base64UrlDecode(t.jti);
        if (!jti || jti->size() != 16 || !isUuid(t.account) || !isRandomId(t.deployment) || !isRandomId(t.key_id) ||
            !isHex64(t.spki_sha256) || t.audience.empty() || t.audience.size() > 63 || exp <= iat || renew < 1)
            return refuse(TicketRefusal::Malformed);
        const auto lim = j.find("lim");
        if (lim == j.end() || !lim->is_object() || !natural(*lim, "stream_bytes", 1ULL << 60, t.stream_bytes))
            return refuse(TicketRefusal::Malformed);
        t.issued_at = static_cast<int64_t>(iat);
        t.expires_at = static_cast<int64_t>(exp);
        t.renew = static_cast<int64_t>(renew);
        if (t.expires_at - t.issued_at > kMaxTicketLifetime) return refuse(TicketRefusal::Malformed);
        if (t.audience != audience) return refuse(TicketRefusal::WrongAudience);
        if (t.account != account) return refuse(TicketRefusal::WrongAccount);
        if (t.deployment != deployment) return refuse(TicketRefusal::WrongDeployment);
        if (t.issued_at > now + kClockSkew) return refuse(TicketRefusal::NotYetValid);
        if (now >= t.expires_at) return refuse(TicketRefusal::Expired);
        return {.ticket = std::move(t), .refusal = TicketRefusal::Malformed};
    } catch (...) {
        return refuse(TicketRefusal::Malformed);
    }
}

std::optional<std::string> unverifiedJti(const std::string_view ticket) {
    if (!ticket.starts_with(kTicketPrefix)) return std::nullopt;
    const auto rest = ticket.substr(kTicketPrefix.size());
    const auto claims = vl::keykit::base64UrlDecode(rest.substr(0, rest.find('.')));
    if (!claims) return std::nullopt;
    const auto j = json::parse(claims->begin(), claims->end(), nullptr, false);
    std::string jti;
    if (j.is_discarded() || !j.is_object() || !text(j, "jti", jti)) return std::nullopt;
    return jti;
}

bool JtiLedger::spend(const std::string& jti, const int64_t expiresAt, const int64_t now) {
    const std::scoped_lock lock(mutex_);
    std::erase_if(seen_, [now](const auto& kv) { return kv.second <= now; });
    if (seen_.size() >= kMaxEntries) return false;
    return seen_.emplace(jti, expiresAt).second;
}

void JtiLedger::clear() {
    const std::scoped_lock lock(mutex_);
    seen_.clear();
}

// ---- the browser's key proof --------------------------------------------------------------------------------------

std::string proofMessage(const std::string_view jti, const std::span<const uint8_t> nonce,
                         const std::span<const uint8_t> exporter) {
    return std::string(kProofContext) + std::string(jti) + "\n" + vl::keykit::base64UrlEncode(nonce) + "\n" +
           vl::keykit::base64UrlEncode(exporter);
}

std::array<uint8_t, kChallengeRecordBytes> challengeRecord(const std::span<const uint8_t, kNonceBytes> nonce) {
    std::array<uint8_t, kChallengeRecordBytes> out{};
    out[0] = kProofVersion;
    std::ranges::copy(nonce, out.begin() + 1);
    return out;
}

std::string_view toString(const ProofRefusal r) noexcept {
    switch (r) {
        case ProofRefusal::Malformed: return "malformed_proof";
        case ProofRefusal::KeyMismatch: return "key_mismatch";
        case ProofRefusal::BadSignature: return "bad_proof_signature";
    }
    return "malformed_proof";
}

std::optional<std::vector<uint8_t>> rawSignatureToDer(const std::span<const uint8_t> raw) {
    if (raw.size() != kRawSignatureBytes) return std::nullopt;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) return std::nullopt;
    BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
    if (!r || !s || ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return std::nullopt;
    }
    unsigned char* der = nullptr;
    const int len = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);
    if (len <= 0) return std::nullopt;
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

ProofCheck verifyProof(const std::span<const uint8_t> record, const std::string_view expectedSpkiHex,
                       const std::string_view jti, const std::span<const uint8_t> nonce,
                       const std::span<const uint8_t> exporter) noexcept {
    try {
        if (record.size() != kProofRecordBytes || record[0] != kProofVersion || nonce.size() != kNonceBytes ||
            exporter.size() != kExporterBytes)
            return {.key = std::nullopt, .refusal = ProofRefusal::Malformed};
        const auto spki = record.subspan(1, kSpkiBytes);
        const auto raw = record.subspan(1 + kSpkiBytes, kRawSignatureBytes);
        auto key = device::crypto::p256KeyFromSpki(spki);
        if (!key) return {.key = std::nullopt, .refusal = ProofRefusal::Malformed};
        if (!device::crypto::constantTimeEqual(device::crypto::toHex(key->spkiSha256), expectedSpkiHex))
            return {.key = std::nullopt, .refusal = ProofRefusal::KeyMismatch};
        const auto der = rawSignatureToDer(raw);
        const auto message = proofMessage(jti, nonce, exporter);
        if (!der || !device::crypto::verifyEcdsaP256Sha256(key->spkiDer, bytesOf(message), *der))
            return {.key = std::nullopt, .refusal = ProofRefusal::BadSignature};
        return {.key = std::move(key), .refusal = ProofRefusal::Malformed};
    } catch (...) {
        return {.key = std::nullopt, .refusal = ProofRefusal::Malformed};
    }
}

void FailureLimiter::rollLocked(const int64_t now) {
    if (now / 60 == minute_) return;
    minute_ = now / 60;
    total_ = 0;
    perKey_.clear();
}

bool FailureLimiter::allowed(const std::string& key, const int64_t now) {
    const std::scoped_lock lock(mutex_);
    rollLocked(now);
    if (total_ >= kTotal) return false;
    const auto it = perKey_.find(key);
    return it == perKey_.end() || it->second < kPerKey;
}

void FailureLimiter::fail(const std::string& key, const int64_t now) {
    const std::scoped_lock lock(mutex_);
    rollLocked(now);
    ++total_;
    if (!key.empty() && (perKey_.size() < 4096 || perKey_.contains(key))) ++perKey_[key];
}

void FailureLimiter::clear() {
    const std::scoped_lock lock(mutex_);
    total_ = 0;
    perKey_.clear();
}

}
