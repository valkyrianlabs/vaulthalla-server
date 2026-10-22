#include "vault/KeyAttestation.hpp"

#include "crypto/secrets/KeyProvider.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/vault/Key.hpp"
#include "log/Registry.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/model/Key.hpp"

#include <paths.h>
#include <sodium.h>

#include <mutex>
#include <stdexcept>

namespace vh::vault::attestation {

namespace {

std::vector<uint8_t> keyCheckBytes(const std::string& hex) {
    std::vector<uint8_t> out(16);
    std::size_t len = 0;
    if (hex.size() != 32 ||
        sodium_hex2bin(out.data(), out.size(), hex.data(), hex.size(), nullptr, &len, nullptr) != 0 || len != 16)
        throw std::invalid_argument("a key check is 32 hex digits");
    for (const char c : hex)
        if (c >= 'A' && c <= 'F') throw std::invalid_argument("a key check is lowercase hex");
    return out;
}

// This node's signing seed, unsealed once per state directory (tests switch it) and kept in guarded memory.
struct SigningSeed {
    std::mutex mutex;
    std::string sealedFor;  // the backing path the seed was unsealed from
    std::vector<uint8_t> seed;

    void clear() {
        if (!seed.empty()) sodium_memzero(seed.data(), seed.size());
        seed.clear();
        sealedFor.clear();
    }
};

SigningSeed& signingSeed() {
    static SigningSeed s;
    return s;
}

std::string providerName() { return paths::testMode ? "test_key_attest" : "key_attest"; }

// Unseals this node's seed, or generates (and seals) a new one when there is none or it no longer unseals: a TPM reset
// makes the old key unusable, but its public key stays in key_attestation_keys, so its attestations still verify.
std::vector<uint8_t> loadSeedLocked(SigningSeed& s) {
    const auto here = paths::getBackingPath().string();
    if (!s.seed.empty() && s.sealedFor == here) return s.seed;
    s.clear();

    crypto::secrets::KeyProvider provider(providerName());
    std::vector<uint8_t> seed;
    try {
        provider.init();  // generates and seals a 32-byte seed when none exists
        seed = provider.getMasterKey();
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[KeyAttestation] The key attestation signing key does not unseal on this host "
                                      "({}); generating a new one. Attestations by the old key still verify.",
                                      e.what());
    }
    if (seed.size() != kSeedSize) {
        if (!seed.empty()) sodium_memzero(seed.data(), seed.size());
        seed.assign(kSeedSize, 0);
        randombytes_buf(seed.data(), seed.size());
        provider.updateMasterKey(seed);  // re-seals over the unusable blob
        log::Registry::audit()->info("[KeyAttestation] Created a new key attestation signing key on this host");
    }
    s.seed = std::move(seed);
    s.sealedFor = here;
    return s.seed;
}

}

std::vector<uint8_t> message(const std::string_view nodeId, const uint64_t vaultId, const uint32_t version,
                             const std::string& keyCheckHex) {
    if (nodeId.empty()) throw std::invalid_argument("an attestation needs this node's id");
    const auto check = keyCheckBytes(keyCheckHex);
    std::vector<uint8_t> out(kDomain.begin(), kDomain.end());
    out.insert(out.end(), nodeId.begin(), nodeId.end());
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(vaultId >> shift));
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(version >> shift));
    out.insert(out.end(), check.begin(), check.end());
    return out;
}

std::vector<uint8_t> publicKeyFromSeed(const std::span<const uint8_t> seed) {
    if (seed.size() != kSeedSize) throw std::invalid_argument("an attestation seed is 32 bytes");
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
    sodium_memzero(sk.data(), sk.size());
    return pk;
}

std::vector<uint8_t> signWithSeed(const std::span<const uint8_t> seed, const std::span<const uint8_t> msg) {
    if (seed.size() != kSeedSize) throw std::invalid_argument("an attestation seed is 32 bytes");
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
    std::vector<uint8_t> sig(crypto_sign_BYTES);
    crypto_sign_detached(sig.data(), nullptr, msg.data(), msg.size(), sk.data());
    sodium_memzero(sk.data(), sk.size());
    return sig;
}

bool verifySignature(const std::span<const uint8_t> publicKey, const std::span<const uint8_t> msg,
                     const std::span<const uint8_t> signature) {
    if (publicKey.size() != kPublicKeySize || signature.size() != kSignatureSize) return false;
    return crypto_sign_verify_detached(signature.data(), msg.data(), msg.size(), publicKey.data()) == 0;
}

std::optional<Attestation> attest(const unsigned int vaultId, const unsigned int version,
                                  const std::string& keyCheckHex) {
    try {
        const auto msg = message(db::query::device::Devices::nodeId(), vaultId, version, keyCheckHex);
        auto& s = signingSeed();
        std::scoped_lock lock(s.mutex);
        auto seed = loadSeedLocked(s);
        const auto pk = publicKeyFromSeed(seed);
        Attestation out{.key_id = db::query::vault::Key::attestationKeyId(pk), .signature = signWithSeed(seed, msg)};
        sodium_memzero(seed.data(), seed.size());
        return out;
    } catch (const std::exception& e) {
        log::Registry::crypto()->error("[KeyAttestation] Could not attest key version {} of vault {}: {}", version,
                                       vaultId, e.what());
        return std::nullopt;
    }
}

std::string to_string(const Verdict verdict) {
    switch (verdict) {
        case Verdict::Valid: return "valid";
        case Verdict::Missing: return "missing";
        case Verdict::UnknownKey: return "unknown_key";
        case Verdict::BadSignature: return "bad_signature";
    }
    return "bad_signature";
}

Verdict check(const Attestation& attestation, const unsigned int vaultId, const unsigned int version,
              const std::string& keyCheckHex) {
    if (attestation.signature.empty()) return Verdict::Missing;
    const auto pk = db::query::vault::Key::attestationPublicKey(attestation.key_id);
    if (!pk) return Verdict::UnknownKey;
    std::vector<uint8_t> msg;
    try {
        msg = message(db::query::device::Devices::nodeId(), vaultId, version, keyCheckHex);
    } catch (const std::invalid_argument&) {
        return Verdict::BadSignature;
    }
    return verifySignature(*pk, msg, attestation.signature) ? Verdict::Valid : Verdict::BadSignature;
}

db::query::vault::Key::Provenance provenanceOf(const unsigned int vaultId, const unsigned int version,
                                               const std::span<const uint8_t> key) {
    db::query::vault::Key::Provenance out{.key_check = keyCheck(key, vaultId, version)};
    if (auto a = attest(vaultId, version, out.key_check)) {
        out.attestation_key_id = a->key_id;
        out.attestation = std::move(a->signature);
    }
    return out;
}

void backfill(const vh::vault::model::Key& rec, const std::span<const uint8_t> key) {
    try {
        const auto check = keyCheck(key, rec.vaultId, rec.version);
        const bool checkOk = rec.key_check && keyCheckEquals(*rec.key_check, check);
        if (checkOk && !rec.attestation.empty()) return;
        if (rec.key_check && !checkOk)
            log::Registry::crypto()->warn("[KeyAttestation] The recorded key check of vault {} key version {} does not "
                                          "match the key that unsealed; recording the correct one", rec.vaultId,
                                          rec.version);
        const auto p = provenanceOf(rec.vaultId, rec.version, key);
        if (db::query::vault::Key::recordProvenance(rec, p) > 0)
            log::Registry::crypto()->debug("[KeyAttestation] Recorded the provenance of vault {} key version {}",
                                           rec.vaultId, rec.version);
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[KeyAttestation] Could not record the provenance of vault {} key version {}: {}",
                                      rec.vaultId, rec.version, e.what());
    }
}

void resetForTesting() {
    auto& s = signingSeed();
    std::scoped_lock lock(s.mutex);
    s.clear();
}

}
