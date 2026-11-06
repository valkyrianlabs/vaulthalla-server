#include "auth/mfa/Keys.hpp"

#include "crypto/secrets/Dependents.hpp"
#include "crypto/secrets/Manager.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/uuid.hpp"
#include "db/Transactions.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"

#include <sodium.h>

#include <algorithm>
#include <mutex>
#include <string>

namespace vh::auth::mfa::keys {

namespace {

constexpr std::string_view kTotpAadDomain = "vh/mfa/totp/v1";

std::mutex mfaKeysMutex;
Key cachedSeal;
Key cachedPepper;

Key loadMfaKey(Key& cache, const char* name, const crypto::secrets::DependentsCheck& dependents) {
    std::scoped_lock lock(mfaKeysMutex);
    if (cache) return cache;
    try {
        if (!db::Transactions::dbPool_) throw std::runtime_error("no database");
        const auto secrets = runtime::Deps::get().secretsManager;
        if (!secrets) throw std::runtime_error("no secrets manager");
        cache = std::make_shared<const crypto::SecretBytes>(secrets->sealedKey(name, kKeyBytes, dependents));
        return cache;
    } catch (const std::exception& e) {
        log::Registry::crypto()->error("[auth::mfa] {} unavailable: {}", name, e.what());
        throw Unavailable(std::string(name) + " unavailable");
    }
}

std::vector<uint8_t> totpAad(const uint32_t userId, const std::string_view factorUuid) {
    if (factorUuid.size() != 36) throw std::invalid_argument("factor uuid must be canonical");
    std::vector<uint8_t> aad(kTotpAadDomain.begin(), kTotpAadDomain.end());
    aad.push_back(static_cast<uint8_t>(userId >> 24));
    aad.push_back(static_cast<uint8_t>(userId >> 16));
    aad.push_back(static_cast<uint8_t>(userId >> 8));
    aad.push_back(static_cast<uint8_t>(userId));
    aad.insert(aad.end(), factorUuid.begin(), factorUuid.end());
    return aad;
}

crypto::util::GcmKey gcmKey(const std::span<const uint8_t> key) {
    if (key.size() != crypto::util::AES_KEY_SIZE) throw std::invalid_argument("mfa_seal has the wrong length");
    return key.first<crypto::util::AES_KEY_SIZE>();
}

}

Key seal() { return loadMfaKey(cachedSeal, kSealName, crypto::secrets::dependents::mfaSeal()); }

Key pepper() { return loadMfaKey(cachedPepper, kPepperName, crypto::secrets::dependents::mfaPepper()); }

void resetForTesting() {
    std::scoped_lock lock(mfaKeysMutex);
    cachedSeal.reset();
    cachedPepper.reset();
}

void setForTesting(Key seal, Key pepper) {
    std::scoped_lock lock(mfaKeysMutex);
    cachedSeal = std::move(seal);
    cachedPepper = std::move(pepper);
}

SealedSecret sealTotpSecret(const std::span<const uint8_t> key, const uint32_t userId,
                            const std::string_view factorUuid, const std::span<const uint8_t> secret) {
    crypto::util::ensure_sodium_init();
    const auto aad = totpAad(userId, factorUuid);
    SealedSecret out;
    out.iv.resize(crypto::util::AES_IV_SIZE);
    randombytes_buf(out.iv.data(), out.iv.size());
    out.ciphertext.resize(secret.size() + crypto::util::AES_TAG_SIZE);

    crypto::util::GcmStreamEncryptor enc(gcmKey(key), std::span<const uint8_t, crypto::util::AES_IV_SIZE>(out.iv),
                                         aad);
    enc.update(secret, std::span<uint8_t>(out.ciphertext).first(secret.size()));
    const auto tag = enc.finish();
    std::ranges::copy(tag, out.ciphertext.begin() + static_cast<std::ptrdiff_t>(secret.size()));
    return out;
}

crypto::SecretBytes openTotpSecret(const std::span<const uint8_t> key, const uint32_t userId,
                                   const std::string_view factorUuid, const SealedSecret& sealed) {
    if (sealed.iv.size() != crypto::util::AES_IV_SIZE || sealed.ciphertext.size() <= crypto::util::AES_TAG_SIZE)
        throw std::runtime_error("sealed TOTP secret is malformed");
    const auto aad = totpAad(userId, factorUuid);
    const auto bodySize = sealed.ciphertext.size() - crypto::util::AES_TAG_SIZE;
    const std::span<const uint8_t> all(sealed.ciphertext);
    crypto::WipedKeyCopy plain{std::vector<uint8_t>(bodySize)};
    if (!crypto::util::gcmDecrypt(gcmKey(key), std::span<const uint8_t, crypto::util::AES_IV_SIZE>(sealed.iv),
                                  all.first(bodySize), all.subspan(bodySize).first<crypto::util::AES_TAG_SIZE>(),
                                  plain.bytes, aad))
        throw std::runtime_error("sealed TOTP secret does not open (wrong key, account or factor)");
    return crypto::SecretBytes(plain.bytes);
}

}
