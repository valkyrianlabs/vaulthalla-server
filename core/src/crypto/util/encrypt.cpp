#include "crypto/util/encrypt.hpp"
#include "crypto/util/Gcm.hpp"
#include "log/Registry.hpp"
#include "config/Registry.hpp"

#include <sodium.h>
#include <openssl/evp.h>
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <cstring>
#include <array>
#include <cstdlib>
#include <sstream>

using namespace vh::config;

namespace vh::crypto::util {

namespace {

struct AESGCMCapability {
    bool supported = false;
    bool devOverride = false;
    bool cpuFeaturesChecked = false;
    bool sodiumReportedAvailable = false;
    bool runtimeProbeTried = false;
    bool runtimeProbeSucceeded = false;
    std::vector<std::string> missingFeatures;
    std::string failureReason;
};

static std::string join_features(const std::vector<std::string> &features) {
    std::ostringstream oss;
    for (size_t i = 0; i < features.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << features[i];
    }
    return oss.str();
}

static bool probe_sodium_aes256gcm_encrypt() {
    std::array<unsigned char, AES_KEY_SIZE> key{};
    std::array<unsigned char, AES_IV_SIZE> nonce{};
    std::array<unsigned char, 1> plaintext{0x41};
    std::array<unsigned char, 1 + AES_TAG_SIZE> ciphertext{};
    unsigned long long ciphertext_len = 0;

    randombytes_buf(key.data(), key.size());
    randombytes_buf(nonce.data(), nonce.size());

    return crypto_aead_aes256gcm_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        nullptr, 0,
        nullptr, nonce.data(), key.data()) == 0;
}

static AESGCMCapability detect_aes_gcm_capability() {
    AESGCMCapability capability{};

    if (Registry::get().dev.enabled || std::getenv("VH_ALLOW_FAKE_AES")) {
        capability.supported = true;
        capability.devOverride = true;
        return capability;
    }

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
    __builtin_cpu_init();
    capability.cpuFeaturesChecked = true;

    const bool hasAES = __builtin_cpu_supports("aes");
    const bool hasPCLMUL = __builtin_cpu_supports("pclmul");
    if (!hasAES) capability.missingFeatures.emplace_back("aes");
    if (!hasPCLMUL) capability.missingFeatures.emplace_back("pclmulqdq");

    if (!capability.missingFeatures.empty()) {
        capability.supported = false;
        return capability;
    }
#endif

    capability.sodiumReportedAvailable = (crypto_aead_aes256gcm_is_available() != 0);
    if (capability.sodiumReportedAvailable) {
        capability.supported = true;
        return capability;
    }

    capability.runtimeProbeTried = true;
    capability.runtimeProbeSucceeded = probe_sodium_aes256gcm_encrypt();
    if (capability.runtimeProbeSucceeded) {
        capability.supported = true;
        return capability;
    }

    capability.supported = false;
    capability.failureReason =
        "libsodium AES256-GCM provider unavailable (crypto_aead_aes256gcm_is_available=0 and runtime probe failed)";
    return capability;
}

static const AESGCMCapability &aes_gcm_capability() {
    static const AESGCMCapability capability = [] {
        auto detected = detect_aes_gcm_capability();
        if (detected.supported) {
            if (detected.devOverride) {
                log::Registry::crypto()->warn(
                    "[crypto::util] AES256-GCM support forced by dev/fake override");
            } else if (detected.cpuFeaturesChecked) {
                log::Registry::crypto()->info(
                    "[crypto::util] AES256-GCM CPU support detected: aes+pclmulqdq");
            }

            if (detected.runtimeProbeTried && detected.runtimeProbeSucceeded) {
                log::Registry::crypto()->warn(
                    "[crypto::util] AES256-GCM runtime probe succeeded despite libsodium availability false");
            }
        } else {
            if (!detected.missingFeatures.empty()) {
                log::Registry::crypto()->error(
                    "[crypto::util] AES256-GCM unavailable: missing {}",
                    join_features(detected.missingFeatures));
            } else if (!detected.failureReason.empty()) {
                log::Registry::crypto()->error(
                    "[crypto::util] AES256-GCM unavailable: {}",
                    detected.failureReason);
            } else {
                log::Registry::crypto()->error(
                    "[crypto::util] AES256-GCM unavailable: unknown capability detection failure");
            }
        }
        return detected;
    }();
    return capability;
}

static bool is_aes_gcm_supported() {
    return aes_gcm_capability().supported;
}

static std::string aes_gcm_unavailable_reason() {
    const auto &capability = aes_gcm_capability();
    if (!capability.missingFeatures.empty()) {
        return "AES256-GCM unavailable: missing " + join_features(capability.missingFeatures);
    }
    if (!capability.failureReason.empty()) {
        return "AES256-GCM unavailable: " + capability.failureReason;
    }
    return "AES256-GCM unavailable on this CPU";
}

} // namespace

std::vector<uint8_t> encrypt_aes256_gcm(
    const std::span<const uint8_t> plaintext,
    const std::span<const uint8_t> key,
    std::vector<uint8_t>& out_iv)
{
    if (key.size() != AES_KEY_SIZE) {
        log::Registry::crypto()->error("[encrypt_aes256_gcm] Invalid AES-256 key size: {} bytes", key.size());
        throw std::invalid_argument("Invalid AES-256 key size");
    }

    out_iv.resize(AES_IV_SIZE);
    randombytes_buf(out_iv.data(), AES_IV_SIZE);

    if (!is_aes_gcm_supported())
        throw std::runtime_error(aes_gcm_unavailable_reason());

    // OpenSSL EVP: ~2-4x the throughput of libsodium's one-shot AEAD on current CPUs (VAES/VPCLMULQDQ) and
    // byte-identical output (body || 16-byte tag, no AAD).
    std::vector<uint8_t> ciphertext(plaintext.size() + AES_TAG_SIZE);
    GcmStreamEncryptor encryptor(GcmKey(key.data(), AES_KEY_SIZE), GcmIv(out_iv.data(), AES_IV_SIZE));
    encryptor.update(plaintext, std::span<uint8_t>(ciphertext.data(), plaintext.size()));
    const auto tag = encryptor.finish();
    std::copy(tag.begin(), tag.end(), ciphertext.begin() + static_cast<std::ptrdiff_t>(plaintext.size()));
    return ciphertext;
}

std::vector<uint8_t> decrypt_aes256_gcm(
    const std::vector<uint8_t>& ciphertext_with_tag,
    const std::span<const uint8_t> key,
    const std::vector<uint8_t>& iv)
{
    if (key.size() != AES_KEY_SIZE || iv.size() != AES_IV_SIZE) {
        log::Registry::crypto()->error("[decrypt_aes256_gcm] Invalid key or IV size: "
                                     "key size = {}, iv size = {}",
                                     key.size(), iv.size());
        throw std::invalid_argument("Invalid key or IV size");
    }

    if (ciphertext_with_tag.size() < AES_TAG_SIZE)
        throw std::runtime_error("Decryption failed: ciphertext shorter than its authentication tag");

    if (!is_aes_gcm_supported())
        throw std::runtime_error(aes_gcm_unavailable_reason());

    const auto bodySize = ciphertext_with_tag.size() - AES_TAG_SIZE;
    std::vector<uint8_t> decrypted(bodySize);
    if (!gcmDecrypt(GcmKey(key.data(), AES_KEY_SIZE), GcmIv(iv.data(), AES_IV_SIZE),
                    std::span<const uint8_t>(ciphertext_with_tag.data(), bodySize),
                    std::span<const uint8_t, AES_TAG_SIZE>(ciphertext_with_tag.data() + bodySize, AES_TAG_SIZE),
                    decrypted))
        throw std::runtime_error("Decryption failed: authentication error");
    return decrypted;
}

void decrypt_aes256_gcm_file(
    const std::filesystem::path& ciphertextPath,
    const std::function<void(std::span<const uint8_t>)>& sink,
    const std::span<const uint8_t> key,
    const std::vector<uint8_t>& iv) {
    if (key.size() != AES_KEY_SIZE) throw std::invalid_argument("Invalid AES-256 key size");
    if (iv.size() != AES_IV_SIZE) throw std::invalid_argument("Invalid AES-GCM IV size");

    const auto total = std::filesystem::file_size(ciphertextPath);
    if (total < AES_TAG_SIZE) throw std::runtime_error("Ciphertext shorter than its tag: " + ciphertextPath.string());
    const auto bodySize = total - AES_TAG_SIZE;

    std::ifstream in(ciphertextPath, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open ciphertext file: " + ciphertextPath.string());
    std::array<unsigned char, AES_TAG_SIZE> tag{};
    in.seekg(static_cast<std::streamoff>(bodySize));
    in.read(reinterpret_cast<char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
    if (!in) throw std::runtime_error("Failed to read AES-GCM tag: " + ciphertextPath.string());
    in.seekg(0);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to allocate AES-GCM context");

    std::array<unsigned char, 64 * 1024> input{};
    std::array<unsigned char, input.size() + AES_TAG_SIZE> output{};
    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("AES-GCM initialization failed");

        uintmax_t remaining = bodySize;
        while (remaining > 0) {
            const auto chunk = static_cast<std::streamsize>(std::min<uintmax_t>(remaining, input.size()));
            in.read(reinterpret_cast<char*>(input.data()), chunk);
            if (in.gcount() != chunk) throw std::runtime_error("Short read decrypting: " + ciphertextPath.string());
            remaining -= static_cast<uintmax_t>(chunk);

            int outLen = 0;
            if (EVP_DecryptUpdate(ctx, output.data(), &outLen, input.data(), static_cast<int>(chunk)) != 1)
                throw std::runtime_error("AES-GCM file decryption failed");
            if (outLen > 0) sink({output.data(), static_cast<std::size_t>(outLen)});
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1)
            throw std::runtime_error("AES-GCM tag setup failed");
        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx, output.data(), &finalLen) != 1)
            throw std::runtime_error("AES-GCM authentication failed: " + ciphertextPath.string());
        if (finalLen > 0) sink({output.data(), static_cast<std::size_t>(finalLen)});
        EVP_CIPHER_CTX_free(ctx);
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        sodium_memzero(output.data(), output.size());
        throw;
    }
    sodium_memzero(output.data(), output.size());
}

std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open vault key file: " + path.string());

    std::vector<uint8_t> buf(std::istreambuf_iterator<char>(in), {});
    return buf;
}

std::string b64_encode(const std::vector<uint8_t>& data) {
    const size_t encoded_len = sodium_base64_ENCODED_LEN(data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string result(encoded_len, '\0');

    sodium_bin2base64(result.data(), result.size(),
                      data.data(), data.size(),
                      sodium_base64_VARIANT_ORIGINAL);

    result.resize(std::strlen(result.c_str())); // Trim null terminator
    return result;
}

std::vector<uint8_t> b64_decode(const std::string& b64) {
    // Any length: GCM IVs (12 bytes) and VHF1 salts (32 bytes) both travel as base64 generation ids.
    std::vector<uint8_t> decoded(b64.size() / 4 * 3 + 3);
    size_t out_len = 0;
    if (sodium_base642bin(decoded.data(), decoded.size(),
                          b64.c_str(), b64.size(),
                          nullptr, &out_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
    {
        throw std::runtime_error("Invalid base64 IV");
    }
    decoded.resize(out_len);
    return decoded;
}

}
