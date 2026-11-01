#include "platform/darwin/SealerBackends.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <Security/Security.h>
#include <sodium/utils.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Secure Enclave backend (#201 decided it, #290 built it). Each seal creates a fresh non-permanent SE P-256 key (no
// keychain item: the key exists only as the token object the SEP hands back, which is stored in the blob), wraps
// "<name>\0<secret>" to its public key with ECIES (ephemeral ECDH, X9.63 KDF over SHA-256, AES-GCM) and keeps both
// in <dir>/<name>.se. Unsealing asks the SEP to do the ECDH with the restored key; the name prefix keeps one slot's
// blob from being accepted for another.
//
// The key is AfterFirstUnlockThisDeviceOnly with private-key usage. Tested on macOS 26.7 and 27.2 (#201): a key the
// LaunchDaemon creates works before anyone logs in (after `fdesetup authrestart`), survives reboots and binary
// upgrades (it isn't bound to code identity), and is refused from sudo or user sessions even as root, because it is
// bound to the keybag context it was made in. So only the daemon, under launchd, ever seals or unseals.
//
// Restoring the key from plain C++ needs the token object id attribute, "toid" (kSecAttrTokenOID), which is not in
// the public headers. If a macOS release ever drops it, seal() fails its read-back check before replacing anything,
// and the fallback is the CryptoKit SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:) shim from the
// spike (~/vh-macos-spikes/se-spike/sespike.swift).
namespace vh::platform::sealer::secure_enclave {

namespace {

// The blob: "VHSE" | version | key length (u16, big endian) | SE key token object | ECIES ciphertext.
constexpr std::array<uint8_t, 4> kSeMagic{'V', 'H', 'S', 'E'};
constexpr uint8_t kSeVersion = 1;
constexpr std::size_t kSeHeader = kSeMagic.size() + 1 + 2;

SecKeyAlgorithm seAlgorithm() { return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM; }
CFStringRef seTokenObjectIdAttr() { return CFSTR("toid"); }

// Owns one +1 Core Foundation reference.
template <class Ref>
class CfOwned {
public:
    explicit CfOwned(Ref ref = nullptr) noexcept : ref_(ref) {}
    ~CfOwned() { if (ref_) CFRelease(ref_); }
    CfOwned(const CfOwned&) = delete;
    CfOwned& operator=(const CfOwned&) = delete;
    [[nodiscard]] Ref get() const noexcept { return ref_; }
    explicit operator bool() const noexcept { return ref_ != nullptr; }

private:
    Ref ref_;
};

std::string cfDescribe(CFErrorRef err) {
    if (!err) return "unknown error";
    const CfOwned<CFErrorRef> owned(err);
    const CfOwned<CFStringRef> desc(CFErrorCopyDescription(err));
    std::string out = "error " + std::to_string(CFErrorGetCode(err));
    if (desc) {
        std::array<char, 1024> buf{};
        if (CFStringGetCString(desc.get(), buf.data(), buf.size(), kCFStringEncodingUTF8))
            out = std::string(buf.data()) + " (" + out + ")";
    }
    return out;
}

[[noreturn]] void failSe(const std::string& what, CFErrorRef err) {
    throw std::runtime_error("Secure Enclave: " + what + " failed: " + cfDescribe(err));
}

CFDictionaryRef cfDict(const std::initializer_list<std::pair<const void*, const void*>> entries) {
    std::vector<const void*> keys, values;
    for (const auto& [k, v] : entries) {
        keys.push_back(k);
        values.push_back(v);
    }
    return CFDictionaryCreate(kCFAllocatorDefault, keys.data(), values.data(), static_cast<CFIndex>(keys.size()),
                              &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

std::vector<uint8_t> cfBytes(CFDataRef data) {
    const auto* p = CFDataGetBytePtr(data);
    return {p, p + CFDataGetLength(data)};
}

// A CFData view of bytes we own (no copy), so the plaintext isn't duplicated into a buffer we can't wipe.
CFDataRef cfView(const std::vector<uint8_t>& bytes) {
    return CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, bytes.data(), static_cast<CFIndex>(bytes.size()),
                                       kCFAllocatorNull);
}

SecKeyRef restoreKey(CFDataRef tokenObject) {
    int bits = 256;
    const CfOwned<CFNumberRef> size(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits));
    const CfOwned<CFDictionaryRef> attrs(cfDict({
        {kSecAttrTokenID, kSecAttrTokenIDSecureEnclave},
        {seTokenObjectIdAttr(), tokenObject},
        {kSecAttrKeyClass, kSecAttrKeyClassPrivate},
        {kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom},
        {kSecAttrKeySizeInBits, size.get()},
    }));
    // The key data argument is ignored for token keys but must not be NULL.
    const CfOwned<CFDataRef> empty(CFDataCreate(kCFAllocatorDefault, nullptr, 0));
    CFErrorRef err = nullptr;
    SecKeyRef key = SecKeyCreateWithData(empty.get(), attrs.get(), &err);
    if (!key) failSe("restoring the sealing key", err);
    return key;
}

std::vector<uint8_t> labelled(const std::string& name, const std::vector<uint8_t>& secret) {
    std::vector<uint8_t> out(name.begin(), name.end());
    out.push_back(0);
    out.insert(out.end(), secret.begin(), secret.end());
    return out;
}

void wipe(std::vector<uint8_t>& bytes) { sodium_memzero(bytes.data(), bytes.size()); }

struct SeBlob {
    std::vector<uint8_t> tokenObject;
    std::vector<uint8_t> ciphertext;
};

std::vector<uint8_t> encodeBlob(const SeBlob& blob) {
    if (blob.tokenObject.empty() || blob.tokenObject.size() > 0xffff)
        throw std::runtime_error("Secure Enclave: unexpected key token object size " +
                                 std::to_string(blob.tokenObject.size()));
    std::vector<uint8_t> out(kSeMagic.begin(), kSeMagic.end());
    out.push_back(kSeVersion);
    out.push_back(static_cast<uint8_t>(blob.tokenObject.size() >> 8));
    out.push_back(static_cast<uint8_t>(blob.tokenObject.size() & 0xff));
    out.insert(out.end(), blob.tokenObject.begin(), blob.tokenObject.end());
    out.insert(out.end(), blob.ciphertext.begin(), blob.ciphertext.end());
    return out;
}

SeBlob decodeBlob(const std::vector<uint8_t>& bytes, const std::filesystem::path& from) {
    const auto bad = [&](const std::string& why) {
        return std::runtime_error("sealed secret " + from.string() + " is not a Secure Enclave blob: " + why);
    };
    if (bytes.size() < kSeHeader || !std::equal(kSeMagic.begin(), kSeMagic.end(), bytes.begin())) throw bad("bad magic");
    if (bytes[4] != kSeVersion) throw bad("unknown version " + std::to_string(bytes[4]));
    const std::size_t keyLen = (static_cast<std::size_t>(bytes[5]) << 8) | bytes[6];
    if (keyLen == 0 || bytes.size() <= kSeHeader + keyLen) throw bad("truncated");
    const auto key = bytes.begin() + static_cast<std::ptrdiff_t>(kSeHeader);
    const auto ct = key + static_cast<std::ptrdiff_t>(keyLen);
    return {{key, ct}, {ct, bytes.end()}};
}

std::vector<uint8_t> unwrap(const SeBlob& blob, const std::string& name, const std::filesystem::path& from) {
    const CfOwned<CFDataRef> tokenObject(CFDataCreate(kCFAllocatorDefault, blob.tokenObject.data(),
                                                      static_cast<CFIndex>(blob.tokenObject.size())));
    const CfOwned<SecKeyRef> key(restoreKey(tokenObject.get()));
    const CfOwned<CFDataRef> ct(CFDataCreate(kCFAllocatorDefault, blob.ciphertext.data(),
                                             static_cast<CFIndex>(blob.ciphertext.size())));
    CFErrorRef err = nullptr;
    const CfOwned<CFDataRef> pt(SecKeyCreateDecryptedData(key.get(), seAlgorithm(), ct.get(), &err));
    if (!pt)
        throw std::runtime_error(
            "Secure Enclave: unsealing " + from.string() + " failed: " + cfDescribe(err) +
            ". A sealed secret opens only on the Mac that sealed it and only in the daemon's launchd context; "
            "vaulthalla-server must be started by launchd (not by hand, sudo or a login session)");
    auto plain = cfBytes(pt.get());
    const auto prefix = labelled(name, {});
    if (plain.size() < prefix.size() || !std::equal(prefix.begin(), prefix.end(), plain.begin())) {
        wipe(plain);
        throw std::runtime_error("sealed secret " + from.string() + " was sealed for another name; refusing");
    }
    std::vector<uint8_t> secret(plain.begin() + static_cast<std::ptrdiff_t>(prefix.size()), plain.end());
    wipe(plain);
    return secret;
}

}

bool available() noexcept {
    static const bool present = [] {
        const io_service_t sep = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSEPManager"));
        if (!sep) return false;
        IOObjectRelease(sep);
        return true;
    }();
    return present;
}

std::filesystem::path path(const std::filesystem::path& dir, const std::string& name) {
    return dir / (name + ".se");
}

void seal(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret) {
    CFErrorRef err = nullptr;
    const CfOwned<SecAccessControlRef> access(SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &err));
    if (!access) failSe("creating the key's access control", err);
    const CfOwned<CFDictionaryRef> privateAttrs(cfDict({
        {kSecAttrIsPermanent, kCFBooleanFalse},
        {kSecAttrAccessControl, access.get()},
    }));
    int bits = 256;
    const CfOwned<CFNumberRef> size(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits));
    const CfOwned<CFDictionaryRef> attrs(cfDict({
        {kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom},
        {kSecAttrKeySizeInBits, size.get()},
        {kSecAttrTokenID, kSecAttrTokenIDSecureEnclave},
        {kSecPrivateKeyAttrs, privateAttrs.get()},
    }));
    const CfOwned<SecKeyRef> key(SecKeyCreateRandomKey(attrs.get(), &err));
    if (!key) failSe("creating a sealing key", err);

    const CfOwned<CFDictionaryRef> keyAttrs(SecKeyCopyAttributes(key.get()));
    const auto tokenObject = keyAttrs ? CFDictionaryGetValue(keyAttrs.get(), seTokenObjectIdAttr()) : nullptr;
    if (!tokenObject || CFGetTypeID(tokenObject) != CFDataGetTypeID())
        throw std::runtime_error("Secure Enclave: the new key has no token object id (\"toid\") to persist");

    const CfOwned<SecKeyRef> publicKey(SecKeyCopyPublicKey(key.get()));
    if (!publicKey) throw std::runtime_error("Secure Enclave: the new key has no public key");
    auto plain = labelled(name, secret);
    const CfOwned<CFDataRef> plainView(cfView(plain));
    const CfOwned<CFDataRef> ct(SecKeyCreateEncryptedData(publicKey.get(), seAlgorithm(), plainView.get(), &err));
    wipe(plain);
    if (!ct) failSe("wrapping the secret", err);

    const SeBlob blob{cfBytes(static_cast<CFDataRef>(tokenObject)), cfBytes(ct.get())};
    const auto target = path(dir, name);

    // Read it back the way unseal() will (restore from the stored token object, decrypt in the SEP) before replacing
    // the old blob, so a sealing path that can't be undone never costs the secret already on disk.
    auto check = unwrap(blob, name, target);
    const bool same = check == secret;
    wipe(check);
    if (!same) throw std::runtime_error("Secure Enclave: read-back of the new blob for " + name + " didn't match");

    writePrivateFile(target, encodeBlob(blob));
}

std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name) {
    const auto from = path(dir, name);
    return unwrap(decodeBlob(readPrivateFile(from), from), name, from);
}

}
