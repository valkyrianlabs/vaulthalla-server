#pragma once

#include "device/Crypto.hpp"

#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/types.h>

// The device listener's own identity (docs/pairing.md §2, D2): a self-signed ECDSA P-256 certificate whose key is
// sealed through crypto::secrets::KeyProvider (TPM2 on Linux, the file backend on macOS). Clients pin the SPKI hash,
// never the certificate, so a certificate re-issued for the same key (lost file, profile change) changes nothing for
// them; only a new key does, and every paired Desktop then has to pair again (spec §5).
namespace vh::device {

class ServerIdentity {
public:
    // A fresh key and certificate (tests; the daemon goes through loadOrCreateServerIdentity()).
    [[nodiscard]] static std::shared_ptr<const ServerIdentity> generate();
    // From the 32-byte private scalar. `certificatePem` is reused when it carries this key and parses; otherwise a new
    // certificate is issued (certificateIsNew()). Throws on an invalid scalar.
    [[nodiscard]] static std::shared_ptr<const ServerIdentity> fromPrivateScalar(std::span<const uint8_t> scalar,
                                                                                 std::string_view certificatePem);

    ~ServerIdentity();
    ServerIdentity(const ServerIdentity&) = delete;
    ServerIdentity& operator=(const ServerIdentity&) = delete;

    [[nodiscard]] const crypto::Hash& spkiSha256() const noexcept { return spki_; }
    [[nodiscard]] std::string spkiHex() const { return crypto::toHex(spki_); }
    [[nodiscard]] const std::string& certificatePem() const noexcept { return certificatePem_; }
    [[nodiscard]] bool certificateIsNew() const noexcept { return certificateIsNew_; }
    // For the TLS context. Owned by this object.
    [[nodiscard]] EVP_PKEY* key() const noexcept { return key_; }
    [[nodiscard]] X509* certificate() const noexcept { return certificate_; }
    // The private scalar, for sealing. Callers wipe their copy.
    [[nodiscard]] std::vector<uint8_t> privateScalar() const;

private:
    ServerIdentity() = default;

    EVP_PKEY* key_{nullptr};
    X509* certificate_{nullptr};
    crypto::Hash spki_{};
    std::string certificatePem_;
    bool certificateIsNew_{false};
};

// Where the certificate is kept (next to the sealed secrets in the state directory; public, 0644).
[[nodiscard]] std::filesystem::path serverCertificatePath();

// The daemon's identity: the key unsealed from KeyProvider("device_tls"), generated and sealed on first use; the
// certificate read from serverCertificatePath() and (re)written when a new one had to be issued.
[[nodiscard]] std::shared_ptr<const ServerIdentity> loadOrCreateServerIdentity();

// The identity the listener presents, which pairing codes and device.server.identity use. Null until the device
// listener (or a test) sets it.
[[nodiscard]] std::shared_ptr<const ServerIdentity> currentServerIdentity();
void setCurrentServerIdentity(std::shared_ptr<const ServerIdentity> identity);

}
