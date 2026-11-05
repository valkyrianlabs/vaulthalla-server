#pragma once

#include <vector>
#include <string>
#include <string_view>
#include <cstdint>
#include <filesystem>
#include <optional>

namespace vh::crypto::secrets {

// One named secret sealed to this machine (master, psql, vault_master, ...). The sealing itself is the platform's
// (platform/Sealer.hpp: TPM2 on Linux, the Secure Enclave on macOS); this class decides when to generate, unseal or
// reseal.
class KeyProvider {
public:
    explicit KeyProvider(const std::string& name = "master");

    void init(const std::optional<std::string>& initSecret = std::nullopt);  // check or generate
    [[nodiscard]] const std::vector<uint8_t>& getMasterKey() const;

    void updateMasterKey(const std::vector<uint8_t>& newMasterKey);

    [[nodiscard]] bool sealedExists() const;

    // The sealing backend in use: "tpm2" (Linux), "secure-enclave" (macOS), or "file" (the macOS development
    // backend, also used where no Secure Enclave key works).
    [[nodiscard]] static std::string_view backend() noexcept;

    // A fresh master secret from libsodium's CSPRNG (the OS generator: getrandom(2) / arc4random). Throws if
    // libsodium can't initialize. Never std::random_device, whose source is implementation-defined (#318).
    [[nodiscard]] static std::vector<uint8_t> generateMasterSecret(std::size_t bytes = 32);

private:
    std::vector<uint8_t> masterKey_;
    std::string name_;
    std::filesystem::path sealedDir_;

    void generateAndSeal();
};

} // namespace vh::crypto::secrets
