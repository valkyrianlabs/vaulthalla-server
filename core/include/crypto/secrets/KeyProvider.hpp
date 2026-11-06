#pragma once

#include <vector>
#include <string>
#include <string_view>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>

namespace vh::crypto::secrets {

// A master secret that wraps stored records is gone (its sealed blob is missing) while those records still exist.
// Generating a new one would leave every one of them undecryptable, so init() refuses (#326). The message names
// the slot, the records that depend on it and the ways back: restore the sealed state, import the per-vault key
// backups, or `vh secret` restore.
struct MasterSecretLost final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Counts the stored records a slot's secret wraps (0: nothing would be lost by generating a fresh one). Returns a
// human description such as "3 vault key version(s)", or nullopt when there are none.
using DependentsCheck = std::function<std::optional<std::string>()>;

// One named secret sealed to this machine (master, psql, vault_master, ...). The sealing itself is the platform's
// (platform/Sealer.hpp: TPM2 on Linux, the Secure Enclave on macOS); this class decides when to generate, unseal or
// reseal.
class KeyProvider {
public:
    explicit KeyProvider(const std::string& name = "master");

    void init(const std::optional<std::string>& initSecret = std::nullopt);  // check or generate
    // init() for a secret that wraps stored records: when there is no sealed secret to unseal but `dependents`
    // reports records, throws MasterSecretLost instead of generating a replacement (#326).
    void initGuarded(const DependentsCheck& dependents);
    [[nodiscard]] const std::vector<uint8_t>& getMasterKey() const;

    void updateMasterKey(const std::vector<uint8_t>& newMasterKey);

    [[nodiscard]] bool sealedExists() const;

    // The sealing backend in use: "tpm2" (Linux), "secure-enclave" (macOS), or "file" (the macOS development
    // backend, when the build or config.yaml selects it).
    [[nodiscard]] static std::string_view backend() noexcept;
    // What protects the sealed secrets: "hardware" (a hardware TPM, the Secure Enclave), "software" (swtpm: no
    // hardware binding; its state on disk is the key), "development" (plain files) or "unknown" (an explicit TCTI
    // override). With secrets.require_hardware, anything but "hardware" refuses to seal or unseal.
    [[nodiscard]] static std::string_view posture() noexcept;

    // A fresh master secret from libsodium's CSPRNG (the OS generator: getrandom(2) / arc4random). Throws if
    // libsodium can't initialize. Never std::random_device, whose source is implementation-defined (#318).
    [[nodiscard]] static std::vector<uint8_t> generateMasterSecret(std::size_t bytes = 32);

private:
    std::vector<uint8_t> masterKey_;
    std::string name_;
    std::filesystem::path sealedDir_;

    void generateAndSeal();
    static void requirePosture();
};

} // namespace vh::crypto::secrets
