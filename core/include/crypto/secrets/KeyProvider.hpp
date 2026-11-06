#pragma once

#include "crypto/SecretBytes.hpp"

#include <span>
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

    // Unseals the sealed secret, or seals `initial` (a generated one when it is empty) when there is none yet.
    void init(std::span<const uint8_t> initial = {});
    // init() for a secret that wraps stored records: when there is no sealed secret to unseal but `dependents`
    // reports records, throws MasterSecretLost instead of generating a replacement (#326).
    void initGuarded(const DependentsCheck& dependents);
    // The secret, in locked memory that is zeroed when this provider is destroyed or the secret replaced (#350).
    // Valid until then; empty before init(). Read it where it is needed; never copy it into a buffer that outlives
    // the call (wrap a copy an API insists on in crypto::WipedKeyCopy).
    [[nodiscard]] std::span<const uint8_t> getMasterKey() const noexcept { return master_.bytes(); }

    // Seals `newMasterKey` (a generated secret when it is empty) over the stored one, then holds it. When sealing
    // throws, the provider keeps the secret it had.
    void updateMasterKey(std::span<const uint8_t> newMasterKey);

    [[nodiscard]] bool sealedExists() const;

    // Deletes this secret's sealed state from the host and wipes the held copy. Irreversible: only for a secret
    // nothing is wrapped under any more, verified by the caller (a rewrap's finalized or discarded vault master
    // version, vault/MasterRewrap.hpp). Every backend keeps a secret entirely in its own directory.
    void destroySealed();

    // The sealing backend in use: "tpm2" (Linux), "secure-enclave" (macOS), or "file" (the macOS development
    // backend, when the build or config.yaml selects it).
    [[nodiscard]] static std::string_view backend() noexcept;
    // What protects the sealed secrets: "hardware" (a hardware TPM, the Secure Enclave), "software" (swtpm: no
    // hardware binding; its state on disk is the key), "development" (plain files) or "unknown" (an explicit TCTI
    // override). With secrets.require_hardware, anything but "hardware" refuses to seal or unseal.
    [[nodiscard]] static std::string_view posture() noexcept;

    // A fresh master secret from libsodium's CSPRNG (the OS generator: getrandom(2) / arc4random). Throws if
    // libsodium can't initialize. Never std::random_device, whose source is implementation-defined (#318).
    [[nodiscard]] static crypto::SecretBytes generateMasterSecret(std::size_t bytes = 32);

    // Tests only: runs on each secret a sealer returns, before the provider keeps it, so a test can fail an unseal
    // midway (by throwing) and check that the unsealed bytes were wiped. nullptr (the default) turns it off.
    using UnsealHook = void (*)(std::span<const uint8_t> unsealed);
    static void setUnsealHookForTesting(UnsealHook hook) noexcept;

private:
    crypto::SecretBytes master_;
    std::string name_;
    std::filesystem::path sealedDir_;

    void unsealStored();
    void sealAndKeep(crypto::SecretBytes candidate);
    static void requirePosture();
};

} // namespace vh::crypto::secrets
