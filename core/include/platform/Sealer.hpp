#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Seals small secrets (the master keys, the DB password) to this machine. crypto::secrets::KeyProvider decides
// what to seal and when; a backend only stores and recovers bytes. Each secret lives in its own directory
// (<state>/.sealed_<name>.blob/).
//   Linux: TPM2 (hardware /dev/tpmrm0, else swtpm), files <name>.priv + <name>.pub.
//   macOS: "secure-enclave" (default): a non-permanent Secure Enclave key per secret, file <name>.se. Bound to this
//          Mac and to the daemon's launchd context, so only the daemon running under launchd seals or unseals; an
//          installer or CLI hands secrets to the daemon instead (see platform/darwin/SealerBackends.hpp).
//          "file": a development backend with no hardware binding (<name>.key, a 0600 file in a 0700 directory),
//          used with -Ddarwin_sealer=file or where no Secure Enclave key works. A file-sealed secret is moved into
//          the Secure Enclave the first time the daemon unseals it there.
//   The backend name is reported wherever health is.
// Policy (#351): on Linux a blob can additionally be bound to PCR 7 (the secure-boot state) with a TPM PolicyPCR, so it
// unseals only while PCR 7 holds the value it was sealed under. macOS is unaffected: the Secure Enclave has no PCRs,
// seal() ignores the policy there and policySupported() is false.
// seal() and unseal() are safe to call from any thread: the TPM backend runs one operation at a time per process
// (the TPM has only a few transient object slots) and retries, boundedly, when another process has the TPM full.
namespace vh::platform::sealer {

// How a sealed blob is additionally bound to this machine's state. Off by default (secrets.tpm_pcr_policy).
enum class Policy : uint8_t { None, Pcr7 };
[[nodiscard]] std::string_view policyName(Policy policy) noexcept;  // "none", "pcr7"
[[nodiscard]] std::optional<Policy> parsePolicy(std::string_view text) noexcept;
// Whether this platform can bind blobs to a policy (a TPM can; the Secure Enclave has none).
[[nodiscard]] bool policySupported() noexcept;

// A blob is bound to a policy this machine no longer satisfies (PCR 7 changed: a firmware update, a Secure Boot key or
// db/dbx change, another boot configuration). Nothing was unsealed and nothing was regenerated: the message names the
// recovery paths (the `vh secret export` files and the per-vault key exports, or booting the original configuration
// and turning the policy off with `vh secret reseal`). Never swallowed into "missing": callers fail closed.
struct PolicyUnsatisfied final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

[[nodiscard]] std::string_view backend() noexcept;
// "hardware", "software", "development" or "unknown" (crypto::secrets::KeyProvider::posture()).
[[nodiscard]] std::string_view posture() noexcept;

// `policy` binds the new blob (Linux TPM only; ignored on macOS). Pcr7 reads PCR 7 as it is now.
void seal(const std::filesystem::path& dir, const std::string& name, std::span<const uint8_t> secret,
          Policy policy = Policy::None);
// The caller owns the returned secret and wipes it (KeyProvider keeps only a locked copy).
[[nodiscard]] std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name);

// A sealed secret exists to unseal (what init() checks).
[[nodiscard]] bool present(const std::filesystem::path& dir, const std::string& name);
// Every part of it is there.
[[nodiscard]] bool complete(const std::filesystem::path& dir, const std::string& name);

// The policy the blob on disk is bound to (read from its public part: no TPM needed). None on macOS.
[[nodiscard]] Policy policyOf(const std::filesystem::path& dir, const std::string& name);

// What a reseal did to one blob.
struct ResealResult {
    Policy from{Policy::None}, to{Policy::None};
    bool changed{false};  // false: it already carried exactly this policy at the current PCR values
};
// Replaces the blob with one bound to `to` at the current PCR values, staged and verified: the old blob is unsealed
// (under its own policy; PolicyUnsatisfied when it no longer can be), the new one is written beside it
// (<name>.staged.*), unsealed and compared byte for byte, the old pair is kept (<name>.prev.*), then the new pair is
// renamed into place and unsealed once more before the kept copy is removed. A crash at any point leaves a pair that
// unseals or one recover() puts right. The secret never changes. Throws on macOS (nothing to reseal).
ResealResult reseal(const std::filesystem::path& dir, const std::string& name, Policy to);
// Finishes or rolls back a reseal a crash interrupted (no-op when none was): a live pair that unseals stays, else the
// kept old pair is restored, else a complete staged pair is installed; leftovers are removed. Called before every
// unseal of a secret by KeyProvider.
void recover(const std::filesystem::path& dir, const std::string& name);

// Tests only: called at each stage of reseal() (see TpmSealer.cpp for the names); a throw there simulates a crash.
using ResealHook = void (*)(std::string_view stage);
void setResealHookForTesting(ResealHook hook) noexcept;

}
