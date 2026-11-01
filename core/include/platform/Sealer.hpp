#pragma once

#include <cstdint>
#include <filesystem>
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
//          used with -Ddarwin_sealer=file or on a Mac without a Secure Enclave. A file-sealed secret is moved into
//          the Secure Enclave the first time the daemon unseals it there.
//   The backend name is reported wherever health is.
// seal() and unseal() are safe to call from any thread: the TPM backend runs one operation at a time per process
// (the TPM has only a few transient object slots) and retries, boundedly, when another process has the TPM full.
namespace vh::platform::sealer {

[[nodiscard]] std::string_view backend() noexcept;

void seal(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret);
[[nodiscard]] std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name);

// A sealed secret exists to unseal (what init() checks).
[[nodiscard]] bool present(const std::filesystem::path& dir, const std::string& name);
// Every part of it is there.
[[nodiscard]] bool complete(const std::filesystem::path& dir, const std::string& name);

}
