#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// The two macOS sealer backends behind platform/Sealer.hpp. platform/darwin/Sealer.cpp picks one per process and
// reads whichever format a secret's directory holds, so a secret sealed by the other backend is migrated, never lost.
// Only darwin sources and the darwin sealer test include this.
namespace vh::platform::sealer {

// "file": DEVELOPMENT backend. <dir>/<name>.key, the secret as-is in a 0600 file in a 0700 directory.
namespace file {

[[nodiscard]] std::filesystem::path path(const std::filesystem::path& dir, const std::string& name);
void seal(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret);
[[nodiscard]] std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name);

}

// "secure-enclave": the production default (#201, #290). <dir>/<name>.se holds a non-permanent Secure Enclave P-256
// key's token object (its dataRepresentation) and the secret wrapped to it with ECIES (X9.63 SHA-256, AES-GCM).
// Unwrapping needs this Mac's Secure Enclave and the keybag context the key was created in: a key created by the
// LaunchDaemon can't be used from sudo or a user session, even as root. Only the daemon seals and unseals.
namespace secure_enclave {

// This Mac has a Secure Enclave (Apple silicon or a T2; not a virtual machine).
[[nodiscard]] bool available() noexcept;
[[nodiscard]] std::filesystem::path path(const std::filesystem::path& dir, const std::string& name);
void seal(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret);
[[nodiscard]] std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name);

}

// Shared by both: write <path> atomically (sibling, full flush, rename, directory flush) as a 0600 file in a 0700
// directory, and read one back, refusing a file that group or others can read.
void writePrivateFile(const std::filesystem::path& path, const std::vector<uint8_t>& bytes);
[[nodiscard]] std::vector<uint8_t> readPrivateFile(const std::filesystem::path& path);
// Remove <path> if it exists and flush its directory.
void removeDurably(const std::filesystem::path& path);

}
