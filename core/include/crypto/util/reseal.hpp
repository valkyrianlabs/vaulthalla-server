#pragma once

#include "crypto/SecretKey.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace vh::crypto::util {

// Re-seals one sealed file (AES-256-GCM body followed by its 16-byte tag, no header, no AAD: every vault file and
// recovery blob) from oldKey/oldIvB64 into dst under newKey with a fresh random IV, and returns that IV (base64).
// Streams 64 KiB at a time in constant memory; plaintext only ever exists in a wiped in-memory chunk, never on disk.
// dst (parents created, mode 0600) is truncated first and is valid only once this returns: when the old tag does
// not verify or src is shorter than its tag, dst is removed and storage::IntegrityError is thrown; any other
// failure (I/O, bad IV) removes dst too. The caller fsyncs and publishes dst like any other content sidecar.
[[nodiscard]] std::string resealFile(const std::filesystem::path& src, const SecretKey& oldKey,
                                     const std::string& oldIvB64, const std::filesystem::path& dst,
                                     const SecretKey& newKey);

// In-memory form of resealFile: body‖tag under oldKey/oldIv → body‖tag under newKey, the fresh IV in outIv.
// Throws storage::IntegrityError (and leaves outIv untouched) when the old tag does not verify.
[[nodiscard]] std::vector<uint8_t> resealBuffer(std::span<const uint8_t> sealed, const SecretKey& oldKey,
                                                std::span<const uint8_t> oldIv, const SecretKey& newKey,
                                                std::vector<uint8_t>& outIv);

}
