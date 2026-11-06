#pragma once

#include "fs/PlaintextSource.hpp"
#include "vault/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// S3 gateway multipart parts at rest (#345). A part has to outlive the daemon (an S3 client may resume an upload
// days later), so it can't use the per-process scratch key (crypto::ScratchFile): it is sealed under the vault's key.
//
// Format: one AES-256-GCM message per part, body ‖ 16-byte tag, the vault's current key, a fresh random 96-bit IV for
// every write, and
//   AAD = "vaulthalla/s3-multipart-part/v1" ‖ 0x00 ‖ BE32(vault id) ‖ BE32(len(upload id)) ‖ upload id
//         ‖ BE32(part number) ‖ BE64(plaintext size)
// The IV and key version live in the part's row (s3_gateway_multipart_part, migration 118); every write goes to a new
// file name and the row is switched to it, so the file and its IV change together. A flipped byte, a part file moved
// to another part number, upload or vault, an older copy of the part (its IV is no longer the row's), and a cut-off or
// extended file all fail closed (Tampered). The AAD's domain label also keeps a part from ever authenticating as a
// vault file (no AAD) or the other way round.
namespace vh::protocols::s3::part_cipher {

// What a sealed part is bound to.
struct Binding {
    uint32_t vault_id{};
    std::string upload_id;
    uint32_t part_number{};
};

// A part was sealed: what its row records.
struct Sealed {
    std::string encryption_iv;   // base64 of the 12-byte IV
    unsigned int key_version{};
    uint64_t size_bytes{};       // plaintext
    std::vector<uint8_t> md5;    // of the plaintext: the part's ETag
};

// A stored part to read back.
struct Stored {
    Binding binding;
    std::filesystem::path path;
    std::string encryption_iv;
    unsigned int key_version{};
    uint64_t size_bytes{};
};

// A part failed authentication or doesn't have the length its row records.
class Tampered final : public std::runtime_error {
public:
    Tampered(uint32_t partNumber, const std::string& what);
    [[nodiscard]] uint32_t partNumber() const { return partNumber_; }

private:
    uint32_t partNumber_;
};

[[nodiscard]] std::vector<uint8_t> aad(const Binding& binding, uint64_t size);

// Streams `source` into a new file at `path` (created exclusively, 0600, fsynced with its directory) under the vault's
// current key; returns what the row records. On failure nothing is left at `path`.
[[nodiscard]] Sealed seal(const vault::EncryptionManager& keys, const Binding& binding,
                          const fs::PlaintextSource& source, const std::filesystem::path& path);

// The concatenated plaintext of `parts`, in order, for sealing into the vault without a plaintext copy on disk. Every
// part is authenticated before this returns (Tampered otherwise), and again as the source is read in order: the read
// that finishes a part checks its tag, so a part changed after the first check makes that read throw (the caller
// then discards what it was given). Reads out of order (MIME sniffing) decrypt the already authenticated part at
// their offset. The key of a part sealed before a key rotation is the retained version it names
// (EncryptionManager::historicalKeySnapshot): an upload in flight survives a rotation and is resealed under the
// current key when it completes. The source keeps the part files open; it is not thread-safe beyond one reader.
[[nodiscard]] fs::PlaintextSource open(const vault::EncryptionManager& keys, const std::vector<Stored>& parts);

}
