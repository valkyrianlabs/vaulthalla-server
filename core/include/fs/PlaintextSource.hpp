#pragma once

#include "crypto/Fwd.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>

namespace vh::fs {

// Plaintext to be sealed into a vault file (fs::Filesystem::createFile, FUSE working-copy seals): its size and a
// positioned reader that fills `out` from `offset` and returns how much it filled (0 only at the end). Staged
// plaintext is a crypto::ScratchFile (ciphertext under the process key, #328); nothing here writes plaintext.
struct PlaintextSource {
    uint64_t size{};
    std::function<std::size_t(uint64_t offset, std::span<uint8_t> out)> read;
};

// A scratch file's content. The scratch file must outlive the source.
[[nodiscard]] PlaintextSource sourceOf(const crypto::ScratchFile& file);

// A file on disk, opened now (read-only); the descriptor lives as long as the source. For content that is not ours to
// keep encrypted at rest: files read through the FUSE mount, and the plaintext multipart parts of versions before #345
// (read once, to seal them).
[[nodiscard]] PlaintextSource sourceOf(const std::filesystem::path& path);

// Feeds the whole source to `sink` in order, in chunks of at most 64 KiB (wiped afterwards). Throws if the source
// ends early.
void forEachChunk(const PlaintextSource& source, const std::function<void(std::span<const uint8_t>)>& sink);

// libmagic's MIME type of the source's first bytes (as much as libmagic itself would read of a file), or the type
// inferred from `fallbackName` when that fails or the source is empty.
[[nodiscard]] std::string mimeTypeOf(const PlaintextSource& source, const std::filesystem::path& fallbackName);

}
