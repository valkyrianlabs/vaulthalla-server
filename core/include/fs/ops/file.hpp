#pragma once

#include <cstdint>
#include <filesystem>
#include <string_view>
#include <functional>
#include <span>
#include <vector>
#include <string>
#include <random>
#include <memory>
#include <sys/types.h>
#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"

namespace vh::fs::ops {

std::vector<uint8_t> readFileToVector(const std::filesystem::path& path);

std::string readFileToString(const std::filesystem::path& path);

// Backing files are never written in place (a retained generation may share the inode; recovery.md): create them
// with writeFileExclusive or replace them with replaceFileAtomic / writeFileAtomic. tools/contracts guards this.

// fsync(2) a file, or a directory (so a rename or create in it is durable). Throw std::system_error.
// Every content replacement (overwrite, FUSE seal, key rotation) stages the new ciphertext here, commits the row,
// then renames it over the backing file; startup recovery settles a leftover by keeping whichever copy authenticates
// under the row (sync::rotation::recoverVault).
inline constexpr std::string_view kContentSidecarSuffix = ".vh-rotate";
[[nodiscard]] std::filesystem::path contentSidecarPath(const std::filesystem::path& backing);

void fsyncFile(const std::filesystem::path& path);
void fsyncDirectory(const std::filesystem::path& dir);

// Creates absPath (O_CREAT | O_EXCL, never following or reusing an existing name) with `mode`, writes `bytes` and
// fsyncs the file when `bytes` is not empty (an empty inode has no data to flush). The directory entry is not
// fsynced. On failure nothing is left at absPath.
void writeFileExclusive(const std::filesystem::path& absPath, std::span<const uint8_t> bytes, mode_t mode = 0600);
// How many file fsyncs writeFileExclusive issued in this process (tests: empty creates issue none).
[[nodiscard]] uint64_t writeFileExclusiveFsyncsForTesting();

// Durably replaces absPath: `produce` writes the new content to a private sibling temp file (created 0600, O_EXCL),
// which is fsynced and renamed over absPath, then the directory is fsynced. Readers see the old file or the new
// one, never a partial one. On failure the temp file is removed and absPath is untouched. An existing file keeps its
// permission bits; a new one is 0600. A failed directory fsync after the rename is logged, not thrown: the
// replacement has happened, and callers record metadata for the new bytes.
void replaceFileAtomic(const std::filesystem::path& absPath,
                       const std::function<void(const std::filesystem::path& tempPath)>& produce);

// replaceFileAtomic with the bytes in memory.
void writeFileAtomic(const std::filesystem::path& absPath, std::span<const uint8_t> bytes);

std::string generate_random_suffix(size_t length = 8);

std::vector<uint8_t> decrypt_file_to_memory(unsigned int vault_id,
                                           const std::filesystem::path& rel_path,
                                           const std::shared_ptr<storage::Engine>& engine);

std::vector<uint8_t> decrypt_file_to_memory(const std::shared_ptr<model::File>& file,
                                           const std::shared_ptr<storage::Engine>& engine);

bool isProbablyEncrypted(const std::filesystem::path& path);

std::string bytesToSize(uintmax_t bytes);

}
