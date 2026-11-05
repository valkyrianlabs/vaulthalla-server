#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

// How log lines name files (#327). A file or folder name can itself be regulated data (a patient's name, a case
// number), and vaulthalla.log and audit.log are read, shipped and retained far more widely than vault contents. So by
// default (`logging.file_paths: ids`) a log line names a file by its entry id, and a path that has no entry yet by an
// opaque tag: a keyed hash that is stable for this daemon run (so one file's lines can be followed) and useless
// outside it (the key is random per process and never written down, so the tag can't be checked against guessed
// names). `full` adds the vault path, for debugging on hosts that hold nothing sensitive.
//
// Every log line that would carry a vault, FUSE or backing path goes through these helpers.
namespace vh::log {

enum class FilePaths : uint8_t { Ids, Full };

void setFilePaths(FilePaths mode) noexcept;
[[nodiscard]] FilePaths filePaths() noexcept;

// "entry 42"; in full mode "entry 42 (/Reports/q3.pdf)". A missing or zero id falls back to path().
[[nodiscard]] std::string file(std::optional<uint64_t> entryId, const std::filesystem::path& path);

// "path#3f9a1c2e5b7d0a46"; in full mode the path itself.
[[nodiscard]] std::string path(const std::filesystem::path& path);

}
