#pragma once

#include <filesystem>
#include <string>
#include <string_view>

// Where an HTTP upload's bytes wait between its PUT and the commit (Filesystem::createFile, which seals them and
// writes the row). Chosen at build time (meson option `http_upload_staging`); the coordinator never switches mid-way.
//   mount   (Linux default): next to the target, *through the FUSE mount* — the established Linux behavior
//           (CLAUDE.md: intentional; the kernel bridge serializes staging with every other writer).
//   private (macOS default): <backing>/.upload-staging/<vault id>/, 0700, the daemon's uid only, outside every vault,
//           never served, listed or synced. HTTP/WS uploads then work whether a FUSE mount exists, is healthy, or not.
// Either way the staged bytes are plaintext only while the upload is in flight, and the commit path is the same.
namespace vh::protocols::http::upload::staging {

// "mount" or "private".
[[nodiscard]] std::string_view mode() noexcept;

// The staging file named `name` for the upload whose final path (under the vault root) is `targetAbsPath`. Creates
// the private directories when needed.
[[nodiscard]] std::filesystem::path pathFor(const std::filesystem::path& targetAbsPath, unsigned int vaultId,
                                            const std::string& name);

// Removes what an earlier run left in the private staging area; call once at startup, before uploads are accepted.
// Nothing to do for mount staging (the FUSE working-copy cleanup covers it).
void sweepAtStartup();

}
