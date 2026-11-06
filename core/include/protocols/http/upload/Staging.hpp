#pragma once

#include "fs/PlaintextSource.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>

// Where an HTTP upload's bytes wait between its PUT and the commit (Filesystem::createFile, which seals them and
// writes the row). Chosen at build time (meson option `http_upload_staging`); the coordinator never switches mid-way.
//   mount   (Linux default): next to the target, *through the FUSE mount* — the established Linux behavior
//           (CLAUDE.md: intentional; the kernel bridge serializes staging with every other writer).
//   private (macOS default): <backing>/.upload-staging/<vault id>/, 0700, the daemon's uid only, outside every vault,
//           never served, listed or synced. HTTP/WS uploads then work whether a FUSE mount exists, is healthy, or not.
// Neither ever puts plaintext on disk (#328): private staging is a crypto::ScratchFile (ciphertext under the
// process's in-memory key); mount staging lands in a FUSE working copy (the same) and, once closed, is sealed as an
// ordinary vault file. The commit path is the same for both.
namespace vh::protocols::http::upload::staging {

// "mount" or "private".
[[nodiscard]] std::string_view mode() noexcept;

// Whether staging files live inside the FUSE namespace (so the FS cache can hold an entry for one): mount only.
[[nodiscard]] bool insideMount() noexcept;

// The staging file named `name` for the upload whose final path (under the vault root) is `targetAbsPath`. Creates
// the private directories when needed.
[[nodiscard]] std::filesystem::path pathFor(const std::filesystem::path& targetAbsPath, unsigned int vaultId,
                                            const std::string& name);

// The staged body of one upload, written in order.
class Body {
public:
    virtual ~Body() = default;
    virtual void append(std::span<const uint8_t> data) = 0;
    // All bytes are in (mount: the descriptor is closed, which seals the staging file like any FUSE file).
    virtual void close() = 0;
    // Removes the staged bytes now; the body is unusable afterwards. Destruction does the same.
    virtual void discard() noexcept = 0;
    [[nodiscard]] virtual uint64_t size() const = 0;
    // The staged content for fs::Filesystem::createFile; the body must outlive it.
    [[nodiscard]] virtual fs::PlaintextSource source() const = 0;
};

// Creates the staging file `path` (from pathFor; nothing may exist there yet), empty and open for appending.
[[nodiscard]] std::unique_ptr<Body> create(const std::filesystem::path& path);

// Removes what an earlier run left in the private staging area; call once at startup, before uploads are accepted.
// Nothing to do for mount staging (the FUSE working-copy cleanup covers it).
void sweepAtStartup();

}
