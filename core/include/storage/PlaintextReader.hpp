#pragma once

#include "fs/Fwd.hpp"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::storage {

// One content generation of a vault file. Every content write reseals the file with a fresh random IV, so the
// IV identifies the bytes; an empty file is always the same generation, and a rare unencrypted legacy file is
// identified by size + mtime. Rename and move keep it (except for that legacy case). The etag() is what
// /download/content serves and what an entry's `content_version` carries.
struct Generation {
    uint32_t vault_id{};
    uint32_t file_id{};
    std::string iv_b64;           // empty for unencrypted (empty or legacy) files
    uint32_t key_version{};
    uint64_t size{};              // plaintext size
    std::time_t updated_at{};

    // Changes whenever the content changes; stable across rename/move. Used as the derived-artifact source id.
    [[nodiscard]] std::string sourceId() const;

    // Strong HTTP validator: "g<file_id>-<hex16(sha256(sourceId|key_version|size))>" (quoted).
    [[nodiscard]] std::string etag() const;

    [[nodiscard]] bool encrypted() const { return !iv_b64.empty(); }
};

// The generation of a file as currently recorded (no I/O beyond the model).
[[nodiscard]] Generation generationOf(const ::vh::fs::model::File& file);

// Thrown when the bytes of a generation fail authentication (GCM tag mismatch), including mid-stream: an
// optimistic reader may already have released some bytes before verification completed.
class IntegrityError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The bytes are not available locally and policy forbids fetching them (remote policy "off", or the remote
// request/price budget refused the fetch).
class ContentUnavailable final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class IntegrityPolicy {
    FromConfig,  // preview.media.integrity
    Optimistic,  // serve immediately, verify the whole GCM message once in the background, abort on failure
    Strict       // verify the whole message before releasing any byte
};

enum class RemoteFetchPolicy {
    FromConfig,  // preview.media.remote
    Hydrate,     // fetch the whole object once (metered, budgeted), verify, keep the local ciphertext copy
    Ranged,      // opt-in: metered ranged GETs bound to the object version (If-Match); no per-range authentication
    Off          // never fetch: ContentUnavailable for remote-only files
};

struct ReaderOptions {
    IntegrityPolicy integrity{IntegrityPolicy::FromConfig};
    RemoteFetchPolicy remote{RemoteFetchPolicy::FromConfig};
};

// Positioned plaintext access to one file generation, without materializing plaintext anywhere but the caller's
// buffer. The single funnel every byte consumer (download, media, models, previews, thumbnails, converters,
// text) goes through, so a future at-rest format is an implementation detail of the reader.
class PlaintextReader {
public:
    virtual ~PlaintextReader() = default;

    [[nodiscard]] virtual uint64_t size() const = 0;

    // Reads up to out.size() bytes at offset and returns the count (0 at or past EOF). Short reads happen only at
    // EOF. Throws IntegrityError when the generation failed verification, std::system_error on I/O failure.
    virtual std::size_t read(uint64_t offset, std::span<uint8_t> out) = 0;

    [[nodiscard]] virtual const Generation& generation() const = 0;

    // The whole content, authenticated before it is returned when the format allows it (one pass, no
    // separate verification read). Throws std::length_error over maxBytes. Default: sequential read().
    [[nodiscard]] virtual std::vector<uint8_t> readAllAuthenticated(uint64_t maxBytes);

    // Blocks until the whole generation is authenticated, throwing IntegrityError when it is not. For a consumer
    // that streamed every byte through read() and must not vouch for them (a ZIP member's CRC) until they are known
    // good. Default: nothing to wait for (readers whose format has no whole-message check, or already checked it).
    virtual void requireAuthenticated() {}
};

// Reads the whole content into memory, refusing (std::length_error) anything larger than maxBytes. For small
// inputs only (thumbnail sources, text documents, converter inputs with their own caps). Authenticated.
[[nodiscard]] std::vector<uint8_t> readAll(PlaintextReader& reader, uint64_t maxBytes);

}
