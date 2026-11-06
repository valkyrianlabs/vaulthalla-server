#pragma once

#include "crypto/Fwd.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/vhf1/Format.hpp"
#include "fs/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The at-rest formats of vault file content (local backing files, recovery blobs, upstream objects of encrypting
// vaults) and the one place that tells them apart (#367, design/encryption/02-authenticated-file-format.md):
//
//   Plain  nothing sealed: every empty file (zero bytes), and plaintext an older build left behind.
//   Gcm0   the legacy format: one headerless AES-256-GCM message (body ‖ tag) under the vault key, its 12-byte IV
//          recorded beside it. Read until the conversion (#372) and the retirement (#376); never written for new
//          content.
//   Vhf1   the authenticated chunked format (crypto::vhf1): every new generation.
//
// The format is never a separate flag that could disagree with the bytes: it follows from the generation id the
// catalog records with the content (files.encryption_iv, recovery_blob.encryption_iv, upload_session_file, the
// upstream x-amz-meta-vh-iv and the remote index), which is the GCM IV (12 bytes) for Gcm0 and the VHF1 salt
// (32 bytes, = the header's salt) for Vhf1, base64 either way. files.content_format and recovery_blob.content_format
// (migration 126) are generated from that column for queries.
namespace vh::vault::content {

enum class Format : uint8_t { Plain, Gcm0, Vhf1 };

[[nodiscard]] std::string_view to_string(Format format);

// The format of a generation id: "" → Plain, a 12-byte IV → Gcm0, a 32-byte salt → Vhf1. Anything else is
// std::invalid_argument (a damaged catalog row, never guessed).
[[nodiscard]] Format formatOf(std::string_view generationB64);
// Whether a generation id is a VHF1 salt (never throws: anything else, malformed ids included, is not).
[[nodiscard]] bool isVhf1(std::string_view generationB64) noexcept;

// Sealed bytes on disk / upstream for a plaintext size: P (Plain), P + 16 (Gcm0), 120 + P + 16·n (Vhf1, 64 KiB
// chunks; an empty plaintext is 136 bytes).
[[nodiscard]] uint64_t sealedSize(uint64_t plaintextSize, Format format);
// The inverse: the plaintext size a sealed size holds, nullopt when no plaintext seals to that size.
[[nodiscard]] std::optional<uint64_t> plaintextSizeOf(uint64_t sealedSize, Format format);
// What new content of this size takes once sealed (Vhf1): space and transfer estimates before anything is written.
[[nodiscard]] uint64_t newSealedSize(uint64_t plaintextSize);
// The plaintext size a sealed size holds for a generation id: nullopt for a malformed id or a size no plaintext
// seals to in its format.
[[nodiscard]] std::optional<uint64_t> plaintextSizeOfGeneration(uint64_t sealedSize, std::string_view generationB64) noexcept;
// The sealed size of a generation, by its id (plaintext size → bytes stored).
[[nodiscard]] uint64_t sealedSizeOf(uint64_t plaintextSize, std::string_view generationB64);

[[nodiscard]] std::string generationOf(const crypto::vhf1::Salt& salt);

// What a reader holds a sealed generation to: the vault it belongs to, the generation id and key version the catalog
// recorded, and the object's uid when the catalog's row is known to be the one that sealed it. For Vhf1 the header
// must name this vault, this salt and this key version (and this object, when given), and every chunk must
// authenticate; for Gcm0 the IV and the vault key of keyVersion are the whole binding (the legacy format has no more).
struct Binding {
    crypto::id::ObjectUid vaultUid{};
    std::string generation;
    uint32_t keyVersion{};
    std::optional<crypto::id::ObjectUid> objectUid{};
};

// The expectation a Vhf1 binding checks (storage::IntegrityError when the generation is not a salt).
[[nodiscard]] crypto::vhf1::Expectation expectationOf(const Binding& binding);
// Opens and authenticates a Vhf1 header against binding (vault, salt, key version and object when given) with `key`
// as the vault key of binding.keyVersion. Throws storage::IntegrityError naming the spec's error code.
[[nodiscard]] crypto::vhf1::OpenedHeader openHeader(std::span<const uint8_t> header, const Binding& binding,
                                                    const crypto::SecretKeyPtr& key);

// A vhf1::Error (or any failure to read a sealed generation) as the storage::IntegrityError readers throw.
[[noreturn]] void throwIntegrity(const crypto::vhf1::Error& error, std::string_view what);

// ---- writing (always Vhf1) ------------------------------------------------------------------------------------------

// The header of a new generation of a vault file: kind FileContent, 64 KiB chunks, a fresh salt.
[[nodiscard]] crypto::vhf1::HeaderParams fileHeader(const crypto::id::ObjectUid& vaultUid,
                                                    const crypto::id::ObjectUid& objectUid, uint32_t keyVersion);

// One sealing of a vault file streamed out through `sink` (the header first, then each chunk once it is complete;
// the last is sealed final by finish()). generation() is the salt's base64, final from construction.
class Sealer {
public:
    using Sink = std::function<void(std::span<const uint8_t>)>;
    Sealer(const crypto::SecretKey& key, uint32_t keyVersion, const crypto::id::ObjectUid& vaultUid,
           const crypto::id::ObjectUid& objectUid, Sink sink);
    ~Sealer();
    Sealer(const Sealer&) = delete;
    Sealer& operator=(const Sealer&) = delete;

    void write(std::span<const uint8_t> plaintext);
    void finish();

    [[nodiscard]] const std::string& generation() const { return generation_; }
    [[nodiscard]] uint32_t keyVersion() const { return keyVersion_; }
    [[nodiscard]] uint64_t objectSize() const;

private:
    std::unique_ptr<crypto::vhf1::Writer> writer_;
    std::string generation_;
    uint32_t keyVersion_{};
};

struct Sealed {
    std::vector<uint8_t> bytes;
    std::string generation;
};

[[nodiscard]] Sealed sealBuffer(std::span<const uint8_t> plaintext, const crypto::SecretKey& key, uint32_t keyVersion,
                                const crypto::id::ObjectUid& vaultUid, const crypto::id::ObjectUid& objectUid);

// Streams `source` into a new Vhf1 file at `path` (parents created, 0600, truncated; removed again on any failure)
// and returns its generation. Plaintext exists only in wiped 64 KiB buffers.
[[nodiscard]] std::string sealSourceToFile(const fs::PlaintextSource& source, const std::filesystem::path& path,
                                           const crypto::SecretKey& key, uint32_t keyVersion,
                                           const crypto::id::ObjectUid& vaultUid,
                                           const crypto::id::ObjectUid& objectUid);

// ---- reading (every format) -----------------------------------------------------------------------------------------

using Sink = std::function<void(std::span<const uint8_t>)>;

// The whole plaintext of a sealed buffer, authenticated before it is returned (storage::IntegrityError otherwise).
// A Plain binding returns the bytes as they are.
[[nodiscard]] std::vector<uint8_t> openBuffer(std::span<const uint8_t> sealed, const Binding& binding,
                                              const crypto::SecretKey& key);

// Streams a sealed file's plaintext into sink. Vhf1: only authenticated chunks reach the sink, and the whole object
// is authenticated (size, final chunk) when this returns. Gcm0: what the sink received is NOT authenticated until this
// returns (the legacy format has one tag at the end); on a throw the caller discards it. storage::IntegrityError on
// any authentication failure.
void openFileTo(const std::filesystem::path& path, const Binding& binding, const crypto::SecretKey& key,
                const Sink& sink);

// Authenticates a whole sealed file on fd (from offset 0) whose plaintext is plaintextSize bytes: the size, and every
// chunk (Vhf1) or the tag (Gcm0). No plaintext leaves this function. false on any mismatch.
[[nodiscard]] bool verifyFd(int fd, uint64_t plaintextSize, const Binding& binding, const crypto::SecretKey& key);
[[nodiscard]] bool verifyFile(const std::filesystem::path& path, uint64_t plaintextSize, const Binding& binding,
                              const crypto::SecretKey& key);
// verifyFile for a file whose plaintext size isn't recorded (a content sidecar): the size its stored length implies.
[[nodiscard]] bool verifyWholeFile(const std::filesystem::path& path, const Binding& binding,
                                   const crypto::SecretKey& key);

// Sealed bytes arriving in order (a GET body) opened as they come: Vhf1 passes on each chunk once it authenticated;
// Gcm0 passes on unauthenticated plaintext and checks the tag in finish() (callers discard on a throw, as with
// openFileTo). sealedSize is the object's full size (fixed by the catalog or the HEAD).
class StreamOpener {
public:
    StreamOpener(const Binding& binding, crypto::SecretKeyPtr key, uint64_t sealedSize);
    ~StreamOpener();
    StreamOpener(const StreamOpener&) = delete;
    StreamOpener& operator=(const StreamOpener&) = delete;

    void update(std::span<const uint8_t> sealed, const Sink& sink);
    // Throws storage::IntegrityError unless the whole object arrived and authenticated.
    void finish(const Sink& sink);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Re-seals a sealed file (any format, bound by `from` and opened with fromKey) into a new Vhf1 file at dst under
// toKey/toKeyVersion with a fresh salt, streaming; returns the new generation. dst holds the result only once this
// returns: a source that fails authentication throws storage::IntegrityError and leaves no dst (nor does any other
// failure). An empty Plain source yields an empty dst and "" (every empty file is stored as nothing); a non-empty
// Plain source is refused (std::invalid_argument).
[[nodiscard]] std::string resealFile(const std::filesystem::path& src, const Binding& from,
                                     const crypto::SecretKey& fromKey, const std::filesystem::path& dst,
                                     const crypto::SecretKey& toKey, uint32_t toKeyVersion,
                                     const crypto::id::ObjectUid& objectUid);

}
