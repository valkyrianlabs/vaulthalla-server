#pragma once

#include "crypto/SecretKey.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>

// VHF1, the versioned, self-describing authenticated file format (design/encryption/02-authenticated-file-format.md
// §3, golden vectors in design/encryption/vectors/vectors.json):
//
//   object = header (120 bytes) ‖ C_0 ‖ … ‖ C_{n-1},  C_i = AES-256-GCM(K_enc, nonce_i, P_i, AAD_i) = ct_i ‖ tag_i
//
// The header body (bytes 0..88) is hashed (hh) into every chunk's AAD and into both HKDF infos, and tagged with
// HMAC-SHA-256 under K_hdr. Every primitive comes from OpenSSL (HKDF, HMAC, SHA-256, AES-GCM) or libsodium (CSPRNG,
// constant-time compare, wiping); nothing here implements a primitive.
//
// This header holds the format itself: constants, error codes, the header codec, the key schedule, the size math and
// single-chunk sealing/opening. Writer.hpp streams objects out, Reader.hpp reads them back (whole, streamed, ranged).
namespace vh::crypto::vhf1 {

inline constexpr std::array<uint8_t, 8> kMagic{0x89, 0x56, 0x48, 0x46, 0x0D, 0x0A, 0x1A, 0x0A};  // "\x89VHF\r\n\x1a\n"
inline constexpr uint16_t kFormatVersion = 1;
inline constexpr uint16_t kSuiteAes256GcmHkdfSha256 = 0x0001;
inline constexpr std::size_t kHeaderSize = 120;
inline constexpr std::size_t kHeaderBodySize = 88;  // the bytes the header tag covers and hh hashes
inline constexpr std::size_t kHeaderTagSize = 32;
inline constexpr std::size_t kTagSize = 16;         // per-chunk GCM tag
inline constexpr std::size_t kNonceSize = 12;
inline constexpr std::size_t kAadSize = 41;         // hh ‖ UInt64BE(i) ‖ UInt8(final)
inline constexpr std::size_t kHashSize = 32;
inline constexpr std::size_t kUidSize = 16;
inline constexpr std::size_t kSaltSize = 32;
inline constexpr uint8_t kMinChunkLog2 = 10;
inline constexpr uint8_t kMaxChunkLog2 = 22;
inline constexpr uint8_t kWriterChunkLog2 = 16;     // 64 KiB: what product writers use

enum class Kind : uint8_t {
    FileContent = 1,
    ManifestSegment = 2,
    ManifestRoot = 3,
};

// The reader's failure modes, in the check order of spec 02 §3.6 (header, caller expectations, header tag, size,
// chunks). The names are the vectors' `expect.error` spellings (errorCodeName).
enum class ErrorCode : uint8_t {
    BadMagic,
    UnsupportedVersion,
    BadHeaderLength,
    UnsupportedSuite,
    BadChunkSize,
    ReservedNonzero,
    KindMismatch,
    VaultMismatch,
    ObjectMismatch,
    GenerationMismatch,  // §3.6 "generation check": the salt is not the generation the caller expects
    KeyUnavailable,
    HeaderAuthFailed,
    SizeUnknown,         // a range read without an authenticated object size (§3.7)
    SizeMismatch,
    BadSize,
    RangeOutOfBounds,
    ChunkAuthFailed,
};

[[nodiscard]] std::string_view errorCodeName(ErrorCode code);
[[nodiscard]] std::optional<ErrorCode> errorCodeFromName(std::string_view name);

// Every rejection of a VHF1 object. chunkIndex() is set for ChunkAuthFailed only.
class Error : public std::runtime_error {
public:
    explicit Error(ErrorCode code, std::optional<uint64_t> chunkIndex = std::nullopt);

    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
    [[nodiscard]] std::optional<uint64_t> chunkIndex() const noexcept { return chunkIndex_; }

private:
    ErrorCode code_;
    std::optional<uint64_t> chunkIndex_;
};

using Uid = std::array<uint8_t, kUidSize>;
using Salt = std::array<uint8_t, kSaltSize>;
using HeaderHash = std::array<uint8_t, kHashSize>;
using HeaderBody = std::array<uint8_t, kHeaderBodySize>;
using HeaderTag = std::array<uint8_t, kHeaderTagSize>;
using Nonce = std::array<uint8_t, kNonceSize>;
using Aad = std::array<uint8_t, kAadSize>;

// What a writer puts in the header. The salt is the generation id: fresh from the CSPRNG (freshSalt()) for every
// sealing, never reused for different content (§3.3 nonce discipline).
struct HeaderParams {
    Kind kind{Kind::FileContent};
    uint32_t keyVersion{};
    Uid vaultUid{};
    Uid objectUid{};
    Salt salt{};
    uint8_t chunkLog2{kWriterChunkLog2};
};

[[nodiscard]] Salt freshSalt();

// Header body bytes for params. Throws std::invalid_argument for a kind outside 1..3, key version 0, or a chunk size
// outside kMinChunkLog2..kMaxChunkLog2.
[[nodiscard]] HeaderBody encodeHeaderBody(const HeaderParams& params);
[[nodiscard]] HeaderHash headerHash(std::span<const uint8_t, kHeaderBodySize> body);

// §3.3: PRK = HKDF-Extract(salt, vault key); K_hdr / K_enc = HKDF-Expand(PRK, "vh.f1.hdr"/"vh.f1.enc" ‖ hh, 32).
struct KeySchedule {
    SecretKeyPtr prk;
    SecretKeyPtr headerKey;
    SecretKeyPtr contentKey;
};
[[nodiscard]] KeySchedule deriveKeys(const SecretKey& vaultKey, const Salt& salt, const HeaderHash& hh);
[[nodiscard]] HeaderTag headerTag(const SecretKey& headerKey, std::span<const uint8_t, kHeaderBodySize> body);

[[nodiscard]] Nonce chunkNonce(uint64_t index);
[[nodiscard]] Aad chunkAad(const HeaderHash& hh, uint64_t index, bool final);

// Size math (§3.4). S = 120 + P + 16·n with n = max(1, ceil(P / C)).
struct Layout {
    uint64_t chunkCount{};
    uint64_t plaintextSize{};

    [[nodiscard]] bool operator==(const Layout&) const = default;
};

// Object bytes [begin, end).
struct ByteSpan {
    uint64_t begin{};
    uint64_t end{};

    [[nodiscard]] uint64_t size() const { return end - begin; }
    [[nodiscard]] bool operator==(const ByteSpan&) const = default;
};

[[nodiscard]] uint64_t chunkSizeOf(uint8_t chunkLog2);
// Throws std::overflow_error when the object would not fit in 64 bits.
[[nodiscard]] uint64_t objectSizeFor(uint64_t plaintextSize, uint8_t chunkLog2);
// (n, P) from the object size, or Error(BadSize) when S has no valid layout.
[[nodiscard]] Layout layoutFor(uint64_t objectSize, uint8_t chunkLog2);
// Where chunk `index` (sealed: ciphertext ‖ tag) sits in the object. Throws std::out_of_range past the last chunk.
[[nodiscard]] ByteSpan chunkSpan(uint64_t index, const Layout& layout, uint8_t chunkLog2);

// A plaintext buffer with a fixed capacity, wiped (sodium_memzero) on destruction and on clear(). It never
// reallocates, so no copy of the plaintext is left behind in freed memory. Move-only.
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t capacity);
    ~SecureBytes();
    SecureBytes(SecureBytes&& other) noexcept;
    SecureBytes& operator=(SecureBytes&& other) noexcept;
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    // Throws std::length_error past the capacity.
    void append(std::span<const uint8_t> bytes);
    void resize(std::size_t size);  // within the capacity; new bytes are zero
    void clear();

    [[nodiscard]] std::size_t size() const { return size_; }
    [[nodiscard]] std::size_t capacity() const { return capacity_; }
    [[nodiscard]] bool empty() const { return size_ == 0; }
    [[nodiscard]] uint8_t* data() { return data_.get(); }
    [[nodiscard]] const uint8_t* data() const { return data_.get(); }
    [[nodiscard]] std::span<uint8_t> span() { return {data_.get(), size_}; }
    [[nodiscard]] std::span<const uint8_t> span() const { return {data_.get(), size_}; }
    // The whole allocation, used or not (scratch buffers).
    [[nodiscard]] std::span<uint8_t> storage() { return {data_.get(), capacity_}; }

private:
    void wipe() noexcept;

    std::unique_ptr<uint8_t[]> data_;
    std::size_t capacity_{};
    std::size_t size_{};
};

// What the caller knows about the object it is reading (the DB row or the manifest entry), checked in step 2 of
// §3.6. generation, when set, is the salt the caller expects (stale reads and rollbacks fail GenerationMismatch).
// objectUid is nullopt only when the caller doesn't hold the uid the object was sealed under (a path_v0 row indexed
// from a bucket listing before its object was read); the generation then binds the object to the row on its own
// (a 256-bit salt names exactly one sealing). An expectation with neither is refused (std::invalid_argument).
struct Expectation {
    Kind kind{Kind::FileContent};
    Uid vaultUid{};
    std::optional<Uid> objectUid{};
    std::optional<Salt> generation;
};

// The vault key of a key version, or nullptr when it is not held (KeyUnavailable).
using KeyLookup = std::function<SecretKeyPtr(uint32_t keyVersion)>;

// A header that passed §3.6 steps 1-3, with its derived content key. Cheap to copy (the key is shared).
class OpenedHeader {
public:
    [[nodiscard]] const HeaderParams& params() const { return params_; }
    [[nodiscard]] const HeaderHash& hash() const { return hash_; }
    [[nodiscard]] uint64_t chunkSize() const { return chunkSizeOf(params_.chunkLog2); }
    [[nodiscard]] const SecretKey& contentKey() const { return *contentKey_; }

private:
    friend OpenedHeader openHeader(std::span<const uint8_t>, const Expectation&, const KeyLookup&);
    OpenedHeader(const HeaderParams& params, const HeaderHash& hash, SecretKeyPtr contentKey);

    HeaderParams params_;
    HeaderHash hash_{};
    SecretKeyPtr contentKey_;
};

// Parses and authenticates the header at the start of `object` (only its first kHeaderSize bytes are read; fewer is
// BadMagic). Throws Error with the first failing check, in the order of §3.6 steps 1-3.
[[nodiscard]] OpenedHeader openHeader(std::span<const uint8_t> object, const Expectation& expect,
                                      const KeyLookup& keys);

// Seals chunk `index`: out (plaintext.size() + kTagSize bytes) = ciphertext ‖ tag.
void sealChunk(const SecretKey& contentKey, const HeaderHash& hh, uint64_t index, bool final,
               std::span<const uint8_t> plaintext, std::span<uint8_t> out);

// Opens one sealed chunk (ciphertext ‖ tag) into out (sealed.size() - kTagSize bytes). Returns false when the tag
// does not verify, with out wiped: the plaintext written while decrypting is never left for the caller.
[[nodiscard]] bool openChunk(const OpenedHeader& header, uint64_t index, bool final,
                             std::span<const uint8_t> sealed, std::span<uint8_t> out);

}
