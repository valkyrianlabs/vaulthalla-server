#pragma once

#include "crypto/SecretKey.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// KEV1 key envelopes (design/encryption/03-metadata-recovery.md §5.2): one vault key version wrapped to one recovery
// recipient's public key, stored in the vault's bucket as `.vaulthalla/key/<kid>`. Vectors: vectors.json `kev1`.
//
//   offset  len  field
//    0       8   magic 89 56 48 4B 0D 0A 1A 0A
//    8       2   version 1
//   10       2   suite: 1 = X25519 + HKDF-SHA-256 + AES-256-GCM (recovery recipients),
//                       2 = P-256 ECDH + HKDF-SHA-256 + AES-256-GCM (device grants, spec 04)
//   12       1   purpose: 1 = a whole vault key version; 2-255 reserved
//   13       1   recipient_class: 0 = customer-controlled; 1-255 reserved for separately authorized classes
//   14       2   reserved, 0
//   16       4   key_version (>= 1)
//   20      16   vault_uid
//   36      32   recipient_id = SHA-256(recipient public key: 32 raw bytes, or the 65-byte uncompressed P-256 point)
//   68       2   epk_len (32 or 65)
//   70   epk_len epk, fresh per envelope
//   70+e    48   AES-256-GCM(K_wrap, nonce 0^12, vault key, AAD = bytes[0 .. 70+e))
//
//   K_wrap = HKDF-Expand(HKDF-Extract(salt = epk ‖ rpk, IKM = Z), "vh.kev1.wrap" ‖ prefix, 32)
//
// Every envelope this code writes has purpose 1 and recipient_class 0: the only class implemented is the customer's
// own (custody amendment, #344). A reader refuses reserved purposes and classes (a restore skips such envelopes and
// goes on), so a later, separately approved recipient type fits without changing any byte written today (§5.7).
namespace vh::crypto::kev1 {

inline constexpr std::array<uint8_t, 8> kMagic{0x89, 0x56, 0x48, 0x4B, 0x0D, 0x0A, 0x1A, 0x0A};
inline constexpr uint16_t kVersion = 1;
inline constexpr uint8_t kPurposeVaultKey = 1;
inline constexpr uint8_t kClassCustomer = 0;
inline constexpr std::size_t kFixedPrefixSize = 70;
inline constexpr std::size_t kWrappedSize = 48;
inline constexpr std::size_t kX25519KeySize = 32;
inline constexpr std::size_t kP256PointSize = 65;
inline constexpr std::size_t kP256ScalarSize = 32;
inline constexpr std::string_view kObjectPrefix = ".vaulthalla/key/";

enum class Suite : uint16_t { X25519 = 1, P256 = 2 };

using VaultUid = std::array<uint8_t, 16>;
using Digest = std::array<uint8_t, 32>;

// The reader's checks, in the order it makes them (§5.2); the vectors name the first that fails.
enum class ErrorCode : uint8_t {
    BadMagic,
    UnsupportedVersion,
    UnsupportedSuite,
    BadPurpose,                 // reserved purpose (e.g. a future threshold share): skipped by a restore
    UnsupportedRecipientClass,  // reserved class (e.g. a future custodian): skipped by a restore, never decrypted
    ReservedNonzero,
    VaultMismatch,
    RecipientMismatch,          // addressed to another recipient: skipped by a restore
    BadLength,
    BadEphemeral,
    WrapAuthFailed,
    BadKeyVersion,
};

[[nodiscard]] std::string_view errorCodeName(ErrorCode code);

class Error : public std::runtime_error {
public:
    explicit Error(ErrorCode code);
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

// Envelopes a restore passes over without failing (spec 03 §6.2 step 2): another recipient's, and those of a purpose
// or recipient class this reader doesn't implement.
[[nodiscard]] bool skippedByRestore(ErrorCode code) noexcept;

// SHA-256 of a recipient public key (the envelope's recipient_id, the root's grants[].recipient_id).
[[nodiscard]] Digest recipientId(std::span<const uint8_t> publicKey);

// The public key of a secret: X25519 (32 bytes) or P-256 (the scalar's 65-byte uncompressed point).
[[nodiscard]] std::vector<uint8_t> publicKeyOf(Suite suite, std::span<const uint8_t> secretKey);

// Wraps `vaultKey` (version keyVersion of the vault vaultUid) to `recipientPublicKey`. The ephemeral key is fresh
// from the CSPRNG; `ephemeralSecretForTesting` (the vectors) fixes it. Throws std::invalid_argument for a public key
// of the wrong size or that is not a valid point, Error(BadEphemeral) for a degenerate shared secret.
[[nodiscard]] std::vector<uint8_t> wrap(const SecretKey& vaultKey, Suite suite, uint32_t keyVersion,
                                        const VaultUid& vaultUid, std::span<const uint8_t> recipientPublicKey,
                                        std::span<const uint8_t> ephemeralSecretForTesting = {});

struct Unwrapped {
    uint32_t key_version{};
    SecretKeyPtr key;
};

// The reader. Throws Error with the first check that fails.
[[nodiscard]] Unwrapped unwrap(std::span<const uint8_t> envelope, std::span<const uint8_t> recipientSecretKey,
                               Suite expectedSuite, const VaultUid& vaultUid);

// The authenticated prefix's fields, read without a key (listing, reporting). Applies the reader's structural checks
// through reserved_nonzero and the length check; never the vault or recipient ones.
struct Header {
    uint16_t suite{};
    uint8_t purpose{};
    uint8_t recipient_class{};
    uint32_t key_version{};
    VaultUid vault_uid{};
    Digest recipient_id{};
};
[[nodiscard]] Header inspect(std::span<const uint8_t> envelope);

// kid = base32(SHA-256(envelope)[0..16]); the object key is `.vaulthalla/key/<kid>`.
[[nodiscard]] std::string kid(std::span<const uint8_t> envelope);
[[nodiscard]] std::string objectKey(std::string_view kid);

}
