#pragma once

#include "ops/Actor.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

// Importing the two MFA keys on a new host (#398; follows #356, #393): `vh secret set mfa-seal|mfa-pepper <file>` takes
// what `vh secret export` wrote. A database restored onto a host without its old state directory has TOTP seeds and
// recovery code hashes that only the old keys open; this puts the old key back instead of enrolling everyone again.
//
// Super admins only (audited, refusals included, as secrets.mfa_key.import; the key and the recovery code never reach
// the audit trail or the log). A key is adopted only after it proves itself against stored rows:
//   mfa-seal    at least one stored TOTP seed decrypts with it (AES-256-GCM with the factor's AAD).
//   mfa-pepper  the keyed hash of a recovery code the actor supplies (`--code`, one of their own, used or not) is a
//               stored hash of theirs.
// It refuses a key that does not match, a key whose current value already works on this host (a readable stored key is
// never replaced), and a key with nothing stored to protect. A refusal changes nothing. Adopting asks for a
// confirmation (NeedsConfirmation, code mfa_seal_import / mfa_pepper_import) and reads the stored key back.
namespace vh::ops::mfa_keys {

enum class Key { Seal, Pepper };

struct ImportResult {
    Key key{Key::Seal};
    std::size_t verified{};  // rows the key opened (seal), or recovery code hashes it reproduced (pepper)
    std::size_t rows{};      // rows stored that depend on it
    bool replaced_unreadable{false};
};

[[nodiscard]] std::string_view cliName(Key key);

// `key` is the 32 raw bytes. `recoveryCode` is required for Key::Pepper only. Wipes nothing it does not own.
[[nodiscard]] ImportResult import(const Actor& actor, Key which, std::span<const uint8_t> key,
                                  std::string_view recoveryCode, bool confirmed);

}
