#pragma once

#include "crypto/SecretBytes.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

// TOTP, the MFA fallback factor (#356; MFA design note docs/dev/mfa-design.md section 4.2): RFC 6238 over RFC 4226
// HOTP with HMAC-SHA1, 6 digits and a 30 s period, the parameters every authenticator app (1Password, Google
// Authenticator, Aegis) accepts. Pure functions: storage, sealing and the replay guard are auth::mfa (Factors.hpp).
//
// A code, a seed, its base32 form and an otpauth URI are secrets: never log them, put them in audit details or
// telemetry, or keep a copy longer than the call that needs it.
namespace vh::auth::mfa::totp {

inline constexpr std::size_t kSecretBytes = 20;  // 160 bits, RFC 4226's recommendation
inline constexpr int kDigits = 6;
inline constexpr int64_t kPeriodSeconds = 30;
inline constexpr int64_t kWindowSteps = 1;  // the step before and after the current one are accepted too

// A fresh seed from libsodium's CSPRNG, in locked memory.
[[nodiscard]] crypto::SecretBytes generateSecret();

// The clock codes are checked against (Factors.hpp's default `now`): the system clock, plus what a test moved it by.
[[nodiscard]] std::chrono::system_clock::time_point now();

// Tests only (refused outside test mode): moves now() forward, so a sign-in after a spent step doesn't wait up to 30 s
// for the next one in real time. resetClockForTesting() goes back to the system clock.
void advanceClockForTesting(std::chrono::seconds by);
void resetClockForTesting();

// The RFC 6238 time step of `t`: floor(unix seconds / 30).
[[nodiscard]] int64_t stepAt(std::chrono::system_clock::time_point t);

// HOTP(secret, step) truncated to `digits` (6..8) decimal digits, zero-padded.
[[nodiscard]] std::string code(std::span<const uint8_t> secret, int64_t step, int digits = kDigits);

// The user's input as exactly six ASCII digits (spaces dropped), or nullopt.
[[nodiscard]] std::optional<std::string> normalizeCode(std::string_view input);

// The step in currentStep-1 .. currentStep+1 whose code equals `input`, provided it is later than `lastStep` (the
// replay guard: a step already used, or one older than the last used, is refused). Every candidate is computed and
// compared in constant time. The caller still has to claim the step (Factors.cpp: UPDATE ... WHERE last_step < step).
[[nodiscard]] std::optional<int64_t> match(std::span<const uint8_t> secret, std::string_view input,
                                           int64_t currentStep, int64_t lastStep);

// RFC 4648 base32 without padding (what authenticator apps take for a pasted seed).
[[nodiscard]] std::string base32(std::span<const uint8_t> bytes);

// otpauth://totp/<issuer>:<account>?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30, label and issuer
// percent-encoded.
[[nodiscard]] std::string otpauthUri(std::string_view issuer, std::string_view account, std::string_view secretBase32);

}
