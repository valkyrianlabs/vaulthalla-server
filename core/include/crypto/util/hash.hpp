#pragma once

#include <string>
#include <string_view>
#include <filesystem>

namespace vh::crypto::hash {

std::string blake2b(const std::filesystem::path& filepath);

// Hashes a password with Argon2id using libsodium
std::string password(const std::string& password);

// Unit tests only (refused outside test mode): new password hashes use libsodium's minimum Argon2id cost instead of
// MODERATE (~0.5 s and 256 MiB each). The daemon, test instances included, never calls it.
void setMinimalPasswordCostForTesting();

// Verifies a password against a given Argon2id hash
bool verifyPassword(const std::string& password, const std::string& hash);

// Server-minted session tokens (refresh tokens) are stored as a fast digest, not a password hash: `sha256:<64
// lowercase hex>` of the raw token. A slow KDF only defends low-entropy secrets against offline guessing; a refresh
// token is an HS256 JWT whose signature is a 256-bit HMAC keyed by the daemon's JWT secret, so it is not guessable,
// and anyone holding that secret can re-mint the exact token from the row's claims anyway (HS256 is deterministic).
// Argon2 here cost ~0.57 s per verify (#171). Never use this for user passwords.
std::string tokenDigest(std::string_view token);

enum class TokenMatch {
    Mismatch,   // wrong token, or a stored value that is neither format
    Digest,     // matched a `sha256:` digest
    Legacy,     // matched a libsodium pwhash (Argon2) string written before #171; rewrite it with tokenDigest()
};

// Verifies a raw token against a stored value in either format. Digests compare in constant time.
TokenMatch verifyToken(std::string_view token, const std::string& stored);

std::string generate_secure_password(size_t length = 128);

}
