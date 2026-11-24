#pragma once

#include <chrono>
#include <ctime>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// OpenPGP public-key encryption for vault read grants (ops/ReadGrants.hpp), through the system GnuPG (`gpg`, Debian
// package gpg, Homebrew gnupg). Every call runs gpg in a throwaway home directory that holds nothing but the public
// keys it is given, with --no-options (no gpg.conf), --no-autostart (no gpg-agent, dirmngr or keyboxd is ever started,
// so nothing outlives the call) and --batch. Input reaches gpg over a socket on its stdin and output comes back on
// stdout: a plaintext is never on a command line, in the environment or in a file. Public keys are written into the
// home directory (they are public). Nothing is imported anywhere else, no keyserver is contacted and no trust database
// outside the home directory is consulted: who a message is for is exactly the keys the caller passes.
namespace vh::crypto::openpgp {

// gpg isn't installed (or can't be run).
struct Unavailable : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// The input isn't one usable OpenPGP public key, or gpg refused it. what() says why, for people.
struct BadKey : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct KeyInfo {
    std::string fingerprint;                  // the primary key's, 40 upper-case hex digits (a v4 key)
    std::string algorithm;                    // "ed25519", "rsa4096", …
    std::vector<std::string> user_ids;
    std::time_t created_at{};
    std::optional<std::time_t> expires_at;
    bool revoked{false};
    bool expired{false};
    bool invalid{false};                      // no valid self-signature or user ID (gpg validity "i")
    // Fingerprints of the keys a message would be encrypted to: valid encryption-capable subkeys (or the primary key,
    // when it may encrypt itself).
    std::vector<std::string> encryption_keys;
    std::vector<std::string> encryption_algorithms;   // the same keys' algorithms ("cv25519", …)

    // Why nothing can be encrypted to this key ("revoked", "expired on …", …), or nullopt when it can.
    [[nodiscard]] std::optional<std::string> unusableReason() const;
};

// Upper-cased, spaces removed; throws std::invalid_argument unless it is 40 hex digits (a full v4 fingerprint; a key
// id or a shortened fingerprint is never accepted).
[[nodiscard]] std::string normalizeFingerprint(std::string_view text);

// Whether gpg can be run here.
[[nodiscard]] bool available();

// The one public key in `armored` (ASCII armor or binary). Throws BadKey when it holds no key, more than one, or secret
// key material; Unavailable without gpg.
[[nodiscard]] KeyInfo inspect(const std::string& armored);

// Throws BadKey with unusableReason() when the key can't be encrypted to.
void requireEncryptable(const KeyInfo& key);

// One ASCII-armored OpenPGP message that each of `armoredKeys` (one or more public keys) decrypts. Each key is checked
// with inspect + requireEncryptable first. Compression is off. Throws BadKey or Unavailable; what() never contains the
// plaintext.
[[nodiscard]] std::string encrypt(std::string_view plaintext, const std::vector<std::string>& armoredKeys);

// ---- process plumbing, public for tests -------------------------------------------------------------------------

struct RunResult {
    int exit_code{-1};
    bool timed_out{false};
    std::string out;
    std::string err;
};

// Runs `executable` with `args` (argv[1..]), a minimal environment (LC_ALL=C, PATH=/usr/bin:/bin), `input` on its
// stdin and its stdout/stderr captured (each capped at 4 MiB). Every other descriptor is closed in the child. Kills it
// after `timeout`.
[[nodiscard]] RunResult run(const std::filesystem::path& executable, const std::vector<std::string>& args,
                            std::string_view input, std::chrono::seconds timeout = std::chrono::seconds(30));

// The gpg binary used (test mode may point elsewhere; nullopt restores the search: /usr/bin/gpg,
// /opt/homebrew/bin/gpg, /usr/local/bin/gpg).
[[nodiscard]] std::optional<std::filesystem::path> executable();
void setExecutableForTesting(std::optional<std::filesystem::path> path);

// A private directory (0700) under the temp directory, removed with everything in it when the object goes away.
class TempHome {
public:
    TempHome();
    ~TempHome();
    TempHome(const TempHome&) = delete;
    TempHome& operator=(const TempHome&) = delete;
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

}
