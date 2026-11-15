#pragma once

#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"

#include <nlohmann/json_fwd.hpp>

#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The linked account's recovery key on this server (design/cloud/key-manager.md, work items 2, 3 and 6; the cloud's
// docs/design/key-manager.md): fetching the key statement chain and the account's signed recovery policy
// (GET /v1/keys/account), verifying both with vl-keykit, pinning the key once a super admin confirms its fingerprint
// (the only confirmation a server asks for), following signed rotations from the pin, refusing a rollback, a chain that
// doesn't reach the pin and an unsigned replacement until a person confirms it, and keeping each covered vault's
// account-managed recovery grants equal to the accepted policy.
//
// Nothing here runs unless the server is linked, and nothing sends a vault key, the account key's private half (the
// server never has it) or anything unwrapped: the cloud receives only what it already serves back. The network check
// runs on the CLI's thread (`vh cloud key refresh`, `vh cloud link`) or the background service (cloud::KeyService),
// never on a FUSE, sync or ws path; a failed check changes nothing and is retried.
namespace vh::ops::cloud_keys {

using Channel = vault_keys::Channel;

struct Generation {
    uint32_t generation{};
    std::string fingerprint;     // eight groups of four hex digits, computed here from the statement
    std::string state;           // pending | pinned | superseded | refused
    std::string link;            // initial | rotation | replacement (vl-keykit's verifyChain, never the cloud's word)
    std::string reason;          // initial | routine | compromise (signed in the statement)
    std::string x25519_public;   // base64url
    std::optional<std::string> confirmed_by;
    std::optional<std::time_t> confirmed_at;
};

struct PolicyRecipient {
    std::string recipient_id;  // hex SHA-256 of the public key, as a grant's
    std::string label;
};

struct Policy {
    uint32_t sequence{};
    uint32_t generation{};
    std::string sha256;  // hex
    std::string issued_at;
    std::vector<PolicyRecipient> recipients;
};

struct VaultCoverage {
    unsigned int vault_id{};
    std::string vault_name;
    std::optional<uint32_t> account_key_generation;  // the active account-key grant's
    unsigned int policy_grants{};                    // active grants the policy added
    std::optional<uint32_t> applied_sequence;        // the policy sequence this vault last applied
};

struct Status {
    // unlinked | unchecked (linked, no key fetched yet) | none (the account has no key yet) | pending (waiting for
    // the first confirmation) | pinned | change_pending (a replacement waits for a confirmation) | tampered
    std::string state{"unlinked"};
    std::optional<std::string> account_public_id;
    std::optional<Generation> pinned;
    std::optional<Generation> waiting;  // the pending first key or a refused replacement
    std::vector<Generation> generations;
    std::optional<Policy> policy;  // the accepted policy (the floor)
    std::vector<VaultCoverage> vaults;
    std::string offline_copy{"unknown"};  // confirmed | none | unknown (never checked)
    std::optional<std::time_t> offline_copy_at;
    std::optional<std::time_t> checked_at;
    std::optional<std::string> check;         // the last check: ok | none | unreachable | refused | rejected | tampered
    std::optional<std::string> check_detail;
    std::optional<std::string> issue;         // cloud_account_key_tampered | cloud_account_key_change_pending
    std::optional<std::string> next_step;
};

// Super admins or the encryption-key View permission; any channel, agents included (public values only). Reads the
// database only.
[[nodiscard]] Status status(const Actor& actor);

// Fetches and verifies now (super admins; the CLI, a paired device or the console, never an agent).
[[nodiscard]] Status refresh(const Actor& actor, Channel channel);

// The same as the system (the background service, the link, a confirmation): no permission check. Throws only when
// the server isn't linked; every other outcome is recorded in the link row and the audit trail and returned.
[[nodiscard]] Status check(const std::string& trigger);

struct Confirmed {
    Generation generation;
    bool replacement = false;           // a new key replaced a pin (the old one is superseded)
    std::vector<unsigned int> vaults;   // vaults whose account-key grant moved to it
};
// The first pin, or a replacement's: `fingerprint` must equal the waiting generation's (lenient: upper case, spaces
// or no separators). Super admins; the CLI, or a paired device with the keys step-up; the console is refused
// cloud_key_requires_device, an agent denied. On the CLI a key not fetched yet is fetched first.
[[nodiscard]] Confirmed confirm(const Actor& actor, const std::string& fingerprint, Channel channel);

struct Forgotten {
    unsigned int generations{};
};
// Destroys the pin (rows and the sealed key) so the next link asks again. Super admins, CLI only. Refused while a
// vault holds an active account-managed grant (revoke those first): no vault silently loses a recovery path.
[[nodiscard]] Forgotten forget(const Actor& actor, Channel channel);

// The linked account's pinned key, MAC-verified (nullopt: none). Refused cloud_account_key_tampered when its rows fail.
struct PinnedKey {
    std::string account_public_id;
    uint32_t generation{};
    std::array<uint8_t, 32> x25519_public{};
    std::string fingerprint;
    std::string confirmed_by;
    std::string statement;  // the pinned generation's statement (account::parseStatement: label::seal takes it)
};
[[nodiscard]] std::optional<PinnedKey> pinnedKey();

// Makes vault `vaultId`'s policy grants equal the accepted policy (a vault that just got the account-key grant).
// Best effort: what can't be wrapped yet is written by the next check or sync pass. Never throws.
void applyPolicy(unsigned int vaultId) noexcept;

// What health reports (only once a row exists): cloud_account_key_tampered or cloud_account_key_change_pending.
struct HealthIssue {
    std::string code;
    std::string detail;
};
[[nodiscard]] std::optional<HealthIssue> health();

[[nodiscard]] nlohmann::json toJson(const Status& s);
[[nodiscard]] nlohmann::json toJson(const Generation& g);
[[nodiscard]] nlohmann::json toJson(const Confirmed& c);

}
