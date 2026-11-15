#pragma once

#include "db/query/cloud/AccountKey.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

// The pin of the linked account's recovery key (design/cloud/key-manager.md, "Where the pin lives"): every
// cloud_account_key row (migration 141) carries an HMAC-SHA-256 over all its other columns under a 32-byte key sealed
// to this host like the identity key (crypto::secrets::KeyProvider, slot `cloud_account_pin`; `test_cloud_account_pin`
// in test mode). A database writer can therefore neither swap the pinned key nor lower the policy floor the pinned row
// holds: every wrap to the account key and every policy checks the row first. The slot survives `vh cloud unlink`, so
// a server linked again to the same account follows its old pin; `vh cloud key forget` destroys it.
//
// Residual risk, by design of a MAC without a sealed counter: a writer who saved an earlier copy of a row can put that
// copy back (an older floor, or the pin before a rotation). Both keys involved were confirmed for the account, and a
// later check moves the pin forward again.
namespace vh::cloud::pin {

// The slot exists but no longer unseals (a TPM reset): every row fails, and only `vh cloud key forget` starts over.
class KeyLost : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

using Mac = std::array<uint8_t, 32>;

// The MAC of `row` (its `mac` field ignored). `create`: seal a fresh key when the slot is empty (the first row ever
// stored); otherwise an empty slot throws KeyLost too. The key is unsealed once and kept in locked memory.
[[nodiscard]] Mac macOf(const db::query::cloud::AccountKeyRow& row, bool create = false);
// Whether `row.mac` is its MAC. False for a lost key.
[[nodiscard]] bool verifies(const db::query::cloud::AccountKeyRow& row) noexcept;
// Whether a pin key is sealed on this host.
[[nodiscard]] bool exists();
// Destroys the sealed key and forgets the unsealed copy.
void destroy();

// The rows of an account, each checked. `tampered` names the generations whose MAC failed (or all of them when the key
// is lost); a caller uses nothing of an account with any tampered row.
struct Checked {
    std::vector<db::query::cloud::AccountKeyRow> rows;  // the rows that verify
    std::vector<uint32_t> tampered;
    bool key_lost = false;
    [[nodiscard]] bool ok() const { return tampered.empty() && !key_lost; }
    [[nodiscard]] const db::query::cloud::AccountKeyRow* pinned() const;
    [[nodiscard]] const db::query::cloud::AccountKeyRow* waiting() const;  // pending or refused (the newest)
};
[[nodiscard]] Checked load(const std::string& accountPublicId);
// Every account's rows (health, forget).
[[nodiscard]] Checked loadAll();

// The wrap guards (vault::envelopes::put): whether `x25519` is a MAC-verified pinned key of generation `generation`,
// and whether it is a recipient of the recovery policy a MAC-verified pinned row accepted.
[[nodiscard]] bool isPinnedKey(uint32_t generation, std::span<const uint8_t> x25519);
[[nodiscard]] bool isPolicyRecipient(std::span<const uint8_t> x25519);

}
