#pragma once

#include "crypto/SecretBytes.hpp"

#include <optional>

// This installation's Vaulthalla Cloud identity: an Ed25519 seed sealed to this host like the other per-node secrets
// (crypto::secrets::KeyProvider, slot `cloud_identity`; `test_cloud_identity` in test mode). It exists only while
// the server is linked or a link is pending: `vh cloud link` creates a fresh one, `vh cloud unlink` destroys it. The
// cloud only ever sees its public key; nothing else is wrapped under it, so losing it only means linking again.
namespace vh::cloud::identity {

// A fresh seed, sealed over any previous one.
[[nodiscard]] crypto::SecretBytes create();
// The sealed seed, or nullopt when there is none (or it no longer unseals, e.g. after a TPM reset).
[[nodiscard]] std::optional<crypto::SecretBytes> load();
// Deletes the sealed seed, if any.
void destroy();

}
