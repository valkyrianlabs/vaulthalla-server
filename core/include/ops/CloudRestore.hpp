#pragma once

#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"

#include <nlohmann/json.hpp>
#include <vl/keykit/kit.hpp>

#include <ctime>
#include <optional>
#include <string>

// The receiving side of a Vaulthalla Cloud restore (`vh vault recover --from-cloud`; Tier B, spec 05 §3.2; the
// cloud's docs/design/recovery-restore.md). This server, linked to the vault's account, asks the cloud to restore a
// vault with a temporary X25519 key whose secret stays in this process's memory; the account owner approves on
// vaulthalla.cloud; a device that holds one of the vault's recovery recipients (Vaulthalla Desktop) compares the
// restore code and re-wraps the key versions to the temporary key. The delivered keys become a key export (the shape
// `vh vault keys export` writes) that `vault_recover` proves and imports like any other: every version must verify
// against the bucket's own manifest records and the origin node's attestation, so keys the cloud (or anyone) made up
// are refused, never stored.
namespace vh::ops::cloud_restore {

using Channel = vault_keys::Channel;

struct Started {
    std::string restore_id;
    std::string restore_code;  // xxxx-xxxx-xxxx-xxxx: what the delivering device must show too
    std::time_t expires_at = 0;
};
// The encryption-key Export permission (as `vh vault recover`), the local CLI or a paired device, a linked server.
Started start(const Actor& actor, const std::string& vaultUid, Channel channel);

struct Delivered {
    nlohmann::json exported;   // a key export document; holds key bytes (base64): the caller wipes it
    // The manifest checkpoint the cloud recorded at enrollment (the vault's own node uploaded it): the restore's
    // rollback bound. nullopt when the vault was enrolled without one.
    std::optional<vl::keykit::KitCheckpoint> checkpoint;
    std::string deliverer;     // the delivering device's name
    unsigned int versions = 0;
};
// nullopt while the restore waits for approval or delivery. Refused("cloud_restore_<status>") once it was denied,
// cancelled or expired (its temporary key is then discarded).
std::optional<Delivered> poll(const Actor& actor, const std::string& restoreId);

// Tells the cloud the keys were imported (it deletes the bundle) and discards the temporary key.
void complete(const Actor& actor, const std::string& restoreId);
// Cancels it (best effort) and discards the temporary key. Never throws.
void cancel(const Actor& actor, const std::string& restoreId) noexcept;

}
