#pragma once

#include <cstdint>
#include <string>

// Key rotation on a mirrored vault (design/peers/mirror.md "Key rotation"): refused on both servers, with its own
// reason, until rotation over the link is built. A new key version on the core would seal files the mirror has no key
// for; on the mirror, keys are the core's. Every path that mints a key version asks here: `vh vault keys rotate`
// (EncryptionManager::prepare_key_rotation, also the attach-remote's rotation and an import's salvage) and
// EncryptionManager::mintSalvageKey.
namespace vh::mirror::start {

// The vault is mirrored here (any role: core, mirror, orphaned) or a start of it is running on this server.
[[nodiscard]] bool mirroredOrStarting(uint32_t vaultId);
// ops::Refused("vault_mirrored") naming `what` when mirroredOrStarting.
void refuseIfMirrored(uint32_t vaultId, const std::string& what);

// Tests only: lets a rotation through on a mirrored vault (the replication log's own test drives the `key` rows a
// rotation over the link will write). Never set by the daemon.
void allowRotationOnMirroredForTesting(bool allow);

}
