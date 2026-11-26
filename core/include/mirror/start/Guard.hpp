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

// Deleting a mirrored vault is refused until its mirror is ended (owner, 2026-11-26; mirror.md "Ending a mirror"), at
// every entry point that deletes, schedules or purges a vault (ops::vaults::remove, the S3 gateway's DeleteBucket):
// ops::Refused "vault_mirrored" on the core (or while a start runs: end the mirror first, vh mirror cancel <id>
// [--remove-copy]) and on a mirror (another server's vault); "vault_orphaned_copy" for an orphaned copy, which is
// removed only through vh mirror cancel <id> (one way, so the step-up and the audit line are always the same).
void refuseDeletionIfMirrored(uint32_t vaultId);

// Tests only: lets a rotation through on a mirrored vault (the replication log's own test drives the `key` rows a
// rotation over the link will write). Never set by the daemon.
void allowRotationOnMirroredForTesting(bool allow);

}
