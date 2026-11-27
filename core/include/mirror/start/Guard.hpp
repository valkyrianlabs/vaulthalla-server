#pragma once

#include <cstdint>
#include <optional>
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

// Deleting a mirrored vault in one step, on its core (wave 5; design/peers/mirror.md "Ending a mirror from the core, and
// deleting"): the caller says what happens to the mirror's copy, exactly as mirror.cancel [--remove-copy] (the mirror's
// keep setting still decides on its side), and the deletion then goes the usual way (its retention window included).
enum class MirrorCopy { Remove, Leave };
// "remove" | "leave"; nullopt for none; ops::Invalid for anything else.
[[nodiscard]] std::optional<MirrorCopy> mirrorCopyFrom(const std::optional<std::string>& text);
// Whether deleting the vault must end a mirror first (a `core` row, or a start of it running). On a copy held here
// (mirror, orphaned) it refuses as refuseDeletionIfMirrored does (detach it, or vh mirror cancel an orphaned one); on the
// core with no choice: ops::Refused "mirror_copy_choice_required". A choice for a vault that is not mirrored is ignored.
[[nodiscard]] bool deletionEndsMirror(uint32_t vaultId, const std::optional<MirrorCopy>& choice);
// Ends the mirror for the deletion (cancelOnCore, reason vault_deleted, the mirror told when reachable). Audited
// mirror.cancel with the choice.
void endMirrorForDeletion(uint32_t vaultId, MirrorCopy choice, std::optional<uint32_t> actorId, const std::string& actorName);

// Tests only: lets a rotation through on a mirrored vault (the replication log's own test drives the `key` rows a
// rotation over the link will write). Never set by the daemon.
void allowRotationOnMirroredForTesting(bool allow);

}
