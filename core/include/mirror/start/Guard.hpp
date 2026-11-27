#pragma once

#include <cstdint>
#include <optional>
#include <string>

// A new key version on a mirrored vault (design/peers/mirror.md "Key rotation"). A rotation runs on the core and goes
// over the link first (mirror/rotate/Rotate.hpp, from EncryptionManager::prepare_key_rotation); on a copy held here it
// is refused (its keys are its core's). A key salvage on a mirrored vault stays refused on both servers: every path
// that mints a salvage version asks here (ops::vault_keys' salvage, EncryptionManager::mintSalvageKey).
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
// keep setting still decides on its side); the deletion goes the usual way, its retention window included, and the
// mirror ends with that choice when the vault is purged.
enum class MirrorCopy { Remove, Leave };
// "remove" | "leave"; nullopt for none; ops::Invalid for anything else.
[[nodiscard]] std::optional<MirrorCopy> mirrorCopyFrom(const std::optional<std::string>& text);
// Whether deleting the vault must end a mirror first (a `core` row, or a start of it running). On a copy held here
// (mirror, orphaned) it refuses as refuseDeletionIfMirrored does (detach it, or vh mirror cancel an orphaned one); on the
// core with no choice: ops::Refused "mirror_copy_choice_required". A choice for a vault that is not mirrored is ignored.
[[nodiscard]] bool deletionEndsMirror(uint32_t vaultId, const std::optional<MirrorCopy>& choice);
// A copy held here (mirror, orphaned) is never deleted as a vault: ops::Refused vault_mirrored / vault_orphaned_copy
// naming detach and vh mirror cancel. The deletion itself never ends the mirror: its purge does, with the choice
// recorded at the schedule (mirror::leave::endForPurge), so a restore within the window keeps the mirror.
void refuseDeletingAHeldCopy(uint32_t vaultId);

// Tests only: lets a rotation or salvage through on a mirrored core without the link (the replication log's own test
// drives the `key` rows a rotation writes). Never set by the daemon.
void allowRotationOnMirroredForTesting(bool allow);
[[nodiscard]] bool rotationAllowedForTesting();

}
