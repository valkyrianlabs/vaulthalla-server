#pragma once

#include "db/query/vault/Key.hpp"
#include "peer/Peer.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <span>

// Key rotation on a mirrored vault, run by its core (design/peers/mirror.md "Key rotation", the simple way):
//
//   core                                              mirror
//   prepare_key_rotation: a new version in memory
//   peer.mirror.key: KEV1 to the mirror's wrap key, ─▶ proven against the attestation keys pinned at pairing (as at
//   the core's key check and attestation               the start); held, not current (vault_keys_trashed, origin)
//   (installed) ◀───────────────────────────────────── the answer
//   the rotation commits and re-seals as on any vault; the log carries the key row, then each file's new generation
//   and key version                                 ─▶ the applier makes the version current when the log names it
//                                                      (its key check must be the delivered one's); the re-sealed
//                                                      files are fetched through the contents path (no local re-seal)
//
// Refused before anything is written when the mirror is not live or unreachable, or refuses the key: rotate when the
// link is up, or end the mirror. The outgoing version stays held on both servers (retired keys are never dropped while
// anything references them; the mirror reads a file under the version it was sealed with until its re-sealed bytes
// arrive). A key salvage on a mirrored vault stays refused (mirror/start/Guard.hpp). Key material is never logged,
// audited or put in an error.
namespace vh::mirror::rotate {

using json = nlohmann::json;

inline constexpr std::chrono::seconds kDeliverTimeout{30};

// EncryptionManager::prepare_key_rotation, before the new version is committed: nothing to do for a vault that is not
// mirrored. On a copy held here, or while a start of the vault runs: ops::Refused vault_mirrored / mirror_start_running.
// On the core: delivers `key` as `version` to the mirror and waits for its acknowledgement (ops::Refused
// mirror_not_live, mirror_link_down, mirror_key_refused, key_version_unattested otherwise).
void deliverBeforeRotation(uint32_t vaultId, uint32_t version, std::span<const uint8_t> key,
                           const db::query::vault::Key::Provenance& provenance);

// peer.mirror.key, on the mirror (a linked server's session; the handler checks the switch): the vault this server
// holds as `from`'s mirror, the version proven and held. Answers {vault_uid, version, installed: true}.
[[nodiscard]] json keyReceived(const vh::peer::Record& from, const json& payload);

}
