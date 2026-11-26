#pragma once

#include "db/query/mirror/Log.hpp"
#include "mirror/apply/Applier.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>

// The server mirror's data plane on the link (design/peers/mirror.md "Following the core", "As built: following the
// core"): peer.mirror.tree, peer.mirror.log and peer.mirror.ack (the core answers its mirror), peer.mirror.notify (the
// core tells its mirror a group was numbered). Peer sessions only, refused while peers.experimental is off
// (protocols::ws::handler::MirrorFollow). The caller must be the vault's linked server with the other role: for
// another server, a vault it is not the linked server of, or no such vault, every message answers exactly as the
// sealed lane does (ops::NotFound "Not found", code not_found), so a peer learns nothing about vaults it is not the
// mirror (or the core) of.
//
// Every answer is bounded by bytes as well as rows: the link's websocket takes messages of at most 1 MiB
// (protocols::ws::Session, kWebSocketReadBufferMaxBytes), so an answer stays under kAnswerBytes. A log page holds whole
// groups only; a single group larger than an answer is served in parts (`part`), which the mirror collects and applies
// as one group.
namespace vh::mirror::follow {

inline constexpr std::size_t kAnswerBytes = 768 * 1024;
inline constexpr std::size_t kTreePageRows = 1'000;
inline constexpr std::size_t kLogPageRows = 2'000;

// Tests: a smaller byte bound (0 restores kAnswerBytes).
void setAnswerBytesForTesting(std::size_t bytes);
[[nodiscard]] std::size_t answerBytes();

// ---- the core: answers to its mirror

// peer.mirror.tree {vault_uid, after}: the baseline's position, digest, entry count and how many entries it serves,
// the vault's document then, and a page of state documents after `after` (ord) in order (a folder before what is under
// it): {baseline: {term, seq}, digest, entries, rows, vault, items: [{ord, state}], more}. {expired: true} once the
// baseline is gone (the mirror acknowledged, or the vault is no longer this server's core).
[[nodiscard]] nlohmann::json serveTree(uint32_t callerPeerId, const nlohmann::json& payload);

// peer.mirror.log {vault_uid, term, seq, part?: {txid, after_seq}}: whole groups after (term, seq), Log::groupsAfter
// pages: {groups: [{term, txid, first_seq, last_seq, rows: [...]}], last: {term, seq}, more}; {expired: true} below
// retention, above what was numbered, or when the vault is no longer this server's core. A first group too large for
// one answer comes as {part: {term, txid, first_seq, last_seq, rows, complete}}, and the next parts are asked with
// `part` (the group's txid and the last seq held).
[[nodiscard]] nlohmann::json serveLog(uint32_t callerPeerId, const nlohmann::json& payload);

// peer.mirror.ack {vault_uid, term, seq, digest, entries}: MirrorVaults::acknowledgeChecked: {known, match, recorded,
// core_digest, core_entries}. A mismatch stops the vault here as diverged and the answer says so (match false).
[[nodiscard]] nlohmann::json serveAck(uint32_t callerPeerId, const nlohmann::json& payload);

// ---- the mirror: the core's notice

// peer.mirror.notify {vault_uid, term, seq}: wakes the follower for the vault ({}).
[[nodiscard]] nlohmann::json receiveNotify(uint32_t callerPeerId, const nlohmann::json& payload);

// ---- the forms on the wire

[[nodiscard]] nlohmann::json toJson(const vh::db::query::mirror::Row& row);
[[nodiscard]] vh::mirror::apply::LogRow rowFromJson(const nlohmann::json& j);
[[nodiscard]] vh::mirror::apply::LogGroup groupFromJson(const nlohmann::json& j);
[[nodiscard]] vh::mirror::apply::TreePage treePageFromJson(const nlohmann::json& j);

}
