#pragma once

#include "peer/Fwd.hpp"
#include "protocols/http/Router.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// The sealed lane on the device listener (design/peers/mirror.md "Contents"; peer/ObjectClient.hpp has the address):
// GET (and HEAD) /peer/object/<vault uid>/<object uid>/<generation> serves one file generation's backing bytes exactly
// as they are on disk. Only a Peer session reaches it (the listener hands it nothing else), and only while
// peers.experimental is on; every answer is decided here, per request, before a byte is read:
//
//   404 not_found              the switch is off, no such mirrored vault, the vault's linked server is another one
//                              (whatever role this server has: core or mirror; never orphaned), or no such file there
//   403 peer_revoked           the caller's link was revoked (or its key is no longer the row's) since its handshake
//   410 generation_not_current the file's current generation is another one
//   422 format_not_portable    the generation is legacy gcm0, or plain with bytes (it binds nothing: never sent)
//   404 not_held               the bytes are not on this server's disk (a bucket-only file: hydrating belongs to the
//                              next piece), or what is there is not that generation's length
//   400 invalid, 405           a malformed address, another method
//
// 200 / 206 carry the sealed bytes (application/octet-stream), Content-Length, the generation as the ETag, one range
// over sealed offsets (If-Range on the ETag), Cache-Control: no-store. No plaintext is produced on this path: the bytes
// are read from the descriptor the checks opened and written to the socket as they are.
namespace vh::protocols::device::peer_object {

// "/peer/object/…" (any target the lane would have to answer, malformed ones included).
[[nodiscard]] bool isTarget(std::string_view target) noexcept;

// Answers one request from the linked server `caller`.
[[nodiscard]] http::model::preview::Response serve(const http::request& req, const vh::peer::Principal& caller);

// PUT on the same address (design/peers/mirror.md "A change made on the mirror" step 2): the vault's mirror sends a
// generation's sealed bytes to this server, its core, ahead of the change that commits them. Decided from the header
// first (the switch, the link, the address, this server the vault's core and the caller its mirror, the facts in the
// X-VH-* headers, a Content-Length that is that generation's sealed length): a refusal, or where the body goes. Then
// finishPut verifies what arrived and keeps it staged (mirror::submit::contents::stage): 201 {"staged": true}, or
// 422 invalid_contents, 409 key_version_missing, 404 not_found.
struct PutTarget {
    uint32_t vault_id{};
    std::string object_uuid{};
    std::string generation{};
    uint32_t key_version{};
    uint64_t plaintext_size{};
    std::string content_hash{};
    uint64_t sealed_size{};
    std::string receiving{};   // the file the body is written to
};
struct PutStart {
    std::optional<http::model::preview::Response> refusal{};
    PutTarget target{};
};
[[nodiscard]] PutStart beginPut(const http::request& req, const vh::peer::Principal& caller,
                                std::optional<uint64_t> contentLength);
[[nodiscard]] http::model::preview::Response finishPut(const http::request& req, const PutTarget& target);

// The sealed lane's open connections, per peer, so that unlinking closes them at once (link.md invariant 7) the way it
// closes the link's websocket. A handle unregisters when it goes away.
using Registration = std::shared_ptr<void>;
[[nodiscard]] Registration track(uint32_t peerId, std::function<void()> close);
// Closes every lane connection of `peerId` (LinkService::disconnect). Returns how many.
std::size_t closeConnections(uint32_t peerId);
std::size_t closeAllConnections();

}
