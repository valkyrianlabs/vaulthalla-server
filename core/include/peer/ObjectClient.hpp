#pragma once

#include "crypto/id/ObjectUid.hpp"
#include "peer/Fwd.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace boost::asio::ssl { class context; }

// The sealed lane (design/peers/mirror.md "Contents"): one file generation's sealed bytes, exactly as they sit on the
// serving server's disk, fetched from a linked server's device listener over a separate connection with the link's
// pins. The address names the content by permanent ids:
//
//   GET /peer/object/<vault uid>/<object uid>/<generation>
//
// the uids in their text form (lower-case Crockford base32, vl::keykit), the generation as the unpadded base64url of
// its bytes (files.encryption_iv decoded; "" for an empty plain file). The answer carries the sealed length, the
// generation as the entity tag ("<base64url>", quoted) and one byte range over sealed offsets (206), so an interrupted
// transfer resumes where it stopped. The serving half is protocols::device::peer_object.
namespace vh::peer::object {

inline constexpr std::string_view kPrefix = "/peer/object/";

struct Address {
    vh::crypto::id::ObjectUid vault{};
    vh::crypto::id::ObjectUid object{};
    std::string generation{};  // files.encryption_iv form (standard base64)
};

// files.encryption_iv (standard base64) <-> the address's form (unpadded base64url). nullopt for anything that is not
// base64 of some bytes.
[[nodiscard]] std::optional<std::string> generationToUrl(std::string_view standardB64);
[[nodiscard]] std::optional<std::string> generationFromUrl(std::string_view urlB64);

[[nodiscard]] std::string target(const Address& a);
// The address a request target names; nullopt when it is not exactly kPrefix + three segments (no query).
[[nodiscard]] std::optional<Address> parseTarget(std::string_view target);
// The entity tag of a generation: the quoted address form.
[[nodiscard]] std::string etagOf(const std::string& generation);

enum class FetchStatus {
    Complete,     // every byte from the offset to the end went to the sink
    Interrupted,  // the server was reached and the transfer broke off: resume from offset + received
    Refused,      // the server answered and will not serve it (http_status, code): not worth repeating at once
    Unreachable,  // no endpoint answered with the pinned key: the link is down for this purpose
    Cancelled,    // stopped by the caller (or the service stopping)
};

struct FetchOptions {
    // protocols::device::makeClientContext for this server's identity (peer::LinkService::clientTls()).
    std::shared_ptr<boost::asio::ssl::context> tls{};
    uint64_t offset{0};                      // bytes already held: asked for as Range: bytes=<offset>-
    std::optional<uint64_t> expectedSize{};  // the sealed length expected; another answer is refused before the body
    std::chrono::steady_clock::time_point deadline{};   // the whole call
    std::chrono::milliseconds ioTimeout{std::chrono::seconds(30)};  // any one step without progress
    // Polled every kCancelSlice; true stops the transfer (the socket is closed).
    std::function<bool()> cancelled{};
};

// How often a transfer looks at its cancellation and deadline while it waits on the network.
inline constexpr std::chrono::milliseconds kCancelSlice{200};

struct FetchResult {
    FetchStatus status{FetchStatus::Unreachable};
    uint64_t received{0};       // bytes this call passed to the sink
    uint64_t total{0};          // the sealed length the server announced (0 before an answer)
    unsigned http_status{0};
    std::string code{};         // the refusal's code (the lane's JSON body), or a client-side one
    std::string error{};        // for logs and status: what failed, never a secret
    std::string address{};      // the endpoint that answered
};

using Sink = std::function<void(std::span<const uint8_t>)>;

// One attempt: tries the row's endpoints in order (last good first) until one completes a TLS 1.3 handshake with the
// pinned key (pinnedKeyOf; an announced next key in use becomes the pin, as the link does), then GETs `what` from
// `options.offset` and streams the body into `sink` in order, at the pace the sink takes it. A sink that throws ends
// the attempt and the exception propagates (the connection is closed first). Never blocks past the deadline by more
// than one kCancelSlice.
[[nodiscard]] FetchResult fetch(const Record& peer, const Address& what, const FetchOptions& options, const Sink& sink);

[[nodiscard]] std::string_view toString(FetchStatus s);

}
