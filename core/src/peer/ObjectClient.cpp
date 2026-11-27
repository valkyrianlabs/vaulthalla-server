#include "peer/ObjectClient.hpp"

#include "db/query/peer/Peer.hpp"
#include "device/Crypto.hpp"
#include "peer/Peer.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <vector>

#include <version.h>

namespace vh::peer::object {

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace bhttp = beast::http;
namespace ssl = asio::ssl;
namespace dc = vh::device::crypto;
using tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

constexpr std::size_t kBodyChunk = 256 * 1024;
constexpr std::size_t kErrorBodyLimit = 64 * 1024;

bool isIpLiteral(const std::string& host) {
    boost::system::error_code ec;
    (void)asio::ip::make_address(host, ec);
    return !ec;
}

std::optional<std::string> encode(std::span<const uint8_t> bytes, const int variant) {
    std::string out(sodium_base64_encoded_len(bytes.size(), variant), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), variant);
    out.resize(std::strlen(out.c_str()));
    return out;
}

std::optional<std::vector<uint8_t>> decode(const std::string_view text, const int variant) {
    std::vector<uint8_t> bytes(text.size());
    std::size_t len = 0;
    const char* end = nullptr;
    if (sodium_base642bin(bytes.data(), bytes.size(), text.data(), text.size(), nullptr, &len, &end, variant) != 0 ||
        end != text.data() + text.size())
        return std::nullopt;
    bytes.resize(len);
    return bytes;
}

// "bytes a-b/total": a and total.
std::optional<std::pair<uint64_t, uint64_t>> contentRange(const std::string_view v) {
    constexpr std::string_view unit = "bytes ";
    if (!v.starts_with(unit)) return std::nullopt;
    const auto dash = v.find('-', unit.size());
    const auto slash = v.find('/', unit.size());
    if (dash == std::string_view::npos || slash == std::string_view::npos || dash > slash) return std::nullopt;
    uint64_t first = 0, total = 0;
    const auto a = v.substr(unit.size(), dash - unit.size());
    const auto t = v.substr(slash + 1);
    if (std::from_chars(a.data(), a.data() + a.size(), first).ec != std::errc{} ||
        std::from_chars(t.data(), t.data() + t.size(), total).ec != std::errc{})
        return std::nullopt;
    return std::make_pair(first, total);
}

// One connection's io: every asynchronous step runs on a private io_context, in slices of kCancelSlice, so the caller's
// cancellation and the overall deadline are seen promptly; the stream's own expiry bounds each step's inactivity.
class Connection {
public:
    explicit Connection(const FetchOptions& options) : options_(options), stream_(ioc_, *options.tls) {}

    ~Connection() { close(); }

    beast::ssl_stream<beast::tcp_stream>& stream() { return stream_; }
    tcp::resolver& resolver() { return resolver_; }

    void arm() {
        const auto now = Clock::now();
        auto until = now + options_.ioTimeout;
        if (options_.deadline != Clock::time_point{}) until = std::min(until, options_.deadline);
        beast::get_lowest_layer(stream_).expires_at(until);
    }

    // Runs until `done`; false (the socket closed) when the caller cancelled or the deadline passed first.
    bool drive(const bool& done) {
        while (!done) {
            if (cancelled()) {
                cancelledByCaller_ = true;
                abort();
                return false;
            }
            if (options_.deadline != Clock::time_point{} && Clock::now() >= options_.deadline) {
                abort();
                return false;
            }
            ioc_.restart();
            ioc_.run_for(kCancelSlice);
        }
        return true;
    }

    [[nodiscard]] bool cancelledByCaller() const { return cancelledByCaller_; }
    [[nodiscard]] bool cancelled() const { return options_.cancelled && options_.cancelled(); }

    void close() {
        boost::system::error_code ignored;
        resolver_.cancel();
        auto& socket = beast::get_lowest_layer(stream_).socket();
        if (socket.is_open()) {
            socket.shutdown(tcp::socket::shutdown_both, ignored);
            socket.close(ignored);
        }
    }

private:
    // Closes the socket and lets every pending handler run (with operation_aborted), so nothing outlives this object.
    void abort() {
        close();
        ioc_.restart();
        ioc_.run_for(std::chrono::seconds(1));
    }

    const FetchOptions& options_;
    asio::io_context ioc_;
    beast::ssl_stream<beast::tcp_stream> stream_;
    tcp::resolver resolver_{ioc_};
    bool cancelledByCaller_{false};
};

struct Step {
    bool done{false};
    boost::system::error_code ec{};
};

}

std::optional<std::string> generationToUrl(const std::string_view standardB64) {
    if (standardB64.empty()) return std::string{};
    const auto bytes = decode(standardB64, sodium_base64_VARIANT_ORIGINAL);
    if (!bytes || bytes->empty()) return std::nullopt;
    return encode(*bytes, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

std::optional<std::string> generationFromUrl(const std::string_view urlB64) {
    if (urlB64.empty()) return std::string{};
    const auto bytes = decode(urlB64, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (!bytes || bytes->empty()) return std::nullopt;
    return encode(*bytes, sodium_base64_VARIANT_ORIGINAL);
}

std::string target(const Address& a) {
    const auto gen = generationToUrl(a.generation);
    if (!gen) throw std::invalid_argument("not a generation id");
    return std::string(kPrefix) + vl::keykit::toBase32(a.vault) + "/" + vl::keykit::toBase32(a.object) + "/" + *gen;
}

std::optional<Address> parseTarget(const std::string_view target) {
    if (!target.starts_with(kPrefix)) return std::nullopt;
    const auto rest = target.substr(kPrefix.size());
    const auto first = rest.find('/');
    if (first == std::string_view::npos) return std::nullopt;
    const auto second = rest.find('/', first + 1);
    if (second == std::string_view::npos) return std::nullopt;
    const auto genText = rest.substr(second + 1);
    if (genText.find_first_of("/?#%") != std::string_view::npos) return std::nullopt;
    const auto vault = vl::keykit::fromBase32(rest.substr(0, first));
    const auto object = vl::keykit::fromBase32(rest.substr(first + 1, second - first - 1));
    const auto generation = generationFromUrl(genText);
    if (!vault || !object || !generation) return std::nullopt;
    // One spelling per generation: the canonical unpadded form only.
    if (generationToUrl(*generation) != genText) return std::nullopt;
    return Address{.vault = *vault, .object = *object, .generation = *generation};
}

std::string etagOf(const std::string& generation) {
    const auto url = generationToUrl(generation);
    return "\"" + url.value_or(std::string{}) + "\"";
}

std::string_view toString(const FetchStatus s) {
    switch (s) {
        case FetchStatus::Complete: return "complete";
        case FetchStatus::Interrupted: return "interrupted";
        case FetchStatus::Refused: return "refused";
        case FetchStatus::Unreachable: return "unreachable";
        case FetchStatus::Cancelled: return "cancelled";
    }
    return "unknown";
}

namespace {

// One endpoint: resolved, connected and through a TLS 1.3 handshake with the pinned key (the row's, or the one it
// announced, which becomes the pin as the link does). Ok, or why not: TryNext (another endpoint may answer), StopAll
// (the deadline: no other endpoint is tried), Cancelled.
enum class Dial { Ok, TryNext, StopAll, Cancelled };

Dial dialPinned(Connection& conn, const vh::peer::Endpoint& endpoint, const Record& peer, std::string& why) {
    Step resolved;
    tcp::resolver::results_type results;
    conn.resolver().async_resolve(endpoint.host, std::to_string(endpoint.port),
                                  [&](const boost::system::error_code& ec, tcp::resolver::results_type r) {
                                      resolved.ec = ec;
                                      results = std::move(r);
                                      resolved.done = true;
                                  });
    if (!conn.drive(resolved.done)) {
        if (conn.cancelledByCaller()) return Dial::Cancelled;
        why = "timed out resolving";
        return Dial::StopAll;
    }
    if (resolved.ec) {
        why = "cannot resolve: " + resolved.ec.message();
        return Dial::TryNext;
    }
    Step connected;
    conn.arm();
    beast::get_lowest_layer(conn.stream()).async_connect(results, [&](const boost::system::error_code& ec,
                                                                      const tcp::endpoint&) {
        connected.ec = ec;
        connected.done = true;
    });
    if (!conn.drive(connected.done)) {
        if (conn.cancelledByCaller()) return Dial::Cancelled;
        why = "timed out connecting";
        return Dial::StopAll;
    }
    if (connected.ec) {
        why = "cannot connect: " + connected.ec.message();
        return Dial::TryNext;
    }
    boost::system::error_code ignored;
    beast::get_lowest_layer(conn.stream()).socket().set_option(tcp::no_delay(true), ignored);

    // TLS 1.3 with the pin: the row's key or the one it announced, never the trust store.
    auto& stream = conn.stream();
    if (!isIpLiteral(endpoint.host) && !SSL_set_tlsext_host_name(stream.native_handle(), endpoint.host.c_str())) {
        why = "cannot set the server name";
        return Dial::TryNext;
    }
    stream.set_verify_mode(ssl::verify_peer);
    stream.set_verify_callback([&peer](bool, ssl::verify_context& ctx) {
        X509_STORE_CTX* store = ctx.native_handle();
        if (X509_STORE_CTX_get_error_depth(store) > 0) return true;
        return pinnedKeyOf(peer, X509_STORE_CTX_get_current_cert(store)).has_value();
    });
    Step shaken;
    conn.arm();
    stream.async_handshake(ssl::stream_base::client, [&](const boost::system::error_code& ec) {
        shaken.ec = ec;
        shaken.done = true;
    });
    if (!conn.drive(shaken.done)) {
        if (conn.cancelledByCaller()) return Dial::Cancelled;
        why = "timed out in the TLS handshake";
        return Dial::StopAll;
    }
    if (shaken.ec) {
        why = "TLS handshake failed: " + shaken.ec.message();
        return Dial::TryNext;
    }
    // Whatever the callback saw, the certificate the session ended up with is checked again.
    X509* leaf = SSL_get1_peer_certificate(stream.native_handle());
    const auto key = pinnedKeyOf(peer, leaf);
    X509_free(leaf);
    if (!key) {
        why = "the server's key is not the linked server's";
        return Dial::TryNext;
    }
    if (const auto hex = dc::toHex(key->spkiSha256);
        hex != peer.spki_sha256 && !db::query::peer::Peers::promoteNext(peer.id, hex)) {
        why = "the announced key is no longer this link's";
        return Dial::TryNext;
    }
    return Dial::Ok;
}

}

FetchResult fetch(const Record& peer, const Address& what, const FetchOptions& options, const Sink& sink) {
    FetchResult out;
    if (!options.tls) {
        out.error = "no TLS context";
        return out;
    }
    if (peer.endpoints.empty()) {
        out.error = "no endpoints known for " + peer.name;
        return out;
    }
    const auto path = target(what);
    const auto expectEtag = etagOf(what.generation);
    std::string lastError;

    for (const auto& endpoint : peer.endpoints) {
        Connection conn(options);
        std::string why;
        const auto dialed = dialPinned(conn, endpoint, peer, why);
        if (dialed == Dial::Cancelled) return {.status = FetchStatus::Cancelled, .error = "cancelled"};
        if (dialed != Dial::Ok) {
            lastError = toString(endpoint) + ": " + why;
            if (dialed == Dial::StopAll) break;
            continue;
        }
        auto& stream = conn.stream();
        out.address = toString(endpoint);

        // From here on the server was reached: a failure is an interruption (resume), not an unreachable link.
        bhttp::request<bhttp::empty_body> req{bhttp::verb::get, path, 11};
        req.set(bhttp::field::host, endpoint.host);
        req.set(bhttp::field::user_agent, std::string("vaulthalla-server/") + VH_VERSION);
        req.set(bhttp::field::accept, "application/octet-stream");
        req.set(bhttp::field::connection, "close");
        if (options.offset > 0) {
            req.set(bhttp::field::range, "bytes=" + std::to_string(options.offset) + "-");
            req.set(bhttp::field::if_range, expectEtag);
        }
        Step written;
        conn.arm();
        bhttp::async_write(stream, req, [&](const boost::system::error_code& ec, std::size_t) {
            written.ec = ec;
            written.done = true;
        });
        const auto interrupted = [&](const std::string& why) {
            out.status = conn.cancelledByCaller() ? FetchStatus::Cancelled : FetchStatus::Interrupted;
            out.error = toString(endpoint) + ": " + why;
            return out;
        };
        if (!conn.drive(written.done)) return interrupted(conn.cancelledByCaller() ? "cancelled" : "timed out sending");
        if (written.ec) return interrupted("cannot send the request: " + written.ec.message());

        beast::flat_buffer buffer;
        bhttp::response_parser<bhttp::buffer_body> parser;
        parser.body_limit(boost::none);
        Step header;
        conn.arm();
        bhttp::async_read_header(stream, buffer, parser, [&](const boost::system::error_code& ec, std::size_t) {
            header.ec = ec;
            header.done = true;
        });
        if (!conn.drive(header.done)) return interrupted(conn.cancelledByCaller() ? "cancelled" : "timed out waiting");
        if (header.ec) return interrupted("no answer: " + header.ec.message());

        const auto& res = parser.get();
        out.http_status = res.result_int();
        const auto status = res.result();
        if (status != bhttp::status::ok && status != bhttp::status::partial_content) {
            // A refusal: its JSON body ({"error", "code"}), bounded.
            std::string body;
            std::array<char, 8192> chunk{};
            while (!parser.is_done() && body.size() < kErrorBodyLimit) {
                parser.get().body().data = chunk.data();
                parser.get().body().size = chunk.size();
                Step read;
                conn.arm();
                bhttp::async_read(stream, buffer, parser, [&](const boost::system::error_code& ec, std::size_t) {
                    read.ec = ec;
                    read.done = true;
                });
                if (!conn.drive(read.done)) break;
                body.append(chunk.data(), chunk.size() - parser.get().body().size);
                if (read.ec && read.ec != bhttp::error::need_buffer) break;
            }
            out.status = FetchStatus::Refused;
            try {
                const auto j = nlohmann::json::parse(body);
                out.code = j.value("code", std::string());
                out.error = j.value("error", std::string());
            } catch (const std::exception&) {
            }
            if (out.code.empty()) out.code = "http_" + std::to_string(out.http_status);
            if (out.error.empty()) out.error = fmt::format("HTTP {}", out.http_status);
            return out;
        }
        const auto refuse = [&](const std::string& code, const std::string& why) {
            out.status = FetchStatus::Refused;
            out.code = code;
            out.error = why;
            return out;
        };
        if (std::string(res[bhttp::field::etag]) != expectEtag)
            return refuse("etag_mismatch", "the answer is another generation's");
        uint64_t total = 0;
        if (status == bhttp::status::partial_content) {
            const auto range = contentRange(std::string(res[bhttp::field::content_range]));
            if (!range || range->first != options.offset)
                return refuse("range_mismatch", "the answer does not start where this transfer resumes");
            total = range->second;
        } else {
            if (options.offset > 0) return refuse("range_ignored", "the server sent the whole object to a resume");
            if (!parser.content_length()) return refuse("no_length", "the answer has no length");
            total = *parser.content_length();
        }
        out.total = total;
        if (options.expectedSize && total != *options.expectedSize)
            return refuse("size_mismatch", fmt::format("the server holds {} sealed bytes, {} were expected", total,
                                                       *options.expectedSize));

        // The body, in order, at the sink's pace.
        std::vector<uint8_t> chunk(kBodyChunk);
        while (!parser.is_done()) {
            parser.get().body().data = chunk.data();
            parser.get().body().size = chunk.size();
            Step read;
            conn.arm();
            // Some progress at a time (a TLS record or what is buffered): the sink sees bytes as they come.
            bhttp::async_read_some(stream, buffer, parser, [&](const boost::system::error_code& ec, std::size_t) {
                read.ec = ec;
                read.done = true;
            });
            const bool finished = conn.drive(read.done);
            const auto got = chunk.size() - parser.get().body().size;
            if (got > 0) {
                if (options.offset + out.received + got > total)
                    return refuse("too_long", "the answer is longer than it said");
                sink(std::span<const uint8_t>(chunk.data(), got));
                out.received += got;
            }
            // Asked to stop: at once, not after the next read (a fast link delivers the rest within one slice).
            if (conn.cancelled() && !(finished && parser.is_done())) {
                out.status = FetchStatus::Cancelled;
                out.error = toString(endpoint) + ": cancelled";
                return out;
            }
            if (!finished) return interrupted(conn.cancelledByCaller() ? "cancelled" : "timed out reading");
            if (read.ec == bhttp::error::need_buffer) continue;
            if (read.ec) return interrupted("the transfer broke off: " + read.ec.message());
        }
        if (options.offset + out.received != total) return interrupted("the transfer ended early");
        out.status = FetchStatus::Complete;
        return out;
    }
    out.status = FetchStatus::Unreachable;
    out.error = lastError.empty() ? "no endpoint answered" : lastError;
    return out;
}

FetchResult put(const Record& peer, const Address& what, const PutFacts& facts, const PutOptions& options,
               const std::string& sealedPath) {
    FetchResult out;
    if (!options.tls) {
        out.error = "no TLS context";
        return out;
    }
    if (peer.endpoints.empty()) {
        out.error = "no endpoints known for " + peer.name;
        return out;
    }
    const FetchOptions connection{.tls = options.tls, .deadline = options.deadline, .ioTimeout = options.ioTimeout,
                                  .cancelled = options.cancelled};
    const auto path = target(what);
    std::string lastError;
    for (const auto& endpoint : peer.endpoints) {
        Connection conn(connection);
        std::string why;
        const auto dialed = dialPinned(conn, endpoint, peer, why);
        if (dialed == Dial::Cancelled) return {.status = FetchStatus::Cancelled, .error = "cancelled"};
        if (dialed != Dial::Ok) {
            lastError = toString(endpoint) + ": " + why;
            if (dialed == Dial::StopAll) break;
            continue;
        }
        auto& stream = conn.stream();
        out.address = toString(endpoint);
        const auto interrupted = [&](const std::string& reason) {
            out.status = conn.cancelledByCaller() ? FetchStatus::Cancelled : FetchStatus::Interrupted;
            out.error = toString(endpoint) + ": " + reason;
            return out;
        };

        bhttp::request<bhttp::file_body> req{bhttp::verb::put, path, 11};
        boost::system::error_code openEc;
        req.body().open(sealedPath.c_str(), beast::file_mode::scan, openEc);
        if (openEc) {
            out.status = FetchStatus::Refused;
            out.code = "not_held";
            out.error = "cannot open the sealed bytes: " + openEc.message();
            return out;
        }
        req.set(bhttp::field::host, endpoint.host);
        req.set(bhttp::field::user_agent, std::string("vaulthalla-server/") + VH_VERSION);
        req.set(bhttp::field::content_type, "application/octet-stream");
        req.set(bhttp::field::connection, "close");
        req.set(std::string(kSizeHeader), std::to_string(facts.plaintext_size));
        req.set(std::string(kContentHashHeader), facts.content_hash);
        req.set(std::string(kKeyVersionHeader), std::to_string(facts.key_version));
        req.prepare_payload();

        // The body at the network's pace, each step bounded by the inactivity timeout.
        bhttp::request_serializer<bhttp::file_body> serializer{req};
        while (!serializer.is_done()) {
            Step written;
            conn.arm();
            bhttp::async_write_some(stream, serializer, [&](const boost::system::error_code& ec, std::size_t) {
                written.ec = ec;
                written.done = true;
            });
            if (!conn.drive(written.done)) return interrupted(conn.cancelledByCaller() ? "cancelled" : "timed out sending");
            if (written.ec) return interrupted("the transfer broke off: " + written.ec.message());
        }

        beast::flat_buffer buffer;
        bhttp::response_parser<bhttp::string_body> parser;
        parser.body_limit(kErrorBodyLimit);
        Step answered;
        conn.arm();
        bhttp::async_read(stream, buffer, parser, [&](const boost::system::error_code& ec, std::size_t) {
            answered.ec = ec;
            answered.done = true;
        });
        if (!conn.drive(answered.done)) return interrupted(conn.cancelledByCaller() ? "cancelled" : "timed out waiting");
        if (answered.ec) return interrupted("no answer: " + answered.ec.message());
        const auto& res = parser.get();
        out.http_status = res.result_int();
        if (res.result() == bhttp::status::created || res.result() == bhttp::status::ok) {
            out.status = FetchStatus::Complete;
            out.received = 0;
            return out;
        }
        out.status = FetchStatus::Refused;
        try {
            const auto j = nlohmann::json::parse(res.body());
            out.code = j.value("code", std::string());
            out.error = j.value("error", std::string());
        } catch (const std::exception&) {
        }
        if (out.code.empty()) out.code = "http_" + std::to_string(out.http_status);
        if (out.error.empty()) out.error = fmt::format("HTTP {}", out.http_status);
        return out;
    }
    out.status = FetchStatus::Unreachable;
    out.error = lastError.empty() ? "no endpoint answered" : lastError;
    return out;
}

}
