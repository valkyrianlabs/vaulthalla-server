#include "protocols/s3/Session.hpp"

#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "protocols/s3/Xml.hpp"

#include <algorithm>
#include <array>
#include <boost/system/system_error.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "crypto/util/digest.hpp"
#include <paths.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/time.h>
#include <utility>
#include <vector>
#include <zlib.h>

namespace vh::protocols::s3 {

namespace {
constexpr std::chrono::seconds kS3SocketIdleTimeout{60};
constexpr std::size_t kReadBufferBytes = 64u * 1024u;
constexpr std::size_t kMaxBufferedBodyBytes = 16u * 1024u * 1024u;

std::atomic<uint64_t> g_totalRequests{0};
std::atomic<uint64_t> g_failedRequests{0};

[[nodiscard]] SessionLifetimes& sessionLifetimes() {
    static SessionLifetimes value;
    return value;
}

[[nodiscard]] std::mutex& activeSessionsMutex() {
    static std::mutex value;
    return value;
}

[[nodiscard]] std::vector<std::weak_ptr<Session>>& activeSessions() {
    static std::vector<std::weak_ptr<Session>> value;
    return value;
}

void pruneActiveSessionsLocked() {
    auto& sessions = activeSessions();
    sessions.erase(
        std::remove_if(sessions.begin(), sessions.end(), [](const std::weak_ptr<Session>& session) {
            return session.expired();
        }),
        sessions.end()
    );
}

void registerActiveSession(const std::shared_ptr<Session>& session) {
    std::scoped_lock lock(activeSessionsMutex());
    pruneActiveSessionsLocked();
    activeSessions().push_back(session);
}

void unregisterActiveSession(const Session* session) {
    std::scoped_lock lock(activeSessionsMutex());
    auto& sessions = activeSessions();
    sessions.erase(
        std::remove_if(sessions.begin(), sessions.end(), [session](const std::weak_ptr<Session>& item) {
            const auto locked = item.lock();
            return !locked || locked.get() == session;
        }),
        sessions.end()
    );
}

void setSocketTimeouts(const int fd) noexcept {
    if (fd < 0) return;
    timeval timeout{
        .tv_sec = static_cast<decltype(timeval::tv_sec)>(kS3SocketIdleTimeout.count()),
        .tv_usec = 0
    };
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string headerValue(const http::request_header<>& header, const std::string& name) {
    const auto wanted = lower(name);
    for (const auto& field : header) {
        if (lower(std::string(field.name_string())) == wanted) return std::string(field.value());
    }
    return {};
}

bool shouldStreamBody(const http::request_header<>& header) {
    if (header.method() != http::verb::put) return false;
    if (!headerValue(header, "x-amz-copy-source").empty()) return false;
    const auto transferEncoding = lower(headerValue(header, "transfer-encoding"));
    return header.find(http::field::content_length) != header.end() || transferEncoding.contains("chunked");
}

std::filesystem::path requestBodyTempRoot() {
    return paths::getBackingPath() / "s3-request-body";
}

std::string digestHex(const unsigned char* digest, const std::size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i)
        out << std::setw(2) << static_cast<unsigned>(digest[i]);
    return out.str();
}

std::string sha256Hex(const unsigned char* digest) {
    return digestHex(digest, SHA256_DIGEST_LENGTH);
}

std::string md5Hex(const unsigned char* digest) {
    return digestHex(digest, MD5_DIGEST_LENGTH);
}

std::string sessionMd5Base64(const unsigned char* digest) {
    std::array<unsigned char, EVP_ENCODE_LENGTH(MD5_DIGEST_LENGTH)> encoded{};
    const auto len = EVP_EncodeBlock(encoded.data(), digest, MD5_DIGEST_LENGTH);
    return {reinterpret_cast<char*>(encoded.data()), static_cast<std::size_t>(len)};
}

template <std::size_t N>
std::string digestBase64(const std::array<unsigned char, N>& digest) {
    std::array<unsigned char, EVP_ENCODE_LENGTH(N)> encoded{};
    const auto len = EVP_EncodeBlock(encoded.data(), digest.data(), static_cast<int>(digest.size()));
    return {reinterpret_cast<char*>(encoded.data()), static_cast<std::size_t>(len)};
}

std::string sha256Base64(const unsigned char* digest) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> raw{};
    std::copy_n(digest, raw.size(), raw.begin());
    return digestBase64(raw);
}

std::string crc32Base64(const uint32_t checksum) {
    const std::array<unsigned char, 4> raw{
        static_cast<unsigned char>((checksum >> 24) & 0xff),
        static_cast<unsigned char>((checksum >> 16) & 0xff),
        static_cast<unsigned char>((checksum >> 8) & 0xff),
        static_cast<unsigned char>(checksum & 0xff)
    };
    return digestBase64(raw);
}

struct BodyDigest {
    std::string sha256_hex;
    std::string sha256_base64;
    std::string md5_base64;
    std::string md5_hex;
    std::string crc32_base64;
};

struct BodyHash {
    crypto::util::EvpDigest sha{EVP_sha256()};
    crypto::util::EvpDigest md5{EVP_md5()};
    uLong crc = crc32(0L, Z_NULL, 0);

    void update(const char* data, const std::size_t size) {
        if (size == 0) return;
        sha.update(data, size);
        md5.update(data, size);
        crc = crc32(crc, reinterpret_cast<const Bytef*>(data), static_cast<uInt>(size));
    }

    BodyDigest finish() {
        const auto shaBytes = sha.finish();
        const auto md5Bytes = md5.finish();
        const auto* shaDigest = shaBytes.data();
        const auto* md5Digest = md5Bytes.data();

        return {
            .sha256_hex = sha256Hex(shaDigest),
            .sha256_base64 = sha256Base64(shaDigest),
            .md5_base64 = sessionMd5Base64(md5Digest),
            .md5_hex = md5Hex(md5Digest),
            .crc32_base64 = crc32Base64(static_cast<uint32_t>(crc))
        };
    }
};

Router::BodyPayload makePayload(
    const std::filesystem::path& path,
    const uint64_t size,
    BodyDigest digest,
    std::map<std::string, std::string> trailers = {}) {
    return {
        .temp_file = path,
        .size = size,
        .trailer_headers = std::move(trailers),
        .sha256_hex = std::move(digest.sha256_hex),
        .sha256_base64 = std::move(digest.sha256_base64),
        .md5_base64 = std::move(digest.md5_base64),
        .md5_hex = std::move(digest.md5_hex),
        .crc32_base64 = std::move(digest.crc32_base64)
    };
}

bool hasAwsChunkedEncoding(const Router::Request& request) {
    const auto it = request.find(http::field::content_encoding);
    return it != request.end() && lower(std::string(it->value())).contains("aws-chunked");
}

std::string readCrLfLine(std::ifstream& in) {
    std::string line;
    if (!std::getline(in, line)) throw std::runtime_error("Malformed aws-chunked body");
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

uint64_t parseAwsChunkSize(const std::string& line) {
    const auto semi = line.find(';');
    const auto sizeHex = line.substr(0, semi);
    if (sizeHex.empty()) throw std::runtime_error("Malformed aws-chunked size");
    char* end = nullptr;
    const auto size = std::strtoull(sizeHex.c_str(), &end, 16);
    if (!end || *end != '\0') throw std::runtime_error("Malformed aws-chunked size");
    return static_cast<uint64_t>(size);
}

std::map<std::string, std::string> readAwsChunkTrailers(std::ifstream& in) {
    std::map<std::string, std::string> trailers;
    while (true) {
        auto line = readCrLfLine(in);
        if (line.empty()) break;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        auto name = lower(line.substr(0, colon));
        auto value = line.substr(colon + 1);
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
            value.erase(value.begin());
        trailers[std::move(name)] = std::move(value);
    }
    return trailers;
}

Router::BodyPayload decodeAwsChunkedBody(
    const std::filesystem::path& sourcePath,
    const std::filesystem::path& decodedPath) {
    std::ifstream in(sourcePath, std::ios::binary);
    if (!in) throw std::runtime_error("Unable to open aws-chunked request body");
    std::ofstream out(decodedPath, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Unable to open decoded aws-chunked request body");

    BodyHash hash;
    uint64_t decodedSize = 0;
    std::array<char, kReadBufferBytes> buffer{};
    std::map<std::string, std::string> trailers;

    while (true) {
        const auto line = readCrLfLine(in);
        const auto chunkSize = parseAwsChunkSize(line);
        if (chunkSize == 0) {
            trailers = readAwsChunkTrailers(in);
            break;
        }

        uint64_t remaining = chunkSize;
        while (remaining > 0) {
            const auto toRead = static_cast<std::streamsize>(std::min<uint64_t>(remaining, buffer.size()));
            in.read(buffer.data(), toRead);
            if (in.gcount() != toRead) throw std::runtime_error("Truncated aws-chunked body");
            out.write(buffer.data(), toRead);
            if (!out) throw std::runtime_error("Failed writing decoded aws-chunked body");
            hash.update(buffer.data(), static_cast<std::size_t>(toRead));
            remaining -= static_cast<uint64_t>(toRead);
            decodedSize += static_cast<uint64_t>(toRead);
        }

        char crlf[2]{};
        in.read(crlf, 2);
        if (in.gcount() != 2 || crlf[0] != '\r' || crlf[1] != '\n')
            throw std::runtime_error("Malformed aws-chunked chunk terminator");
    }

    out.close();
    return makePayload(decodedPath, decodedSize, hash.finish(), std::move(trailers));
}
} // namespace

Session::Session(tcp::socket socket) : lifetime_(sessionLifetimes()), socket_(std::move(socket)) {
    buffer_.max_size(64u * 1024u);
    nativeHandle_.store(socket_.native_handle(), std::memory_order_release);
    setSocketTimeouts(nativeHandle_.load(std::memory_order_acquire));
}

std::shared_ptr<Session> Session::open(tcp::socket socket) {
    auto session = std::make_shared<Session>(std::move(socket));
    registerActiveSession(session);
    return session;
}

bool Session::waitUntilNoneAlive(const std::chrono::milliseconds timeout) {
    return sessionLifetimes().waitUntilNoneAlive(timeout);
}

void Session::run() {
    const auto self = shared_from_this();

    while (!stopRequested_.load(std::memory_order_acquire) && readOne()) {}

    close();
    unregisterActiveSession(this);
}

void Session::cancel() noexcept {
    stopRequested_.store(true, std::memory_order_release);
    std::scoped_lock lock(socketMutex_);
    const auto fd = nativeHandle_.load(std::memory_order_acquire);
    if (fd >= 0) (void)::shutdown(fd, SHUT_RDWR);
}

void Session::cancelAllActive() noexcept {
    std::vector<std::shared_ptr<Session>> sessions;
    {
        std::scoped_lock lock(activeSessionsMutex());
        pruneActiveSessionsLocked();
        sessions.reserve(activeSessions().size());
        for (const auto& weak : activeSessions()) {
            if (auto session = weak.lock()) sessions.push_back(std::move(session));
        }
    }

    for (const auto& session : sessions) {
        if (session) session->cancel();
    }
}

Session::Metrics Session::metrics() noexcept {
    return {
        .activeSessions = sessionLifetimes().live(),
        .totalRequests = g_totalRequests.load(std::memory_order_relaxed),
        .failedRequests = g_failedRequests.load(std::memory_order_relaxed)
    };
}

bool Session::readOne() {
    if (stopRequested_.load(std::memory_order_acquire)) return false;

    http::request_parser<http::buffer_body> parser;
    parser.body_limit(static_cast<uint64_t>(config::Registry::get().s3_gateway.max_body_size_bytes));

    beast::error_code ec;
    http::read_header(socket_, buffer_, parser, ec);
    if (ec == http::error::end_of_stream || ec == boost::asio::error::eof) return false;

    if (ec) {
        if (!stopRequested_.load(std::memory_order_acquire)) {
            const auto& header = parser.get();
            log::Registry::runtime()->warn("[S3Gateway] Request read failed: {}", ec.message());
            g_failedRequests.fetch_add(1, std::memory_order_relaxed);
            if (ec == http::error::body_limit)
                return writeReadError(header, http::status::payload_too_large, "EntityTooLarge",
                                      "Request body exceeds configured S3 gateway limit");
        }
        return false;
    }

    try {
        if (shouldStreamBody(parser.get()))
            return handleStreamedRequest(parser);
        return handleBufferedRequest(parser);
    } catch (const boost::system::system_error& e) {
        if (stopRequested_.load(std::memory_order_acquire)) return false;
        log::Registry::runtime()->warn("[S3Gateway] Request handling failed: {}", e.what());
        g_failedRequests.fetch_add(1, std::memory_order_relaxed);
        return false;
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[S3Gateway] Session request failed: {}", e.what());
        g_failedRequests.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
}

Router::Request Session::makeRequestFromParser(
    const http::request_parser<http::buffer_body>& parser,
    std::string body) {
    const auto& src = parser.get();
    Router::Request request{src.method(), src.target(), src.version()};
    for (const auto& field : src)
        request.insert(field.name_string(), field.value());
    request.keep_alive(src.keep_alive());
    request.body() = std::move(body);
    return request;
}

bool Session::handleBufferedRequest(http::request_parser<http::buffer_body>& parser) {
    std::string body;
    std::array<char, kReadBufferBytes> storage{};
    beast::error_code ec;

    while (!parser.is_done() && !stopRequested_.load(std::memory_order_acquire)) {
        parser.get().body().data = storage.data();
        parser.get().body().size = storage.size();
        http::read(socket_, buffer_, parser, ec);

        const auto used = storage.size() - parser.get().body().size;
        if (used > 0) {
            if (body.size() > kMaxBufferedBodyBytes - used) {
                (void)writeReadError(parser.get(), http::status::payload_too_large, "EntityTooLarge",
                                     "Request body is too large for a buffered S3 control request");
                return false;
            }
            body.append(storage.data(), used);
        }

        if (ec == http::error::need_buffer) {
            ec = {};
            continue;
        }
        if (ec) throw boost::system::system_error(ec);
    }

    if (stopRequested_.load(std::memory_order_acquire)) return false;

    auto request = makeRequestFromParser(parser, std::move(body));
    const auto keepAlive = request.keep_alive();
    g_totalRequests.fetch_add(1, std::memory_order_relaxed);

    return writeResponse(router_.route(std::move(request))) && keepAlive;
}

bool Session::handleStreamedRequest(http::request_parser<http::buffer_body>& parser) {
    std::filesystem::create_directories(requestBodyTempRoot());
    const auto tempPath = requestBodyTempRoot() / (boost::uuids::to_string(boost::uuids::random_generator()()) + ".body");

    std::ofstream out(tempPath, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Unable to open S3 request body temp file");

    BodyHash rawHash;
    uint64_t bytes = 0;

    std::array<char, kReadBufferBytes> storage{};
    beast::error_code ec;
    std::optional<std::filesystem::path> decodedPath;

    try {
        while (!parser.is_done() && !stopRequested_.load(std::memory_order_acquire)) {
            parser.get().body().data = storage.data();
            parser.get().body().size = storage.size();
            http::read(socket_, buffer_, parser, ec);

            const auto used = storage.size() - parser.get().body().size;
            if (used > 0) {
                out.write(storage.data(), static_cast<std::streamsize>(used));
                rawHash.update(storage.data(), used);
                bytes += static_cast<uint64_t>(used);
            }

            if (ec == http::error::need_buffer) {
                ec = {};
                continue;
            }
            if (ec) throw boost::system::system_error(ec);
        }

        if (stopRequested_.load(std::memory_order_acquire)) {
            out.close();
            std::filesystem::remove(tempPath);
            return false;
        }

        out.close();

        auto request = makeRequestFromParser(parser);
        const auto keepAlive = request.keep_alive();
        Router::BodyPayload payload;
        if (hasAwsChunkedEncoding(request)) {
            decodedPath = tempPath;
            decodedPath->concat(".decoded");
            payload = decodeAwsChunkedBody(tempPath, *decodedPath);
            const auto expectedDecodedLength = headerValue(parser.get(), "x-amz-decoded-content-length");
            if (!expectedDecodedLength.empty()) {
                try {
                    if (std::stoull(expectedDecodedLength) != payload.size)
                        throw std::runtime_error("Decoded aws-chunked body length mismatch");
                } catch (const std::invalid_argument&) {
                    throw std::runtime_error("Invalid x-amz-decoded-content-length");
                } catch (const std::out_of_range&) {
                    throw std::runtime_error("Invalid x-amz-decoded-content-length");
                }
            }
        } else {
            payload = makePayload(tempPath, bytes, rawHash.finish());
        }

        g_totalRequests.fetch_add(1, std::memory_order_relaxed);
        const auto wrote = writeResponse(router_.route(std::move(request), std::move(payload)));
        std::filesystem::remove(tempPath);
        if (decodedPath) std::filesystem::remove(*decodedPath);
        return wrote && keepAlive;
    } catch (...) {
        out.close();
        std::filesystem::remove(tempPath);
        if (decodedPath) std::filesystem::remove(*decodedPath);
        throw;
    }
}

bool Session::writeResponse(Router::Response&& response) {
    if (stopRequested_.load(std::memory_order_acquire)) return false;

    beast::error_code ec;
    http::write(socket_, response, ec);
    if (ec) {
        if (!stopRequested_.load(std::memory_order_acquire))
            log::Registry::runtime()->warn("[S3Gateway] Response write failed: {}", ec.message());
        return false;
    }

    if (static_cast<unsigned>(response.result_int()) >= 400)
        g_failedRequests.fetch_add(1, std::memory_order_relaxed);

    return true;
}

bool Session::writeReadError(const http::request_header<>& header, const http::status status,
                             const std::string& code, const std::string& message) {
    Router::Request request{header.method(), header.target(), header.version()};
    request.keep_alive(false);
    Router::Response response{status, header.version()};
    response.set(http::field::server, "VaulthallaS3Gateway");
    response.set(http::field::content_type, "application/xml");
    response.set(http::field::cache_control, Router::kCacheControl);
    response.body() = xml::error(code, message, std::string(header.target()), "");
    response.keep_alive(false);
    response.prepare_payload();
    return writeResponse(std::move(response));
}

void Session::close() noexcept {
    stopRequested_.store(true, std::memory_order_release);
    std::scoped_lock lock(socketMutex_);
    nativeHandle_.store(-1, std::memory_order_release);
    beast::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_both, ec);
    ec.clear();
    socket_.close(ec);
}

} // namespace vh::protocols::s3
