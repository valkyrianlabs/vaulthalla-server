#include "protocols/s3/RequestBody.hpp"

#include "protocols/s3/Auth.hpp"
#include "protocols/s3/Error.hpp"
#include "crypto/ScratchFile.hpp"
#include "log/Registry.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <iomanip>
#include <openssl/evp.h>
#include <paths.h>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace vh::protocols::s3 {

namespace {

std::string bodyDigestHex(const std::vector<unsigned char>& digest) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : digest) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

std::string bodyDigestBase64(const unsigned char* digest, const std::size_t size) {
    std::vector<unsigned char> encoded(4 * ((size + 2) / 3) + 1);
    const auto len = EVP_EncodeBlock(encoded.data(), digest, static_cast<int>(size));
    return {reinterpret_cast<const char*>(encoded.data()), static_cast<std::size_t>(len)};
}

std::string bodyCrc32Base64(const uint32_t checksum) {
    const std::array<unsigned char, 4> raw{
        static_cast<unsigned char>((checksum >> 24) & 0xff),
        static_cast<unsigned char>((checksum >> 16) & 0xff),
        static_cast<unsigned char>((checksum >> 8) & 0xff),
        static_cast<unsigned char>(checksum & 0xff)
    };
    return bodyDigestBase64(raw.data(), raw.size());
}

std::string requestHeader(const Router::Request& request, const std::string_view name) {
    const auto it = request.find(name);
    return it == request.end() ? std::string{} : std::string(it->value());
}

vl::sigv4::PayloadMode requestPayloadMode(const Router::Request& request) {
    return vl::sigv4::payloadMode(requestHeader(request, "x-amz-content-sha256"));
}

std::optional<uint64_t> decodedContentLength(const Router::Request& request) {
    const auto it = request.find("x-amz-decoded-content-length");
    if (it == request.end()) return std::nullopt;
    const std::string_view value = it->value();
    uint64_t length = 0;
    const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), length);
    if (value.empty() || ec != std::errc{} || end != value.data() + value.size())
        throw invalidArgument("Invalid x-amz-decoded-content-length", std::string(request.target()));
    return length;
}

S3Error chunkedBodyError(const vl::sigv4::Error& error, const Router::Request& request) {
    return sigv4Error(error.code, false, error.message, std::string(request.target()));
}

}

BodyHash::BodyHash() : sha_(EVP_sha256()), md5_(EVP_md5()), crc_(crc32(0L, Z_NULL, 0)) {}

void BodyHash::update(const char* data, const std::size_t size) {
    if (size == 0) return;
    sha_.update(data, size);
    md5_.update(data, size);
    crc_ = crc32(crc_, reinterpret_cast<const Bytef*>(data), static_cast<uInt>(size));
}

Router::BodyPayload BodyHash::finish(const uint64_t size, std::map<std::string, std::string> trailers) {
    const auto sha = sha_.finish();
    const auto md5 = md5_.finish();
    return {
        .file = nullptr,
        .size = size,
        .trailer_headers = std::move(trailers),
        .sha256_hex = bodyDigestHex(sha),
        .sha256_base64 = bodyDigestBase64(sha.data(), sha.size()),
        .md5_base64 = bodyDigestBase64(md5.data(), md5.size()),
        .md5_hex = bodyDigestHex(md5),
        .crc32_base64 = bodyCrc32Base64(static_cast<uint32_t>(crc_)),
        .aws_chunked_decode_to = std::nullopt
    };
}

bool isAwsChunked(const Router::Request& request) {
    auto encoding = requestHeader(request, "content-encoding");
    std::ranges::transform(encoding, encoding.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (encoding.contains("aws-chunked")) return true;
    switch (requestPayloadMode(request)) {
        case vl::sigv4::PayloadMode::StreamingSigned:
        case vl::sigv4::PayloadMode::StreamingSignedTrailer:
        case vl::sigv4::PayloadMode::StreamingUnsignedTrailer: return true;
        case vl::sigv4::PayloadMode::Hashed:
        case vl::sigv4::PayloadMode::Unsigned:
        case vl::sigv4::PayloadMode::Unsupported: return false;
    }
    return false;
}

bool hasSignedChunks(const Router::Request& request) {
    const auto mode = requestPayloadMode(request);
    return mode == vl::sigv4::PayloadMode::StreamingSigned || mode == vl::sigv4::PayloadMode::StreamingSignedTrailer;
}

Router::BodyPayload decodeAwsChunkedBody(const fs::PlaintextSource& in, const std::filesystem::path& decodedPath,
                                         const Router::Request& request,
                                         std::optional<vl::sigv4::ChunkVerifier> chain) {
    vl::sigv4::ChunkedDecoderOptions options;
    options.decoded_length = decodedContentLength(request);
    if (const auto trailer = request.find("x-amz-trailer"); trailer != request.end())
        options.declared_trailers = vl::sigv4::parseTrailerNames(trailer->value());
    auto decoder = chain ? vl::sigv4::AwsChunkedDecoder(std::move(*chain), std::move(options))
                         : vl::sigv4::AwsChunkedDecoder(std::move(options));

    // Decoded data reaches the scratch file (ciphertext) before its chunk's signature is checked; nothing reads it
    // unless finish() succeeds, and an exception takes the file with it.
    auto out = std::make_shared<crypto::ScratchFile>(decodedPath);
    BodyHash hash;
    const vl::sigv4::AwsChunkedDecoder::Sink sink = [&](const std::string_view data) {
        out->append({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
        hash.update(data.data(), data.size());
    };

    fs::forEachChunk(in, [&](const std::span<const uint8_t> chunk) {
        if (const auto fed = decoder.feed(std::string_view(reinterpret_cast<const char*>(chunk.data()), chunk.size()),
                                          sink);
            !fed)
            throw chunkedBodyError(fed.error(), request);
    });
    if (const auto finished = decoder.finish(); !finished) throw chunkedBodyError(finished.error(), request);
    out->flush();

    std::map<std::string, std::string> trailers;
    for (const auto& [name, value] : decoder.trailers()) trailers[name] = value;
    auto payload = hash.finish(decoder.decodedLength(), std::move(trailers));
    payload.file = std::move(out);
    return payload;
}

std::filesystem::path requestBodyRoot() {
    return paths::getBackingPath() / ".s3-request-body";
}

void ensureRequestBodyRoot() {
    const auto root = requestBodyRoot();
    std::filesystem::create_directories(root);
    std::filesystem::permissions(root, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
}

std::size_t sweepRequestBodiesAtStartup() noexcept {
    std::size_t removed = 0;
    // The plaintext spool of versions before #345, then the previous run's ciphertext (its key died with it).
    for (const auto& dir : {paths::getBackingPath() / "s3-request-body", requestBodyRoot()}) {
        std::error_code ec;
        const auto n = std::filesystem::remove_all(dir, ec);
        if (ec) {
            log::Registry::runtime()->warn("[S3Gateway] Could not clear request body staging {}: {}", dir.string(),
                                           ec.message());
            continue;
        }
        if (n > 1)  // the directory itself counts once
            log::Registry::runtime()->info("[S3Gateway] Removed {} unfinished request bodies left in {}", n - 1,
                                           dir.string());
        if (n > 0) removed += n - 1;
    }
    return removed;
}

}
