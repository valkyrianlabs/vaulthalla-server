#pragma once

#include "protocols/s3/Router.hpp"

#include <vl/sigv4/streaming.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <map>
#include <optional>
#include <string>

#include <zlib.h>

#include "crypto/util/digest.hpp"

// A streamed S3 gateway request body: the digests the router checks (Content-MD5, x-amz-checksum-*), computed as the
// body is written to its temp file, and the aws-chunked decoding (vl::sigv4::AwsChunkedDecoder, the one parser for
// signed and unsigned framing).

namespace vh::protocols::s3 {

// SHA-256, MD5 and CRC32 of a body fed in pieces.
class BodyHash {
public:
    BodyHash();

    void update(const char* data, std::size_t size);

    // The payload for a body of `size` bytes stored at `path`. Call once.
    [[nodiscard]] Router::BodyPayload finish(const std::filesystem::path& path, uint64_t size,
                                             std::map<std::string, std::string> trailers = {});

private:
    crypto::util::EvpDigest sha_;
    crypto::util::EvpDigest md5_;
    uLong crc_;
};

// True when the body is aws-chunked framed: Content-Encoding names aws-chunked, or x-amz-content-sha256 is a streaming
// mode (STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER], STREAMING-UNSIGNED-PAYLOAD-TRAILER). MinIO's Go client (mc) sends
// signed chunks without Content-Encoding.
[[nodiscard]] bool isAwsChunked(const Router::Request& request);

// True when x-amz-content-sha256 is a signed streaming mode: the chunk signatures must verify before anything acts on
// the body.
[[nodiscard]] bool hasSignedChunks(const Router::Request& request);

// Decodes an aws-chunked body from `in` into `decodedPath` and returns its payload (digests, trailers). With `chain`,
// every chunk signature (and with -TRAILER the trailer signature) must verify. x-amz-decoded-content-length and
// x-amz-trailer, when present, must match. Throws S3Error on a framing, length or signature failure (nothing about
// the body may be used then); the caller removes `decodedPath` either way.
[[nodiscard]] Router::BodyPayload decodeAwsChunkedBody(std::istream& in, const std::filesystem::path& decodedPath,
                                                       const Router::Request& request,
                                                       std::optional<vl::sigv4::ChunkVerifier> chain);

}
