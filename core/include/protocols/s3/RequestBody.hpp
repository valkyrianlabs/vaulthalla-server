#pragma once

#include "protocols/s3/Router.hpp"
#include "fs/PlaintextSource.hpp"

#include <vl/sigv4/streaming.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>

#include <zlib.h>

#include "crypto/util/digest.hpp"

// A streamed S3 gateway request body: the digests the router checks (Content-MD5, x-amz-checksum-*), computed as the
// body is written to its scratch file, and the aws-chunked decoding (vl::sigv4::AwsChunkedDecoder, the one parser for
// signed and unsigned framing). Bodies are staged only as crypto::ScratchFile ciphertext under the process key (#345)
// in requestBodyRoot(), never as plaintext.

namespace vh::protocols::s3 {

// SHA-256, MD5 and CRC32 of a body fed in pieces.
class BodyHash {
public:
    BodyHash();

    void update(const char* data, std::size_t size);

    // The payload (digests; the caller sets `file`) for a body of `size` bytes. Call once.
    [[nodiscard]] Router::BodyPayload finish(uint64_t size, std::map<std::string, std::string> trailers = {});

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

// Decodes an aws-chunked body from `in` into a new scratch file at `decodedPath` and returns its payload (that file,
// digests, trailers). With `chain`, every chunk signature (and with -TRAILER the trailer signature) must verify.
// x-amz-decoded-content-length and x-amz-trailer, when present, must match. Throws S3Error on a framing, length or
// signature failure (nothing about the body may be used then; the scratch file is gone with the exception).
[[nodiscard]] Router::BodyPayload decodeAwsChunkedBody(const fs::PlaintextSource& in,
                                                       const std::filesystem::path& decodedPath,
                                                       const Router::Request& request,
                                                       std::optional<vl::sigv4::ChunkVerifier> chain);

// Where streamed request bodies are staged: <backing>/.s3-request-body (0700).
[[nodiscard]] std::filesystem::path requestBodyRoot();
// Creates requestBodyRoot() (0700) if needed.
void ensureRequestBodyRoot();
// At startup: removes the previous run's scratch bodies (unreadable without its key) and the plaintext spool of
// versions before #345 (<backing>/s3-request-body). Returns how many entries were removed.
std::size_t sweepRequestBodiesAtStartup() noexcept;

}
