#pragma once

#include "crypto/SecretKey.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/RemoteFetch.hpp"
#include "storage/s3/RequestUsage.hpp"
#include "vault/Content.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace vh::storage {

namespace s3 { class Controller; }

// Opt-in (preview.media.remote: ranged) positioned reader over a remote-only object, without keeping a local copy.
// Every read maps to S3 ranged GETs of aligned windows (RangedReadLimits::window_bytes) carrying If-Match with the
// ETag seen at open, so all bytes come from one object version; a changed object fails with IntegrityError. A small
// LRU of ciphertext windows absorbs re-reads. Bytes are CTR-decrypted with the remote IV and the vault key snapshot.
//
// INTEGRITY: for a VHF1 object (spec 02 §3.7) every read is authenticated: the header is fetched and checked against
// the vault, generation and key version when the reader opens, windows are whole chunks, and each chunk's tag (with
// its index and final flag) verifies before any byte of it is returned; a failed chunk is sticky for the reader. No
// GCM CTR keystream is used for it. For a legacy GCM object positioned reads are NOT authenticated (AES-GCM
// authenticates only the whole message): a hostile or corrupt bucket can flip plaintext bits in ranges served that
// way. readAllAuthenticated() fetches the whole object and checks it. Hydrate (the default) authenticates before
// serving.
//
// COST: every GET and byte is metered through s3::Controller::recordRequest (engine-wide budget + this reader's own
// ScopedS3RequestUsageCapture + any outer capture on the calling thread) and capped per reader; past the cap reads
// throw ContentUnavailable. The price reservation taken at open is committed with the actual usage when the reader
// is destroyed.
class RemoteRangedReader final : public PlaintextReader {
public:
    struct Params {
        std::shared_ptr<const CloudEngine> engine;  // owns the controller; target of the usage capture
        std::shared_ptr<s3::Controller> controller;
        std::filesystem::path objectKey;            // S3 key (no leading slash)
        std::string etag;                           // every GET carries If-Match: etag
        uint64_t plaintextSize{};
        crypto::SecretKeyPtr key;                   // null: the remote object is plaintext (encrypt_upstream off)
        std::array<uint8_t, 12> iv{};               // legacy GCM objects
        struct Vhf1Object {
            vault::content::Binding binding;
            uint64_t objectSize{};                  // from the catalog (authenticated), equal to the HEAD's length
        };
        std::optional<Vhf1Object> vhf1;             // set: a VHF1 object, read through authenticated chunks
        Generation generation;
        RangedReadLimits limits;
        std::unique_ptr<RemoteFetchReservation> reservation;
        s3::S3GatewayUpstreamUsage initialUsage;     // what opening cost (the HEAD), part of the committed usage
    };

    explicit RemoteRangedReader(Params params);
    ~RemoteRangedReader() override;

    RemoteRangedReader(const RemoteRangedReader&) = delete;
    RemoteRangedReader& operator=(const RemoteRangedReader&) = delete;

    [[nodiscard]] uint64_t size() const override { return params_.plaintextSize; }
    std::size_t read(uint64_t offset, std::span<uint8_t> out) override;
    [[nodiscard]] const Generation& generation() const override { return params_.generation; }

    // One GET of the whole object (body and tag), authenticated before anything is returned.
    [[nodiscard]] std::vector<uint8_t> readAllAuthenticated(uint64_t maxBytes) override;

    // Upstream usage so far (GETs and bytes, as metered).
    [[nodiscard]] s3::S3GatewayUpstreamUsage usage() const;
    [[nodiscard]] uint64_t maxGetRequests() const { return maxGets_; }
    [[nodiscard]] uint64_t maxDownloadedBytes() const { return maxBytes_; }

    // The caps a reader of this size gets (also what the price preflight reserves).
    [[nodiscard]] static uint64_t defaultMaxGetRequests(uint64_t plaintextSize, const RangedReadLimits& limits);
    [[nodiscard]] static uint64_t defaultMaxDownloadedBytes(uint64_t plaintextSize, const RangedReadLimits& limits);

private:
    struct Window {
        Window() = default;
        Window(Window&&) noexcept = default;
        Window& operator=(Window&&) noexcept = default;
        ~Window();
        uint64_t index{};
        // Legacy GCM: ciphertext; unencrypted: plaintext; VHF1: authenticated plaintext (wiped on eviction).
        std::vector<uint8_t> bytes;
    };

    const Window& window(uint64_t index);
    // One metered, capped, If-Match-bound ranged GET of [first, last] into out (exactly last - first + 1 bytes).
    void fetchRange(uint64_t first, uint64_t last, std::vector<uint8_t>& out);

    // VHF1: the header fetched and authenticated at open, and the chunk reader over it.
    struct Vhf1State;
    std::unique_ptr<Vhf1State> vhf1_;
    [[nodiscard]] uint64_t windowBytes() const;

    Params params_;
    uint64_t maxGets_{};
    uint64_t maxBytes_{};
    mutable std::mutex mutex_;
    std::list<Window> windows_;  // most recently used first
    s3::S3GatewayUpstreamUsage usage_;
};

}
