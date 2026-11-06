#pragma once

#include "crypto/SecretKey.hpp"
#include "crypto/vhf1/Format.hpp"
#include "vault/Content.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <sodium.h>

// VHF1 sealing of a file whose size is known up front but whose plaintext arrives as a growing contiguous prefix,
// possibly across process restarts: the resumable upload sealing cursor (#367, design/encryption/02 §4 "Resumable
// upload part retried with different bytes", docs/reference/transfer-protocol.md §3.5).
//
//   - Whole chunks are sealed as soon as they are complete (the last one, final=1, when the whole size is in); the
//     partial chunk at the end of the prefix is held back in locked-down memory, never on disk.
//   - The object is written at its final offsets through a caller-owned descriptor; the caller fsyncs and records
//     sealed() as the durable prefix.
//   - A restart rebuilds the sealing by authenticating the durable prefix (header against the binding, every chunk
//     with its index and final flag), never by encrypting again.
//   - It never seals an index twice under one salt with different bytes: feed() compares bytes below fed() with what
//     was sealed or held back for them and answers Diverged without changing anything; a resume that finds bytes past
//     the durable prefix (a crash between writing and recording) reports tail(). Both cases are the caller's cue to
//     continue under a new salt with resealed(): the authenticated plaintext kept so far goes into a fresh sealing.
namespace vh::vault::content {

// Authenticated plaintext reads out of a VHF1 file that may still be growing (its sealed prefix): whole chunks are
// authenticated before a byte of them is used. Not thread-safe.
class PrefixReader {
public:
    // Reads and authenticates the header (storage::IntegrityError on any mismatch with binding).
    PrefixReader(int fd, const Binding& binding, const crypto::SecretKeyPtr& key, uint64_t plaintextSize);
    ~PrefixReader();
    PrefixReader(const PrefixReader&) = delete;
    PrefixReader& operator=(const PrefixReader&) = delete;

    // Plaintext [offset, offset + out.size()); storage::IntegrityError when a chunk it needs is missing or fails.
    void read(uint64_t offset, std::span<uint8_t> out);

    [[nodiscard]] const crypto::vhf1::OpenedHeader& header() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class PrefixSealer {
public:
    struct Params {
        int fd{-1};                    // read/write; owned by the caller
        Binding binding;               // generation: the sealing's salt; objectUid: required by begin()
        crypto::SecretKeyPtr key;      // the vault key of binding.keyVersion
        uint64_t plaintextSize{};      // > 0 (an empty file is not sealed)
    };

    enum class Fed { Ok, Diverged };

    // A new sealing: the descriptor is truncated and the header written.
    [[nodiscard]] static std::unique_ptr<PrefixSealer> begin(const Params& params);
    // The sealing on the descriptor, resumed at `durable` plaintext bytes (a multiple of the chunk size, or the whole
    // size): the header and those chunks are authenticated (storage::IntegrityError otherwise). With durable == 0 an
    // empty descriptor is a fresh start; anything on it is a tail().
    [[nodiscard]] static std::unique_ptr<PrefixSealer> resume(const Params& params, uint64_t durable);

    ~PrefixSealer();
    PrefixSealer(const PrefixSealer&) = delete;
    PrefixSealer& operator=(const PrefixSealer&) = delete;

    // A fresh sealing (new salt) on newFd holding this sealing's authenticated plaintext [0, keep), keep <= fed().
    [[nodiscard]] std::unique_ptr<PrefixSealer> resealed(int newFd, uint64_t keep);

    // Plaintext at `offset` (<= fed()). Bytes below fed() must equal what was sealed or held back for them, else
    // Diverged and nothing changes; the rest extends the prefix, sealing every chunk it completes.
    [[nodiscard]] Fed feed(uint64_t offset, std::span<const uint8_t> plaintext);

    [[nodiscard]] uint64_t fed() const { return fed_; }
    [[nodiscard]] uint64_t sealed() const { return sealed_; }        // plaintext in sealed chunks on the descriptor
    [[nodiscard]] uint64_t sealedObjectBytes() const;                // object bytes those chunks (and the header) take
    [[nodiscard]] bool complete() const { return sealed_ == size_; }
    [[nodiscard]] bool tail() const { return tail_; }
    [[nodiscard]] uint64_t size() const { return size_; }
    [[nodiscard]] const std::string& generation() const { return binding_.generation; }
    [[nodiscard]] const crypto::id::ObjectUid& objectUid() const;
    // complete() only: BLAKE2b of the whole object, hex (what files.content_hash holds).
    [[nodiscard]] std::string contentHash() const;

private:
    PrefixSealer() = default;
    void sealPending();
    void hashUpdate(std::span<const uint8_t> bytes);
    [[nodiscard]] uint64_t chunkLength(uint64_t index) const;
    [[nodiscard]] uint64_t chunkOffset(uint64_t index) const;

    int fd_{-1};
    Binding binding_;
    crypto::SecretKeyPtr key_;
    std::optional<crypto::vhf1::OpenedHeader> header_;
    std::unique_ptr<PrefixReader> reader_;    // authenticated reads of what is sealed (divergence checks, resealed())
    uint64_t size_{};
    uint64_t chunkSize_{};
    uint64_t fed_{};
    uint64_t sealed_{};
    bool tail_{false};
    crypto::vhf1::SecureBytes pending_;       // plaintext of the chunk being filled
    std::vector<uint8_t> out_;                // one sealed chunk (ciphertext)
    crypto_generichash_state hash_{};
};

}
