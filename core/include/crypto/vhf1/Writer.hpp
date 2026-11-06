#pragma once

#include "crypto/vhf1/Format.hpp"

#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace vh::crypto::vhf1 {

// Streaming VHF1 writer (spec 02 §3.8). The header (with its tag) goes to the sink first and is never rewritten; the
// chunks follow in index order. The size need not be known: the writer holds back the current chunk until more
// plaintext arrives (it is then sealed with final=0) or finish() seals it with final=1, so the output is byte for
// byte what seal() produces for the same plaintext, whatever the write() split.
//
// One Writer is one sealing: it uses its salt for exactly these chunk indexes. A writer that failed (the sink threw)
// can't continue; a restart is a new Writer with freshSalt() (§3.3 nonce discipline, §4.3).
class Writer {
public:
    using Sink = std::function<void(std::span<const uint8_t> objectBytes)>;

    // Throws std::invalid_argument for params encodeHeaderBody rejects.
    Writer(const HeaderParams& params, const SecretKey& vaultKey, Sink sink);
    ~Writer();
    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;

    void write(std::span<const uint8_t> plaintext);
    void finish();

    [[nodiscard]] const HeaderHash& headerHash() const { return hash_; }
    [[nodiscard]] uint64_t plaintextSize() const { return plaintextSize_; }
    [[nodiscard]] uint64_t objectSize() const { return objectSize_; }  // bytes given to the sink so far
    [[nodiscard]] bool finished() const { return finished_; }

private:
    void emit(std::span<const uint8_t> bytes);
    void sealPending(bool final);
    void ensureUsable() const;

    Sink sink_;
    HeaderHash hash_{};
    SecretKeyPtr contentKey_;
    uint64_t chunkSize_;
    SecureBytes pending_;            // the held-back plaintext chunk
    std::vector<uint8_t> sealed_;    // one sealed chunk (ciphertext: not secret)
    uint64_t nextIndex_{};
    uint64_t plaintextSize_{};
    uint64_t objectSize_{};
    bool finished_{false};
    bool broken_{false};
};

// One-shot sealing of an in-memory plaintext.
[[nodiscard]] std::vector<uint8_t> seal(std::span<const uint8_t> plaintext, const HeaderParams& params,
                                        const SecretKey& vaultKey);

}
