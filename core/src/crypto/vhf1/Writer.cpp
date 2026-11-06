#include "crypto/vhf1/Writer.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace vh::crypto::vhf1 {

Writer::Writer(const HeaderParams& params, const SecretKey& vaultKey, Sink sink)
    : sink_(std::move(sink)), chunkSize_(chunkSizeOf(params.chunkLog2)),
      pending_(static_cast<std::size_t>(chunkSize_)), sealed_(static_cast<std::size_t>(chunkSize_) + kTagSize) {
    if (!sink_) throw std::invalid_argument("VHF1 writer needs a sink");
    const auto body = encodeHeaderBody(params);
    hash_ = vhf1::headerHash(body);
    auto ks = deriveKeys(vaultKey, params.salt, hash_);
    const auto tag = headerTag(*ks.headerKey, body);
    contentKey_ = std::move(ks.contentKey);

    std::array<uint8_t, kHeaderSize> header{};
    std::ranges::copy(body, header.begin());
    std::ranges::copy(tag, header.begin() + kHeaderBodySize);
    emit(header);
}

Writer::~Writer() = default;

void Writer::ensureUsable() const {
    if (broken_) throw std::logic_error("VHF1 writer failed earlier; restart the sealing with a fresh salt");
    if (finished_) throw std::logic_error("VHF1 writer used after finish()");
}

void Writer::emit(const std::span<const uint8_t> bytes) {
    try {
        sink_(bytes);
    } catch (...) {
        broken_ = true;
        throw;
    }
    objectSize_ += bytes.size();
}

void Writer::sealPending(const bool final) {
    const auto out = std::span<uint8_t>(sealed_).first(pending_.size() + kTagSize);
    try {
        sealChunk(*contentKey_, hash_, nextIndex_, final, pending_.span(), out);
    } catch (...) {
        broken_ = true;
        throw;
    }
    pending_.clear();
    ++nextIndex_;
    emit(out);
}

void Writer::write(std::span<const uint8_t> plaintext) {
    ensureUsable();
    while (!plaintext.empty()) {
        // A full chunk is sealed as non-final only once we know more plaintext follows it.
        if (pending_.size() == chunkSize_) sealPending(false);
        const auto take = std::min<std::size_t>(plaintext.size(), static_cast<std::size_t>(chunkSize_) - pending_.size());
        pending_.append(plaintext.first(take));
        plaintext = plaintext.subspan(take);
        plaintextSize_ += take;
    }
}

void Writer::finish() {
    ensureUsable();
    // The held-back chunk is the last one; for an empty plaintext it is the single empty final chunk.
    sealPending(true);
    finished_ = true;
}

std::vector<uint8_t> seal(const std::span<const uint8_t> plaintext, const HeaderParams& params,
                          const SecretKey& vaultKey) {
    std::vector<uint8_t> out;
    out.reserve(static_cast<std::size_t>(objectSizeFor(plaintext.size(), params.chunkLog2)));
    Writer writer(params, vaultKey, [&out](const std::span<const uint8_t> bytes) {
        out.insert(out.end(), bytes.begin(), bytes.end());
    });
    writer.write(plaintext);
    writer.finish();
    return out;
}

}
