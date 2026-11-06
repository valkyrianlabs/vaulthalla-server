#include "crypto/vhf1/Reader.hpp"

#include <sodium.h>

#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace vh::crypto::vhf1 {

namespace reader_detail {

using WipeObserver = std::function<void(uint64_t, std::span<const uint8_t>)>;

std::mutex& wipeObserverMutex() {
    static std::mutex m;
    return m;
}

WipeObserver& wipeObserver() {
    static WipeObserver observer;
    return observer;
}

void notifyWiped(const uint64_t index, const std::span<const uint8_t> scratch) {
    WipeObserver observer;
    {
        std::scoped_lock lock(wipeObserverMutex());
        observer = wipeObserver();
    }
    if (observer) observer(index, scratch);
}

// Opens chunk `index` into plain; on a tag failure plain is already wiped (openChunk), the observer sees it, and
// the error is returned for the caller to make sticky and throw.
[[nodiscard]] std::optional<Error> openInto(const OpenedHeader& header, const Layout& layout, const uint64_t index,
                                            const std::span<const uint8_t> sealed, const std::span<uint8_t> plain) {
    if (openChunk(header, index, index + 1 == layout.chunkCount, sealed, plain)) return std::nullopt;
    notifyWiped(index, plain);
    return Error(ErrorCode::ChunkAuthFailed, index);
}

[[nodiscard]] Layout rangeLayout(const OpenedHeader& header, const std::optional<uint64_t> authenticatedSize,
                                 const uint64_t providerSize) {
    if (!authenticatedSize) throw Error(ErrorCode::SizeUnknown);
    if (*authenticatedSize != providerSize) throw Error(ErrorCode::SizeMismatch);
    return layoutFor(providerSize, header.params().chunkLog2);
}

}

SecureBytes open(const std::span<const uint8_t> object, const Expectation& expect, const KeyLookup& keys,
                 const std::optional<uint64_t> authenticatedSize) {
    auto header = openHeader(object, expect, keys);
    if (authenticatedSize && *authenticatedSize != object.size()) throw Error(ErrorCode::SizeMismatch);
    ChunkWalker walker(std::move(header), object.size());
    SecureBytes out(static_cast<std::size_t>(walker.layout().plaintextSize));
    walker.update(object.subspan(kHeaderSize),
                  [&out](uint64_t, const std::span<const uint8_t> plain) { out.append(plain); });
    walker.finish();
    return out;
}

ChunkWalker::ChunkWalker(OpenedHeader header, const uint64_t objectSize)
    : header_(std::move(header)), layout_(layoutFor(objectSize, header_.params().chunkLog2)),
      scratch_(static_cast<std::size_t>(header_.chunkSize())) {}

void ChunkWalker::fail(const Error& error) {
    failed_ = error;
    throw error;
}

void ChunkWalker::openOne(const std::span<const uint8_t> sealed, const Sink& sink) {
    const auto plain = scratch_.storage().first(sealed.size() - kTagSize);
    if (auto err = reader_detail::openInto(header_, layout_, next_, sealed, plain)) fail(*err);
    try {
        sink(next_, plain);
    } catch (...) {
        sodium_memzero(plain.data(), plain.size());
        broken_ = true;
        throw;
    }
    sodium_memzero(plain.data(), plain.size());
    ++next_;
}

void ChunkWalker::update(std::span<const uint8_t> sealed, const Sink& sink) {
    if (broken_) throw std::logic_error("VHF1 chunk walker: the sink failed earlier");
    if (failed_) throw *failed_;
    if (finished_) throw std::logic_error("VHF1 chunk walker used after finish()");
    while (!sealed.empty()) {
        if (next_ >= layout_.chunkCount) fail(Error(ErrorCode::SizeMismatch));
        const auto want = static_cast<std::size_t>(chunkSpan(next_, layout_, header_.params().chunkLog2).size());
        if (pending_.empty() && sealed.size() >= want) {
            openOne(sealed.first(want), sink);
            sealed = sealed.subspan(want);
            continue;
        }
        const auto take = std::min(want - pending_.size(), sealed.size());
        pending_.insert(pending_.end(), sealed.begin(), sealed.begin() + static_cast<std::ptrdiff_t>(take));
        sealed = sealed.subspan(take);
        if (pending_.size() == want) {
            openOne(pending_, sink);
            pending_.clear();
        }
    }
}

void ChunkWalker::finish() {
    if (broken_) throw std::logic_error("VHF1 chunk walker: the sink failed earlier");
    if (failed_) throw *failed_;
    if (next_ != layout_.chunkCount) fail(Error(ErrorCode::SizeMismatch));
    finished_ = true;
}

RangeReader::RangeReader(OpenedHeader header, const std::optional<uint64_t> authenticatedSize,
                         const uint64_t providerSize)
    : header_(std::move(header)), layout_(reader_detail::rangeLayout(header_, authenticatedSize, providerSize)),
      scratch_(static_cast<std::size_t>(header_.chunkSize())) {}

RangePlan RangeReader::plan(const uint64_t start, const uint64_t end) const {
    if (start > end || end > layout_.plaintextSize) throw Error(ErrorCode::RangeOutOfBounds);
    RangePlan p{start, end, std::nullopt, std::nullopt, std::nullopt};
    if (start == end) return p;
    const auto c = header_.chunkSize();
    const auto log2 = header_.params().chunkLog2;
    p.chunkFirst = start / c;
    p.chunkLast = (end - 1) / c;
    p.objectRange = ByteSpan{chunkSpan(*p.chunkFirst, layout_, log2).begin, chunkSpan(*p.chunkLast, layout_, log2).end};
    return p;
}

SecureBytes RangeReader::read(const uint64_t start, const uint64_t end, const std::span<const uint8_t> window) {
    if (failed_) throw *failed_;
    const auto p = plan(start, end);
    if (!p.objectRange) {
        if (!window.empty()) throw Error(ErrorCode::SizeMismatch);
        return {};
    }
    if (window.size() != p.objectRange->size()) throw Error(ErrorCode::SizeMismatch);

    const auto c = header_.chunkSize();
    const auto log2 = header_.params().chunkLog2;
    SecureBytes out(static_cast<std::size_t>(end - start));
    for (uint64_t i = *p.chunkFirst; i <= *p.chunkLast; ++i) {
        const auto cs = chunkSpan(i, layout_, log2);
        const auto sealed = window.subspan(static_cast<std::size_t>(cs.begin - p.objectRange->begin),
                                           static_cast<std::size_t>(cs.size()));
        const auto plain = scratch_.storage().first(sealed.size() - kTagSize);
        if (auto err = reader_detail::openInto(header_, layout_, i, sealed, plain)) {
            failed_ = *err;
            throw *failed_;  // `out` (earlier, authentic chunks of this range) is wiped on unwind
        }
        const uint64_t base = i * c;
        const uint64_t from = std::max(start, base) - base;
        const uint64_t to = std::min<uint64_t>(end, base + plain.size()) - base;
        out.append(plain.subspan(static_cast<std::size_t>(from), static_cast<std::size_t>(to - from)));
        sodium_memzero(plain.data(), plain.size());
    }
    return out;
}

SecureBytes RangeReader::read(const uint64_t start, const uint64_t end, const Fetch& fetch) {
    if (failed_) throw *failed_;
    const auto p = plan(start, end);
    if (!p.objectRange) return read(start, end, std::span<const uint8_t>{});
    const auto window = fetch(p.objectRange->begin, p.objectRange->size());
    return read(start, end, std::span<const uint8_t>(window));
}

void setChunkWipeObserverForTesting(std::function<void(uint64_t, std::span<const uint8_t>)> observer) {
    std::scoped_lock lock(reader_detail::wipeObserverMutex());
    reader_detail::wipeObserver() = std::move(observer);
}

}
