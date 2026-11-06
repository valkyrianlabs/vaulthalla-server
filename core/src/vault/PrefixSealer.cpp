#include "vault/PrefixSealer.hpp"

#include "crypto/vhf1/Reader.hpp"
#include "storage/PlaintextReader.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace vh::vault::content {

namespace prefix_detail {

std::size_t preadSome(const int fd, std::span<uint8_t> out, const uint64_t offset) {
    std::size_t done = 0;
    while (done < out.size()) {
        const auto got = ::pread(fd, out.data() + done, out.size() - done, static_cast<off_t>(offset + done));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "reading a sealed prefix");
        }
        if (got == 0) break;
        done += static_cast<std::size_t>(got);
    }
    return done;
}

void pwriteAll(const int fd, std::span<const uint8_t> bytes, uint64_t offset) {
    while (!bytes.empty()) {
        const auto n = ::pwrite(fd, bytes.data(), bytes.size(), static_cast<off_t>(offset));
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "writing a sealed chunk");
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
        offset += static_cast<uint64_t>(n);
    }
}

uint64_t fdSize(const int fd) {
    struct stat st{};
    if (::fstat(fd, &st) != 0) throw std::system_error(errno, std::generic_category(), "stat a sealed prefix");
    return static_cast<uint64_t>(st.st_size);
}

crypto::vhf1::OpenedHeader readHeader(const int fd, const Binding& binding, const crypto::SecretKeyPtr& key) {
    std::array<uint8_t, crypto::vhf1::kHeaderSize> header{};
    if (preadSome(fd, header, 0) != header.size()) throw storage::IntegrityError("The sealed prefix has no header");
    return openHeader(header, binding, key);
}

}

// ---- PrefixReader ----------------------------------------------------------------------------------------------------

struct PrefixReader::Impl {
    int fd{-1};
    std::optional<crypto::vhf1::RangeReader> range;
    std::optional<uint64_t> cachedIndex;
    crypto::vhf1::SecureBytes cached;
    std::vector<uint8_t> window;
    uint64_t size{};
};

PrefixReader::PrefixReader(const int fd, const Binding& binding, const crypto::SecretKeyPtr& key,
                           const uint64_t plaintextSize)
    : impl_(std::make_unique<Impl>()) {
    impl_->fd = fd;
    impl_->size = plaintextSize;
    auto opened = prefix_detail::readHeader(fd, binding, key);
    // The layout of the whole object: chunk positions and final flags don't depend on how much is on disk yet.
    const auto objectSize = crypto::vhf1::objectSizeFor(plaintextSize, opened.params().chunkLog2);
    impl_->range.emplace(std::move(opened), objectSize, objectSize);
    impl_->cached = crypto::vhf1::SecureBytes(static_cast<std::size_t>(impl_->range->header().chunkSize()));
}

PrefixReader::~PrefixReader() = default;

const crypto::vhf1::OpenedHeader& PrefixReader::header() const { return impl_->range->header(); }

void PrefixReader::read(const uint64_t offset, std::span<uint8_t> out) {
    auto& m = *impl_;
    if (offset > m.size || out.size() > m.size - offset)
        throw storage::IntegrityError("Read past the end of the sealed content");
    const auto c = m.range->header().chunkSize();
    uint64_t pos = offset;
    while (!out.empty()) {
        const auto index = pos / c;
        if (m.cachedIndex != index) {
            m.cachedIndex.reset();
            m.cached.clear();
            const auto start = index * c;
            const auto end = std::min<uint64_t>(start + c, m.size);
            const auto plan = m.range->plan(start, end);
            m.window.resize(static_cast<std::size_t>(plan.objectRange->size()));
            if (prefix_detail::preadSome(m.fd, m.window, plan.objectRange->begin) != m.window.size())
                throw storage::IntegrityError("The sealed prefix ends before chunk " + std::to_string(index));
            try {
                const auto plain = m.range->read(start, end, m.window);
                m.cached.append(plain.span());
            } catch (const crypto::vhf1::Error& e) {
                throwIntegrity(e, "The sealed prefix");
            }
            m.cachedIndex = index;
        }
        const auto in = static_cast<std::size_t>(pos - index * c);
        const auto take = std::min(out.size(), m.cached.size() - in);
        std::memcpy(out.data(), m.cached.data() + in, take);
        out = out.subspan(take);
        pos += take;
    }
}

// ---- PrefixSealer ----------------------------------------------------------------------------------------------------

PrefixSealer::~PrefixSealer() = default;

uint64_t PrefixSealer::chunkLength(const uint64_t index) const {
    return std::min<uint64_t>(chunkSize_, size_ - index * chunkSize_);
}

uint64_t PrefixSealer::chunkOffset(const uint64_t index) const {
    return crypto::vhf1::kHeaderSize + index * (chunkSize_ + crypto::vhf1::kTagSize);
}

uint64_t PrefixSealer::sealedObjectBytes() const {
    if (complete()) return crypto::vhf1::objectSizeFor(size_, header_->params().chunkLog2);
    return chunkOffset(sealed_ / chunkSize_);
}

const crypto::id::ObjectUid& PrefixSealer::objectUid() const { return header_->params().objectUid; }

void PrefixSealer::hashUpdate(const std::span<const uint8_t> bytes) {
    crypto_generichash_update(&hash_, bytes.data(), bytes.size());
}

std::string PrefixSealer::contentHash() const {
    if (!complete()) throw std::logic_error("The sealing is not complete");
    auto state = hash_;
    std::array<unsigned char, crypto_generichash_BYTES> digest{};
    crypto_generichash_final(&state, digest.data(), digest.size());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (const auto b : digest) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

std::unique_ptr<PrefixSealer> PrefixSealer::begin(const Params& params) {
    if (params.plaintextSize == 0) throw std::invalid_argument("An empty file is not sealed");
    if (!params.binding.objectUid) throw std::invalid_argument("A new sealing names its object");
    if (!params.key) throw std::invalid_argument("A sealing needs the vault key");
    const auto salt = [&] {
        const auto raw = crypto::util::b64_decode(params.binding.generation);
        if (raw.size() != crypto::vhf1::kSaltSize) throw std::invalid_argument("The generation is not a VHF1 salt");
        crypto::vhf1::Salt s{};
        std::ranges::copy(raw, s.begin());
        return s;
    }();

    crypto::vhf1::HeaderParams hp;
    hp.kind = crypto::vhf1::Kind::FileContent;
    hp.keyVersion = params.binding.keyVersion;
    hp.vaultUid = params.binding.vaultUid;
    hp.objectUid = *params.binding.objectUid;
    hp.salt = salt;
    hp.chunkLog2 = crypto::vhf1::kWriterChunkLog2;
    const auto body = crypto::vhf1::encodeHeaderBody(hp);
    const auto hh = crypto::vhf1::headerHash(body);
    const auto ks = crypto::vhf1::deriveKeys(*params.key, salt, hh);
    const auto tag = crypto::vhf1::headerTag(*ks.headerKey, body);
    std::array<uint8_t, crypto::vhf1::kHeaderSize> header{};
    std::ranges::copy(body, header.begin());
    std::ranges::copy(tag, header.begin() + crypto::vhf1::kHeaderBodySize);

    if (::ftruncate(params.fd, 0) != 0)
        throw std::system_error(errno, std::generic_category(), "truncating a sealing");
    prefix_detail::pwriteAll(params.fd, header, 0);

    std::unique_ptr<PrefixSealer> s(new PrefixSealer());
    s->fd_ = params.fd;
    s->binding_ = params.binding;
    s->key_ = params.key;
    s->size_ = params.plaintextSize;
    s->header_ = openHeader(header, params.binding, params.key);
    s->chunkSize_ = s->header_->chunkSize();
    s->pending_ = crypto::vhf1::SecureBytes(static_cast<std::size_t>(s->chunkSize_));
    s->out_.resize(static_cast<std::size_t>(s->chunkSize_ + crypto::vhf1::kTagSize));
    crypto_generichash_init(&s->hash_, nullptr, 0, crypto_generichash_BYTES);
    s->hashUpdate(header);
    return s;
}

std::unique_ptr<PrefixSealer> PrefixSealer::resume(const Params& params, const uint64_t durable) {
    if (params.plaintextSize == 0) throw std::invalid_argument("An empty file is not sealed");
    const auto onDisk = prefix_detail::fdSize(params.fd);
    if (durable == 0) {
        if (onDisk == 0) {
            auto fresh = params;
            if (!fresh.binding.objectUid) fresh.binding.objectUid = crypto::id::newObjectUid();
            return begin(fresh);
        }
        // Something was written under this salt but never recorded: which chunks, with what bytes, is unknown.
        std::unique_ptr<PrefixSealer> s(new PrefixSealer());
        s->fd_ = params.fd;
        s->binding_ = params.binding;
        s->key_ = params.key;
        s->size_ = params.plaintextSize;
        s->tail_ = true;
        // A header that authenticates lets resealed() keep its object uid; a torn one gets a new uid.
        try {
            s->header_ = prefix_detail::readHeader(params.fd, params.binding, params.key);
        } catch (const storage::IntegrityError&) {
            auto bound = params.binding;
            if (!bound.objectUid) bound.objectUid = crypto::id::newObjectUid();
            s->binding_ = bound;
            return s;
        }
        s->chunkSize_ = s->header_->chunkSize();
        s->pending_ = crypto::vhf1::SecureBytes(static_cast<std::size_t>(s->chunkSize_));
        s->out_.resize(static_cast<std::size_t>(s->chunkSize_ + crypto::vhf1::kTagSize));
        crypto_generichash_init(&s->hash_, nullptr, 0, crypto_generichash_BYTES);
        return s;
    }

    std::unique_ptr<PrefixSealer> s(new PrefixSealer());
    s->fd_ = params.fd;
    s->binding_ = params.binding;
    s->key_ = params.key;
    s->size_ = params.plaintextSize;
    s->reader_ = std::make_unique<PrefixReader>(params.fd, params.binding, params.key, params.plaintextSize);
    s->header_ = s->reader_->header();
    s->binding_.objectUid = s->header_->params().objectUid;
    s->chunkSize_ = s->header_->chunkSize();
    if (durable > s->size_ || (durable != s->size_ && durable % s->chunkSize_ != 0))
        throw storage::IntegrityError("The recorded sealed prefix is not a chunk boundary");
    s->pending_ = crypto::vhf1::SecureBytes(static_cast<std::size_t>(s->chunkSize_));
    s->out_.resize(static_cast<std::size_t>(s->chunkSize_ + crypto::vhf1::kTagSize));
    crypto_generichash_init(&s->hash_, nullptr, 0, crypto_generichash_BYTES);

    // Rebuild by authentication: every durable chunk opens with its own index and final flag; the hash of the object
    // so far is recomputed from the bytes read.
    std::array<uint8_t, crypto::vhf1::kHeaderSize> header{};
    (void)prefix_detail::preadSome(params.fd, header, 0);
    s->hashUpdate(header);
    std::vector<uint8_t> sealedChunk;
    crypto::vhf1::SecureBytes scratch(static_cast<std::size_t>(s->chunkSize_));
    const auto chunks = durable == s->size_ ? (s->size_ + s->chunkSize_ - 1) / s->chunkSize_ : durable / s->chunkSize_;
    const auto lastIndex = (s->size_ + s->chunkSize_ - 1) / s->chunkSize_ - 1;
    for (uint64_t i = 0; i < chunks; ++i) {
        sealedChunk.resize(static_cast<std::size_t>(s->chunkLength(i) + crypto::vhf1::kTagSize));
        if (prefix_detail::preadSome(params.fd, sealedChunk, s->chunkOffset(i)) != sealedChunk.size())
            throw storage::IntegrityError("The sealed prefix ends before chunk " + std::to_string(i));
        if (!crypto::vhf1::openChunk(*s->header_, i, i == lastIndex, sealedChunk,
                                     scratch.storage().first(sealedChunk.size() - crypto::vhf1::kTagSize)))
            throw storage::IntegrityError("Chunk " + std::to_string(i) + " of the sealed prefix failed authentication");
        s->hashUpdate(sealedChunk);
    }
    s->sealed_ = s->fed_ = durable;
    s->tail_ = onDisk > s->sealedObjectBytes();
    return s;
}

void PrefixSealer::sealPending() {
    const auto index = sealed_ / chunkSize_;
    const auto lastIndex = (size_ + chunkSize_ - 1) / chunkSize_ - 1;
    const auto out = std::span<uint8_t>(out_).first(pending_.size() + crypto::vhf1::kTagSize);
    crypto::vhf1::sealChunk(header_->contentKey(), header_->hash(), index, index == lastIndex, pending_.span(), out);
    prefix_detail::pwriteAll(fd_, out, chunkOffset(index));
    hashUpdate(out);
    sealed_ += pending_.size();
    pending_.clear();
}

PrefixSealer::Fed PrefixSealer::feed(const uint64_t offset, std::span<const uint8_t> plaintext) {
    if (!header_ || tail_) throw std::logic_error("The sealing must continue under a new salt first");
    if (offset > fed_) throw std::invalid_argument("Plaintext past the sealed prefix leaves a gap");
    if (plaintext.size() > size_ - offset) throw std::invalid_argument("Plaintext past the file's size");

    // 1. Bytes this sealing already decided: they must not change.
    if (offset < fed_) {
        const auto overlap = static_cast<std::size_t>(std::min<uint64_t>(plaintext.size(), fed_ - offset));
        const auto decided = plaintext.first(overlap);
        uint64_t pos = offset;
        std::size_t done = 0;
        if (pos < sealed_) {
            if (!reader_) reader_ = std::make_unique<PrefixReader>(fd_, binding_, key_, size_);
            const auto n = static_cast<std::size_t>(std::min<uint64_t>(overlap, sealed_ - pos));
            crypto::vhf1::SecureBytes was(n);
            was.resize(n);
            reader_->read(pos, was.span());
            if (sodium_memcmp(was.data(), decided.data(), n) != 0) return Fed::Diverged;
            done += n;
            pos += n;
        }
        if (done < overlap) {
            const auto at = static_cast<std::size_t>(pos - sealed_);
            if (sodium_memcmp(pending_.data() + at, decided.data() + done, overlap - done) != 0) return Fed::Diverged;
        }
        plaintext = plaintext.subspan(overlap);
    }

    // 2. New bytes: extend the prefix, sealing each chunk once it is complete.
    while (!plaintext.empty()) {
        const auto index = sealed_ / chunkSize_;
        const auto want = static_cast<std::size_t>(chunkLength(index) - pending_.size());
        const auto take = std::min(want, plaintext.size());
        pending_.append(plaintext.first(take));
        plaintext = plaintext.subspan(take);
        fed_ += take;
        if (pending_.size() == chunkLength(index)) sealPending();
    }
    return Fed::Ok;
}

std::unique_ptr<PrefixSealer> PrefixSealer::resealed(const int newFd, const uint64_t keep) {
    const auto readable = tail_ ? sealed_ : fed_;
    if (keep > readable) throw std::invalid_argument("Only authenticated plaintext can be kept");
    Params p;
    p.fd = newFd;
    p.binding = binding_;
    p.binding.generation = generationOf(crypto::vhf1::freshSalt());
    if (header_) p.binding.objectUid = header_->params().objectUid;
    if (!p.binding.objectUid) p.binding.objectUid = crypto::id::newObjectUid();
    p.key = key_;
    p.plaintextSize = size_;
    auto next = begin(p);

    crypto::vhf1::SecureBytes buf(static_cast<std::size_t>(std::max<uint64_t>(chunkSize_, 1)));
    for (uint64_t pos = 0; pos < keep;) {
        const auto n = static_cast<std::size_t>(std::min<uint64_t>(buf.capacity(), keep - pos));
        buf.resize(n);
        if (pos < sealed_) {
            if (!reader_) reader_ = std::make_unique<PrefixReader>(fd_, binding_, key_, size_);
            const auto fromDisk = static_cast<std::size_t>(std::min<uint64_t>(n, sealed_ - pos));
            reader_->read(pos, buf.span().first(fromDisk));
            if (fromDisk < n)
                std::memcpy(buf.data() + fromDisk, pending_.data(), n - fromDisk);
        } else {
            std::memcpy(buf.data(), pending_.data() + (pos - sealed_), n);
        }
        if (next->feed(pos, buf.span()) != Fed::Ok) throw std::logic_error("A fresh sealing diverged");
        pos += n;
    }
    return next;
}

}
