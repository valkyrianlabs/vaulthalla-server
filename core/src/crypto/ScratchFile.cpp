#include "crypto/ScratchFile.hpp"

#include <sodium.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <system_error>

namespace vh::crypto {

namespace scratch {

// Plaintext scratch memory: kept out of swap where the platform allows it, zeroed when released.
class LockedBlock {
public:
    LockedBlock() : bytes_(std::make_unique<uint8_t[]>(ScratchFile::kBlockSize)) {
        (void)sodium_mlock(bytes_.get(), ScratchFile::kBlockSize);  // best effort, as for SecretKey
    }
    ~LockedBlock() { sodium_munlock(bytes_.get(), ScratchFile::kBlockSize); }  // also zeroes
    LockedBlock(const LockedBlock&) = delete;
    LockedBlock& operator=(const LockedBlock&) = delete;

    [[nodiscard]] uint8_t* data() const noexcept { return bytes_.get(); }

private:
    std::unique_ptr<uint8_t[]> bytes_;
};

}

namespace {

static_assert(ScratchFile::kNonceSize == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(ScratchFile::kTagSize == crypto_aead_xchacha20poly1305_ietf_ABYTES);
static_assert(util::AES_KEY_SIZE == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

[[noreturn]] void throwErrno(const char* what) { throw std::system_error(errno, std::generic_category(), what); }

std::array<uint8_t, ScratchFile::kIdSize + 8> aadFor(const std::array<uint8_t, ScratchFile::kIdSize>& id,
                                                     const uint64_t index) {
    std::array<uint8_t, ScratchFile::kIdSize + 8> aad{};
    std::ranges::copy(id, aad.begin());
    for (int i = 0; i < 8; ++i) aad[ScratchFile::kIdSize + static_cast<std::size_t>(i)] =
        static_cast<uint8_t>(index >> (56 - 8 * i));
    return aad;
}

void pwriteAll(const int fd, const uint8_t* data, std::size_t size, uint64_t offset) {
    while (size > 0) {
        const auto n = ::pwrite(fd, data, size, static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throwErrno("write scratch file");
        data += n;
        size -= static_cast<std::size_t>(n);
        offset += static_cast<uint64_t>(n);
    }
}

// Reads exactly `size` bytes; false if the file ends first.
bool preadAll(const int fd, uint8_t* data, std::size_t size, uint64_t offset) {
    while (size > 0) {
        const auto n = ::pread(fd, data, size, static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) throwErrno("read scratch file");
        if (n == 0) return false;
        data += n;
        size -= static_cast<std::size_t>(n);
        offset += static_cast<uint64_t>(n);
    }
    return true;
}

const std::array<uint8_t, ScratchFile::kBlockSize>& zeroBlock() {
    static const std::array<uint8_t, ScratchFile::kBlockSize> zeros{};
    return zeros;
}

}

struct ScratchFile::Cache {
    scratch::LockedBlock block;          // plaintext; zero beyond `length`
    uint64_t index{};
    std::size_t length{};
    bool dirty{false};
};

// The block a partial read decrypted last, valid while generation_ hasn't moved: small sequential reads (FUSE passes
// an application's reads through as they are, direct_io) decrypt each block once instead of once per read.
struct ScratchFile::ReadCache {
    scratch::LockedBlock block;
    uint64_t index{};
    uint64_t generation{};
    bool valid{false};
};

const SecretKeyPtr& ScratchFile::processKey() {
    static const SecretKeyPtr key = [] {
        if (sodium_init() < 0) throw std::runtime_error("libsodium failed to initialize");
        return SecretKey::random();
    }();
    return key;
}

ScratchFile::ScratchFile(std::filesystem::path path, SecretKeyPtr key) : path_(std::move(path)), key_(std::move(key)) {
    if (!key_) throw std::invalid_argument("A scratch file needs a key");
    if (sodium_init() < 0) throw std::runtime_error("libsodium failed to initialize");
    randombytes_buf(id_.data(), id_.size());
    fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd_ < 0) throwErrno("create scratch file");
}

ScratchFile::~ScratchFile() {
    dropCache();
    read_.reset();
    if (fd_ >= 0) ::close(fd_);
    std::error_code ec;
    std::filesystem::remove(path_, ec);
}

uint64_t ScratchFile::blockCount(const uint64_t size) const noexcept { return (size + kBlockSize - 1) / kBlockSize; }

std::size_t ScratchFile::blockLength(const uint64_t index, const uint64_t size) const noexcept {
    const auto start = index * kBlockSize;
    if (start >= size) return 0;
    return static_cast<std::size_t>(std::min<uint64_t>(kBlockSize, size - start));
}

void ScratchFile::writeRecord(const uint64_t index, const std::span<const uint8_t> plain) {
    std::array<uint8_t, kRecordSize> record;  // NOLINT: fully written below
    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());
    std::ranges::copy(nonce, record.begin());
    const auto aad = aadFor(id_, index);
    unsigned long long sealed = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(record.data() + kNonceSize, &sealed, plain.data(), plain.size(),
                                               aad.data(), aad.size(), nullptr, nonce.data(), key_->bytes().data());
    pwriteAll(fd_, record.data(), kNonceSize + static_cast<std::size_t>(sealed), index * kRecordSize);
    if (nonces_.size() <= index) nonces_.resize(index + 1);
    nonces_[index] = nonce;
}

void ScratchFile::readRecord(const uint64_t index, const std::span<uint8_t> out) const {
    std::array<uint8_t, kRecordSize> record;  // NOLINT: filled by preadAll
    const auto length = kRecordOverhead + out.size();
    if (index >= nonces_.size() || !preadAll(fd_, record.data(), length, index * kRecordSize))
        throw Tampered("A scratch file block is missing");
    if (sodium_memcmp(record.data(), nonces_[index].data(), kNonceSize) != 0)
        throw Tampered("A scratch file block is not the one last written");
    const auto aad = aadFor(id_, index);
    unsigned long long opened = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &opened, nullptr, record.data() + kNonceSize,
                                                   length - kNonceSize, aad.data(), aad.size(), record.data(),
                                                   key_->bytes().data()) != 0 ||
        opened != out.size()) {
        sodium_memzero(out.data(), out.size());
        throw Tampered("A scratch file block failed authentication");
    }
}

void ScratchFile::flushCache() {
    if (!cache_ || !cache_->dirty) return;
    writeRecord(cache_->index, {cache_->block.data(), cache_->length});
    cache_->dirty = false;
}

void ScratchFile::dropCache() noexcept { cache_.reset(); }

// Makes block `index` (< blockCount(size_) + 1) the cached one. keepContent: its current plaintext is needed (a
// partial write); otherwise the caller overwrites all of it.
void ScratchFile::loadCache(const uint64_t index, const bool keepContent) {
    if (cache_ && cache_->index == index) return;
    flushCache();
    if (!cache_) cache_ = std::make_unique<Cache>();
    cache_->index = index;
    cache_->dirty = false;
    cache_->length = blockLength(index, size_);
    sodium_memzero(cache_->block.data(), kBlockSize);
    if (keepContent && cache_->length > 0) {
        try {
            readRecord(index, {cache_->block.data(), cache_->length});
        } catch (...) {
            dropCache();
            throw;
        }
    }
}

void ScratchFile::growTo(const uint64_t size) {
    // Everything that can fail comes before any state changes, so a failed extension leaves the file as it was.
    const auto oldBlocks = blockCount(size_);
    const bool partialTail = size_ % kBlockSize != 0;
    if (partialTail) loadCache(oldBlocks - 1, true);
    const auto newBlocks = blockCount(size);
    if (nonces_.size() < newBlocks) nonces_.resize(newBlocks);
    for (auto i = oldBlocks; i < newBlocks; ++i) writeRecord(i, {zeroBlock().data(), blockLength(i, size)});
    if (partialTail) {
        // The partial last block grows (zeros past its old end; the cache is zero beyond its length).
        cache_->length = blockLength(oldBlocks - 1, size);
        cache_->dirty = true;
    }
    size_ = size;
}

std::size_t ScratchFile::read(const uint64_t offset, const std::span<uint8_t> out) const {
    std::shared_lock lock(mutex_);
    if (offset >= size_ || out.empty()) return 0;
    const auto total = static_cast<std::size_t>(std::min<uint64_t>(out.size(), size_ - offset));

    std::size_t done = 0;
    while (done < total) {
        const auto pos = offset + done;
        const auto index = pos / kBlockSize;
        const auto within = static_cast<std::size_t>(pos % kBlockSize);
        const auto length = blockLength(index, size_);
        const auto chunk = std::min(length - within, total - done);
        if (cache_ && cache_->index == index) {
            std::memcpy(out.data() + done, cache_->block.data() + within, chunk);
        } else if (within == 0 && chunk == length) {
            readRecord(index, out.subspan(done, length));
        } else {
            std::scoped_lock readLock(readMutex_);
            if (!read_) read_ = std::make_unique<ReadCache>();
            if (!read_->valid || read_->index != index || read_->generation != generation_) {
                read_->valid = false;
                readRecord(index, {read_->block.data(), length});
                read_->index = index;
                read_->generation = generation_;
                read_->valid = true;
            }
            std::memcpy(out.data() + done, read_->block.data() + within, chunk);
        }
        done += chunk;
    }
    return total;
}

void ScratchFile::write(const uint64_t offset, const std::span<const uint8_t> data) {
    if (data.empty()) return;
    std::unique_lock lock(mutex_);
    writeLocked(offset, data);
}

void ScratchFile::append(const std::span<const uint8_t> data) {
    if (data.empty()) return;
    std::unique_lock lock(mutex_);
    writeLocked(size_, data);
}

void ScratchFile::writeLocked(const uint64_t offset, const std::span<const uint8_t> data) {
    if (offset > std::numeric_limits<uint64_t>::max() - data.size())
        throw std::system_error(EFBIG, std::generic_category(), "write scratch file");
    ++generation_;
    if (offset > size_) growTo(offset);

    std::size_t done = 0;
    while (done < data.size()) {
        const auto pos = offset + done;
        const auto index = pos / kBlockSize;
        const auto within = static_cast<std::size_t>(pos % kBlockSize);
        const auto chunk = std::min(kBlockSize - within, data.size() - done);
        // Whatever of the block this write doesn't replace has to be kept.
        loadCache(index, !(within == 0 && chunk >= blockLength(index, size_)));
        std::memcpy(cache_->block.data() + within, data.data() + done, chunk);
        cache_->length = std::max(cache_->length, within + chunk);
        cache_->dirty = true;
        size_ = std::max(size_, index * kBlockSize + cache_->length);
        if (nonces_.size() < blockCount(size_)) nonces_.resize(blockCount(size_));
        done += chunk;
    }
}

void ScratchFile::truncate(const uint64_t size) {
    std::unique_lock lock(mutex_);
    if (size == size_) return;
    ++generation_;
    if (size > size_) {
        growTo(size);
        return;
    }
    const auto blocks = blockCount(size);
    if (cache_ && cache_->index >= blocks) dropCache();
    const auto tail = blockLength(blocks == 0 ? 0 : blocks - 1, size);
    if (size % kBlockSize != 0) {
        // The new last block keeps its head (read under the old size, then rewritten shorter).
        loadCache(blocks - 1, true);
        sodium_memzero(cache_->block.data() + tail, kBlockSize - tail);
        cache_->length = tail;
        cache_->dirty = true;
    }
    size_ = size;
    nonces_.resize(blocks);
    const auto physical = blocks == 0 ? 0 : (blocks - 1) * kRecordSize + kRecordOverhead + tail;
    if (::ftruncate(fd_, static_cast<off_t>(physical)) != 0) throwErrno("truncate scratch file");
}

uint64_t ScratchFile::size() const {
    std::shared_lock lock(mutex_);
    return size_;
}

void ScratchFile::flush() {
    std::unique_lock lock(mutex_);
    flushCache();
    dropCache();
    std::scoped_lock readLock(readMutex_);
    read_.reset();
}

void ScratchFile::rename(const std::filesystem::path& to) {
    std::unique_lock lock(mutex_);
    std::filesystem::rename(path_, to);
    path_ = to;
}

std::filesystem::path ScratchFile::path() const {
    std::shared_lock lock(mutex_);
    return path_;
}

std::optional<ScratchFile::Nonce> ScratchFile::nonceOf(const uint64_t index) const {
    std::shared_lock lock(mutex_);
    if (index >= nonces_.size() || (cache_ && cache_->index == index && cache_->dirty)) return std::nullopt;
    return nonces_[index];
}

}
