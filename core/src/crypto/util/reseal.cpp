#include "crypto/util/reseal.hpp"
#include "crypto/util/Gcm.hpp"
#include "storage/PlaintextReader.hpp"

#include <openssl/crypto.h>
#include <sodium.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <stdexcept>
#include <system_error>

namespace vh::crypto::util {

namespace reseal_detail {

constexpr std::size_t kChunk = 64 * 1024;

class Fd {
public:
    explicit Fd(const int fd) : fd_(fd) {}
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    [[nodiscard]] int get() const { return fd_; }
    // Reports deferred write errors; the destructor's close is only the fallback on an error path.
    void close() {
        const int fd = fd_;
        fd_ = -1;
        if (::close(fd) != 0 && errno != EINTR) throw std::system_error(errno, std::generic_category(), "close");
    }

private:
    int fd_;
};

// Reads out.size() bytes at offset unless EOF comes first; returns how many were read.
std::size_t preadFully(const int fd, const std::span<uint8_t> out, const uint64_t offset) {
    std::size_t done = 0;
    while (done < out.size()) {
        const auto got = ::pread(fd, out.data() + done, out.size() - done, static_cast<off_t>(offset + done));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "pread while re-sealing");
        }
        if (got == 0) break;
        done += static_cast<std::size_t>(got);
    }
    return done;
}

void writeFully(const int fd, const std::span<const uint8_t> in) {
    std::size_t done = 0;
    while (done < in.size()) {
        const auto put = ::write(fd, in.data() + done, in.size() - done);
        if (put < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "write while re-sealing");
        }
        done += static_cast<std::size_t>(put);
    }
}

std::array<uint8_t, AES_IV_SIZE> decodeIv(const std::string& ivB64) {
    const auto raw = b64_decode(ivB64);
    if (raw.size() != AES_IV_SIZE) throw std::invalid_argument("Re-seal needs a 12-byte AES-GCM IV");
    std::array<uint8_t, AES_IV_SIZE> iv{};
    std::ranges::copy(raw, iv.begin());
    return iv;
}

}

namespace reseal_detail {

void resealInto(const std::filesystem::path& src, const SecretKey& oldKey, const GcmIv oldIv,
                const std::filesystem::path& dst, const SecretKey& newKey, const GcmIv newIv) {
    const Fd in(::open(src.c_str(), O_RDONLY | O_CLOEXEC));
    if (in.get() < 0) throw std::system_error(errno, std::generic_category(), "open " + src.string());
    struct stat st{};
    if (::fstat(in.get(), &st) != 0) throw std::system_error(errno, std::generic_category(), "stat " + src.string());
    const auto total = static_cast<uint64_t>(st.st_size);
    if (total < AES_TAG_SIZE)
        throw storage::IntegrityError("Sealed content is shorter than its authentication tag: " + src.string());
    const uint64_t bodySize = total - AES_TAG_SIZE;

    std::array<uint8_t, AES_TAG_SIZE> oldTag{};
    if (preadFully(in.get(), oldTag, bodySize) != oldTag.size())
        throw storage::IntegrityError("Sealed content is shorter than its metadata: " + src.string());

    if (dst.has_parent_path()) std::filesystem::create_directories(dst.parent_path());
    Fd out(::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    if (out.get() < 0) throw std::system_error(errno, std::generic_category(), "open " + dst.string());

    std::array<uint8_t, kChunk> sealed{};
    std::array<uint8_t, kChunk> plain{};
    std::array<uint8_t, kChunk> resealed{};
    try {
        GcmStreamDecryptor decryptor(oldKey.bytes(), oldIv);
        GcmStreamEncryptor encryptor(newKey.bytes(), newIv);
        uint64_t offset = 0;
        while (offset < bodySize) {
            const auto want = static_cast<std::size_t>(std::min<uint64_t>(sealed.size(), bodySize - offset));
            const std::span<uint8_t> chunk(sealed.data(), want);
            if (preadFully(in.get(), chunk, offset) != want)
                throw storage::IntegrityError("Sealed content shrank while it was being re-sealed: " + src.string());
            decryptor.update(chunk, plain);
            encryptor.update({plain.data(), want}, resealed);
            writeFully(out.get(), {resealed.data(), want});
            offset += want;
        }
        OPENSSL_cleanse(plain.data(), plain.size());
        if (!decryptor.finish(oldTag))
            throw storage::IntegrityError("Sealed content failed authentication; nothing was re-sealed: " + src.string());
        writeFully(out.get(), encryptor.finish());
        out.close();
    } catch (...) {
        OPENSSL_cleanse(plain.data(), plain.size());
        throw;
    }
}

}

std::string resealFile(const std::filesystem::path& src, const SecretKey& oldKey, const std::string& oldIvB64,
                       const std::filesystem::path& dst, const SecretKey& newKey) {
    const auto oldIv = reseal_detail::decodeIv(oldIvB64);
    std::array<uint8_t, AES_IV_SIZE> newIv{};
    randombytes_buf(newIv.data(), newIv.size());
    try {
        reseal_detail::resealInto(src, oldKey, oldIv, dst, newKey, newIv);
    } catch (...) {
        // Whatever dst held (a leftover sidecar, or our partial output) is not a valid generation.
        std::error_code ec;
        std::filesystem::remove(dst, ec);
        throw;
    }
    return b64_encode(std::vector<uint8_t>(newIv.begin(), newIv.end()));
}

std::vector<uint8_t> resealBuffer(const std::span<const uint8_t> sealed, const SecretKey& oldKey,
                                  const std::span<const uint8_t> oldIv, const SecretKey& newKey,
                                  std::vector<uint8_t>& outIv) {
    if (oldIv.size() != AES_IV_SIZE) throw std::invalid_argument("Re-seal needs a 12-byte AES-GCM IV");
    if (sealed.size() < AES_TAG_SIZE)
        throw storage::IntegrityError("Sealed content is shorter than its authentication tag");
    const auto bodySize = sealed.size() - AES_TAG_SIZE;

    std::vector<uint8_t> plain(bodySize);
    if (!gcmDecrypt(oldKey.bytes(), GcmIv(oldIv.data(), AES_IV_SIZE), sealed.first(bodySize),
                    std::span<const uint8_t, AES_TAG_SIZE>(sealed.data() + bodySize, AES_TAG_SIZE), plain))
        throw storage::IntegrityError("Sealed content failed authentication; nothing was re-sealed");

    std::vector<uint8_t> iv(AES_IV_SIZE);
    randombytes_buf(iv.data(), iv.size());
    std::vector<uint8_t> out(bodySize + AES_TAG_SIZE);
    try {
        GcmStreamEncryptor encryptor(newKey.bytes(), GcmIv(iv.data(), AES_IV_SIZE));
        encryptor.update(plain, std::span<uint8_t>(out.data(), bodySize));
        const auto tag = encryptor.finish();
        std::ranges::copy(tag, out.begin() + static_cast<std::ptrdiff_t>(bodySize));
    } catch (...) {
        sodium_memzero(plain.data(), plain.size());
        throw;
    }
    sodium_memzero(plain.data(), plain.size());
    outIv = std::move(iv);
    return out;
}

}
