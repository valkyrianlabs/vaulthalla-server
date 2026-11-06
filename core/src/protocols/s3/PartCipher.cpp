#include "protocols/s3/PartCipher.hpp"

#include "crypto/SecretKey.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/digest.hpp"
#include "crypto/util/encrypt.hpp"
#include "platform/Durable.hpp"
#include "vault/EncryptionManager.hpp"

#include <sodium.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <limits>
#include <memory>
#include <mutex>
#include <string_view>
#include <system_error>
#include <utility>

namespace vh::protocols::s3::part_cipher {

namespace {

constexpr std::string_view kDomain = "vaulthalla/s3-multipart-part/v1";
constexpr std::size_t kIoChunk = 64 * 1024;

using Iv = std::array<uint8_t, crypto::util::AES_IV_SIZE>;

void putBe(std::vector<uint8_t>& out, const uint64_t value, const int bytes) {
    for (int i = bytes - 1; i >= 0; --i) out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
}

struct Fd {
    int fd{-1};
    explicit Fd(const int f) : fd(f) {}
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
    Fd& operator=(Fd&&) = delete;
    void reset() noexcept {
        if (fd >= 0) ::close(fd);
        fd = -1;
    }
};

void writeAll(const int fd, const uint8_t* data, std::size_t n) {
    while (n > 0) {
        const auto w = ::write(fd, data, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) throw std::system_error(errno, std::generic_category(), "writing a multipart part");
        data += w;
        n -= static_cast<std::size_t>(w);
    }
}

// False when the file ends first.
bool readExact(const int fd, uint8_t* data, std::size_t n, uint64_t offset) {
    while (n > 0) {
        const auto r = ::pread(fd, data, n, static_cast<off_t>(offset));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) throw std::system_error(errno, std::generic_category(), "reading a multipart part");
        if (r == 0) return false;
        data += r;
        n -= static_cast<std::size_t>(r);
        offset += static_cast<uint64_t>(r);
    }
    return true;
}

void syncDirectory(const std::filesystem::path& dir) {
    Fd fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd.fd < 0) throw std::system_error(errno, std::generic_category(), "opening the multipart part directory");
    if (platform::durable::sync(fd.fd) != 0)
        throw std::system_error(errno, std::generic_category(), "flushing the multipart part directory");
}

Iv ivFrom(const Stored& part) {
    const auto raw = crypto::util::b64_decode(part.encryption_iv);
    if (raw.size() != crypto::util::AES_IV_SIZE)
        throw Tampered(part.binding.part_number, "Multipart part " + std::to_string(part.binding.part_number) +
                                                     " has no valid IV");
    Iv iv{};
    std::ranges::copy(raw, iv.begin());
    return iv;
}

struct OpenPart {
    uint32_t number{};
    Fd fd;
    crypto::SecretKeyPtr key;
    Iv iv{};
    std::vector<uint8_t> aad;
    uint64_t size{};
    uint64_t start{};  // offset of its first byte in the whole
};

class Reader {
public:
    explicit Reader(std::vector<OpenPart> parts) : parts_(std::move(parts)) {
        for (const auto& p : parts_) total_ += p.size;
    }

    [[nodiscard]] uint64_t size() const { return total_; }

    std::size_t read(const uint64_t offset, const std::span<uint8_t> out) {
        std::scoped_lock lock(m_);
        if (offset >= total_ || out.empty()) return 0;
        const auto k = partAt(offset);
        auto& part = parts_[k];
        const auto local = offset - part.start;

        if (!(cursor_ && cursorPart_ == k && cursorPos_ == local) && local == 0) {
            // A part read from its start: decrypt it in order, authenticating as we go.
            cursor_ = std::make_unique<crypto::util::GcmStreamDecryptor>(part.key->bytes(), part.iv, part.aad);
            cursorPart_ = k;
            cursorPos_ = 0;
        }

        const auto n = static_cast<std::size_t>(std::min<uint64_t>(out.size(), part.size - local));
        ct_.resize(std::max(ct_.size(), n));
        if (!readExact(part.fd.fd, ct_.data(), n, local))
            throw Tampered(part.number, "Multipart part " + std::to_string(part.number) + " is shorter than recorded");

        if (cursor_ && cursorPart_ == k && cursorPos_ == local) {
            cursor_->update({ct_.data(), n}, out.first(n));
            cursorPos_ += n;
            if (cursorPos_ == part.size) {
                std::array<uint8_t, crypto::util::AES_TAG_SIZE> tag{};
                const bool ok = readExact(part.fd.fd, tag.data(), tag.size(), part.size) && cursor_->finish(tag);
                cursor_.reset();
                if (!ok) {
                    sodium_memzero(out.data(), n);
                    throw Tampered(part.number, "Multipart part " + std::to_string(part.number) +
                                                    " changed while it was being read");
                }
            }
            return n;
        }

        // Out of order: positioned decryption of a part authenticated when the source was opened.
        crypto::util::gcmCtrDecryptAt(part.key->bytes(), part.iv, local, {ct_.data(), n}, out.first(n));
        return n;
    }

private:
    // The part holding `offset` (< total_): the last one starting at or before it, which is never an empty one.
    [[nodiscard]] std::size_t partAt(const uint64_t offset) const {
        const auto it = std::upper_bound(parts_.begin(), parts_.end(), offset,
                                         [](const uint64_t o, const OpenPart& p) { return o < p.start; });
        return static_cast<std::size_t>(std::distance(parts_.begin(), it)) - 1;
    }

    std::mutex m_;
    std::vector<OpenPart> parts_;
    uint64_t total_{};
    std::unique_ptr<crypto::util::GcmStreamDecryptor> cursor_;
    std::size_t cursorPart_{};
    uint64_t cursorPos_{};
    std::vector<uint8_t> ct_;
};

}

Tampered::Tampered(const uint32_t partNumber, const std::string& what)
    : std::runtime_error(what), partNumber_(partNumber) {}

std::vector<uint8_t> aad(const Binding& binding, const uint64_t size) {
    std::vector<uint8_t> out(kDomain.begin(), kDomain.end());
    out.push_back(0);
    putBe(out, binding.vault_id, 4);
    putBe(out, binding.upload_id.size(), 4);
    out.insert(out.end(), binding.upload_id.begin(), binding.upload_id.end());
    putBe(out, binding.part_number, 4);
    putBe(out, size, 8);
    return out;
}

Sealed seal(const vault::EncryptionManager& keys, const Binding& binding, const fs::PlaintextSource& source,
            const std::filesystem::path& path) {
    const auto [key, version] = keys.currentKey();
    Iv iv{};
    randombytes_buf(iv.data(), iv.size());
    const auto ad = aad(binding, source.size);

    Fd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (fd.fd < 0) throw std::system_error(errno, std::generic_category(), "creating multipart part " + path.string());
    try {
        crypto::util::GcmStreamEncryptor encryptor(key->bytes(), iv, ad);
        crypto::util::EvpDigest md5(EVP_md5());
        std::array<uint8_t, kIoChunk> ct{};
        uint64_t written = 0;
        fs::forEachChunk(source, [&](const std::span<const uint8_t> chunk) {
            md5.update(chunk.data(), chunk.size());
            encryptor.update(chunk, {ct.data(), chunk.size()});
            writeAll(fd.fd, ct.data(), chunk.size());
            written += chunk.size();
        });
        if (written != source.size) throw std::runtime_error("The multipart part body ended before its size");
        const auto tag = encryptor.finish();
        writeAll(fd.fd, tag.data(), tag.size());
        if (platform::durable::sync(fd.fd) != 0)
            throw std::system_error(errno, std::generic_category(), "flushing a multipart part");
        fd.reset();
        syncDirectory(path.parent_path());

        const auto digest = md5.finish();
        return {.encryption_iv = crypto::util::b64_encode(std::vector<uint8_t>(iv.begin(), iv.end())),
                .key_version = version,
                .size_bytes = source.size,
                .md5 = std::vector<uint8_t>(digest.begin(), digest.end())};
    } catch (...) {
        fd.reset();
        std::error_code ec;
        std::filesystem::remove(path, ec);
        throw;
    }
}

fs::PlaintextSource open(const vault::EncryptionManager& keys, const std::vector<Stored>& parts) {
    std::vector<OpenPart> opened;
    opened.reserve(parts.size());
    uint64_t start = 0;
    for (const auto& part : parts) {
        const auto number = part.binding.part_number;
        const auto label = "Multipart part " + std::to_string(number);
        Fd fd(::open(part.path.c_str(), O_RDONLY | O_CLOEXEC));
        if (fd.fd < 0) throw Tampered(number, label + " is missing from the part store");
        struct stat st{};
        if (::fstat(fd.fd, &st) != 0) throw std::system_error(errno, std::generic_category(), "stat " + label);
        if (part.size_bytes > std::numeric_limits<uint64_t>::max() - crypto::util::AES_TAG_SIZE ||
            static_cast<uint64_t>(st.st_size) != part.size_bytes + crypto::util::AES_TAG_SIZE)
            throw Tampered(number, label + " does not have the length its row records");

        OpenPart p{.number = number, .fd = std::move(fd), .key = keys.historicalKeySnapshot(part.key_version),
                   .iv = ivFrom(part), .aad = aad(part.binding, part.size_bytes), .size = part.size_bytes,
                   .start = start};
        if (!crypto::util::gcmVerifyFd(p.fd.fd, 0, p.size, p.key->bytes(), p.iv, p.aad))
            throw Tampered(number, label + " failed authentication");
        start += p.size;
        opened.push_back(std::move(p));
    }

    auto reader = std::make_shared<Reader>(std::move(opened));
    return {.size = reader->size(), .read = [reader](const uint64_t offset, const std::span<uint8_t> out) {
                return reader->read(offset, out);
            }};
}

}
