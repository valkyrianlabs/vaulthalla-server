#include "vault/Content.hpp"

#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/vhf1/Reader.hpp"
#include "crypto/vhf1/Writer.hpp"
#include "fs/PlaintextSource.hpp"
#include "storage/PlaintextReader.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <fmt/format.h>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace vh::vault::content {

namespace content_detail {

constexpr std::size_t kIoChunk = 64 * 1024;
constexpr uint8_t kChunkLog2 = crypto::vhf1::kWriterChunkLog2;

struct Fd {
    explicit Fd(const int f) : fd(f) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { if (fd >= 0) ::close(fd); }
    int fd;
};

std::size_t preadSome(const int fd, std::span<uint8_t> out, const uint64_t offset) {
    std::size_t done = 0;
    while (done < out.size()) {
        const auto got = ::pread(fd, out.data() + done, out.size() - done, static_cast<off_t>(offset + done));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "pread sealed content");
        }
        if (got == 0) break;
        done += static_cast<std::size_t>(got);
    }
    return done;
}

uint64_t fdSize(const int fd) {
    const auto end = ::lseek(fd, 0, SEEK_END);
    if (end < 0) throw std::system_error(errno, std::generic_category(), "size of sealed content");
    return static_cast<uint64_t>(end);
}

crypto::vhf1::Salt saltOf(const std::string& generation) {
    const auto raw = crypto::util::b64_decode(generation);
    if (raw.size() != crypto::vhf1::kSaltSize) throw storage::IntegrityError("The generation is not a VHF1 salt");
    crypto::vhf1::Salt salt{};
    std::ranges::copy(raw, salt.begin());
    return salt;
}

std::vector<uint8_t> ivOf(const std::string& generation) {
    auto iv = crypto::util::b64_decode(generation);
    if (iv.size() != crypto::util::AES_IV_SIZE) throw storage::IntegrityError("The generation is not a GCM IV");
    return iv;
}

crypto::vhf1::KeyLookup lookupFor(const uint32_t keyVersion, const crypto::SecretKeyPtr& key) {
    // Only the version the catalog recorded: a header naming another one fails as key_unavailable.
    return [keyVersion, key](const uint32_t version) -> crypto::SecretKeyPtr {
        return version == keyVersion ? key : nullptr;
    };
}

// A non-owning SecretKeyPtr over a caller's key, for the codec's KeyLookup (the key outlives the call).
crypto::SecretKeyPtr borrow(const crypto::SecretKey& key) {
    return {std::shared_ptr<const crypto::SecretKey>{}, &key};
}

void writeAllFd(const int fd, std::span<const uint8_t> bytes, const std::filesystem::path& path) {
    while (!bytes.empty()) {
        const auto n = ::write(fd, bytes.data(), bytes.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "write " + path.string());
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
}

}

std::string_view to_string(const Format format) {
    switch (format) {
    case Format::Plain: return "plain";
    case Format::Gcm0: return "gcm0";
    case Format::Vhf1: return "vhf1";
    }
    return "unknown";
}

Format formatOf(const std::string_view generationB64) {
    if (generationB64.empty()) return Format::Plain;
    // base64 of 12 bytes is 16 symbols, of 32 bytes 44: the length alone decides, decoding confirms.
    std::vector<uint8_t> raw;
    try {
        raw = crypto::util::b64_decode(std::string(generationB64));
    } catch (const std::exception&) {
        throw std::invalid_argument("Malformed content generation id");
    }
    if (raw.size() == crypto::util::AES_IV_SIZE) return Format::Gcm0;
    if (raw.size() == crypto::vhf1::kSaltSize) return Format::Vhf1;
    throw std::invalid_argument(fmt::format("Content generation id of {} bytes is neither a GCM IV nor a VHF1 salt",
                                            raw.size()));
}

bool isVhf1(const std::string_view generationB64) noexcept {
    if (generationB64.size() != 44) return false;
    try {
        return formatOf(generationB64) == Format::Vhf1;
    } catch (...) {
        return false;
    }
}

uint64_t sealedSize(const uint64_t plaintextSize, const Format format) {
    switch (format) {
    case Format::Plain: return plaintextSize;
    case Format::Gcm0: return plaintextSize + crypto::util::AES_TAG_SIZE;
    case Format::Vhf1: return crypto::vhf1::objectSizeFor(plaintextSize, content_detail::kChunkLog2);
    }
    throw std::invalid_argument("Unknown content format");
}

std::optional<uint64_t> plaintextSizeOf(const uint64_t sealed, const Format format) {
    switch (format) {
    case Format::Plain: return sealed;
    case Format::Gcm0:
        if (sealed < crypto::util::AES_TAG_SIZE) return std::nullopt;
        return sealed - crypto::util::AES_TAG_SIZE;
    case Format::Vhf1:
        try {
            return crypto::vhf1::layoutFor(sealed, content_detail::kChunkLog2).plaintextSize;
        } catch (const crypto::vhf1::Error&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<uint64_t> plaintextSizeOfGeneration(const uint64_t sealed, const std::string_view generationB64) noexcept {
    try {
        return plaintextSizeOf(sealed, formatOf(generationB64));
    } catch (...) {
        return std::nullopt;
    }
}

uint64_t newSealedSize(const uint64_t plaintextSize) { return sealedSize(plaintextSize, Format::Vhf1); }

uint64_t sealedSizeOf(const uint64_t plaintextSize, const std::string_view generationB64) {
    return sealedSize(plaintextSize, formatOf(generationB64));
}

std::string generationOf(const crypto::vhf1::Salt& salt) {
    return crypto::util::b64_encode(std::vector<uint8_t>(salt.begin(), salt.end()));
}

crypto::vhf1::Expectation expectationOf(const Binding& binding) {
    crypto::vhf1::Expectation e;
    e.kind = crypto::vhf1::Kind::FileContent;
    e.vaultUid = binding.vaultUid;
    e.objectUid = binding.objectUid;
    e.generation = content_detail::saltOf(binding.generation);
    return e;
}

void throwIntegrity(const crypto::vhf1::Error& error, const std::string_view what) {
    throw storage::IntegrityError(fmt::format("{} failed authentication ({}{})", what,
                                              crypto::vhf1::errorCodeName(error.code()),
                                              error.chunkIndex() ? fmt::format(", chunk {}", *error.chunkIndex()) : ""));
}

crypto::vhf1::OpenedHeader openHeader(const std::span<const uint8_t> header, const Binding& binding,
                                      const crypto::SecretKeyPtr& key) {
    try {
        return crypto::vhf1::openHeader(header, expectationOf(binding),
                                        content_detail::lookupFor(binding.keyVersion, key));
    } catch (const crypto::vhf1::Error& e) {
        throwIntegrity(e, "Content header");
    }
}

crypto::vhf1::HeaderParams fileHeader(const crypto::id::ObjectUid& vaultUid, const crypto::id::ObjectUid& objectUid,
                                      const uint32_t keyVersion) {
    crypto::vhf1::HeaderParams p;
    p.kind = crypto::vhf1::Kind::FileContent;
    p.keyVersion = keyVersion;
    p.vaultUid = vaultUid;
    p.objectUid = objectUid;
    p.salt = crypto::vhf1::freshSalt();
    p.chunkLog2 = content_detail::kChunkLog2;
    return p;
}

// ---- writing ---------------------------------------------------------------------------------------------------------

Sealer::Sealer(const crypto::SecretKey& key, const uint32_t keyVersion, const crypto::id::ObjectUid& vaultUid,
               const crypto::id::ObjectUid& objectUid, Sink sink)
    : keyVersion_(keyVersion) {
    const auto params = fileHeader(vaultUid, objectUid, keyVersion);
    generation_ = generationOf(params.salt);
    writer_ = std::make_unique<crypto::vhf1::Writer>(params, key, std::move(sink));
}

Sealer::~Sealer() = default;

void Sealer::write(const std::span<const uint8_t> plaintext) { writer_->write(plaintext); }
void Sealer::finish() { writer_->finish(); }
uint64_t Sealer::objectSize() const { return writer_->objectSize(); }

Sealed sealBuffer(const std::span<const uint8_t> plaintext, const crypto::SecretKey& key, const uint32_t keyVersion,
                  const crypto::id::ObjectUid& vaultUid, const crypto::id::ObjectUid& objectUid) {
    const auto params = fileHeader(vaultUid, objectUid, keyVersion);
    return {.bytes = crypto::vhf1::seal(plaintext, params, key), .generation = generationOf(params.salt)};
}

std::string sealSourceToFile(const fs::PlaintextSource& source, const std::filesystem::path& path,
                             const crypto::SecretKey& key, const uint32_t keyVersion,
                             const crypto::id::ObjectUid& vaultUid, const crypto::id::ObjectUid& objectUid) {
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    content_detail::Fd out(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    if (out.fd < 0) throw std::system_error(errno, std::generic_category(), "open " + path.string());
    try {
        Sealer sealer(key, keyVersion, vaultUid, objectUid, [&](const std::span<const uint8_t> bytes) {
            content_detail::writeAllFd(out.fd, bytes, path);
        });
        fs::forEachChunk(source, [&](const std::span<const uint8_t> chunk) { sealer.write(chunk); });
        sealer.finish();
        return sealer.generation();
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        throw;
    }
}

// ---- reading ---------------------------------------------------------------------------------------------------------

std::vector<uint8_t> openBuffer(const std::span<const uint8_t> sealed, const Binding& binding,
                                const crypto::SecretKey& key) {
    switch (formatOf(binding.generation)) {
    case Format::Plain:
        return {sealed.begin(), sealed.end()};
    case Format::Gcm0:
        try {
            return crypto::util::decrypt_aes256_gcm(std::vector<uint8_t>(sealed.begin(), sealed.end()), key.bytes(),
                                                    content_detail::ivOf(binding.generation));
        } catch (const storage::IntegrityError&) {
            throw;
        } catch (const std::exception& e) {
            throw storage::IntegrityError(std::string("Content failed authentication: ") + e.what());
        }
    case Format::Vhf1:
        try {
            auto plain = crypto::vhf1::open(sealed, expectationOf(binding),
                                            content_detail::lookupFor(binding.keyVersion, content_detail::borrow(key)));
            std::vector<uint8_t> out(plain.span().begin(), plain.span().end());
            return out;
        } catch (const crypto::vhf1::Error& e) {
            throwIntegrity(e, "Content");
        }
    }
    throw std::logic_error("unreachable");
}

void openFileTo(const std::filesystem::path& path, const Binding& binding, const crypto::SecretKey& key,
                const Sink& sink) {
    const auto format = formatOf(binding.generation);
    if (format == Format::Plain) {
        fs::forEachChunk(fs::sourceOf(path), sink);
        return;
    }
    if (format == Format::Gcm0) {
        try {
            crypto::util::decrypt_aes256_gcm_file(path, sink, key.bytes(), content_detail::ivOf(binding.generation));
        } catch (const storage::IntegrityError&) {
            throw;
        } catch (const std::system_error&) {
            throw;
        } catch (const std::exception& e) {
            throw storage::IntegrityError(std::string("Content failed authentication: ") + e.what());
        }
        return;
    }

    content_detail::Fd in(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (in.fd < 0) throw std::system_error(errno, std::generic_category(), "open " + path.string());
    const auto size = content_detail::fdSize(in.fd);
    StreamOpener opener(binding, content_detail::borrow(key), size);
    std::vector<uint8_t> buf(content_detail::kIoChunk);
    for (uint64_t pos = 0; pos < size;) {
        const auto want = static_cast<std::size_t>(std::min<uint64_t>(buf.size(), size - pos));
        const auto got = content_detail::preadSome(in.fd, {buf.data(), want}, pos);
        if (got == 0) break;
        opener.update({buf.data(), got}, sink);
        pos += got;
    }
    opener.finish(sink);
}

bool verifyFd(const int fd, const uint64_t plaintextSize, const Binding& binding, const crypto::SecretKey& key) {
    const auto format = formatOf(binding.generation);
    const auto size = content_detail::fdSize(fd);
    if (size != sealedSize(plaintextSize, format)) return false;
    if (format == Format::Plain) return true;
    if (format == Format::Gcm0) {
        const auto iv = content_detail::ivOf(binding.generation);
        return crypto::util::gcmVerifyFd(fd, 0, plaintextSize, key.bytes(),
                                         crypto::util::GcmIv(iv.data(), crypto::util::AES_IV_SIZE));
    }
    try {
        StreamOpener opener(binding, content_detail::borrow(key), size);
        std::vector<uint8_t> buf(content_detail::kIoChunk);
        const Sink discard = [](std::span<const uint8_t>) {};
        for (uint64_t pos = 0; pos < size;) {
            const auto want = static_cast<std::size_t>(std::min<uint64_t>(buf.size(), size - pos));
            const auto got = content_detail::preadSome(fd, {buf.data(), want}, pos);
            if (got == 0) return false;
            opener.update({buf.data(), got}, discard);
            pos += got;
        }
        opener.finish(discard);
        return true;
    } catch (const storage::IntegrityError&) {
        return false;
    }
}

bool verifyFile(const std::filesystem::path& path, const uint64_t plaintextSize, const Binding& binding,
                const crypto::SecretKey& key) {
    content_detail::Fd in(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (in.fd < 0) throw std::system_error(errno, std::generic_category(), "open " + path.string());
    return verifyFd(in.fd, plaintextSize, binding, key);
}

bool verifyWholeFile(const std::filesystem::path& path, const Binding& binding, const crypto::SecretKey& key) {
    content_detail::Fd in(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (in.fd < 0) throw std::system_error(errno, std::generic_category(), "open " + path.string());
    const auto plain = plaintextSizeOf(content_detail::fdSize(in.fd), formatOf(binding.generation));
    return plain && verifyFd(in.fd, *plain, binding, key);
}

struct StreamOpener::Impl {
    Format format{};
    Binding binding;
    crypto::SecretKeyPtr key;
    uint64_t sealedSize{};
    uint64_t received{};
    // Vhf1
    std::vector<uint8_t> header;
    std::optional<crypto::vhf1::ChunkWalker> walker;
    // Gcm0
    std::unique_ptr<crypto::util::GcmStreamDecryptor> gcm;
    std::array<uint8_t, crypto::util::AES_TAG_SIZE> tag{};
    std::vector<uint8_t> plain;
};

StreamOpener::StreamOpener(const Binding& binding, crypto::SecretKeyPtr key, const uint64_t sealedSize)
    : impl_(std::make_unique<Impl>()) {
    impl_->format = formatOf(binding.generation);
    impl_->binding = binding;
    impl_->key = std::move(key);
    impl_->sealedSize = sealedSize;
    if (impl_->format == Format::Plain) return;
    if (!impl_->key) throw storage::IntegrityError("No vault key for the content's key version");
    if (impl_->format == Format::Gcm0) {
        if (sealedSize < crypto::util::AES_TAG_SIZE) throw storage::IntegrityError("Content is shorter than its tag");
        const auto iv = content_detail::ivOf(binding.generation);
        impl_->gcm = std::make_unique<crypto::util::GcmStreamDecryptor>(
            impl_->key->bytes(), crypto::util::GcmIv(iv.data(), crypto::util::AES_IV_SIZE));
    }
}

StreamOpener::~StreamOpener() {
    if (!impl_->plain.empty()) sodium_memzero(impl_->plain.data(), impl_->plain.size());
}

void StreamOpener::update(std::span<const uint8_t> sealed, const Sink& sink) {
    auto& m = *impl_;
    if (sealed.size() > m.sealedSize - m.received) throw storage::IntegrityError("Content is longer than its size");
    if (m.format == Format::Plain) {
        m.received += sealed.size();
        sink(sealed);
        return;
    }
    if (m.format == Format::Gcm0) {
        const auto bodySize = m.sealedSize - crypto::util::AES_TAG_SIZE;
        while (!sealed.empty()) {
            if (m.received < bodySize) {
                const auto n = static_cast<std::size_t>(std::min<uint64_t>(sealed.size(), bodySize - m.received));
                m.plain.resize(n);
                m.gcm->update(sealed.first(n), m.plain);
                sink(m.plain);
                sodium_memzero(m.plain.data(), m.plain.size());
                m.received += n;
                sealed = sealed.subspan(n);
            } else {
                const auto at = static_cast<std::size_t>(m.received - bodySize);
                const auto n = std::min(sealed.size(), m.tag.size() - at);
                std::copy_n(sealed.begin(), n, m.tag.begin() + static_cast<std::ptrdiff_t>(at));
                m.received += n;
                sealed = sealed.subspan(n);
            }
        }
        return;
    }
    try {
        while (!sealed.empty()) {
            if (!m.walker) {
                const auto n = std::min(sealed.size(), crypto::vhf1::kHeaderSize - m.header.size());
                m.header.insert(m.header.end(), sealed.begin(), sealed.begin() + static_cast<std::ptrdiff_t>(n));
                m.received += n;
                sealed = sealed.subspan(n);
                if (m.header.size() < crypto::vhf1::kHeaderSize) continue;
                auto opened = crypto::vhf1::openHeader(m.header, expectationOf(m.binding),
                                                       content_detail::lookupFor(m.binding.keyVersion, m.key));
                m.walker.emplace(std::move(opened), m.sealedSize);
                continue;
            }
            m.walker->update(sealed, [&](uint64_t, const std::span<const uint8_t> plain) { sink(plain); });
            m.received += sealed.size();
            sealed = {};
        }
    } catch (const crypto::vhf1::Error& e) {
        throwIntegrity(e, "Content");
    }
}

void StreamOpener::finish(const Sink&) {
    auto& m = *impl_;
    if (m.received != m.sealedSize) throw storage::IntegrityError("Content is shorter than its size");
    if (m.format == Format::Plain) return;
    if (m.format == Format::Gcm0) {
        if (!m.gcm->finish(m.tag)) throw storage::IntegrityError("Content failed authentication");
        return;
    }
    try {
        if (!m.walker) throw crypto::vhf1::Error(crypto::vhf1::ErrorCode::BadMagic);
        m.walker->finish();
    } catch (const crypto::vhf1::Error& e) {
        throwIntegrity(e, "Content");
    }
}

std::string resealFile(const std::filesystem::path& src, const Binding& from, const crypto::SecretKey& fromKey,
                       const std::filesystem::path& dst, const crypto::SecretKey& toKey, const uint32_t toKeyVersion,
                       const crypto::id::ObjectUid& objectUid) {
    if (dst.has_parent_path()) std::filesystem::create_directories(dst.parent_path());
    if (formatOf(from.generation) == Format::Plain) {
        if (std::filesystem::file_size(src) != 0)
            throw std::invalid_argument("Refusing to re-seal an unencrypted generation: " + src.string());
        content_detail::Fd out(::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
        if (out.fd < 0) throw std::system_error(errno, std::generic_category(), "open " + dst.string());
        return {};
    }
    content_detail::Fd out(::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    if (out.fd < 0) throw std::system_error(errno, std::generic_category(), "open " + dst.string());
    try {
        Sealer sealer(toKey, toKeyVersion, from.vaultUid, objectUid, [&](const std::span<const uint8_t> bytes) {
            content_detail::writeAllFd(out.fd, bytes, dst);
        });
        openFileTo(src, from, fromKey, [&](const std::span<const uint8_t> plain) { sealer.write(plain); });
        sealer.finish();
        return sealer.generation();
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove(dst, ec);
        throw;
    }
}

}
