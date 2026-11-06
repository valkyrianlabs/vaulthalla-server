#include "storage/Vhf1FileReader.hpp"

#include "crypto/vhf1/Reader.hpp"
#include "platform/FileTime.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace vh::storage {

struct Vhf1FileReader::Impl {
    int fd{-1};
    std::optional<crypto::vhf1::RangeReader> range;
    crypto::IntegrityKey integrityKey;
    std::optional<uint64_t> cachedIndex;
    crypto::vhf1::SecureBytes cached;
    std::vector<uint8_t> window;  // one sealed chunk (ciphertext)
    uint64_t contiguous{};         // chunks [0, contiguous) all authenticated by this reader
    std::optional<crypto::vhf1::Error> failed;

    ~Impl() {
        if (fd >= 0) ::close(fd);
    }
};

namespace vhf1_file_reader_detail {

std::size_t preadFully(const int fd, std::span<uint8_t> out, const uint64_t offset, const std::filesystem::path& path) {
    std::size_t done = 0;
    while (done < out.size()) {
        const auto got = ::pread(fd, out.data() + done, out.size() - done, static_cast<off_t>(offset + done));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "pread " + path.filename().string());
        }
        if (got == 0) break;
        done += static_cast<std::size_t>(got);
    }
    return done;
}

}

Vhf1FileReader::Vhf1FileReader(Params params) : params_(std::move(params)), impl_(std::make_unique<Impl>()) {
    namespace detail = vhf1_file_reader_detail;
    auto& m = *impl_;
    m.fd = ::open(params_.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (m.fd < 0) throw std::system_error(errno, std::generic_category(), "open " + params_.path.string());
    struct stat st{};
    if (::fstat(m.fd, &st) != 0) throw std::system_error(errno, std::generic_category(), "fstat " + params_.path.string());

    m.integrityKey = crypto::IntegrityKey{
        .domain = params_.integrityDomain,
        .iv_b64 = params_.binding.generation,
        .key_version = params_.binding.keyVersion,
        .dev = static_cast<uint64_t>(st.st_dev),
        .ino = static_cast<uint64_t>(st.st_ino),
        .size = static_cast<uint64_t>(st.st_size),
        .mtime_ns = static_cast<int64_t>(platform::mtime(st).tv_sec) * 1'000'000'000 + platform::mtime(st).tv_nsec};
    if (const auto state = crypto::IntegrityRegistry::instance().peek(m.integrityKey);
        state == crypto::IntegrityState::Failed)
        throw IntegrityError("Content failed integrity verification");

    const auto expected = vh::vault::content::sealedSize(params_.plaintextSize, vh::vault::content::Format::Vhf1);
    if (static_cast<uint64_t>(st.st_size) != expected)
        // The catalog's size is the authenticated object size: a different stored size is damage or a replacement.
        throw IntegrityError("Stored size of " + params_.path.filename().string() + " does not match its metadata");

    std::array<uint8_t, crypto::vhf1::kHeaderSize> header{};
    if (detail::preadFully(m.fd, header, 0, params_.path) != header.size())
        throw IntegrityError("Content is shorter than its header");
    try {
        auto opened = vh::vault::content::openHeader(header, params_.binding, params_.key);
        m.range.emplace(std::move(opened), expected, static_cast<uint64_t>(st.st_size));
    } catch (const IntegrityError&) {
        crypto::IntegrityRegistry::instance().record(m.integrityKey, false);
        throw;
    } catch (const crypto::vhf1::Error& e) {
        crypto::IntegrityRegistry::instance().record(m.integrityKey, false);
        vh::vault::content::throwIntegrity(e, "Content");
    }
    m.cached = crypto::vhf1::SecureBytes(static_cast<std::size_t>(m.range->header().chunkSize()));
}

Vhf1FileReader::~Vhf1FileReader() = default;

void Vhf1FileReader::fail(const crypto::vhf1::Error& error) {
    impl_->failed = error;
    impl_->cachedIndex.reset();
    impl_->cached.clear();
    crypto::IntegrityRegistry::instance().record(impl_->integrityKey, false);
    vh::vault::content::throwIntegrity(error, "Content");
}

void Vhf1FileReader::loadChunk(const uint64_t index) {
    namespace detail = vhf1_file_reader_detail;
    auto& m = *impl_;
    if (m.failed) vh::vault::content::throwIntegrity(*m.failed, "Content");
    if (m.cachedIndex == index) {
        if (index == m.contiguous) ++m.contiguous;
        return;
    }
    const auto c = m.range->header().chunkSize();
    const auto start = index * c;
    const auto end = std::min<uint64_t>(start + c, params_.plaintextSize);
    const auto plan = m.range->plan(start, end);
    m.window.resize(static_cast<std::size_t>(plan.objectRange->size()));
    if (detail::preadFully(m.fd, m.window, plan.objectRange->begin, params_.path) != m.window.size())
        fail(crypto::vhf1::Error(crypto::vhf1::ErrorCode::SizeMismatch));
    m.cachedIndex.reset();
    m.cached.clear();
    try {
        auto plain = m.range->read(start, end, m.window);
        m.cached.append(plain.span());
    } catch (const crypto::vhf1::Error& e) {
        fail(e);
    }
    m.cachedIndex = index;
    if (index == m.contiguous) ++m.contiguous;
    if (m.contiguous == m.range->layout().chunkCount)
        crypto::IntegrityRegistry::instance().record(m.integrityKey, true);
}

std::size_t Vhf1FileReader::read(const uint64_t offset, const std::span<uint8_t> out) {
    std::scoped_lock lock(mutex_);
    auto& m = *impl_;
    if (m.failed) vh::vault::content::throwIntegrity(*m.failed, "Content");
    if (offset >= params_.plaintextSize || out.empty()) return 0;
    const auto n = static_cast<std::size_t>(std::min<uint64_t>(out.size(), params_.plaintextSize - offset));
    const auto c = m.range->header().chunkSize();
    std::size_t done = 0;
    try {
        while (done < n) {
            const auto pos = offset + done;
            const auto index = pos / c;
            loadChunk(index);
            const auto in = static_cast<std::size_t>(pos - index * c);
            const auto take = std::min(n - done, m.cached.size() - in);
            std::memcpy(out.data() + done, m.cached.data() + in, take);
            done += take;
        }
    } catch (...) {
        sodium_memzero(out.data(), n);  // a failed read returns nothing, not the authentic chunks before the bad one
        throw;
    }
    return n;
}

std::vector<uint8_t> Vhf1FileReader::readAllAuthenticated(const uint64_t maxBytes) {
    if (params_.plaintextSize > maxBytes) throw std::length_error("Content exceeds the allowed size");
    std::vector<uint8_t> out(static_cast<std::size_t>(params_.plaintextSize));
    try {
        if (read(0, out) != out.size()) throw IntegrityError("Content is shorter than its metadata");
    } catch (...) {
        sodium_memzero(out.data(), out.size());
        throw;
    }
    return out;
}

void Vhf1FileReader::requireAuthenticated() {
    std::scoped_lock lock(mutex_);
    auto& m = *impl_;
    if (m.failed) vh::vault::content::throwIntegrity(*m.failed, "Content");
    while (m.contiguous < m.range->layout().chunkCount) loadChunk(m.contiguous);
}

}
