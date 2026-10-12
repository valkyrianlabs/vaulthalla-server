#include "storage/GcmFileReader.hpp"
#include "platform/FileTime.hpp"

#include "crypto/util/Gcm.hpp"

#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace vh::storage {

namespace {

std::atomic<IntegrityPolicy> defaultIntegrity{IntegrityPolicy::Optimistic};
std::atomic<RemoteFetchPolicy> defaultRemote{RemoteFetchPolicy::Hydrate};

[[nodiscard]] crypto::util::GcmKey keySpan(const crypto::SecretKeyPtr& key) { return key->bytes(); }

}

void setDefaultIntegrityPolicy(const IntegrityPolicy policy) {
    if (policy != IntegrityPolicy::FromConfig) defaultIntegrity.store(policy);
}

void setDefaultRemotePolicy(const RemoteFetchPolicy policy) {
    if (policy != RemoteFetchPolicy::FromConfig) defaultRemote.store(policy);
}

IntegrityPolicy resolveIntegrityPolicy(const IntegrityPolicy policy) {
    return policy == IntegrityPolicy::FromConfig ? defaultIntegrity.load() : policy;
}

RemoteFetchPolicy resolveRemotePolicy(const RemoteFetchPolicy policy) {
    return policy == RemoteFetchPolicy::FromConfig ? defaultRemote.load() : policy;
}

GcmFileReader::GcmFileReader(Params params) : params_(std::move(params)) {
    fd_ = ::open(params_.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd_ < 0) throw std::system_error(errno, std::generic_category(), "open " + params_.path.string());

    struct stat st{};
    if (::fstat(fd_, &st) != 0) {
        const auto err = errno;
        ::close(fd_);
        throw std::system_error(err, std::generic_category(), "fstat " + params_.path.string());
    }

    if (!params_.expectedHeader.empty()) {
        std::vector<uint8_t> header(params_.expectedHeader.size());
        const auto got = ::pread(fd_, header.data(), header.size(), 0);
        if (got != static_cast<ssize_t>(header.size()) || header != params_.expectedHeader) {
            ::close(fd_);
            fd_ = -1;
            throw IntegrityError("Content changed while it was being opened");
        }
    }

    const auto expected = params_.dataOffset + params_.plaintextSize + (params_.key ? crypto::util::AES_TAG_SIZE : 0);
    if (static_cast<uint64_t>(st.st_size) != expected) {
        ::close(fd_);
        // A size mismatch is either a concurrent replacement or damage; never serve it.
        throw IntegrityError("Stored size of " + params_.path.filename().string() + " does not match its metadata");
    }

    if (!params_.key) return;  // unencrypted legacy/empty file: nothing to authenticate

    integrityKey_ = crypto::IntegrityKey{
        .domain = params_.integrityDomain,
        .iv_b64 = params_.generation.iv_b64,
        .key_version = params_.generation.key_version,
        .dev = static_cast<uint64_t>(st.st_dev),
        .ino = static_cast<uint64_t>(st.st_ino),
        .size = static_cast<uint64_t>(st.st_size),
        .mtime_ns = static_cast<int64_t>(platform::mtime(st).tv_sec) * 1'000'000'000 + platform::mtime(st).tv_nsec
    };

    if (params_.strict) {
        ensureTicket();
        if (const auto state = ticket_->wait(); state != crypto::IntegrityState::Verified) {
            ::close(fd_);
            fd_ = -1;
            throw IntegrityError(state == crypto::IntegrityState::Superseded
                                     ? "Content changed while it was being verified"
                                     : "Content failed integrity verification");
        }
    }
}

void GcmFileReader::ensureTicket() {
    if (ticket_ || !params_.key) return;

    struct OwnedFd {
        explicit OwnedFd(const int f) : fd(f) {}
        OwnedFd(const OwnedFd&) = delete;
        OwnedFd& operator=(const OwnedFd&) = delete;
        ~OwnedFd() { if (fd >= 0) ::close(fd); }
        int fd;
    };
    // The verifier owns a duplicate descriptor so it can outlive this reader.
    const int dup = ::fcntl(fd_, F_DUPFD_CLOEXEC, 0);
    if (dup < 0) throw std::system_error(errno, std::generic_category(), "dup for verification");
    auto owned = std::make_shared<OwnedFd>(dup);

    auto verifier = [owned, key = params_.key, iv = params_.iv, aad = params_.aad, offset = params_.dataOffset,
                     size = params_.plaintextSize]() {
        return crypto::util::gcmVerifyFd(owned->fd, offset, size, key->bytes(), iv, aad);
    };
    ticket_ = crypto::IntegrityRegistry::instance().ensure(integrityKey_, std::move(verifier), params_.stillCurrent);
}

GcmFileReader::~GcmFileReader() {
    if (fd_ >= 0) ::close(fd_);
}

crypto::IntegrityState GcmFileReader::integrityState() const {
    return ticket_ ? ticket_->state() : crypto::IntegrityState::Verified;
}

void GcmFileReader::throwIfFailed() const {
    if (!ticket_) return;
    const auto state = ticket_->state();
    if (state == crypto::IntegrityState::Failed) throw IntegrityError("Content failed integrity verification");
    if (state == crypto::IntegrityState::Superseded) throw IntegrityError("Content changed while it was being read");
}

std::size_t GcmFileReader::preadFully(const uint64_t fileOffset, const std::span<uint8_t> out) const {
    std::size_t done = 0;
    while (done < out.size()) {
        const auto got = ::pread(fd_, out.data() + done, out.size() - done, static_cast<off_t>(fileOffset + done));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "pread " + params_.path.filename().string());
        }
        if (got == 0) break;
        done += static_cast<std::size_t>(got);
    }
    return done;
}

std::size_t GcmFileReader::read(const uint64_t offset, const std::span<uint8_t> out) {
    ensureTicket();
    throwIfFailed();
    if (offset >= params_.plaintextSize || out.empty()) return 0;
    const auto want = static_cast<std::size_t>(std::min<uint64_t>(out.size(), params_.plaintextSize - offset));
    const auto region = out.first(want);

    const auto got = preadFully(params_.dataOffset + offset, region);
    if (got != want) throw IntegrityError("Content is shorter than its metadata");

    if (params_.key)
        crypto::util::gcmCtrDecryptAt(keySpan(params_.key), params_.iv, offset, region, region);

    // Never hand out bytes once the generation is known bad, even if this read raced the verdict.
    if (ticket_ && ticket_->failed()) {
        sodium_memzero(region.data(), region.size());
        throwIfFailed();
    }
    return want;
}

void GcmFileReader::requireAuthenticated() {
    if (!params_.key) return;  // unencrypted legacy/empty file: nothing to authenticate
    ensureTicket();
    if (const auto state = ticket_->wait(); state != crypto::IntegrityState::Verified)
        throw IntegrityError(state == crypto::IntegrityState::Superseded ? "Content changed while it was being read"
                                                                         : "Content failed integrity verification");
}

std::vector<uint8_t> GcmFileReader::readAllAuthenticated(const uint64_t maxBytes) {
    throwIfFailed();
    if (params_.plaintextSize > maxBytes) throw std::length_error("Content exceeds the allowed size");
    std::vector<uint8_t> out(static_cast<std::size_t>(params_.plaintextSize));
    if (!params_.key) {
        if (preadFully(params_.dataOffset, out) != out.size()) throw IntegrityError("Content is shorter than its metadata");
        return out;
    }

    std::vector<uint8_t> sealed(out.size() + crypto::util::AES_TAG_SIZE);
    if (preadFully(params_.dataOffset, sealed) != sealed.size()) throw IntegrityError("Content is shorter than its metadata");
    const auto bodySize = out.size();
    const bool ok = crypto::util::gcmDecrypt(
        keySpan(params_.key), params_.iv, std::span<const uint8_t>(sealed.data(), bodySize),
        std::span<const uint8_t, crypto::util::AES_TAG_SIZE>(sealed.data() + bodySize, crypto::util::AES_TAG_SIZE),
        out, params_.aad);
    crypto::IntegrityRegistry::instance().record(integrityKey_, ok);
    if (!ok) throw IntegrityError("Content failed integrity verification");
    return out;
}

}
