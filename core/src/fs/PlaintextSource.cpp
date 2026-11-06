#include "fs/PlaintextSource.hpp"

#include "crypto/ScratchFile.hpp"
#include "fs/metadata/Magic.hpp"
#include "fs/model/Path.hpp"
#include "log/Registry.hpp"

#include <sodium.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace vh::fs {

namespace {

// Zeroes a plaintext buffer when it goes out of scope.
struct Wiped {
    std::vector<uint8_t> bytes;
    explicit Wiped(const std::size_t n) : bytes(n) {}
    ~Wiped() { sodium_memzero(bytes.data(), bytes.size()); }
    Wiped(const Wiped&) = delete;
    Wiped& operator=(const Wiped&) = delete;
};

struct OwnedFd {
    int fd{-1};
    explicit OwnedFd(const int f) : fd(f) {}
    ~OwnedFd() { if (fd >= 0) ::close(fd); }
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
};

}

PlaintextSource sourceOf(const crypto::ScratchFile& file) {
    return {.size = file.size(),
            .read = [&file](const uint64_t offset, const std::span<uint8_t> out) { return file.read(offset, out); }};
}

PlaintextSource sourceOf(const std::filesystem::path& path) {
    auto fd = std::make_shared<OwnedFd>(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd->fd < 0) throw std::system_error(errno, std::generic_category(), "open " + path.string());
    const auto size = std::filesystem::file_size(path);
    return {.size = size, .read = [fd](const uint64_t offset, const std::span<uint8_t> out) -> std::size_t {
        for (;;) {
            const auto n = ::pread(fd->fd, out.data(), out.size(), static_cast<off_t>(offset));
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) throw std::system_error(errno, std::generic_category(), "read plaintext source");
            return static_cast<std::size_t>(n);
        }
    }};
}

void forEachChunk(const PlaintextSource& source, const std::function<void(std::span<const uint8_t>)>& sink) {
    Wiped buffer(64 * 1024);
    uint64_t offset = 0;
    while (offset < source.size) {
        const auto want = static_cast<std::size_t>(std::min<uint64_t>(buffer.bytes.size(), source.size - offset));
        const auto got = source.read(offset, {buffer.bytes.data(), want});
        if (got == 0) throw std::runtime_error("The staged content ended before its size");
        sink({buffer.bytes.data(), got});
        offset += got;
    }
}

std::string mimeTypeOf(const PlaintextSource& source, const std::filesystem::path& fallbackName) {
    if (source.size == 0) return model::inferMimeTypeFromPath(fallbackName);
    try {
        Wiped head(static_cast<std::size_t>(std::min<uint64_t>(source.size, metadata::Magic::sniff_limit())));
        std::size_t filled = 0;
        while (filled < head.bytes.size()) {
            const auto got = source.read(filled, std::span(head.bytes).subspan(filled));
            if (got == 0) break;
            filled += got;
        }
        if (filled == 0) return model::inferMimeTypeFromPath(fallbackName);
        return metadata::Magic::get_mime_type_from_bytes({head.bytes.data(), filled});
    } catch (const std::exception& e) {
        log::Registry::fs()->warn("[Filesystem] Could not detect the MIME type of staged content: {}", e.what());
        return model::inferMimeTypeFromPath(fallbackName);
    }
}

}
