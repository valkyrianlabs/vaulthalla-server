#include "platform/darwin/SealerBackends.hpp"
#include "platform/Durable.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// DEVELOPMENT backend: the secret is stored as-is in a 0600 file inside a 0700 directory. Nothing binds it to this
// machine, so it protects exactly as well as the state directory's permissions (and FileVault at rest). It is used
// where the build asks for it (-Ddarwin_sealer=file) or the Mac has no Secure Enclave, and is reported as "file".
namespace vh::platform::sealer {

namespace {

[[noreturn]] void failFile(const std::string& what, const std::filesystem::path& p, const int err) {
    throw std::runtime_error(what + " " + p.string() + ": " + std::strerror(err));
}

void syncDirectory(const std::filesystem::path& dir) {
    const int fd = ::open(dir.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (fd < 0) failFile("open", dir, errno);
    const int rc = durable::sync(fd);
    const int err = errno;
    ::close(fd);
    if (rc != 0) failFile("fsync", dir, err);
}

}

void writePrivateFile(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    const auto dir = path.parent_path();
    std::filesystem::create_directories(dir);
    if (::chmod(dir.c_str(), 0700) != 0) failFile("chmod", dir, errno);

    // Write a sibling, flush it, then rename over the old file: a crash leaves the old secret or the new one.
    auto tmp = path;
    tmp += ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) failFile("create", tmp, errno);
    std::size_t off = 0;
    while (off < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            const int err = errno;
            ::close(fd);
            failFile("write", tmp, err);
        }
        off += static_cast<std::size_t>(n);
    }
    if (durable::sync(fd) != 0) {
        const int err = errno;
        ::close(fd);
        failFile("fsync", tmp, err);
    }
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) failFile("rename", path, errno);
    syncDirectory(dir);
}

std::vector<uint8_t> readPrivateFile(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) failFile("open", path, errno);
    struct stat st{};
    if (::fstat(fd, &st) != 0 || (st.st_mode & 077) != 0) {
        ::close(fd);
        throw std::runtime_error("sealed secret " + path.string() + " is readable by group or others; refusing");
    }
    std::vector<uint8_t> out(static_cast<std::size_t>(st.st_size));
    std::size_t off = 0;
    while (off < out.size()) {
        const ssize_t n = ::read(fd, out.data() + off, out.size() - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            ::close(fd);
            failFile("read", path, n < 0 ? errno : EIO);
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return out;
}

void removeDurably(const std::filesystem::path& path) {
    if (::unlink(path.c_str()) != 0) {
        if (errno == ENOENT) return;
        failFile("unlink", path, errno);
    }
    syncDirectory(path.parent_path());
}

namespace file {

std::filesystem::path path(const std::filesystem::path& dir, const std::string& name) {
    return dir / (name + ".key");
}

void seal(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret) {
    writePrivateFile(path(dir, name), secret);
}

std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name) {
    return readPrivateFile(path(dir, name));
}

}

}
