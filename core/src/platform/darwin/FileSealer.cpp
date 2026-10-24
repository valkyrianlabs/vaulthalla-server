#include "platform/Sealer.hpp"
#include "platform/Durable.hpp"
#include "log/Registry.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// DEVELOPMENT backend: the secret is stored as-is in a 0600 file inside a 0700 directory. Nothing binds it to this
// machine, so it protects exactly as well as the state directory's permissions (and FileVault at rest). It exists
// so the macOS daemon runs end to end while the production backend (Secure Enclave or keychain) is decided; it is
// reported as "file" by KeyProvider::backend() and in health output.
namespace vh::platform::sealer {

namespace {

std::filesystem::path keyFile(const std::filesystem::path& dir, const std::string& name) {
    return dir / (name + ".key");
}

void warnOnce() {
    static std::atomic<bool> warned{false};
    if (!warned.exchange(true))
        log::Registry::crypto()->warn("[Sealer] Using the development 'file' secret backend: sealed secrets are "
                                      "plain 0600 files with no hardware binding");
}

[[noreturn]] void fail(const std::string& what, const std::filesystem::path& p, const int err) {
    throw std::runtime_error(what + " " + p.string() + ": " + std::strerror(err));
}

}

std::string_view backend() noexcept { return "file"; }

void seal(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret) {
    warnOnce();
    std::filesystem::create_directories(dir);
    if (::chmod(dir.c_str(), 0700) != 0) fail("chmod", dir, errno);

    // Write a sibling, fsync, then rename over the old file: a crash leaves the old secret or the new one.
    const auto target = keyFile(dir, name);
    auto tmp = target;
    tmp += ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail("create", tmp, errno);
    std::size_t off = 0;
    while (off < secret.size()) {
        const ssize_t n = ::write(fd, secret.data() + off, secret.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            const int err = errno;
            ::close(fd);
            fail("write", tmp, err);
        }
        off += static_cast<std::size_t>(n);
    }
    if (durable::sync(fd) != 0) {
        const int err = errno;
        ::close(fd);
        fail("fsync", tmp, err);
    }
    ::close(fd);
    if (::rename(tmp.c_str(), target.c_str()) != 0) fail("rename", target, errno);
}

std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name) {
    warnOnce();
    const auto path = keyFile(dir, name);
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("open", path, errno);
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
            fail("read", path, n < 0 ? errno : EIO);
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return out;
}

bool present(const std::filesystem::path& dir, const std::string& name) {
    return std::filesystem::exists(keyFile(dir, name));
}

bool complete(const std::filesystem::path& dir, const std::string& name) {
    return present(dir, name);
}

}
