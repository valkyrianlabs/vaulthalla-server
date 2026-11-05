#include "protocols/http/upload/Staging.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>

namespace vh::protocols::http::upload::staging {

namespace {

// A file through the FUSE mount: its bytes live in the inode's (encrypted) working copy while it is open and are
// sealed as an ordinary vault file when it is closed.
class MountBody final : public Body {
public:
    explicit MountBody(std::filesystem::path path) : path_(std::move(path)) {
        fd_ = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd_ < 0) throw std::runtime_error(std::string("Unable to open the upload staging file: ") + std::strerror(errno));
    }
    ~MountBody() override { discard(); }

    void append(const std::span<const uint8_t> data) override {
        if (fd_ < 0) throw std::runtime_error("The upload staging file is closed");
        const auto* p = data.data();
        std::size_t left = data.size();
        while (left) {
            const auto n = ::write(fd_, p, left);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw std::runtime_error(std::string("Writing the upload staging file failed: ") + std::strerror(errno));
            p += n;
            left -= static_cast<std::size_t>(n);
        }
    }

    void close() override {
        if (fd_ < 0) return;
        const int rc = ::close(fd_);
        fd_ = -1;
        if (rc != 0) throw std::runtime_error(std::string("Closing the upload staging file failed: ") + std::strerror(errno));
    }

    void discard() noexcept override {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
        if (path_.empty()) return;
        std::error_code ec;
        std::filesystem::remove(path_, ec);
        path_.clear();
    }

    [[nodiscard]] uint64_t size() const override {
        if (path_.empty()) throw std::runtime_error("The upload staging file was discarded");
        return std::filesystem::file_size(path_);
    }

    [[nodiscard]] fs::PlaintextSource source() const override {
        if (path_.empty()) throw std::runtime_error("The upload staging file was discarded");
        return fs::sourceOf(path_);
    }

private:
    std::filesystem::path path_;
    int fd_{-1};
};

}

std::string_view mode() noexcept { return "mount"; }

bool insideMount() noexcept { return true; }

std::filesystem::path pathFor(const std::filesystem::path& targetAbsPath, unsigned int, const std::string& name) {
    return targetAbsPath.parent_path() / name;
}

std::unique_ptr<Body> create(const std::filesystem::path& path) { return std::make_unique<MountBody>(path); }

void sweepAtStartup() {}

}
