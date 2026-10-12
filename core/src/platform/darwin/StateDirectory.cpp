#include "platform/StateDirectory.hpp"

#include <cerrno>
#include <cstring>
#include <system_error>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace vh::platform::state {

namespace {

std::string errnoText(const std::string& what, const std::filesystem::path& p, const int err) {
    return what + " " + p.string() + ": " + std::strerror(err);
}

// A directory another local account could swap out from under us: writable by group or others, unless it's a
// root-owned sticky directory (like /private/tmp), where only an entry's owner may replace it.
bool replaceableByOthers(const struct stat& st) {
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) == 0) return false;
    return !((st.st_mode & S_ISVTX) && st.st_uid == 0);
}

}

std::string restrictToService(const std::filesystem::path& root) {
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec) return "create " + root.string() + ": " + ec.message();

    // Every ancestor of the canonical location must be safe from other accounts.
    const auto canonicalParent = std::filesystem::canonical(root.parent_path(), ec);
    if (ec) return "resolve " + root.parent_path().string() + ": " + ec.message();
    for (auto p = canonicalParent; ; p = p.parent_path()) {
        struct stat st{};
        if (::lstat(p.c_str(), &st) != 0) return errnoText("stat", p, errno);
        if (replaceableByOthers(st)) return p.string() + " is writable by other accounts";
        if (p == p.parent_path()) break;
    }

    // The root itself: never a symlink, a directory owned by this process's uid, then owner-only. lstat gives the
    // clear diagnostic; O_NOFOLLOW keeps a swap between the two calls from being followed.
    struct stat link{};
    if (::lstat(root.c_str(), &link) != 0) return errnoText("stat", root, errno);
    if (S_ISLNK(link.st_mode)) return "refusing symlinked state directory " + root.string();
    const int fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errnoText("open", root, errno);
    struct stat st{};
    std::string problem;
    if (::fstat(fd, &st) != 0) problem = errnoText("stat", root, errno);
    else if (st.st_uid != ::geteuid())
        problem = root.string() + " is owned by uid " + std::to_string(st.st_uid) + ", not the service uid " +
                  std::to_string(::geteuid());
    else if (::fchmod(fd, S_IRWXU) != 0) problem = errnoText("chmod 0700", root, errno);
    else if (::fstat(fd, &st) != 0 || (st.st_mode & 07777) != S_IRWXU) problem = root.string() + " did not become 0700";
    ::close(fd);
    return problem;
}

}
