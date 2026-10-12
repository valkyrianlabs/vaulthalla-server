#pragma once

#include <sys/stat.h>
#include <ctime>

namespace vh::platform {

// struct stat's timestamps: st_atim/st_mtim/st_ctim on Linux, st_atimespec/... on macOS.
#if defined(__APPLE__)
inline timespec& atime(struct stat& st) noexcept { return st.st_atimespec; }
inline timespec& mtime(struct stat& st) noexcept { return st.st_mtimespec; }
inline timespec& ctime(struct stat& st) noexcept { return st.st_ctimespec; }
inline const timespec& atime(const struct stat& st) noexcept { return st.st_atimespec; }
inline const timespec& mtime(const struct stat& st) noexcept { return st.st_mtimespec; }
inline const timespec& ctime(const struct stat& st) noexcept { return st.st_ctimespec; }
#else
inline timespec& atime(struct stat& st) noexcept { return st.st_atim; }
inline timespec& mtime(struct stat& st) noexcept { return st.st_mtim; }
inline timespec& ctime(struct stat& st) noexcept { return st.st_ctim; }
inline const timespec& atime(const struct stat& st) noexcept { return st.st_atim; }
inline const timespec& mtime(const struct stat& st) noexcept { return st.st_mtim; }
inline const timespec& ctime(const struct stat& st) noexcept { return st.st_ctim; }
#endif

}
