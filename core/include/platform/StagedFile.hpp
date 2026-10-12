#pragma once

namespace vh::platform::staged {

// An unnamed file in `dir` that becomes visible only when linkUnnamed() links it (Linux O_TMPFILE), so a crash
// leaves nothing behind. Returns -1 with errno set where the OS or filesystem has none (always on macOS); callers
// then stage a named 0600 O_EXCL sibling instead.
[[nodiscard]] int openUnnamed(const char* dir) noexcept;

// Links an openUnnamed() descriptor at `target`, never replacing an existing file. 0, or -1 with errno (EEXIST:
// someone stored the target meanwhile).
[[nodiscard]] int linkUnnamed(int fd, const char* target) noexcept;

}
