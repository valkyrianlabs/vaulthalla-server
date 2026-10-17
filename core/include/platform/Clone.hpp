#pragma once

namespace vh::platform::clone {

// Creates `target` (0600, never replacing an existing name) as a copy-on-write clone of `source`: Linux FICLONE
// (btrfs, XFS with reflink, bcachefs, …), macOS clonefile(2) (APFS). No data is copied. 0, or -1 with errno set
// (EOPNOTSUPP/ENOTTY/EXDEV/EINVAL where the filesystem can't clone): callers fall back to a copy. On failure nothing is
// left at `target`.
[[nodiscard]] int cloneFile(const char* source, const char* target) noexcept;

}
