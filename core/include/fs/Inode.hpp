#pragma once

#include <cstdint>

namespace vh::fs {

// Inode numbers the FS cache hands out (FUSE_ROOT_ID = 1, then 2, 3, ...). The FUSE bridge passes them to the
// kernel as fuse_ino_t, which is the same type (fuse/Bridge.cpp asserts it); everything outside the kernel bridge
// uses this alias so storage, the FS cache and sync build without libfuse.
using Inode = std::uint64_t;

// The mount root's inode (FUSE_ROOT_ID; fuse/Bridge.cpp asserts they match).
inline constexpr Inode kRootInode = 1;

}
