#pragma once

namespace vh::platform::durable {

// Flushes a file's (or a directory's) data and metadata to stable storage, so it survives a power loss: the step
// every write-temp / commit-row / rename sequence relies on. Linux: fsync(2). macOS: fsync only pushes to the drive,
// whose cache can still lose or reorder the writes, so this is fcntl(F_FULLFSYNC), falling back to fsync only where
// the file system doesn't support it. 0, or -1 with errno set, like fsync.
[[nodiscard]] int sync(int fd) noexcept;

}
