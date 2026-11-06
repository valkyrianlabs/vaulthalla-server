#pragma once

// A per-process scratch root under the temp directory. Several test binaries run at once on a shared box (other
// worktrees, harness runs as root), so a fixed name like /tmp/vh_sync_idle collides: one run deletes another's
// tree, or a root-owned leftover can't be removed ("cannot remove all: Permission denied").

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>

namespace vh::test {

inline std::filesystem::path uniqueTempRoot(const std::string& label) {
    static std::atomic<unsigned> n{0};
    return std::filesystem::temp_directory_path() /
           (label + "_" + std::to_string(::getpid()) + "_" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
            std::to_string(n.fetch_add(1)));
}

}
