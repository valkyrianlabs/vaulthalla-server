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

// A short name suffix unique in this process and unlikely to repeat across runs on one database: the run's clock
// (mod 100000), `letter`, a counter.
inline std::string uniqueTag(const char letter) {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + letter + std::to_string(n.fetch_add(1));
}

// A scratch directory under uniqueTempRoot(label), removed with the object.
class TempDir {
public:
    explicit TempDir(const std::string& label = "vh_test") : path_(uniqueTempRoot(label)) {
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

}
