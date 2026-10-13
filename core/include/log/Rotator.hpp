#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <mutex>
#include <vector>

namespace vh::log {

constexpr std::uint64_t operator""_KiB(unsigned long long v) { return v * 1024ULL; }
constexpr std::uint64_t operator""_MiB(unsigned long long v) { return v * 1024ULL * 1024ULL; }
constexpr std::uint64_t operator""_GiB(unsigned long long v) { return v * 1024ULL * 1024ULL * 1024ULL; }

class Rotator {
public:
    enum class Compression { None, Gzip, Zstd };

    struct Options {
        // Active file, e.g. /var/log/vaulthalla/vaulthalla.log
        std::filesystem::path active_path;

        // Rotation triggers
        std::optional<std::uint64_t> max_bytes;                 // rotate when size >= max_bytes
        std::optional<std::chrono::seconds> max_interval;       // rotate when now - mtime >= max_interval

        // Prune policy (new)
        std::chrono::days retention_days{std::chrono::days{30}};       // drop files older than this
        std::optional<std::uint64_t> max_retained_size;                 // cap total size of rotated files
        bool strict_retention = false;                                   // if true, ignore size cap within retention window

        // Compression (applied to rotated file)
        Compression compression = Compression::None;
        bool ignore_compress_errors = true;

        // Hooks
        std::function<void()> on_reopen = nullptr;                       // called after rename of active file
        std::function<void(std::string_view)> diag_log = nullptr;        // lightweight diagnostics

        // Rotated file matcher. Default: "<base>.<YYYYMMDD-HHMMSS><ext>[.gz|.zst]"
        std::function<bool(const std::filesystem::path&)> rotated_filter = nullptr;

        // Where to place an advisory lock to avoid concurrent rotations
        std::optional<std::filesystem::path> lock_dir = std::nullopt;
    };

    explicit Rotator(Options opts);

    // Rotation / pruning API
    void maybeRotate() const;
    void forceRotate() const;
    void pruneOnly() const;

private:
    enum class RotateReason { None, Size, Interval, Forced };

    Options opts_;
    std::filesystem::path dir_;
    std::string base_;
    std::string ext_;
    mutable std::mutex m_;

    // Helpers
    static std::string escapeRx(const std::string& s);
    static std::chrono::system_clock::time_point to_sys(std::filesystem::file_time_type tp);
    RotateReason rotationReason() const;
    static std::string nowStamp();
    std::filesystem::path rotatedName() const;

    class FileLock {
    public:
        explicit FileLock(std::filesystem::path p);
        ~FileLock();
        FileLock(const FileLock&) = delete;
        FileLock& operator=(const FileLock&) = delete;
    private:
        std::filesystem::path path_;
#ifdef __linux__
        int fd_{-1};
#endif
    };

    void rotateImpl(RotateReason why) const;
    bool compressFile(const std::filesystem::path& src, Compression c) const;
    static std::string shellQuote(const std::string& s);
    void pruneImpl() const;

    static const char* reasonStr(RotateReason r);
};

}
