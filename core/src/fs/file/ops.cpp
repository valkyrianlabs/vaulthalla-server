#include "fs/ops/file.hpp"
#include "storage/Engine.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "runtime/Deps.hpp"
#include "log/Registry.hpp"
#include "fs/cache/Registry.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>

#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <random>
#include <array>
#include <cmath>
#include <fmt/format.h>

using namespace vh::fs::model;

namespace vh::fs::ops {

std::vector<uint8_t> readFileToVector(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("Failed to open file: " + path.string());

    const std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!in.read(reinterpret_cast<char*>(buffer.data()), size))
        throw std::runtime_error("Failed to read file: " + path.string());
    in.close();

    return buffer;
}

std::string readFileToString(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("Failed to open file: " + path.string());

    const std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::string buffer(size, '\0');
    if (!in.read(buffer.data(), size))
        throw std::runtime_error("Failed to read file: " + path.string());
    in.close();

    return buffer;
}

namespace {

[[noreturn]] void throwErrnoAt(const int err, const std::string& what, const std::filesystem::path& path) {
    throw std::system_error(err, std::generic_category(), what + ": " + path.string());
}

void fsyncOpened(const std::filesystem::path& path, const int flags, const char* what) {
    const int fd = ::open(path.c_str(), flags | O_CLOEXEC);
    if (fd < 0) throwErrnoAt(errno, std::string("open for ") + what, path);
    const int rc = ::fsync(fd);
    const int err = errno;
    ::close(fd);
    if (rc < 0) throwErrnoAt(err, what, path);
}

// Permission bits a replacement keeps: the existing file's, or owner-only for a new file.
mode_t replacementMode(const std::filesystem::path& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) return st.st_mode & 07777;
    return 0600;
}

void createPrivateExclusive(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) throwErrnoAt(errno, "create", path);
    ::close(fd);
}

void writeAllToFd(const int fd, std::span<const uint8_t> bytes, const std::filesystem::path& path) {
    while (!bytes.empty()) {
        const auto written = ::write(fd, bytes.data(), bytes.size());
        if (written < 0) {
            if (errno == EINTR) continue;
            throwErrnoAt(errno, "write", path);
        }
        bytes = bytes.subspan(static_cast<std::size_t>(written));
    }
}

}

void fsyncFile(const std::filesystem::path& path) { fsyncOpened(path, O_RDONLY, "fsync"); }

void fsyncDirectory(const std::filesystem::path& dir) {
    fsyncOpened(dir.empty() ? std::filesystem::path(".") : dir, O_RDONLY | O_DIRECTORY, "fsync directory");
}

void writeFileExclusive(const std::filesystem::path& absPath, const std::span<const uint8_t> bytes, const mode_t mode) {
    const int fd = ::open(absPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) throwErrnoAt(errno, "create", absPath);
    try {
        writeAllToFd(fd, bytes, absPath);
        // The umask may have narrowed the create mode: set exactly what was asked for.
        if (::fchmod(fd, mode) < 0) throwErrnoAt(errno, "chmod", absPath);
        if (::fsync(fd) < 0) throwErrnoAt(errno, "fsync", absPath);
    } catch (...) {
        ::close(fd);
        std::error_code ec;
        std::filesystem::remove(absPath, ec);
        throw;
    }
    if (::close(fd) < 0) {
        const int err = errno;
        std::error_code ec;
        std::filesystem::remove(absPath, ec);
        throwErrnoAt(err, "close", absPath);
    }
}

void replaceFileAtomic(const std::filesystem::path& absPath,
                       const std::function<void(const std::filesystem::path& tempPath)>& produce) {
    if (absPath.empty() || !absPath.has_filename()) throw std::invalid_argument("replaceFileAtomic: no file name");

    const auto dir = absPath.parent_path();
    const auto mode = replacementMode(absPath);
    const auto temp = dir / (absPath.filename().string() + ".vh-tmp-" + generate_random_suffix(12));

    createPrivateExclusive(temp);
    try {
        produce(temp);
        if (::chmod(temp.c_str(), mode) < 0) throwErrnoAt(errno, "chmod", temp);
        fsyncFile(temp);
        std::filesystem::rename(temp, absPath);
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove(temp, ec);
        throw;
    }

    try {
        fsyncDirectory(dir);
    } catch (const std::exception& e) {
        log::Registry::fs()->error("[replaceFileAtomic] Replaced {} but could not fsync its directory: {}",
                                   absPath.string(), e.what());
    }
}

void writeFileAtomic(const std::filesystem::path& absPath, const std::span<const uint8_t> bytes) {
    replaceFileAtomic(absPath, [&](const std::filesystem::path& temp) {
        const int fd = ::open(temp.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0) throwErrnoAt(errno, "open", temp);
        try {
            writeAllToFd(fd, bytes, temp);
        } catch (...) {
            ::close(fd);
            throw;
        }
        if (::close(fd) < 0) throwErrnoAt(errno, "close", temp);
    });
}


std::string generate_random_suffix(const size_t length) {
    static constexpr char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    thread_local std::mt19937 rng{std::random_device{}()};
    thread_local std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) result += charset[dist(rng)];
    return result;
}

std::vector<uint8_t> decrypt_file_to_memory(const unsigned int /*vault_id*/,
                                            const std::filesystem::path& rel_path,
                                            const std::shared_ptr<storage::Engine>& engine) {
    const auto abs_path = engine->vaultPathToFusePath(rel_path);
    const auto entry = runtime::Deps::get().fsCache->getEntry(abs_path);
    if (!entry) {
        log::Registry::storage()->error("[decrypt_file_to_memory] Entry not found for path: {}", abs_path.string());
        throw std::runtime_error("Entry not found for path: " + abs_path.string());
    }

    const auto file = std::dynamic_pointer_cast<File>(entry);
    if (!file) throw std::runtime_error("Entry is not a file: " + abs_path.string());
    return decrypt_file_to_memory(file, engine);
}

std::vector<uint8_t> decrypt_file_to_memory(const std::shared_ptr<File>& file,
                                            const std::shared_ptr<storage::Engine>& engine) {
    if (!file) throw std::invalid_argument("Cannot decrypt a null file");
    if (!engine) throw std::invalid_argument("Cannot decrypt file without storage engine");

    std::vector<uint8_t> plaintext;
    try {
        plaintext = engine->decrypt(file);
    } catch (...) {
        if (!file->encryption_iv.empty()) throw;
        plaintext = readFileToVector(file->backing_path);
    }
    return plaintext;
}

bool isProbablyEncrypted(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const auto size = in.tellg();
    return size >= 12 + 16;  // IV + tag = minimum
}

std::string bytesToSize(uintmax_t bytes) {
    // Units (binary / IEC-ish labels would be KiB/MiB/GiB/TiB; using KB/MB... to match your style)
    static constexpr std::array<const char*, 5> suffix = {"B", "KB", "MB", "GB", "TB"};

    // Fast path: tiny
    if (bytes < 1024) return std::to_string(bytes) + "B";

    // Use double for scaling; uintmax_t may be huge.
    auto value = static_cast<double>(bytes);
    std::size_t unit = 0;

    // Divide until we fit, capped at TB so we never go past suffix array.
    while (value >= 1024.0 && unit + 1 < suffix.size()) {
        value /= 1024.0;
        ++unit;
    }

    // You can choose formatting:
    // - no decimals for KB+ when it's an integer-ish
    // - 1 decimal for non-integers (looks nicer)
    if (value >= 100.0 || std::fabs(value - std::round(value)) < 0.05)
        return fmt::format("{:.0f}{}", value, suffix[unit]);
    return fmt::format("{:.1f}{}", value, suffix[unit]);
}


std::filesystem::path contentSidecarPath(const std::filesystem::path& backing) {
    auto sidecar = backing;
    sidecar += std::string(kContentSidecarSuffix);
    return sidecar;
}

}
