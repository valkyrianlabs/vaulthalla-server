#include "fs/metadata/Magic.hpp"
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <magic.h>
#include <paths.h>  // generated: VH_MAGIC_DB_PATH

using namespace vh::fs::metadata;

Magic::Magic() {
    cookie = magic_open(MAGIC_MIME_TYPE);
    if (!cookie) throw std::runtime_error("Failed to create magic cookie");

    // Debian/Ubuntu's database, else the one the install ships (the macOS package bundles libmagic without
    // Homebrew's share/), else libmagic's own compiled-in default (nullptr: a Homebrew development build).
    constexpr const char* kDebianMagicDb = "/usr/share/misc/magic.mgc";
    std::error_code ec;
    const char* database = nullptr;
    for (const char* candidate : {kDebianMagicDb, VH_MAGIC_DB_PATH})
        if (std::filesystem::exists(candidate, ec)) { database = candidate; break; }
    if (magic_load(cookie, database) != 0) {
        std::string err = magic_error(cookie) ? magic_error(cookie) : "Unknown error";
        magic_close(cookie);
        throw std::runtime_error("Failed to load magic database: " + err);
    }
}

Magic::~Magic() {
    if (cookie) magic_close(cookie);
}

std::string Magic::mime_type(const std::string& path) const {
    if (path.empty()) throw std::invalid_argument("Cannot detect MIME type of empty path");

    std::scoped_lock lock(mutex_);
    const char* result = magic_file(cookie, path.c_str());
    if (!result) {
        const std::string err = magic_error(cookie) ? magic_error(cookie) : "Unknown error";
        throw std::runtime_error("magic_file failed: " + err);
    }
    return {result};
}

std::string Magic::mime_type_buffer(const std::string& buffer) const {
    if (buffer.empty()) throw std::invalid_argument("Cannot detect MIME type from empty buffer");

    std::scoped_lock lock(mutex_);
    const char* result = magic_buffer(cookie, buffer.data(), buffer.size());
    if (!result) {
        std::string err = magic_error(cookie) ? magic_error(cookie) : "Unknown error";
        throw std::runtime_error("magic_buffer failed: " + err);
    }
    return {result};
}

// Static interface
std::string Magic::get_mime_type(const std::string& path) {
    static Magic instance;
    return instance.mime_type(path);
}

std::string Magic::get_mime_type_from_buffer(const std::string& buffer) {
    static Magic instance;
    return instance.mime_type_buffer(buffer);
}

std::string Magic::get_mime_type_from_buffer(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) throw std::invalid_argument("Cannot detect MIME type from empty buffer");

    static Magic instance;
    return instance.mime_type_buffer(std::string(buffer.begin(), buffer.end()));
}
