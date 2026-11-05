#include "log/Redact.hpp"

#include <sodium.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <stdexcept>

namespace vh::log {

namespace {

std::atomic<FilePaths> g_filePaths{FilePaths::Ids};

const std::array<unsigned char, crypto_shorthash_KEYBYTES>& tagKey() {
    static std::array<unsigned char, crypto_shorthash_KEYBYTES> key{};
    static std::once_flag once;
    std::call_once(once, [] {
        if (sodium_init() < 0) throw std::runtime_error("libsodium failed to initialize");
        randombytes_buf(key.data(), key.size());
    });
    return key;
}

std::string tagOf(const std::string& value) {
    std::array<unsigned char, crypto_shorthash_BYTES> out{};
    crypto_shorthash(out.data(), reinterpret_cast<const unsigned char*>(value.data()), value.size(), tagKey().data());
    std::string hex(out.size() * 2, '0');
    for (size_t i = 0; i < out.size(); ++i) std::snprintf(hex.data() + i * 2, 3, "%02x", out[i]);
    return "path#" + hex;
}

}

void setFilePaths(const FilePaths mode) noexcept { g_filePaths.store(mode, std::memory_order_relaxed); }

FilePaths filePaths() noexcept { return g_filePaths.load(std::memory_order_relaxed); }

std::string path(const std::filesystem::path& p) {
    if (filePaths() == FilePaths::Full) return p.string();
    return tagOf(p.lexically_normal().string());
}

std::string file(const std::optional<uint64_t> entryId, const std::filesystem::path& p) {
    if (!entryId || *entryId == 0) return path(p);
    auto out = "entry " + std::to_string(*entryId);
    if (filePaths() == FilePaths::Full) out += " (" + p.string() + ")";
    return out;
}

}
