#include "storage/PlaintextReader.hpp"

#include "fs/model/File.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <fmt/format.h>

namespace vh::storage {

std::string Generation::sourceId() const {
    if (!iv_b64.empty()) return iv_b64;
    // Every empty file has the same (zero) bytes, so its generation doesn't depend on updated_at: renaming, moving or
    // touching an empty file keeps its validator (entry content_version, #257). A legacy plaintext file has nothing
    // else that changes with its content, until repairAtRest seals it.
    if (size == 0) return "plain:0";
    return fmt::format("plain:{}:{}", size, static_cast<long long>(updated_at));
}

std::string Generation::etag() const {
    const auto material = fmt::format("{}|{}|{}", sourceId(), key_version, size);
    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(material.data()), material.size());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(16);
    for (std::size_t i = 0; i < 8; ++i) {
        hex.push_back(kHex[digest[i] >> 4]);
        hex.push_back(kHex[digest[i] & 0x0f]);
    }
    return fmt::format("\"g{}-{}\"", file_id, hex);
}

Generation generationOf(const ::vh::fs::model::File& file) {
    return Generation{
        .vault_id = static_cast<uint32_t>(file.vault_id.value_or(0)),
        .file_id = file.id,
        .iv_b64 = file.encryption_iv,
        .key_version = file.encryption_iv.empty() ? 0u : file.encrypted_with_key_version,
        .size = file.size_bytes,
        .updated_at = file.updated_at
    };
}

std::vector<uint8_t> PlaintextReader::readAllAuthenticated(const uint64_t maxBytes) {
    const auto total = size();
    if (total > maxBytes) throw std::length_error("Content exceeds the allowed size");
    std::vector<uint8_t> out(static_cast<std::size_t>(total));
    std::size_t done = 0;
    while (done < out.size()) {
        const auto got = read(done, std::span<uint8_t>(out.data() + done, out.size() - done));
        if (got == 0) throw IntegrityError("Content is shorter than its metadata");
        done += got;
    }
    return out;
}

std::vector<uint8_t> readAll(PlaintextReader& reader, const uint64_t maxBytes) {
    return reader.readAllAuthenticated(maxBytes);
}

}
