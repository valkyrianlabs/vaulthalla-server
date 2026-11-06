#pragma once

#include "crypto/IntegrityRegistry.hpp"
#include "crypto/SecretKey.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/Content.hpp"

#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>

namespace vh::storage {

// Positioned reader over one VHF1 generation stored in a local file (a vault backing file, a hydrated copy, a recovery
// blob). Every read authenticates whole 64 KiB chunks (crypto::vhf1::RangeReader) before a byte of them is returned:
// no plaintext is ever released unauthenticated, so there is no optimistic/strict distinction (spec 02 §3.7) and no
// GCM CTR keystream (gcmCtrDecryptAt) anywhere on this path. The header must name the vault, the generation (salt) and
// the key version the catalog recorded; the file's size must be the VHF1 size of the recorded plaintext size (the
// catalog's size is the authenticated object size, fstat the provider's). A failed chunk is sticky: for this reader,
// and for the generation through crypto::IntegrityRegistry, so later opens fail fast. The last authenticated chunk is
// kept (wiped on release) so small sequential reads don't authenticate a chunk again.
class Vhf1FileReader final : public PlaintextReader {
public:
    struct Params {
        std::filesystem::path path;
        uint64_t plaintextSize{};
        vault::content::Binding binding;
        crypto::SecretKeyPtr key;  // the vault key of binding.keyVersion
        Generation generation;
        std::string integrityDomain;
    };

    explicit Vhf1FileReader(Params params);
    ~Vhf1FileReader() override;

    Vhf1FileReader(const Vhf1FileReader&) = delete;
    Vhf1FileReader& operator=(const Vhf1FileReader&) = delete;

    [[nodiscard]] uint64_t size() const override { return params_.plaintextSize; }
    std::size_t read(uint64_t offset, std::span<uint8_t> out) override;
    [[nodiscard]] const Generation& generation() const override { return params_.generation; }
    [[nodiscard]] std::vector<uint8_t> readAllAuthenticated(uint64_t maxBytes) override;
    // Authenticates every chunk not read yet (no plaintext leaves): a consumer that streamed some bytes may then vouch
    // for the whole object.
    void requireAuthenticated() override;

private:
    struct Impl;
    [[noreturn]] void fail(const crypto::vhf1::Error& error);
    void loadChunk(uint64_t index);

    Params params_;
    std::unique_ptr<Impl> impl_;
    std::mutex mutex_;
};

}
