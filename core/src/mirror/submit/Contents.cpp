#include "mirror/submit/Contents.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/hash.hpp"
#include "log/Registry.hpp"
#include "paths.h"
#include "peer/ObjectClient.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sodium.h>
#include <unistd.h>

#include <array>
#include <system_error>

namespace vh::mirror::submit::contents {

namespace {

std::filesystem::path submitContentsRoot(const char* name) { return vh::paths::getBackingPath() / name; }

std::string submitContentsRandom() {
    std::array<unsigned char, 8> bytes{};
    randombytes_buf(bytes.data(), bytes.size());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (const auto b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

Staging submitContentsRefuse(const unsigned status, std::string code, std::string error) {
    return {.ok = false, .http_status = status, .code = std::move(code), .error = std::move(error)};
}

struct SubmitContentsFd {
    int fd{-1};
    explicit SubmitContentsFd(const std::filesystem::path& p) : fd(::open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) {}
    ~SubmitContentsFd() {
        if (fd >= 0) ::close(fd);
    }
    SubmitContentsFd(const SubmitContentsFd&) = delete;
    SubmitContentsFd& operator=(const SubmitContentsFd&) = delete;
};

}

std::filesystem::path pendingBlob(const uint32_t vaultId, const uint64_t rowId) {
    return submitContentsRoot(".vh-mirror-pending") / std::to_string(vaultId) / std::to_string(rowId);
}

std::filesystem::path heldBlob(const uint32_t vaultId, const uint64_t heldId) {
    return submitContentsRoot(".vh-mirror-held") / std::to_string(vaultId) / std::to_string(heldId);
}

void keep(const std::filesystem::path& from, const std::filesystem::path& to) {
    std::filesystem::create_directories(to.parent_path());
    std::error_code ec;
    std::filesystem::remove(to, ec);
    std::filesystem::create_hard_link(from, to, ec);
    if (!ec) return;
    std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing);
}

void moveBlob(const std::filesystem::path& from, const std::filesystem::path& to) {
    std::error_code ec;
    if (!std::filesystem::exists(from, ec)) return;
    std::filesystem::create_directories(to.parent_path(), ec);
    std::filesystem::rename(from, to, ec);
    if (ec)
        vh::log::Registry::sync()->warn("[MirrorSubmit] Could not keep the sealed bytes {} as {}: {}", from.string(),
                                        to.string(), ec.message());
}

void dropBlob(const std::filesystem::path& blob) noexcept {
    std::error_code ec;
    std::filesystem::remove(blob, ec);
}

std::filesystem::path stagedPath(const uint32_t vaultId, const std::string& objectUuid, const std::string& generation) {
    const auto gen = vh::peer::object::generationToUrl(generation).value_or("none");
    return submitContentsRoot(".vh-mirror-staged") / std::to_string(vaultId) / (objectUuid + "." + gen);
}

std::filesystem::path receivingPath(const uint32_t vaultId) {
    auto dir = submitContentsRoot(".vh-mirror-staged") / std::to_string(vaultId);
    std::filesystem::create_directories(dir);
    return dir / (".receiving-" + submitContentsRandom());
}

std::optional<std::filesystem::path> staged(const uint32_t vaultId, const std::string& objectUuid,
                                            const std::string& generation) {
    auto p = stagedPath(vaultId, objectUuid, generation);
    std::error_code ec;
    if (std::filesystem::is_regular_file(p, ec)) return p;
    return std::nullopt;
}

Staging stage(const uint32_t vaultId, const std::string& objectUuid, const Facts& facts,
              const std::filesystem::path& received) {
    struct Cleanup {
        const std::filesystem::path& p;
        bool armed{true};
        ~Cleanup() {
            if (armed) dropBlob(p);
        }
    } cleanup{received};

    const auto& manager = vh::runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine || !engine->encryptionManager) return submitContentsRefuse(404, "not_found", "Not found");
    vh::vault::content::Format format{};
    try {
        format = vh::vault::content::formatOf(facts.generation);
    } catch (const std::invalid_argument&) {
        return submitContentsRefuse(422, "invalid_contents", "not a generation id");
    }
    if (format != vh::vault::content::Format::Vhf1)
        return submitContentsRefuse(422, "format_not_portable", "only sealed (VHF1) contents travel");
    vh::crypto::SecretKeyPtr key;
    try {
        key = engine->encryptionManager->keySnapshot(facts.key_version);
    } catch (const std::exception&) {
        key = nullptr;
    }
    if (!key) return submitContentsRefuse(409, "key_version_missing", "this server holds no such key version");

    SubmitContentsFd fd(received);
    if (fd.fd < 0) return submitContentsRefuse(500, "internal", "Internal error");
    // Invariant 6: the core never commits a mirror's file without holding its verified contents. In order: the size,
    // the content hash over the sealed bytes, then the header and every chunk authenticated with the vault's key as
    // that generation (the object is not bound: a copy keeps its source's header, wave 2's rule).
    const auto want = vh::vault::content::sealedSizeOf(facts.size, facts.generation);
    struct stat st{};
    if (::fstat(fd.fd, &st) != 0 || static_cast<uint64_t>(st.st_size) != want)
        return submitContentsRefuse(422, "invalid_contents", "the bytes are not that generation's length");
    if (vh::crypto::hash::blake2bFd(fd.fd) != facts.content_hash)
        return submitContentsRefuse(422, "invalid_contents", "the bytes are not the ones the change names");
    const vh::vault::content::Binding binding{.vaultUid = engine->encryptionManager->vaultUid(),
                                               .generation = facts.generation, .keyVersion = facts.key_version,
                                               .objectUid = std::nullopt};
    if (!vh::vault::content::verifyFd(fd.fd, facts.size, binding, *key))
        return submitContentsRefuse(422, "invalid_contents", "the bytes do not open under the vault key as that generation");

    const auto to = stagedPath(vaultId, objectUuid, facts.generation);
    std::error_code ec;
    std::filesystem::create_directories(to.parent_path(), ec);
    std::filesystem::rename(received, to, ec);
    if (ec) return submitContentsRefuse(500, "internal", "Internal error");
    cleanup.armed = false;
    return {.ok = true, .http_status = 201};
}

std::size_t sweep(const std::chrono::hours age) {
    std::size_t n = 0;
    const auto root = submitContentsRoot(".vh-mirror-staged");
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) return 0;
    const auto cutoff = std::filesystem::file_time_type::clock::now() - age;
    for (auto it = std::filesystem::recursive_directory_iterator(root, ec);
         !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
        std::error_code e2;
        if (!it->is_regular_file(e2)) continue;
        if (it->last_write_time(e2) < cutoff) {
            std::filesystem::remove(it->path(), e2);
            ++n;
        }
    }
    return n;
}

}
