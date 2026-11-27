#include "mirror/submit/Contents.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Pending.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/submit/Submit.hpp"
#include "fs/ops/file.hpp"
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

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <sodium.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <span>
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
    std::filesystem::copy_file(from, to, std::filesystem::copy_options::none);   // created here, never over a file
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

namespace {

std::filesystem::path submitContentsFactsPath(const std::filesystem::path& staged) {
    return staged.parent_path() / (staged.filename().string() + ".facts");
}

}

std::optional<StagedBytes> staged(const uint32_t vaultId, const std::string& objectUuid, const std::string& generation) {
    auto p = stagedPath(vaultId, objectUuid, generation);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(p, ec)) return std::nullopt;
    try {
        std::ifstream in(submitContentsFactsPath(p));
        if (!in) return std::nullopt;
        const auto j = nlohmann::json::parse(in);
        StagedBytes out{.path = p,
                        .facts = {.generation = j.at("generation").get<std::string>(),
                                  .key_version = j.at("key_version").get<uint32_t>(),
                                  .size = j.at("size").get<uint64_t>(),
                                  .content_hash = j.at("content_hash").get<std::string>()}};
        if (out.facts.generation != generation) return std::nullopt;
        return out;
    } catch (const std::exception&) {
        return std::nullopt;   // no verified facts: as good as not staged
    }
}

void dropStaged(const StagedBytes& s) noexcept {
    dropBlob(s.path);
    dropBlob(submitContentsFactsPath(s.path));
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
    cleanup.armed = false;
    return keepVerified(vaultId, objectUuid, facts, received);
}

Staging keepVerified(const uint32_t vaultId, const std::string& objectUuid, const Facts& facts,
                     const std::filesystem::path& received) {
    struct Cleanup {
        const std::filesystem::path& p;
        bool armed{true};
        ~Cleanup() {
            if (armed) dropBlob(p);
        }
    } cleanup{received};
    // The verified facts first (a private file), then the bytes into place: staged bytes always have them.
    const auto to = stagedPath(vaultId, objectUuid, facts.generation);
    std::error_code ec;
    std::filesystem::create_directories(to.parent_path(), ec);
    const auto factsPath = submitContentsFactsPath(to);
    try {
        dropBlob(factsPath);
        const auto text = nlohmann::json{{"generation", facts.generation}, {"key_version", facts.key_version},
                                         {"size", facts.size}, {"content_hash", facts.content_hash}}.dump();
        vh::fs::ops::writeFileExclusive(factsPath, std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()),
                                        0600);
    } catch (const std::exception&) {
        return submitContentsRefuse(500, "internal", "Internal error");
    }
    std::filesystem::rename(received, to, ec);
    if (ec) {
        dropBlob(factsPath);
        return submitContentsRefuse(500, "internal", "Internal error");
    }
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

void dropVault(const uint32_t vaultId) noexcept {
    for (const auto* area : {".vh-mirror-pending", ".vh-mirror-held", ".vh-mirror-staged"}) {
        std::error_code ec;
        std::filesystem::remove_all(submitContentsRoot(area) / std::to_string(vaultId), ec);
    }
}

void dropStagedOf(const uint32_t vaultId) noexcept {
    std::error_code ec;
    std::filesystem::remove_all(submitContentsRoot(".vh-mirror-staged") / std::to_string(vaultId), ec);
}

namespace {

std::optional<uint32_t> submitContentsVaultDir(const std::filesystem::directory_entry& d) {
    std::error_code ec;
    if (!d.is_directory(ec)) return std::nullopt;
    const auto name = d.path().filename().string();
    if (name.empty() || name.size() > 9 || !std::ranges::all_of(name, [](const char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    return static_cast<uint32_t>(std::stoul(name));
}

std::optional<uint64_t> submitContentsNumberedFile(const std::filesystem::directory_entry& f) {
    std::error_code ec;
    if (!f.is_regular_file(ec)) return std::nullopt;
    const auto name = f.path().filename().string();
    if (name.empty() || name.size() > 19 || !std::ranges::all_of(name, [](const char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    return std::stoull(name);
}

bool submitContentsVaultExists(const uint32_t vaultId) {
    return vh::db::Transactions::exec("mirror::submit::contents vault", [&](pqxx::work& txn) {
        return !txn.exec("SELECT 1 FROM vault WHERE id = $1", pqxx::params{vaultId}).empty();
    });
}

}

std::size_t housekeeping(const bool startup) {
    std::size_t n = 0;
    std::error_code ec;
    // Partial receptions a stop interrupted (a PUT's body is never resumed: the mirror sends it again).
    if (startup) {
        const auto root = submitContentsRoot(".vh-mirror-staged");
        if (std::filesystem::exists(root, ec))
            for (auto it = std::filesystem::recursive_directory_iterator(root, ec);
                 !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
                if (it->path().filename().string().starts_with(".receiving-")) {
                    std::error_code e2;
                    if (std::filesystem::remove(it->path(), e2)) ++n;
                }
    }
    n += sweep(std::chrono::hours(24));

    // Staged bytes of a vault that is not this server's core (any more).
    if (const auto root = submitContentsRoot(".vh-mirror-staged"); std::filesystem::exists(root, ec))
        for (const auto& d : std::filesystem::directory_iterator(root, ec))
            if (const auto v = submitContentsVaultDir(d)) {
                const auto mv = vh::db::query::mirror::MirrorVaults::get(*v);
                if (!mv || mv->role != "core") {
                    std::error_code e2;
                    n += static_cast<std::size_t>(std::filesystem::remove_all(d.path(), e2));
                }
            }

    // A copy whose core ended its mirror: its pending changes are kept as held ones (and their bytes with them).
    for (const auto& m : vh::db::query::mirror::MirrorVaults::list())
        if (m.role == "orphaned" && !vh::db::query::mirror::Pending::list(m.vault_id).empty())
            n += vh::mirror::submit::orphaned(m.vault_id);

    // Pending bytes of a change that is gone; held bytes of a held change no longer open; a vault that is gone.
    for (const auto* area : {".vh-mirror-pending", ".vh-mirror-held"}) {
        const bool held = std::string_view(area) == ".vh-mirror-held";
        const auto root = submitContentsRoot(area);
        if (!std::filesystem::exists(root, ec)) continue;
        for (const auto& d : std::filesystem::directory_iterator(root, ec)) {
            const auto v = submitContentsVaultDir(d);
            if (!v) continue;
            std::error_code e2;
            if (!submitContentsVaultExists(*v)) {
                n += static_cast<std::size_t>(std::filesystem::remove_all(d.path(), e2));
                continue;
            }
            // Under the vault's change lock: a blob moves (pending to held, held to pending) with its row under it.
            const std::scoped_lock local(vh::mirror::submit::vaultMutex(*v));
            for (const auto& f : std::filesystem::directory_iterator(d.path(), e2)) {
                const auto id = submitContentsNumberedFile(f);
                if (!id) continue;
                bool keep = false;
                if (held) {
                    const auto h = vh::db::query::mirror::Pending::heldChange(*id);
                    keep = h && h->vault_id == *v && h->state == "open";
                } else {
                    const auto p = vh::db::query::mirror::Pending::get(*id);
                    keep = p && p->vault_id == *v;
                }
                if (!keep) {
                    std::error_code e3;
                    if (std::filesystem::remove(f.path(), e3)) ++n;
                }
            }
        }
    }
    return n;
}

}
