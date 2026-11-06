#include "protocols/http/upload/Staging.hpp"
#include "crypto/ScratchFile.hpp"
#include "log/Registry.hpp"

#include <system_error>
#include <paths.h>

namespace vh::protocols::http::upload::staging {

namespace {

std::filesystem::path root() {
    return paths::getBackingPath() / ".upload-staging";
}

void ownerOnly(const std::filesystem::path& dir) {
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
}

// Ciphertext under the process key; the file goes with the object.
class ScratchBody final : public Body {
public:
    explicit ScratchBody(const std::filesystem::path& path) : file_(std::make_unique<crypto::ScratchFile>(path)) {}

    void append(const std::span<const uint8_t> data) override { live().append(data); }
    void close() override { live().flush(); }  // its cached block on disk: no memory held until the commit
    void discard() noexcept override { file_.reset(); }
    [[nodiscard]] uint64_t size() const override { return live().size(); }
    [[nodiscard]] fs::PlaintextSource source() const override { return fs::sourceOf(live()); }

private:
    [[nodiscard]] crypto::ScratchFile& live() const {
        if (!file_) throw std::runtime_error("The upload staging file was discarded");
        return *file_;
    }

    std::unique_ptr<crypto::ScratchFile> file_;
};

}

std::string_view mode() noexcept { return "private"; }

bool insideMount() noexcept { return false; }

std::filesystem::path pathFor(const std::filesystem::path&, const unsigned int vaultId, const std::string& name) {
    const auto dir = root() / std::to_string(vaultId);
    std::filesystem::create_directories(dir);
    ownerOnly(root());
    ownerOnly(dir);
    return dir / name;
}

std::unique_ptr<Body> create(const std::filesystem::path& path) { return std::make_unique<ScratchBody>(path); }

void sweepAtStartup() {
    std::error_code ec;
    const auto removed = std::filesystem::remove_all(root(), ec);
    if (ec)
        log::Registry::fs()->warn("[HttpUpload] Could not clear upload staging {}: {}", root().string(), ec.message());
    else if (removed > 0)
        log::Registry::fs()->info("[HttpUpload] Removed {} stale upload staging entries (unreadable: encrypted under "
                                  "the previous run's in-memory key)", removed);
}

}
