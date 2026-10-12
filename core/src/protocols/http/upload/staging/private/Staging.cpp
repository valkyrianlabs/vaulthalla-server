#include "protocols/http/upload/Staging.hpp"
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

void sweepAtStartup() {
    std::error_code ec;
    const auto removed = std::filesystem::remove_all(root(), ec);
    if (ec)
        log::Registry::fs()->warn("[HttpUpload] Could not clear upload staging {}: {}", root().string(), ec.message());
    else if (removed > 0)
        log::Registry::fs()->info("[HttpUpload] Removed {} stale upload staging entries", removed);
}

}
