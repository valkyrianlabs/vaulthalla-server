#include "protocols/http/upload/Staging.hpp"

namespace vh::protocols::http::upload::staging {

std::string_view mode() noexcept { return "mount"; }

std::filesystem::path pathFor(const std::filesystem::path& targetAbsPath, unsigned int, const std::string& name) {
    return targetAbsPath.parent_path() / name;
}

void sweepAtStartup() {}

}
