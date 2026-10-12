#include "platform/StateDirectory.hpp"

#include <system_error>

namespace vh::platform::state {

std::string restrictToService(const std::filesystem::path& root) {
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec) return "create " + root.string() + ": " + ec.message();
    std::filesystem::permissions(root, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
    if (ec) return "chmod 0700 " + root.string() + ": " + ec.message();
    return {};
}

}
