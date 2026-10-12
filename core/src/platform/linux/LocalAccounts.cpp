#include "platform/LocalAccounts.hpp"

#include <algorithm>
#include <grp.h>
#include <pwd.h>
#include <vector>

namespace vh::platform::accounts {

bool isMember(const uid_t uid, const gid_t gid) {
    const passwd* pw = ::getpwuid(uid);
    if (!pw) return false;
    if (pw->pw_gid == gid) return true;
    int ng = 0;
    ::getgrouplist(pw->pw_name, pw->pw_gid, nullptr, &ng);
    std::vector<gid_t> gs(ng);
    if (::getgrouplist(pw->pw_name, pw->pw_gid, gs.data(), &ng) < 0) return false;
    return std::ranges::any_of(gs, [gid](const gid_t g) { return g == gid; });
}

uid_t firstHumanUid() noexcept { return 1000; }

std::string addMemberCommand(const std::string_view user, const std::string_view group) {
    return "sudo usermod -aG " + std::string(group) + " " + std::string(user);
}

}
