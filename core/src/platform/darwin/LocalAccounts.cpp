#include "platform/LocalAccounts.hpp"

#include <membership.h>

namespace vh::platform::accounts {

bool isMember(const uid_t uid, const gid_t gid) {
    uuid_t user{};
    uuid_t group{};
    if (::mbr_uid_to_uuid(uid, user) != 0) return false;
    if (::mbr_gid_to_uuid(gid, group) != 0) return false;
    int member = 0;
    return ::mbr_check_membership(user, group, &member) == 0 && member == 1;
}

uid_t firstHumanUid() noexcept { return 501; }

std::string addMemberCommand(const std::string_view user, const std::string_view group) {
    return "sudo dseditgroup -o edit -a " + std::string(user) + " -t user " + std::string(group);
}

}
