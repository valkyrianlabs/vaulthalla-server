#pragma once

#include <string>
#include <string_view>
#include <sys/types.h>

namespace vh::platform::accounts {

// Whether the account `uid` is a member of group `gid` in the system account database: its primary group or a
// supplementary one. Linux: passwd + getgrouplist. macOS: Directory Services via mbr_check_membership (getgrouplist
// there misses directory and nested groups). uid 0 gets no special treatment here; callers decide.
[[nodiscard]] bool isMember(uid_t uid, gid_t gid);

// The lowest uid this OS gives a person's account (Linux 1000, macOS 501). System and service accounts sit below.
[[nodiscard]] uid_t firstHumanUid() noexcept;

// The command an administrator runs to add `user` to `group`, for error messages.
[[nodiscard]] std::string addMemberCommand(std::string_view user, std::string_view group);

}
