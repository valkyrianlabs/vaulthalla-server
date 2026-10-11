#pragma once

#include "identities/Group.hpp"
#include "identities/User.hpp"

#include <memory>
#include <utility>

// The harness's user and group specs are detached identities (never the Manager's canonical objects): it edits them
// to record what a generated command is expected to change.
namespace vh::test::integration::entity {

template <typename Fn>
void edit(const std::shared_ptr<identities::User>& user, Fn&& fn) {
    auto next = *user->state();
    std::forward<Fn>(fn)(next);
    user->replaceDetachedState(std::move(next));
}

template <typename Fn>
void edit(const std::shared_ptr<identities::Group>& group, Fn&& fn) {
    auto next = *group->state();
    std::forward<Fn>(fn)(next);
    group->replaceDetachedState(std::move(next));
}

}
