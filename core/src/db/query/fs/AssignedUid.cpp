#include "db/query/fs/AssignedUid.hpp"

#include <utility>

namespace vh::db::query::fs {

namespace {

AssignedUid*& assignedUidInnermost() {
    thread_local AssignedUid* innermost = nullptr;
    return innermost;
}

}

AssignedUid::AssignedUid(const uint32_t vaultId, std::filesystem::path path, const vh::crypto::id::ObjectUid& uid)
    : outer_(assignedUidInnermost()), vaultId_(vaultId), path_(std::move(path).lexically_normal()), uid_(uid) {
    assignedUidInnermost() = this;
}

AssignedUid::~AssignedUid() { assignedUidInnermost() = outer_; }

std::optional<vh::crypto::id::ObjectUid> AssignedUid::forPath(const uint32_t vaultId,
                                                               const std::filesystem::path& path) {
    const auto normal = path.lexically_normal();
    for (const AssignedUid* a = assignedUidInnermost(); a; a = a->outer_)
        if (a->vaultId_ == vaultId && a->path_ == normal) return a->uid_;
    return std::nullopt;
}

vh::crypto::id::ObjectUid AssignedUid::forPathOrNew(const uint32_t vaultId, const std::filesystem::path& path) {
    if (auto uid = forPath(vaultId, path)) return *uid;
    return vh::crypto::id::newObjectUid();
}

}
