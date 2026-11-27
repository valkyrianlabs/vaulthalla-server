// PIECE A'S FILE (wave 4): piece B's minimal stand-in for vh::mirror::access (see the header). Replaced at the merge.
#include "mirror/access/Access.hpp"

#include "db/query/mirror/MirrorVault.hpp"
#include "peer/Links.hpp"
#include "rbac/Mirrored.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace vh::mirror::access {

namespace {

std::mutex& accessStubMutex() {
    static std::mutex m;
    return m;
}

std::map<uint32_t, bool>& accessStubLinkOverrides() {
    static std::map<uint32_t, bool> m;
    return m;
}

std::optional<bool> accessStubOverride(const uint32_t vaultId) {
    std::scoped_lock lock(accessStubMutex());
    const auto& m = accessStubLinkOverrides();
    if (const auto it = m.find(vaultId); it != m.end()) return it->second;
    return std::nullopt;
}

// "" when Live; the reason otherwise. Only for a vault held here.
std::string accessStubWhy(const uint32_t vaultId, const vh::rbac::mirrored::Held& held) {
    if (held.role != "mirror") return "mirror_orphaned";
    const auto mv = vh::db::query::mirror::MirrorVaults::get(vaultId);
    if (!mv || mv->role != "mirror") return "mirror_orphaned";
    if (mv->state != "live") return "mirror_" + mv->state;
    if (!mv->copy_finished) return "mirror_copy_unfinished";
    bool up = false;
    if (const auto o = accessStubOverride(vaultId)) up = *o;
    else if (const auto links = vh::peer::linkService()) up = links->connected(mv->peer_id);
    return up ? std::string{} : std::string("mirror_link_down");
}

}

State state(const uint32_t vaultId) {
    const auto held = vh::rbac::mirrored::find(vaultId);
    if (!held) return State::NotMirrored;
    return accessStubWhy(vaultId, *held).empty() ? State::Live : State::ReadOnly;
}

std::string reason(const uint32_t vaultId) {
    const auto held = vh::rbac::mirrored::find(vaultId);
    if (!held) return {};
    return accessStubWhy(vaultId, *held);
}

void requireWritable(const uint32_t vaultId, const std::string_view) {
    const auto held = vh::rbac::mirrored::find(vaultId);
    if (!held) return;
    auto why = accessStubWhy(vaultId, *held);
    if (why.empty() && acceptsLocalChanges()) return;
    throw MirrorReadOnly(why.empty() ? std::string("mirror_writes_not_built") : std::move(why));
}

bool acceptsLocalChanges() { return true; }

void setLinkUpForTesting(const uint32_t vaultId, const bool up) {
    std::scoped_lock lock(accessStubMutex());
    accessStubLinkOverrides()[vaultId] = up;
}

void clearForTesting() {
    std::scoped_lock lock(accessStubMutex());
    accessStubLinkOverrides().clear();
}

}
