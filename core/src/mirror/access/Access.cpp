#include "mirror/access/Access.hpp"

#include "config/Registry.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "log/Registry.hpp"
#include "peer/Links.hpp"

#include <fmt/format.h>

#include <atomic>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <utility>

namespace vh::mirror::access {

namespace mirror_access_detail {

struct HeldVault {
    uint32_t peer_id{};
    std::string role{};
    std::string state{};
    bool copy_finished{false};
    std::optional<std::string> stop_reason{};
};

struct Gate {
    std::shared_mutex mutex;
    std::map<uint32_t, HeldVault> vaults;   // only vaults held here as another server's copy
    std::map<uint32_t, bool> links;         // peer id -> up; no entry: down
    std::mutex publishMutex;                // one reader of the table publishes at a time
};

Gate& gate() {
    static Gate g;
    return g;
}

std::atomic<bool> anyHeld{false};

std::map<uint32_t, HeldVault> heldFrom(const std::vector<vh::db::query::mirror::MirrorVault>& rows) {
    std::map<uint32_t, HeldVault> out;
    for (const auto& m : rows) {
        if (m.role != "mirror" && m.role != "orphaned") continue;
        out.emplace(m.vault_id, HeldVault{.peer_id = m.peer_id, .role = m.role, .state = m.state,
                                          .copy_finished = m.copy_finished, .stop_reason = m.stop_reason});
    }
    return out;
}

bool sameHeld(const HeldVault& a, const HeldVault& b) {
    return a.peer_id == b.peer_id && a.role == b.role && a.state == b.state && a.copy_finished == b.copy_finished &&
           a.stop_reason == b.stop_reason;
}

bool sameMaps(const std::map<uint32_t, HeldVault>& a, const std::map<uint32_t, HeldVault>& b) {
    if (a.size() != b.size()) return false;
    for (auto ia = a.begin(), ib = b.begin(); ia != a.end(); ++ia, ++ib)
        if (ia->first != ib->first || !sameHeld(ia->second, ib->second)) return false;
    return true;
}

// Publishes `next` (always when `force`); true when it differed from what was published.
bool publishHeld(std::map<uint32_t, HeldVault> next, const bool force) {
    auto& g = gate();
    std::unique_lock lock(g.mutex);
    const bool changed = !sameMaps(g.vaults, next);
    if (!changed && !force) return false;
    g.vaults = std::move(next);
    anyHeld.store(!g.vaults.empty(), std::memory_order_release);
    return changed;
}

bool peersOn() { return vh::config::Registry::get().peers.experimental; }

// The reason a held vault is read-only, "" when it is live. Caller holds the gate's lock (shared).
std::string readOnlyReason(const HeldVault& v, const bool linkUp) {
    if (v.role == "orphaned") return std::string(kOrphaned);
    if (v.state == "diverged") return std::string(kDiverged);
    if (v.state == "expired") return std::string(kExpired);
    if (v.state == "paused" && v.stop_reason && *v.stop_reason == kCoreDeleting) return std::string(kCoreDeleting);
    if (v.state == "paused") return std::string(kPaused);
    if (v.state != "live") return std::string(kStopped);
    if (!v.copy_finished) return std::string(kFirstCopy);
    if (!peersOn()) return std::string(kPeersOff);
    if (!linkUp) return std::string(kLinkDown);
    return {};
}

struct Judged {
    State state{State::NotMirrored};
    std::string reason{};
};

Judged judge(const uint32_t vaultId) {
    if (!anyHeld.load(std::memory_order_acquire)) return {};
    auto& g = gate();
    std::shared_lock lock(g.mutex);
    const auto it = g.vaults.find(vaultId);
    if (it == g.vaults.end()) return {};
    const auto link = g.links.find(it->second.peer_id);
    auto why = readOnlyReason(it->second, link != g.links.end() && link->second);
    if (why.empty()) return {.state = State::Live, .reason = {}};
    return {.state = State::ReadOnly, .reason = std::move(why)};
}

}

std::string_view to_string(const State state) noexcept {
    switch (state) {
    case State::NotMirrored: return "not_mirrored";
    case State::Live: return "live";
    case State::ReadOnly: return "read_only";
    }
    return "read_only";
}

bool acceptsLocalChanges() noexcept {
    // Piece B: a Live mirror's changes are applied here as pending, sent to the core, and confirmed through the log or
    // reverted and kept (mirror::submit).
    return true;
}

std::optional<Facts> facts(const uint32_t vaultId) {
    auto& g = mirror_access_detail::gate();
    std::shared_lock lock(g.mutex);
    const auto it = g.vaults.find(vaultId);
    if (it == g.vaults.end()) return std::nullopt;
    const auto link = g.links.find(it->second.peer_id);
    return Facts{.vault_id = vaultId, .peer_id = it->second.peer_id, .role = it->second.role,
                 .state = it->second.state, .copy_finished = it->second.copy_finished,
                 .stop_reason = it->second.stop_reason, .link_up = link != g.links.end() && link->second};
}

State state(const uint32_t vaultId) noexcept {
    try {
        return mirror_access_detail::judge(vaultId).state;
    } catch (...) {
        return State::ReadOnly;   // never writable by accident (an allocation failure in a lookup)
    }
}

bool held(const uint32_t vaultId) noexcept { return state(vaultId) != State::NotMirrored; }

std::string reason(const uint32_t vaultId) {
    auto j = mirror_access_detail::judge(vaultId);
    if (j.state == State::ReadOnly) return j.reason;
    if (j.state == State::Live && !acceptsLocalChanges()) return std::string(kWritesNotBuilt);
    return {};
}

std::optional<std::string> refusalReason(const uint32_t vaultId) {
    auto why = reason(vaultId);
    if (why.empty()) return std::nullopt;
    return why;
}

std::string sentence(const std::string_view code) {
    if (code == kOrphaned)
        return "This vault is a copy of another server's vault that its core server stopped mirroring; it is read-only "
               "here (remove it with vh mirror cancel)";
    if (code == kFirstCopy)
        return "This vault's first copy from its core server is still arriving; it is read-only until the copy is "
               "complete";
    if (code == kDiverged)
        return "This copy no longer matches its core server's vault and stopped following it; it is read-only";
    if (code == kExpired)
        return "This copy fell behind what its core server keeps, or the core no longer mirrors it; it is read-only";
    if (code == kStopped) return "This copy stopped following its core server; it is read-only";
    if (code == kPaused) return "Following this vault's core server is paused; the copy is read-only";
    if (code == kCoreDeleting)
        return "This vault's core server is deleting it: the copy is read-only until the core's restore window ends, "
               "when it is removed here or kept as an orphaned copy (vh mirror info shows which, and when), unless the "
               "core restores the vault; to keep it as this server's own vault, detach it (vh mirror detach)";
    if (code == kPeersOff)
        return "Linked servers are switched off on this server (peers.experimental); a mirrored copy is read-only";
    if (code == kLinkDown)
        return "The link to this vault's core server is down; the copy is read-only until it is back";
    if (code == kCoreOwned)
        return "This vault is a copy of another server's vault; its settings, keys and remote are its core server's, "
               "and are changed there";
    if (code == kWritesNotBuilt)
        return "This vault is a mirror of another server's vault; changes are made on its core server (this server "
               "does not take changes to a mirror yet)";
    return "This vault is a copy of another server's vault; it is read-only here";
}

MirrorReadOnly::MirrorReadOnly(const uint32_t vaultId, std::string reasonCode, const std::string_view operation)
    : vh::ops::ReadOnly(reasonCode, fmt::format("{} ({} refused)", sentence(reasonCode), operation)),
      vault_id(vaultId) {}

void requireWritable(const uint32_t vaultId, const std::string_view operation) {
    if (!mirror_access_detail::anyHeld.load(std::memory_order_acquire)) return;
    if (auto why = refusalReason(vaultId)) throw MirrorReadOnly(vaultId, std::move(*why), operation);
}

void refuseIfHeld(const uint32_t vaultId, const std::string_view operation) {
    if (held(vaultId)) throw MirrorReadOnly(vaultId, std::string(kCoreOwned), operation);
}

void reload() {
    auto& g = mirror_access_detail::gate();
    const std::scoped_lock lock(g.publishMutex);
    (void)mirror_access_detail::publishHeld(mirror_access_detail::heldFrom(vh::db::query::mirror::MirrorVaults::list()),
                                            true);
}

bool reconcile() {
    auto& g = mirror_access_detail::gate();
    bool changed = false;
    {
        const std::scoped_lock lock(g.publishMutex);
        changed = mirror_access_detail::publishHeld(
            mirror_access_detail::heldFrom(vh::db::query::mirror::MirrorVaults::list()), false);
    }
    if (changed)
        vh::log::Registry::sync()->info("[mirror::access] The vaults held here as another server's copy changed outside the "
                                    "daemon; the gate was republished");
    // The links, from the service that keeps them (a hook that was missed heals here). No service (tests, before it
    // starts): what the hooks said stays.
    if (const auto links = vh::peer::linkService()) {
        std::vector<uint32_t> peers;
        {
            std::shared_lock lock(g.mutex);
            for (const auto& [_, v] : g.vaults) peers.push_back(v.peer_id);
        }
        for (const auto peer : peers) {
            const bool up = links->connected(peer);
            std::unique_lock lock(g.mutex);
            auto& known = g.links[peer];
            if (known != up) {
                known = up;
                changed = true;
            }
        }
    }
    return changed;
}

void linkChanged(const uint32_t peerId, const bool up) noexcept {
    try {
        auto& g = mirror_access_detail::gate();
        std::unique_lock lock(g.mutex);
        g.links[peerId] = up;
    } catch (...) {
        // An allocation failure: the watcher's pass sets it.
    }
}

std::vector<uint32_t> heldVaults() {
    auto& g = mirror_access_detail::gate();
    std::shared_lock lock(g.mutex);
    std::vector<uint32_t> out;
    out.reserve(g.vaults.size());
    for (const auto& [id, _] : g.vaults) out.push_back(id);
    return out;
}

void resetForTesting() noexcept {
    auto& g = mirror_access_detail::gate();
    std::unique_lock lock(g.mutex);
    g.vaults.clear();
    g.links.clear();
    mirror_access_detail::anyHeld.store(false, std::memory_order_release);
}

}
