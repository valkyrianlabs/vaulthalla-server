#include "rbac/Mirrored.hpp"

#include "concurrency/AtomicSharedPtr.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "log/Registry.hpp"
#include "mirror/access/Access.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/role/Vault.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vh::rbac::mirrored {

namespace {

struct Snapshot {
    std::unordered_map<uint32_t, std::shared_ptr<const Held>> byVault{};
    std::string fingerprint{};  // what reconcile() compares: every held row's role and grant, in vault order
};

std::atomic<bool> anyHeld{false};
concurrency::AtomicSharedPtr<const Snapshot> published{std::make_shared<const Snapshot>()};
std::mutex publishMutex;  // one reader of the table publishes at a time, so an older read never replaces a newer one

// The granted role as a role of its own: the core's name and bits, no id, no overrides, no assignment.
std::shared_ptr<const role::Vault> grantedRole(const db::query::mirror::Grant& g) {
    namespace pv = vh::rbac::permission::vault;
    auto r = std::make_shared<role::Vault>();
    r->name = g.role_name;
    r->fs.files = pv::fs::Files(static_cast<pv::fs::Files::Mask>(g.files));
    r->fs.directories = pv::fs::Directories(static_cast<pv::fs::Directories::Mask>(g.directories));
    r->sync = pv::Sync(static_cast<pv::Sync::Mask>(g.sync));
    r->roles = pv::Roles(static_cast<pv::Roles::Mask>(g.roles));
    return r;
}

std::string fingerprintOf(const std::vector<db::query::mirror::MirrorVault>& rows) {
    std::string out;
    for (const auto& m : rows) {
        if (m.role == "core") continue;
        out += std::to_string(m.vault_id) + ':' + std::to_string(m.peer_id) + ':' + m.role;
        if (m.grant)
            out += ':' + m.grant->role_name + ':' + std::to_string(m.grant->files) + ':' +
                   std::to_string(m.grant->directories) + ':' + std::to_string(m.grant->sync) + ':' +
                   std::to_string(m.grant->roles) + ':' + m.grant->granted_by_node + ':' +
                   std::to_string(m.grant->granted_at);
        out += ';';
    }
    return out;
}

std::shared_ptr<const Snapshot> snapshotOf(const std::vector<db::query::mirror::MirrorVault>& rows) {
    auto snap = std::make_shared<Snapshot>();
    for (const auto& m : rows) {
        if (m.role == "core") continue;
        auto held = std::make_shared<Held>();
        held->vault_id = m.vault_id;
        held->peer_id = m.peer_id;
        held->role = m.role;
        if (m.grant)
            held->grant = Grant{.role_name = m.grant->role_name, .role = grantedRole(*m.grant),
                                .granted_by_node = m.grant->granted_by_node, .granted_at = m.grant->granted_at};
        snap->byVault.emplace(m.vault_id, std::move(held));
    }
    snap->fingerprint = fingerprintOf(rows);
    return snap;
}

// Publishes `rows` when they differ from what is published (always when `force`). True when something changed.
bool publish(const std::vector<db::query::mirror::MirrorVault>& rows, const bool force) {
    auto next = snapshotOf(rows);
    const auto current = published.load();
    if (!force && current && current->fingerprint == next->fingerprint) return false;
    const bool changed = !current || current->fingerprint != next->fingerprint;
    const bool held = !next->byVault.empty();
    // Rows first, then the flag: a reader that sees the flag set finds the rows. Clearing it last-but-one is safe the
    // other way round too: a reader that still sees it set finds an empty map.
    published.store(std::move(next));
    anyHeld.store(held, std::memory_order_release);
    if (changed) rbac::bumpPolicyEpoch();
    return changed;
}

}

std::shared_ptr<const Held> find(const uint32_t vaultId) noexcept {
    if (!anyHeld.load(std::memory_order_acquire)) return nullptr;
    const auto snap = published.load();
    if (!snap) return nullptr;
    const auto it = snap->byVault.find(vaultId);
    return it == snap->byVault.end() ? nullptr : it->second;
}

bool any() noexcept { return anyHeld.load(std::memory_order_acquire); }

void reload() {
    const std::scoped_lock lock(publishMutex);
    (void)publish(db::query::mirror::MirrorVaults::list(), true);
}

bool reconcile() {
    const std::scoped_lock lock(publishMutex);
    const auto changed = publish(db::query::mirror::MirrorVaults::list(), false);
    if (changed)
        log::Registry::auth()->info("[rbac::mirrored] Vaults held as another server's copy changed outside the daemon; "
                                    "republished");
    return changed;
}

void resetForTesting() {
    const std::scoped_lock lock(publishMutex);
    published.store(std::make_shared<const Snapshot>());
    anyHeld.store(false, std::memory_order_release);
    rbac::bumpPolicyEpoch();
}

Watcher::Watcher() : AsyncService("MirrorAccessWatcher") {}

const std::shared_ptr<Watcher>& Watcher::instance() {
    static const auto watcher = std::make_shared<Watcher>();
    return watcher;
}

void Watcher::runLoop() {
    auto backoff = kWatchInterval;
    while (!shouldStop()) {
        try {
            (void)reconcile();
            // The write gate of the same vaults (mirror::access): its rows' states and the links' state, healed here
            // when a hook was missed.
            (void)vh::mirror::access::reconcile();
            backoff = kWatchInterval;
        } catch (const std::exception& e) {
            log::Registry::auth()->debug("[rbac::mirrored::Watcher] Reconcile failed: {}", e.what());
            backoff = std::min<std::chrono::milliseconds>(backoff * 2, std::chrono::seconds(30));
        }
        if (!lazySleep(backoff)) break;
    }
}

}
