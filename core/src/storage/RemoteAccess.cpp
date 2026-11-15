#include "storage/RemoteAccess.hpp"

#include "audit/Trail.hpp"
#include "db/query/vault/RemoteAccess.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "sync/Controller.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <map>
#include <mutex>
#include <shared_mutex>

namespace vh::storage::remote_access {

namespace remote_access_detail {

struct Held {
    std::shared_mutex mutex;
    std::map<uint32_t, State> states;   // only vaults whose row says something: no entry = full
};

Held& held() {
    static Held h;
    return h;
}

void remember(const State& s) {
    auto& h = held();
    std::unique_lock lock(h.mutex);
    h.states[s.vault_id] = s;
}

}

std::string_view to_string(const Mode mode) {
    switch (mode) {
    case Mode::Full: return "full";
    case Mode::ReadOnly: return "read_only";
    case Mode::None: return "none";
    }
    return "none";
}

std::optional<Mode> modeFromString(const std::string_view text) {
    for (const auto m : {Mode::Full, Mode::ReadOnly, Mode::None})
        if (to_string(m) == text) return m;
    return std::nullopt;
}

Mode mode(const uint32_t vaultId) noexcept {
    auto& h = remote_access_detail::held();
    std::shared_lock lock(h.mutex);
    const auto it = h.states.find(vaultId);
    return it == h.states.end() ? Mode::Full : it->second.mode;
}

State state(const uint32_t vaultId) {
    auto& h = remote_access_detail::held();
    std::shared_lock lock(h.mutex);
    const auto it = h.states.find(vaultId);
    if (it == h.states.end()) return State{.vault_id = vaultId, .mode = Mode::Full, .reason = {}, .set_by = {}, .set_at = {}};
    return it->second;
}

void refresh(const uint32_t vaultId) {
    try {
        if (const auto row = db::query::vault::RemoteAccess::get(vaultId)) remote_access_detail::remember(*row);
        else forget(vaultId);
    } catch (const std::exception& e) {
        // What memory held stays: an unreadable database never turns a restricted vault into a writable one.
        log::Registry::storage()->warn("[RemoteAccess] Vault {}: access not read ({}); keeping {}", vaultId, e.what(),
                                       to_string(mode(vaultId)));
    }
}

void forget(const uint32_t vaultId) noexcept {
    auto& h = remote_access_detail::held();
    std::unique_lock lock(h.mutex);
    h.states.erase(vaultId);
}

void clear() noexcept {
    auto& h = remote_access_detail::held();
    std::unique_lock lock(h.mutex);
    h.states.clear();
}

State set(const uint32_t vaultId, const Mode newMode, const std::optional<std::string>& reason, const std::string& setBy) {
    const auto before = mode(vaultId);
    const auto stored = db::query::vault::RemoteAccess::set(vaultId, newMode, reason, setBy);
    if (!stored) throw std::invalid_argument("vault " + std::to_string(vaultId) + " is not a live S3 vault");
    remote_access_detail::remember(*stored);
    vh::audit::record({.action = "vault.remote.access", .outcome = vh::audit::Outcome::Success, .actor_id = std::nullopt,
                       .actor = setBy, .vault_id = vaultId, .entry_id = std::nullopt,
                       .details = {{"from", std::string(to_string(before))},
                                   {"to", std::string(to_string(newMode))},
                                   {"cause", reason.value_or("")}}},
                      fmt::format("[RemoteAccess] Vault {}: remote access {} -> {} by {}{}", vaultId, to_string(before),
                                  to_string(newMode), setBy, reason ? " (" + *reason + ")" : std::string{}));
    // Back to full: the pass a restricted vault skipped runs now and uploads what waited (a skipped pass, like any
    // stalled one, is not rescheduled by itself).
    if (newMode == Mode::Full && before != Mode::Full) {
        try {
            if (const auto& controller = runtime::Deps::get().syncController) (void)controller->runNow(vaultId);
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[RemoteAccess] Vault {}: the sync pass was not started: {}", vaultId, e.what());
        }
    }
    return *stored;
}

Restricted::Restricted(const uint32_t vaultId, const Mode mode, const std::string_view operation)
    : std::runtime_error(fmt::format("{}: vault {}'s remote is {} ({} refused before any request)",
                                     mode == Mode::None ? "remote_unavailable" : "remote_read_only", vaultId,
                                     mode == Mode::None ? "unavailable" : "read-only", operation)),
      vaultId_(vaultId), mode_(mode) {}

std::string_view Restricted::code() const noexcept {
    return mode_ == Mode::None ? "remote_unavailable" : "remote_read_only";
}

void requireWrite(const uint32_t vaultId, const std::string_view operation) {
    if (const auto m = mode(vaultId); !allowsWrites(m)) throw Restricted(vaultId, m, operation);
}

void requireRead(const uint32_t vaultId, const std::string_view operation) {
    if (const auto m = mode(vaultId); !allowsReads(m)) throw Restricted(vaultId, m, operation);
}

}
