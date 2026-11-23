#include "device/ScopeAudit.hpp"

#include "audit/Trail.hpp"
#include "identities/User.hpp"
#include "log/AuditOrigin.hpp"

#include <nlohmann/json.hpp>

#include <map>
#include <mutex>

namespace vh::device {

// Named, not anonymous: the unity build joins this file with others that have helpers of the same names.
namespace scope_audit_detail {

struct Window {
    std::chrono::steady_clock::time_point start{};
    int recorded = 0;
    int64_t suppressed = 0;
};

std::mutex& mutex() {
    static std::mutex m;
    return m;
}

std::map<uint32_t, Window>& windows() {
    static std::map<uint32_t, Window> w;
    return w;
}

}

std::string auditOrigin(const Peer& peer, const std::string_view surface) {
    std::string out = "device " + peer.shortId();
    if (!surface.empty()) out += " " + std::string(surface);
    if (peer.scoped()) out += " scope " + peer.scope;
    return out;
}

namespace scope_audit {

void refused(const Peer& peer, const std::shared_ptr<identities::User>& user, const std::string_view surface,
             const std::string_view what, const std::optional<std::string_view> effect) {
    namespace d = scope_audit_detail;
    const auto row = peer.deviceRowId.value_or(0);
    int64_t suppressedBefore = 0;
    {
        std::scoped_lock lock(d::mutex());
        auto& w = d::windows()[row];
        const auto now = std::chrono::steady_clock::now();
        if (w.recorded == 0 || now - w.start >= kWindow) {
            suppressedBefore = w.suppressed;
            w = d::Window{.start = now, .recorded = 0, .suppressed = 0};
        }
        if (w.recorded >= kPerWindow) {
            ++w.suppressed;
            return;
        }
        ++w.recorded;
    }
    const std::string asked = effect ? std::string(what) : std::string("(unknown)");
    nlohmann::json details{{"device", row},
                           {"surface", std::string(surface)},
                           {"command", asked},
                           {"effect", effect ? nlohmann::json(std::string(*effect)) : nlohmann::json(nullptr)},
                           {"scope", peer.scope}};
    if (suppressedBefore > 0) details["suppressed"] = suppressedBefore;
    const log::AuditOrigin origin(auditOrigin(peer, surface == "mcp" ? "mcp" : ""));
    ::vh::audit::record({.action = "device.scope.refused",
                         .outcome = ::vh::audit::Outcome::Denied,
                         .actor_id = user ? std::optional<uint32_t>(user->id) : std::nullopt,
                         .actor = user ? user->name() : std::string(),
                         .details = std::move(details)},
                        "[device] device " + peer.shortId() + " (scope " + peer.scope + ") was refused " + asked +
                            (effect ? " (" + std::string(*effect) + ")" : std::string()) +
                            (suppressedBefore > 0 ? "; " + std::to_string(suppressedBefore) +
                                                        " more refusal(s) in the last window were not recorded one by one"
                                                  : std::string()),
                        spdlog::level::warn);
}

void expireWindowsForTesting() {
    namespace d = scope_audit_detail;
    std::scoped_lock lock(d::mutex());
    for (auto& [row, w] : d::windows()) w.start -= kWindow;
}

void resetForTesting() {
    namespace d = scope_audit_detail;
    std::scoped_lock lock(d::mutex());
    d::windows().clear();
}

}

}
