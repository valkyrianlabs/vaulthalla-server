#include "ops/Sessions.hpp"

#include "audit/Trail.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/session/Idle.hpp"
#include "auth/session/Manager.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>

namespace vh::ops::sessions {

namespace {

// The per-process key for session ids. Never stored or logged.
const std::array<unsigned char, crypto_generichash_KEYBYTES>& handleKey() {
    static const auto key = [] {
        std::array<unsigned char, crypto_generichash_KEYBYTES> k{};
        randombytes_buf(k.data(), k.size());
        return k;
    }();
    return key;
}

int64_t unixSeconds(const std::chrono::system_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

void requireUser(const Actor& actor) {
    requireActor(actor);
    if (actor->systemOnly() || !actor->authorizing()) throw Denied("this account has no web sessions");
}

// The caller's rows a person could still use: live, unexpired (the query) and not past the idle timeout.
std::vector<std::shared_ptr<auth::model::RefreshToken>> liveRows(const uint32_t userId) {
    auto rows = db::query::auth::RefreshToken::list(userId);
    const auto now = std::chrono::system_clock::now();
    const auto limit = auth::session::idle::timeout();
    std::erase_if(rows, [&](const auto& row) {
        return !row || row->revoked || auth::session::idle::expired(row->lastActivity, now, limit);
    });
    return rows;
}

}

void to_json(nlohmann::json& j, const Info& info) {
    j = {{"id", info.id},
         {"current", info.current},
         {"aal", info.aal},
         {"amr", info.amr},
         {"auth_time", info.auth_time},
         {"last_activity_at", info.last_activity_at},
         {"ip_address", info.ip_address},
         {"user_agent", info.user_agent}};
}

std::string handle(const std::string_view jti) {
    std::array<unsigned char, 16> out{};
    const auto& key = handleKey();
    crypto_generichash(out.data(), out.size(), reinterpret_cast<const unsigned char*>(jti.data()), jti.size(),
                       key.data(), key.size());
    std::array<char, 33> hex{};
    sodium_bin2hex(hex.data(), hex.size(), out.data(), out.size());
    return std::string(hex.data(), 32);
}

std::vector<Info> list(const Actor& actor, const std::optional<std::string>& currentJti) {
    requireUser(actor);
    std::vector<Info> out;
    for (const auto& row : liveRows(actor->id)) {
        out.push_back({.id = handle(row->jti),
                       .current = currentJti && *currentJti == row->jti,
                       .aal = row->aal,
                       .amr = row->amr,
                       .auth_time = unixSeconds(row->authTime),
                       .last_activity_at = unixSeconds(row->lastActivity),
                       .ip_address = row->ipAddress,
                       .user_agent = row->userAgent});
    }
    std::ranges::sort(out, [](const Info& a, const Info& b) {
        return a.auth_time != b.auth_time ? a.auth_time > b.auth_time : a.id < b.id;
    });
    return out;
}

std::size_t revoke(const Actor& actor, const std::optional<std::string>& currentJti, const Revoke& req,
                   const std::shared_ptr<protocols::ws::Session>& caller) {
    requireUser(actor);
    if (req.id.has_value() == req.all_others) throw Invalid("give either id or all_others");

    std::vector<std::string> targets;
    bool includesCurrent = false;
    for (const auto& row : liveRows(actor->id)) {
        const bool current = currentJti && *currentJti == row->jti;
        if (req.all_others ? !current : handle(row->jti) == *req.id) {
            targets.push_back(row->jti);
            includesCurrent = includesCurrent || current;
        }
    }
    if (req.id && targets.empty()) throw NotFound("no such session");

    // Rows first, so nothing can rehydrate from them while the live sockets are ended.
    std::size_t revoked = 0;
    for (const auto& jti : targets)
        if (db::query::auth::RefreshToken::revokeOfUser(jti, actor->id)) ++revoked;
    std::size_t sockets = 0;
    if (const auto& manager = runtime::Deps::get().sessionManager)
        for (const auto& jti : targets) sockets += manager->endSessionsWithRefreshJti(actor->id, jti, caller);

    vh::audit::record({.action = "auth.session.revoke", .actor_id = actor->id, .actor = actor->name(),
                       .details = {{"scope", req.all_others ? "all_others" : "one"},
                                   {"revoked", revoked},
                                   {"current", includesCurrent},
                                   {"sockets_closed", sockets}}},
                      "[auth] " + actor->name() + " revoked " + std::to_string(revoked) + " of their sessions");
    return revoked;
}

}
