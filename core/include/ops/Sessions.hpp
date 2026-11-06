#pragma once

#include "ops/Actor.hpp"
#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The signed-in web sessions of the caller's own account (#354): auth.sessions.list and auth.sessions.revoke, the
// console's Account → Security → Sessions panel. A session is one refresh token row (every tab of one browser shares
// it). Nobody lists or revokes another account's sessions here; admins end those through the account itself
// (deactivation, role change, password reset: auth::Manager::revokeSessions).
//
// Ids are opaque: a keyed hash of the row's jti under a key that lives only in this process, so an id never reveals
// the jti (the refresh JWT's id) and stops matching after a restart (list again).
namespace vh::ops::sessions {

struct Info {
    std::string id{};
    bool current{false};  // the session the request came in on
    int aal{1};
    std::vector<std::string> amr{};
    int64_t auth_time{};         // Unix seconds
    int64_t last_activity_at{};  // Unix seconds
    std::string ip_address{};
    std::string user_agent{};
};

// The ws shape (contract model AuthSession).
void to_json(nlohmann::json& j, const Info& info);

// The opaque id of the session whose refresh token has this jti.
[[nodiscard]] std::string handle(std::string_view jti);

// The caller's live sessions (not revoked, not expired, not past the idle timeout), most recent sign-in first.
// `currentJti`: the refresh token of the session asking (none for a device session).
[[nodiscard]] std::vector<Info> list(const Actor& actor, const std::optional<std::string>& currentJti);

struct Revoke {
    std::optional<std::string> id{};  // one session
    bool all_others{false};           // every session but the current one
};

// Revokes the rows and ends their sockets and HTTP lanes at once. Exactly one of id / all_others. `caller` is the ws
// session asking (closed after its reply when it revokes itself). Returns how many sessions were revoked; an id that
// is not one of the caller's live sessions is ops::NotFound.
[[nodiscard]] std::size_t revoke(const Actor& actor, const std::optional<std::string>& currentJti, const Revoke& req,
                                 const std::shared_ptr<protocols::ws::Session>& caller);

}
