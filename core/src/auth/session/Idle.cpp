#include "auth/session/Idle.hpp"

#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "config/Registry.hpp"
#include "protocols/ws/Session.hpp"

namespace vh::auth::session::idle {

std::chrono::minutes timeout() {
    return std::chrono::minutes(config::Registry::get().services.connection_lifecycle_manager.idle_timeout_minutes);
}

bool applies(const protocols::ws::Session& session) {
    return session.user && !session.onDeviceListener() && !session.isShareSession() && session.tokens &&
           session.tokens->refreshToken;
}

bool sessionExpired(const protocols::ws::Session& session) {
    if (!applies(session)) return false;
    return expired(session.tokens->refreshToken->lastActivity, std::chrono::system_clock::now(), timeout());
}

}
