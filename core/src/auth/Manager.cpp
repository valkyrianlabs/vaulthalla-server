#include "auth/Manager.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "auth/session/Manager.hpp"
#include "auth/registration/Validator.hpp"
#include "crypto/util/hash.hpp"
#include "db/query/identities/Loader.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "storage/Manager.hpp"
#include "protocols/ws/Session.hpp"
#include "log/Registry.hpp"
#include "crypto/secrets/Manager.hpp"
#include "runtime/Deps.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/Bootstrap.hpp"

#include <sodium.h>
#include <stdexcept>
#include <uuid/uuid.h>

using namespace vh::auth;
using namespace vh::auth::model;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::crypto;
using namespace vh::storage;
using namespace vh::protocols::ws;

namespace vh::auth {
namespace {
void validateNewPassword(const std::string& newPassword) {
    if (const auto violation = registration::Validator::passwordPolicyViolation(newPassword))
        throw std::runtime_error("New password does not meet password policy: " + *violation);
}

std::string hashNewPassword(const std::string& newPassword) {
    validateNewPassword(newPassword);

    auto passwordHash = hash::password(newPassword);
    if (passwordHash.empty()) throw std::runtime_error("Failed to hash new password");
    return passwordHash;
}
}

std::shared_ptr<User> Manager::registerUser(const identities::UserState& draft, const std::string& password) {
    registration::Validator::validateRegistration(draft, password);

    auto& identities = vh::identities::manager();
    const auto user = identities.createUser(draft, hash::password(password));
    try {
        runtime::Deps::get().storageManager->initUserStorage(user);
    } catch (...) {
        // Don't leave a half-registered account behind an error response.
        identities.deleteUser(user->id);
        throw;
    }

    log::Registry::auth()->info("[AuthManager] User registered: {}", draft.name);
    return user;
}

// Credentials always come from the database (never from cached identity state): accounts change through the CLI and
// the web alike, and a login or a password check against a cached copy honoured renamed, deactivated, demoted and
// even deleted accounts.
void Manager::loginUser(const std::string& name, const std::string& password, const std::shared_ptr<Session>& session) {
    const auto credentials = db::query::identities::Loader::credentialsByName(name);
    if (!credentials) throw std::runtime_error("User not found: " + name);
    if (credentials->systemOnly) throw std::runtime_error("System-only users cannot log in");
    if (!credentials->active) throw std::runtime_error("This account is deactivated");

    if (!hash::verifyPassword(password, credentials->passwordHash)) throw std::runtime_error(
        "Invalid password for user: " + name);

    auto& identities = vh::identities::manager();
    identities.recordLogin(credentials->id);
    const auto user = identities.user(credentials->id);
    if (!user) throw std::runtime_error("User not found: " + name);

    session->setAuthenticatedUser(user);
    runtime::Deps::get().sessionManager->promote(session);

    log::Registry::auth()->info("[AuthManager] User logged in: {}", name);
}

std::shared_ptr<User> Manager::changePassword(const uint32_t userId, const std::string& oldPassword,
                                              const std::string& newPassword) {
    const auto user = getUser(userId);
    const auto credentials = db::query::identities::Loader::credentialsById(userId);
    if (!credentials) throw std::runtime_error("User not found: " + std::to_string(userId));
    if (credentials->systemOnly) throw std::runtime_error("System-only users cannot change passwords");

    const auto name = user->name();
    if (!hash::verifyPassword(oldPassword, credentials->passwordHash)) throw std::runtime_error(
        "Invalid old password for user: " + name);

    vh::identities::manager().setPasswordHash(userId, hashNewPassword(newPassword));

    log::Registry::audit()->info("[AuthManager] User {} is changing password", name);
    log::Registry::auth()->info("[AuthManager] Changing password for user: {}", name);
    if (name == bootstrap::kSuperAdminName) (void)bootstrap::onSuperAdminPasswordChanged();

    return user;
}

std::shared_ptr<User> Manager::resetPassword(const uint32_t userId, const std::string& newPassword) {
    const auto user = getUser(userId);
    if (user->systemOnly()) throw std::runtime_error("System-only users cannot receive normal user passwords");

    vh::identities::manager().setPasswordHash(userId, hashNewPassword(newPassword));

    const auto name = user->name();
    log::Registry::audit()->info("[AuthManager] Password reset for user {}", name);
    log::Registry::auth()->info("[AuthManager] Reset password for user: {}", name);
    if (name == bootstrap::kSuperAdminName) (void)bootstrap::onSuperAdminPasswordChanged();

    return user;
}

std::shared_ptr<User> Manager::getUser(const std::string& name) {
    if (const auto user = vh::identities::manager().userByName(name)) return user;
    throw std::runtime_error("User not found: " + name);
}

std::shared_ptr<identities::User> Manager::getUser(const uint32_t id) {
    if (const auto user = vh::identities::manager().user(id)) return user;
    throw std::runtime_error("User not found: " + std::to_string(id));
}

void Manager::revokeSessions(const uint32_t userId) {
    // Refresh tokens first, so no live session can rehydrate from one while the runtime sessions are dropped.
    db::query::auth::RefreshToken::revokeAll(userId);
    if (const auto& sessions = runtime::Deps::get().sessionManager)
        for (const auto& session : sessions->getSessionsByUserId(userId)) {
            try {
                sessions->invalidate(session);
                // A paired device's session has no token to revoke: it ends now, and its next connection is
                // authorized afresh (or refused) at the TLS handshake.
                if (session->isDeviceSession()) session->close();
            } catch (const std::exception& e) {
                log::Registry::auth()->error("[AuthManager] Failed to invalidate a session of user id {}: {}", userId, e.what());
            }
        }
    log::Registry::auth()->info("[AuthManager] Revoked sessions for user id {}", userId);
}
}
