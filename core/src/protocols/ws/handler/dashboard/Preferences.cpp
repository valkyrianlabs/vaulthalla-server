#include "protocols/ws/handler/dashboard/Preferences.hpp"

#include "db/query/dashboard/Preferences.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"
#include "stats/model/DashboardPreferences.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/except>
#include <stdexcept>
#include <utility>

namespace vh::protocols::ws::handler::dashboard {

namespace {

constexpr const char* kDefaultPreferenceKey = "dashboard.home";

std::uint32_t currentUserId(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw std::runtime_error("Unauthorized");
    if (session->user->id == 0) throw std::runtime_error("Unauthorized");
    return session->user->id;
}

std::string preferenceKeyFromPayload(const json& payload) {
    if (!payload.is_object()) return kDefaultPreferenceKey;
    return payload.value("preference_key", std::string{kDefaultPreferenceKey});
}

// db::query::dashboard::Preferences validates the key and the layout with std::invalid_argument before it opens a
// transaction, and a preference_key that is not a string fails reading the payload (json type_error): refusals of
// the request, so they answer data.code "invalid" with the same message. libpqxx's own argument_error (also an
// invalid_argument) is a fault and passes through unchanged.
template<class Fn>
auto withTypedValidation(Fn&& fn) {
    try {
        return std::forward<Fn>(fn)();
    } catch (const pqxx::argument_error&) {
        throw;
    } catch (const std::invalid_argument& e) {
        throw vh::ops::Invalid(e.what());
    } catch (const nlohmann::json::type_error& e) {
        throw vh::ops::Invalid(e.what());
    }
}

}

json Preferences::get(const json& payload, const std::shared_ptr<Session>& session) {
    const auto userId = currentUserId(session);
    const auto preferences = withTypedValidation([&] {
        return vh::db::query::dashboard::Preferences::getForUser(userId, preferenceKeyFromPayload(payload));
    });

    return {{"preferences", preferences ? json(*preferences) : json(nullptr)}};
}

json Preferences::update(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object()) throw vh::ops::Invalid("Dashboard preference update payload must be an object.");
    if (!payload.contains("layout")) throw vh::ops::Invalid("Dashboard preference update requires a layout.");

    const auto userId = currentUserId(session);
    const auto preferences = withTypedValidation([&] {
        return vh::db::query::dashboard::Preferences::upsertForUser(userId, preferenceKeyFromPayload(payload),
                                                                     payload.at("layout"));
    });

    return {{"preferences", preferences ? json(*preferences) : json(nullptr)}};
}

json Preferences::reset(const json& payload, const std::shared_ptr<Session>& session) {
    const auto userId = currentUserId(session);
    const auto reset = withTypedValidation([&] {
        return vh::db::query::dashboard::Preferences::resetForUser(userId, preferenceKeyFromPayload(payload));
    });

    return {{"reset", true}, {"deleted", reset}};
}

}
