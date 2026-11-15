#include "ops/CloudRelay.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/cloud/Relay.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/device/Service.hpp"

#include <nlohmann/json.hpp>


namespace vh::ops::cloud_relay {

namespace {

using json = nlohmann::json;

void requireView(const Actor& actor) {
    requireActor(actor);
    if (!actor->isSuperAdmin() && !actor->cloudPerms().canView())
        throw Denied("only super admins or users with the view cloud permission can see the relay");
}

void requireSwitch(const Actor& actor, const Channel channel) {
    requireActor(actor);
    if (channel == Channel::Agent)
        throw Denied("whether browsers may reach this server through Vaulthalla Cloud is decided by a person, never an "
                     "agent; run `vh cloud relay` yourself");
    if (!actor->isSuperAdmin()) throw Denied("only a super admin can switch the Vaulthalla Cloud relay");
}

// The service's view, with the switch read from the database (the service may not have looked yet).
::vh::cloud::RelayStatus current() {
    auto s = ::vh::cloud::relaySnapshot().value_or(::vh::cloud::RelayStatus{});
    const auto row = db::query::cloud::Link::get();
    const bool linked = row && row->status == "linked" && row->installation_id;
    const auto sw = db::query::cloud::RelaySwitch::get();
    s.enabled = linked && sw && sw->installation_id == *row->installation_id;
    s.enabled_by = s.enabled ? std::optional(sw->enabled_by) : std::nullopt;
    s.enabled_at = s.enabled ? std::optional(sw->enabled_at) : std::nullopt;
    if (!linked) s.state = "not_linked";
    else if (!s.enabled) s.state = "off";
    else if (s.state == "off" || s.state == "not_linked") s.state = "connecting";  // switched on; the service looks next
    return s;
}

json optTime(const std::optional<std::time_t>& t) { return t ? json(static_cast<int64_t>(*t)) : json(nullptr); }
json optStr(const std::optional<std::string>& s) { return s ? json(*s) : json(nullptr); }

}

::vh::cloud::RelayStatus status(const Actor& actor) {
    requireView(actor);
    return current();
}

::vh::cloud::RelayStatus enable(const Actor& actor, const Channel channel) {
    requireSwitch(actor, channel);
    const auto row = db::query::cloud::Link::get();
    if (!row || row->status != "linked" || !row->installation_id)
        throw Conflict("this server isn't linked to a Vaulthalla Cloud account (`vh cloud link`)");
    if (const auto sw = db::query::cloud::RelaySwitch::get(); sw && sw->installation_id == *row->installation_id) {
        ::vh::cloud::wakeRelay(true);  // already on: switching it on again is how a stopped relay tries again
        return current();
    }
    auth::stepup::require(auth::stepup::Family::DeviceTrust, std::string("cloud.relay.enable"));
    db::query::cloud::RelaySwitch::enable(*row->installation_id, actor->name());
    ::vh::audit::record({.action = "cloud.relay.enable", .actor_id = actor->id, .actor = actor->name(),
                         .details = {{"installation", *row->installation_id}}},
                        "[ops::cloud_relay] " + actor->name() + " switched the Vaulthalla Cloud relay on");
    ::vh::cloud::wakeRelay(true);
    return current();
}

::vh::cloud::RelayStatus disable(const Actor& actor, const Channel channel) {
    requireSwitch(actor, channel);
    if (db::query::cloud::RelaySwitch::disable()) {
        ::vh::audit::record({.action = "cloud.relay.disable", .actor_id = actor->id, .actor = actor->name(),
                             .details = json::object()},
                            "[ops::cloud_relay] " + actor->name() + " switched the Vaulthalla Cloud relay off");
    }
    ::vh::cloud::wakeRelay();
    // At once, not at the service's next look: switching off ends every relayed session.
    (void)protocols::device::closeRelayedDeviceSessions();
    return current();
}

json toJson(const ::vh::cloud::RelayStatus& s) {
    return {{"state", s.state},
            {"enabled", s.enabled},
            {"enabled_by", optStr(s.enabled_by)},
            {"enabled_at", optTime(s.enabled_at)},
            {"relay_url", optStr(s.relay_url)},
            {"connected_since", optTime(s.connected_since)},
            {"renew_by", optTime(s.renew_by)},
            {"last_ticket_at", optTime(s.last_ticket_at)},
            {"next_attempt_at", optTime(s.next_attempt_at)},
            {"last_error", optStr(s.last_error)},
            {"streams", s.streams},
            {"streams_accepted", s.streams_accepted},
            {"streams_refused", s.streams_refused}};
}

}
