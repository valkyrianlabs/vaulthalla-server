#pragma once

#include "cloud/RelayService.hpp"
#include "ops/Actor.hpp"

#include <nlohmann/json_fwd.hpp>

// The Vaulthalla Cloud relay's local switch (design/cloud/relay.md): off by default, on for this linked installation
// only, by a super admin (`vh cloud relay enable|disable`, ws cloud.relay.enable|disable; switching it on is a
// device.trust step-up, like remote device connections: it admits relayed pairing attempts). The account holder has a
// switch at the cloud too; both must be on. Status: super admins and the admin cloud View permission. Agents may read
// the status and never switch it.
namespace vh::ops::cloud_relay {

enum class Channel { Cli, Web, Agent };

// What the service reports, plus the switch.
[[nodiscard]] ::vh::cloud::RelayStatus status(const Actor& actor);
// On for the linked installation (Conflict when not linked); wakes the service. Audited cloud.relay.enable.
::vh::cloud::RelayStatus enable(const Actor& actor, Channel channel);
// Off: the connection and every relayed session close. Audited cloud.relay.disable when it was on.
::vh::cloud::RelayStatus disable(const Actor& actor, Channel channel);

[[nodiscard]] nlohmann::json toJson(const ::vh::cloud::RelayStatus& s);

}
