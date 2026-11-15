#pragma once

#include <ctime>
#include <optional>
#include <string>

// The relay's local switch (migration 144, `cloud_relay`): on for one linked installation, by a super admin.
// Trusted primitives: ops::cloud_relay authorizes.
namespace vh::db::query::cloud {

struct RelaySwitchRow {
    std::string installation_id;
    std::string enabled_by;
    std::time_t enabled_at = 0;
};

struct RelaySwitch {
    [[nodiscard]] static std::optional<RelaySwitchRow> get();
    // On for `installationId` (replacing any earlier row).
    static void enable(const std::string& installationId, const std::string& by);
    // Off. True when it was on.
    static bool disable();
};

}
