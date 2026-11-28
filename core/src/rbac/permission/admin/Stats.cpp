#include "rbac/permission/admin/Stats.hpp"

#include <nlohmann/json.hpp>
#include <ostream>
#include <sstream>

namespace vh::rbac::permission::admin {
    std::string Stats::toString(const uint8_t indent) const {
        std::ostringstream oss;
        oss << std::string(indent, ' ') << "Stats:\n";
        const auto in = std::string(indent + 2, ' ');
        oss << in << "View: " << bool_to_string(canView()) << "\n";
        oss << in << "Manage: " << bool_to_string(canManage()) << "\n";
        return oss.str();
    }

    std::string Stats::toFlagsString() const {
        return joinFlagsWithOwn();
    }

    Stats::Mask Stats::toMask() const { return packWithOwn(); }
    void Stats::fromMask(const Mask mask) { unpackWithOwn(mask); }

    void to_json(nlohmann::json &j, const Stats &s) {
        j = {{"view", s.canView()}, {"manage", s.canManage()}};
    }

    void from_json(const nlohmann::json &j, Stats &s) {
        s.clear();
        if (j.at("view").get<bool>()) s.grant(StatsPermissions::View);
        // Absent in roles written before the permission existed: not granted.
        if (j.value("manage", false)) s.grant(StatsPermissions::Manage);
    }
}
