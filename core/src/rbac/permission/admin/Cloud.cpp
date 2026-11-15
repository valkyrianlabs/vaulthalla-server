#include "rbac/permission/admin/Cloud.hpp"

#include <nlohmann/json.hpp>
#include <ostream>
#include <sstream>

namespace vh::rbac::permission::admin {
    std::string Cloud::toString(const uint8_t indent) const {
        std::ostringstream oss;
        oss << std::string(indent, ' ') << "Cloud:\n";
        const auto in = std::string(indent + 2, ' ');
        oss << in << "View: " << bool_to_string(canView()) << "\n";
        oss << in << "Storage: " << bool_to_string(canManageStorage()) << "\n";
        oss << in << "Billing: " << bool_to_string(canBilling()) << "\n";
        return oss.str();
    }

    std::string Cloud::toFlagsString() const {
        return joinFlagsWithOwn();
    }

    Cloud::Mask Cloud::toMask() const { return packWithOwn(); }
    void Cloud::fromMask(const Mask mask) { unpackWithOwn(mask); }

    void to_json(nlohmann::json &j, const Cloud &s) {
        j = {{"view", s.canView()}, {"storage", s.canManageStorage()}, {"billing", s.canBilling()}};
    }

    void from_json(const nlohmann::json &j, Cloud &s) {
        s.clear();
        if (j.value("view", false)) s.grant(CloudPermissions::View);
        if (j.value("storage", false)) s.grant(CloudPermissions::Storage);
        if (j.value("billing", false)) s.grant(CloudPermissions::Billing);
    }
}
