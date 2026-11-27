#include "rbac/permission/admin/Mirror.hpp"

#include <nlohmann/json.hpp>
#include <ostream>
#include <sstream>

namespace vh::rbac::permission::admin {
    std::string Mirror::toString(const uint8_t indent) const {
        std::ostringstream oss;
        oss << std::string(indent, ' ') << "Mirror:\n";
        const auto in = std::string(indent + 2, ' ');
        oss << in << "Detach: " << bool_to_string(canDetach()) << "\n";
        oss << in << "Takeover: " << bool_to_string(canTakeover()) << "\n";
        return oss.str();
    }

    std::string Mirror::toFlagsString() const {
        return joinFlagsWithOwn();
    }

    Mirror::Mask Mirror::toMask() const { return packWithOwn(); }
    void Mirror::fromMask(const Mask mask) { unpackWithOwn(mask); }

    void to_json(nlohmann::json &j, const Mirror &s) {
        j = {{"detach", s.canDetach()}, {"takeover", s.canTakeover()}};
    }

    void from_json(const nlohmann::json &j, Mirror &s) {
        s.clear();
        if (j.value("detach", false)) s.grant(MirrorPermissions::Detach);
        if (j.value("takeover", false)) s.grant(MirrorPermissions::Takeover);
    }
}
