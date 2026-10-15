#include "rbac/permission/admin/Upstream.hpp"

#include <nlohmann/json.hpp>
#include <ostream>
#include <sstream>

namespace vh::rbac::permission::admin {
    std::string Upstream::toString(const uint8_t indent) const {
        std::ostringstream oss;
        oss << std::string(indent, ' ') << "Upstream:\n";
        const auto in = std::string(indent + 2, ' ');
        oss << in << "View: " << bool_to_string(canView()) << "\n";
        oss << in << "Configure: " << bool_to_string(canConfigure()) << "\n";
        oss << in << "Provision: " << bool_to_string(canProvision()) << "\n";
        oss << in << "Protect: " << bool_to_string(canProtect()) << "\n";
        oss << in << "Unprotect: " << bool_to_string(canUnprotect()) << "\n";
        oss << in << "Destroy: " << bool_to_string(canDestroy()) << "\n";
        return oss.str();
    }

    std::string Upstream::toFlagsString() const {
        return joinFlagsWithOwn();
    }

    Upstream::Mask Upstream::toMask() const { return packWithOwn(); }
    void Upstream::fromMask(const Mask mask) { unpackWithOwn(mask); }

    void to_json(nlohmann::json &j, const Upstream &u) {
        j = {{"view", u.canView()},
             {"configure", u.canConfigure()},
             {"provision", u.canProvision()},
             {"protect", u.canProtect()},
             {"unprotect", u.canUnprotect()},
             {"destroy", u.canDestroy()}};
    }

    void from_json(const nlohmann::json &j, Upstream &u) {
        u.clear();
        if (j.value("view", false)) u.grant(UpstreamPermissions::View);
        if (j.value("configure", false)) u.grant(UpstreamPermissions::Configure);
        if (j.value("provision", false)) u.grant(UpstreamPermissions::Provision);
        if (j.value("protect", false)) u.grant(UpstreamPermissions::Protect);
        if (j.value("unprotect", false)) u.grant(UpstreamPermissions::Unprotect);
        if (j.value("destroy", false)) u.grant(UpstreamPermissions::Destroy);
    }
}
