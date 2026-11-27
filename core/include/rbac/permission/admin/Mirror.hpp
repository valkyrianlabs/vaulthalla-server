#pragma once

#include "rbac/permission/template/ModuleSet.hpp"
#include "rbac/permission/template/Traits.hpp"

#include <cstdint>
#include <nlohmann/json_fwd.hpp>

namespace vh::rbac::permission {
    namespace admin {
        // Leaving a mirror (design/peers/mirror.md "Who may do it"; design/peers/identity.md "The permission to leave"):
        // admin permissions on the server that holds another server's copy of a vault, outside the shared access list,
        // so nothing the core governs can take them away. Detach turns a held copy (live, stopped, diverged, expired or
        // orphaned) into an ordinary local vault here. Super admins hold every bit; no other built-in role holds any.
        // Never an agent, a scoped device or a relayed session, whatever its role (ops::peer_policy::requirePerson).
        // Bit positions are persisted in admin_role.mirror_permissions (migration 167): append new bits (take over as
        // core is the next), never renumber.
        enum class MirrorPermissions : uint8_t {
            None = 0,
            Detach = 1 << 0,
            All = Detach
        };
    }

    template<>
    struct PermissionTraits<admin::MirrorPermissions> {
        using Entry = PermissionEntry<admin::MirrorPermissions>;

        static constexpr std::array entries{
            Entry{admin::MirrorPermissions::Detach, "detach",
                  "Allows detaching mirrored vaults: a copy of another server's vault held here becomes a standalone "
                  "vault on this server."},
        };
    };

    namespace admin {
        struct Mirror final : ModuleSet<uint8_t, MirrorPermissions, uint8_t> {
            static constexpr const auto *FLAG_CONTEXT = "mirror";

            Mirror() = default;

            explicit Mirror(const Mask &mask) : ModuleSet(mask) {}

            [[nodiscard]] const char *name() const override { return FLAG_CONTEXT; }
            [[nodiscard]] const char *flagPrefix() const override { return FLAG_CONTEXT; }
            [[nodiscard]] Mask toMask() const override;
            void fromMask(Mask mask) override;
            [[nodiscard]] std::string toFlagsString() const override;

            [[nodiscard]] std::vector<std::string> getFlags() const override {
                return getFlagsWithOwn();
            }

            [[nodiscard]] PackedPermissionExportT<Mask> exportPermissions() const {
                return packAndExportWithOwn("admin.mirror");
            }

            [[nodiscard]] std::string toString(uint8_t indent) const override;

            [[nodiscard]] bool canDetach() const noexcept { return has(MirrorPermissions::Detach); }

            static Mirror None() {
                Mirror s;
                s.clear();
                return s;
            }

            static Mirror Full() {
                Mirror s;
                s.clear();
                s.grant(MirrorPermissions::All);
                return s;
            }
        };

        void to_json(nlohmann::json &j, const Mirror &s);

        void from_json(const nlohmann::json &j, Mirror &s);
    }
}
