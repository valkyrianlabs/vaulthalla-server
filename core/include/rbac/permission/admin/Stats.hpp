#pragma once

#include "rbac/permission/template/ModuleSet.hpp"
#include "rbac/permission/template/Traits.hpp"

#include <cstdint>
#include <nlohmann/json_fwd.hpp>

namespace vh::rbac::permission {
    namespace admin {
        // Runtime telemetry (#166): server, daemon and system stats, the health dashboard and its severity. Vault-scoped
        // stats are authorized per vault instead (admin.vaults.*.view_stats, or owning the vault). Bit positions are
        // persisted in admin_role.stats_permissions (migration 105): append new bits, never renumber.
        enum class StatsPermissions : uint8_t {
            None = 0,
            View = 1 << 0,
            // Acknowledging and silencing health findings (design/health/findings.md §4): it changes what every
            // operator is told, so seeing the dashboard is not enough.
            Manage = 1 << 1,
            All = View | Manage
        };
    }

    template<>
    struct PermissionTraits<admin::StatsPermissions> {
        using Entry = PermissionEntry<admin::StatsPermissions>;

        static constexpr std::array entries{
            Entry{admin::StatsPermissions::View, "view", "Allows viewing server, daemon and system stats and the health dashboard."},
            Entry{admin::StatsPermissions::Manage, "manage", "Allows acknowledging and silencing health findings."},
        };
    };

    namespace admin {
        struct Stats final : ModuleSet<uint8_t, StatsPermissions, uint8_t> {
            static constexpr const auto *FLAG_CONTEXT = "stats";

            Stats() = default;

            explicit Stats(const Mask &mask) : ModuleSet(mask) {}

            [[nodiscard]] const char *name() const override { return FLAG_CONTEXT; }
            [[nodiscard]] const char *flagPrefix() const override { return FLAG_CONTEXT; }
            [[nodiscard]] Mask toMask() const override;
            void fromMask(Mask mask) override;
            [[nodiscard]] std::string toFlagsString() const override;

            [[nodiscard]] std::vector<std::string> getFlags() const override {
                return getFlagsWithOwn();
            }

            [[nodiscard]] PackedPermissionExportT<Mask> exportPermissions() const {
                return packAndExportWithOwn("admin.stats");
            }

            [[nodiscard]] std::string toString(uint8_t indent) const override;

            [[nodiscard]] bool canView() const noexcept { return has(StatsPermissions::View); }
            [[nodiscard]] bool canManage() const noexcept { return has(StatsPermissions::Manage); }

            static Stats None() {
                Stats s;
                s.clear();
                return s;
            }

            static Stats ViewOnly() {
                Stats s;
                s.clear();
                s.grant(StatsPermissions::View);
                return s;
            }

            static Stats Full() {
                Stats s;
                s.clear();
                s.grant(StatsPermissions::All);
                return s;
            }
        };

        void to_json(nlohmann::json &j, const Stats &s);

        void from_json(const nlohmann::json &j, Stats &s);
    }
}
