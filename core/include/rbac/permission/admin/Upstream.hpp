#pragma once

#include "rbac/permission/template/ModuleSet.hpp"
#include "rbac/permission/template/Traits.hpp"

#include <cstdint>
#include <nlohmann/json_fwd.hpp>

namespace vh::rbac::permission {
    namespace admin {
        // Upstream control plane (#237, #96): provider bucket inventory, hard protection locks, lifecycle and event
        // subscriptions, bucket provisioning/adoption and explicit cleanup. Each ops::upstream operation also needs the
        // API key's own keys.api permission. Bit positions are persisted in admin_role.upstream_permissions
        // (migration 110): append new bits, never renumber.
        enum class UpstreamPermissions : uint8_t {
            None = 0,
            View = 1 << 0,
            Configure = 1 << 1,
            Provision = 1 << 2,
            Protect = 1 << 3,
            Unprotect = 1 << 4,
            Destroy = 1 << 5,
            All = View | Configure | Provision | Protect | Unprotect | Destroy
        };
    }

    template<>
    struct PermissionTraits<admin::UpstreamPermissions> {
        using Entry = PermissionEntry<admin::UpstreamPermissions>;

        static constexpr std::array entries{
            Entry{admin::UpstreamPermissions::View, "view",
                  "Allows viewing upstream bucket inventory, bucket configuration, event status and the upstream audit log."},
            Entry{admin::UpstreamPermissions::Configure, "configure",
                  "Allows enabling provider administration on API keys and managing lifecycle rules and event subscriptions."},
            Entry{admin::UpstreamPermissions::Provision, "provision",
                  "Allows creating managed upstream buckets and adopting existing ones into vaults."},
            Entry{admin::UpstreamPermissions::Protect, "protect",
                  "Allows protecting upstream buckets from every Vaulthalla operation."},
            Entry{admin::UpstreamPermissions::Unprotect, "unprotect",
                  "Allows removing upstream bucket protection."},
            Entry{admin::UpstreamPermissions::Destroy, "destroy",
                  "Allows detaching managed buckets and deleting upstream buckets and their objects."},
        };
    };

    namespace admin {
        struct Upstream final : ModuleSet<uint8_t, UpstreamPermissions, uint8_t> {
            static constexpr const auto *FLAG_CONTEXT = "upstream";

            Upstream() = default;

            explicit Upstream(const Mask &mask) : ModuleSet(mask) {}

            [[nodiscard]] const char *name() const override { return FLAG_CONTEXT; }
            [[nodiscard]] const char *flagPrefix() const override { return FLAG_CONTEXT; }
            [[nodiscard]] Mask toMask() const override;
            void fromMask(Mask mask) override;
            [[nodiscard]] std::string toFlagsString() const override;

            [[nodiscard]] std::vector<std::string> getFlags() const override {
                return getFlagsWithOwn();
            }

            [[nodiscard]] PackedPermissionExportT<Mask> exportPermissions() const {
                return packAndExportWithOwn("admin.upstream");
            }

            [[nodiscard]] std::string toString(uint8_t indent) const override;

            [[nodiscard]] bool canView() const noexcept { return has(UpstreamPermissions::View); }
            [[nodiscard]] bool canConfigure() const noexcept { return has(UpstreamPermissions::Configure); }
            [[nodiscard]] bool canProvision() const noexcept { return has(UpstreamPermissions::Provision); }
            [[nodiscard]] bool canProtect() const noexcept { return has(UpstreamPermissions::Protect); }
            [[nodiscard]] bool canUnprotect() const noexcept { return has(UpstreamPermissions::Unprotect); }
            [[nodiscard]] bool canDestroy() const noexcept { return has(UpstreamPermissions::Destroy); }

            static Upstream None() {
                Upstream u;
                u.clear();
                return u;
            }

            static Upstream ViewOnly() {
                Upstream u;
                u.clear();
                u.grant(UpstreamPermissions::View);
                return u;
            }

            // View + protect: security roles may lock buckets, never unlock or destroy them.
            static Upstream Guardian() {
                Upstream u;
                u.clear();
                u.grant(UpstreamPermissions::View);
                u.grant(UpstreamPermissions::Protect);
                return u;
            }

            // Day-to-day administration: everything but unlocking and destroying.
            static Upstream Operator() {
                Upstream u;
                u.clear();
                u.grant(UpstreamPermissions::View);
                u.grant(UpstreamPermissions::Configure);
                u.grant(UpstreamPermissions::Provision);
                u.grant(UpstreamPermissions::Protect);
                return u;
            }

            static Upstream Full() {
                Upstream u;
                u.clear();
                u.grant(UpstreamPermissions::All);
                return u;
            }
        };

        void to_json(nlohmann::json &j, const Upstream &u);

        void from_json(const nlohmann::json &j, Upstream &u);
    }
}
