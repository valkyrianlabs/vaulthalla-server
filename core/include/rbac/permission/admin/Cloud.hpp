#pragma once

#include "rbac/permission/template/ModuleSet.hpp"
#include "rbac/permission/template/Traits.hpp"

#include <cstdint>
#include <nlohmann/json_fwd.hpp>

namespace vh::rbac::permission {
    namespace admin {
        // The server's link to an account and its managed storage (design/cloud/managed-remotes.md, "Surfaces"): view
        // (the link and the managed-storage status), storage (per-vault switches, the offer, bucket key rotation and
        // the default for new vaults; a switch also needs the vault's admin Edit permission) and billing (opening the
        // account's billing pages). Linking and unlinking stay super-admin only; recovery keeps its own rules. Bit
        // positions are persisted in admin_role.cloud_permissions (migration 142): append new bits, never renumber.
        enum class CloudPermissions : uint8_t {
            None = 0,
            View = 1 << 0,
            Storage = 1 << 1,
            Billing = 1 << 2,
            All = View | Storage | Billing
        };
    }

    template<>
    struct PermissionTraits<admin::CloudPermissions> {
        using Entry = PermissionEntry<admin::CloudPermissions>;

        static constexpr std::array entries{
            Entry{admin::CloudPermissions::View, "view", "Allows viewing the server's link and its managed storage."},
            Entry{admin::CloudPermissions::Storage, "storage",
                  "Allows switching managed storage on or off per vault, answering the offer, rotating bucket keys and "
                  "setting the default for new vaults."},
            Entry{admin::CloudPermissions::Billing, "billing", "Allows opening the account's billing pages."},
        };
    };

    namespace admin {
        struct Cloud final : ModuleSet<uint8_t, CloudPermissions, uint8_t> {
            static constexpr const auto *FLAG_CONTEXT = "cloud";

            Cloud() = default;

            explicit Cloud(const Mask &mask) : ModuleSet(mask) {}

            [[nodiscard]] const char *name() const override { return FLAG_CONTEXT; }
            [[nodiscard]] const char *flagPrefix() const override { return FLAG_CONTEXT; }
            [[nodiscard]] Mask toMask() const override;
            void fromMask(Mask mask) override;
            [[nodiscard]] std::string toFlagsString() const override;

            [[nodiscard]] std::vector<std::string> getFlags() const override {
                return getFlagsWithOwn();
            }

            [[nodiscard]] PackedPermissionExportT<Mask> exportPermissions() const {
                return packAndExportWithOwn("admin.cloud");
            }

            [[nodiscard]] std::string toString(uint8_t indent) const override;

            [[nodiscard]] bool canView() const noexcept { return has(CloudPermissions::View); }
            [[nodiscard]] bool canManageStorage() const noexcept { return has(CloudPermissions::Storage); }
            [[nodiscard]] bool canBilling() const noexcept { return has(CloudPermissions::Billing); }

            static Cloud None() {
                Cloud s;
                s.clear();
                return s;
            }

            static Cloud ViewOnly() {
                Cloud s;
                s.clear();
                s.grant(CloudPermissions::View);
                return s;
            }

            static Cloud Full() {
                Cloud s;
                s.clear();
                s.grant(CloudPermissions::All);
                return s;
            }
        };

        void to_json(nlohmann::json &j, const Cloud &s);

        void from_json(const nlohmann::json &j, Cloud &s);
    }
}
