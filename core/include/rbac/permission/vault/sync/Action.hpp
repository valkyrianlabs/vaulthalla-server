#pragma once

#include "rbac/permission/template/Set.hpp"
#include "rbac/permission/template/Traits.hpp"

#include <nlohmann/json_fwd.hpp>

namespace vh::rbac::permission {
    namespace vault::sync {
        enum class SyncActionPermissions : uint8_t {
            None = 0,
            Trigger = 1 << 0,
            SignWaiver = 1 << 1,
            // #187: keep local / keep remote on a conflict recorded under the `ask` policy. Bit 2: no stored bit moves.
            ResolveConflicts = 1 << 2,
            // Vault read grants (ops/ReadGrants.hpp, migration 155): issue, list and revoke credentials that let a
            // pinned OpenPGP recipient read the vault through the S3 gateway and from its upstream bucket. Bit 3: no
            // stored bit moves. Deliberately outside All: no built-in role or preset grants it; it is given explicitly.
            ReadGrants = 1 << 3,
            All = Trigger | SignWaiver | ResolveConflicts
        };
    }

    template<>
    struct PermissionTraits<vault::sync::SyncActionPermissions> {
        using Entry = PermissionEntry<vault::sync::SyncActionPermissions>;

        static constexpr std::array entries{
            Entry{vault::sync::SyncActionPermissions::Trigger, "trigger", "Allows the user to trigger a sync action."},
            Entry{vault::sync::SyncActionPermissions::SignWaiver, "sign_waiver", "Allows the user to sign a waiver enabling upstream encryption (eg. S3) for vault."},
            Entry{vault::sync::SyncActionPermissions::ResolveConflicts, "resolve_conflicts", "Allows the user to resolve sync conflicts (keep local or keep remote); each file also needs Overwrite."},
            Entry{vault::sync::SyncActionPermissions::ReadGrants, "read_grants", "Allows the user to issue, list and revoke vault read grants: read-only S3 gateway and upstream credentials, delivered only encrypted to a pinned OpenPGP recipient."},
        };
    };

    namespace vault::sync {
        struct Action final : Set<SyncActionPermissions, uint8_t> {
            static constexpr const auto* FLAG_CONTEXT = "sync-action";

            [[nodiscard]] const char* flagPrefix() const override { return FLAG_CONTEXT; }
            [[nodiscard]] std::string toString(uint8_t indent) const override;

            [[nodiscard]] bool canTrigger() const noexcept { return has(SyncActionPermissions::Trigger); }
            [[nodiscard]] bool canSignWaiver() const noexcept { return has(SyncActionPermissions::SignWaiver); }
            [[nodiscard]] bool canResolveConflicts() const noexcept { return has(SyncActionPermissions::ResolveConflicts); }
            [[nodiscard]] bool canManageReadGrants() const noexcept { return has(SyncActionPermissions::ReadGrants); }

            static Action None() {
                Action a;
                a.clear();
                return a;
            }

            static Action TriggerOnly() {
                Action a;
                a.clear();
                a.grant(SyncActionPermissions::Trigger);
                return a;
            }

            // Run syncs and resolve the conflicts they record (the built-in operator/manager roles).
            static Action Operate() {
                Action a;
                a.clear();
                a.grant(SyncActionPermissions::Trigger);
                a.grant(SyncActionPermissions::ResolveConflicts);
                return a;
            }

            static Action WaiverOnly() {
                Action a;
                a.clear();
                a.grant(SyncActionPermissions::SignWaiver);
                return a;
            }

            static Action Full() {
                Action a;
                a.clear();
                a.grant(SyncActionPermissions::All);
                return a;
            }
        };

        void to_json(nlohmann::json& j, const Action& a);
        void from_json(const nlohmann::json& j, Action& a);
    }
}
