#pragma once

#include "rbac/permission/template/Module.hpp"
#include "rbac/permission/vault/sync/Config.hpp"
#include "rbac/permission/vault/sync/Action.hpp"

#include <cstdint>
#include <memory>
#include <nlohmann/json_fwd.hpp>

namespace vh::rbac::permission::vault {

struct Sync final : Module<uint32_t> {
    static constexpr const auto* ModuleName = "Sync";

    sync::Config config;
    sync::Action action;

    Sync() = default;
    explicit Sync(const Mask& mask) { fromMask(mask); }

    [[nodiscard]] std::string toString(uint8_t indent) const override;
    [[nodiscard]] std::string toFlagsString() const override;

    [[nodiscard]] const char* name() const override { return ModuleName; }

    [[nodiscard]] std::vector<std::string> getFlags() const override { return Module::getFlags(config, action); }

    [[nodiscard]] uint32_t toMask() const override { return pack(config, action); }
    void fromMask(const Mask mask) override { unpack(mask, config, action); }

    [[nodiscard]] bool canViewConfig() const noexcept { return config.canView(); }
    [[nodiscard]] bool canEditConfig() const noexcept { return config.canEdit(); }
    [[nodiscard]] bool canTriggerSync() const noexcept { return action.canTrigger(); }
    [[nodiscard]] bool canSignWaiver() const noexcept { return action.canSignWaiver(); }
    [[nodiscard]] bool canResolveConflicts() const noexcept { return action.canResolveConflicts(); }
    [[nodiscard]] bool canManageReadGrants() const noexcept { return action.canManageReadGrants(); }

    [[nodiscard]] PackedPermissionExportT<Mask> exportPermissions() const {
        return packAndExportPerms(
            mount("vault.sync.config", config),
            mount("vault.sync.action", action)
        );
    }

    static Sync None() {
        Sync s;
        s.config = sync::Config::None();
        s.action = sync::Action::None();
        return s;
    }

    static Sync Viewer() {
        Sync s;
        s.config = sync::Config::ViewOnly();
        s.action = sync::Action::None();
        return s;
    }

    static Sync Operator() {
        Sync s;
        s.config = sync::Config::ViewOnly();
        s.action = sync::Action::Operate();
        return s;
    }

    static Sync Manager() {
        Sync s;
        s.config = sync::Config::Editor();
        s.action = sync::Action::Operate();
        return s;
    }

    static Sync WaiverSigner() {
        Sync s;
        s.config = sync::Config::ViewOnly();
        s.action = sync::Action::WaiverOnly();
        return s;
    }

    static Sync SecureOperator() {
        Sync s;
        s.config = sync::Config::ViewOnly();
        s.action = sync::Action::Full();
        return s;
    }

    static Sync Full() {
        Sync s;
        s.config = sync::Config::Full();
        s.action = sync::Action::Full();
        return s;
    }

    static Sync Custom(sync::Config config, sync::Action action) {
        Sync s;
        s.config = std::move(config);
        s.action = std::move(action);
        return s;
    }
};

void to_json(nlohmann::json& j, const Sync& v);
void from_json(const nlohmann::json& j, Sync& v);

}
