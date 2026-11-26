#pragma once

#include "identities/User.hpp"
#include "identities/Group.hpp"
#include "storage/Engine.hpp"
#include "log/Registry.hpp"
#include "vault/model/Vault.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace vh::rbac::resolver::vault {
    struct ResolvedContext {
        std::shared_ptr<storage::Engine> engine;
        std::shared_ptr<::vh::vault::model::Vault> vault;
        std::shared_ptr<identities::User> owner;
        std::shared_ptr<identities::User> targetUser;
        std::shared_ptr<identities::Group> targetGroup;
        // A linked server as the subject of a vault role (migration 162): the `peer` row's id. Whether it exists and
        // may be named is ops::roles' and ops::peer_policy's to check; the resolver judges the actor's right.
        std::optional<uint32_t> targetPeer;

        [[nodiscard]] bool isValid() const {
            if (!engine) log::Registry::auth()->warn("ResolvedContext is missing engine");
            if (!vault) log::Registry::auth()->warn("ResolvedContext is missing vault");
            if (!owner) log::Registry::auth()->warn("ResolvedContext is missing owner");
            return engine && vault && owner;
        }

        [[nodiscard]] bool hasTargetUser() const { return !!targetUser; }
        [[nodiscard]] bool hasTargetGroup() const { return !!targetGroup; }
        [[nodiscard]] bool hasTargetPeer() const { return targetPeer.has_value(); }
        [[nodiscard]] bool hasTargetSubject() const { return targetUser || targetGroup || targetPeer; }
    };
}
