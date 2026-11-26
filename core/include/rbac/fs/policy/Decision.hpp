#pragma once

#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/permission/Override.hpp"
#include "fs/model/Entry.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <sstream>

namespace vh::rbac::fs::policy {
    struct Decision {
        enum class Reason : uint8_t {
            Allowed,
            MissingPath,
            MissingEntry,
            MissingPathAndEntry,
            MissingUser,
            InvalidActionForEntryType,
            DeniedByOverride,
            AllowedByOverride,
            DeniedByBasePermissions,
            AllowedByBasePermissions,
            StorageEngineNotFound,
            UnableToResolvePaths,
            LowRiskOpRequiredForOverrideTraversal,
            EntryVaultMismatch,
            // A vault held here as another server's copy, for an account its core's grant doesn't reach (not a super
            // admin of this server, or no grant recorded): rbac/Mirrored.hpp.
            NotGrantedOnMirror
        };

        bool allowed{false};
        Reason reason{Reason::DeniedByBasePermissions};

        std::optional<std::string> evaluated_path{};
        std::optional<std::string> matched_override{};
        std::optional<permission::OverrideOpt> override_effect{};

        [[nodiscard]] std::string toString() const;
    };

    std::string reasonToString(const Decision::Reason& reason);
}
