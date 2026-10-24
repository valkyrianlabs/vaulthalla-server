#pragma once

#include "rbac/fs/glob/model/Pattern.hpp"
#include "rbac/fs/policy/Decision.hpp"
#include "rbac/fs/policy/Request.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "identities/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace vh::rbac::fs::policy {
    struct Evaluator {
        struct ResolvedRequest {
            permission::vault::FilesystemAction action{};
            std::filesystem::path vaultPath{};
            bool exists{true};
            bool isDirectory{false};
        };

        [[nodiscard]]
        static Decision evaluate(const Request &req);

        [[nodiscard]]
        static Decision evaluate(const permission::vault::Filesystem &perms, const ResolvedRequest &req);

        [[nodiscard]]
        static std::optional<permission::vault::fs::FilePermissions> filePermissionForAction(
            permission::vault::FilesystemAction action
        );

        [[nodiscard]]
        static std::optional<permission::vault::fs::DirectoryPermissions> directoryPermissionForAction(
            permission::vault::FilesystemAction action
        );

        // False only when no enabled override can match `directory` or any entry below it: every entry in that
        // subtree is then judged by the base permissions alone (per kind, the same for all of them).
        [[nodiscard]]
        static bool overridesMayAffectListing(
            const permission::vault::Filesystem& perms,
            const std::filesystem::path& directory
        );

    private:
        struct TargetContext {
            std::shared_ptr<storage::Engine> engine{nullptr};
            std::filesystem::path fusePath, vaultPath;
            std::shared_ptr<vh::fs::model::Entry> entry;
            bool exists{false};
            bool isDir{false};
        };

        struct StageResult {
            bool matched{false};
            std::optional<bool> allowed{};
            Decision::Reason reason{Decision::Reason::DeniedByBasePermissions};
            std::optional<std::string> matchedOverride{};
            std::optional<permission::OverrideOpt> overrideEffect{};
        };

        [[nodiscard]]
        static std::optional<Decision> resolveTarget(const Request &req, TargetContext &out);

        [[nodiscard]]
        static StageResult resolveStage(
            const permission::vault::Filesystem &perms,
            const TargetContext &target,
            permission::vault::FilesystemAction action
        );

        [[nodiscard]]
        static StageResult resolveOverrides(
            const std::vector<permission::Override> &overrides,
            std::string_view absolutePath,
            const rbac::permission::vault::FilesystemAction& action
        );

        [[nodiscard]]
        static bool requiresExistingEntry(permission::vault::FilesystemAction action);

        [[nodiscard]]
        static bool inferIsDirectoryForMissingEntry(permission::vault::FilesystemAction action);

        [[nodiscard]]
        static bool isValidForFile(permission::vault::FilesystemAction action);

        [[nodiscard]]
        static bool isValidForDirectory(permission::vault::FilesystemAction action);

        [[nodiscard]]
        static bool allowedByBase(
            const permission::vault::Filesystem &perms,
            bool isDir,
            permission::vault::FilesystemAction action
        );

        [[nodiscard]]
        static std::optional<permission::OverrideOpt> overrideEffect(const permission::Override &o);

        [[nodiscard]] static bool requiresTraversalThrough(
            const std::vector<permission::Override> &overrides,
            const std::filesystem::path& absolutePath
        );

        [[nodiscard]] static const permission::Override *findBestOverride(
            const std::vector<permission::Override> &overrides,
            const std::filesystem::path& absolutePath,
            const rbac::permission::vault::FilesystemAction& action
        );

        [[nodiscard]]
        static std::size_t scorePattern(const ::vh::rbac::fs::glob::model::Pattern &pattern);
    };
}
