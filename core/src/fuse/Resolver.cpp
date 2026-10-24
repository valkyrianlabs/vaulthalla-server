#include "fuse/Resolver.hpp"
#include "fuse/resolver/Denial.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "identities/Group.hpp"
#include "runtime/Deps.hpp"
#include "log/Registry.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"
#include "rbac/fs/Visibility.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/resolver/Admin.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "fs/model/Path.hpp"

#include <algorithm>
#include <cerrno>

namespace vh::fuse {
    using resolver::Request;
    using resolver::Resolved;
    using resolver::Status;
    using resolver::Target;

    namespace {
        [[nodiscard]]
        bool needsEntry(const Request& req) {
            return resolver::hasFlag(req.target, Target::Entry) ||
                   resolver::hasFlag(req.target, Target::EntryForPath) ||
                   resolver::hasFlag(req.target, Target::List);
        }

        [[nodiscard]]
        bool needsPath(const Request& req) {
            return resolver::hasFlag(req.target, Target::Path) ||
                   resolver::hasFlag(req.target, Target::EntryForPath);
        }

        [[nodiscard]]
        std::string_view entryName(const std::shared_ptr<fs::model::Entry>& entry) {
            return entry ? std::string_view(entry->name) : std::string_view("null");
        }

        [[nodiscard]]
        bool needsList(const Request& req) {
            return resolver::hasFlag(req.target, Target::List);
        }

        [[nodiscard]]
        bool isMountRootEntry(const std::shared_ptr<fs::model::Entry>& entry) {
            return entry && !entry->vault_id && entry->fuse_path == "/";
        }

        [[nodiscard]]
        bool isVaultRootEntry(const std::shared_ptr<fs::model::Entry>& entry) {
            return entry && entry->vault_id && entry->path == "/";
        }

        [[nodiscard]]
        bool isMountRootMetadataAction(const rbac::permission::vault::FilesystemAction action) {
            using Action = rbac::permission::vault::FilesystemAction;
            return action == Action::Lookup || action == Action::List;
        }

        [[nodiscard]]
        std::shared_ptr<vault::model::Vault> vaultForEntry(const std::shared_ptr<fs::model::Entry>& entry) {
            if (!entry || !entry->vault_id) return nullptr;
            const auto& manager = runtime::Deps::get().storageManager;
            if (!manager) return nullptr;
            return manager->getVault(static_cast<unsigned int>(*entry->vault_id));
        }

        [[nodiscard]]
        bool isVaultOwner(
            const std::shared_ptr<identities::User>& user,
            const std::shared_ptr<fs::model::Entry>& entry
        ) {
            if (!user) return false;
            const auto vault = vaultForEntry(entry);
            return vault && vault->owner_id == user->id;
        }

        [[nodiscard]]
        bool hasAdminVaultView(
            const std::shared_ptr<identities::User>& user,
            const std::shared_ptr<fs::model::Entry>& entry
        ) {
            if (!user || !entry || !entry->vault_id) return false;

            using Perm = rbac::permission::admin::VaultPermissions;
            try {
                return rbac::resolver::Admin::has<Perm>({
                    .user = user,
                    .permission = Perm::View,
                    .vault_id = static_cast<std::uint32_t>(*entry->vault_id)
                });
            } catch (const std::exception& e) {
                log::Registry::auth()->warn(
                    "[fuse::Resolver] Failed to evaluate admin vault visibility for vault {}: {}",
                    *entry->vault_id,
                    e.what()
                );
                return false;
            }
        }

        [[nodiscard]]
        bool hasVaultPermission(
            const std::shared_ptr<identities::User>& user,
            const rbac::permission::vault::FilesystemAction action,
            const std::shared_ptr<fs::model::Entry>& entry,
            const std::optional<std::filesystem::path>& path = std::nullopt
        ) {
            return rbac::resolver::Vault::has<rbac::permission::vault::FilesystemAction>({
                .user = user,
                .permission = action,
                .path = path,
                .entry = entry
            });
        }

        [[nodiscard]]
        bool canExposeVaultRoot(
            const std::shared_ptr<identities::User>& user,
            const std::shared_ptr<fs::model::Entry>& entry,
            const rbac::permission::vault::FilesystemAction action
        ) {
            if (!user || !isVaultRootEntry(entry)) return false;
            if (user->isSuperAdmin()) return true;
            if (isVaultOwner(user, entry)) return true;
            if (hasAdminVaultView(user, entry)) return true;
            return hasVaultPermission(user, action, entry);
        }

        [[nodiscard]]
        bool canSeeEntry(
            const std::shared_ptr<identities::User>& user,
            const std::shared_ptr<fs::model::Entry>& entry
        ) {
            using Action = rbac::permission::vault::FilesystemAction;
            if (isMountRootEntry(entry)) return true;

            // Only asked after a denial; failing to evaluate visibility hides the entry rather than confirming it.
            try {
                if (isVaultRootEntry(entry)) return canExposeVaultRoot(user, entry, Action::Lookup);
                return hasVaultPermission(user, Action::Lookup, entry);
            } catch (const std::exception& e) {
                log::Registry::auth()->warn(
                    "[fuse::Resolver] Failed to evaluate visibility of {} after a denial: {}",
                    entry ? entry->fuse_path.string() : std::string("null"),
                    e.what()
                );
                return false;
            }
        }
    }

    int resolver::deniedErrno(
        const rbac::permission::vault::FilesystemAction denied,
        const std::shared_ptr<fs::model::Entry>& entry,
        const std::shared_ptr<fs::model::Entry>& parentEntry,
        const CanSeeEntry& canSee
    ) {
        const auto& subject = entry ? entry : parentEntry;
        if (!subject || isMountRootEntry(subject)) return EACCES;

        // Lookup is the visibility check itself: a denied Lookup on the entry already means it is hidden.
        if (entry && denied == rbac::permission::vault::FilesystemAction::Lookup) return ENOENT;

        return canSee && canSee(subject) ? EACCES : ENOENT;
    }

    Resolved Resolver::resolve(const Request& req) {
        Resolved res;

        if (!req.fuseReq) {
            res.setStatus(Status::MissingFuseContext, EINVAL);
            return res;
        }

        if (!resolveIdentity(req, res)) return res;
        if (!resolveParentEntry(req, res)) return res;
        if (!resolveEntry(req, res)) return res;
        if (!resolvePath(req, res)) return res;
        if (!resolveEntryForPath(req, res)) return res;
        if (!resolveEngine(req, res)) return res;
        if (!enforcePermissions(req, res)) return res;
        if (!resolveList(req, res)) return res;

        if (!res.ino && (res.entry || res.path)) {
            log::Registry::fuse()->debug(
                "[{}] Attempting to resolve inode from entry or path: entry: {}, path: {}",
                req.caller,
                std::string(entryName(res.entry)),
                res.path && !res.path->empty() ? res.path->string() : "null"
            );

            if (res.path)
                res.ino = runtime::Deps::get().fsCache->getOrAssignInode(*res.path);

            if (!res.ino && res.entry && res.entry->inode)
                res.ino = res.entry->inode;

            if (!res.ino)
                res.setStatus(Status::MissingIno, EINVAL);
        }

        return res;
    }

    bool Resolver::resolveIdentity(const Request& req, Resolved& out) {
        const fuse_ctx* fctx = fuse_req_ctx(req.fuseReq);
        if (!fctx) {
            out.setStatus(Status::MissingFuseContext, EINVAL);
            return false;
        }

        const uid_t uid = fctx->uid;
        const gid_t gid = fctx->gid;

        // Canonical identities, from memory once the identity index is warm: no database round trip per FUSE op.
        auto& identities = vh::identities::manager();
        out.user = identities.userByLinuxUid(uid);
        if (!out.user || !out.user->authorizing()) {
            log::Registry::fuse()->debug("[{}] No authorizing user for UID {}", req.caller, uid);
            out.setStatus(Status::MissingUser, EACCES);
            out.user.reset();
            return false;
        }

        // Only stamps new entries' group_gid; authorization uses the user's memberships.
        out.group = identities.groupByLinuxGid(gid);
        return true;
    }

    bool Resolver::resolveParentEntry(const Request& req, Resolved& out) {
        if (!req.parentIno) return true;
        if (out.parentEntry) return true;

        out.parentEntry = runtime::Deps::get().fsCache->getEntry(*req.parentIno);
        if (!out.parentEntry) {
            log::Registry::fuse()->debug("[{}] Failed to resolve parent entry from inode {}", req.caller, *req.parentIno);
            out.setStatus(Status::MissingParentEntry, ENOENT);
            return false;
        }

        return true;
    }

    bool Resolver::resolveEntry(const Request& req, Resolved& out) {
        if (!needsEntry(req)) return true;
        if (out.entry) return true;

        if (req.ino) {
            out.entry = runtime::Deps::get().fsCache->getEntry(*req.ino);
            if (out.entry) {
                if (req.caller == "statfs")
                    log::Registry::fuse()->trace(
                        "[{}] Resolved entry from inode {}: {}",
                        req.caller, *req.ino, out.entry->fuse_path.string()
                    );
                else
                    log::Registry::fuse()->debug(
                        "[{}] Resolved entry from inode {}: {}",
                        req.caller, *req.ino, out.entry->fuse_path.string()
                    );
                return true;
            }

            log::Registry::fuse()->debug("[{}] Failed to resolve entry from inode {}", req.caller, *req.ino);
        }

        return true;
    }

    bool Resolver::resolvePath(const Request& req, Resolved& out) {
        if (!needsPath(req)) return true;
        if (out.path) return true;

        if (req.parentIno && req.childName) {
            try {
                if (!out.parentEntry) {
                    out.setStatus(Status::MissingParentEntry, ENOENT);
                    return false;
                }

                const auto parentPath = out.parentEntry->fuse_path;
                const auto child = std::filesystem::path(*req.childName).filename();
                out.path = parentPath / child;

                log::Registry::fuse()->debug(
                    "[{}] Resolved path from parent/child: {}",
                    req.caller, out.path->string()
                );
                return true;
            } catch (const std::exception& e) {
                log::Registry::fuse()->debug(
                    "[{}] Failed to resolve path from parent/child: {}",
                    req.caller, e.what()
                );
            }
        }

        if (out.entry) {
            out.path = out.entry->fuse_path;
            log::Registry::fuse()->debug(
                "[{}] Resolved path from entry: {}",
                req.caller, out.path->string()
            );
            return true;
        }

        if (req.ino) {
            if (const auto entry = runtime::Deps::get().fsCache->getEntry(*req.ino)) {
                out.entry = entry;
                out.path = entry->fuse_path;

                if (req.caller == "statfs")
                    log::Registry::fuse()->trace(
                        "[{}] Resolved path from inode {} via entry: {}",
                        req.caller, *req.ino, out.path->string()
                    );
                else
                    log::Registry::fuse()->debug(
                        "[{}] Resolved path from inode {} via entry: {}",
                        req.caller, *req.ino, out.path->string()
                    );
                return true;
            }
        }

        log::Registry::fuse()->debug(
            "[{}] Failed to resolve path: no parent/child path and no inode/entry fallback",
            req.caller
        );
        out.setStatus(Status::MissingPath, ENOENT);
        return false;
    }

    bool Resolver::resolveEntryForPath(const Request& req, Resolved& out) {
        if (!needsEntry(req)) return true;
        if (out.entry) return true;

        log::Registry::fuse()->debug(
            "[{}] Resolving entry for path: {}, parent inode: {}, child name: {}",
            req.caller,
            out.path ? out.path->string() : "null",
            req.parentIno ? std::to_string(*req.parentIno) : "null",
            req.childName ? *req.childName : "null"
        );

        if (!out.path) {
            log::Registry::fuse()->debug("[{}] Need entry but no path resolved", req.caller);
            out.setStatus(Status::MissingPath, EINVAL);
            return false;
        }

        out.entry = runtime::Deps::get().fsCache->getEntry(*out.path);
        if (!out.entry) {
            log::Registry::fuse()->debug("[{}] Failed to resolve entry for path {}", req.caller, out.path->string());

            // Important: for create/lookup of not-yet-existing children, missing entry may be acceptable.
            if (req.action == rbac::permission::vault::FilesystemAction::Write ||
                req.action == rbac::permission::vault::FilesystemAction::Touch ||
                req.action == rbac::permission::vault::FilesystemAction::Link) {
                return true;
            }

            out.setStatus(Status::MissingEntry, ENOENT);
            return false;
        }

        return true;
    }

    static bool enforcePermission(
        const std::shared_ptr<vh::identities::User>& user,
        const rbac::permission::vault::FilesystemAction& action,
        const std::shared_ptr<fs::model::Entry>& entry,
        const std::optional<std::filesystem::path>& path = std::nullopt
    ) {
        if (isMountRootEntry(entry))
            return isMountRootMetadataAction(action);

        if (isVaultRootEntry(entry) && isMountRootMetadataAction(action))
            return canExposeVaultRoot(user, entry, action);

        if (hasVaultPermission(user, action, entry, path))
            return true;

        if (entry)
            log::Registry::fuse()->warn("[auth] Access denied for user {} on path {}", user->name(), entry->path.string());
        else if (path)
            log::Registry::fuse()->warn("[auth] Access denied for user {} on path {}", user->name(), path->string());
        else
            log::Registry::fuse()->warn("[auth] Access denied for user {} with no resolved path/entry", user->name());

        return false;
    }

    bool Resolver::enforcePermissions(const Request& req, Resolved& out) {
        const bool checkEntry = needsEntry(req);
        const bool checkPath = needsPath(req);

        // Status stays AccessDenied even when the caller is told ENOENT: callers that special-case a genuinely
        // missing entry (unlink of an HTTP upload temp part) must not treat a hidden one as already gone.
        auto deny = [&](const rbac::permission::vault::FilesystemAction action) {
            out.setStatus(Status::AccessDenied, resolver::deniedErrno(
                action,
                out.entry,
                out.parentEntry,
                [&](const std::shared_ptr<fs::model::Entry>& subject) { return canSeeEntry(out.user, subject); }
            ));
        };

        if (req.action && (checkEntry || checkPath) && !enforcePermission(out.user, *req.action, out.entry, out.path)) {
            deny(*req.action);
            return false;
        }

        for (const auto& action : req.actions)
            if ((checkEntry || checkPath) && !enforcePermission(out.user, action, out.entry, out.path)) {
                deny(action);
                return false;
            }

        return true;
    }

    bool Resolver::resolveEngine(const Request& req, Resolved& out) {
        if (isMountRootEntry(out.entry)) return true;

        if (!(req.action || !req.actions.empty() || needsPath(req))) return true;

        if (out.entry && out.entry->vault_id)
            out.engine = runtime::Deps::get().storageManager->getEngine(*out.entry->vault_id);

        if (!out.engine && out.path)
            out.engine = runtime::Deps::get().storageManager->resolveStorageEngine(*out.path);

        if (!out.engine) {
            out.setStatus(Status::MissingEngine, EIO);
            return false;
        }

        return true;
    }

    bool Resolver::resolveList(const Request& req, Resolved& out) {
        if (!needsList(req)) return true;

        if (!out.entry) {
            out.setStatus(Status::MissingEntry, ENOENT);
            return false;
        }

        if (!out.entry->isDirectory()) {
            out.setStatus(Status::InvalidRequest, ENOTDIR);
            return false;
        }

        std::vector<std::shared_ptr<fs::model::Entry>> entries;
        try {
            entries = runtime::Deps::get().fsCache->listDir(out.entry->id, false);
        } catch (const std::exception& e) {
            log::Registry::fuse()->error("[{}] Failed to list inode {}: {}", req.caller, out.entry->inode.value_or(0), e.what());
            out.setStatus(Status::InternalError, EIO);
            return false;
        }

        std::ranges::sort(entries, [](const auto& lhs, const auto& rhs) {
            if (!lhs || !rhs) return !!lhs;
            return lhs->name < rhs->name;
        });

        if (isMountRootEntry(out.entry)) {
            if (out.user && out.user->isSuperAdmin()) {
                out.dir = std::move(entries);
                return true;
            }

            std::vector<std::shared_ptr<fs::model::Entry>> visible;
            visible.reserve(entries.size());

            for (const auto& entry : entries)
                if (isVaultRootEntry(entry) &&
                    canExposeVaultRoot(out.user, entry, rbac::permission::vault::FilesystemAction::List))
                    visible.push_back(entry);

            out.dir = std::move(visible);
            return true;
        }

        // Children the caller cannot Lookup are left out (#170); the same rule as ws fs.dir.list and `vh fs ls`.
        out.dir = rbac::fs::visibility::visibleChildren(out.user, out.entry, std::move(entries));
        return true;
    }
}
