#include "fuse/Bridge.hpp"
#include "storage/Manager.hpp"
#include "storage/Engine.hpp"
#include "identities/User.hpp"
#include "fs/model/Entry.hpp"
#include "config/Registry.hpp"
#include "fs/Filesystem.hpp"
#include "runtime/Deps.hpp"
#include "stats/model/FuseStats.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/fs/Directory.hpp"
#include "log/Registry.hpp"
#include "fs/cache/Registry.hpp"
#include "fuse/Resolver.hpp"
#include "fuse/WorkingCopies.hpp"
#include "fuse/task/Request.hpp"
#include "rbac/fs/Placement.hpp"
#include "rbac/fs/Visibility.hpp"
#include "fs/model/Symlink.hpp"
#include "fs/model/File.hpp"
#include "db/Transactions.hpp"
#include "recovery/local/Versions.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <sys/statvfs.h>
#include <unistd.h>

#include "fs/Inode.hpp"
#include "platform/FileTime.hpp"

// The FS cache's inode numbers go to the kernel unconverted.
static_assert(std::is_same_v<fuse_ino_t, vh::fs::Inode>);
static_assert(FUSE_ROOT_ID == vh::fs::kRootInode);

using vh::identities::User;
using vh::identities::Group;
using namespace vh::storage;
using namespace vh::config;
using namespace vh::fs;
using namespace vh::fs::model;
using namespace vh::rbac;

namespace vh::fuse {

namespace {

// Entry and attr timeouts for every reply (#183). The kernel's dentry/attr cache is shared across uids and the mount
// doesn't use default_permissions, so anything cached is answered for *any* caller without asking the daemon: a
// non-zero timeout let a denied uid stat a path another uid had just resolved (60 s after a create). With 0, every
// lookup and getattr reaches the resolver and is authorized for the calling uid. Sizes stay coherent mid-write
// because statFromEntry reports an open working copy's size (writeback cache is off, handles are direct_io).
constexpr double kKernelMetadataTimeout = 0.0;

using stats::model::FuseOperation;
using stats::model::ScopedFuseOpTimer;

stats::model::FuseStats* fuseStats() noexcept {
    return runtime::Deps::get().fuseStats.get();
}

void replyError(const fuse_req_t req, ScopedFuseOpTimer& timer, const int errnum) {
    const int normalized = errnum < 0 ? -errnum : errnum;
    timer.error(normalized);
    fuse_reply_err(req, normalized);
}

// A refusal by the permission model (a uid with no Vaulthalla user, or RBAC) is the mount doing its job: system
// processes such as MOTD scripts stat every mount, and they must not raise the dashboard's FUSE error rate. Every
// other resolver failure is reported as an error.
void replyResolveError(const fuse_req_t req, ScopedFuseOpTimer& timer, const resolver::Resolved& resolved) {
    const int normalized = resolved.errnum < 0 ? -resolved.errnum : resolved.errnum;
    if (resolved.status == resolver::Status::MissingUser || resolved.status == resolver::Status::AccessDenied)
        timer.denied(normalized);
    else
        timer.error(normalized);
    fuse_reply_err(req, normalized);
}

void replyOk(const fuse_req_t req, ScopedFuseOpTimer& timer) {
    timer.success();
    fuse_reply_err(req, 0);
}

void recordOpenHandle() noexcept {
    if (const auto& stats = runtime::Deps::get().fuseStats) stats->record_open_handle();
}

void recordCloseHandle() noexcept {
    if (const auto& stats = runtime::Deps::get().fuseStats) stats->record_close_handle();
}

WorkingCopies::Handle workingHandle(const FileHandle& fh) { return {fh.copy, fh.fd}; }

int errnoFrom(const std::exception& e) {
    if (const auto* sys = dynamic_cast<const std::system_error*>(&e); sys && sys->code().value() > 0)
        return sys->code().value();
    return EIO;
}

std::optional<int32_t> userIdOf(const std::shared_ptr<identities::User>& user) {
    if (!user) return std::nullopt;
    return static_cast<int32_t>(user->id);
}

bool isHttpUploadTempPartName(const std::string_view name) noexcept {
    return name.starts_with(".upload-http-") && name.ends_with(".part") &&
           name.find('/') == std::string_view::npos;
}

void warnSetattrMetadataNoOpOncePerMinute() {
    static std::mutex mutex;
    static std::chrono::steady_clock::time_point lastWarning{};

    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lock(mutex);

    if (lastWarning != std::chrono::steady_clock::time_point{} &&
        now - lastWarning < std::chrono::minutes(1))
        return;

    lastWarning = now;
    log::Registry::fuse()->warn(
        "chmod/chown is forbidden beyond the gates. If this is a cp operation you may disregard this warning.");
}

// A folder's size is its subtree total, which counts entries the caller may not be allowed to see (#269). A caller who
// can't see the whole subtree gets the visible part instead: recounted (one subtree listing, as fs.dir.list does) where
// the size is what the call is for (getattr, setattr), and withheld (0) in lookup's attributes, which every path walk
// asks for and stat(2) never shows on its own (attr timeouts are 0, so the kernel asks getattr before answering; only
// statx(AT_STATX_DONT_SYNC) would read lookup's). Super admins and vault owners keep the stored totals. The mount root
// spans every vault: only a super admin sees its size.
enum class FolderSize { Recount, Withhold };

void applyVisibleFolderSize(struct stat& st, const std::shared_ptr<User>& user, const std::shared_ptr<Entry>& entry,
                            const FolderSize how) {
    if (!entry || !entry->isDirectory()) return;
    if (!entry->vault_id) {
        if (!user || !user->isSuperAdmin()) st.st_size = 0;
        return;
    }
    if (how == FolderSize::Withhold) {
        if (!rbac::fs::visibility::seesWholeSubtree(user, entry)) st.st_size = 0;
        return;
    }
    if (const auto totals = rbac::fs::visibility::visibleTotals(user, entry))
        st.st_size = static_cast<off_t>(totals->size_bytes);
}

fuse_ino_t inodeForEntry(const std::shared_ptr<Entry>& entry) {
    if (!entry) return FUSE_ROOT_ID;
    if (entry->inode) return *entry->inode;
    if (!entry->fuse_path.empty())
        return runtime::Deps::get().fsCache->getOrAssignInode(entry->fuse_path);
    return FUSE_ROOT_ID;
}

}

void getattr(const fuse_req_t req, const fuse_ino_t ino, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::GetAttr);
    log::Registry::fuse()->debug("[getattr] Called for inode: {}", ino);
    (void)fi;

    const auto resolved = Resolver::resolve({
        .caller = "getattr",
        .fuseReq = req,
        .ino = ino,
        .action = permission::vault::FilesystemAction::Lookup,
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (!resolved.entry) {
        replyError(req, timer, ENOENT);
        return;
    }

    auto st = statFromEntry(resolved.entry, ino);
    applyVisibleFolderSize(st, resolved.user, resolved.entry, FolderSize::Recount);
    timer.success();
    fuse_reply_attr(req, &st, kKernelMetadataTimeout);
}

void setattr(const fuse_req_t req, const fuse_ino_t ino,
                         struct stat* attr, int to_set, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::SetAttr);
    log::Registry::fuse()->debug("[setattr] Called for inode: {}, to_set: {}", ino, to_set);

    const auto resolved = Resolver::resolve({
        .caller = "setattr",
        .fuseReq = req,
        .ino = ino,
        .action = permission::vault::FilesystemAction::Write,
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (resolved.entry->isSymlink()) {
        replyError(req, timer, EOPNOTSUPP);
        return;
    }

    if (to_set & (FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID))
        warnSetattrMetadataNoOpOncePerMinute();

    // truncate(2)/ftruncate(2): change the plaintext, then seal it like any other write.
    if (to_set & FUSE_SET_ATTR_SIZE) {
        if (resolved.entry->isDirectory()) {
            replyError(req, timer, EISDIR);
            return;
        }
        try {
            auto& copies = WorkingCopies::instance();
            if (const auto* fh = fi ? reinterpret_cast<FileHandle*>(fi->fh) : nullptr; fh && fh->copy) {
                copies.truncate(workingHandle(*fh), attr->st_size, userIdOf(resolved.user));
            } else {
                auto handle = copies.open(ino, std::static_pointer_cast<File>(resolved.entry), O_RDWR);
                try {
                    copies.truncate(handle, attr->st_size, userIdOf(resolved.user));
                } catch (...) {
                    copies.release(handle);
                    throw;
                }
                copies.release(handle);
            }
        } catch (const std::exception& e) {
            log::Registry::fuse()->error("[setattr] Could not truncate {}: {}", resolved.entry->fuse_path.string(), e.what());
            replyError(req, timer, errnoFrom(e));
            return;
        }
    }

    timespec times[2]{};
    if (to_set & FUSE_SET_ATTR_ATIME) times[0] = platform::atime(*attr);
    else times[0].tv_nsec = UTIME_OMIT;
    if (to_set & FUSE_SET_ATTR_MTIME) times[1] = platform::mtime(*attr);
    else times[1].tv_nsec = UTIME_OMIT;

    if (::utimensat(AT_FDCWD, resolved.entry->backing_path.c_str(), times, 0) < 0) {
        replyError(req, timer, errno);
        return;
    }

    // Re-stat file so kernel gets fresh info
    struct stat st = {};
    if (::stat(resolved.entry->backing_path.c_str(), &st) < 0) {
        replyError(req, timer, errno);
        return;
    }

    auto sanitized = statFromEntry(resolved.entry, ino);  // plaintext size, not the ciphertext's
    applyVisibleFolderSize(sanitized, resolved.user, resolved.entry, FolderSize::Recount);
    platform::atime(sanitized) = platform::atime(st);
    platform::mtime(sanitized) = platform::mtime(st);
    platform::ctime(sanitized) = platform::ctime(st);

    timer.success();
    fuse_reply_attr(req, &sanitized, kKernelMetadataTimeout);
}

void readdir(const fuse_req_t req, const fuse_ino_t ino, const size_t size, const off_t off, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::ReadDir);
    log::Registry::fuse()->debug("[readdir] Called for inode: {}, size: {}, offset: {}", ino, size, off);
    (void)fi;

    const auto resolved = Resolver::resolve({
        .caller = "readdir",
        .fuseReq = req,
        .ino = ino,
        .action = permission::vault::FilesystemAction::List,
        .target = resolver::Target::Entry | resolver::Target::List
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (!resolved.entry) {
        replyError(req, timer, ENOENT);
        return;
    }

    if (!resolved.dir) {
        replyError(req, timer, EIO);
        return;
    }

    std::vector<char> buf(size);
    size_t buf_used = 0;

    auto add_entry = [&](const std::string& name, const struct stat& st, const off_t next_off) {
        const size_t entry_size = fuse_add_direntry(req, nullptr, 0, name.c_str(), &st, next_off);
        if (buf_used + entry_size > size) return false;

        fuse_add_direntry(req, buf.data() + buf_used, entry_size, name.c_str(), &st, next_off);
        buf_used += entry_size;
        return true;
    };

    off_t current_off = 0;

    if (off <= current_off++) {
        struct stat dot{};
        dot.st_mode = S_IFDIR;
        if (!add_entry(".", dot, current_off)) goto reply;
    }

    if (off <= current_off++) {
        struct stat dotdot{};
        dotdot.st_mode = S_IFDIR;
        if (!add_entry("..", dotdot, current_off)) goto reply;
    }

    for (size_t i = 0; i < resolved.dir->size(); ++i, ++current_off) {
        if (off > current_off) continue;
        const auto& entry = resolved.dir->at(i);
        if (!entry) continue;
        if (!add_entry(entry->name, statFromEntry(entry, inodeForEntry(entry)), current_off + 1)) break;
    }

    reply:
        timer.success(buf_used, 0);
        fuse_reply_buf(req, buf.data(), buf_used);
}

void lookup(const fuse_req_t req, const fuse_ino_t parent, const char* name) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Lookup);
    log::Registry::fuse()->debug("[lookup] Called for parent: {}, name: {}", parent, name);

    const auto resolved = Resolver::resolve({
        .caller = "lookup",
        .fuseReq = req,
        .parentIno = parent,
        .childName = name,
        .action = permission::vault::FilesystemAction::Lookup,
        .target = resolver::Target::EntryForPath
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    fuse_entry_param e{};
    e.ino = *resolved.ino;
    e.attr_timeout = kKernelMetadataTimeout;
    e.entry_timeout = kKernelMetadataTimeout;
    e.attr = statFromEntry(resolved.entry, *resolved.ino);
    applyVisibleFolderSize(e.attr, resolved.user, resolved.entry, FolderSize::Withhold);

    timer.success();
    fuse_reply_entry(req, &e);
}

void readlink(const fuse_req_t req, const fuse_ino_t ino) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::ReadLink);
    log::Registry::fuse()->debug("[readlink] Called for inode: {}", ino);

    const auto resolved = Resolver::resolve({
        .caller = "readlink",
        .fuseReq = req,
        .ino = ino,
        .action = permission::vault::FilesystemAction::Read,
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (!resolved.entry->isSymlink()) {
        replyError(req, timer, EINVAL);
        return;
    }

    const auto link = std::static_pointer_cast<Symlink>(resolved.entry);
    timer.success(static_cast<std::uint64_t>(link->target.size()), 0);
    fuse_reply_readlink(req, link->target.c_str());
}

void create(const fuse_req_t req, const fuse_ino_t parent, const char* name, const mode_t mode, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Create);
    log::Registry::fuse()->debug("[create] Called for parent: {}, name: {}, mode: {}",
        parent, name, mode);

    const auto resolved = Resolver::resolve({
        .caller = "create",
        .fuseReq = req,
        .parentIno = parent,
        .childName = name,
        .action = permission::vault::FilesystemAction::Write,
        .target = resolver::Target::Path
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (runtime::Deps::get().fsCache->entryExists(*resolved.path)) {
        replyError(req, timer, EEXIST);
        return;
    }

    const auto [err, newEntry] = Filesystem::createFile({
        .resolved = resolved,
        .mode = mode
    });
    if (err) {
        replyError(req, timer, err);
        return;
    }

    const auto st = statFromEntry(newEntry, *newEntry->inode);

    WorkingCopies::Handle handle;
    try {
        handle = WorkingCopies::instance().open(
            *newEntry->inode, std::static_pointer_cast<File>(newEntry), fi->flags & ~(O_CREAT | O_EXCL));
    } catch (const std::exception& e) {
        log::Registry::fuse()->error("[create] Could not open {}: {}", newEntry->fuse_path.string(), e.what());
        replyError(req, timer, errnoFrom(e));
        return;
    }

    auto* fh = new FileHandle{newEntry->backing_path.string(), handle.fd, 0, handle.copy};
    fi->fh = reinterpret_cast<uint64_t>(fh);

    fi->direct_io = 1;
    fi->keep_cache = 0;

    fuse_entry_param e{};
    e.ino           = *newEntry->inode;
    e.attr          = st;
    e.attr_timeout  = kKernelMetadataTimeout;
    e.entry_timeout = kKernelMetadataTimeout;

    runtime::Deps::get().storageManager->registerOpenHandle(*newEntry->inode);
    recordOpenHandle();
    timer.success();
    fuse_reply_create(req, &e, fi);
}

void symlink(const fuse_req_t req, const char* link, const fuse_ino_t parent, const char* name) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Symlink);
    log::Registry::fuse()->debug("[symlink] Called for parent: {}, name: {}, target: {}",
        parent, name ? name : "null", link ? link : "null");

    if (!link || !name || std::string_view(name).find('/') != std::string::npos) {
        replyError(req, timer, EINVAL);
        return;
    }

    const auto resolved = Resolver::resolve({
        .caller = "symlink",
        .fuseReq = req,
        .parentIno = parent,
        .childName = name,
        .action = permission::vault::FilesystemAction::Link,
        .target = resolver::Target::Path
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    const auto [err, newEntry] = Filesystem::createSymlink({
        .resolved = resolved,
        .target = link
    });
    if (err || !newEntry || !newEntry->inode) {
        replyError(req, timer, err ? err : EIO);
        return;
    }

    fuse_entry_param e{};
    e.ino = static_cast<fuse_ino_t>(*newEntry->inode);
    e.attr = statFromEntry(newEntry, e.ino);
    e.attr_timeout = kKernelMetadataTimeout;
    e.entry_timeout = kKernelMetadataTimeout;

    timer.success();
    fuse_reply_entry(req, &e);
}

void open(const fuse_req_t req, const fuse_ino_t ino, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Open);
    log::Registry::fuse()->debug("[open] Called for inode: {}, flags: {}", ino, fi->flags);

    // A handle that can modify the file needs Write; one that can read it needs Read (O_RDWR needs both).
    const int access = fi->flags & O_ACCMODE;
    const bool reads = access != O_WRONLY;
    const bool writes = access != O_RDONLY || (fi->flags & O_TRUNC);
    std::vector<permission::vault::FilesystemAction> also;
    if (reads && writes) also.push_back(permission::vault::FilesystemAction::Write);

    const auto resolved = Resolver::resolve({
        .caller = "open",
        .fuseReq = req,
        .ino = ino,
        .action = reads ? permission::vault::FilesystemAction::Read : permission::vault::FilesystemAction::Write,
        .actions = std::move(also),
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (resolved.entry->isSymlink()) {
        replyError(req, timer, ELOOP);
        return;
    }
    if (resolved.entry->isDirectory()) {
        replyError(req, timer, EISDIR);
        return;
    }

    WorkingCopies::Handle handle;
    try {
        handle = WorkingCopies::instance().open(ino, std::static_pointer_cast<File>(resolved.entry), fi->flags);
    } catch (const std::exception& e) {
        log::Registry::fuse()->error("[open] Could not open {}: {}", resolved.entry->fuse_path.string(), e.what());
        replyError(req, timer, errnoFrom(e));
        return;
    }

    auto* fh = new FileHandle{resolved.entry->backing_path.string(), handle.fd, 0, handle.copy};
    fi->fh = reinterpret_cast<uint64_t>(fh);

    fi->direct_io = 1;
    fi->keep_cache = 0;

    runtime::Deps::get().storageManager->registerOpenHandle(ino);
    recordOpenHandle();
    timer.success();
    fuse_reply_open(req, fi);
}

void write(const fuse_req_t req, const fuse_ino_t ino, const char* buf,
                       const size_t size, const off_t off, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Write);
    log::Registry::fuse()->debug("[write] Called for inode: {}, size: {}, offset: {}, file handle: {}",
        ino, size, off, fi->fh);

    const auto* fh = reinterpret_cast<FileHandle*>(fi->fh);
    if (!fh) {
        log::Registry::fuse()->debug("[write] Invalid file handle for inode: {}", ino);
        replyError(req, timer, EBADF);
        return;
    }

    // Check before anything is written: a refused write must not change the file.
    const auto resolved = Resolver::resolve({
        .caller = "write",
        .fuseReq = req,
        .ino = ino,
        .action = permission::vault::FilesystemAction::Write,
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    ssize_t res = 0;
    try {
        res = WorkingCopies::instance().write(workingHandle(*fh), buf, size, off, userIdOf(resolved.user));
    } catch (const std::exception& e) {
        replyError(req, timer, errnoFrom(e));
        return;
    }

    fuse_lowlevel_notify_inval_inode(runtime::Deps::get().fuseSession, ino, 0, 0);
    timer.success(0, static_cast<std::uint64_t>(res));
    fuse_reply_write(req, res);
}

void read(const fuse_req_t req, const fuse_ino_t ino, const size_t size, const off_t off, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Read);
    log::Registry::fuse()->debug("[read] Called for inode: {}, size: {}, offset: {}, file handle: {}",
        ino, size, off, fi->fh);

    const auto* fh = reinterpret_cast<FileHandle*>(fi->fh);
    if (!fh) {
        log::Registry::fuse()->debug("[read] Invalid file handle for inode: {}", ino);
        replyError(req, timer, EBADF);
        return;
    }

    const auto resolved = Resolver::resolve({
        .caller = "read",
        .fuseReq = req,
        .ino = ino,
        .action = permission::vault::FilesystemAction::Read,
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    std::vector<char> buffer(size);
    ssize_t res = 0;
    try {
        res = WorkingCopies::instance().read(workingHandle(*fh), buffer.data(), size, off);
    } catch (const std::exception& e) {
        replyError(req, timer, errnoFrom(e));
        return;
    }

    timer.success(static_cast<std::uint64_t>(res), 0);
    fuse_reply_buf(req, buffer.data(), res);
}

void mkdir(const fuse_req_t req, const fuse_ino_t parent, const char* name, const mode_t mode) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::MkDir);
    log::Registry::fuse()->debug("[mkdir] Called for parent: {}, name: {}, mode: {}", parent, name, mode);

    const auto resolved = Resolver::resolve({
        .caller = "mkdir",
        .fuseReq = req,
        .parentIno = parent,
        .childName = name,
        .action = permission::vault::FilesystemAction::Touch,
        .target = resolver::Target::Path
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (std::string_view(name).find('/') != std::string::npos) {
        replyError(req, timer, EINVAL);
        return;
    }

    const auto [err, newEntry] = Filesystem::mkdir({
        .resolved = resolved,
        .mode = mode
    });
    if (err) {
        replyError(req, timer, err);
        return;
    }
    if (!newEntry || !newEntry->inode) {
        replyError(req, timer, EIO);
        return;
    }

    const auto finalInode = static_cast<fuse_ino_t>(*newEntry->inode);

    fuse_entry_param e{};
    e.ino = finalInode;
    e.attr_timeout = kKernelMetadataTimeout;
    e.entry_timeout = kKernelMetadataTimeout;
    e.attr = statFromEntry(newEntry, finalInode);

    timer.success();
    fuse_reply_entry(req, &e);
}

void rename(const fuse_req_t req, const fuse_ino_t parent, const char* name, const fuse_ino_t newparent, const char* newname, const unsigned int flags) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Rename);
    log::Registry::fuse()->debug("[rename] Called for parent: {}, name: {}, newparent: {}, newname: {}, flags: {}",
                               parent, name, newparent, newname, flags);

    const auto& cache = runtime::Deps::get().fsCache;

    const auto resolved = Resolver::resolve({
        .caller = "rename",
        .fuseReq = req,
        .parentIno = parent,
        .childName = name,
        .action = permission::vault::FilesystemAction::Rename,
        .target = resolver::Target::EntryForPath
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    // Only RENAME_NOREPLACE is implemented. An exchange (RENAME_EXCHANGE; RENAME_SWAP on macOS) or any flag we don't
    // know is refused: carried out as a plain rename it would overwrite the entry the caller asked to keep.
    if (flags & ~static_cast<unsigned int>(RENAME_NOREPLACE)) {
        replyError(req, timer, EINVAL);
        return;
    }

    // A destination folder inode the cache doesn't know (gone since the kernel looked it up) is ENOENT (#263).
    std::filesystem::path toPath;
    try {
        toPath = cache->resolvePath(newparent) / newname;
    } catch (const std::runtime_error&) {
        replyError(req, timer, ENOENT);
        return;
    }

    // Into another folder (#256): the entry arrives there, so it needs what creating it there needs, Touch for a
    // folder and Write for a file or symlink (mkdir/create/ws copy), with a create's answer when refused
    // (resolver::deniedErrno on that parent: ENOENT when the caller cannot see it, EACCES when it can). A folder
    // carries its contents, each checked the same way at its new path (EACCES: the destination folder is visible by
    // then). A rename within its folder adds nothing there. Across vaults nothing moves (Filesystem::rename answers
    // EXDEV): nothing to authorize.
    if (newparent != parent) {
        const auto destinationParent = cache->getEntry(newparent);
        if (destinationParent && destinationParent->vault_id && resolved.entry &&
            destinationParent->vault_id == resolved.entry->vault_id) {
            const auto destination = Resolver::resolve({
                .caller = "rename",
                .fuseReq = req,
                .parentIno = newparent,
                .childName = newname,
                .action = rbac::fs::placement::createAction(*resolved.entry),
                .target = resolver::Target::Path
            });

            if (!destination.ok()) {
                replyResolveError(req, timer, destination);
                return;
            }

            if (rbac::fs::placement::firstRefusedDescendant(resolved.user, resolved.entry, toPath)) {
                timer.denied(EACCES);
                fuse_reply_err(req, EACCES);
                return;
            }
        }
    }

    // Without RENAME_NOREPLACE an existing destination is replaced (editors save by renaming a temp file over the
    // original). That removes it the way unlink/rmdir would, so it needs what they need: Delete on it. Replace is
    // only granted for a destination checked here; one that appears after this check is refused (EEXIST).
    auto mode = RenameMode::NoReplace;
    if (!(flags & RENAME_NOREPLACE) && cache->entryExists(toPath)) {
        const auto target = Resolver::resolve({
            .caller = "rename",
            .fuseReq = req,
            .parentIno = newparent,
            .childName = newname,
            .action = permission::vault::FilesystemAction::Delete,
            .target = resolver::Target::EntryForPath
        });

        if (target.ok()) mode = RenameMode::Replace;
        else if (target.status != resolver::Status::MissingEntry) {
            replyResolveError(req, timer, target);
            return;
        }
    }

    if (const auto err = Filesystem::rename(*resolved.path, toPath, resolved.user, nullptr, mode); err) {
        replyError(req, timer, err);
        return;
    }

    replyOk(req, timer);
}

void forget(const fuse_req_t req, const fuse_ino_t ino, const uint64_t nlookup) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Forget);
    log::Registry::fuse()->debug("[forget] Called for inode: {}, nlookup: {}", ino, nlookup);

    // The kernel dropping its lookup references says nothing about our metadata: the cache is seeded at startup
    // and kept current by every daemon-side change. Evicting here broke path resolution once a vault root was
    // forgotten (memory pressure, `echo 2 > /proc/sys/vm/drop_caches`): the whole vault answered ENOENT until restart.
    timer.success();
    fuse_reply_none(req); // no return value
}

void access(const fuse_req_t req, const fuse_ino_t ino, const int mask) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Access);
    log::Registry::fuse()->debug("[access] Called for inode: {}, mask: {}", ino, mask);

    std::vector<rbac::permission::vault::FilesystemAction> requiredPermissions;
    if (mask & W_OK) requiredPermissions.push_back(permission::vault::FilesystemAction::Write);
    if (mask & R_OK) requiredPermissions.push_back(permission::vault::FilesystemAction::Read);

    if (ino != FUSE_ROOT_ID && mask & X_OK) requiredPermissions.push_back(permission::vault::FilesystemAction::List);

    const auto resolved = Resolver::resolve({
        .caller = "access",
        .fuseReq = req,
        .ino = ino,
        .actions = requiredPermissions,
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    replyOk(req, timer);
}

void unlink(const fuse_req_t req, const fuse_ino_t parent, const char* name) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Unlink);
    log::Registry::fuse()->debug("[unlink] Called for parent: {}, name: {}", parent, name);

    const auto childName = name ? std::string_view{name} : std::string_view{};
    const auto isHttpUploadTemp = isHttpUploadTempPartName(childName);
    const auto resolved = Resolver::resolve({
        .caller = "unlink",
        .fuseReq = req,
        .parentIno = parent,
        .childName = name,
        .action = permission::vault::FilesystemAction::Delete,
        .target = resolver::Target::EntryForPath
    });

    if (!resolved.ok()) {
        if (isHttpUploadTemp && resolved.status == resolver::Status::MissingEntry) {
            const auto tempResolved = Resolver::resolve({
                .caller = "unlink",
                .fuseReq = req,
                .parentIno = parent,
                .childName = name,
                .action = permission::vault::FilesystemAction::Delete,
                .target = resolver::Target::Path
            });

            if (!tempResolved.ok()) {
                replyResolveError(req, timer, tempResolved);
                return;
            }

            log::Registry::fuse()->debug(
                "[unlink] Treating missing HTTP upload temp part as already removed: {}",
                tempResolved.path->string()
            );
            replyOk(req, timer);
            return;
        }

        replyResolveError(req, timer, resolved);
        return;
    }

    const auto entry = resolved.entry;

    if (entry->isDirectory()) {
        replyError(req, timer, EISDIR);
        return;
    }

    if (entry->isSymlink()) {
        const auto link = std::static_pointer_cast<Symlink>(entry);
        db::query::fs::Symlink::deleteSymlink(link);

        if (::unlink(entry->backing_path.c_str()) < 0)
            log::Registry::fuse()->debug("[unlink] Failed to remove backing symlink: {}: {}", entry->backing_path.string(), strerror(errno));

        runtime::Deps::get().fsCache->evictPath(entry->fuse_path);
        if (entry->parent_id) runtime::Deps::get().fsCache->refreshDirStats(*entry->parent_id);
        replyOk(req, timer);
        return;
    }

    if (isHttpUploadTemp) {
        db::query::fs::File::deleteFile(resolved.user->id, std::static_pointer_cast<File>(entry));

        if (::unlink(entry->backing_path.c_str()) < 0)
            log::Registry::fuse()->debug("[unlink] Failed to remove backing upload temp file: {}: {}", entry->backing_path.string(), strerror(errno));

        runtime::Deps::get().fsCache->evictPath(entry->fuse_path);
        if (entry->parent_id) runtime::Deps::get().fsCache->refreshDirStats(*entry->parent_id);
        replyOk(req, timer);
        return;
    }

    {
        // Local versioning keeps the file's last generation (a link, staged before the row goes); the backing file
        // is unlinked only after the trash committed. Under the file's content lock, with the row re-read: a seal
        // (or overwrite, rotation) renaming new bytes over the backing file since the lookup would otherwise be linked
        // under the old IV. The lock is held until the backing file and the cache entry are gone, so a seal that
        // waited for it finds nothing to write back to.
        std::scoped_lock contentLock(vh::fs::Filesystem::contentWriteMutex(entry->id));
        const auto current = db::query::fs::File::getFileById(entry->id);
        auto kept = resolved.engine && current
            ? vh::recovery::local::versions::retain(*resolved.engine, *current, vh::recovery::local::Reason::Delete,
                                                    {.actor = resolved.user->id})
            : vh::recovery::local::versions::Pending{};
        vh::db::Transactions::exec("fuse::unlink", [&](pqxx::work& txn) {
            kept.attach(txn);
            db::query::fs::File::markFileAsTrashed(txn, resolved.user->id, static_cast<unsigned int>(*entry->vault_id),
                                                   entry->path, entry->backing_path);
        });
        kept.committed();

        if (::unlink(entry->backing_path.c_str()) < 0)
            log::Registry::fuse()->debug("[unlink] Failed to remove backing file: {}: {}", entry->backing_path.string(), strerror(errno));
        runtime::Deps::get().fsCache->evictPath(entry->fuse_path);
    }

    // The file id ended with the trash: drop its sealed derived artifacts (best effort, never throws).
    if (resolved.engine) resolved.engine->purgeDerivedArtifacts(entry->id);

    // The folder stays (#168); its cached totals (what fs.dir.list shows) follow the delete.
    if (entry->parent_id) runtime::Deps::get().fsCache->refreshDirStats(*entry->parent_id);
    replyOk(req, timer);
}

void rmdir(const fuse_req_t req, const fuse_ino_t parent, const char* name) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::RmDir);
    log::Registry::fuse()->debug("[rmdir] Called for parent: {}, name: {}", parent, name);

    const auto resolved = Resolver::resolve({
        .caller = "rmdir",
        .fuseReq = req,
        .parentIno = parent,
        .childName = name,
        .action = permission::vault::FilesystemAction::Delete,
        .target = resolver::Target::EntryForPath
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    if (!resolved.entry->isDirectory()) {
        replyError(req, timer, ENOTDIR);
        return;
    }

    // Something is still under it (possibly entries this caller can't see): refuse instead of dropping it all.
    if (!db::query::fs::Directory::deleteEmptyDirectory(resolved.entry->id)) {
        replyError(req, timer, ENOTEMPTY);
        return;
    }

    if (::rmdir(resolved.entry->backing_path.c_str()) < 0)
        log::Registry::fuse()->warn("[rmdir] Failed to remove backing directory: {}: {}", resolved.entry->backing_path.string(), strerror(errno));

    runtime::Deps::get().fsCache->evictPath(resolved.entry->fuse_path);
    if (resolved.entry->parent_id) runtime::Deps::get().fsCache->refreshDirStats(*resolved.entry->parent_id);
    replyOk(req, timer);
}

void flush(const fuse_req_t req, const fuse_ino_t ino, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Flush);
    log::Registry::fuse()->debug("[flush] Called for inode: {}, file handle: {}", ino, fi->fh);

    // close(2) waits for flush: encrypt what changed now, so the file is complete on disk (and in the console)
    // when close returns. Flush can come several times per handle; an unchanged copy is not re-sealed.
    if (const auto* fh = reinterpret_cast<FileHandle*>(fi->fh); fh && fh->copy) {
        try {
            WorkingCopies::instance().persist(workingHandle(*fh));
        } catch (const std::exception& e) {
            log::Registry::fuse()->error("[flush] Could not encrypt inode {} to disk: {}", ino, e.what());
            replyError(req, timer, errnoFrom(e));
            return;
        }
    }

    replyOk(req, timer);
}

void release(const fuse_req_t req, const fuse_ino_t ino, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Release);
    log::Registry::fuse()->debug("[release] Called for inode: {}, file handle: {}", ino, fi->fh);

    const auto* fh = reinterpret_cast<FileHandle*>(fi->fh);
    if (!fh) {
        log::Registry::fuse()->debug("[release] Invalid file handle for inode: {}", ino);
        replyError(req, timer, EBADF);
        return;
    }

    auto handle = workingHandle(*fh);
    try {
        WorkingCopies::instance().release(handle);
    } catch (const std::exception& e) {
        log::Registry::fuse()->error("[release] Could not encrypt inode {} to disk: {}", ino, e.what());
    }

    delete fh;  // clean up heap allocation
    fi->fh = 0; // clear the kernel-side handle

    runtime::Deps::get().storageManager->closeOpenHandle(ino);
    recordCloseHandle();

    replyOk(req, timer);
}

void fsync(const fuse_req_t req, const fuse_ino_t ino, const int datasync, fuse_file_info* fi) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::Fsync);
    log::Registry::fuse()->debug("[fsync] Called for inode: {}, file handle: {}, isdatasync: {}", ino, fi->fh, datasync);
    (void) datasync;

    const auto resolved = Resolver::resolve({
        .caller = "fsync",
        .fuseReq = req,
        .ino = ino,
        .action = permission::vault::FilesystemAction::Write,
        .target = resolver::Target::Entry
    });

    if (!resolved.ok()) {
        replyResolveError(req, timer, resolved);
        return;
    }

    const auto* fh = reinterpret_cast<FileHandle*>(fi->fh);
    if (!fh) {
        log::Registry::fuse()->debug("[fsync] Invalid file handle for inode: {}", ino);
        replyError(req, timer, EBADF);
        return;
    }

    // Durable means encrypted on disk: seal the working copy (the sealed file is fsynced before it replaces the
    // backing file).
    try {
        WorkingCopies::instance().persist(workingHandle(*fh));
    } catch (const std::exception& e) {
        log::Registry::fuse()->error("[fsync] Could not encrypt inode {} to disk: {}", ino, e.what());
        replyError(req, timer, errnoFrom(e));
        return;
    }

    replyOk(req, timer);
}

void statfs(const fuse_req_t req, const fuse_ino_t ino) {
    ScopedFuseOpTimer timer(fuseStats(), FuseOperation::StatFs);
    log::Registry::fuse()->trace("[statfs] Called for inode: {}", ino);

    const auto entry = runtime::Deps::get().fsCache->getEntry(ino);
    if (!entry) {
        replyError(req, timer, ENOENT);
        return;
    }

    struct statvfs st{};

    if (::statvfs(entry->backing_path.c_str(), &st) < 0) {
        log::Registry::fuse()->debug("[statfs] Failed to get filesystem stats for: {}: {}", entry->backing_path.string(), strerror(errno));
        replyError(req, timer, errno);
        return;
    }

    timer.success();
    fuse_reply_statfs(req, &st);
}

// Every op goes through the reply guard (task::Guard, #263): an exception that escapes an op, a database pool timeout
// above all, is answered instead of leaving the kernel request (and its caller) waiting forever.
// tools/contracts/test_fuse_reply_guard_contract.py keeps every registration guarded.
fuse_lowlevel_ops getOperations() {
    fuse_lowlevel_ops ops = {};
    ops.getattr = task::guarded<&getattr>;
    ops.setattr = task::guarded<&setattr>;
    ops.readdir = task::guarded<&readdir>;
    ops.lookup = task::guarded<&lookup>;
    ops.readlink = task::guarded<&readlink>;
    ops.symlink = task::guarded<&symlink>;
    ops.open = task::guarded<&open>;
    ops.read = task::guarded<&read>;
    ops.forget = task::guardedForget<&forget>;
    ops.write = task::guarded<&write>;
    ops.create = task::guarded<&create>;
    ops.release = task::guarded<&release>;
    ops.access = task::guarded<&access>;
    ops.mkdir = task::guarded<&mkdir>;
    ops.rename = task::guarded<&rename>;
    ops.unlink = task::guarded<&unlink>;
    ops.rmdir = task::guarded<&rmdir>;
    ops.flush = task::guarded<&flush>;
    ops.fsync = task::guarded<&fsync>;
    ops.statfs = task::guarded<&statfs>;
    return ops;
}

struct stat statFromEntry(const std::shared_ptr<Entry>& entry, const fuse_ino_t& ino) {
    struct stat st{};
    st.st_ino = ino;
    if (entry->isDirectory()) st.st_mode = S_IFDIR | 0755;
    else if (entry->isSymlink()) st.st_mode = S_IFLNK | 0777;
    else st.st_mode = S_IFREG | 0644;
    st.st_size = static_cast<off_t>(entry->size_bytes);
    // While a file is open its working copy holds the newest plaintext.
    if (!entry->isDirectory() && !entry->isSymlink())
        if (const auto open = WorkingCopies::instance().openSize(ino)) st.st_size = static_cast<off_t>(*open);
    platform::mtime(st).tv_sec = entry->updated_at;
    platform::atime(st) = platform::ctime(st) = platform::mtime(st);
    st.st_nlink = 1;
    return st;
}

}
