#pragma once

#define FUSE_USE_VERSION 35

#include <filesystem>
#include <fuse3/fuse_lowlevel.h>
#include <memory>
#include "fs/Fwd.hpp"

namespace vh::fuse {
    struct WorkingCopy;

    // An open file: the open(2) flags on the inode's working copy (see WorkingCopies), never the backing file.
    struct FileHandle {
        std::filesystem::path path;
        int flags;
        size_t size = 0;
        std::shared_ptr<WorkingCopy> copy;
    };

    void getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi);

    void setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, fuse_file_info *fi);

    void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi);

    void lookup(fuse_req_t req, fuse_ino_t parent, const char *name);

    void readlink(fuse_req_t req, fuse_ino_t ino);

    void symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name);

    void open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi);

    void read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi);

    void forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);

    void write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size,
               off_t off, fuse_file_info *fi);

    void create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, fuse_file_info *fi);

    void unlink(fuse_req_t req, fuse_ino_t parent, const char *name);

    void rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname,
                unsigned int flags);

    void mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode);

    void flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi);

    void release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi);

    void access(fuse_req_t req, fuse_ino_t ino, int mask);

    void rmdir(fuse_req_t req, fuse_ino_t parent, const char *name);

    void fsync(fuse_req_t req, fuse_ino_t ino, int datasync, fuse_file_info *fi);

    void statfs(fuse_req_t req, fuse_ino_t ino);

    fuse_lowlevel_ops getOperations();

    struct stat statFromEntry(const std::shared_ptr<fs::model::Entry> &entry, const fuse_ino_t &ino);
}
