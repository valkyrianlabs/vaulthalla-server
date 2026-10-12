// vh_fuse_probe: a tiny libfuse3 low-level filesystem for the macOS FUSE proof matrix (roadmap #200/#221).
//
// It answers one question per operation: who does the kernel say is calling, and does the daemon get asked at all?
// Every request is logged as one line:  <monotonic ms> <op> uid=<u> gid=<g> pid=<p> <args> -> <result>
// using fuse_req_ctx(), and authorization follows Vaulthalla's rules: a denied entry looks missing (ENOENT), the
// mount root is always visible, and entry/attr timeouts default to 0 so every lookup should reach the daemon.
//
// Namespace (in memory):  /public (everyone)  /secret (only uids in the policy file)  /scratch/ (read-write, any
// allowed caller; files created here hold their bytes in memory for integrity checks).
// Policy file: one uid per line allowed to see /secret; re-read on every request, so grants and revocations apply
// immediately (that is the point: a cached answer would show up as a request that never reached the daemon).
//
// Build: cc -std=c11 -Wall -Wextra -DFUSE_USE_VERSION=35 -DFUSE_DARWIN_ENABLE_EXTENSIONS=0 \
//          $(pkg-config --cflags --libs fuse3) vh_fuse_probe.c -o vh_fuse_probe
// Run:   vh_fuse_probe <mountpoint> --log <file> --policy <file> [--entry-timeout S] [--attr-timeout S] \
//          [-- <extra mount options, e.g. -o allow_other -o backend=fskit>]
// Unmount with umount(8) / diskutil unmount; SIGINT/SIGTERM exit cleanly.

#define _GNU_SOURCE
#include <fuse_lowlevel.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { INO_ROOT = FUSE_ROOT_ID, INO_PUBLIC = 2, INO_SECRET = 3, INO_SCRATCH = 4, INO_FIRST_DYNAMIC = 100 };
enum { MAX_FILES = 256, MAX_NAME = 255 };

typedef struct {
    int used;
    fuse_ino_t ino;
    char name[MAX_NAME + 1];
    unsigned char* data;
    size_t size;
    uid_t owner;
} scratch_file;

static const char kPublic[] = "public file\n";
static const char kSecret[] = "secret file: only policy uids may see this\n";

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static scratch_file g_files[MAX_FILES];
static fuse_ino_t g_next_ino = INO_FIRST_DYNAMIC;
static FILE* g_log;
static const char* g_policy_path;
static double g_entry_timeout = 0.0, g_attr_timeout = 0.0;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void logf_req(fuse_req_t req, const char* op, const char* fmt, ...) {
    const struct fuse_ctx* c = fuse_req_ctx(req);
    char args[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(args, sizeof args, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&g_lock);
    fprintf(g_log, "%.1f %s uid=%u gid=%u pid=%d %s\n", now_ms(), op, c ? (unsigned)c->uid : 0u,
            c ? (unsigned)c->gid : 0u, c ? (int)c->pid : -1, args);
    fflush(g_log);
    pthread_mutex_unlock(&g_lock);
}

// Re-read on every request: grants and revocations must take effect at once.
static int secret_allowed(uid_t uid) {
    FILE* f = g_policy_path ? fopen(g_policy_path, "r") : NULL;
    if (!f) return 0;
    char line[64];
    int allowed = 0;
    while (fgets(line, sizeof line, f))
        if ((uid_t)strtoul(line, NULL, 10) == uid && line[0] >= '0' && line[0] <= '9') allowed = 1;
    fclose(f);
    return allowed;
}

static scratch_file* find_file_by_ino(fuse_ino_t ino) {
    for (int i = 0; i < MAX_FILES; ++i)
        if (g_files[i].used && g_files[i].ino == ino) return &g_files[i];
    return NULL;
}

static scratch_file* find_file_by_name(const char* name) {
    for (int i = 0; i < MAX_FILES; ++i)
        if (g_files[i].used && strcmp(g_files[i].name, name) == 0) return &g_files[i];
    return NULL;
}

// -1: does not exist or hidden from this caller (ENOENT). 0: filled.
static int stat_for(fuse_req_t req, fuse_ino_t ino, struct stat* st) {
    const struct fuse_ctx* c = fuse_req_ctx(req);
    memset(st, 0, sizeof *st);
    st->st_ino = ino;
    st->st_uid = c->uid;  // report the caller as owner: the daemon decides, the kernel's permission check passes
    st->st_gid = c->gid;
    switch (ino) {
        case INO_ROOT:
        case INO_SCRATCH:
            st->st_mode = S_IFDIR | 0755;
            st->st_nlink = 2;
            return 0;
        case INO_PUBLIC:
            st->st_mode = S_IFREG | 0644;
            st->st_nlink = 1;
            st->st_size = sizeof kPublic - 1;
            return 0;
        case INO_SECRET:
            if (!secret_allowed(c->uid)) return -1;
            st->st_mode = S_IFREG | 0600;
            st->st_nlink = 1;
            st->st_size = sizeof kSecret - 1;
            return 0;
        default: {
            pthread_mutex_lock(&g_lock);
            const scratch_file* f = find_file_by_ino(ino);
            if (f) {
                st->st_mode = S_IFREG | 0644;
                st->st_nlink = 1;
                st->st_size = (off_t)f->size;
            }
            pthread_mutex_unlock(&g_lock);
            return f ? 0 : -1;
        }
    }
}

static void reply_entry(fuse_req_t req, fuse_ino_t ino) {
    struct fuse_entry_param e;
    memset(&e, 0, sizeof e);
    if (stat_for(req, ino, &e.attr) != 0) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    e.ino = ino;
    e.attr_timeout = g_attr_timeout;
    e.entry_timeout = g_entry_timeout;
    fuse_reply_entry(req, &e);
}

static void op_lookup(fuse_req_t req, fuse_ino_t parent, const char* name) {
    fuse_ino_t ino = 0;
    if (parent == INO_ROOT) {
        if (!strcmp(name, "public")) ino = INO_PUBLIC;
        else if (!strcmp(name, "secret")) ino = INO_SECRET;
        else if (!strcmp(name, "scratch")) ino = INO_SCRATCH;
    } else if (parent == INO_SCRATCH) {
        pthread_mutex_lock(&g_lock);
        const scratch_file* f = find_file_by_name(name);
        if (f) ino = f->ino;
        pthread_mutex_unlock(&g_lock);
    }
    struct stat st;
    const int visible = ino && stat_for(req, ino, &st) == 0;
    logf_req(req, "lookup", "parent=%llu name=%s -> %s", (unsigned long long)parent, name, visible ? "found" : "ENOENT");
    if (!visible) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    reply_entry(req, ino);
}

static void op_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
    (void)fi;
    struct stat st;
    const int rc = stat_for(req, ino, &st);
    logf_req(req, "getattr", "ino=%llu -> %s", (unsigned long long)ino, rc == 0 ? "ok" : "ENOENT");
    if (rc != 0) fuse_reply_err(req, ENOENT);
    else fuse_reply_attr(req, &st, g_attr_timeout);
}

static void op_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* fi) {
    (void)fi;
    const struct fuse_ctx* c = fuse_req_ctx(req);
    char names[MAX_FILES + 4][MAX_NAME + 1];
    fuse_ino_t inos[MAX_FILES + 4];
    int n = 0;
    if (ino != INO_ROOT && ino != INO_SCRATCH) {
        logf_req(req, "readdir", "ino=%llu -> ENOTDIR", (unsigned long long)ino);
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    strcpy(names[n], "."); inos[n++] = ino;
    strcpy(names[n], ".."); inos[n++] = INO_ROOT;
    if (ino == INO_ROOT) {
        strcpy(names[n], "public"); inos[n++] = INO_PUBLIC;
        if (secret_allowed(c->uid)) { strcpy(names[n], "secret"); inos[n++] = INO_SECRET; }
        strcpy(names[n], "scratch"); inos[n++] = INO_SCRATCH;
    } else {
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < MAX_FILES; ++i)
            if (g_files[i].used) { strcpy(names[n], g_files[i].name); inos[n++] = g_files[i].ino; }
        pthread_mutex_unlock(&g_lock);
    }
    char* buf = calloc(1, size);
    size_t used = 0;
    for (int i = (int)off; i < n; ++i) {
        struct stat st = {.st_ino = inos[i], .st_mode = (inos[i] == INO_ROOT || inos[i] == INO_SCRATCH) ? S_IFDIR : S_IFREG};
        const size_t need = fuse_add_direntry(req, buf + used, size - used, names[i], &st, i + 1);
        if (need > size - used) break;
        used += need;
    }
    logf_req(req, "readdir", "ino=%llu off=%lld entries=%d secret_listed=%d", (unsigned long long)ino, (long long)off,
             n, ino == INO_ROOT && secret_allowed(c->uid));
    fuse_reply_buf(req, buf, used);
    free(buf);
}

static void op_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
    struct stat st;
    const int rc = stat_for(req, ino, &st);
    logf_req(req, "open", "ino=%llu flags=0x%x -> %s", (unsigned long long)ino, fi->flags, rc == 0 ? "ok" : "ENOENT");
    if (rc != 0) { fuse_reply_err(req, ENOENT); return; }
    if ((ino == INO_PUBLIC || ino == INO_SECRET) && (fi->flags & O_ACCMODE) != O_RDONLY) { fuse_reply_err(req, EACCES); return; }
    fi->direct_io = 1;  // like Vaulthalla: no page cache between callers
    fi->keep_cache = 0;
    fuse_reply_open(req, fi);
}

static void op_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* fi) {
    (void)fi;
    struct stat st;
    if (stat_for(req, ino, &st) != 0) {
        logf_req(req, "read", "ino=%llu -> ENOENT (revoked while open)", (unsigned long long)ino);
        fuse_reply_err(req, ENOENT);
        return;
    }
    const char* src = NULL;
    size_t len = 0;
    unsigned char* copy = NULL;
    if (ino == INO_PUBLIC) { src = kPublic; len = sizeof kPublic - 1; }
    else if (ino == INO_SECRET) { src = kSecret; len = sizeof kSecret - 1; }
    else {
        pthread_mutex_lock(&g_lock);
        const scratch_file* f = find_file_by_ino(ino);
        if (f && f->size) { copy = malloc(f->size); memcpy(copy, f->data, f->size); len = f->size; }
        pthread_mutex_unlock(&g_lock);
        src = (const char*)copy;
    }
    const size_t start = (size_t)off < len ? (size_t)off : len;
    const size_t count = len - start < size ? len - start : size;
    logf_req(req, "read", "ino=%llu off=%lld size=%zu -> %zu", (unsigned long long)ino, (long long)off, size, count);
    fuse_reply_buf(req, src ? src + start : NULL, count);
    free(copy);
}

static void op_create(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode, struct fuse_file_info* fi) {
    (void)mode;
    if (parent != INO_SCRATCH || strlen(name) > MAX_NAME) {
        logf_req(req, "create", "parent=%llu name=%s -> EACCES", (unsigned long long)parent, name);
        fuse_reply_err(req, EACCES);
        return;
    }
    pthread_mutex_lock(&g_lock);
    scratch_file* f = find_file_by_name(name);
    if (!f)
        for (int i = 0; i < MAX_FILES && !f; ++i)
            if (!g_files[i].used) {
                f = &g_files[i];
                memset(f, 0, sizeof *f);
                f->used = 1;
                f->ino = g_next_ino++;
                strcpy(f->name, name);
                f->owner = fuse_req_ctx(req)->uid;
            }
    const fuse_ino_t ino = f ? f->ino : 0;
    pthread_mutex_unlock(&g_lock);
    logf_req(req, "create", "parent=%llu name=%s -> %s", (unsigned long long)parent, name, ino ? "ok" : "ENOSPC");
    if (!ino) { fuse_reply_err(req, ENOSPC); return; }
    struct fuse_entry_param e;
    memset(&e, 0, sizeof e);
    stat_for(req, ino, &e.attr);
    e.ino = ino;
    e.attr_timeout = g_attr_timeout;
    e.entry_timeout = g_entry_timeout;
    fi->direct_io = 1;
    fuse_reply_create(req, &e, fi);
}

static void op_write(fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size, off_t off, struct fuse_file_info* fi) {
    (void)fi;
    pthread_mutex_lock(&g_lock);
    scratch_file* f = find_file_by_ino(ino);
    int err = 0;
    if (!f) err = EACCES;
    else if ((size_t)off + size > f->size) {
        unsigned char* grown = realloc(f->data, (size_t)off + size);
        if (!grown) err = ENOSPC;
        else { memset(grown + f->size, 0, (size_t)off + size - f->size); f->data = grown; f->size = (size_t)off + size; }
    }
    if (!err) memcpy(f->data + off, buf, size);
    pthread_mutex_unlock(&g_lock);
    logf_req(req, "write", "ino=%llu off=%lld size=%zu -> %s", (unsigned long long)ino, (long long)off, size, err ? strerror(err) : "ok");
    if (err) fuse_reply_err(req, err);
    else fuse_reply_write(req, size);
}

static void op_setattr(fuse_req_t req, fuse_ino_t ino, struct stat* attr, int to_set, struct fuse_file_info* fi) {
    (void)fi;
    if (to_set & FUSE_SET_ATTR_SIZE) {
        pthread_mutex_lock(&g_lock);
        scratch_file* f = find_file_by_ino(ino);
        if (f) {
            unsigned char* grown = realloc(f->data, (size_t)attr->st_size ? (size_t)attr->st_size : 1);
            if (grown) { if ((size_t)attr->st_size > f->size) memset(grown + f->size, 0, (size_t)attr->st_size - f->size); f->data = grown; f->size = (size_t)attr->st_size; }
        }
        pthread_mutex_unlock(&g_lock);
    }
    logf_req(req, "setattr", "ino=%llu to_set=0x%x", (unsigned long long)ino, to_set);
    op_getattr(req, ino, NULL);
}

static void op_unlink(fuse_req_t req, fuse_ino_t parent, const char* name) {
    int err = ENOENT;
    if (parent == INO_SCRATCH) {
        pthread_mutex_lock(&g_lock);
        scratch_file* f = find_file_by_name(name);
        if (f) { free(f->data); memset(f, 0, sizeof *f); err = 0; }
        pthread_mutex_unlock(&g_lock);
    }
    logf_req(req, "unlink", "parent=%llu name=%s -> %s", (unsigned long long)parent, name, err ? "ENOENT" : "ok");
    fuse_reply_err(req, err);
}

static void op_rename(fuse_req_t req, fuse_ino_t parent, const char* name, fuse_ino_t newparent, const char* newname, unsigned int flags) {
    int err = 0;
    if (flags & ~(unsigned)RENAME_NOREPLACE) err = EINVAL;  // exchange and anything unknown: refuse, never fall back
    else if (parent != INO_SCRATCH || newparent != INO_SCRATCH || strlen(newname) > MAX_NAME) err = EACCES;
    else {
        pthread_mutex_lock(&g_lock);
        scratch_file* f = find_file_by_name(name);
        scratch_file* existing = find_file_by_name(newname);
        if (!f) err = ENOENT;
        else if (existing && (flags & RENAME_NOREPLACE)) err = EEXIST;
        else {
            if (existing && existing != f) { free(existing->data); memset(existing, 0, sizeof *existing); }
            strcpy(f->name, newname);
        }
        pthread_mutex_unlock(&g_lock);
    }
    logf_req(req, "rename", "%s -> %s flags=0x%x -> %s", name, newname, flags, err ? strerror(err) : "ok");
    fuse_reply_err(req, err);
}

static void op_statfs(fuse_req_t req, fuse_ino_t ino) {
    (void)ino;
    struct statvfs sv;
    memset(&sv, 0, sizeof sv);
    sv.f_bsize = sv.f_frsize = 4096;
    sv.f_blocks = sv.f_bfree = sv.f_bavail = 1 << 20;
    sv.f_files = sv.f_ffree = 1 << 16;
    sv.f_namemax = MAX_NAME;
    logf_req(req, "statfs", "");
    fuse_reply_statfs(req, &sv);
}

static void op_access(fuse_req_t req, fuse_ino_t ino, int mask) {
    struct stat st;
    const int rc = stat_for(req, ino, &st);
    logf_req(req, "access", "ino=%llu mask=0x%x -> %s", (unsigned long long)ino, mask, rc == 0 ? "ok" : "ENOENT");
    fuse_reply_err(req, rc == 0 ? 0 : ENOENT);
}

static void op_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    logf_req(req, "forget", "ino=%llu nlookup=%llu", (unsigned long long)ino, (unsigned long long)nlookup);
    fuse_reply_none(req);
}

static void op_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
    (void)fi;
    logf_req(req, "release", "ino=%llu", (unsigned long long)ino);
    fuse_reply_err(req, 0);
}

static void op_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
    (void)fi;
    logf_req(req, "flush", "ino=%llu", (unsigned long long)ino);
    fuse_reply_err(req, 0);
}

static const struct fuse_lowlevel_ops kOps = {
    .lookup = op_lookup, .getattr = op_getattr, .setattr = op_setattr, .readdir = op_readdir, .open = op_open,
    .read = op_read, .write = op_write, .create = op_create, .unlink = op_unlink, .rename = op_rename,
    .statfs = op_statfs, .access = op_access, .forget = op_forget, .release = op_release, .flush = op_flush,
};

int main(int argc, char** argv) {
    const char* mountpoint = NULL;
    const char* log_path = NULL;
    int extra = argc;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) { extra = i + 1; break; }
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) log_path = argv[++i];
        else if (!strcmp(argv[i], "--policy") && i + 1 < argc) g_policy_path = argv[++i];
        else if (!strcmp(argv[i], "--entry-timeout") && i + 1 < argc) g_entry_timeout = atof(argv[++i]);
        else if (!strcmp(argv[i], "--attr-timeout") && i + 1 < argc) g_attr_timeout = atof(argv[++i]);
        else if (!mountpoint) mountpoint = argv[i];
    }
    if (!mountpoint || !log_path || !g_policy_path) {
        fprintf(stderr, "usage: %s <mountpoint> --log <file> --policy <file> [--entry-timeout S] [--attr-timeout S] [-- -o opt ...]\n", argv[0]);
        return 2;
    }
    g_log = fopen(log_path, "a");
    if (!g_log) { perror("log"); return 2; }

    // libfuse argument vector: program name, then the caller's mount options after "--".
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, argv[0]);
    for (int i = extra; i < argc; ++i) fuse_opt_add_arg(&args, argv[i]);

    struct fuse_session* se = fuse_session_new(&args, &kOps, sizeof kOps, NULL);
    if (!se) { fprintf(stderr, "fuse_session_new failed\n"); return 1; }
    if (fuse_set_signal_handlers(se) != 0) return 1;
    if (fuse_session_mount(se, mountpoint) != 0) { fprintf(stderr, "mount failed: %s\n", mountpoint); return 1; }
    fprintf(g_log, "%.1f mounted %s pid=%d euid=%u entry_timeout=%.1f attr_timeout=%.1f\n", now_ms(), mountpoint,
            (int)getpid(), (unsigned)geteuid(), g_entry_timeout, g_attr_timeout);
    fflush(g_log);

    // Single-threaded on purpose: requests are logged in the order the daemon sees them.
    const int rc = fuse_session_loop(se);

    fuse_session_unmount(se);
    fuse_remove_signal_handlers(se);
    fuse_session_destroy(se);
    fuse_opt_free_args(&args);
    fprintf(g_log, "%.1f unmounted rc=%d\n", now_ms(), rc);
    fclose(g_log);
    return rc ? 1 : 0;
}
