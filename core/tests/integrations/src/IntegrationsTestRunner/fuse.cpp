#include "identities/Manager.hpp"
#include "IntegrationsTestRunner.hpp"
#include "cmd/generators.hpp"
#include "fuse/helpers.hpp"
#include "fuse/Builder.hpp"
#include "identities/User.hpp"
#include "fs/model/Path.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "vault/model/Vault.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/rbac/role/vault/Assignments.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/http/model/preview/Response.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "storage/PlaintextReader.hpp"
#include "seed/Stream.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <stdexcept>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "rbac/role/Vault.hpp"

#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace vh::test::integration::fuse;
using namespace vh::rbac;
using vh::identities::User;
using vh::identities::Group;

namespace vh::test::integration {

    namespace {
        std::shared_ptr<storage::Engine> makeVaultForOwner(const uint32_t ownerId, const std::string& usage) {
            auto vault = std::make_shared<vault::model::Vault>();
            vault->name = generateVaultName(usage);
            vault->description = "FUSE root listing fixture vault";
            vault->owner_id = ownerId;

            const auto sync = std::make_shared<sync::model::LocalPolicy>();
            sync->interval = std::chrono::minutes(15);
            sync->conflict_policy = sync::model::LocalPolicy::ConflictPolicy::Overwrite;

            const auto storageManager = runtime::Deps::get().storageManager;
            if (!storageManager) throw std::runtime_error("Storage manager not initialized");

            vault = storageManager->addVault(vault, sync);
            const auto engine = storageManager->getEngine(vault->id);
            if (!engine) throw std::runtime_error("Failed to initialize FUSE test vault engine");
            return engine;
        }

        std::string listingNeedle(const std::shared_ptr<storage::Engine>& engine) {
            if (!engine || !engine->vault) return {};
            return engine->vault->effectiveFuseName() + "\n";
        }

        std::vector<std::string> mountedVaultListingNeedles() {
            const auto storageManager = runtime::Deps::get().storageManager;
            if (!storageManager) throw std::runtime_error("Storage manager not initialized");

            std::vector<std::string> names;
            for (const auto& engine : storageManager->getEngines()) {
                auto name = listingNeedle(engine);
                if (!name.empty()) names.push_back(std::move(name));
            }

            std::ranges::sort(names);
            names.erase(std::unique(names.begin(), names.end()), names.end());
            return names;
        }

        std::vector<std::string> mountedVaultListingNeedlesForOwner(const uint32_t ownerId) {
            const auto storageManager = runtime::Deps::get().storageManager;
            if (!storageManager) throw std::runtime_error("Storage manager not initialized");

            std::vector<std::string> names;
            for (const auto& engine : storageManager->getEngines()) {
                if (!engine || !engine->vault || engine->vault->owner_id != ownerId) continue;
                auto name = listingNeedle(engine);
                if (!name.empty()) names.push_back(std::move(name));
            }

            std::ranges::sort(names);
            names.erase(std::unique(names.begin(), names.end()), names.end());
            return names;
        }

        void assignVaultRoleToUser(
            const std::shared_ptr<User>& user,
            const uint32_t vaultId,
            const std::string& templateName,
            const std::string& usage
        ) {
            if (!user) throw std::runtime_error("Cannot assign vault role to null user");

            const auto role = db::query::rbac::role::Vault::get(templateName);
            if (!role) throw std::runtime_error("Vault role template not found: " + templateName);

            role->id = 0;
            role->name = generateRoleName(EntityType::VAULT_ROLE, usage);
            role->description = "FUSE root listing fixture role";
            role->assign(user->id, "user", vaultId);

            db::query::rbac::role::Vault::upsert(role);
            vh::identities::manager().mutate({.users = {user->id}},
                                             [&] { db::query::rbac::role::vault::Assignments::assign(role); });
        }

        std::shared_ptr<::vh::protocols::ws::Session> wsSessionFor(const std::shared_ptr<User>& user) {
            auto session = std::make_shared<::vh::protocols::ws::Session>(std::make_shared<::vh::protocols::ws::Router>());
            session->user = user;
            return session;
        }

        // Runs a ws filesystem command in-process as `user`, the way the console sends it.
        ExecResult wsCommand(const std::function<nlohmann::json(const std::shared_ptr<::vh::protocols::ws::Session>&)>& fn,
                             const std::shared_ptr<User>& user, const std::string& okText) {
            const auto command = "ws handler (in-process) as " + user->name() + ": " + okText;
            try {
                (void)fn(wsSessionFor(user));
                return {.exit_code = 0, .stdout_text = okText + "\n", .stderr_text = {}, .command = command};
            } catch (const std::exception& e) {
                return {.exit_code = EIO, .stdout_text = {}, .stderr_text = e.what(), .command = command};
            }
        }

        // GET /download?vault_id=&path= through the HTTP router as `user`; stdout is the body.
        ExecResult httpDownload(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<User>& user,
                                const std::string& vaultPath) {
            namespace http = ::vh::protocols::http;
            std::string encoded;
            for (const char c : vaultPath) encoded += c == '/' ? std::string("%2F") : std::string(1, c);

            const auto session = wsSessionFor(user);
            http::Router::setPreviewSessionResolverForTesting([session](const http::request&) { return session; });
            ExecResult out;
            try {
                http::request req{http::verb::get,
                                  "/download?vault_id=" + std::to_string(engine->vault->id) + "&path=" + encoded, 11};
                auto res = http::Router::route(std::move(req));
                const auto code = std::visit([](const auto& r) { return static_cast<int>(r.result()); }, res);
                std::string body;
                if (const auto* v = std::get_if<http::vector_response>(&res)) body.assign(v->body().begin(), v->body().end());
                else if (const auto* s = std::get_if<http::string_response>(&res)) body = s->body();
                else if (const auto* st = std::get_if<http::model::preview::StreamResponse>(&res); st && st->reader) {
                    std::vector<uint8_t> buf(static_cast<std::size_t>(st->length));
                    std::size_t done = 0;
                    while (done < buf.size()) {
                        const auto n = st->reader->read(st->offset + done, std::span(buf.data() + done, buf.size() - done));
                        if (n == 0) break;
                        done += n;
                    }
                    body.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(done));
                }
                out = {.exit_code = code == 200 ? 0 : (code & 0xFF), .stdout_text = body, .stderr_text = {}};
            } catch (const std::exception& e) {
                out = {.exit_code = EIO, .stdout_text = {}, .stderr_text = e.what()};
            }
            http::Router::resetPreviewSessionResolverForTesting();
            out.command = "GET /download?vault_id=" + std::to_string(engine->vault->id) + "&path=" + encoded +
                          " (in-process) as " + user->name();
            return out;
        }

        // #255: the names FUSE readdir gives `uid` for a folder against the names ws fs.dir.list gives `user` (the same
        // account) for it. Passes with "PARITY" and the shared names, one per line, when the two sets are equal.
        ExecResult listingParity(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<User>& user,
                                 const uid_t uid, const std::filesystem::path& fuseDir, const std::string& vaultDir) {
            const auto command = "readdir of " + fuseDir.string() + " as uid " + std::to_string(uid) +
                                 " vs fs.dir.list " + vaultDir + " as " + user->name();
            const auto readdir = ls_as(uid, fuseDir);
            if (readdir.exit_code != 0) return readdir;

            std::vector<std::string> fuseNames;
            for (std::size_t start = 0, end; start < readdir.stdout_text.size(); start = end + 1) {
                end = readdir.stdout_text.find('\n', start);
                if (end == std::string::npos) end = readdir.stdout_text.size();
                if (end > start) fuseNames.push_back(readdir.stdout_text.substr(start, end - start));
            }

            std::vector<std::string> wsNames;
            try {
                const auto listing = ::vh::protocols::ws::handler::fs::Storage::listDir(
                    {{"vault_id", engine->vault->id}, {"path", vaultDir}}, wsSessionFor(user));
                for (const auto& f : listing.at("files")) wsNames.push_back(f.at("name").get<std::string>());
            } catch (const std::exception& e) {
                return {.exit_code = EIO, .stdout_text = {}, .stderr_text = e.what(), .command = command};
            }

            std::ranges::sort(fuseNames);
            std::ranges::sort(wsNames);
            const auto join = [](const std::vector<std::string>& names) {
                std::string out;
                for (const auto& n : names) out += n + "\n";
                return out;
            };
            if (fuseNames != wsNames)
                return {.exit_code = EIO, .stdout_text = {},
                        .stderr_text = "readdir:\n" + join(fuseNames) + "fs.dir.list:\n" + join(wsNames),
                        .command = command};
            return {.exit_code = 0, .stdout_text = "PARITY\n" + join(wsNames), .stderr_text = {}, .command = command};
        }

        // Runs `first`, and `then` only when it succeeded (a delete followed by a look at what it left).
        ExecResult andThen(const ExecResult& first, const std::function<ExecResult()>& then) {
            if (first.exit_code != 0) return first;
            return then();
        }
    }

    // #167: fs.entry.copy of a folder copies the whole subtree, and every copied file is readable at once (through the
    // mount and /download), with no sync pass in between. #168: deleting a file never removes the folder it was in,
    // whether it is deleted through the mount or the console; rmdir of a non-empty folder is ENOTEMPTY.
    static TestStage testCopyAndDelete() {
        auto builder = Builder::make({
            .name = "Copy And Delete",
            .baseDir = "copy_delete_seed"
        });

        const auto [ctx, subj] = builder.scenario();
        (void)subj;

        const auto uid = *ctx.admin->state()->meta.linux_uid;
        const auto src = ctx.base() / "src";
        const auto copy = ctx.base() / "copy";
        const std::string vaultBase = "/" + ctx.baseDir;
        const std::vector<std::pair<std::string, std::string>> files{
            {"a.txt", "alpha copy\n"},
            {"sub/b.txt", "bravo copy\n"},
            {"sub/deep/c.txt", "charlie copy\n"}
        };

        (void)mkdir_as(uid, src / "sub" / "deep");
        (void)mkdir_as(uid, src / "empty");
        for (const auto& [rel, content] : files) (void)write_as(uid, src / rel, content);

        builder.makeTestCase({
            .name = "fs.entry.copy of a nested folder (admin)",
            .path = "fs/copy",
            .must_contain = {"OK copy"},
            .fn = [=] {
                return wsCommand([&](const auto& session) {
                    return ::vh::protocols::ws::handler::fs::Storage::copy(
                        {{"vault_id", ctx.engine->vault->id}, {"from", vaultBase + "/src"}, {"to", vaultBase + "/copy"}},
                        session);
                }, ctx.admin, "OK copy");
            }
        });

        builder.makeTestCase({
            .name = "FUSE ls of the copy shows its subtree (admin)",
            .path = "fuse/ls",
            .must_contain = {"a.txt\n", "sub\n", "empty\n"},
            .fn = [=] { return ls_as(uid, copy); }
        });

        for (const auto& [rel, content] : files) {
            builder.makeTestCase({
                .name = "FUSE read of copied " + rel + " (admin)",
                .path = "fuse/read",
                .must_contain = {content},
                .fn = [=] { return read_as(uid, copy / rel); }
            });

            builder.makeTestCase({
                .name = "/download of copied " + rel + " (admin)",
                .path = "http/download",
                .must_contain = {content},
                .fn = [=] { return httpDownload(ctx.engine, ctx.admin, vaultBase + "/copy/" + rel); }
            });
        }

        builder.makeTestCase({
            .name = "FUSE ls of the copied empty folder (admin)",
            .path = "fuse/ls",
            .fn = [=] { return ls_as(uid, copy / "empty"); }
        });

        builder.makeTestCase({
            .name = "FUSE unlink of a folder's last file keeps the folder (admin)",
            .path = "fuse/unlink",
            .must_contain = {"deep\n"},
            .fn = [=] {
                return andThen(unlink_as(uid, copy / "sub" / "deep" / "c.txt"), [=] { return ls_as(uid, copy / "sub"); });
            }
        });

        builder.makeTestCase({
            .name = "fs.entry.delete of a folder's last file keeps it and its parents (admin)",
            .path = "fs/delete",
            .must_contain = {"deep\n"},
            .fn = [=] {
                const auto deleted = wsCommand([&](const auto& session) {
                    return ::vh::protocols::ws::handler::fs::Storage::remove(
                        {{"vault_id", ctx.engine->vault->id}, {"path", vaultBase + "/copy/sub/b.txt"}}, session);
                }, ctx.admin, "OK delete");
                return andThen(deleted, [=] { return ls_as(uid, copy / "sub"); });
            }
        });

        builder.makeTestCase({
            .name = "FUSE rmdir of a non-empty folder is ENOTEMPTY (admin)",
            .path = "fuse/rmdir",
            .expect_exit = ENOTEMPTY,
            .fn = [=] { return rmdir_as(uid, copy / "sub"); }
        });

        builder.makeTestCase({
            .name = "FUSE rmdir of empty folders (admin)",
            .path = "fuse/rmdir",
            .must_contain = {"OK rmdir"},
            .fn = [=] {
                return andThen(rmdir_as(uid, copy / "sub" / "deep"), [=] { return rmdir_as(uid, copy / "sub"); });
            }
        });

        builder.makeTestCase({
            .name = "The source is untouched by all of it (admin)",
            .path = "fuse/read",
            .must_contain = {"charlie copy\n"},
            .fn = [=] { return read_as(uid, src / "sub" / "deep" / "c.txt"); }
        });

        return builder.exec();
    }

    static TestStage testFUSECRUD() {
        auto builder = Builder::make({
            .name = "CRUD",
            .baseDir = "crud_seed"
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeTestCase({
            .name = "FUSE write (admin)",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(*ctx.admin->state()->meta.linux_uid, ctx.hello(), "hello world!\n"); }
        });

        builder.makeTestCase({
            .name = "FUSE chmod no-op compatibility (admin)",
            .path = "fuse/chmod",
            .must_contain = {"OK chmod"},
            .fn = [=]{ return chmod_as(*ctx.admin->state()->meta.linux_uid, ctx.hello(), 0600); }
        });

        builder.makeTestCase({
            .name = "FUSE chmod preserves Vaulthalla attrs (admin)",
            .path = "fuse/stat",
            .must_contain = {"mode=644"},
            .fn = [=]{ return stat_mode_as(*ctx.admin->state()->meta.linux_uid, ctx.hello(), 0644); }
        });

        builder.makeTestCase({
            .name = "FUSE cp -a tree with git metadata (admin)",
            .path = "fuse/cp",
            .must_contain = {"OK cp -a"},
            .fn = [=]{ return cp_preserve_tree_as(*ctx.admin->state()->meta.linux_uid, ctx.root / "copied_tree"); }
        });

        builder.makeTestCase({
            .name = "FUSE read copied git config (admin)",
            .path = "fuse/read",
            .must_contain = {"repositoryformatversion"},
            .fn = [=] { return read_as(*ctx.admin->state()->meta.linux_uid, ctx.root / "copied_tree" / ".git" / "config"); }
        });

        // Bytes are ciphertext on disk; reads through the mount decrypt them (#173).
        builder.makeTestCase({
            .name = "FUSE read (admin)",
            .path = "fuse/read",
            .must_contain = {"hello world!"},
            .fn = [=] { return read_as(*ctx.admin->state()->meta.linux_uid, ctx.hello()); }
        });

        builder.makeTestCase({
            .name = "FUSE stat reports the plaintext size (admin)",
            .path = "fuse/stat",
            .must_contain = {" size=13\n"},
            .fn = [=] { return stat_size_as(*ctx.admin->state()->meta.linux_uid, ctx.hello()); }
        });

        // The kernel forgetting every inode (as under memory pressure) must not make the vault unreachable.
        builder.makeTestCase({
            .name = "FUSE vault reachable after the kernel forgets its inodes (admin)",
            .path = "fuse/read",
            .must_contain = {"hello world!"},
            .fn = [=] {
                ::sync();
                std::ofstream("/proc/sys/vm/drop_caches") << "2\n";
                return read_as(*ctx.admin->state()->meta.linux_uid, ctx.hello());
            }
        });

        builder.makeTestCase({
            .name = "FUSE rename (admin)",
            .path = "fuse/rename",
            .must_contain = {"OK mv"},
            .fn = [=]{ return mv_as(*ctx.admin->state()->meta.linux_uid, ctx.hello(), ctx.base() / "hello2.txt"); }
        });

        // The bridge only implements RENAME_NOREPLACE. An exchange used to run as a plain rename, overwriting the
        // other entry; it must be refused and leave both files as they were (the next cases read them).
        builder.makeTestCase({
            .name = "FUSE write a second file for the exchange check (admin)",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "exchange-other.txt", "other\n"); }
        });

        builder.makeTestCase({
            .name = "FUSE RENAME_EXCHANGE is refused (admin)",
            .path = "fuse/rename",
            .expect_exit = EINVAL,
            .fn = [=]{ return exchange_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "hello2.txt",
                                          ctx.base() / "exchange-other.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE refused exchange left the other file alone (admin)",
            .path = "fuse/read",
            .must_contain = {"other"},
            .fn = [=] { return read_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "exchange-other.txt"); }
        });

        // How editors save (vim, LibreOffice, IDEs): write a temp file, rename(2) it over the original. It used to
        // fail with EIO (UNIQUE(parent_id, name)) and leave the cached temp entry claiming the target's path.
        builder.makeTestCase({
            .name = "FUSE write an editor temp file (admin)",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / ".exchange-other.txt.swp", "saved\n"); }
        });

        builder.makeTestCase({
            .name = "FUSE rename over an existing file replaces it (admin)",
            .path = "fuse/rename",
            .must_contain = {"OK mv"},
            .fn = [=]{ return mv_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / ".exchange-other.txt.swp",
                                    ctx.base() / "exchange-other.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE replaced file reads the new content (admin)",
            .path = "fuse/read",
            .must_contain = {"saved"},
            .must_not_contain = {"other\n"},
            .fn = [=] { return read_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "exchange-other.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE renamed temp file is gone (admin)",
            .path = "fuse/read",
            .expect_exit = ENOENT,
            .fn = [=] { return read_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / ".exchange-other.txt.swp"); }
        });

        builder.makeTestCase({
            .name = "FUSE read after rename is still plaintext (admin)",
            .path = "fuse/read",
            .must_contain = {"hello world!"},
            .fn = [=] { return read_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "hello2.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE overwrite with shorter content leaves no tail (admin)",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "hello2.txt", "hi\n"); }
        });

        builder.makeTestCase({
            .name = "FUSE stat after shorter overwrite (admin)",
            .path = "fuse/stat",
            .must_contain = {" size=3\n"},
            .fn = [=] { return stat_size_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "hello2.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE truncate (admin)",
            .path = "fuse/truncate",
            .must_contain = {"OK truncate"},
            .fn = [=] { return truncate_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "hello2.txt", 1); }
        });

        builder.makeTestCase({
            .name = "FUSE stat after truncate (admin)",
            .path = "fuse/stat",
            .must_contain = {" size=1\n"},
            .fn = [=] { return stat_size_as(*ctx.admin->state()->meta.linux_uid, ctx.base() / "hello2.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE rm -rf (admin)",
            .path = "fuse/rmrf",
            .must_contain = {"OK rm -rf"},
            .fn = [=]{ return rmrf_as(*ctx.admin->state()->meta.linux_uid, ctx.base()); }
        });

        return builder.exec();
    }

    static TestStage testFUSERootListingSuperAdmin() {
        auto builder = Builder::make({
            .name = "Root Listing Super Admin",
            .baseDir = "root_listing_super_admin_seed"
        });

        const auto [ctx, subj] = builder.scenario();
        (void)subj;

        (void)makeVaultForOwner(ctx.admin->id, "vault/create/root_listing_super_admin/extra_a");
        (void)makeVaultForOwner(ctx.admin->id, "vault/create/root_listing_super_admin/extra_b");

        builder.makeTestCase({
            .name = "FUSE root ls lists all mounted vaults for super-admin",
            .path = "fuse/ls/root",
            .must_contain = mountedVaultListingNeedles(),
            .fn = [=]{ return ls_as(*ctx.admin->state()->meta.linux_uid, ctx.engine->paths->fuseRoot); }
        });

        return builder.exec();
    }

    static TestStage testFUSERootListingUnprivilegedUser() {
        auto builder = Builder::make({
            .name = "Root Listing Unprivileged User",
            .baseDir = "root_listing_unprivileged_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/root_listing_unprivileged" });

        const auto [ctx, subj] = builder.scenario();

        (void)makeVaultForOwner(ctx.admin->id, "vault/create/root_listing_unprivileged/admin_a");
        (void)makeVaultForOwner(ctx.admin->id, "vault/create/root_listing_unprivileged/admin_b");

        const auto userVaultA = makeVaultForOwner(subj.user->id, "vault/create/root_listing_unprivileged/user_a");
        const auto userVaultB = makeVaultForOwner(subj.user->id, "vault/create/root_listing_unprivileged/user_b");

        assignVaultRoleToUser(
            subj.user,
            userVaultA->vault->id,
            role::Vault::PowerUser().name,
            "vault_role/create/root_listing_unprivileged/user_a"
        );
        assignVaultRoleToUser(
            subj.user,
            userVaultB->vault->id,
            role::Vault::PowerUser().name,
            "vault_role/create/root_listing_unprivileged/user_b"
        );

        builder.makeTestCase({
            .name = "FUSE root ls hides admin vaults from unprivileged user",
            .path = "fuse/ls/root",
            .must_contain = {
                listingNeedle(userVaultA),
                listingNeedle(userVaultB)
            },
            .must_not_contain = mountedVaultListingNeedlesForOwner(ctx.admin->id),
            .fn = [=]{ return ls_as(subj.uid, ctx.engine->paths->fuseRoot); }
        });

        auto stage = builder.exec();

        vh::identities::manager().mutate({.users = {subj.user->id}}, [&] {
            db::query::rbac::role::vault::Assignments::unassign(userVaultA->vault->id, "user", subj.user->id);
            db::query::rbac::role::vault::Assignments::unassign(userVaultB->vault->id, "user", subj.user->id);
        });

        return stage;
    }

    static TestStage testFUSEAllow() {
        auto builder = Builder::make({
            .name = "Permissions Allow",
            .baseDir = "perm_allow_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/allow" });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::PowerUser().name,
            .roleNameSeed = "vault_role/create/allow",
            .description = "Vault role with permissions to test allow cases",
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeTestCase({
             .name = "FUSE allow: ls seed",
             .path = "fuse/ls",
             .fn = [=]{ return ls_as(subj.uid, ctx.base()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: read secret",
            .path = "fuse/read",
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: write user_note",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(subj.uid, ctx.note(), "hey\n"); },
        });

        return builder.exec();
    }

    static TestStage testFUSEDeny() {
        auto builder = Builder::make({
            .name = "Permissions Deny",
            .baseDir = "perm_deny_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/deny" });

        const auto [ctx, subj] = builder.scenario();

        builder.makeTestCase({
            .name = "FUSE deny: ls seed",
            .path = "fuse/ls",
            .expect_exit = ENOENT,
            .fn = [=]{ return ls_as(subj.uid, ctx.base()); }
        });

        // #170: the kernel's dentry/attr cache is shared across uids, so right after the admin resolves a path the
        // denied user's ls skips LOOKUP and the daemon first sees readdir/open. Hidden must still look missing.
        builder.makeTestCase({
            .name = "FUSE deny: ls seed right after admin resolved it",
            .path = "fuse/ls",
            .expect_exit = ENOENT,
            .fn = [=]{
                (void)ls_as(*ctx.admin->state()->meta.linux_uid, ctx.base());
                return ls_as(subj.uid, ctx.base());
            }
        });

        builder.makeTestCase({
            .name = "FUSE deny: read secret",
            .path = "fuse/read",
            .expect_exit = ENOENT,
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: read secret right after admin read it",
            .path = "fuse/read",
            .expect_exit = ENOENT,
            .fn = [=]{
                (void)read_as(*ctx.admin->state()->meta.linux_uid, ctx.secret());
                return read_as(subj.uid, ctx.secret());
            }
        });

        // #183: the kernel answers stat from its dentry/attr cache, shared across uids, without asking the daemon. Any
        // non-zero entry/attr timeout let a denied uid read the metadata of a path another uid had just resolved
        // (60 s after a create).
        builder.makeTestCase({
            .name = "FUSE deny: stat secret right after admin stat'd it",
            .path = "fuse/stat",
            .expect_exit = ENOENT,
            .fn = [=]{
                (void)stat_size_as(*ctx.admin->state()->meta.linux_uid, ctx.secret());
                return stat_size_as(subj.uid, ctx.secret());
            }
        });

        builder.makeTestCase({
            .name = "FUSE deny: stat a file right after admin created it",
            .path = "fuse/stat",
            .expect_exit = ENOENT,
            .fn = [=]{
                const auto fresh = ctx.docs() / "created-by-admin.txt";
                (void)write_as(*ctx.admin->state()->meta.linux_uid, fresh, "fresh\n");
                return stat_size_as(subj.uid, fresh);
            }
        });

        builder.makeTestCase({
            .name = "FUSE deny: write hax",
            .path = "fuse/write",
            .expect_exit = ENOENT,
            .fn = [=]{ return write_as(subj.uid, ctx.docs() / "hax.txt", "nope\n"); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: chmod note",
            .path = "fuse/chmod",
            .expect_exit = ENOENT,
            .fn = [=]{ return chmod_as(subj.uid, ctx.note(), 0600); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: rm -rf seed",
            .path = "fuse/rmrf",
            .fn = [=]{ return rmrf_as(subj.uid, ctx.base()); }
        });

        return builder.exec();
    }

    static TestStage testVaultPermOverridesAllow() {
        auto builder = Builder::make({
            .name = "Vault Permission Overrides Allow",
            .baseDir = "perm_override_allow_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/override" });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::ImplicitDeny().name,
            .roleNameSeed = "vault_role/create/override",
            .description = "Vault role with override",
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeOverride({
            .subjectType = TargetSubject::User,
            .permName = "vault.fs.files.download",
            .effect = permission::OverrideOpt::ALLOW,
            .pattern = fs::model::makeAbsolute(ctx.baseDir) / "docs" / "*.txt"
        });

        builder.makeTestCase({
            .name = "FUSE override allow: read secret",
            .path = "fuse/read",
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        // note.txt matches no override and the base role grants no preview, so the user cannot see it: hidden, not
        // denied (#170). The parent stays visible through traversal toward docs/*.txt, so rm -rf below is EACCES.
        builder.makeTestCase({
            .name = "FUSE deny: read note",
            .path = "fuse/read",
            .expect_exit = ENOENT,
            .fn = [=]{ return read_as(subj.uid, ctx.note()); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: rm -rf seed",
            .path = "fuse/rmrf",
            .expect_exit = EACCES,
            .fn = [=]{ return rmrf_as(subj.uid, ctx.base()); }
        });

        return builder.exec();
    }

    static TestStage testVaultPermOverridesDeny() {
        auto builder = Builder::make({
            .name = "Vault Permission Overrides Deny",
            .baseDir = "perm_override_deny_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/override_deny" });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::PowerUser().name,
            .roleNameSeed = "vault_role/create/override_deny",
            .description = "Vault role with override",
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeOverride({
            .subjectType = TargetSubject::User,
            .permName = "vault.fs.files.download",
            .effect = permission::OverrideOpt::DENY,
            .pattern = fs::model::makeAbsolute(ctx.baseDir) / "docs" / "*.txt"
        });

        builder.makeTestCase({
            .name = "FUSE override deny: read secret",
            .path = "fuse/read",
            .expect_exit = EACCES,
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: read note",
            .path = "fuse/read",
            .fn = [=]{ return read_as(subj.uid, ctx.note()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: rm -rf seed",
            .path = "fuse/rmrf",
            .fn = [=]{ return rmrf_as(subj.uid, ctx.base()); }
        });

        return builder.exec();
    }

    // Renaming over an existing file removes it, so it needs Delete on it, as unlink does.
    static TestStage testRenameOverNeedsDelete() {
        auto builder = Builder::make({
            .name = "Rename Over Needs Delete",
            .baseDir = "rename_over_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/rename_over" });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::PowerUser().name,
            .roleNameSeed = "vault_role/create/rename_over",
            .description = "Power user who may not delete docs/*.txt",
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeOverride({
            .subjectType = TargetSubject::User,
            .permName = "vault.fs.files.delete",
            .effect = permission::OverrideOpt::DENY,
            .pattern = fs::model::makeAbsolute(ctx.baseDir) / "docs" / "*.txt"
        });

        builder.makeTestCase({
            .name = "FUSE write a temp file next to the protected one",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(subj.uid, ctx.docs() / "edit.tmp", "replaced\n"); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: rename over a file the caller may not delete",
            .path = "fuse/rename",
            .expect_exit = EACCES,
            .fn = [=]{ return mv_as(subj.uid, ctx.docs() / "edit.tmp", ctx.secret()); }
        });

        builder.makeTestCase({
            .name = "FUSE refused rename-over left the file alone",
            .path = "fuse/read",
            .must_contain = {"TOP SECRET"},
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: rename over a file the caller may delete",
            .path = "fuse/rename",
            .must_contain = {"OK mv"},
            .fn = [=]{ return mv_as(subj.uid, ctx.docs() / "edit.tmp", ctx.note()); }
        });

        builder.makeTestCase({
            .name = "FUSE allowed rename-over reads the new content",
            .path = "fuse/read",
            .must_contain = {"replaced"},
            .fn = [=]{ return read_as(subj.uid, ctx.note()); }
        });

        return builder.exec();
    }

    // #256: rename(2) authorized Rename on the source (and Delete on a replaced target) but never the destination
    // folder, so a user could move a file into a folder they may not write. Into another folder it now needs what a
    // create there needs, answered like one (EACCES for a visible folder, ENOENT for a hidden one), and a folder
    // carries its contents, each checked at its new path. A refused rename leaves everything where it was.
    static TestStage testMoveIntoUnwritableFolder() {
        auto builder = Builder::make({
            .name = "Move Into Unwritable Folder",
            .baseDir = "move_authz_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/move_authz" });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::PowerUser().name,
            .roleNameSeed = "vault_role/create/move_authz",
            .description = "Power user who may not create anything in locked/ nor upload into drop/",
        });

        const auto [ctx, subj] = builder.scenario();
        const auto adminUid = *ctx.admin->state()->meta.linux_uid;
        const auto base = fs::model::makeAbsolute(ctx.baseDir);

        for (const auto* dir : {"locked", "open", "drop", "hidden", "folder"})
            (void)mkdir_as(adminUid, ctx.base() / dir);
        (void)write_as(adminUid, ctx.base() / "folder" / "f.txt", "carried\n");

        for (const auto* perm : {"vault.fs.files.upload", "vault.fs.directories.touch"})
            for (const auto* dir : {"locked", "hidden"})
                builder.makeOverride({.subjectType = TargetSubject::User, .permName = perm,
                                      .effect = permission::OverrideOpt::DENY, .pattern = base / dir / "**"});
        builder.makeOverride({.subjectType = TargetSubject::User, .permName = "vault.fs.directories.list",
                              .effect = permission::OverrideOpt::DENY, .pattern = base / "hidden"});
        builder.makeOverride({.subjectType = TargetSubject::User, .permName = "vault.fs.files.upload",
                              .effect = permission::OverrideOpt::DENY, .pattern = base / "drop" / "**"});

        builder.makeTestCase({
            .name = "FUSE write a file to move",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(subj.uid, ctx.base() / "mine.txt", "mine\n"); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: rename into a folder the caller may not write",
            .path = "fuse/rename",
            .expect_exit = EACCES,
            .fn = [=]{ return mv_as(subj.uid, ctx.base() / "mine.txt", ctx.base() / "locked" / "mine.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE refused rename left the file where it was",
            .path = "fuse/read",
            .must_contain = {"mine"},
            .fn = [=]{ return read_as(subj.uid, ctx.base() / "mine.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE refused rename put nothing in the locked folder",
            .path = "fuse/ls",
            .must_not_contain = {"mine.txt\n"},
            .fn = [=]{ return ls_as(adminUid, ctx.base() / "locked"); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: rename into a folder the caller cannot see is ENOENT",
            .path = "fuse/rename",
            .expect_exit = ENOENT,
            .fn = [=]{ return mv_as(subj.uid, ctx.base() / "mine.txt", ctx.base() / "hidden" / "mine.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE deny: a folder carries a file into a folder without upload",
            .path = "fuse/rename",
            .expect_exit = EACCES,
            .fn = [=]{ return mv_as(subj.uid, ctx.base() / "folder", ctx.base() / "drop" / "folder"); }
        });

        builder.makeTestCase({
            .name = "FUSE refused folder rename left its content where it was",
            .path = "fuse/read",
            .must_contain = {"carried"},
            .fn = [=]{ return read_as(subj.uid, ctx.base() / "folder" / "f.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: rename within the same folder",
            .path = "fuse/rename",
            .must_contain = {"OK mv"},
            .fn = [=]{ return mv_as(subj.uid, ctx.base() / "mine.txt", ctx.base() / "mine2.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: rename into a writable folder",
            .path = "fuse/rename",
            .must_contain = {"OK mv"},
            .fn = [=]{ return mv_as(subj.uid, ctx.base() / "mine2.txt", ctx.base() / "open" / "mine.txt"); }
        });

        builder.makeTestCase({
            .name = "FUSE moved file reads back in its new folder",
            .path = "fuse/read",
            .must_contain = {"mine"},
            .fn = [=]{ return read_as(subj.uid, ctx.base() / "open" / "mine.txt"); }
        });

        return builder.exec();
    }

    static TestStage testVaultPermOverridesListFilter() {
        auto builder = Builder::make({
            .name = "Vault Permission Overrides List Filter",
            .baseDir = "perm_override_list_filter_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/override_list_filter" });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::ImplicitDeny().name,
            .roleNameSeed = "vault_role/create/override_list_filter",
            .description = "Vault role with scoped list override",
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeOverride({
            .subjectType = TargetSubject::User,
            .permName = "vault.fs.directories.list",
            .effect = permission::OverrideOpt::ALLOW,
            .pattern = fs::model::makeAbsolute(ctx.baseDir) / "docs"
        });

        builder.makeTestCase({
            .name = "FUSE override list filter: parent shows only allowed child",
            .path = "fuse/ls",
            .must_contain = {"docs\n"},
            .must_not_contain = {"note.txt\n"},
            .fn = [=]{ return ls_as(subj.uid, ctx.base()); }
        });

        return builder.exec();
    }

    // #255: fs.dir.list returned every child; FUSE readdir hides those the caller cannot Lookup (#170). Both now take
    // the same rule (rbac::fs::visibility), so for the same account and folder they list the same names: a file
    // hidden by a deny override, a folder hidden by a list deny, and a file hidden by a wildcard reaching in from
    // above (that one used to slip past the listing shortcut in readdir too).
    static TestStage testListVisibilityParity() {
        auto builder = Builder::make({
            .name = "List Visibility Parity",
            .baseDir = "list_parity_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/list_parity" });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::PowerUser().name,
            .roleNameSeed = "vault_role/create/list_parity",
            .description = "Power user with hidden entries",
        });

        const auto [ctx, subj] = builder.scenario();
        const auto adminUid = *ctx.admin->state()->meta.linux_uid;
        const auto vaultBase = "/" + ctx.baseDir;

        (void)write_as(adminUid, ctx.docs() / "open.txt", "open\n");
        (void)write_as(adminUid, ctx.docs() / "deploy.key", "key\n");
        (void)mkdir_as(adminUid, ctx.base() / "hidden_dir");
        (void)write_as(adminUid, ctx.base() / "hidden_dir" / "inner.txt", "inner\n");
        (void)mkdir_as(adminUid, ctx.base() / "shown_dir");

        const auto secret = fs::model::makeAbsolute(ctx.baseDir) / "docs" / "secret.txt";
        for (const auto* perm : {"vault.fs.files.preview", "vault.fs.files.download"}) {
            builder.makeOverride({.subjectType = TargetSubject::User, .permName = perm,
                                  .effect = permission::OverrideOpt::DENY, .pattern = secret});
            builder.makeOverride({.subjectType = TargetSubject::User, .permName = perm,
                                  .effect = permission::OverrideOpt::DENY, .pattern = "/**/*.key"});
        }
        builder.makeOverride({.subjectType = TargetSubject::User, .permName = "vault.fs.directories.list",
                              .effect = permission::OverrideOpt::DENY,
                              .pattern = fs::model::makeAbsolute(ctx.baseDir) / "hidden_dir"});

        builder.makeTestCase({
            .name = "readdir == fs.dir.list: seed folder hides the denied folder",
            .path = "fuse/ls+ws/fs.dir.list",
            .must_contain = {"PARITY\n", "docs\n", "note.txt\n", "shown_dir\n"},
            .must_not_contain = {"hidden_dir\n"},
            .fn = [=] { return listingParity(ctx.engine, subj.user, subj.uid, ctx.base(), vaultBase); }
        });

        builder.makeTestCase({
            .name = "readdir == fs.dir.list: docs hides the denied file and the wildcard-denied key",
            .path = "fuse/ls+ws/fs.dir.list",
            .must_contain = {"PARITY\n", "open.txt\n"},
            .must_not_contain = {"secret.txt\n", "deploy.key\n"},
            .fn = [=] { return listingParity(ctx.engine, subj.user, subj.uid, ctx.docs(), vaultBase + "/docs"); }
        });

        builder.makeTestCase({
            .name = "readdir == fs.dir.list: the admin sees every entry",
            .path = "fuse/ls+ws/fs.dir.list",
            .must_contain = {"PARITY\n", "open.txt\n", "secret.txt\n", "deploy.key\n"},
            .fn = [=] { return listingParity(ctx.engine, ctx.admin, adminUid, ctx.docs(), vaultBase + "/docs"); }
        });

        return builder.exec();
    }

    static TestStage testFUSEGroupPermissions() {
        auto builder = Builder::make({
            .name = "Group Permissions",
            .baseDir = "group_perm_allow_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/group_perm" });
        builder.makeGroup("group/create/group_perm");
        builder.addUserToGroup();

        builder.buildAssignVRole({
            .subjectType = TargetSubject::Group,
            .templateName = role::Vault::PowerUser().name,
            .roleNameSeed = "vault_role/create/group_perm",
            .description = "Vault role for testing group perms",
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeTestCase({
            .name = "FUSE allow: ls seed",
            .path = "fuse/ls",
            .fn = [=]{ return ls_as(subj.uid, ctx.base()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: read secret",
            .path = "fuse/read",
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: write user_note",
            .path = "fuse/write",
            .must_contain = {"OK write"},
            .fn = [=]{ return write_as(subj.uid, ctx.note(), "hey\n"); }
        });

        return builder.exec();
    }

    static TestStage testGroupPermOverrides() {
        auto builder = Builder::make({
            .name = "Group Permission Overrides",
            .baseDir = "group_perm_override_deny_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/group_override" });
        builder.makeGroup("group/create/group_override");
        builder.addUserToGroup();

        builder.buildAssignVRole({
            .subjectType = TargetSubject::Group,
            .templateName = role::Vault::PowerUser().name,
            .roleNameSeed = "vault_role/create/group_override",
            .description = "Vault role for testing group override perms",
        });

        const auto [ctx, subj] = builder.scenario();

        builder.makeOverride({
            .subjectType = TargetSubject::Group,
            .permName = "vault.fs.files.download",
            .effect = permission::OverrideOpt::DENY,
            .pattern = fs::model::makeAbsolute(ctx.baseDir) / "docs" / "*.txt"
        });

        builder.makeTestCase({
            .name = "FUSE override deny: read secret",
            .path = "fuse/read",
            .expect_exit = EACCES,
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: read note",
            .path = "fuse/read",
            .fn = [=]{ return read_as(subj.uid, ctx.note()); }
        });

        builder.makeTestCase({
            .name = "FUSE allow: rm -rf seed",
            .path = "fuse/rmrf",
            .fn = [=]{ return rmrf_as(subj.uid, ctx.base()); }
        });

        return builder.exec();
    }

    static TestStage testFUSEUserOverridesGroupOverride() {
        auto builder = Builder::make({
            .name = "User Vault Perm Override - Overrides Group Vault Perm Override",
            .baseDir = "user_override_group_override_seed"
        });

        builder.makeUser({ .userNameSeed = "user/create/override_deny" });
        builder.makeGroup("group/create/override_deny");
        builder.addUserToGroup();

        builder.buildAssignVRole({
            .subjectType = TargetSubject::Group,
            .templateName = role::Vault::ImplicitDeny().name,
            .roleNameSeed = "vault_role/create/override_deny_group",
            .description = "Vault role for testing group override perms",
        });

        builder.buildAssignVRole({
            .subjectType = TargetSubject::User,
            .templateName = role::Vault::ImplicitDeny().name,
            .roleNameSeed = "vault_role/create/override_deny_user",
            .description = "Vault role for testing user override perms",
        });

        const auto [ctx, subj] = builder.scenario();

        const auto pattern = fs::model::makeAbsolute(ctx.baseDir) / "docs" / "*.txt";

        builder.makeOverride({
            .subjectType = TargetSubject::Group,
            .permName = "vault.fs.files.download",
            .effect = permission::OverrideOpt::DENY,
            .pattern = pattern
        });

        builder.makeOverride({
            .subjectType = TargetSubject::User,
            .permName = "vault.fs.files.download",
            .effect = permission::OverrideOpt::ALLOW,
            .pattern = pattern
        });

        builder.makeTestCase({
            .name = "FUSE override user allow/group deny: read secret",
            .path = "fuse/read",
            .fn = [=]{ return read_as(subj.uid, ctx.secret()); }
        });

        // Implicit deny with no preview on note.txt: the user cannot see it, so it looks missing (#170).
        builder.makeTestCase({
            .name = "FUSE implicit deny: read note",
            .path = "fuse/read",
            .expect_exit = ENOENT,
            .fn = [=]{ return read_as(subj.uid, ctx.note()); }
        });

        builder.makeTestCase({
            .name = "FUSE implicit deny: rm -rf seed",
            .path = "fuse/rmrf",
            .expect_exit = EACCES,
            .fn = [=]{ return rmrf_as(subj.uid, ctx.base()); }
        });

        return builder.exec();
    }

    void IntegrationsTestRunner::runFUSETests() {
        struct Scenario {
            const char* name;
            TestStage (*fn)();
        };

        // One scenario's failure (a throw from setup, say) is reported as that scenario's failure; the rest still run.
        const auto run = [&](const Scenario& s) {
            TestStage stage;
            try {
                const seed::Scope scope(std::string("fuse:") + s.name);
                stage = s.fn();
            } catch (const std::exception& e) {
                auto tc = std::make_shared<TestCase>();
                tc->name = std::string(s.name) + " scenario";
                tc->path = "fuse/scenario";
                tc->result.exit_code = -1;
                tc->result.stderr_text = e.what();
                tc->fail(std::string("FUSE scenario aborted by a harness exception: ") + e.what());
                stage = TestStage{std::string("FUSE: ") + s.name + " (aborted)", {tc}};
            }
            actors().reset();
            validateStage(stage);

            for (const auto& uid : stage.uids) linux_uids_.push_back(uid);
            for (const auto& gid : stage.gids) linux_gids_.push_back(gid);

            stages_.push_back(std::move(stage));
        };

        constexpr std::array<Scenario, 2> always_run {{
            {"CRUD", testFUSECRUD},
            {"Copy And Delete", testCopyAndDelete},
        }};

        for (const auto& s : always_run) run(s);

        if (geteuid() != 0) {
            std::cout << "FUSE: not root, skipping the 13 root-only RBAC scenarios (bin/tests/run_proof.sh runs them)"
                      << std::endl;
            return;
        }

        constexpr std::array<Scenario, 13> root_only {{
            {"Root Listing Super Admin", testFUSERootListingSuperAdmin},
            {"Root Listing Unprivileged User", testFUSERootListingUnprivilegedUser},
            {"Permissions Allow", testFUSEAllow},
            {"Permissions Deny", testFUSEDeny},
            {"Vault Permission Overrides Allow", testVaultPermOverridesAllow},
            {"Vault Permission Overrides Deny", testVaultPermOverridesDeny},
            {"Rename Over Needs Delete", testRenameOverNeedsDelete},
            {"Move Into Unwritable Folder", testMoveIntoUnwritableFolder},
            {"Vault Permission Overrides List Filter", testVaultPermOverridesListFilter},
            {"List Visibility Parity", testListVisibilityParity},
            {"Group Permissions", testFUSEGroupPermissions},
            {"Group Permission Overrides", testGroupPermOverrides},
            {"User Overrides Group Override", testFUSEUserOverridesGroupOverride},
        }};

        for (const auto& s : root_only) run(s);
    }
}
