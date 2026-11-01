// Sync conflict resolution (#187), against the test DB and an in-memory bucket (fake S3 controller):
//  - under `ask`, a file changed on both sides is recorded once (one open row, however many passes) and skipped,
//    while a file changed on one side syncs in that direction;
//  - an open conflict closes itself ('converged') when both sides become equal again;
//  - keep_local uploads the local copy, keep_remote downloads (and decrypts/re-seals) the remote one;
//  - a decision about a side that changed since it was recorded is refused and the conflict stays open;
//  - RBAC: no permission, permission without filesystem Overwrite, an admin through vault globals;
//  - vault roles (the member's own or a group's) grant sync permissions through the shared resolver (#189);
//  - keep_remote / keep_newest do not download a file again once it is in sync (#190).

#include "../helpers/sync_conflict_harness.hpp"

#include "protocols/http/Access.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/http/handler/Handlers.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "ops/Groups.hpp"
#include "rbac/permission/vault/sync/Config.hpp"
#include "rbac/resolver/vault/all.hpp"

namespace vh::test_sync_conflicts {

using namespace test_support::sync_conflicts;
using Decision = sync::ConflictDecision;
using ActionType = sync::model::ActionType;

class SyncConflictsTest : public Harness {};

// Detection itself: no DB, the decision table that keeps one-sided changes out of `ask`.
TEST(SyncConflictBaseline, OnlyTwoSidedChangesAreConflicts) {
    fs::model::File local, remote;
    local.id = 7;
    local.size_bytes = remote.size_bytes = 4;
    local.content_hash = remote.content_hash = "h0";
    const auto base = sync::model::Baseline::agreed(local, remote);
    using sync::model::Divergence;
    EXPECT_EQ(sync::model::classify(local, remote, &base), Divergence::InSync);
    EXPECT_EQ(sync::model::classify(local, remote, nullptr), Divergence::Unknown);

    local.content_hash = "h1";
    EXPECT_EQ(sync::model::classify(local, remote, &base), Divergence::LocalOnly);
    remote.content_hash = "h2";
    EXPECT_EQ(sync::model::classify(local, remote, &base), Divergence::Both);
    local.content_hash = "h0";
    EXPECT_EQ(sync::model::classify(local, remote, &base), Divergence::RemoteOnly);

    // A hashless index row (LIST / inventory / events): ETag, then size, as recorded at the last agreement. Its size
    // is the stored (ciphertext) size, which never equals the plaintext size: that alone is not a change.
    fs::model::File listed;
    listed.size_bytes = 20;
    listed.remote_etag = "\"e1\"";
    const auto afterDownload = sync::model::Baseline::afterDownload(local, listed);
    EXPECT_EQ(sync::model::classify(local, listed, &afterDownload), Divergence::InSync);
    listed.remote_etag = "\"e2\"";
    EXPECT_EQ(sync::model::classify(local, listed, &afterDownload), Divergence::RemoteOnly);
}

TEST_F(SyncConflictsTest, AskRecordsATwoSidedConflictOnceAndKeepsSyncingTheRest) {
    const auto f = remoteVault(superUser);
    write(f, "/both.txt", "base");
    write(f, "/local-only.txt", "base");
    write(f, "/remote-only.txt", "base");
    const auto first = pass(f);
    EXPECT_EQ(planned(first, ActionType::Upload, "/both.txt"), 1u);

    write(f, "/both.txt", "local edit");
    remoteWrite(f, "/both.txt", "remote edit");
    write(f, "/local-only.txt", "local edit");
    remoteWrite(f, "/remote-only.txt", "remote edit");

    const auto second = pass(f);
    EXPECT_EQ(planned(second, ActionType::Upload, "/both.txt") + planned(second, ActionType::Download, "/both.txt"), 0u)
        << "a conflicted file waits for a decision";
    EXPECT_EQ(planned(second, ActionType::Upload, "/local-only.txt"), 1u) << "a local-only change is not a conflict";
    EXPECT_EQ(planned(second, ActionType::Download, "/remote-only.txt"), 1u) << "a remote-only change is not a conflict";
    EXPECT_FALSE(openFor(f, "/local-only.txt"));
    EXPECT_FALSE(openFor(f, "/remote-only.txt"));
    EXPECT_EQ(readLocal(f, "/remote-only.txt"), "remote edit");

    const auto c = openFor(f, "/both.txt");
    ASSERT_TRUE(c);
    EXPECT_EQ(c->local.size_bytes, std::string("local edit").size());
    EXPECT_EQ(c->remote.size_bytes, std::string("remote edit").size());
    EXPECT_EQ(c->remote.content_hash, std::optional<std::string>("remote-remote edit"));
    EXPECT_TRUE(c->remote.etag.has_value());
    EXPECT_EQ(c->remote.encrypted, std::optional<bool>(true));
    EXPECT_FALSE(c->reasons.empty());

    (void)pass(f);
    (void)pass(f);
    EXPECT_EQ(openRows(c->file_id), 1u) << "one open row however many passes see it";
    EXPECT_EQ(openFor(f, "/both.txt")->id, c->id);

    const auto summary = ops::conflicts::summary(superUser);
    EXPECT_GE(summary.total, 1u);
    EXPECT_TRUE(std::ranges::any_of(summary.vaults, [&](const auto& v) { return v.vault_id == f.vault->id && v.count == 1; }));
}

TEST_F(SyncConflictsTest, AnOpenConflictClosesItselfWhenBothSidesConverge) {
    const auto f = remoteVault(superUser);
    const auto c = conflicted(f, "/converge.txt");
    // The local side is brought to exactly what the remote holds (same content hash as the index row).
    const auto local = db::query::fs::File::getFileByPath(f.vault->id, "/converge.txt");
    write(f, "/converge.txt", "remote edit");
    db::Transactions::exec("SyncConflictsTest::sameHash", [&](pqxx::work& txn) {
        txn.exec("UPDATE files SET content_hash = 'remote-remote edit' WHERE fs_entry_id = $1", pqxx::params{local->id});
        // Converged means the same content at the same time: the remote index row takes the local file's exact
        // updated_at. Not the other way round: fs_entry's BEFORE UPDATE trigger (set_updated_at) stamps
        // CURRENT_TIMESTAMP over any value written to it, so pinning the local side did nothing, and whenever the local
        // write landed in a later second than remoteWrite the pass saw a "newer" local file and planned an upload
        // (#265, once in ~1500 runs).
        const auto pinned = txn.exec("UPDATE remote_object_index SET last_modified = "
                                     "(SELECT updated_at FROM fs_entry WHERE id = $1) "
                                     "WHERE vault_id = $2 AND object_key = 'converge.txt'",
                                     pqxx::params{local->id, f.vault->id});
        ASSERT_EQ(pinned.affected_rows(), 1u);
    });
    const auto plan = pass(f);
    EXPECT_EQ(planned(plan, ActionType::Upload, "/converge.txt") + planned(plan, ActionType::Download, "/converge.txt"), 0u);
    EXPECT_EQ(resolutionOf(c.id), "converged");
    EXPECT_EQ(openRows(c.file_id), 0u);
}

TEST_F(SyncConflictsTest, KeepLocalUploadsTheLocalCopy) {
    const auto f = remoteVault(superUser);
    const auto c = conflicted(f, "/keep-local.txt");
    const auto putsBefore = f.bucket->puts();

    const auto result = ops::conflicts::resolve(superUser, Decision::KeepLocal, {c.id});
    ASSERT_EQ(result.results.size(), 1u);
    EXPECT_TRUE(result.results[0].ok) << result.results[0].status << ": " << result.results[0].message.value_or("");
    EXPECT_EQ(resolutionOf(c.id), "kept_local");
    EXPECT_GT(f.bucket->puts(), putsBefore);

    const auto local = db::query::fs::File::getFileByPath(f.vault->id, "/keep-local.txt");
    const auto object = f.bucket->get("keep-local.txt");
    ASSERT_TRUE(object);
    EXPECT_EQ(object->meta.at("x-amz-meta-vh-iv"), local->encryption_iv) << "the bucket now holds the local ciphertext";
    EXPECT_EQ(readLocal(f, "/keep-local.txt"), "local edit");

    const auto after = pass(f);
    EXPECT_EQ(planned(after, ActionType::Upload, "/keep-local.txt") + planned(after, ActionType::Download, "/keep-local.txt"), 0u);
    EXPECT_FALSE(openFor(f, "/keep-local.txt")) << "resolved: no new conflict on the next pass";
}

TEST_F(SyncConflictsTest, KeepRemoteDownloadsAndReseals) {
    const auto f = remoteVault(superUser);
    const auto c = conflicted(f, "/keep-remote.txt");

    const auto result = ops::conflicts::resolve(superUser, Decision::KeepRemote, {c.id});
    ASSERT_EQ(result.results.size(), 1u);
    EXPECT_TRUE(result.results[0].ok) << result.results[0].status << ": " << result.results[0].message.value_or("");
    EXPECT_EQ(resolutionOf(c.id), "kept_remote");
    EXPECT_EQ(readLocal(f, "/keep-remote.txt"), "remote edit");

    // Ciphertext at rest, never the plaintext.
    const auto local = db::query::fs::File::getFileByPath(f.vault->id, "/keep-remote.txt");
    std::ifstream in(local->backing_path, std::ios::binary);
    const std::string onDisk((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(onDisk.find("remote edit"), std::string::npos);

    const auto after = pass(f);
    EXPECT_EQ(planned(after, ActionType::Upload, "/keep-remote.txt") + planned(after, ActionType::Download, "/keep-remote.txt"), 0u);
    EXPECT_FALSE(openFor(f, "/keep-remote.txt"));
}

TEST_F(SyncConflictsTest, AStaleDecisionIsRefusedAndTheConflictStaysOpen) {
    const auto f = remoteVault(superUser);
    const auto c = conflicted(f, "/stale-local.txt");
    write(f, "/stale-local.txt", "an even newer local edit");  // after the conflict was recorded
    auto result = ops::conflicts::resolve(superUser, Decision::KeepRemote, {c.id});
    ASSERT_EQ(result.results.size(), 1u);
    EXPECT_FALSE(result.results[0].ok);
    EXPECT_EQ(result.results[0].status, "conflict");
    EXPECT_EQ(resolutionOf(c.id), "unresolved");
    EXPECT_EQ(readLocal(f, "/stale-local.txt"), "an even newer local edit") << "the newer change was not clobbered";

    const auto r = conflicted(f, "/stale-remote.txt");
    const auto newer = f.bucket->get("stale-remote.txt");
    f.bucket->put("stale-remote.txt", newer->body, {});  // the bucket moved on: new ETag
    result = ops::conflicts::resolve(superUser, Decision::KeepLocal, {r.id});
    EXPECT_EQ(result.results[0].status, "conflict");
    EXPECT_EQ(resolutionOf(r.id), "unresolved");

    // A closed conflict is a conflict too, and a batch carries on past failures.
    const auto ok = conflicted(f, "/batch.txt");
    result = ops::conflicts::resolve(superUser, Decision::KeepLocal, {r.id, ok.id, 999999u, ok.id});
    ASSERT_EQ(result.results.size(), 3u) << "duplicates are ignored";
    EXPECT_EQ(result.results[0].status, "conflict");
    EXPECT_EQ(result.results[1].status, "resolved");
    EXPECT_EQ(result.results[2].status, "not_found");
    EXPECT_EQ(result.resolved, 1u);
    EXPECT_EQ(result.failed, 2u);
    result = ops::conflicts::resolve(superUser, Decision::KeepLocal, {ok.id});
    EXPECT_EQ(result.results[0].status, "conflict") << "already closed";
}

TEST_F(SyncConflictsTest, ResolutionNeedsThePermissionAndOverwrite) {
    const auto owner = createUser("sc_owner", "unprivileged");
    const auto f = remoteVault(owner);
    const auto c = conflicted(f, "/rbac.txt");

    // No vault role at all: nothing to see, nothing to resolve.
    const auto stranger = createUser("sc_stranger", "unprivileged");
    EXPECT_EQ(ops::conflicts::summary(stranger).total, 0u);
    EXPECT_TRUE(ops::conflicts::list(stranger).empty());
    EXPECT_THROW((void)ops::conflicts::list(stranger, f.vault->id), ops::Denied);
    EXPECT_EQ(ops::conflicts::resolve(stranger, Decision::KeepLocal, {c.id}).results[0].status, "denied");
    EXPECT_THROW((void)ops::conflicts::previewTarget(stranger, c.id), ops::Denied);

    // The permission without filesystem Overwrite: sees it, cannot resolve it.
    auto readerBase = rbac::role::vault::Base::Reader();
    readerBase.sync.action.grant(rbac::permission::vault::sync::SyncActionPermissions::ResolveConflicts);
    const auto viewer = assign(createUser("sc_viewer", "unprivileged"), f.vault->id,
                               vaultRole("sc_resolve_no_overwrite_" + tag(), readerBase));
    EXPECT_EQ(ops::conflicts::summary(viewer).total, 1u);
    const auto seen = ops::conflicts::list(viewer, f.vault->id);
    ASSERT_EQ(seen.size(), 1u);
    EXPECT_FALSE(seen[0].can_overwrite);
    EXPECT_EQ(ops::conflicts::resolve(viewer, Decision::KeepLocal, {c.id}).results[0].status, "denied");
    EXPECT_EQ(resolutionOf(c.id), "unresolved");

    // Overwrite without the permission (a role that edits files but has no sync rights): denied too.
    auto editorNoSync = rbac::role::vault::Base::Editor();
    editorNoSync.sync = rbac::permission::vault::Sync::None();
    const auto editor = assign(createUser("sc_editor", "unprivileged"), f.vault->id,
                               vaultRole("sc_overwrite_no_resolve_" + tag(), editorNoSync));
    EXPECT_EQ(ops::conflicts::summary(editor).total, 0u);
    EXPECT_EQ(ops::conflicts::resolve(editor, Decision::KeepLocal, {c.id}).results[0].status, "denied");

    // An admin through vault globals (platform_operator: PowerUser in every scope) resolves it.
    const auto admin = createUser("sc_platform", "platform_operator");
    EXPECT_TRUE(ops::conflicts::canResolveIn(admin, f.vault->id));
    const auto listed = ops::conflicts::list(admin, f.vault->id);
    ASSERT_EQ(listed.size(), 1u);
    EXPECT_TRUE(listed[0].can_overwrite);
    const auto result = ops::conflicts::resolve(admin, Decision::KeepLocal, {c.id});
    EXPECT_TRUE(result.results[0].ok) << result.results[0].status << ": " << result.results[0].message.value_or("");

    // An auditor's vault globals are Reader: no resolve.
    const auto auditor = createUser("sc_auditor", "auditor");
    EXPECT_FALSE(ops::conflicts::canResolveIn(auditor, f.vault->id));
}

TEST_F(SyncConflictsTest, KeepPoliciesStillResolveAutomaticallyAndCloseAnOpenConflict) {
    const auto f = remoteVault(superUser);
    const auto c = conflicted(f, "/policy.txt");
    f.engine->remote_policy()->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::KeepLocal;
    const auto plan = pass(f);
    EXPECT_EQ(planned(plan, ActionType::Upload, "/policy.txt"), 1u);
    EXPECT_EQ(resolutionOf(c.id), "kept_local") << "the policy decided; the open row is closed with its decision";

    // keep_local still treats any content difference as its conflict to resolve (unchanged behaviour).
    write(f, "/policy.txt", "only local changed");
    const auto again = pass(f);
    EXPECT_EQ(planned(again, ActionType::Upload, "/policy.txt"), 1u);
    EXPECT_FALSE(openFor(f, "/policy.txt"));
}

// #189: the shared vault resolver honours vault-role sync bits, so every path that checks them (sync trigger, sync
// settings, conflict resolution) agrees. A role's bits only add to what the vault globals grant.
TEST_F(SyncConflictsTest, VaultRoleSyncPermissionsAreHonouredByTheResolver) {
    using ActionPerm = rbac::permission::vault::sync::SyncActionPermissions;
    using ConfigPerm = rbac::permission::vault::sync::SyncConfigPermissions;
    const auto owner = createUser("sr_owner", "unprivileged");
    const auto f = remoteVault(owner);
    const auto vaultId = f.vault->id;
    const auto can = [&](const UserPtr& u, const ActionPerm p) {
        return rbac::resolver::Vault::has<ActionPerm>({.user = u, .permission = p, .vault_id = vaultId});
    };
    const auto canConfig = [&](const UserPtr& u, const ConfigPerm p) {
        return rbac::resolver::Vault::has<ConfigPerm>({.user = u, .permission = p, .vault_id = vaultId});
    };

    // Contributor: trigger + resolve, view-only settings, no waiver.
    const auto contributor = assign(createUser("sr_contrib", "unprivileged"), vaultId,
                                    vaultRole("sr_contributor_" + tag(), rbac::role::vault::Base::Contributor()));
    EXPECT_TRUE(can(contributor, ActionPerm::Trigger));
    EXPECT_TRUE(can(contributor, ActionPerm::ResolveConflicts));
    EXPECT_TRUE(ops::conflicts::canResolveIn(contributor, vaultId));
    EXPECT_FALSE(can(contributor, ActionPerm::SignWaiver));
    EXPECT_TRUE(canConfig(contributor, ConfigPerm::View));
    EXPECT_FALSE(canConfig(contributor, ConfigPerm::Edit));
    EXPECT_THROW((void)ops::vaults::updateSync(contributor, vaultId, {.interval = std::chrono::seconds(900)}), ops::Denied);

    // A reader's role has no sync actions: no trigger, through the resolver or the operation.
    const auto reader = assign(createUser("sr_reader", "unprivileged"), vaultId,
                               vaultRole("sr_reader_" + tag(), rbac::role::vault::Base::Reader()));
    EXPECT_FALSE(can(reader, ActionPerm::Trigger));
    EXPECT_THROW((void)ops::vaults::triggerSync(reader, vaultId), ops::Denied);
    EXPECT_FALSE(ops::conflicts::canResolveIn(reader, vaultId));

    // No role on the vault at all.
    const auto stranger = createUser("sr_stranger", "unprivileged");
    EXPECT_FALSE(can(stranger, ActionPerm::Trigger));
    EXPECT_THROW((void)ops::vaults::triggerSync(stranger, vaultId), ops::Denied);

    // Through a group: a manager role edits sync settings for every member, and leaving the group takes it away.
    const auto member = createUser("sr_member", "unprivileged");
    const auto group = ops::groups::create(superUser, {.name = "sr_group_" + tag()});
    (void)ops::groups::addMember(superUser, {.group = group->id, .user = member->id});
    assignGroup(group->id, vaultId, vaultRole("sr_manager_" + tag(), rbac::role::vault::Base::Manager()));
    EXPECT_TRUE(can(member, ActionPerm::Trigger));
    EXPECT_TRUE(canConfig(member, ConfigPerm::Edit));
    const auto policy = ops::vaults::updateSync(member, vaultId, {.interval = std::chrono::seconds(900)});
    ASSERT_TRUE(policy);
    EXPECT_EQ(policy->interval, std::chrono::seconds(900));
    (void)ops::groups::removeMember(superUser, {.group = group->id, .user = member->id});
    EXPECT_FALSE(can(member, ActionPerm::Trigger));
    EXPECT_FALSE(canConfig(member, ConfigPerm::Edit));

    // A deactivated member keeps the assignment row but authorizes nothing.
    (void)ops::users::update(superUser, {.id = contributor->id, .is_active = false});
    EXPECT_FALSE(can(contributor, ActionPerm::Trigger));
}

// #190: under keep_remote / keep_newest a file this vault downloaded used to be downloaded again on every pass (its
// local hash is of the re-sealed bytes, never the object's). The per-file baseline says neither side changed.
TEST_F(SyncConflictsTest, KeepPoliciesDoNotDownloadAnUnchangedFileAgain) {
    for (const auto policy : {sync::model::RemotePolicy::ConflictPolicy::KeepRemote,
                              sync::model::RemotePolicy::ConflictPolicy::KeepNewest}) {
        SCOPED_TRACE(sync::model::to_string(policy));
        const auto f = remoteVault(superUser, policy);
        remoteWrite(f, "/fetched.txt", "written by another client");
        const auto first = pass(f);
        ASSERT_EQ(planned(first, ActionType::Download, "/fetched.txt"), 1u);
        EXPECT_EQ(readLocal(f, "/fetched.txt"), "written by another client");

        for (int i = 0; i < 2; ++i) {
            const auto again = pass(f);
            EXPECT_EQ(planned(again, ActionType::Download, "/fetched.txt"), 0u) << "pass " << i + 2;
            EXPECT_EQ(planned(again, ActionType::Upload, "/fetched.txt"), 0u) << "pass " << i + 2;
        }

        // A real change still syncs: the remote object changes, the next pass fetches it once.
        remoteWrite(f, "/fetched.txt", "changed again upstream");
        EXPECT_EQ(planned(pass(f), ActionType::Download, "/fetched.txt"), 1u);
        EXPECT_EQ(readLocal(f, "/fetched.txt"), "changed again upstream");
        EXPECT_EQ(planned(pass(f), ActionType::Download, "/fetched.txt"), 0u);
    }
}

namespace http_lane {

using namespace protocols::http;
using Response = model::preview::Response;
using StreamResponse = model::preview::StreamResponse;

request get(const std::string& target, const verb method = verb::get) {
    request req{method, target, 11};
    req.keep_alive(true);
    return req;
}

status statusOf(const Response& r) {
    return std::visit([](const auto& res) { return res.result(); }, r);
}

std::string header(const Response& r, const std::string& name) {
    return std::visit([&](const auto& res) -> std::string {
        const auto it = res.find(name);
        return it == res.end() ? std::string{} : std::string(it->value());
    }, r);
}

std::string bodyOf(const Response& r) {
    if (const auto* s = std::get_if<string_response>(&r)) return s->body();
    if (const auto* st = std::get_if<StreamResponse>(&r)) {
        if (!st->reader || st->headOnly) return {};
        std::string out(static_cast<std::size_t>(st->length), '\0');
        std::size_t done = 0;
        while (done < out.size()) {
            const auto n = st->reader->read(st->offset + done, std::span(reinterpret_cast<uint8_t*>(out.data()) + done,
                                                                          out.size() - done));
            if (n == 0) break;
            done += n;
        }
        out.resize(done);
        return out;
    }
    return {};
}

void as(const UserPtr& user) {
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->user = user;
    Router::setPreviewSessionResolverForTesting([session](const request&) { return session; });
    access::clearCachesForTesting();
}

}

// GET|HEAD /download/conflict: both sides of an open conflict for someone who may resolve it; the remote side is
// fetched from the bucket (decrypted, not stored), HEAD never contacts the bucket, closed conflicts are 409, and a
// caller without the permission gets 403.
TEST_F(SyncConflictsTest, PreviewLaneServesBothSidesToResolversOnly) {
    using namespace http_lane;
    const auto f = remoteVault(superUser);
    const auto c = conflicted(f, "/preview.txt");
    const auto target = [&](const std::string& side) {
        return "/download/conflict?conflict_id=" + std::to_string(c.id) + "&side=" + side;
    };

    as(superUser);
    const auto local = Router::route(get(target("local")));
    EXPECT_EQ(statusOf(local), status::ok);
    EXPECT_EQ(bodyOf(local), "local edit");
    EXPECT_EQ(header(local, "X-Vaulthalla-Conflict-Side"), "local");
    EXPECT_EQ(header(local, "X-Content-Type-Options"), "nosniff");

    const auto remote = Router::route(get(target("remote")));
    EXPECT_EQ(statusOf(remote), status::ok);
    EXPECT_EQ(bodyOf(remote), "remote edit") << "decrypted with the object's own metadata";
    EXPECT_EQ(header(remote, "X-Vaulthalla-Conflict-Side"), "remote");
    EXPECT_EQ(header(remote, "Cache-Control"), "no-store");

    const auto head = Router::route(get(target("remote"), verb::head));
    EXPECT_EQ(statusOf(head), status::ok);
    EXPECT_EQ(header(head, "Content-Length"), std::to_string(std::string("remote edit").size()));

    EXPECT_EQ(statusOf(Router::route(get(target("sideways")))), status::bad_request);
    EXPECT_EQ(statusOf(Router::route(get("/download/conflict?conflict_id=999999&side=local"))), status::not_found);

    const auto stranger = createUser("sc_http_stranger", "unprivileged");
    as(stranger);
    EXPECT_EQ(statusOf(Router::route(get(target("remote")))), status::forbidden);
    EXPECT_EQ(statusOf(Router::route(get(target("local")))), status::forbidden);

    as(superUser);
    (void)ops::conflicts::resolve(superUser, Decision::KeepLocal, {c.id});
    EXPECT_EQ(statusOf(Router::route(get(target("local")))), status::conflict) << "closed conflicts have no sides";
    Router::resetPreviewSessionResolverForTesting();
}

}
