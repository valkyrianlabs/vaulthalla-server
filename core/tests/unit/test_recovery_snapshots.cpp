// Local snapshots (recovery::local::snapshots, ops::recovery::createSnapshot): what a snapshot captures (sealed
// generations by link, empty directories) and skips (symlinks, upload staging, remote content the gate refuses), the
// mode gate, dedupe, quotas, RBAC over every entry, crash cleanup, deletion and garbage collection, local version
// deletion rules, and the recovery points the dispatcher lists. DB-backed; skipped without the VH_TEST_DB_* environment.

#include "../helpers/recovery_local.hpp"
#include "../helpers/versioned_bucket.hpp"

#include "db/Transactions.hpp"
#include "fs/ops/file.hpp"
#include "ops/Error.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/RemoteFetch.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <iterator>

namespace vh::test_recovery_snapshots {

using namespace vh::test_support::recovery_local;
namespace store = vh::recovery::store;
namespace versioned = vh::test_support::versioned;

std::string slurpFile(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

class RecoverySnapshotsTest : public LocalRecoveryFixture {
protected:
    static void SetUpTestSuite() { setUpSuite("recovery_snapshots"); }
    static void TearDownTestSuite() { tearDownSuite(); }

    [[nodiscard]] nlohmann::json skippedOf(const int64_t snapshotId) const {
        return nlohmann::json::parse(rq::Snapshot::get(snapshotId)->skipped_json);
    }

    [[nodiscard]] static bool skippedHas(const nlohmann::json& skipped, const std::string& path, const std::string& reason) {
        return std::ranges::any_of(skipped, [&](const nlohmann::json& s) {
            return s.value("path", "") == path && s.value("reason", "") == reason;
        });
    }
};

TEST_F(RecoverySnapshotsTest, AFileSnapshotKeepsTheSealedGenerationAfterTheFileChanges) {
    mkdir("/docs");
    write("/docs/a.txt", "first\n");
    const auto before = file("/docs/a.txt");

    const auto created = snapshot("/docs/a.txt", "before-edit");
    EXPECT_EQ(created.file_count, 1u);
    EXPECT_EQ(created.directory_count, 0u);
    EXPECT_EQ(created.plaintext_bytes, 6u);
    const auto row = rq::Snapshot::get(created.snapshot_id);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->state, "ready");
    EXPECT_EQ(row->root_type, vh::recovery::PointKind::File);
    EXPECT_EQ(row->name, "before-edit");
    EXPECT_EQ(row->created_by_name, superUser->name());

    const auto m = member(created.snapshot_id, "/docs/a.txt");
    ASSERT_TRUE(m);
    EXPECT_EQ(m->rel_path, "a.txt");
    EXPECT_EQ(m->file_id, before->id);
    EXPECT_EQ(m->encryption_iv, before->encryption_iv) << "the sealed generation, not a re-encryption";
    EXPECT_EQ(m->key_version, before->encrypted_with_key_version);
    const auto ref = store::vaultRef(*engine->vault);
    const auto blob = store::open(ref, *m->blob_id);
    ASSERT_TRUE(blob && blob->present);
    const auto sealedBefore = slurpFile(before->backing_path);
    EXPECT_EQ(slurpFile(blob->path), sealedBefore);

    write("/docs/a.txt", "second, longer\n");
    EXPECT_EQ(plaintext("/docs/a.txt"), "second, longer\n");
    EXPECT_EQ(slurpFile(blob->path), sealedBefore) << "the retained inode is never written again";

    const auto again = snapshot("/docs/a.txt");
    EXPECT_GT(again.new_bytes, 0u) << "a changed file is a new generation";
}

TEST_F(RecoverySnapshotsTest, ADirectorySnapshotRecordsEmptyDirectoriesAndSkipsSymlinksAndStaging) {
    mkdir("/proj");
    mkdir("/proj/sub/deep");
    mkdir("/proj/empty");
    mkdir("/proj/only-link");
    write("/proj/a.txt", "alpha\n");
    write("/proj/sub/deep/c.txt", "gamma\n");
    write("/proj/zero.txt", "");
    write("/proj/.upload-http-7-big.bin.part", "partial");
    symlink("/proj/only-link/l", "../a.txt");

    const auto created = snapshot("/proj");
    EXPECT_EQ(created.file_count, 3u) << "a.txt, c.txt and the empty zero.txt";
    const auto row = rq::Snapshot::get(created.snapshot_id);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->state, "ready");
    EXPECT_EQ(row->root_type, vh::recovery::PointKind::Directory);
    EXPECT_EQ(row->file_count, 3u);
    EXPECT_EQ(row->directory_count, 5u) << "proj, sub, deep, empty, only-link";
    EXPECT_EQ(row->plaintext_bytes, 12u);
    auto empties = row->empty_directories;
    std::ranges::sort(empties);
    EXPECT_EQ(empties, (std::vector<std::string>{"/proj/empty", "/proj/only-link"}));
    const auto skipped = skippedOf(created.snapshot_id);
    EXPECT_TRUE(skippedHas(skipped, "/proj/only-link/l", "symlink")) << skipped.dump();
    EXPECT_TRUE(skippedHas(skipped, "/proj/.upload-http-7-big.bin.part", "upload_staging")) << skipped.dump();
    EXPECT_EQ(created.skipped.size(), 2u);

    const auto c = member(created.snapshot_id, "/proj/sub/deep/c.txt");
    ASSERT_TRUE(c);
    EXPECT_EQ(c->rel_path, "sub/deep/c.txt");
    const auto zero = member(created.snapshot_id, "/proj/zero.txt");
    ASSERT_TRUE(zero);
    EXPECT_EQ(zero->size_bytes, 0u);
    EXPECT_TRUE(zero->blob_id) << "an empty file is an empty blob, restorable like any other";

    const auto detail = local::points::detail(snapId(created.snapshot_id));
    ASSERT_TRUE(detail);
    EXPECT_EQ(detail->point.id, "snap-" + std::to_string(created.snapshot_id));
    EXPECT_EQ(detail->point.file_count, 3u);
    EXPECT_TRUE(detail->point.restorable);
    EXPECT_EQ(detail->members.size(), 3u);
    EXPECT_EQ(detail->skipped.size(), 2u);
    EXPECT_EQ(detail->created_by, superUser->name());
}

TEST_F(RecoverySnapshotsTest, SnapshotsNeedTheLocalSnapshotsModeAndAUniqueName) {
    write("/x.txt", "x");
    setMode(vaultId(), vh::recovery::Mode::Off);
    try {
        (void)snapshot("/x.txt");
        FAIL() << "mode off must refuse";
    } catch (const ops::Invalid& e) {
        EXPECT_NE(std::string(e.what()).find("off"), std::string::npos) << e.what();
    }
    setMode(vaultId(), vh::recovery::Mode::ProviderVersioning);
    EXPECT_THROW((void)snapshot("/x.txt"), ops::Invalid);
    EXPECT_TRUE(rq::Snapshot::listByVault(vaultId(), 10).empty()) << "nothing recorded";

    setMode(vaultId(), vh::recovery::Mode::LocalSnapshots);
    (void)snapshot("/x.txt", "daily");
    EXPECT_THROW((void)snapshot("/x.txt", "daily"), ops::Conflict);
    EXPECT_THROW((void)snapshot("/missing.txt"), ops::NotFound);
    EXPECT_THROW((void)snapshot("/x.txt", std::string(201, 'n')), ops::Invalid);
}

TEST_F(RecoverySnapshotsTest, TwoSnapshotsOfAnUnchangedFileShareOneBlob) {
    write("/same.bin", std::string(4096, 's'));
    const auto first = snapshot("/same.bin");
    const auto physical = store::physicalBytes(vaultId(), std::chrono::milliseconds(0));
    EXPECT_EQ(first.new_bytes, 4096u + 16u);
    const auto second = snapshot("/same.bin");
    EXPECT_EQ(second.new_bytes, 0u) << "the generation is already retained";
    EXPECT_EQ(store::physicalBytes(vaultId(), std::chrono::milliseconds(0)), physical);
    EXPECT_EQ(member(first.snapshot_id, "/same.bin")->blob_id, member(second.snapshot_id, "/same.bin")->blob_id);
    EXPECT_EQ(rq::Blob::usage(vaultId()).blobs, 1u);
}

TEST_F(RecoverySnapshotsTest, DeletingASnapshotCollectsOnlyBlobsNothingElseReferences) {
    write("/keep.txt", "unchanged");
    write("/edit.txt", "v1");
    const auto first = snapshot("/", "first");
    write("/edit.txt", "v2");
    const auto second = snapshot("/", "second");

    const auto keepBlob = *member(first.snapshot_id, "/keep.txt")->blob_id;
    const auto oldEditBlob = *member(first.snapshot_id, "/edit.txt")->blob_id;
    const auto newEditBlob = *member(second.snapshot_id, "/edit.txt")->blob_id;
    EXPECT_EQ(keepBlob, *member(second.snapshot_id, "/keep.txt")->blob_id);
    EXPECT_NE(oldEditBlob, newEditBlob);
    const auto ref = store::vaultRef(*engine->vault);
    const auto oldEditPath = store::open(ref, oldEditBlob)->path;

    local::snapshots::remove(first.snapshot_id);
    EXPECT_FALSE(rq::Snapshot::get(first.snapshot_id));
    EXPECT_TRUE(rq::Blob::get(keepBlob)) << "still referenced by the second snapshot";
    EXPECT_TRUE(rq::Blob::get(newEditBlob));
    EXPECT_FALSE(rq::Blob::get(oldEditBlob)) << "nothing references it any more";
    EXPECT_FALSE(std::filesystem::exists(oldEditPath));
    EXPECT_FALSE(rq::Snapshot::getByName(vaultId(), "first")) << "the name is free again";
    (void)snapshot("/", "first");

    EXPECT_THROW(local::snapshots::remove(first.snapshot_id), ops::NotFound);
}

TEST_F(RecoverySnapshotsTest, TheSnapshotQuotaAndTheVaultQuotaRefuseBeforeAnythingIsCaptured) {
    write("/big.bin", std::string(10000, 'b'));
    setMode(vaultId(), vh::recovery::Mode::LocalSnapshots, 5000);
    try {
        (void)snapshot("/big.bin");
        FAIL() << "the snapshot quota must refuse";
    } catch (const ops::Conflict& e) {
        EXPECT_NE(std::string(e.what()).find("snapshot quota"), std::string::npos) << e.what();
    }
    EXPECT_TRUE(rq::Snapshot::listByVault(vaultId(), 10).empty());
    EXPECT_EQ(rq::Blob::usage(vaultId()).blobs, 0u);

    setMode(vaultId(), vh::recovery::Mode::LocalSnapshots, 1u << 20);
    const auto quota = engine->vault->quota;
    engine->vault->quota = engine->getVaultAndCacheTotalSize() + storage::Engine::MIN_FREE_SPACE + 100;
    try {
        (void)snapshot("/big.bin");
        engine->vault->quota = quota;
        FAIL() << "the vault quota must refuse";
    } catch (const ops::Conflict& e) {
        EXPECT_NE(std::string(e.what()).find("quota"), std::string::npos) << e.what();
    }
    engine->vault->quota = quota;
    EXPECT_TRUE(rq::Snapshot::listByVault(vaultId(), 10).empty());

    const auto ok = snapshot("/big.bin");
    EXPECT_EQ(ok.file_count, 1u);
    EXPECT_GE(engine->getRecoverySize(), 10016u) << "blob bytes count against the vault quota";
}

TEST_F(RecoverySnapshotsTest, ACrashMidSnapshotIsMarkedFailedAndReleasedAtStartup) {
    write("/c.txt", "crash");
    const auto f = file("/c.txt");
    const auto ref = store::vaultRef(*engine->vault);
    // What a crash leaves: a `creating` snapshot with some members and their blobs.
    const auto id = rq::Snapshot::create({.vault_id = vaultId(), .name = "interrupted", .root_path = "/",
                                          .root_type = vh::recovery::PointKind::Directory, .root_entry_id = std::nullopt,
                                          .created_by = superUser->id, .created_by_name = superUser->name()});
    auto capture = store::captureLink(ref, f->backing_path, {.encryption_iv = f->encryption_iv,
                                                              .key_version = f->encrypted_with_key_version,
                                                              .plaintext_bytes = f->size_bytes,
                                                              .content_hash = f->content_hash});
    const auto blobId = db::Transactions::exec("test::crash", [&](pqxx::work& txn) {
        const auto b = capture.attach(txn);
        (void)rq::Generation::insertSnapshotMember(
            txn, {.vault_id = vaultId(), .file_id = f->id, .blob_id = b, .content_hash = f->content_hash,
                  .size_bytes = f->size_bytes, .mime_type = std::nullopt, .path = "/c.txt", .mode = std::nullopt,
                  .source_updated_at = std::nullopt, .created_by = std::nullopt, .snapshot_id = id, .rel_path = "c.txt",
                  .reason = std::nullopt, .upstream_state = rq::UpstreamState::None, .upstream_key = std::nullopt});
        return b;
    });
    capture.committed();

    EXPECT_THROW(local::snapshots::remove(id), ops::Conflict) << "a snapshot being taken is not deleted under it";
    EXPECT_EQ(local::snapshots::cleanupInterrupted(std::chrono::hours(1)), 0u) << "too young: maybe still running";
    EXPECT_GE(local::snapshots::cleanupInterrupted(), 1u);
    const auto row = rq::Snapshot::get(id);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->state, "failed");
    ASSERT_TRUE(row->error);
    EXPECT_NE(row->error->find("interrupted"), std::string::npos);
    EXPECT_EQ(rq::Generation::countSnapshotMembers(id), 0u);
    EXPECT_FALSE(rq::Blob::get(blobId)) << "released";
    EXPECT_EQ(plaintext("/c.txt"), "crash") << "the live file is untouched";
    local::snapshots::remove(id);
    EXPECT_FALSE(rq::Snapshot::get(id));
}

TEST_F(RecoverySnapshotsTest, TheOpAuthorizesEveryEntryAndRefusesTheWholeSnapshotOnOneDenial) {
    mkdir("/team");
    mkdir("/team/secret");
    write("/team/a.txt", "a");
    write("/team/secret/s.txt", "s");

    // A reader may list, download and copy: allowed.
    const auto reader = userWithVaultRole("reader");
    const auto ok = ops::recovery::createSnapshot(reader, vaultId(), {.path = "/team", .name = "by-reader"});
    EXPECT_EQ(ok.point.file_count, 2u);
    EXPECT_EQ(ok.members.size(), 2u);

    // A reader without copy can't take a snapshot of anything.
    const auto noCopy = userWithVaultRole("reader");
    (void)ops::roles::addVaultRoleOverrides(superUser, {
        .target = {.vault_id = vaultId(), .subject = {.type = "user", .id = noCopy->id}},
        .permissions = {.changes = {{"vault.fs.files.copy", false}}},
        .pattern = "/**"});
    EXPECT_THROW((void)ops::recovery::createSnapshot(vh::identities::manager().user(noCopy->id), vaultId(),
                                                     {.path = "/team/a.txt"}),
                 ops::Denied);

    // A download deny on one subfolder refuses the snapshot of its parent as a whole.
    const auto partial = userWithVaultRole("reader");
    (void)ops::roles::addVaultRoleOverrides(superUser, {
        .target = {.vault_id = vaultId(), .subject = {.type = "user", .id = partial->id}},
        .permissions = {.changes = {{"vault.fs.files.download", false}}},
        .pattern = "/team/secret/**"});
    const auto before = rq::Snapshot::listByVault(vaultId(), 100).size();
    EXPECT_THROW((void)ops::recovery::createSnapshot(vh::identities::manager().user(partial->id), vaultId(),
                                                     {.path = "/team", .name = "partial"}),
                 ops::Denied);
    EXPECT_EQ(rq::Snapshot::listByVault(vaultId(), 100).size(), before) << "nothing recorded";
    const auto single = ops::recovery::createSnapshot(vh::identities::manager().user(partial->id), vaultId(),
                                                      {.path = "/team/a.txt"});
    EXPECT_EQ(single.point.file_count, 1u);

    EXPECT_THROW((void)ops::recovery::createSnapshot(nullptr, vaultId(), {.path = "/team"}), ops::Denied);
}

TEST_F(RecoverySnapshotsTest, LocalVersionDeletionRefusesPendingVersionsAndSnapshotMembers) {
    write("/v.txt", "v");
    const auto f = file("/v.txt");
    const auto ref = store::vaultRef(*engine->vault);
    const auto insertVersion = [&](const rq::UpstreamState state) {
        auto capture = store::captureCopy(ref, f->backing_path, {.encryption_iv = "", .key_version = 0,
                                                                  .plaintext_bytes = f->size_bytes,
                                                                  .content_hash = f->content_hash});
        const auto id = db::Transactions::exec("test::version", [&](pqxx::work& txn) {
            const auto b = capture.attach(txn);
            return rq::Generation::insertLocalVersion(
                txn, {.vault_id = vaultId(), .file_id = f->id, .blob_id = b, .content_hash = f->content_hash,
                      .size_bytes = f->size_bytes, .mime_type = std::nullopt, .path = "/v.txt", .mode = std::nullopt,
                      .source_updated_at = std::nullopt, .created_by = std::nullopt, .snapshot_id = std::nullopt,
                      .rel_path = std::nullopt, .reason = "overwrite", .upstream_state = state,
                      .upstream_key = std::nullopt}).id;
        });
        capture.committed();
        return id;
    };

    const auto pending = insertVersion(rq::UpstreamState::Pending);
    EXPECT_THROW(local::removeVersion(pending), local::VersionPendingUpstream);
    EXPECT_TRUE(rq::Generation::get(pending));

    const auto snap = snapshot("/v.txt");
    const auto memberId = member(snap.snapshot_id, "/v.txt")->id;
    EXPECT_THROW(local::removeVersion(memberId), local::SnapshotMemberNotDeletable);

    const auto plain = insertVersion(rq::UpstreamState::None);
    const auto blob = *rq::Generation::get(plain)->blob_id;
    local::removeVersion(plain);
    EXPECT_FALSE(rq::Generation::get(plain));
    EXPECT_FALSE(rq::Blob::get(blob)) << "its blob went with it";
    EXPECT_THROW(local::removeVersion(plain), ops::NotFound);
}

TEST_F(RecoverySnapshotsTest, PointsListAFilesHistoryAfterDeletionAndTheSnapshotsOfADirectory) {
    mkdir("/hist");
    write("/hist/h.txt", "one");
    const auto first = snapshot("/hist", "one");
    write("/hist/h.txt", "two");
    const auto second = snapshot("/hist/h.txt", "two");
    remove("/hist/h.txt");
    EXPECT_FALSE(exists("/hist/h.txt"));

    const auto history = local::points::list(vaultId(), {.path = "/hist/h.txt"});
    std::vector<std::string> ids;
    for (const auto& p : history) ids.push_back(p.id);
    const auto m1 = "lv-" + std::to_string(member(first.snapshot_id, "/hist/h.txt")->id);
    const auto m2 = "lv-" + std::to_string(member(second.snapshot_id, "/hist/h.txt")->id);
    EXPECT_NE(std::ranges::find(ids, m1), ids.end());
    EXPECT_NE(std::ranges::find(ids, m2), ids.end());
    for (const auto& p : history) {
        EXPECT_TRUE(p.path.starts_with("/hist")) << p.id << " " << p.path;
        if (p.id == m1 || p.id == m2) {
            EXPECT_EQ(p.backend, vh::recovery::Backend::LocalSnapshot);
            EXPECT_TRUE(p.restorable) << p.unavailable_reason.value_or("");
            EXPECT_TRUE(p.encryption.encrypted);
            EXPECT_TRUE(p.encryption.key_available);
            EXPECT_TRUE(p.encryption.key_current);
            EXPECT_EQ(p.retention.policy, "snapshot");
        }
    }
    EXPECT_FALSE(member(first.snapshot_id, "/hist/h.txt")->file_id) << "the deleted file's id is gone (SET NULL)";

    const auto dir = local::points::list(vaultId(), {.path = "/hist", .versions = false});
    std::vector<std::string> snaps;
    for (const auto& p : dir) snaps.push_back(p.id);
    EXPECT_NE(std::ranges::find(snaps, "snap-" + std::to_string(first.snapshot_id)), snaps.end());
    EXPECT_NE(std::ranges::find(snaps, "snap-" + std::to_string(second.snapshot_id)), snaps.end());

    const auto point = local::points::get(lvId(member(first.snapshot_id, "/hist/h.txt")->id));
    ASSERT_TRUE(point);
    EXPECT_EQ(point->size_bytes, 3u);
    EXPECT_FALSE(local::points::get({.type = RecoveryId::Type::ProviderVersion, .id = 1}));
}

// A cloud file with no local copy is fetched through the metered, price-gated hydrate before it is captured; when the
// gate refuses, it is skipped (content_unavailable) and nothing is downloaded.
TEST_F(RecoverySnapshotsTest, ACloudFileWithoutALocalCopyIsHydratedOrSkippedPerTheGate) {
    auto key = std::make_shared<vault::model::APIKey>(superUser->id, "rl_key_" + tag(), vault::model::S3Provider::AWS,
                                                      "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                      "us-east-1", "https://s3.example.com");
    const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
    const auto vault = ops::vaults::create(superUser, {.name = "rl_cloud_" + tag(), .type = vault::model::VaultType::S3,
                                                       .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = "rl-" + tag()}});
    setMode(vault->id, vh::recovery::Mode::LocalSnapshots);
    const auto cloud = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(vault->id));
    ASSERT_TRUE(cloud);
    engine = cloud;
    const auto bucket = std::make_shared<versioned::VersionedBucket>();
    cloud->setS3ControllerForTesting(bucket);
    bool refuse = true;
    unsigned gateCalls = 0;
    struct Reservation final : storage::RemoteFetchReservation {
        void commit(const storage::s3::S3GatewayUpstreamUsage&) noexcept override {}
        void release() noexcept override {}
    };
    cloud->setRemoteFetchGate([&](const storage::CloudEngine&, const storage::RemoteFetchRequest&)
                                  -> std::unique_ptr<storage::RemoteFetchReservation> {
        ++gateCalls;
        if (refuse) throw storage::ContentUnavailable("price budget refused (test)");
        return std::make_unique<Reservation>();
    });

    // Objects upstream, their rows index-only (the local copies dropped, as the cache strategy leaves them).
    const auto remoteOnly = [&](const std::string& path, const std::string& content) {
        write(path, content);
        auto row = file(path);
        const auto sealed = slurpFile(row->backing_path);
        bucket->seed(path.substr(1), std::vector<uint8_t>(sealed.begin(), sealed.end()),
                     {{"vh-encrypted", "true"}, {"vh-iv", row->encryption_iv},
                      {"vh-key-version", std::to_string(row->encrypted_with_key_version)}});
        std::filesystem::remove(row->backing_path);
        return row;
    };
    const auto refusedFile = remoteOnly("/refused.txt", "the gate says no");

    const auto refused = snapshot("/refused.txt", "refused");
    EXPECT_EQ(refused.file_count, 0u);
    EXPECT_TRUE(skippedHas(skippedOf(refused.snapshot_id), "/refused.txt", "content_unavailable"));
    EXPECT_EQ(bucket->counters().body_gets, 0u) << "a refused gate downloads nothing";
    EXPECT_FALSE(std::filesystem::exists(refusedFile->backing_path));
    EXPECT_EQ(gateCalls, 1u);

    refuse = false;
    const auto f = remoteOnly("/remote.txt", "held upstream");
    const auto hydrated = snapshot("/remote.txt", "hydrated");
    EXPECT_TRUE(skippedOf(hydrated.snapshot_id).empty()) << skippedOf(hydrated.snapshot_id).dump();
    EXPECT_EQ(hydrated.file_count, 1u);
    EXPECT_EQ(bucket->counters().body_gets, 1u) << "one bounded, verified fetch";
    EXPECT_TRUE(std::filesystem::exists(f->backing_path)) << "the hydrated copy stays (as a read leaves it)";
    const auto m = member(hydrated.snapshot_id, "/remote.txt");
    ASSERT_TRUE(m);
    EXPECT_EQ(m->encryption_iv, f->encryption_iv);

    // And it restores like any local generation.
    const auto plan = local::planFor(lvId(m->id), std::nullopt, "/restored");
    ASSERT_EQ(plan.items.size(), 1u);
    EXPECT_EQ(plan.items[0].action, ItemAction::Create);
    const auto outcomes = restoreAll(plan);
    EXPECT_EQ(outcomes[0].outcome, "restored") << outcomes[0].error.value_or("");
    EXPECT_EQ(plaintext("/restored/remote.txt"), "held upstream");
}

}
