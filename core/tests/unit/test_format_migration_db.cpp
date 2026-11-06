// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The local format conversion (#372) on real vaults, keys, catalog queries and the recovery store: legacy live files
// and their snapshot/version blobs convert to VHF1 (the shared blob once, as a hard link of the converted file),
// recovery points restore afterwards, including a generation retained under a retired key, the status reports what
// is left, and nothing runs during a key rotation. The protocol itself (crash at every step, digests, no plaintext on
// disk) is FormatMigrationTest (test_format_migration.cpp, DB-free).

#include "../helpers/bytes.hpp"
#include "../helpers/recovery_local.hpp"

#include "crypto/util/encrypt.hpp"
#include "db/query/vault/FormatConversion.hpp"
#include "fs/ops/file.hpp"
#include "ops/VaultFormat.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "recovery/local/Versions.hpp"
#include "vault/Content.hpp"
#include "vault/FormatConversionService.hpp"

namespace vh::test_format_migration_db {

using namespace vh::test_support::recovery_local;
namespace content = vh::vault::content;
namespace conv = vh::vault::conversion;
namespace store = vh::recovery::store;

class FormatMigrationDbTest : public LocalRecoveryFixture {
protected:
    static void SetUpTestSuite() { setUpSuite("format_migration_db"); }
    static void TearDownTestSuite() { tearDownSuite(); }

    void makeLegacy(const std::string& path) const { makeLegacyGcm(engine, path, plaintext(path)); }

    [[nodiscard]] conv::PassResult convert() const {
        return conv::convertVault(engine, {.maxBytesPerSecond = 0, .maxCpuPercent = 100}, nullptr, nullptr);
    }

    [[nodiscard]] std::filesystem::path blobFile(const int64_t blobId) const {
        const auto row = rq::Blob::get(blobId);
        return row ? store::blobPath(store::vaultRef(*engine->vault), row->storage_name) : std::filesystem::path{};
    }

    [[nodiscard]] ops::vault_format::FormatStatus status() const {
        const auto all = ops::vault_format::status(superUser, vaultId());
        EXPECT_EQ(all.size(), 1u);
        return all.front();
    }
};

TEST_F(FormatMigrationDbTest, ALiveFileAndItsSnapshotConvertOnceAndThePointRestores) {
    const std::string body(3 * 64 * 1024 + 11, 'q');
    write("/a.bin", body);
    makeLegacy("/a.bin");
    write("/b.txt", "bravo\n");
    makeLegacy("/b.txt");
    const auto snap = snapshot("/a.bin", "before");
    const auto m = *member(snap.snapshot_id, "/a.bin");
    ASSERT_TRUE(m.blob_id);
    const auto legacyBlob = *rq::Blob::get(*m.blob_id);
    EXPECT_EQ(legacyBlob.encryption_iv, file("/a.bin")->encryption_iv) << "the snapshot links the live generation";
    EXPECT_EQ(vh::test::bin::inodeOf(blobFile(*m.blob_id)), vh::test::bin::inodeOf(file("/a.bin")->backing_path));

    const auto before = status();
    EXPECT_EQ(before.state, "pending");
    EXPECT_EQ(before.files.items, 2u);
    EXPECT_EQ(before.blobs.items, 1u);
    EXPECT_EQ(before.total.items, 3u);
    EXPECT_EQ(before.files.bytes, body.size() + 16 + 6 + 16);
    const auto keyVersion = file("/a.bin")->encrypted_with_key_version;

    const auto result = convert();
    EXPECT_EQ(result.files, 2u);
    EXPECT_EQ(result.blobs, 1u);
    EXPECT_EQ(result.failed, 0u) << (result.failures.empty() ? "" : result.failures.front().reason);

    const auto a = file("/a.bin");
    EXPECT_TRUE(content::isVhf1(a->encryption_iv));
    EXPECT_EQ(a->encrypted_with_key_version, keyVersion) << "no key is rotated";
    const auto blob = *rq::Blob::get(*m.blob_id);
    EXPECT_EQ(blob.encryption_iv, a->encryption_iv) << "converted once, with the file";
    EXPECT_EQ(blob.key_version, keyVersion);
    EXPECT_NE(blob.storage_name, legacyBlob.storage_name);
    EXPECT_EQ(vh::test::bin::inodeOf(blobFile(*m.blob_id)), vh::test::bin::inodeOf(a->backing_path)) << "still a hard link of the live file";
    EXPECT_FALSE(std::filesystem::exists(store::blobPath(store::vaultRef(*engine->vault), legacyBlob.storage_name)));
    EXPECT_FALSE(std::filesystem::exists(fs::ops::contentSidecarPath(a->backing_path)));
    EXPECT_EQ(plaintext("/a.bin"), body);
    EXPECT_EQ(plaintext("/b.txt"), "bravo\n");

    const auto after = status();
    EXPECT_EQ(after.state, "converted");
    EXPECT_EQ(after.total.items, 0u);
    EXPECT_EQ(after.total.bytes, 0u);
    ASSERT_TRUE(after.last_pass);
    EXPECT_EQ(after.last_pass->files, 2u);
    const auto json = ops::vault_format::toJson(after);
    EXPECT_EQ(json.at("remaining").at("total").at("items"), 0);

    // The point restores after the conversion.
    remove("/a.bin");
    const auto plan = local::planFor(snapId(snap.snapshot_id));
    for (const auto& o : restoreAll(plan)) EXPECT_EQ(o.outcome, "restored") << o.error.value_or("");
    EXPECT_EQ(plaintext("/a.bin"), body);

    // Nothing left: another pass touches nothing.
    const auto idle = convert();
    EXPECT_EQ(idle.files + idle.blobs + idle.failed, 0u);
}

TEST_F(FormatMigrationDbTest, LocalVersionsConvertAndRestore) {
    auto policy = rq::Policy::get(vaultId());
    policy.local_versioning = {.enabled = true, .keep_last = std::nullopt, .max_age_days = std::nullopt,
                               .quota_bytes = std::nullopt};
    rq::Policy::upsert(policy);
    vh::recovery::local::invalidatePolicy(vaultId());

    write("/v.txt", "first version\n");
    makeLegacy("/v.txt");
    write("/v.txt", "second version\n");  // keeps the legacy first generation as a local version
    const auto versions = rq::Generation::listByPath(vaultId(), "/v.txt", rq::Origin::Version, 10);
    ASSERT_EQ(versions.size(), 1u);
    ASSERT_TRUE(versions[0].encryption_iv);
    EXPECT_EQ(content::formatOf(*versions[0].encryption_iv), content::Format::Gcm0);
    EXPECT_EQ(status().blobs.items, 1u);

    const auto result = convert();
    EXPECT_EQ(result.blobs, 1u);
    EXPECT_EQ(result.failed, 0u) << (result.failures.empty() ? "" : result.failures.front().reason);
    const auto converted = rq::Generation::listByPath(vaultId(), "/v.txt", rq::Origin::Version, 10);
    ASSERT_EQ(converted.size(), 1u);
    EXPECT_TRUE(content::isVhf1(*converted[0].encryption_iv));

    const auto plan = local::planFor(lvId(converted[0].id));
    for (const auto& o : restoreAll(plan)) EXPECT_EQ(o.outcome, "restored") << o.error.value_or("");
    EXPECT_EQ(plaintext("/v.txt"), "first version\n");
    EXPECT_EQ(status().state, "converted");
}

TEST_F(FormatMigrationDbTest, AGenerationUnderARetiredKeyConvertsUnderItsOwnVersionAndRestores) {
    write("/k.txt", "sealed under the first key, in the legacy format");
    makeLegacy("/k.txt");
    const auto snap = snapshot("/k.txt");
    const auto m = *member(snap.snapshot_id, "/k.txt");
    const auto em = engine->encryptionManager;
    const auto first = em->get_key_version();
    remove("/k.txt");

    em->prepare_key_rotation();
    em->finish_key_rotation();
    ASSERT_GT(em->get_key_version(), first);
    ASSERT_TRUE(em->hasKeyVersion(first));

    const auto result = convert();
    EXPECT_EQ(result.blobs, 1u);
    EXPECT_EQ(result.failed, 0u) << (result.failures.empty() ? "" : result.failures.front().reason);
    const auto blob = *rq::Blob::get(*m.blob_id);
    EXPECT_TRUE(content::isVhf1(blob.encryption_iv));
    EXPECT_EQ(blob.key_version, first) << "re-sealed under the retired version it was sealed with";

    const auto plan = local::planFor(snapId(snap.snapshot_id));
    for (const auto& o : restoreAll(plan)) EXPECT_EQ(o.outcome, "restored") << o.error.value_or("");
    EXPECT_EQ(plaintext("/k.txt"), "sealed under the first key, in the legacy format");
    EXPECT_EQ(file("/k.txt")->encrypted_with_key_version, em->get_key_version());
}

TEST_F(FormatMigrationDbTest, NothingConvertsWhileAKeyRotationIsInProgress) {
    write("/r.txt", "rotating");
    makeLegacy("/r.txt");
    const auto iv = file("/r.txt")->encryption_iv;
    engine->encryptionManager->prepare_key_rotation();

    const auto result = convert();
    EXPECT_TRUE(result.blocked);
    EXPECT_EQ(result.files + result.blobs, 0u);
    EXPECT_EQ(file("/r.txt")->encryption_iv, iv);
    const auto s = status();
    EXPECT_EQ(s.state, "blocked");
    EXPECT_TRUE(s.blocked_reason);
}

TEST_F(FormatMigrationDbTest, TheCliReportsRemainingItemsAndBytesAndRefusesOthers) {
    write("/c.txt", "cli");
    makeLegacy("/c.txt");
    const auto router = std::make_shared<protocols::shell::Router>();
    protocols::shell::commands::vault::registerCommands(router);

    const auto id = std::to_string(vaultId());
    const auto json = router->executeLine("vault format status " + id + " --json", superUser, nullptr);
    ASSERT_EQ(json.exit_code, 0) << json.stderr_text;
    const auto doc = nlohmann::json::parse(json.stdout_text);
    ASSERT_EQ(doc.at("vaults").size(), 1u);
    const auto& v = doc.at("vaults").at(0);
    EXPECT_EQ(v.at("vault_id"), vaultId());
    EXPECT_EQ(v.at("state"), "pending");
    EXPECT_EQ(v.at("remaining").at("files").at("items"), 1);
    EXPECT_EQ(v.at("remaining").at("files").at("bytes"), 3 + 16);
    EXPECT_TRUE(v.at("limits").contains("max_mib_per_second"));

    const auto text = router->executeLine("vault format status all", superUser, nullptr);
    ASSERT_EQ(text.exit_code, 0) << text.stderr_text;
    EXPECT_NE(text.stdout_text.find("vault " + id), std::string::npos) << text.stdout_text;
    EXPECT_NE(text.stdout_text.find("remaining:"), std::string::npos);

    const auto other = userWithVaultRole("power_user");
    const auto refused = router->executeLine("vault format status " + id, other, nullptr);
    EXPECT_NE(refused.exit_code, 0);
    EXPECT_NE(refused.stderr_text.find("view encryption keys"), std::string::npos) << refused.stderr_text;
}

}
