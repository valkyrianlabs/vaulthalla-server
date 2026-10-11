#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Cache.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "preview/cache/Maintenance.hpp"
#include "preview/cache/Store.hpp"
#include "preview/derive/Queue.hpp"
#include "preview/derive/Runner.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/GcmFileReader.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <thread>

namespace vh::preview::derive::test_queue {

namespace {

std::string tag() {
    return std::to_string(::getpid()) + "_" +
           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1'000'000'000);
}

std::vector<uint8_t> bytesOf(const std::string& s) { return {s.begin(), s.end()}; }

std::string stringOf(const std::vector<uint8_t>& v) { return {v.begin(), v.end()}; }

std::vector<uint8_t> fileBytes(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

}

class DeriveQueueDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> admin;
    inline static std::filesystem::path root;

    std::shared_ptr<storage::Engine> engine;
    config::Config original;
    std::filesystem::path fakeHelpers, noHelpers;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_derive_queue_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        admin = vh::identities::manager().userByName("admin");
    }

    static void TearDownTestSuite() {
        Queue::instance().shutdown();
        std::error_code ec;
        if (!root.empty()) std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        original = config::Registry::get();
        Queue::instance().shutdown();

        // Both helper names point at the protocol-speaking fake (see core/tests/helpers/fake_derive_helper.cpp).
        fakeHelpers = root / ("helpers_" + tag());
        noHelpers = root / ("nohelpers_" + tag());
        std::filesystem::create_directories(fakeHelpers);
        std::filesystem::create_directories(noHelpers);
        std::filesystem::create_symlink(VH_TEST_FAKE_HELPER, fakeHelpers / std::string(kCadHelper));
        std::filesystem::create_symlink(VH_TEST_FAKE_HELPER, fakeHelpers / std::string(kMediaHelper));
        configure([this](config::Config& c) {
            c.preview.derive.helper_dir = fakeHelpers;
            c.preview.derive.max_concurrency = 2;
            c.preview.derive.max_queue = 64;
            c.preview.derive.wall_timeout_seconds = 60;
            c.preview.media.transcode = config::PreviewTranscodeMode::OnDemand;
            c.preview.media.hwaccel = config::PreviewHwaccel::Software;
        });

        const auto vault = ops::vaults::create(admin, {.name = "dq_" + tag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
    }

    void TearDown() override {
        if (skipTests) return;
        Queue::instance().shutdown();
        config::Registry::set(original);
    }

    template<class F>
    static void configure(F&& change) {
        auto c = config::Registry::get();
        change(c);
        config::Registry::set(c);
    }

    std::shared_ptr<fs::model::File> write(const std::string& path, const std::string& content, const bool overwrite = false) {
        return fs::Filesystem::createFile({.path = path,
                                           .fuse_path = engine->vaultPathToFusePath(path),
                                           .buffer = bytesOf(content),
                                           .engine = engine,
                                           .user = admin,
                                           .overwrite = overwrite});
    }

    [[nodiscard]] cache::ArtifactKey keyFor(const fs::model::File& file, const std::string& kind) const {
        return {.vault_id = engine->vault->id, .file_id = file.id, .kind = kind, .variant = "v1",
                .source_id = storage::generationOf(file).sourceId(), .generator_version = generatorVersion(kind)};
    }

    // Polls until the job settles (anything but Queued).
    DeriveResult settle(const std::shared_ptr<fs::model::File>& file, const std::string& kind,
                        const std::chrono::seconds timeout = std::chrono::seconds(30)) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        DeriveResult r;
        do {
            r = Queue::instance().request(engine, file, kind);
            if (r.status != DeriveStatus::Queued) return r;
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        } while (std::chrono::steady_clock::now() < deadline);
        return r;
    }

    static bool waitFor(const std::function<bool()>& predicate, const std::chrono::seconds timeout = std::chrono::seconds(15)) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (predicate()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return predicate();
    }

    std::string artifactText(const cache::Artifact& artifact) const {
        const auto reader = cache::Store::open(engine, artifact);
        return stringOf(storage::readAll(*reader, 64u << 20));
    }
};

TEST(DeriveKinds, OneTableMapsKindsToHelpersAndVersions) {
    EXPECT_TRUE(kindKnown("model-glb"));
    EXPECT_TRUE(kindKnown("transcode-h264-1080"));
    EXPECT_FALSE(kindKnown("thumbnail"));    // rendered in-process, not a helper kind
    EXPECT_FALSE(kindKnown("hls-720"));
    EXPECT_EQ(helperFor("model-glb"), kCadHelper);
    EXPECT_EQ(helperFor("poster-jpg"), kMediaHelper);
    EXPECT_EQ(helperFor("probe-json"), kMediaHelper);
    EXPECT_EQ(helperFor("transcode-h264-480"), kMediaHelper);
    EXPECT_EQ(helperFor("nope"), "");
    EXPECT_EQ(generatorVersion("model-glb"), 1u);
    EXPECT_EQ(generatorVersion("nope"), 0u);
}

TEST_F(DeriveQueueDbTest, QueuedThenReadyWithASealedArtifactOfTheHelperOutput) {
    const std::string content = "ISO-10303-21;\nPLAINTEXT-MARKER fake step body\n";
    const auto file = write("/part.step", content);
    const auto before = Queue::instance().stats();

    const auto first = Queue::instance().request(engine, file, "model-glb");
    EXPECT_EQ(first.status, DeriveStatus::Queued);
    EXPECT_GT(first.retryAfterSeconds, 0u);

    const auto done = settle(file, "model-glb");
    ASSERT_EQ(done.status, DeriveStatus::Ready) << done.reason;
    ASSERT_TRUE(done.artifact);
    const auto text = artifactText(*done.artifact);
    EXPECT_TRUE(text.starts_with("CMD convert-step --input-size " + std::to_string(content.size()))) << text;
    EXPECT_NE(text.find("--max-triangles 2000000"), std::string::npos) << text;
    EXPECT_TRUE(text.ends_with(content));
    // Encrypted at rest: the plaintext never reaches the cache directory.
    const auto raw = stringOf(fileBytes(done.artifact->path));
    EXPECT_EQ(raw.find("PLAINTEXT-MARKER"), std::string::npos);
    EXPECT_EQ(Queue::instance().stats().completed, before.completed + 1);

    // A cache hit never runs the helper again.
    EXPECT_EQ(Queue::instance().request(engine, file, "model-glb").status, DeriveStatus::Ready);
    EXPECT_EQ(Queue::instance().stats().completed, before.completed + 1);
}

TEST_F(DeriveQueueDbTest, ConcurrentRequestsForOneKeyRunOneJob) {
    const auto file = write("/slow.step", "FAKE-SLEEP 700\nISO-10303-21;\n");
    const auto before = Queue::instance().stats();
    for (int i = 0; i < 5; ++i) EXPECT_EQ(Queue::instance().request(engine, file, "model-glb").status, DeriveStatus::Queued);
    const auto during = Queue::instance().stats();
    EXPECT_EQ(during.queued + during.running, 1u);

    ASSERT_EQ(settle(file, "model-glb").status, DeriveStatus::Ready);
    EXPECT_EQ(Queue::instance().stats().completed, before.completed + 1);
}

TEST_F(DeriveQueueDbTest, DeterministicFailureIsNegativelyCachedUntilTheSourceChanges) {
    auto file = write("/broken.step", "FAKE-INVALID\n");
    const auto failed = settle(file, "model-glb");
    ASSERT_EQ(failed.status, DeriveStatus::Failed);
    EXPECT_EQ(failed.reason, "invalid_input");
    EXPECT_EQ(cache::Store::lookup(engine, keyFor(*file, "model-glb")).status, cache::LookupStatus::Failed);

    // Stays failed without re-running the converter.
    const auto stats = Queue::instance().stats();
    EXPECT_EQ(Queue::instance().request(engine, file, "model-glb").status, DeriveStatus::Failed);
    EXPECT_EQ(Queue::instance().stats().failed, stats.failed);
    EXPECT_EQ(Queue::instance().stats().queued, 0u);

    // New content is a new generation: the negative entry no longer applies.
    file = write("/broken.step", "ISO-10303-21;\nfixed\n", true);
    EXPECT_EQ(Queue::instance().request(engine, file, "model-glb").status, DeriveStatus::Queued);
    EXPECT_EQ(settle(file, "model-glb").status, DeriveStatus::Ready);
}

TEST_F(DeriveQueueDbTest, CrashesAreCachedButTransientFailuresAreNot) {
    const auto crash = write("/crash.step", "FAKE-CRASH\n");
    const auto crashed = settle(crash, "model-glb");
    ASSERT_EQ(crashed.status, DeriveStatus::Failed);
    EXPECT_EQ(crashed.reason, "crashed");
    EXPECT_EQ(cache::Store::lookup(engine, keyFor(*crash, "model-glb")).status, cache::LookupStatus::Failed);

    const auto flaky = write("/flaky.step", "FAKE-INTERNAL\n");
    const auto internal = settle(flaky, "model-glb");
    ASSERT_EQ(internal.status, DeriveStatus::Failed);   // reported to pollers for a short while ...
    EXPECT_EQ(internal.reason, "internal");
    // ... but never persisted as a negative-cache entry.
    EXPECT_EQ(cache::Store::lookup(engine, keyFor(*flaky, "model-glb")).status, cache::LookupStatus::Missing);
    EXPECT_TRUE(db::query::fs::Cache::listDerivedArtifactsByFile(flaky->id).empty());

    // A fresh queue (daemon restart) retries it.
    Queue::instance().shutdown();
    EXPECT_EQ(Queue::instance().request(engine, flaky, "model-glb").status, DeriveStatus::Queued);
}

// A helper that refuses to run unconfined (no Landlock on this host) is the converter being unavailable: reported
// as such to pollers, never negatively cached against the file.
TEST_F(DeriveQueueDbTest, AHelperWithoutItsSandboxIsConverterUnavailable) {
    const auto file = write("/nosandbox.step", "FAKE-NOSANDBOX\n");
    const auto r = settle(file, "model-glb");
    EXPECT_EQ(r.status, DeriveStatus::Unavailable) << r.reason;
    EXPECT_EQ(r.reason, "converter_unavailable");
    EXPECT_EQ(r.helper, std::string(kCadHelper));
    EXPECT_EQ(cache::Store::lookup(engine, keyFor(*file, "model-glb")).status, cache::LookupStatus::Missing);
    EXPECT_TRUE(db::query::fs::Cache::listDerivedArtifactsByFile(file->id).empty());
}

TEST_F(DeriveQueueDbTest, MissingHelperIsUnavailableWithoutEnqueueing) {
    configure([this](config::Config& c) { c.preview.derive.helper_dir = noHelpers; });
    const auto file = write("/part.step", "ISO-10303-21;\n");
    const auto before = Queue::instance().stats();
    const auto r = Queue::instance().request(engine, file, "model-glb");
    EXPECT_EQ(r.status, DeriveStatus::Unavailable);
    EXPECT_EQ(r.helper, std::string(kCadHelper));
    const auto after = Queue::instance().stats();
    EXPECT_EQ(after.queued, 0u);
    EXPECT_EQ(after.running, 0u);
    EXPECT_EQ(after.completed + after.failed, before.completed + before.failed);
    EXPECT_TRUE(db::query::fs::Cache::listDerivedArtifactsByFile(file->id).empty());
}

TEST_F(DeriveQueueDbTest, FullQueueIsBusyAndShutdownKillsRunningHelpers) {
    configure([](config::Config& c) {
        c.preview.derive.max_concurrency = 1;
        c.preview.derive.max_queue = 1;
    });
    const auto a = write("/a.step", "FAKE-SLEEP 30000\n");
    const auto b = write("/b.step", "FAKE-SLEEP 30000\n");
    const auto c = write("/c.step", "FAKE-SLEEP 30000\n");

    ASSERT_EQ(Queue::instance().request(engine, a, "model-glb").status, DeriveStatus::Queued);
    ASSERT_TRUE(waitFor([] { return Queue::instance().stats().running == 1; }));
    ASSERT_EQ(Queue::instance().request(engine, b, "model-glb").status, DeriveStatus::Queued);
    const auto rejected = Queue::instance().stats().rejectedBusy;
    const auto busy = Queue::instance().request(engine, c, "model-glb");
    EXPECT_EQ(busy.status, DeriveStatus::Busy);
    EXPECT_GT(busy.retryAfterSeconds, 0u);
    EXPECT_EQ(Queue::instance().stats().rejectedBusy, rejected + 1);

    // Shutdown does not wait out the 30 s helper (nor the wall timeout): it SIGKILLs it and joins.
    const auto start = std::chrono::steady_clock::now();
    Queue::instance().shutdown();
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(10));
    const auto stats = Queue::instance().stats();
    EXPECT_EQ(stats.running, 0u);
    EXPECT_EQ(stats.queued, 0u);
    // Cancellation is not a property of the file: nothing negatively cached.
    EXPECT_EQ(cache::Store::lookup(engine, keyFor(*a, "model-glb")).status, cache::LookupStatus::Missing);
}

TEST_F(DeriveQueueDbTest, SourceChangedMidJobCachesNothing) {
    const auto file = write("/moving.step", "FAKE-SLEEP 1500\nfirst generation\n");
    const auto firstKey = keyFor(*file, "model-glb");   // the cached model is rewritten in place by the overwrite
    const auto before = Queue::instance().stats();
    ASSERT_EQ(Queue::instance().request(engine, file, "model-glb").status, DeriveStatus::Queued);
    ASSERT_TRUE(waitFor([] { return Queue::instance().stats().running == 1; }));

    const auto rewritten = write("/moving.step", "second generation\n", true);
    ASSERT_NE(storage::generationOf(*rewritten).sourceId(), firstKey.source_id);

    ASSERT_TRUE(waitFor([] {
        const auto s = Queue::instance().stats();
        return s.running == 0 && s.queued == 0;
    }));
    EXPECT_EQ(Queue::instance().stats().completed, before.completed);
    EXPECT_TRUE(db::query::fs::Cache::listDerivedArtifactsByFile(file->id).empty());
    EXPECT_EQ(cache::Store::lookup(engine, firstKey).status, cache::LookupStatus::Missing);
    EXPECT_EQ(cache::Store::lookup(engine, keyFor(*rewritten, "model-glb")).status, cache::LookupStatus::Missing);
}

TEST_F(DeriveQueueDbTest, AJobForASupersededGenerationNeverRuns) {
    configure([](config::Config& c) { c.preview.derive.max_concurrency = 1; });
    const auto blocker = write("/blocker.step", "FAKE-SLEEP 800\n");
    ASSERT_EQ(Queue::instance().request(engine, blocker, "model-glb").status, DeriveStatus::Queued);
    ASSERT_TRUE(waitFor([] { return Queue::instance().stats().running == 1; }));

    const auto file = write("/later.step", "ISO-10303-21;\nfirst\n");
    const auto firstKey = keyFor(*file, "model-glb");
    ASSERT_EQ(Queue::instance().request(engine, file, "model-glb").status, DeriveStatus::Queued);   // waits
    (void)write("/later.step", "ISO-10303-21;\nsecond, longer\n", true);
    const auto before = Queue::instance().stats();

    ASSERT_TRUE(waitFor([] {
        const auto s = Queue::instance().stats();
        return s.running == 0 && s.queued == 0;
    }));
    const auto after = Queue::instance().stats();
    EXPECT_EQ(after.completed, before.completed + 1);   // the blocker only
    EXPECT_EQ(after.failed, before.failed);             // the stale job was discarded, not failed
    EXPECT_EQ(cache::Store::lookup(engine, firstKey).status, cache::LookupStatus::Missing);
    EXPECT_EQ(settle(file, "model-glb").status, DeriveStatus::Ready);   // the current generation derives normally
}

TEST_F(DeriveQueueDbTest, KindsApplyOnlyToTheirSourcesAndTranscodesFollowConfig) {
    const auto step = write("/part.step", "ISO-10303-21;\n");
    auto clip = write("/clip.mp4", "not really a video");
    clip->mime_type = "video/mp4";   // libmagic cannot call this a video; the plan follows the recorded mime
    auto song = write("/song.mp3", "not really audio");
    song->mime_type = "audio/mpeg";

    EXPECT_EQ(Queue::instance().request(engine, step, "probe-json").status, DeriveStatus::Unsupported);
    EXPECT_EQ(Queue::instance().request(engine, clip, "model-glb").status, DeriveStatus::Unsupported);
    EXPECT_EQ(Queue::instance().request(engine, song, "transcode-h264-720").status, DeriveStatus::Unsupported);
    EXPECT_EQ(Queue::instance().request(engine, step, "no-such-kind").status, DeriveStatus::Unsupported);
    EXPECT_EQ(Queue::instance().request(engine, step, "model-glb", "v2").status, DeriveStatus::Unsupported);

    configure([](config::Config& c) { c.preview.media.transcode = config::PreviewTranscodeMode::Off; });
    const auto off = Queue::instance().request(engine, clip, "transcode-h264-720");
    EXPECT_EQ(off.status, DeriveStatus::Unsupported);
    EXPECT_EQ(off.reason, "transcode_disabled");
    EXPECT_EQ(Queue::instance().request(engine, clip, "probe-json").status, DeriveStatus::Queued);   // still allowed

    configure([](config::Config& c) { c.preview.media.transcode = config::PreviewTranscodeMode::OnDemand; });
    const auto transcoded = settle(clip, "transcode-h264-720");
    ASSERT_EQ(transcoded.status, DeriveStatus::Ready) << transcoded.reason;
    const auto text = artifactText(*transcoded.artifact);
    EXPECT_TRUE(text.starts_with("CMD transcode ")) << text;
    EXPECT_NE(text.find("--profile h264-720 --hwaccel software"), std::string::npos) << text;

    const auto poster = settle(clip, "poster-jpg");
    ASSERT_EQ(poster.status, DeriveStatus::Ready) << poster.reason;
    EXPECT_NE(artifactText(*poster.artifact).find("CMD poster --input-size"), std::string::npos);
    EXPECT_NE(artifactText(*poster.artifact).find("--max-width 1280"), std::string::npos);

    // Audio: whatever the plan lists (probe, the audio-only transcode), nothing else.
    EXPECT_EQ(Queue::instance().request(engine, song, "poster-jpg").status, DeriveStatus::Unsupported);
    const auto probe = settle(song, "probe-json");
    ASSERT_EQ(probe.status, DeriveStatus::Ready) << probe.reason;
    EXPECT_TRUE(artifactText(*probe.artifact).starts_with("CMD probe --input-size"));
    EXPECT_EQ(Queue::instance().request(engine, song, "transcode-h264-480").status, DeriveStatus::Queued);
}

TEST_F(DeriveQueueDbTest, TrashingAFileDropsItsArtifacts) {
    const auto file = write("/gone.step", "ISO-10303-21;\n");
    const auto ready = settle(file, "model-glb");
    ASSERT_EQ(ready.status, DeriveStatus::Ready);
    ASSERT_TRUE(std::filesystem::exists(ready.artifact->path));

    fs::Filesystem::remove(engine->vaultPathToFusePath("/gone.step"), admin->id);
    EXPECT_FALSE(std::filesystem::exists(ready.artifact->path));
    EXPECT_FALSE(std::filesystem::exists(engine->paths->cacheRoot / "derived" / std::to_string(file->id)));
    EXPECT_TRUE(db::query::fs::Cache::listDerivedArtifactsByFile(file->id).empty());
}

TEST_F(DeriveQueueDbTest, RemovingAVaultDropsItsArtifacts) {
    const auto file = write("/kept.step", "ISO-10303-21;\n");
    const auto ready = settle(file, "model-glb");
    ASSERT_EQ(ready.status, DeriveStatus::Ready);
    const auto derivedRoot = engine->paths->cacheRoot / "derived";
    ASSERT_TRUE(std::filesystem::exists(derivedRoot));

    runtime::Deps::get().storageManager->removeVault(engine->vault->id);
    EXPECT_FALSE(std::filesystem::exists(derivedRoot));
}

TEST_F(DeriveQueueDbTest, StartupSweepRemovesLegacyPlaintextThumbnails) {
    const auto legacy = engine->paths->thumbnailRoot / "LEGACYALIAS" / "128.jpg";
    std::filesystem::create_directories(legacy.parent_path());
    std::ofstream(legacy) << "legacy plaintext jpeg";
    const auto file = write("/kept.step", "ISO-10303-21;\n");
    const auto ready = settle(file, "model-glb");
    ASSERT_EQ(ready.status, DeriveStatus::Ready);

    EXPECT_GT(cache::sweepAtStartup(runtime::Deps::get().storageManager->getEngines()), 0u);
    EXPECT_FALSE(std::filesystem::exists(legacy));
    EXPECT_FALSE(std::filesystem::exists(engine->paths->thumbnailRoot));
    EXPECT_TRUE(std::filesystem::exists(ready.artifact->path));   // sealed artifacts of live files stay
}

TEST_F(DeriveQueueDbTest, PeriodicEvictionHonoursTheCacheCap) {
    const auto file = write("/evict.step", "ISO-10303-21;\n");
    const auto ready = settle(file, "model-glb");
    ASSERT_EQ(ready.status, DeriveStatus::Ready);

    configure([](config::Config& c) { c.caching.max_size_mb = 0; });
    EXPECT_GE(cache::evictPeriodic(), ready.artifact->size);
    EXPECT_FALSE(std::filesystem::exists(ready.artifact->path));
    EXPECT_EQ(cache::Store::lookup(engine, keyFor(*file, "model-glb")).status, cache::LookupStatus::Missing);
}

TEST_F(DeriveQueueDbTest, ApplyConfigSetsReaderPoliciesFromPreviewMedia) {
    configure([](config::Config& c) {
        c.preview.media.integrity = config::PreviewIntegrityMode::Strict;
        c.preview.media.remote = config::PreviewRemoteMode::Off;
    });
    cache::applyConfig();
    EXPECT_EQ(storage::resolveIntegrityPolicy(storage::IntegrityPolicy::FromConfig), storage::IntegrityPolicy::Strict);
    EXPECT_EQ(storage::resolveRemotePolicy(storage::RemoteFetchPolicy::FromConfig), storage::RemoteFetchPolicy::Off);

    config::Registry::set(original);
    cache::applyConfig();
    EXPECT_EQ(storage::resolveIntegrityPolicy(storage::IntegrityPolicy::FromConfig), storage::IntegrityPolicy::Optimistic);
    EXPECT_EQ(storage::resolveRemotePolicy(storage::RemoteFetchPolicy::FromConfig), storage::RemoteFetchPolicy::Hydrate);
}

// The real converter end to end, when the build produced it: STEP in a vault -> sealed GLB out.
TEST_F(DeriveQueueDbTest, RealCadHelperConvertsStepToGlbAndCachesMalformedFailures) {
    const std::filesystem::path cad = VH_TEST_CAD_HELPER;
    if (cad.empty() || !Runner::isExecutable(cad)) GTEST_SKIP() << "vaulthalla-preview-cad not built";
    const auto realHelpers = root / ("realhelpers_" + tag());
    std::filesystem::create_directories(realHelpers);
    std::filesystem::create_symlink(cad, realHelpers / std::string(kCadHelper));
    configure([&realHelpers](config::Config& c) { c.preview.derive.helper_dir = realHelpers; });

    const auto step = stringOf(fileBytes(std::filesystem::path(VH_TEST_ASSETS_DIR) / "preview-cad" / "box-and-cylinder.step"));
    ASSERT_FALSE(step.empty());
    const auto file = write("/assembly.step", step);
    const auto ready = settle(file, "model-glb", std::chrono::seconds(120));
    ASSERT_EQ(ready.status, DeriveStatus::Ready) << ready.reason;
    EXPECT_TRUE(artifactText(*ready.artifact).starts_with("glTF"));

    const auto broken = write("/garbage.step", "ISO-10303-21;\nthis is not a STEP exchange structure\n");
    const auto failed = settle(broken, "model-glb", std::chrono::seconds(120));
    ASSERT_EQ(failed.status, DeriveStatus::Failed);
    EXPECT_EQ(failed.reason, "invalid_input");
    EXPECT_EQ(Queue::instance().request(engine, broken, "model-glb").status, DeriveStatus::Failed);
}

}
