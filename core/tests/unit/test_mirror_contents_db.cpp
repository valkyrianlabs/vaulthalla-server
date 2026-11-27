// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// A mirror's file contents (design/peers/mirror.md "Contents"; mirror::contents, db::query::mirror::PendingContents,
// migration 161), in-process: this server is the mirror of a local vault, and the sealed bytes come from a test source
// standing in for the core (the receiver cannot hold the same vault as another daemon yet: key delivery and vault
// creation are the next piece; the two-daemon transfer itself is `vhh drill peers`). Covers invariant 8 (nothing
// unverified is linked: a correct file links and reads back; truncated bytes, a flipped byte in a chunk or the header,
// bytes sealed for another object or another generation, and a row that changed while the transfer ran are each
// discarded and never linked), three failures stopping retries until told, resume by range, the open-time fetch
// (a waiting reader served; the link down giving ENOLINK within the bound, through the mount's working copies too; no
// reader ever seeing partial bytes), the outstanding list's order, and the transfer slots' priority lane.

#include "../helpers/db_suite.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "fuse/WorkingCopies.hpp"
#include "mirror/Contents.hpp"
#include "ops/Error.hpp"
#include "ops/Vaults.hpp"
#include "peer/Links.hpp"
#include "peer/Transfers.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <pqxx/pqxx>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <map>
#include <mutex>
#include <random>
#include <sys/stat.h>
#include <thread>

namespace vh::test_mirror_contents {

namespace contents = vh::mirror::contents;
using vh::db::query::mirror::Expected;
using vh::db::query::mirror::PendingContents;
using vh::peer::object::FetchStatus;
using namespace std::chrono_literals;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "c" + std::to_string(n.fetch_add(1));
}

std::vector<uint8_t> readFile(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

std::string blake2bOf(const std::vector<uint8_t>& bytes) {
    const auto dir = std::filesystem::temp_directory_path() / ("vh-mc-" + tag());
    std::filesystem::create_directories(dir);
    const auto p = dir / "b";
    std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(bytes.data()),
                                             static_cast<std::streamsize>(bytes.size()));
    const auto h = crypto::hash::blake2b(p);
    std::filesystem::remove_all(dir);
    return h;
}

// What the core would send: given bytes, optionally interrupted once, cut short, held mid-way until released.
struct Script {
    std::vector<uint8_t> bytes;
    std::optional<uint64_t> interruptOnceAt;   // the first read stops there (Interrupted)
    std::optional<uint64_t> shortBy;           // Complete, with this many bytes missing at the end
    std::optional<uint64_t> holdAt;            // stops at this offset until release()
    std::optional<FetchStatus> answer;         // instead of any bytes (Unreachable, Refused)
    std::atomic<int> reads{0};
    std::vector<uint64_t> offsets;
    std::mutex mutex;
    std::condition_variable cv;
    bool released{false};
    bool held{false};

    void release() {
        std::scoped_lock lock(mutex);
        released = true;
        cv.notify_all();
    }
    void waitHeld() {
        std::unique_lock lock(mutex);
        ASSERT_TRUE(cv.wait_for(lock, 20s, [&] { return held; }));
    }
};

class ScriptedSource final : public contents::Source {
public:
    explicit ScriptedSource(std::shared_ptr<Script> s) : s_(std::move(s)) {}

    contents::SourceResult read(const uint64_t offset, uint64_t, const std::function<bool()>& cancelled,
                                const vh::peer::object::Sink& sink) override {
        const int n = ++s_->reads;
        {
            std::scoped_lock lock(s_->mutex);
            s_->offsets.push_back(offset);
        }
        if (s_->answer) return {*s_->answer, "scripted"};
        uint64_t end = s_->bytes.size();
        if (s_->shortBy) end -= *s_->shortBy;
        if (n == 1 && s_->interruptOnceAt) end = std::min(end, *s_->interruptOnceAt);
        uint64_t pos = offset;
        while (pos < end) {
            if (s_->holdAt && pos >= *s_->holdAt) {
                std::unique_lock lock(s_->mutex);
                s_->held = true;
                s_->cv.notify_all();
                s_->cv.wait(lock, [&] { return s_->released; });
                s_->holdAt.reset();
            }
            if (cancelled && cancelled()) return {FetchStatus::Cancelled, "cancelled"};
            uint64_t step = std::min<uint64_t>(end - pos, 8192);
            if (s_->holdAt && pos < *s_->holdAt) step = std::min(step, *s_->holdAt - pos);
            sink(std::span<const uint8_t>(s_->bytes.data() + pos, step));
            pos += step;
        }
        if (n == 1 && s_->interruptOnceAt && end < s_->bytes.size()) return {FetchStatus::Interrupted, "broke off"};
        return {FetchStatus::Complete, ""};
    }

private:
    std::shared_ptr<Script> s_;
};

class MirrorContentsDbTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<storage::Engine> engine;
    inline static vh::peer::Record core;   // the vault's linked server (no connection: the link is down)

    struct Held {
        std::shared_ptr<fs::model::File> file;
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> sealed;   // what the core holds
        Expected expected;
    };

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mirror_contents")) return;
        const auto vault = ops::vaults::create(superUser, {.name = "mc_" + tag(), .type = vault::model::VaultType::Local,
                                                           .owner_id = superUser->id});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        db::query::peer::NewPeer p;
        p.node_id = "core-" + tag();
        p.name = "the-core";
        p.spki_sha256 = std::string(63, 'a') + "b";
        vh::peer::Key32 k{};
        k.fill(0x61);
        p.attest_public_keys = {k};
        p.wrap_public_key = k;
        core = db::query::peer::Peers::insert(p);
        (void)db::query::mirror::MirrorVaults::startMirror(vault->id, core.id);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        contents::setSourceFactoryForTesting({});
        engine.reset();
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        contents::setSourceFactoryForTesting({});
    }

    void TearDown() override {
        contents::setSourceFactoryForTesting({});
        contents::setMountWaitCapForTesting(0);
    }

    // A file whose row is on this server and whose sealed bytes are only at the core: written, its bytes taken away,
    // and marked expected with the row's generation, hash and size (what the log applier will do).
    static Held notYetReceived(const std::string& path, const std::size_t size, const int16_t priority = 0) {
        Held h;
        h.plaintext.resize(size);
        std::mt19937 rng(static_cast<unsigned>(size) + static_cast<unsigned>(path.size()));
        for (auto& b : h.plaintext) b = static_cast<uint8_t>(rng());
        // The row is written as the log applier would have written it: here a local write, made while the vault is
        // briefly not held as a mirror (a mirror refuses every local write, wave 4: mirror::access, migration 165).
        EXPECT_TRUE(db::query::mirror::MirrorVaults::remove(engine->vault->id));
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                          .buffer = h.plaintext, .engine = engine, .user = superUser,
                                          .overwrite = true});
        (void)db::query::mirror::MirrorVaults::startMirror(engine->vault->id, core.id);
        h.file = db::query::fs::File::getFileByPath(engine->vault->id, path);
        h.sealed = readFile(h.file->backing_path);
        std::filesystem::remove(h.file->backing_path);
        h.expected = Expected{.vault_id = engine->vault->id, .object_uid = *h.file->object_uid,
                              .generation = h.file->encryption_iv, .key_version = h.file->encrypted_with_key_version,
                              .size_bytes = h.file->size_bytes, .content_hash = h.file->content_hash.value_or(""),
                              .mtime_us = 1'700'000'000'123'456LL, .priority = priority};
        PendingContents::expect(h.expected);
        return h;
    }

    static std::shared_ptr<Script> serve(std::vector<uint8_t> bytes) {
        auto s = std::make_shared<Script>();
        s->bytes = std::move(bytes);
        contents::setSourceFactoryForTesting([s](const auto&, const auto&) { return std::make_unique<ScriptedSource>(s); });
        return s;
    }

    static contents::Result receiveWith(const Held& h, const std::shared_ptr<Script>& s) {
        ScriptedSource source(s);
        return contents::receive(h.expected, source);
    }

    static bool linked(const Held& h) { return std::filesystem::exists(h.file->backing_path); }

    static std::vector<uint8_t> readBack(const Held& h) {
        const auto row = db::query::fs::File::getFileById(h.file->id);
        const auto reader = engine->openPlaintextReader(row);
        return storage::readAll(*reader, 64ull * 1024 * 1024);
    }
};

TEST_F(MirrorContentsDbTest, ACorrectFileLinksIntoPlaceWithItsTimeAndReadsBack) {
    const auto h = notYetReceived("/right.bin", 200'000);
    ASSERT_FALSE(linked(h));
    // The first read breaks off at 70,000 bytes: the second resumes there.
    auto s = std::make_shared<Script>();
    s->bytes = h.sealed;
    s->interruptOnceAt = 70'000;
    const auto r = receiveWith(h, s);
    ASSERT_EQ(r.outcome, contents::Outcome::Received) << r.reason;
    EXPECT_EQ(s->reads.load(), 2);
    EXPECT_EQ(s->offsets, (std::vector<uint64_t>{0, 70'000}));
    ASSERT_TRUE(linked(h));
    EXPECT_EQ(readFile(h.file->backing_path), h.sealed) << "the core's sealed bytes, as they were";
    struct stat st{};
    ASSERT_EQ(::stat(h.file->backing_path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mtime, 1'700'000'000);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    EXPECT_FALSE(PendingContents::get(h.expected.vault_id, h.expected.object_uid)) << "cleared on success";
    EXPECT_FALSE(std::filesystem::exists(vh::fs::ops::contentSidecarPath(h.file->backing_path)));
    EXPECT_EQ(readBack(h), h.plaintext);
}

TEST_F(MirrorContentsDbTest, TruncatedBytesAreDiscardedAndNeverLinked) {
    const auto h = notYetReceived("/short.bin", 150'000);
    auto s = std::make_shared<Script>();
    s->bytes = h.sealed;
    s->shortBy = 1;
    const auto r = receiveWith(h, s);
    EXPECT_EQ(r.outcome, contents::Outcome::Failed);
    EXPECT_NE(r.reason.find("size"), std::string::npos) << r.reason;
    EXPECT_FALSE(linked(h));
    const auto row = PendingContents::get(h.expected.vault_id, h.expected.object_uid);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->attempts, 1u);
    EXPECT_EQ(row->state, "waiting");
}

TEST_F(MirrorContentsDbTest, AFlippedByteInAChunkOrTheHeaderIsDiscarded) {
    for (const std::size_t at : {std::size_t{40}, std::size_t{120 + 70'000}}) {  // the header; a chunk's ciphertext
        const auto h = notYetReceived("/flip" + std::to_string(at) + ".bin", 140'000);
        auto bad = h.sealed;
        bad[at] ^= 0x01;
        // The log's hash names the real bytes: refused at the hash, before the key is used.
        auto r = receiveWith(h, serve(bad));
        EXPECT_EQ(r.outcome, contents::Outcome::Failed);
        EXPECT_NE(r.reason.find("content hash"), std::string::npos) << r.reason;
        EXPECT_FALSE(linked(h));
        // A hash that names the damaged bytes (a wrong log row): refused when the bytes are authenticated.
        auto lying = h.expected;
        lying.content_hash = blake2bOf(bad);
        PendingContents::expect(lying);
        ScriptedSource source(serve(bad));
        r = contents::receive(lying, source);
        EXPECT_EQ(r.outcome, contents::Outcome::Failed);
        EXPECT_NE(r.reason.find("authentication"), std::string::npos) << r.reason;
        EXPECT_FALSE(linked(h)) << "byte " << at;
    }
}

TEST_F(MirrorContentsDbTest, BytesSealedForAnotherObjectOrAnotherGenerationAreDiscarded) {
    const auto h = notYetReceived("/target.bin", 100'000);
    // Another file of the same vault, the same size: its own object, its own generation.
    const auto other = notYetReceived("/other.bin", 100'000);
    ASSERT_EQ(other.sealed.size(), h.sealed.size());
    auto lying = h.expected;
    lying.content_hash = blake2bOf(other.sealed);
    PendingContents::expect(lying);
    ScriptedSource source(serve(other.sealed));
    auto r = contents::receive(lying, source);
    EXPECT_EQ(r.outcome, contents::Outcome::Failed);
    EXPECT_NE(r.reason.find("authentication"), std::string::npos) << r.reason;
    EXPECT_FALSE(linked(h));

    // The same plaintext of the same file, sealed again: another generation (salt) than the one expected.
    const auto again = vh::vault::content::sealBuffer(h.plaintext, *engine->encryptionManager->keySnapshot(
                                                                        h.expected.key_version),
                                                      h.expected.key_version, engine->encryptionManager->vaultUid(),
                                                      h.expected.object_uid);
    ASSERT_NE(again.generation, h.expected.generation);
    ASSERT_EQ(again.bytes.size(), h.sealed.size());
    lying.content_hash = blake2bOf(again.bytes);
    PendingContents::expect(lying);
    ScriptedSource second(serve(again.bytes));
    r = contents::receive(lying, second);
    EXPECT_EQ(r.outcome, contents::Outcome::Failed);
    EXPECT_NE(r.reason.find("authentication"), std::string::npos) << r.reason;
    EXPECT_FALSE(linked(h));
}

TEST_F(MirrorContentsDbTest, ARowThatChangedWhileTheTransferRanIsNeverLinked) {
    // The expectation moves on (the core wrote the file again) while the bytes arrive.
    {
        const auto h = notYetReceived("/moved.bin", 160'000);
        auto s = std::make_shared<Script>();
        s->bytes = h.sealed;
        s->holdAt = 80'000;
        auto running = std::async(std::launch::async, [&] { return receiveWith(h, s); });
        s->waitHeld();
        auto newer = h.expected;
        std::array<uint8_t, 32> salt{};
        salt.fill(0x7e);
        newer.generation = vh::vault::content::generationOf(salt);
        PendingContents::expect(newer);
        s->release();
        const auto r = running.get();
        EXPECT_EQ(r.outcome, contents::Outcome::Superseded) << contents::toString(r.outcome) << ": " << r.reason;
        EXPECT_FALSE(linked(h));
        const auto row = PendingContents::get(h.expected.vault_id, h.expected.object_uid);
        ASSERT_TRUE(row);
        EXPECT_EQ(row->generation, newer.generation) << "the newer expectation stays";
        EXPECT_EQ(row->attempts, 0u) << "not the file's failure";
    }
    // The file's own row moves on (another generation recorded) while the bytes arrive.
    {
        const auto h = notYetReceived("/rewritten.bin", 160'000);
        auto s = std::make_shared<Script>();
        s->bytes = h.sealed;
        s->holdAt = 50'000;
        auto running = std::async(std::launch::async, [&] { return receiveWith(h, s); });
        s->waitHeld();
        std::array<uint8_t, 32> salt{};
        salt.fill(0x3c);
        db::Transactions::exec("row moves on", [&](pqxx::work& txn) {
            db::query::mirror::Log::markMirrorApply(txn);   // as the follower writes it (a mirror refuses other writes)
            txn.exec("UPDATE files SET encryption_iv = $1 WHERE fs_entry_id = $2",
                     pqxx::params{vh::vault::content::generationOf(salt), h.file->id});
        });
        s->release();
        const auto r = running.get();
        EXPECT_EQ(r.outcome, contents::Outcome::Superseded) << contents::toString(r.outcome) << ": " << r.reason;
        EXPECT_FALSE(linked(h));
        EXPECT_FALSE(PendingContents::get(h.expected.vault_id, h.expected.object_uid)) << "dropped as superseded";
    }
}

TEST_F(MirrorContentsDbTest, ThreeFailuresStopRetriesUntilToldTo) {
    const auto h = notYetReceived("/thrice.bin", 90'000);
    auto bad = h.sealed;
    bad[500] ^= 0x80;
    const auto s = serve(bad);
    for (int i = 1; i <= 3; ++i) {
        const auto r = receiveWith(h, s);
        EXPECT_EQ(r.outcome, contents::Outcome::Failed);
        EXPECT_EQ(r.failedForGood, i == 3) << "attempt " << i;
    }
    const auto row = PendingContents::get(h.expected.vault_id, h.expected.object_uid);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->state, "failed");
    EXPECT_EQ(row->attempts, 3u);
    EXPECT_NE(row->last_error.value_or("").find("content hash"), std::string::npos);
    // No fourth fetch: not by receive, not by an open.
    const auto readsBefore = s->reads.load();
    const auto again = receiveWith(h, s);
    EXPECT_EQ(again.outcome, contents::Outcome::Failed);
    EXPECT_TRUE(again.failedForGood);
    try {
        (void)contents::awaitIfPending(*h.file, 2s);
        ADD_FAILURE() << "a failed file opened";
    } catch (const contents::NotReceived& e) {
        EXPECT_EQ(e.reason(), contents::Reason::Failed);
        EXPECT_EQ(e.code().value(), ENODATA);
    }
    EXPECT_EQ(s->reads.load(), readsBefore) << "nothing fetched for a failed file";
    const auto waiting = PendingContents::outstanding(h.expected.vault_id, 100);
    EXPECT_TRUE(std::ranges::none_of(waiting, [&](const Expected& e) { return e.object_uid == h.expected.object_uid; }))
        << "a failed file is not outstanding";
    // Told to: it waits again, and the right bytes go in.
    ASSERT_TRUE(PendingContents::retry(h.expected.vault_id, h.expected.object_uid));
    const auto fixed = receiveWith(h, serve(h.sealed));
    EXPECT_EQ(fixed.outcome, contents::Outcome::Received) << fixed.reason;
    EXPECT_EQ(readBack(h), h.plaintext);
}

TEST_F(MirrorContentsDbTest, AnOpenFetchesAheadAndAWaitingReaderIsServedOnceVerified) {
    const auto h = notYetReceived("/opened.bin", 220'000);
    auto s = std::make_shared<Script>();
    s->bytes = h.sealed;
    s->holdAt = 100'000;
    contents::setSourceFactoryForTesting([s](const auto&, const auto&) { return std::make_unique<ScriptedSource>(s); });
    // A reader that cannot wait long: told it is still coming, never handed partial bytes.
    std::thread opener([&] {
        try {
            (void)contents::awaitIfPending(*h.file, 300ms);
            ADD_FAILURE() << "served before the bytes were verified";
        } catch (const contents::NotReceived& e) {
            EXPECT_EQ(e.reason(), contents::Reason::TimedOut);
            EXPECT_EQ(e.code().value(), ETIMEDOUT);
        }
    });
    s->waitHeld();
    opener.join();
    EXPECT_FALSE(linked(h)) << "half the bytes have arrived; nothing is reachable";
    try {
        (void)engine->openPlaintextReader(db::query::fs::File::getFileById(h.file->id));
        ADD_FAILURE() << "a reader opened partial bytes";
    } catch (const storage::ContentUnavailable& e) {
        EXPECT_EQ(contents::reasonCodeIn(e.what()), "mirror_fetch_timeout") << e.what();
    }
    // A reader that waits (one transfer for both: the same one is still running) is served once it is verified.
    auto waiting = std::async(std::launch::async, [&] { return readBack(h); });
    std::this_thread::sleep_for(100ms);
    s->release();
    EXPECT_EQ(waiting.get(), h.plaintext);
    EXPECT_EQ(s->reads.load(), 1) << "one transfer, however many waited";
    EXPECT_FALSE(PendingContents::get(h.expected.vault_id, h.expected.object_uid));
}

TEST_F(MirrorContentsDbTest, WithTheLinkDownAnOpenFailsWithItsReasonWithinTheBound) {
    const auto h = notYetReceived("/unreachable.bin", 64'000);
    // No test source: the vault's linked server, which has no connection.
    const auto started = std::chrono::steady_clock::now();
    try {
        (void)contents::awaitIfPending(*h.file);
        ADD_FAILURE() << "opened with the link down";
    } catch (const contents::NotReceived& e) {
        EXPECT_EQ(e.reason(), contents::Reason::LinkDown);
        EXPECT_EQ(e.code().value(), ENOLINK);
        EXPECT_TRUE(std::string_view(e.what()).starts_with("mirror_link_down: the link to the-core is down")) << e.what();
    }
    EXPECT_LT(std::chrono::steady_clock::now() - started, 1s) << "the link down is said at once, not after the wait";
    // The download and preview lanes: ContentUnavailable with the code (503 mirror_link_down on HTTP).
    try {
        (void)engine->openPlaintextReader(db::query::fs::File::getFileById(h.file->id));
        ADD_FAILURE();
    } catch (const storage::ContentUnavailable& e) {
        EXPECT_EQ(contents::reasonCodeIn(e.what()), "mirror_link_down");
    }
    // The mount: the working copy's open (what fuse::open calls) fails with ENOLINK, not EIO.
    auto& copies = fuse::WorkingCopies::instance();
    std::filesystem::create_directories(copies.root());
    const auto row = db::query::fs::File::getFileById(h.file->id);
    ASSERT_TRUE(row->inode);
    try {
        (void)copies.open(*row->inode, row, O_RDONLY);
        ADD_FAILURE() << "the mount opened it";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ENOLINK) << e.what();
    }
    EXPECT_FALSE(linked(h));
    const auto pending = PendingContents::get(h.expected.vault_id, h.expected.object_uid);
    ASSERT_TRUE(pending);
    EXPECT_EQ(pending->attempts, 0u) << "a link down is not the file's failure";
}

// The mount's opens share one FUSE worker pool with every vault: only mountWaitCap() of them wait on pending files at
// once. The others answer ETIMEDOUT at once while their fetch still runs ahead of the queue, and every way out of a
// wait (success, timeout, failure, link down) gives its place back.
TEST_F(MirrorContentsDbTest, OnlyAFewMountOpensWaitAndTheRestAnswerAtOnceWhileTheirFetchesGoOn) {
    contents::setMountWaitCapForTesting(2);
    EXPECT_EQ(contents::mountWaitCap(), 2u);
    std::vector<Held> files;
    std::map<std::string, std::shared_ptr<Script>> scripts;
    for (int i = 0; i < 4; ++i) {
        files.push_back(notYetReceived("/many" + std::to_string(i) + ".bin", 90'000));
        auto s = std::make_shared<Script>();
        s->bytes = files.back().sealed;
        s->holdAt = 4096;
        scripts[vl::keykit::toBase32(files.back().expected.object_uid)] = s;
    }
    contents::setSourceFactoryForTesting([scripts](const auto&, const Expected& e) {
        return std::make_unique<ScriptedSource>(scripts.at(vl::keykit::toBase32(e.object_uid)));
    });
    const auto scriptOf = [&](const Held& h) { return scripts.at(vl::keykit::toBase32(h.expected.object_uid)); };

    // Two opens through the mount wait (their transfers held mid-way)...
    std::vector<std::future<bool>> waiting;
    for (int i = 0; i < 2; ++i)
        waiting.push_back(std::async(std::launch::async, [&, i] {
            return contents::awaitIfPending(*files[i].file, 20s, contents::Opener::Mount);
        }));
    for (int i = 0; i < 100 && contents::mountWaitersForTesting() < 2; ++i) std::this_thread::sleep_for(20ms);
    ASSERT_EQ(contents::mountWaitersForTesting(), 2u);
    // ...and the next ones, through the working copies' open (what fuse::open calls), answer at once.
    auto& copies = fuse::WorkingCopies::instance();
    std::filesystem::create_directories(copies.root());
    for (int i = 2; i < 4; ++i) {
        const auto row = db::query::fs::File::getFileById(files[i].file->id);
        const auto started = std::chrono::steady_clock::now();
        try {
            (void)copies.open(*row->inode, row, O_RDONLY);
            ADD_FAILURE() << "an open over the cap waited and opened";
        } catch (const std::system_error& e) {
            EXPECT_EQ(e.code().value(), ETIMEDOUT) << e.what();
        }
        EXPECT_LT(std::chrono::steady_clock::now() - started, 1s) << "over the cap: no wait";
        scriptOf(files[i])->waitHeld();  // its fetch started all the same
    }
    // Other surfaces are not capped: they wait their full bound (here, a short one).
    EXPECT_THROW((void)contents::awaitIfPending(*files[2].file, 200ms, contents::Opener::Other), contents::NotReceived);
    EXPECT_EQ(contents::mountWaitersForTesting(), 2u);

    for (auto& [_, s] : scripts) s->release();
    for (auto& w : waiting) EXPECT_TRUE(w.get());
    EXPECT_EQ(contents::mountWaitersForTesting(), 0u) << "released on success";
    for (int i = 0; i < 4; ++i) {
        for (int t = 0; t < 250 && PendingContents::get(files[i].expected.vault_id, files[i].expected.object_uid); ++t)
            std::this_thread::sleep_for(20ms);
        EXPECT_FALSE(PendingContents::get(files[i].expected.vault_id, files[i].expected.object_uid)) << i;
        EXPECT_EQ(readBack(files[i]), files[i].plaintext) << "the fetch of an open that did not wait completed";
    }
    // A retry of an open that answered at once now opens (nothing is pending any more).
    EXPECT_FALSE(contents::awaitIfPending(*files[3].file, 1s, contents::Opener::Mount));

    // Released on a timeout...
    const auto slow = notYetReceived("/slow.bin", 90'000);
    auto held = std::make_shared<Script>();
    held->bytes = slow.sealed;
    held->holdAt = 4096;
    contents::setSourceFactoryForTesting([held](const auto&, const auto&) { return std::make_unique<ScriptedSource>(held); });
    EXPECT_THROW((void)contents::awaitIfPending(*slow.file, 200ms, contents::Opener::Mount), contents::NotReceived);
    EXPECT_EQ(contents::mountWaitersForTesting(), 0u) << "released on a timeout";
    held->release();
    // ...on a failure (bad bytes, reported after the wait)...
    const auto bad = notYetReceived("/bad.bin", 50'000);
    auto damaged = bad.sealed;
    damaged[300] ^= 0x10;
    (void)serve(damaged);
    try {
        (void)contents::awaitIfPending(*bad.file, 10s, contents::Opener::Mount);
        ADD_FAILURE();
    } catch (const contents::NotReceived& e) {
        EXPECT_EQ(e.reason(), contents::Reason::Failed) << e.what();
    }
    EXPECT_EQ(contents::mountWaitersForTesting(), 0u) << "released on a failure";
    // ...and the link down (said before any wait: no place taken).
    contents::setSourceFactoryForTesting({});
    const auto down = notYetReceived("/down.bin", 20'000);
    EXPECT_THROW((void)contents::awaitIfPending(*down.file, 10s, contents::Opener::Mount), contents::NotReceived);
    EXPECT_EQ(contents::mountWaitersForTesting(), 0u) << "the link down";
    contents::setMountWaitCapForTesting(0);
    EXPECT_GE(contents::mountWaitCap(), 1u);
    EXPECT_LE(contents::mountWaitCap(), 4u);
}

TEST_F(MirrorContentsDbTest, OutstandingFilesComeInPriorityOrderAndOnlyForAMirror) {
    db::Transactions::exec("clean", [](pqxx::work& txn) { txn.exec("DELETE FROM mirror_content_pending"); });
    const auto low = notYetReceived("/low.bin", 10'000, 0);
    const auto high = notYetReceived("/high.bin", 10'000, 5);
    const auto later = notYetReceived("/later.bin", 10'000, 0);
    const auto list = PendingContents::outstanding(engine->vault->id, 10);
    ASSERT_EQ(list.size(), 3u);
    EXPECT_EQ(list[0].object_uid, high.expected.object_uid);
    EXPECT_EQ(list[1].object_uid, low.expected.object_uid);
    EXPECT_EQ(list[2].object_uid, later.expected.object_uid);
    EXPECT_EQ(PendingContents::countOutstanding(engine->vault->id), 3u);
    // Fetched in the background, in that order, through background slots.
    std::vector<std::string> order;
    std::mutex m;
    std::map<std::string, std::vector<uint8_t>> sealedOf{{vl::keykit::toBase32(low.expected.object_uid), low.sealed},
                                                         {vl::keykit::toBase32(high.expected.object_uid), high.sealed},
                                                         {vl::keykit::toBase32(later.expected.object_uid), later.sealed}};
    contents::setSourceFactoryForTesting([&](const auto&, const Expected& e) {
        std::scoped_lock lock(m);
        order.push_back(vl::keykit::toBase32(e.object_uid));
        auto s = std::make_shared<Script>();
        s->bytes = sealedOf.at(order.back());
        return std::make_unique<ScriptedSource>(s);
    });
    EXPECT_EQ(contents::fetchOutstanding(engine->vault->id, 10), 3u);
    EXPECT_EQ(order.front(), vl::keykit::toBase32(high.expected.object_uid));
    EXPECT_EQ(PendingContents::countOutstanding(engine->vault->id), 0u);
    EXPECT_EQ(readBack(later), later.plaintext);

    // Only a mirror waits for contents: a vault this server is not the mirror of refuses.
    const auto plain = ops::vaults::create(superUser, {.name = "mc_plain_" + tag(), .type = vault::model::VaultType::Local,
                                                       .owner_id = superUser->id});
    auto e = low.expected;
    e.vault_id = plain->id;
    EXPECT_THROW(PendingContents::expect(e), ops::NotFound);
    auto malformed = low.expected;
    malformed.content_hash = "nothex";
    EXPECT_THROW(PendingContents::expect(malformed), ops::Invalid);
    EXPECT_FALSE(PendingContents::mayHavePending(plain->id));
}

// The slots (no database): a fixed number per peer, background work never takes the last one, and a person's open goes
// ahead of every waiting background transfer.
TEST(PeerTransfersTest, InteractiveGoesAheadAndBackgroundNeverTakesTheLastSlot) {
    vh::peer::Transfers t;
    const auto now = [] { return std::chrono::steady_clock::now(); };
    std::vector<vh::peer::Transfers::Slot> background;
    for (unsigned i = 0; i < vh::peer::kTransfersPerPeer - vh::peer::kReservedForInteractive; ++i) {
        background.push_back(t.acquire(7, vh::peer::TransferPriority::Background, now()));
        ASSERT_TRUE(background.back());
    }
    EXPECT_FALSE(t.acquire(7, vh::peer::TransferPriority::Background, now())) << "the reserved slot";
    auto interactive = t.acquire(7, vh::peer::TransferPriority::Interactive, now());
    ASSERT_TRUE(interactive);
    EXPECT_EQ(t.inFlight(7), vh::peer::kTransfersPerPeer);
    EXPECT_TRUE(t.acquire(8, vh::peer::TransferPriority::Background, now())) << "per peer";
    background.clear();
    interactive = {};
    EXPECT_EQ(t.inFlight(7), 0u);

    // Full (one background, three interactive): a background request waits, then a person's. Two slots free: the
    // person's goes first, and the background one may not take the other while a person waits, nor the last one.
    auto bgHeld = t.acquire(7, vh::peer::TransferPriority::Background, now());
    std::vector<vh::peer::Transfers::Slot> fgHeld;
    for (int i = 0; i < 3; ++i) fgHeld.push_back(t.acquire(7, vh::peer::TransferPriority::Interactive, now()));
    ASSERT_EQ(t.inFlight(7), vh::peer::kTransfersPerPeer);
    std::atomic<bool> bgGranted{false}, fgGranted{false};
    vh::peer::Transfers::Slot bgSlot, fgSlot;
    std::thread bg([&] {
        bgSlot = t.acquire(7, vh::peer::TransferPriority::Background, now() + 5s);
        bgGranted = static_cast<bool>(bgSlot);
    });
    std::this_thread::sleep_for(50ms);
    std::thread fg([&] {
        fgSlot = t.acquire(7, vh::peer::TransferPriority::Interactive, now() + 5s);
        fgGranted = static_cast<bool>(fgSlot);
    });
    std::this_thread::sleep_for(50ms);
    fgHeld.pop_back();
    fgHeld.pop_back();
    fg.join();
    EXPECT_TRUE(fgGranted.load());
    std::this_thread::sleep_for(100ms);
    EXPECT_FALSE(bgGranted.load()) << "three busy: the last slot is a person's";
    fgSlot = {};
    bg.join();
    EXPECT_TRUE(bgGranted.load());
    bgSlot = {};
    bgHeld = {};
    fgHeld.clear();

    // Stopping wakes every waiter without a slot, and refuses new work.
    for (unsigned i = 0; i < vh::peer::kTransfersPerPeer; ++i)
        background.push_back(t.acquire(7, vh::peer::TransferPriority::Interactive, now()));
    std::atomic<bool> woke{false};
    std::thread waiter([&] {
        EXPECT_FALSE(t.acquire(7, vh::peer::TransferPriority::Interactive, now() + 10s));
        woke = true;
    });
    std::this_thread::sleep_for(50ms);
    const auto stopAt = now();
    t.shutdown();
    waiter.join();
    EXPECT_TRUE(woke.load());
    EXPECT_LT(now() - stopAt, 2s);
    EXPECT_FALSE(t.spawn([] {}));
    background.clear();
}

}
