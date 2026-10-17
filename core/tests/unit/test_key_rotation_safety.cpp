// Vault key rotation must never leave a file the vault can no longer decrypt (audit D2-D4). These tests drive the
// rotation protocol (sync/rotation/Rotation.hpp) with real AES-256-GCM and a stand-in for EncryptionManager that
// keeps the same key rules: during a rotation the current and previous versions decrypt, after it only the current
// one does. The files table is a map with compare-and-set semantics, the remote store a map of objects that carry
// their own IV/version metadata. No TPM, database or S3.

#include "crypto/util/encrypt.hpp"
#include "crypto/util/verify.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "sync/rotation/Rotation.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace vh::test_key_rotation_safety {

namespace stdfs = std::filesystem;
namespace cu = crypto::util;
namespace rotation = sync::rotation;
using rotation::EncryptionState;
using rotation::FileSP;
using rotation::Outcome;
using rotation::PassStatus;
using rotation::Step;

using Bytes = std::vector<uint8_t>;

Bytes slurpBytes(const stdfs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void spitBytes(const stdfs::path& path, const Bytes& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

Bytes randomBytes(const std::size_t n) {
    Bytes out(n);
    randombytes_buf(out.data(), out.size());
    return out;
}

// EncryptionManager's key rules without the TPM.
struct FakeVaultKeys {
    std::map<unsigned int, Bytes> keys;
    unsigned int version = 1;
    bool inProgress = false;

    FakeVaultKeys() { keys[1] = randomBytes(cu::AES_KEY_SIZE); }

    void prepare() {
        ++version;
        keys[version] = randomBytes(cu::AES_KEY_SIZE);
        inProgress = true;
    }

    void finish() {
        for (auto it = keys.begin(); it != keys.end();) it = it->first == version ? std::next(it) : keys.erase(it);
        inProgress = false;
    }

    // Same as EncryptionManager::keyFor: throws outside a rotation for anything but the current version.
    [[nodiscard]] const Bytes& keyFor(const unsigned int v) const {
        if (inProgress) {
            if (v == version - 1 && keys.contains(v)) return keys.at(v);
            return keys.at(version);
        }
        if (v != version) throw std::runtime_error("Key version mismatch");
        return keys.at(version);
    }

    Bytes seal(const Bytes& plaintext, const FileSP& f) const {
        Bytes iv;
        auto out = cu::encrypt_aes256_gcm(plaintext, keys.at(version), iv);
        f->encryption_iv = cu::b64_encode(iv);
        f->encrypted_with_key_version = version;
        return out;
    }

    Bytes open(const Bytes& ciphertext, const EncryptionState& state) const {
        return cu::decrypt_aes256_gcm(ciphertext, keyFor(state.key_version), cu::b64_decode(state.iv_b64));
    }

    Bytes reseal(const Bytes& ciphertext, const FileSP& f) const {
        if (!inProgress) throw std::runtime_error("Key rotation not in progress");
        return seal(open(ciphertext, rotation::stateOf(*f)), f);
    }

    bool fileAuthenticates(const stdfs::path& path, const EncryptionState& state) const {
        if (!state.encrypted()) return false;
        try {
            const auto& key = keyFor(state.key_version);
            return cu::aes256_gcm_file_authenticates(path, key, cu::b64_decode(state.iv_b64));
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()) == "Key version mismatch") return false;
            throw;
        }
    }

    bool bufferAuthenticates(const Bytes& bytes, const EncryptionState& state) const {
        try {
            (void)open(bytes, state);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }
};

struct RemoteObject {
    Bytes bytes;
    std::optional<EncryptionState> state;
};

class KeyRotationSafetyTest : public ::testing::Test {
protected:
    stdfs::path dir;
    FakeVaultKeys keys;

    // The files table: vault path -> (IV, key version), and where each file's bytes live.
    std::map<std::string, EncryptionState> rows;
    std::map<std::string, stdfs::path> backingOf;
    std::map<std::string, Bytes> plaintextOf;

    // The remote store (cloud tests).
    bool cloud = false;
    bool encryptUpstream = true;
    std::map<std::string, RemoteObject> objects;
    unsigned int uploads = 0;

    // Fault injection.
    std::set<std::string> failReseal;
    std::set<std::string> busy;
    std::optional<Step> crashAt;
    std::string crashPath;
    std::function<void(Step, const FileSP&)> onStep;
    bool commitThrowsAfterApplying = false;

    unsigned int finishes = 0;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        if (crypto_aead_aes256gcm_is_available() == 0) GTEST_SKIP() << "AES-256-GCM is not available on this CPU";
        dir = stdfs::temp_directory_path() / ("vh_rot_" + std::to_string(::getpid()) + "_" +
                                              ::testing::UnitTest::GetInstance()->current_test_info()->name());
        stdfs::remove_all(dir);
        stdfs::create_directories(dir / "vault" / "sub");
    }

    void TearDown() override { stdfs::remove_all(dir); }

    FileSP fileFor(const std::string& path) const {
        auto f = std::make_shared<fs::model::File>();
        f->vault_id = 1;
        f->path = path;
        f->backing_path = backingOf.at(path);
        f->content_hash = "hash-of-" + path;
        const auto& row = rows.at(path);
        f->encryption_iv = row.iv_b64;
        f->encrypted_with_key_version = row.key_version;
        return f;
    }

    // An encrypted file at rest under the current key: local copy and/or remote object.
    void addFile(const std::string& path, const std::size_t size, const bool local = true, const bool remote = false) {
        backingOf[path] = dir / "vault" / (path == "/a" || path == "/b" ? "" : "sub") / ("ALIAS" + path.substr(1));
        plaintextOf[path] = randomBytes(size);
        rows[path] = {};
        const auto f = fileFor(path);
        const auto ciphertext = keys.seal(plaintextOf[path], f);
        rows[path] = rotation::stateOf(*f);
        if (local) spitBytes(f->backing_path, ciphertext);
        if (remote) objects[path] = {ciphertext, rotation::stateOf(*f)};
    }

    // An empty file: no bytes sealed, no IV, key version 0.
    void addEmptyFile(const std::string& path) {
        backingOf[path] = dir / "vault" / ("ALIAS" + path.substr(1));
        plaintextOf[path] = {};
        rows[path] = {.iv_b64 = "", .key_version = 0};
        spitBytes(backingOf[path], {});
    }

    // What the files-table query returns: encrypted rows on an older key version, as fresh objects.
    std::vector<FileSP> pending(const unsigned int version) const {
        std::vector<FileSP> out;
        for (const auto& [path, row] : rows)
            if (row.encrypted() && row.key_version < version) out.push_back(fileFor(path));
        return out;
    }

    rotation::Deps deps() {
        rotation::Deps d;
        d.crypto.currentKeyVersion = [this] { return keys.version; };
        d.crypto.reseal = [this](const Bytes& ciphertext, const FileSP& f) {
            if (failReseal.contains(f->path.string())) throw std::runtime_error("injected re-encryption failure");
            return keys.reseal(ciphertext, f);
        };
        d.crypto.seal = [this](const Bytes& plaintext, const FileSP& f) { return keys.seal(plaintext, f); };
        d.crypto.open = [this](const Bytes& ciphertext, const EncryptionState& s) { return keys.open(ciphertext, s); };
        d.crypto.fileAuthenticates = [this](const stdfs::path& p, const EncryptionState& s) {
            return keys.fileAuthenticates(p, s);
        };
        d.crypto.bufferAuthenticates = [this](const Bytes& b, const EncryptionState& s) {
            return keys.bufferAuthenticates(b, s);
        };
        d.catalog.commit = [this](const fs::model::File& f, const EncryptionState& expected) {
            auto& row = rows.at(f.path.string());
            if (!(row == expected)) return false;
            row = rotation::stateOf(f);
            if (commitThrowsAfterApplying) throw std::runtime_error("connection lost after COMMIT");
            return true;
        };
        d.catalog.busy = [this](const FileSP& f) { return busy.contains(f->path.string()); };
        d.afterStep = [this](const Step step, const FileSP& f) {
            if (crashAt && *crashAt == step && f->path.string() == crashPath) throw rotation::SimulatedCrash{step};
            if (onStep) onStep(step, f);
        };
        if (cloud) {
            rotation::Remote remote;
            remote.encryptUpstream = encryptUpstream;
            remote.download = [this](const FileSP& f) { return objects.at(f->path.string()).bytes; };
            remote.objectState = [this](const FileSP& f) { return objects.at(f->path.string()).state; };
            remote.upload = [this](const FileSP& f, const Bytes& bytes, const bool isCiphertext) {
                ++uploads;
                objects[f->path.string()] = {bytes, isCiphertext ? std::make_optional(rotation::stateOf(*f))
                                                                 : std::nullopt};
            };
            d.remote = remote;
        }
        return d;
    }

    rotation::BackingLookup lookup() {
        return [this](const stdfs::path& backing) -> FileSP {
            for (const auto& [path, b] : backingOf)
                if (b == backing) return fileFor(path);
            return nullptr;
        };
    }

    rotation::PassResult runPass(const rotation::Deps& d) {
        rotation::PassDeps pass;
        pass.inProgress = [this] { return keys.inProgress; };
        pass.keyVersion = [this] { return keys.version; };
        pass.recover = [this, &d] { return rotation::recoverSidecars(dir / "vault", lookup(), d); };
        pass.pending = [this](const unsigned int v) { return pending(v); };
        pass.rotateAll = [&d](const std::vector<FileSP>& files) {
            rotation::BatchResult total;
            for (const auto& [b, e] : rotation::splitRanges(files.size(), 2)) total.merge(rotation::rotateRange(files, b, e, d));
            return total;
        };
        pass.finish = [this] {
            keys.finish();
            ++finishes;
        };
        return rotation::runPass(pass);
    }

    // The local copy decrypts, under what its row says, to the original plaintext.
    void expectLocalDecryptable(const std::string& path) const {
        const auto& row = rows.at(path);
        ASSERT_TRUE(row.encrypted()) << path;
        EXPECT_EQ(keys.open(slurpBytes(backingOf.at(path)), row), plaintextOf.at(path)) << path;
    }

    void expectRemoteDecryptable(const std::string& path) const {
        const auto& object = objects.at(path);
        ASSERT_TRUE(object.state) << path;
        EXPECT_EQ(keys.open(object.bytes, *object.state), plaintextOf.at(path)) << path;
    }

    std::size_t sidecarsUnder(const stdfs::path& root) const {
        std::size_t n = 0;
        for (const auto& e : stdfs::recursive_directory_iterator(root))
            n += rotation::isSidecar(e.path()) ? 1 : 0;
        return n;
    }

    std::size_t tempFilesIn(const stdfs::path& d) const {
        std::size_t n = 0;
        for (const auto& e : stdfs::directory_iterator(d))
            n += e.path().filename().string().find(".vh-tmp-") != std::string::npos ? 1 : 0;
        return n;
    }
};

// ---- D2: rotation finishes only when every file made it ------------------------------------------------------------

TEST_F(KeyRotationSafetyTest, AFailedFileKeepsTheRotationInProgressAndARetryFinishesIt) {
    for (const auto* p : {"/a", "/b", "/c", "/d", "/e"}) addFile(p, 1000);
    keys.prepare();
    const auto d = deps();

    failReseal.insert("/c");
    const auto first = runPass(d);

    EXPECT_EQ(first.status, PassStatus::Incomplete);
    EXPECT_EQ(first.batch.failures.size(), 1u);
    EXPECT_EQ(first.batch.rotated, 4u) << "one file failing does not stop the rest of its range";
    EXPECT_EQ(first.remaining, 1u);
    EXPECT_EQ(finishes, 0u);
    EXPECT_TRUE(keys.inProgress) << "the previous key stays loaded";
    EXPECT_EQ(rows["/c"].key_version, 1u);
    for (const auto& [path, _] : rows) expectLocalDecryptable(path);

    failReseal.clear();
    const auto retry = runPass(d);

    EXPECT_EQ(retry.status, PassStatus::Finished);
    EXPECT_EQ(retry.batch.rotated, 1u);
    EXPECT_EQ(finishes, 1u);
    EXPECT_FALSE(keys.inProgress);
    EXPECT_EQ(keys.keys.size(), 1u) << "only now is the previous key dropped";
    for (const auto& [path, row] : rows) {
        EXPECT_EQ(row.key_version, 2u) << path;
        expectLocalDecryptable(path);
    }
    EXPECT_EQ(sidecarsUnder(dir / "vault"), 0u);
}

TEST_F(KeyRotationSafetyTest, EmptyAndUnencryptedFilesDoNotBreakRotation) {
    addFile("/a", 64);
    addEmptyFile("/empty");
    addFile("/b", 64);
    keys.prepare();
    const auto d = deps();

    // Even if a caller hands one over (as the old query did), an IV-less file is skipped, not decrypted.
    std::vector<FileSP> files{fileFor("/a"), fileFor("/empty"), fileFor("/b")};
    const auto batch = rotation::rotateRange(files, 0, files.size(), d);
    EXPECT_TRUE(batch.failures.empty());
    EXPECT_EQ(batch.skipped, 1u);
    EXPECT_EQ(batch.rotated, 2u);

    const auto pass = runPass(d);
    EXPECT_EQ(pass.status, PassStatus::Finished);
    EXPECT_EQ(rows["/empty"].key_version, 0u);
    EXPECT_TRUE(slurpBytes(backingOf["/empty"]).empty());
    expectLocalDecryptable("/a");
    expectLocalDecryptable("/b");
}

TEST_F(KeyRotationSafetyTest, AFileOpenForWritingIsDeferredNotFailed) {
    addFile("/a", 128);
    addFile("/b", 128);
    keys.prepare();
    const auto d = deps();

    busy.insert("/b");
    const auto first = runPass(d);
    EXPECT_EQ(first.status, PassStatus::Incomplete);
    EXPECT_TRUE(first.batch.failures.empty());
    EXPECT_EQ(first.batch.deferred, 1u);
    EXPECT_TRUE(keys.inProgress);
    expectLocalDecryptable("/b");

    busy.clear();
    EXPECT_EQ(runPass(d).status, PassStatus::Finished);
    expectLocalDecryptable("/b");
}

TEST_F(KeyRotationSafetyTest, ARowChangedMidRotationWinsAndTheSidecarIsDropped) {
    addFile("/a", 256);
    keys.prepare();
    const auto d = deps();
    const auto before = slurpBytes(backingOf["/a"]);

    // A concurrent writer re-seals the file between the sidecar write and the commit.
    onStep = [this](const Step step, const FileSP&) {
        if (step != Step::SidecarWritten) return;
        const auto writer = fileFor("/a");
        plaintextOf["/a"] = randomBytes(300);
        const auto sealed = keys.seal(plaintextOf["/a"], writer);
        stdfs::path temp = backingOf["/a"];
        temp += ".writer";
        spitBytes(temp, sealed);
        stdfs::rename(temp, backingOf["/a"]);
        rows["/a"] = rotation::stateOf(*writer);
    };

    EXPECT_EQ(rotation::rotateFile(fileFor("/a"), d), Outcome::Conflict);
    EXPECT_EQ(sidecarsUnder(dir / "vault"), 0u);
    EXPECT_NE(slurpBytes(backingOf["/a"]), before);
    expectLocalDecryptable("/a");
    EXPECT_EQ(rows["/a"].key_version, 2u) << "the writer sealed it with the current key";
}

TEST_F(KeyRotationSafetyTest, UnderTheContentLockAStaleListingIsAConflictAndNothingIsWritten) {
    addFile("/a", 256);
    keys.prepare();
    auto d = deps();
    const auto listed = fileFor("/a");  // what the pending-files query returned
    std::mutex fileLock;
    bool locked = false;
    d.catalog.lock = [&](const FileSP&) {
        locked = true;
        return std::unique_lock(fileLock);
    };
    // An overwrite (holding the same lock in production) re-sealed the file after the listing.
    const auto writer = fileFor("/a");
    plaintextOf["/a"] = randomBytes(64);
    spitBytes(backingOf["/a"], keys.seal(plaintextOf["/a"], writer));
    rows["/a"] = rotation::stateOf(*writer);
    d.catalog.current = [this](const FileSP&) -> std::optional<EncryptionState> { return rows.at("/a"); };
    const auto after = slurpBytes(backingOf["/a"]);

    EXPECT_EQ(rotation::rotateFile(listed, d), Outcome::Conflict);
    EXPECT_TRUE(locked);
    EXPECT_EQ(slurpBytes(backingOf["/a"]), after) << "the overwrite's bytes are never replaced with the stale listing";
    EXPECT_EQ(sidecarsUnder(dir / "vault"), 0u);
    expectLocalDecryptable("/a");
}

TEST_F(KeyRotationSafetyTest, SplitRangesCoversEveryCountIncludingOne) {
    // The old range helper divided by zero for a single file.
    EXPECT_TRUE(rotation::splitRanges(0, 8).empty());
    const auto one = rotation::splitRanges(1, 8);
    ASSERT_EQ(one.size(), 1u);
    EXPECT_EQ(one[0], std::make_pair(std::size_t{0}, std::size_t{1}));

    const auto ranges = rotation::splitRanges(7, 3);
    ASSERT_EQ(ranges.size(), 3u);
    std::size_t next = 0;
    for (const auto& [b, e] : ranges) {
        EXPECT_EQ(b, next);
        EXPECT_GT(e, b);
        next = e;
    }
    EXPECT_EQ(next, 7u);
}

// ---- D3: cloud copies ------------------------------------------------------------------------------------------------

TEST_F(KeyRotationSafetyTest, CacheModeLocalCopyIsRewrittenAndAuthenticatesUnderTheNewRow) {
    cloud = true;
    addFile("/a", 4096, true, true);
    keys.prepare();
    const auto d = deps();

    EXPECT_EQ(rotation::rotateFile(fileFor("/a"), d), Outcome::Rotated);

    EXPECT_EQ(rows["/a"].key_version, 2u);
    expectLocalDecryptable("/a");
    expectRemoteDecryptable("/a");
    EXPECT_EQ(*objects["/a"].state, rows["/a"]) << "the object's metadata matches the row";
    EXPECT_EQ(objects["/a"].bytes, slurpBytes(backingOf["/a"]));
    EXPECT_EQ(uploads, 1u);
    EXPECT_EQ(sidecarsUnder(dir / "vault"), 0u);
}

TEST_F(KeyRotationSafetyTest, CacheModeWithoutALocalCopyWritesNothingLocally) {
    cloud = true;
    addFile("/a", 4096, false, true);
    keys.prepare();
    const auto d = deps();

    EXPECT_EQ(rotation::rotateFile(fileFor("/a"), d), Outcome::Rotated);

    EXPECT_FALSE(stdfs::exists(backingOf["/a"]));
    EXPECT_TRUE(stdfs::is_empty(dir / "vault" / "sub")) << "no local bytes, no sidecar";
    EXPECT_EQ(rows["/a"].key_version, 2u);
    expectRemoteDecryptable("/a");
    EXPECT_EQ(*objects["/a"].state, rows["/a"]);
}

TEST_F(KeyRotationSafetyTest, PlaintextUpstreamVaultRotatesOnlyTheLocalCopy) {
    cloud = true;
    encryptUpstream = false;
    addFile("/a", 512, true, false);
    objects["/a"] = {plaintextOf["/a"], std::nullopt};
    keys.prepare();
    const auto d = deps();

    EXPECT_EQ(rotation::rotateFile(fileFor("/a"), d), Outcome::Rotated);
    EXPECT_EQ(uploads, 0u) << "the remote copy is plaintext: the vault key does not touch it";
    expectLocalDecryptable("/a");
}

TEST_F(KeyRotationSafetyTest, PlaintextUpstreamRemoteOnlyRowDropsItsStaleIv) {
    cloud = true;
    encryptUpstream = false;
    addFile("/a", 512, false, false);  // the row kept an IV from a local copy that was evicted
    objects["/a"] = {plaintextOf["/a"], std::nullopt};
    keys.prepare();
    const auto d = deps();

    EXPECT_EQ(runPass(d).status, PassStatus::Finished);
    EXPECT_FALSE(rows["/a"].encrypted());
    EXPECT_EQ(uploads, 0u);
    EXPECT_EQ(objects["/a"].bytes, plaintextOf["/a"]);
}

TEST_F(KeyRotationSafetyTest, EncryptUpstreamObjectWithoutMetadataIsNeverGuessedAt) {
    cloud = true;
    addFile("/a", 512, false, false);
    objects["/a"] = {randomBytes(528), std::nullopt};  // neither described nor the row's ciphertext
    keys.prepare();
    const auto d = deps();

    const auto pass = runPass(d);
    EXPECT_EQ(pass.status, PassStatus::Incomplete);
    EXPECT_EQ(pass.batch.failures.size(), 1u);
    EXPECT_EQ(uploads, 0u);
    EXPECT_TRUE(keys.inProgress);
}

// ---- D4: crash at every step leaves every file decryptable -----------------------------------------------------------

class KeyRotationCrashTest : public KeyRotationSafetyTest, public ::testing::WithParamInterface<Step> {};
class LocalVaultCrashTest : public KeyRotationCrashTest {};
class CloudLocalCopyCrashTest : public KeyRotationCrashTest {};
class RemoteOnlyCrashTest : public KeyRotationCrashTest {};

std::string stepName(const ::testing::TestParamInfo<Step>& info) {
    switch (info.param) {
        case Step::SidecarWritten: return "AfterSidecarWrite";
        case Step::Published: return "AfterUpload";
        case Step::Committed: return "AfterDbCommit";
        case Step::Renamed: return "AfterRename";
    }
    return "Unknown";
}

TEST_P(LocalVaultCrashTest, CrashAtEachStepRecoversToTheRow) {
    addFile("/a", 70000);  // more than one 64 KiB verification chunk
    addFile("/b", 100);
    keys.prepare();
    const auto d = deps();

    crashAt = GetParam();
    crashPath = "/a";
    EXPECT_THROW((void)rotation::rotateFile(fileFor("/a"), d), rotation::SimulatedCrash);

    const bool sidecarExpected = GetParam() != Step::Renamed;
    EXPECT_EQ(stdfs::exists(rotation::sidecarPathFor(backingOf["/a"])), sidecarExpected);

    // Restart: recovery runs before anything else reads the files.
    crashAt.reset();
    const auto report = rotation::recoverSidecars(dir / "vault", lookup(), d);
    EXPECT_EQ(report.unresolved, 0u);
    EXPECT_EQ(report.promoted, GetParam() == Step::Committed ? 1u : 0u);
    EXPECT_EQ(report.discarded, GetParam() == Step::SidecarWritten ? 1u : 0u);
    EXPECT_EQ(sidecarsUnder(dir / "vault"), 0u);
    expectLocalDecryptable("/a");
    expectLocalDecryptable("/b");

    EXPECT_EQ(runPass(d).status, PassStatus::Finished);
    for (const auto& [path, row] : rows) {
        EXPECT_EQ(row.key_version, 2u);
        expectLocalDecryptable(path);
    }
}

TEST_P(CloudLocalCopyCrashTest, CrashAtEachStepRecoversToTheRow) {
    cloud = true;
    addFile("/a", 3000, true, true);
    keys.prepare();
    const auto d = deps();

    crashAt = GetParam();
    crashPath = "/a";
    EXPECT_THROW((void)rotation::rotateFile(fileFor("/a"), d), rotation::SimulatedCrash);

    crashAt.reset();
    const auto report = rotation::recoverSidecars(dir / "vault", lookup(), d);
    EXPECT_EQ(report.unresolved, 0u);
    expectLocalDecryptable("/a");
    expectRemoteDecryptable("/a");  // the object always describes itself

    EXPECT_EQ(runPass(d).status, PassStatus::Finished);
    EXPECT_EQ(rows["/a"].key_version, 2u);
    expectLocalDecryptable("/a");
    expectRemoteDecryptable("/a");
    EXPECT_EQ(*objects["/a"].state, rows["/a"]);
}

TEST_P(RemoteOnlyCrashTest, CrashAtEachStepRecoversToTheRow) {
    cloud = true;
    addFile("/a", 3000, false, true);
    keys.prepare();
    const auto d = deps();

    crashAt = GetParam();
    crashPath = "/a";
    EXPECT_THROW((void)rotation::rotateFile(fileFor("/a"), d), rotation::SimulatedCrash);
    crashAt.reset();
    expectRemoteDecryptable("/a");

    const auto uploadsBefore = uploads;
    EXPECT_EQ(runPass(d).status, PassStatus::Finished);
    if (GetParam() == Step::Published) {
        EXPECT_EQ(uploads, uploadsBefore) << "an uploaded but uncommitted object is adopted, not uploaded again";
    }
    EXPECT_EQ(*objects["/a"].state, rows["/a"]);
    expectRemoteDecryptable("/a");
    EXPECT_FALSE(stdfs::exists(backingOf["/a"]));
}

// Local vaults: no upload. Cloud with a local copy: every step. Remote only: nothing is written locally.
INSTANTIATE_TEST_SUITE_P(Steps, LocalVaultCrashTest,
                         ::testing::Values(Step::SidecarWritten, Step::Committed, Step::Renamed), stepName);
INSTANTIATE_TEST_SUITE_P(Steps, CloudLocalCopyCrashTest,
                         ::testing::Values(Step::SidecarWritten, Step::Published, Step::Committed, Step::Renamed),
                         stepName);
INSTANTIATE_TEST_SUITE_P(Steps, RemoteOnlyCrashTest, ::testing::Values(Step::Published, Step::Committed), stepName);

TEST_F(KeyRotationSafetyTest, ACommitThatFailsAfterApplyingKeepsTheSidecarForRecovery) {
    addFile("/a", 2048);
    keys.prepare();
    const auto d = deps();

    commitThrowsAfterApplying = true;
    EXPECT_THROW((void)rotation::rotateFile(fileFor("/a"), d), std::runtime_error);
    commitThrowsAfterApplying = false;

    EXPECT_TRUE(stdfs::exists(rotation::sidecarPathFor(backingOf["/a"]))) << "the row may already describe it";
    const auto report = rotation::recoverSidecars(dir / "vault", lookup(), d);
    EXPECT_EQ(report.promoted, 1u);
    expectLocalDecryptable("/a");
}

TEST_F(KeyRotationSafetyTest, ATornSidecarIsDiscardedAndAnUnverifiableOneBlocksFinishing) {
    addFile("/a", 2048);
    addFile("/b", 2048);
    keys.prepare();
    const auto d = deps();

    // Crash mid-write: a partial sidecar, row untouched.
    auto torn = slurpBytes(backingOf["/a"]);
    torn.resize(torn.size() / 2);
    spitBytes(rotation::sidecarPathFor(backingOf["/a"]), torn);

    // Damage that leaves neither copy authenticating: kept for an operator, rotation not finished.
    spitBytes(rotation::sidecarPathFor(backingOf["/b"]), randomBytes(2064));
    const auto goodB = slurpBytes(backingOf["/b"]);
    auto badB = goodB;
    badB[10] ^= 0xFF;
    spitBytes(backingOf["/b"], badB);

    const auto pass = runPass(d);
    EXPECT_EQ(pass.recovery.discarded, 1u);
    EXPECT_EQ(pass.recovery.unresolved, 1u);
    EXPECT_EQ(pass.status, PassStatus::Incomplete);
    EXPECT_TRUE(keys.inProgress);
    EXPECT_TRUE(stdfs::exists(rotation::sidecarPathFor(backingOf["/b"])));
    expectLocalDecryptable("/a");
}

TEST_F(KeyRotationSafetyTest, AnOrphanSidecarIsRemoved) {
    addFile("/a", 64);
    keys.prepare();
    const auto d = deps();
    const auto orphan = dir / "vault" / "sub" / "GONE.vh-rotate";
    spitBytes(orphan, randomBytes(80));

    const auto report = rotation::recoverSidecars(dir / "vault", lookup(), d);
    EXPECT_EQ(report.discarded, 1u);
    EXPECT_FALSE(stdfs::exists(orphan));
}

// ---- Atomic replacement and verification primitives ------------------------------------------------------------------

TEST_F(KeyRotationSafetyTest, WriteFileAtomicReplacesAndPreservesPermissions) {
    const auto target = dir / "vault" / "file";
    spitBytes(target, {1, 2, 3});
    ASSERT_EQ(::chmod(target.c_str(), 0640), 0);

    const Bytes next{9, 8, 7, 6};
    fs::ops::writeFileAtomic(target, next);
    EXPECT_EQ(slurpBytes(target), next);

    struct stat st{};
    ASSERT_EQ(::stat(target.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 07777, 0640u);
    EXPECT_EQ(tempFilesIn(dir / "vault"), 0u);

    const auto fresh = dir / "vault" / "fresh";
    fs::ops::writeFileAtomic(fresh, next);
    ASSERT_EQ(::stat(fresh.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 07777, 0600u) << "a new ciphertext file is owner-only";
}

TEST_F(KeyRotationSafetyTest, AFailedAtomicReplacementLeavesTheOldFileAndNoTemp) {
    const auto target = dir / "vault" / "file";
    const Bytes old{1, 2, 3, 4, 5};
    spitBytes(target, old);

    EXPECT_THROW(fs::ops::replaceFileAtomic(target, [](const stdfs::path& temp) {
        spitBytes(temp, {42, 42});  // half-written
        throw std::runtime_error("encryption failed midway");
    }), std::runtime_error);

    EXPECT_EQ(slurpBytes(target), old);
    EXPECT_EQ(tempFilesIn(dir / "vault"), 0u);
}

TEST_F(KeyRotationSafetyTest, WriteFileExclusiveNeverReplacesAnExistingFile) {
    const auto target = dir / "vault" / "taken";
    const Bytes old{7, 7, 7};
    spitBytes(target, old);
    EXPECT_THROW(fs::ops::writeFileExclusive(target, Bytes{1}), std::system_error);
    EXPECT_EQ(slurpBytes(target), old);
}

// FUSE create and an empty createFile make an empty inode: there is no data to flush, so no file fsync (the
// pre-recovery ofstream create had none either). Content still is fsynced.
TEST_F(KeyRotationSafetyTest, WriteFileExclusiveSkipsTheFsyncOfAnEmptyFile) {
    const auto before = fs::ops::writeFileExclusiveFsyncsForTesting();
    const auto empty = dir / "vault" / "empty";
    fs::ops::writeFileExclusive(empty, {}, 0640);
    EXPECT_EQ(fs::ops::writeFileExclusiveFsyncsForTesting(), before) << "an empty create costs no fsync";
    struct stat st{};
    ASSERT_EQ(::stat(empty.c_str(), &st), 0);
    EXPECT_EQ(st.st_size, 0);
    EXPECT_EQ(st.st_mode & 07777, 0640u);
    EXPECT_THROW(fs::ops::writeFileExclusive(empty, {}), std::system_error) << "still exclusive";

    fs::ops::writeFileExclusive(dir / "vault" / "full", Bytes{1, 2, 3});
    EXPECT_EQ(fs::ops::writeFileExclusiveFsyncsForTesting(), before + 1) << "content is fsynced";
}

TEST_F(KeyRotationSafetyTest, StreamingVerificationMatchesTheTag) {
    const auto key = randomBytes(cu::AES_KEY_SIZE);
    Bytes iv;
    const auto ciphertext = cu::encrypt_aes256_gcm(randomBytes(200000), key, iv);
    const auto path = dir / "vault" / "ct";
    spitBytes(path, ciphertext);
    EXPECT_TRUE(cu::aes256_gcm_file_authenticates(path, key, iv));

    EXPECT_FALSE(cu::aes256_gcm_file_authenticates(path, randomBytes(cu::AES_KEY_SIZE), iv));
    auto tampered = ciphertext;
    tampered[150000] ^= 1;
    spitBytes(path, tampered);
    EXPECT_FALSE(cu::aes256_gcm_file_authenticates(path, key, iv));

    spitBytes(path, Bytes(5, 0));
    EXPECT_FALSE(cu::aes256_gcm_file_authenticates(path, key, iv)) << "shorter than a tag";
    EXPECT_THROW((void)cu::aes256_gcm_file_authenticates(dir / "missing", key, iv), std::exception);
}

}
