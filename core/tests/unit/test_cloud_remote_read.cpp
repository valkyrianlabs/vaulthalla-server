// Remote-only reads on cloud vaults (CloudEngine::openMissingReader): hydrate-first, the opt-in ranged reader,
// policy off, and D11 (paths that read a cloud file prefer its local ciphertext copy over an S3 GET). DB-free: a fake
// S3 transport behind the real s3::Controller::streamObject metering, an injected price gate and catalog commit.

#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "fs/model/File.hpp"
#include "protocols/s3/Error.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "protocols/ws/handler/share/Download.hpp"
#include "protocols/ws/handler/share/Preview.hpp"
#include "share/TargetResolver.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/GcmFileReader.hpp"
#include "storage/RemoteRangedReader.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>
#include <sodium.h>
#include <sys/stat.h>

#include <algorithm>
#include <atomic>
#include <barrier>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace vh::storage::test_cloud_remote_read {

using FileModel = ::vh::fs::model::File;

inline namespace fakes {

constexpr uint32_t kVaultId = 501;
constexpr unsigned int kKeyVersion = 3;

std::vector<uint8_t> randomBytes(const std::size_t n, const uint32_t seed) {
    std::vector<uint8_t> out(n);
    std::mt19937 rng(seed);
    for (auto& b : out) b = static_cast<uint8_t>(rng());
    return out;
}

std::vector<uint8_t> readFile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

void writeFile(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::shared_ptr<vault::model::APIKey> unitApiKey() {
    return std::make_shared<vault::model::APIKey>(
        1, "unit", vault::model::S3Provider::AWS, "ABCDEFGHIJKLMNOPQRST",
        "ABCDEFGHIJKLMNOPQRSTABCDEFGHIJKLMNOPQRST", "us-east-1", "https://s3.example.com");
}

// An in-memory bucket behind the real streamObject: metering, status mapping and Range/If-Match handling are the
// production code; only the wire is fake. HEAD meters like the real getHeadObject.
class FakeBucket final : public s3::Controller {
public:
    struct Object {
        std::vector<uint8_t> body;
        std::string etag;
        std::map<std::string, std::string> meta;  // x-amz-meta-* and storage headers
    };

    struct Get {
        std::string key;
        std::optional<std::string> range;
        std::optional<std::string> ifMatch;
    };

    FakeBucket() : Controller(unitApiKey(), "unit-bucket") {}

    void put(const std::string& key, Object object) {
        std::scoped_lock lock(mutex_);
        objects_[key] = std::move(object);
    }

    void mutate(const std::string& key, const std::function<void(Object&)>& fn) {
        Object copy;
        {
            std::scoped_lock lock(mutex_);
            copy = objects_.at(key);
        }
        fn(copy);
        std::scoped_lock lock(mutex_);
        objects_[key] = std::move(copy);
    }

    void peek(const std::string& key, Object& out) const {
        std::scoped_lock lock(mutex_);
        out = objects_.at(key);
    }

    [[nodiscard]] std::vector<Get> gets() const {
        std::scoped_lock lock(mutex_);
        return gets_;
    }

    [[nodiscard]] int heads() const { return heads_.load(); }

    std::chrono::milliseconds getDelay{0};

    std::optional<std::unordered_map<std::string, std::string>> getHeadObject(const fs::path& key) const override {
        recordRequest(RequestKind::Head);
        ++heads_;
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key.string());
        if (it == objects_.end()) return std::nullopt;
        std::unordered_map<std::string, std::string> headers{
            {"ETag", it->second.etag},
            {"Content-Length", std::to_string(it->second.body.size())},
        };
        for (const auto& [name, value] : it->second.meta) headers[name] = value;
        return headers;
    }

protected:
    TransportResponse transportGet(const fs::path& key, const std::map<std::string, std::string>& extraHeaders,
                                   const TransportBodyFn& onBody) const override {
        Get get{.key = key.string(), .range = {}, .ifMatch = {}};
        if (const auto it = extraHeaders.find("range"); it != extraHeaders.end()) get.range = it->second;
        if (const auto it = extraHeaders.find("if-match"); it != extraHeaders.end()) get.ifMatch = it->second;
        {
            std::scoped_lock lock(mutex_);
            gets_.push_back(get);
        }
        if (getDelay.count() > 0) std::this_thread::sleep_for(getDelay);

        Object object;
        {
            std::scoped_lock lock(mutex_);
            const auto it = objects_.find(key.string());
            if (it == objects_.end()) return deliver(404, toBytes("<Error><Code>NoSuchKey</Code></Error>"), onBody);
            object = it->second;
        }
        if (get.ifMatch && *get.ifMatch != object.etag)
            return deliver(412, toBytes("<Error><Code>PreconditionFailed</Code></Error>"), onBody);
        if (get.range) {
            const auto spec = get.range->substr(std::string("bytes=").size());
            const auto dash = spec.find('-');
            const auto first = std::stoull(spec.substr(0, dash));
            auto last = std::stoull(spec.substr(dash + 1));
            if (first >= object.body.size()) return deliver(416, {}, onBody);
            last = std::min<uint64_t>(last, object.body.size() - 1);
            return deliver(206, {object.body.begin() + static_cast<std::ptrdiff_t>(first),
                                 object.body.begin() + static_cast<std::ptrdiff_t>(last + 1)}, onBody, object.etag);
        }
        return deliver(200, object.body, onBody, object.etag);
    }

private:
    static std::vector<uint8_t> toBytes(const std::string& s) { return {s.begin(), s.end()}; }

    static TransportResponse deliver(const long status, const std::vector<uint8_t>& body, const TransportBodyFn& onBody,
                                     const std::string& etag = {}) {
        TransportResponse response;
        response.http_status = status;
        if (!etag.empty()) response.headers = "ETag: " + etag + "\r\n";
        constexpr std::size_t chunk = 16 * 1024;
        for (std::size_t off = 0; off < body.size(); off += chunk) {
            const auto n = std::min(chunk, body.size() - off);
            if (!onBody(status, {body.data() + off, n})) {
                response.transport_ok = false;
                response.transport_error = "aborted";
                return response;
            }
        }
        return response;
    }

    mutable std::mutex mutex_;
    std::map<std::string, Object> objects_;
    mutable std::vector<Get> gets_;
    mutable std::atomic<int> heads_{0};
};

class FakeReservation final : public RemoteFetchReservation {
public:
    struct Log {
        std::mutex mutex;
        std::vector<RemoteFetchRequest> requests;
        std::vector<s3::S3GatewayUpstreamUsage> commits;
        int releases{0};
    };

    explicit FakeReservation(std::shared_ptr<Log> log) : log_(std::move(log)) {}
    void commit(const s3::S3GatewayUpstreamUsage& actual) noexcept override {
        if (settled_) return;
        settled_ = true;
        std::scoped_lock lock(log_->mutex);
        log_->commits.push_back(actual);
    }
    void release() noexcept override {
        if (settled_) return;
        settled_ = true;
        std::scoped_lock lock(log_->mutex);
        ++log_->releases;
    }

private:
    std::shared_ptr<Log> log_;
    bool settled_{false};
};

class TempDir {
public:
    TempDir() {
        path_ = std::filesystem::temp_directory_path() /
                ("vh_cloud_remote_read_" + std::to_string(::getpid()) + "_" + std::to_string(counter_++));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
    static inline std::atomic<int> counter_{0};
};

}

class CloudRemoteReadTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        key_ = randomBytes(crypto::util::AES_KEY_SIZE, 11);
        vault_ = std::make_shared<vault::model::S3Vault>();
        vault_->id = kVaultId;
        vault_->encrypt_upstream = true;

        engine_ = std::make_shared<CloudEngine>();
        engine_->vault = vault_;
        engine_->encryptionManager =
            std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, kVaultId, key_, kKeyVersion);
        engine_->setS3ControllerForTesting(bucket_);
        engine_->setRemoteFetchGate([log = gateLog_, this](const CloudEngine&, const RemoteFetchRequest& request)
                                        -> std::unique_ptr<RemoteFetchReservation> {
            {
                std::scoped_lock lock(log->mutex);
                log->requests.push_back(request);
            }
            if (refusePrice_) throw ContentUnavailable("S3 price budget refused " + request.operation + " (test)");
            return std::make_unique<FakeReservation>(log);
        });
        engine_->setHydrateCatalogCommitForTesting(
            [this](const FileModel& updated, const std::string& expectedIv, const unsigned int expectedVersion) {
                catalogCommits_.push_back({updated.encryption_iv, updated.encrypted_with_key_version, expectedIv,
                                           expectedVersion, std::filesystem::exists(updated.backing_path)});
                return catalogAccepts_;
            });
    }

    // A remote-only encrypted object (Cache strategy, index-only row: the row carries the remote IV).
    std::shared_ptr<FileModel> remoteEncrypted(const std::string& path, const std::vector<uint8_t>& plaintext) {
        std::vector<uint8_t> iv;
        const auto sealed = crypto::util::encrypt_aes256_gcm(plaintext, key_, iv);
        const auto ivB64 = crypto::util::b64_encode(iv);
        bucket_->put(path.substr(1), FakeBucket::Object{
            .body = sealed,
            .etag = "\"etag-" + std::to_string(++etagCounter_) + "\"",
            .meta = {{"x-amz-meta-vh-encrypted", "true"},
                     {"x-amz-meta-vh-iv", ivB64},
                     {"x-amz-meta-vh-key-version", std::to_string(kKeyVersion)}}});
        return rowFor(path, plaintext.size(), ivB64, kKeyVersion);
    }

    std::shared_ptr<FileModel> rowFor(const std::string& path, const uint64_t size, const std::string& ivB64,
                                      const unsigned int version) {
        auto file = std::make_shared<FileModel>();
        file->id = static_cast<unsigned int>(100 + fileCounter_++);
        file->vault_id = kVaultId;
        file->path = path;
        file->name = std::filesystem::path(path).filename().string();
        file->backing_path = dir_.path() / "backing" / ("alias" + std::to_string(file->id));
        file->size_bytes = size;
        file->encryption_iv = ivB64;
        file->encrypted_with_key_version = version;
        return file;
    }

    [[nodiscard]] std::size_t gateRequests() const {
        std::scoped_lock lock(gateLog_->mutex);
        return gateLog_->requests.size();
    }

    [[nodiscard]] std::vector<s3::S3GatewayUpstreamUsage> commits() const {
        std::scoped_lock lock(gateLog_->mutex);
        return gateLog_->commits;
    }

    struct CatalogCommit {
        std::string iv;
        unsigned int version;
        std::string expectedIv;
        unsigned int expectedVersion;
        bool backingExisted;
    };

    static constexpr ReaderOptions kHydrateStrict{.integrity = IntegrityPolicy::Strict, .remote = RemoteFetchPolicy::Hydrate};

    TempDir dir_;
    std::vector<uint8_t> key_;
    std::shared_ptr<vault::model::S3Vault> vault_;
    std::shared_ptr<FakeBucket> bucket_ = std::make_shared<FakeBucket>();
    std::shared_ptr<CloudEngine> engine_;
    std::shared_ptr<FakeReservation::Log> gateLog_ = std::make_shared<FakeReservation::Log>();
    std::vector<CatalogCommit> catalogCommits_;
    bool refusePrice_{false};
    bool catalogAccepts_{true};
    int etagCounter_{0};
    int fileCounter_{0};
};

TEST_F(CloudRemoteReadTest, HydrateKeepsAuthenticatedCiphertextAndServesRangesLocally) {
    const auto plaintext = randomBytes(300'001, 1);
    const auto file = remoteEncrypted("/media/clip.bin", plaintext);
    ASSERT_FALSE(std::filesystem::exists(file->backing_path));

    const auto reader = engine_->openPlaintextReader(file, kHydrateStrict);

    // One HEAD, one whole-object GET bound to the HEAD's ETag; the stored copy is the remote ciphertext verbatim.
    ASSERT_TRUE(std::filesystem::exists(file->backing_path));
    EXPECT_EQ(1, bucket_->heads());
    const auto gets = bucket_->gets();
    ASSERT_EQ(1u, gets.size());
    EXPECT_FALSE(gets[0].range.has_value());
    EXPECT_EQ("\"etag-1\"", gets[0].ifMatch.value_or(""));
    EXPECT_EQ(plaintext.size() + crypto::util::AES_TAG_SIZE, std::filesystem::file_size(file->backing_path));
    EXPECT_EQ(plaintext, crypto::util::decrypt_aes256_gcm(readFile(file->backing_path), key_,
                                                         crypto::util::b64_decode(file->encryption_iv)));
    struct stat st{};
    ASSERT_EQ(0, ::stat(file->backing_path.c_str(), &st));
    EXPECT_EQ(0600u, st.st_mode & 0777);
    // Even with the same IV the publish is conditional on the row still being this generation (rotation may have
    // re-keyed the object and moved the row on while the GET ran).
    ASSERT_EQ(1u, catalogCommits_.size());

    // Metered and settled: the price gate saw the plan, the reservation got the actual usage.
    ASSERT_EQ(1u, gateRequests());
    const auto settled = commits();
    ASSERT_EQ(1u, settled.size());
    EXPECT_EQ(1u, settled[0].head_requests);
    EXPECT_EQ(1u, settled[0].get_requests);
    EXPECT_EQ(plaintext.size() + crypto::util::AES_TAG_SIZE, settled[0].downloaded_bytes);
    EXPECT_EQ(1u, bucket_->requestMetrics().get_requests);
    EXPECT_EQ(plaintext.size() + crypto::util::AES_TAG_SIZE, bucket_->requestMetrics().downloaded_bytes);

    std::vector<uint8_t> out(5000);
    ASSERT_EQ(out.size(), reader->read(123'457, out));
    EXPECT_TRUE(std::equal(out.begin(), out.end(), plaintext.begin() + 123'457));
    EXPECT_EQ(file->encryption_iv, reader->generation().iv_b64);

    // Now local: another open costs nothing upstream.
    (void)engine_->openPlaintextReader(file, kHydrateStrict);
    EXPECT_EQ(1u, bucket_->gets().size());
    EXPECT_EQ(1, bucket_->heads());
}

TEST_F(CloudRemoteReadTest, ConcurrentReadersShareOneFetch) {
    const auto plaintext = randomBytes(200'000, 2);
    const auto file = remoteEncrypted("/media/shared.bin", plaintext);
    bucket_->getDelay = std::chrono::milliseconds(150);

    constexpr int kThreads = 8;
    std::barrier start(kThreads);
    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i] {
            const auto mine = std::make_shared<FileModel>(*file);
            start.arrive_and_wait();
            const auto reader = engine_->openPlaintextReader(mine, kHydrateStrict);
            std::vector<uint8_t> out(1000);
            const auto offset = static_cast<uint64_t>(i) * 10'000;
            if (reader->read(offset, out) == out.size() &&
                std::equal(out.begin(), out.end(), plaintext.begin() + static_cast<std::ptrdiff_t>(offset)))
                ++ok;
        });
    }
    for (auto& t : threads) t.join();

    EXPECT_EQ(kThreads, ok.load());
    EXPECT_EQ(1u, bucket_->gets().size());
    EXPECT_EQ(1, bucket_->heads());
    EXPECT_EQ(1u, gateRequests());
}

TEST_F(CloudRemoteReadTest, TamperedRemoteObjectFailsAndKeepsNothing) {
    const auto plaintext = randomBytes(70'000, 3);
    const auto file = remoteEncrypted("/media/tampered.bin", plaintext);
    bucket_->mutate("media/tampered.bin", [](FakeBucket::Object& o) { o.body[4242] ^= 0x01; });

    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), IntegrityError);
    EXPECT_FALSE(std::filesystem::exists(file->backing_path));
    // Nothing staged is left behind next to the backing path.
    std::size_t leftovers = 0;
    for (const auto& entry : std::filesystem::directory_iterator(file->backing_path.parent_path())) {
        (void)entry;
        ++leftovers;
    }
    EXPECT_EQ(0u, leftovers);
    EXPECT_EQ(1u, bucket_->gets().size());
    ASSERT_EQ(1u, commits().size());  // the GET happened: it is charged
    EXPECT_EQ(1u, commits()[0].get_requests);
}

TEST_F(CloudRemoteReadTest, AFailedHydrateIsNotRefetchedOnEveryRequest) {
    const auto plaintext = randomBytes(70'000, 31);
    const auto file = remoteEncrypted("/media/bad.bin", plaintext);
    bucket_->mutate("media/bad.bin", [](FakeBucket::Object& o) { o.body[17] ^= 0x01; });
    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), IntegrityError);
    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), IntegrityError);
    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), IntegrityError);
    EXPECT_EQ(1u, bucket_->gets().size()) << "the failure is remembered instead of downloading again";
}

TEST_F(CloudRemoteReadTest, AnUnencryptedRemoteForAnEncryptedFileIsADowngradeAndRefused) {
    const auto plaintext = randomBytes(5'000, 32);
    const auto file = remoteEncrypted("/media/downgrade.bin", plaintext);
    bucket_->mutate("media/downgrade.bin", [&](FakeBucket::Object& o) {
        o.body = plaintext;
        o.meta = {{"x-amz-meta-vh-encrypted", "false"}};
    });
    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), IntegrityError);
    EXPECT_FALSE(std::filesystem::exists(file->backing_path));
    EXPECT_TRUE(bucket_->gets().empty());
}

TEST_F(CloudRemoteReadTest, APlaintextObjectIndexedWithoutAnIvIsSealedOnTheWayInEvenWhenTheVaultEncrypts) {
    // An adopted (or waivered) bucket's existing data: objects another tool wrote, plaintext from the start, indexed
    // without an IV. The vault encrypts what it writes; these must still be readable (#237), sealed locally.
    const auto plaintext = randomBytes(6'000, 35);
    bucket_->put("media/adopted.bin", FakeBucket::Object{.body = plaintext, .etag = "\"etag-adopted\"", .meta = {}});
    const auto file = rowFor("/media/adopted.bin", plaintext.size(), "", 0);
    const auto reader = engine_->openPlaintextReader(file, kHydrateStrict);
    EXPECT_EQ(plaintext, readAll(*reader, plaintext.size()));
    EXPECT_EQ(1u, bucket_->gets().size());
    ASSERT_EQ(1u, catalogCommits_.size()) << "the new IV is recorded before the sealed copy is linked in";
    EXPECT_FALSE(catalogCommits_[0].iv.empty());
}

TEST_F(CloudRemoteReadTest, ARemoteObjectWithAnotherIvIsNotServedUnderThisRow) {
    const auto plaintext = randomBytes(5'000, 33);
    const auto file = remoteEncrypted("/media/rollback.bin", plaintext);
    const auto other = remoteEncrypted("/media/other.bin", randomBytes(5'000, 34));
    // Same size, another object's bytes and IV (a rollback or a copied object).
    bucket_->mutate("media/rollback.bin", [&](FakeBucket::Object& o) {
        FakeBucket::Object copy;
        bucket_->peek("media/other.bin", copy);
        o.body = copy.body;
        o.meta = copy.meta;
    });
    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), ContentUnavailable);
    EXPECT_FALSE(std::filesystem::exists(file->backing_path));
    EXPECT_TRUE(bucket_->gets().empty());
    (void)other;
}

TEST_F(CloudRemoteReadTest, PriceRefusalIsContentUnavailableBeforeAnyRequest) {
    const auto file = remoteEncrypted("/media/expensive.bin", randomBytes(10'000, 4));
    refusePrice_ = true;

    try {
        (void)engine_->openPlaintextReader(file, kHydrateStrict);
        FAIL() << "expected ContentUnavailable";
    } catch (const ContentUnavailable& e) {
        EXPECT_NE(std::string(e.what()).find("price budget"), std::string::npos) << e.what();
    }
    EXPECT_EQ(0, bucket_->heads());
    EXPECT_TRUE(bucket_->gets().empty());
    EXPECT_FALSE(std::filesystem::exists(file->backing_path));
}

TEST_F(CloudRemoteReadTest, RequestBudgetRefusalFetchesNoBody) {
    const auto file = remoteEncrypted("/media/budget.bin", randomBytes(10'000, 5));
    s3::S3RequestBudget budget;
    budget.max_get_requests = 0;
    engine_->configureS3RequestBudget(budget);

    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), ContentUnavailable);
    EXPECT_TRUE(bucket_->gets().empty()) << "the GET was refused before it was sent";
    EXPECT_FALSE(std::filesystem::exists(file->backing_path));
    engine_->clearS3RequestBudget();
}

TEST_F(CloudRemoteReadTest, HydrateIsVisibleToAnOuterUsageCapture) {
    const auto plaintext = randomBytes(40'000, 6);
    const auto file = remoteEncrypted("/media/gateway.bin", plaintext);

    ScopedS3RequestUsageCapture outer(*engine_);
    (void)engine_->openPlaintextReader(file, kHydrateStrict);
    const auto usage = outer.usage();
    EXPECT_EQ(1u, usage.head_requests);
    EXPECT_EQ(1u, usage.get_requests);
    EXPECT_EQ(plaintext.size() + crypto::util::AES_TAG_SIZE, usage.downloaded_bytes);
}

TEST_F(CloudRemoteReadTest, PlaintextUpstreamHydrateStoresCiphertextOnly) {
    vault_->encrypt_upstream = false;
    const auto plaintext = randomBytes(90'000, 7);
    bucket_->put("docs/plain.bin", FakeBucket::Object{
        .body = plaintext, .etag = "\"plain-1\"", .meta = {{"x-amz-meta-vh-encrypted", "false"}}});
    const auto file = rowFor("/docs/plain.bin", plaintext.size(), "", 0);

    const auto reader = engine_->openPlaintextReader(file, kHydrateStrict);

    const auto stored = readFile(file->backing_path);
    ASSERT_EQ(plaintext.size() + crypto::util::AES_TAG_SIZE, stored.size());
    EXPECT_EQ(stored.end(), std::search(stored.begin(), stored.end(), plaintext.begin() + 1000, plaintext.begin() + 1064))
        << "plaintext reached the disk";

    // The fresh IV was recorded (compare-and-set against the old row) before the copy was linked in.
    ASSERT_EQ(1u, catalogCommits_.size());
    EXPECT_FALSE(catalogCommits_[0].backingExisted);
    EXPECT_EQ("", catalogCommits_[0].expectedIv);
    EXPECT_EQ(0u, catalogCommits_[0].expectedVersion);
    EXPECT_EQ(kKeyVersion, catalogCommits_[0].version);
    EXPECT_EQ(catalogCommits_[0].iv, reader->generation().iv_b64);
    EXPECT_EQ(plaintext, crypto::util::decrypt_aes256_gcm(stored, key_, crypto::util::b64_decode(catalogCommits_[0].iv)));
    EXPECT_EQ(plaintext, readAll(*reader, plaintext.size()));
}

TEST_F(CloudRemoteReadTest, HydrateLosingTheRowRaceKeepsNothing) {
    vault_->encrypt_upstream = false;
    const auto plaintext = randomBytes(5'000, 8);
    bucket_->put("docs/raced.bin", FakeBucket::Object{
        .body = plaintext, .etag = "\"raced\"", .meta = {{"x-amz-meta-vh-encrypted", "false"}}});
    const auto file = rowFor("/docs/raced.bin", plaintext.size(), "", 0);
    catalogAccepts_ = false;

    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), ContentUnavailable);
    EXPECT_FALSE(std::filesystem::exists(file->backing_path));
}

TEST_F(CloudRemoteReadTest, IndexMismatchRefusesInsteadOfFetching) {
    const auto plaintext = randomBytes(8'000, 9);
    auto file = remoteEncrypted("/media/stale.bin", plaintext);
    file->size_bytes = 7'000;  // the index disagrees with the object

    EXPECT_THROW((void)engine_->openPlaintextReader(file, kHydrateStrict), ContentUnavailable);
    EXPECT_TRUE(bucket_->gets().empty());
}

TEST_F(CloudRemoteReadTest, PolicyOffIsContentUnavailable) {
    const auto file = remoteEncrypted("/media/off.bin", randomBytes(1'000, 10));
    EXPECT_THROW((void)engine_->openPlaintextReader(file, {.integrity = IntegrityPolicy::Strict,
                                                          .remote = RemoteFetchPolicy::Off}),
                 ContentUnavailable);
    EXPECT_EQ(0, bucket_->heads());
    EXPECT_TRUE(bucket_->gets().empty());
    EXPECT_EQ(0u, gateRequests());
}

TEST_F(CloudRemoteReadTest, RangedReaderFetchesAlignedWindowsBoundToOneVersion) {
    engine_->setRangedReadLimits({.window_bytes = 64 * 1024, .cached_windows = 2,
                                  .max_get_requests = std::nullopt, .max_downloaded_bytes = std::nullopt});
    const auto plaintext = randomBytes(300 * 1024 + 5, 11);
    const auto file = remoteEncrypted("/media/ranged.bin", plaintext);
    const ReaderOptions ranged{.integrity = IntegrityPolicy::Strict, .remote = RemoteFetchPolicy::Ranged};

    auto reader = engine_->openPlaintextReader(file, ranged);
    EXPECT_FALSE(std::filesystem::exists(file->backing_path)) << "ranged mode keeps no local copy";
    EXPECT_EQ(file->encryption_iv, reader->generation().iv_b64);

    std::vector<uint8_t> out(1000);
    ASSERT_EQ(out.size(), reader->read(70'000, out));
    EXPECT_TRUE(std::equal(out.begin(), out.end(), plaintext.begin() + 70'000));
    ASSERT_EQ(out.size(), reader->read(71'000, out));  // same window: cached
    EXPECT_TRUE(std::equal(out.begin(), out.end(), plaintext.begin() + 71'000));

    // A read spanning a window boundary fetches the next window only.
    std::vector<uint8_t> span(4000);
    ASSERT_EQ(span.size(), reader->read(131'072 - 2000, span));
    EXPECT_TRUE(std::equal(span.begin(), span.end(), plaintext.begin() + (131'072 - 2000)));

    // Tail window is short and the last read stops at EOF.
    std::vector<uint8_t> tail(100);
    ASSERT_EQ(5u, reader->read(plaintext.size() - 5, tail));
    EXPECT_TRUE(std::equal(tail.begin(), tail.begin() + 5, plaintext.end() - 5));

    const auto gets = bucket_->gets();
    ASSERT_EQ(3u, gets.size());
    EXPECT_EQ("bytes=65536-131071", gets[0].range.value_or(""));
    EXPECT_EQ("bytes=131072-196607", gets[1].range.value_or(""));
    EXPECT_EQ("bytes=262144-" + std::to_string(plaintext.size() - 1), gets[2].range.value_or(""));
    for (const auto& get : gets) EXPECT_EQ("\"etag-1\"", get.ifMatch.value_or(""));

    const auto* remote = dynamic_cast<RemoteRangedReader*>(reader.get());
    ASSERT_NE(nullptr, remote);
    EXPECT_EQ(3u, remote->usage().get_requests);
    EXPECT_EQ(65'536u + 65'536u + (plaintext.size() - 262'144), remote->usage().downloaded_bytes);
    EXPECT_EQ(1u, remote->usage().head_requests);

    // The worst case was price-reserved at open; the actual usage is committed when the reader goes away.
    ASSERT_EQ(1u, gateRequests());
    EXPECT_EQ("preview_ranged", gateLog_->requests[0].operation);
    EXPECT_EQ(remote->maxGetRequests(), gateLog_->requests[0].get_requests);
    reader.reset();
    ASSERT_EQ(1u, commits().size());
    EXPECT_EQ(3u, commits()[0].get_requests);
}

TEST_F(CloudRemoteReadTest, RangedReaderRefusesPastItsBudget) {
    engine_->setRangedReadLimits({.window_bytes = 16 * 1024, .cached_windows = 1,
                                  .max_get_requests = 2, .max_downloaded_bytes = std::nullopt});
    const auto plaintext = randomBytes(64 * 1024, 12);
    const auto file = remoteEncrypted("/media/scrub.bin", plaintext);
    const auto reader = engine_->openPlaintextReader(file, {.integrity = IntegrityPolicy::Strict,
                                                            .remote = RemoteFetchPolicy::Ranged});
    std::vector<uint8_t> out(10);
    ASSERT_EQ(out.size(), reader->read(0, out));
    ASSERT_EQ(out.size(), reader->read(20'000, out));
    EXPECT_THROW((void)reader->read(40'000, out), ContentUnavailable);
    EXPECT_EQ(2u, bucket_->gets().size());
}

TEST_F(CloudRemoteReadTest, RangedReaderDetectsAChangedObject) {
    engine_->setRangedReadLimits({.window_bytes = 16 * 1024, .cached_windows = 2,
                                  .max_get_requests = std::nullopt, .max_downloaded_bytes = std::nullopt});
    const auto plaintext = randomBytes(64 * 1024, 13);
    const auto file = remoteEncrypted("/media/changing.bin", plaintext);
    const auto reader = engine_->openPlaintextReader(file, {.integrity = IntegrityPolicy::Strict,
                                                            .remote = RemoteFetchPolicy::Ranged});
    std::vector<uint8_t> out(10);
    ASSERT_EQ(out.size(), reader->read(0, out));

    bucket_->mutate("media/changing.bin", [](FakeBucket::Object& o) { o.etag = "\"etag-new\""; });
    EXPECT_THROW((void)reader->read(30'000, out), IntegrityError);
}

TEST_F(CloudRemoteReadTest, RangedReadAllIsAuthenticated) {
    const auto plaintext = randomBytes(50'000, 14);
    const auto file = remoteEncrypted("/media/whole.bin", plaintext);
    const ReaderOptions ranged{.integrity = IntegrityPolicy::Strict, .remote = RemoteFetchPolicy::Ranged};

    const auto reader = engine_->openPlaintextReader(file, ranged);
    EXPECT_EQ(plaintext, readAll(*reader, plaintext.size()));
    EXPECT_EQ("bytes=0-" + std::to_string(plaintext.size() + crypto::util::AES_TAG_SIZE - 1),
              bucket_->gets().back().range.value_or(""));

    bucket_->mutate("media/whole.bin", [](FakeBucket::Object& o) { o.body[100] ^= 0x80; });
    const auto tampered = engine_->openPlaintextReader(file, ranged);
    EXPECT_THROW((void)readAll(*tampered, plaintext.size()), IntegrityError);
}

// D11: a cloud file with a local ciphertext copy is read locally by every legacy lane: zero S3 requests.
TEST_F(CloudRemoteReadTest, LocalCopyIsPreferredByShareLanesAndTheGateway) {
    const auto plaintext = randomBytes(20'000, 15);
    // The remote object exists (with its own IV) but must not be touched.
    const auto remote = remoteEncrypted("/media/local.bin", plaintext);
    auto file = rowFor("/media/local.bin", plaintext.size(), "", 0);
    writeFile(file->backing_path, engine_->encryptionManager->encrypt(plaintext, file));  // local IV != remote IV
    ASSERT_NE(remote->encryption_iv, file->encryption_iv);

    share::ResolvedTarget target;
    target.vault_id = kVaultId;
    target.target_type = share::TargetType::File;
    target.entry = file;
    const auto resolver = [engine = engine_](uint32_t) -> std::shared_ptr<Engine> { return engine; };

    EXPECT_EQ(plaintext, protocols::ws::handler::share::makeDefaultDownloadReader(resolver)->readFile(target));
    EXPECT_EQ(plaintext, protocols::ws::handler::share::makeDefaultPreviewReader(resolver)->readFile(target));

    const auto whole = protocols::s3::ObjectStore::readFileObject(engine_, file, "media/local.bin", std::nullopt);
    EXPECT_EQ(plaintext, whole.bytes);
    EXPECT_FALSE(whole.content_range.has_value());

    const auto ranged = protocols::s3::ObjectStore::readFileObject(
        engine_, file, "media/local.bin", protocols::http::range::Spec{.first = 1000, .last = 1999});
    ASSERT_TRUE(ranged.content_range.has_value());
    EXPECT_EQ(1000u, ranged.content_range->first);
    EXPECT_EQ(1999u, ranged.content_range->second);
    EXPECT_TRUE(std::equal(ranged.bytes.begin(), ranged.bytes.end(), plaintext.begin() + 1000));

    EXPECT_EQ(0, bucket_->heads());
    EXPECT_TRUE(bucket_->gets().empty());
    EXPECT_EQ(0u, bucket_->requestMetrics().get_requests);
    EXPECT_EQ(0u, gateRequests());
}

// The gateway reads a remote-only (index-only) row through the reader too, instead of failing on the missing file.
TEST_F(CloudRemoteReadTest, GatewayHydratesAnIndexOnlyRow) {
    const auto plaintext = randomBytes(12'000, 16);
    const auto file = remoteEncrypted("/media/indexed.bin", plaintext);
    const auto body = protocols::s3::ObjectStore::readFileObject(engine_, file, "media/indexed.bin", std::nullopt);
    EXPECT_EQ(plaintext, body.bytes);
    EXPECT_EQ(1u, bucket_->gets().size());

    refusePrice_ = true;
    const auto other = remoteEncrypted("/media/refused.bin", plaintext);
    try {
        (void)protocols::s3::ObjectStore::readFileObject(engine_, other, "media/refused.bin", std::nullopt);
        FAIL() << "expected a 503";
    } catch (const protocols::s3::S3Error& e) {
        EXPECT_EQ("ServiceUnavailable", e.code);
    }
}

}
