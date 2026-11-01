// The macOS sealer (platform/darwin/Sealer.cpp): Secure Enclave by default, the development "file" backend on a Mac
// without one, and the migration of file-sealed secrets (every macOS install before #290) into the Secure Enclave.
// Secure Enclave cases run from a login session, where the SEP accepts keys the session creates. Apple silicon VMs
// (GitHub's hosted runners) have a virtual SEP that passes too; a Mac where no SE key works skips them.
#if defined(__APPLE__)

#include "platform/Sealer.hpp"
#include "platform/darwin/SealerBackends.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <paths.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

// Named, not anonymous: unity builds merge the test files' anonymous namespaces.
namespace darwin_sealer_test {

namespace fs = std::filesystem;
namespace sealer = vh::platform::sealer;

bool preferSecureEnclave() { return std::string_view(VH_DARWIN_SEALER) == "secure-enclave"; }
bool underSecureEnclave() { return sealer::backend() == "secure-enclave"; }

bool virtualMachine() {
    int vmm = 0;
    std::size_t len = sizeof(vmm);
    return ::sysctlbyname("kern.hv_vmm_present", &vmm, &len, nullptr, 0) == 0 && vmm != 0;
}

std::vector<uint8_t> readAll(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void writeAll(const fs::path& p, const std::vector<uint8_t>& bytes) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

mode_t modeOf(const fs::path& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 ? (st.st_mode & 0777) : 0;
}

class DarwinSealerTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string tmpl = (fs::temp_directory_path() / "vh-darwin-sealer-XXXXXX").string();
        ASSERT_NE(::mkdtemp(tmpl.data()), nullptr);
        root_ = tmpl;
        dir_ = root_ / ".sealed_test.blob";
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    fs::path root_;
    fs::path dir_;
    const std::vector<uint8_t> secret_{'v', 'h', '-', 's', 'e', 'a', 'l', 'e', 'd', '-', 's', 'e', 'c', 'r', 'e', 't'};
};

} // namespace darwin_sealer_test

using darwin_sealer_test::DarwinSealerTest;
namespace dst = darwin_sealer_test;

// The backend is the build's choice, falling back to "file" only where no Secure Enclave key works; never "file" on
// a Mac whose Secure Enclave works. The output records what this host has (CI runs on virtual Macs).
TEST(DarwinSealer, ReportsTheBackendThisMacSupports) {
    const bool se = vh::platform::sealer::secure_enclave::available();
    std::cout << "[darwin-sealer] VH_DARWIN_SEALER=" << VH_DARWIN_SEALER << " secure_enclave_available=" << se
              << " virtual_machine=" << dst::virtualMachine()
              << " reason=" << vh::platform::sealer::secure_enclave::unavailableReason() << std::endl;
    EXPECT_EQ(vh::platform::sealer::backend(), dst::preferSecureEnclave() && se ? "secure-enclave" : "file");
#if defined(__aarch64__) || defined(__arm64__)
    if (!dst::virtualMachine()) EXPECT_TRUE(se) << "Apple silicon outside a VM always has a Secure Enclave";
#endif
}

// The fallback must not hide a working Secure Enclave: where the probe said no, a real seal fails too.
TEST(DarwinSealer, SecureEnclaveProbeAgreesWithARealSeal) {
    if (vh::platform::sealer::secure_enclave::available()) GTEST_SKIP() << "covered by the Secure Enclave cases";
    std::string tmpl = (std::filesystem::temp_directory_path() / "vh-se-probe-XXXXXX").string();
    ASSERT_NE(::mkdtemp(tmpl.data()), nullptr);
    try {
        vh::platform::sealer::secure_enclave::seal(tmpl, "probe", {1, 2, 3});
        ADD_FAILURE() << "the Secure Enclave works on this Mac but available() says it has none";
    } catch (const std::exception& e) {
        std::cout << "[darwin-sealer] no Secure Enclave, as expected: " << e.what() << std::endl;
    }
    std::error_code ec;
    std::filesystem::remove_all(tmpl, ec);
}

TEST_F(DarwinSealerTest, SealsAndUnsealsWithTheActiveBackend) {
    namespace sealer = vh::platform::sealer;
    EXPECT_FALSE(sealer::present(dir_, "slot"));
    sealer::seal(dir_, "slot", secret_);
    EXPECT_TRUE(sealer::present(dir_, "slot"));
    EXPECT_TRUE(sealer::complete(dir_, "slot"));
    EXPECT_EQ(sealer::unseal(dir_, "slot"), secret_);

    const auto active = dst::underSecureEnclave() ? sealer::secure_enclave::path(dir_, "slot")
                                                   : sealer::file::path(dir_, "slot");
    const auto other = dst::underSecureEnclave() ? sealer::file::path(dir_, "slot")
                                                  : sealer::secure_enclave::path(dir_, "slot");
    EXPECT_TRUE(std::filesystem::exists(active));
    EXPECT_FALSE(std::filesystem::exists(other));
    EXPECT_EQ(dst::modeOf(active), 0600u);
    EXPECT_EQ(dst::modeOf(dir_), 0700u);

    const std::vector<uint8_t> rotated{'r', 'o', 't', 'a', 't', 'e', 'd'};
    sealer::seal(dir_, "slot", rotated);
    EXPECT_EQ(sealer::unseal(dir_, "slot"), rotated);
}

TEST_F(DarwinSealerTest, MissingSecretIsAnError) {
    EXPECT_FALSE(vh::platform::sealer::present(dir_, "absent"));
    EXPECT_THROW((void)vh::platform::sealer::unseal(dir_, "absent"), std::runtime_error);
}

TEST_F(DarwinSealerTest, RefusesASealedFileOthersCanRead) {
    namespace sealer = vh::platform::sealer;
    sealer::seal(dir_, "slot", secret_);
    const auto blob = dst::underSecureEnclave() ? sealer::secure_enclave::path(dir_, "slot")
                                                : sealer::file::path(dir_, "slot");
    ASSERT_EQ(::chmod(blob.c_str(), 0640), 0);
    EXPECT_THROW((void)sealer::unseal(dir_, "slot"), std::runtime_error);
}

TEST_F(DarwinSealerTest, SecureEnclaveBlobHoldsNoPlaintext) {
    namespace sealer = vh::platform::sealer;
    if (!dst::underSecureEnclave()) GTEST_SKIP() << "no Secure Enclave backend on this Mac";
    sealer::seal(dir_, "slot", secret_);
    const auto blob = dst::readAll(sealer::secure_enclave::path(dir_, "slot"));
    ASSERT_GT(blob.size(), 4u);
    EXPECT_EQ(std::string(blob.begin(), blob.begin() + 4), "VHSE");
    EXPECT_EQ(std::search(blob.begin(), blob.end(), secret_.begin(), secret_.end()), blob.end());
}

// Every macOS install before #290 sealed with the file backend. The daemon's first start on the Secure Enclave reads
// the file, reseals into the Secure Enclave and removes the plaintext; the secret is unchanged.
TEST_F(DarwinSealerTest, MigratesAFileSealedSecretIntoTheSecureEnclave) {
    namespace sealer = vh::platform::sealer;
    if (!dst::underSecureEnclave()) GTEST_SKIP() << "no Secure Enclave backend on this Mac";
    sealer::file::seal(dir_, "legacy", secret_);
    ASSERT_TRUE(sealer::present(dir_, "legacy"));

    EXPECT_EQ(sealer::unseal(dir_, "legacy"), secret_);
    EXPECT_FALSE(std::filesystem::exists(sealer::file::path(dir_, "legacy")));
    EXPECT_TRUE(std::filesystem::exists(sealer::secure_enclave::path(dir_, "legacy")));
    EXPECT_EQ(sealer::unseal(dir_, "legacy"), secret_);
}

// DB pool connections open together after an upgrade, each unsealing the same file-sealed slot: one migrates it, the
// rest read the result, and every one gets the secret.
TEST_F(DarwinSealerTest, ConcurrentUnsealsOfAFileSealedSlotAllGetTheSecret) {
    namespace sealer = vh::platform::sealer;
    sealer::file::seal(dir_, "psql", secret_);

    constexpr int kThreads = 6;
    std::vector<std::string> errors(kThreads);
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i)
        threads.emplace_back([&, i] {
            try {
                if (sealer::unseal(dir_, "psql") != secret_) errors[static_cast<std::size_t>(i)] = "wrong secret";
            } catch (const std::exception& e) {
                errors[static_cast<std::size_t>(i)] = e.what();
            }
        });
    for (auto& t : threads) t.join();
    for (int i = 0; i < kThreads; ++i)
        EXPECT_TRUE(errors[static_cast<std::size_t>(i)].empty()) << "thread " << i << ": " << errors[static_cast<std::size_t>(i)];
    EXPECT_EQ(std::filesystem::exists(sealer::file::path(dir_, "psql")), !dst::underSecureEnclave());
}

// A crash between writing the Secure Enclave blob and removing the old file leaves both: the blob is the newer one.
TEST_F(DarwinSealerTest, AStaleFileBesideASecureEnclaveBlobLoses) {
    namespace sealer = vh::platform::sealer;
    if (!dst::underSecureEnclave()) GTEST_SKIP() << "no Secure Enclave backend on this Mac";
    sealer::seal(dir_, "slot", secret_);
    sealer::file::seal(dir_, "slot", {'s', 't', 'a', 'l', 'e'});

    EXPECT_EQ(sealer::unseal(dir_, "slot"), secret_);
    EXPECT_FALSE(std::filesystem::exists(sealer::file::path(dir_, "slot")));
}

TEST_F(DarwinSealerTest, SecureEnclaveRejectsATamperedBlob) {
    namespace sealer = vh::platform::sealer;
    if (!dst::underSecureEnclave()) GTEST_SKIP() << "no Secure Enclave backend on this Mac";
    sealer::seal(dir_, "slot", secret_);
    const auto path = sealer::secure_enclave::path(dir_, "slot");
    auto blob = dst::readAll(path);
    blob.back() ^= 0x01;  // the GCM tag
    dst::writeAll(path, blob);
    ASSERT_EQ(::chmod(path.c_str(), 0600), 0);
    EXPECT_THROW((void)sealer::unseal(dir_, "slot"), std::runtime_error);

    blob.back() ^= 0x01;
    blob[10] ^= 0x01;  // the key's token object
    dst::writeAll(path, blob);
    EXPECT_THROW((void)sealer::unseal(dir_, "slot"), std::runtime_error);
}

// Copying one slot's blob over another's (the DB password into the master key's slot) is refused.
TEST_F(DarwinSealerTest, SecureEnclaveRefusesAnotherSlotsBlob) {
    namespace sealer = vh::platform::sealer;
    if (!dst::underSecureEnclave()) GTEST_SKIP() << "no Secure Enclave backend on this Mac";
    sealer::seal(dir_, "psql", secret_);
    std::filesystem::copy_file(sealer::secure_enclave::path(dir_, "psql"), sealer::secure_enclave::path(dir_, "master"));
    try {
        (void)sealer::unseal(dir_, "master");
        ADD_FAILURE() << "another slot's blob unsealed";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("another name"), std::string::npos) << e.what();
    }
}

#endif
