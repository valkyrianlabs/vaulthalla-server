// #350: master secrets live in locked memory that is zeroed when it is released, and no unseal path, a failing one
// included, leaves a copy of the secret behind.

#include "crypto/SecretBytes.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/secrets/KeyProvider.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <numeric>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

namespace vh::test_master_secret_memory {

using crypto::SecretBytes;
using crypto::WipedKeyCopy;
using crypto::secrets::KeyProvider;

// Callers can only borrow the master secret, never take a vector copy of it by accident.
static_assert(std::is_same_v<decltype(std::declval<const KeyProvider&>().getMasterKey()), std::span<const uint8_t>>);
static_assert(!std::is_copy_constructible_v<SecretBytes>);

struct Wiped {
    std::size_t size = 0;
    bool zero = false;
};

std::mutex wipedMutex;
std::vector<std::pair<const void*, Wiped>> wiped;

void recordWipe(const void* where, const std::span<const uint8_t> after) {
    const bool zero = std::ranges::all_of(after, [](const uint8_t b) { return b == 0; });
    std::scoped_lock lock(wipedMutex);
    wiped.emplace_back(where, Wiped{after.size(), zero});
}

// The last wipe recorded at `where` (allocators reuse addresses, so the latest one is the one that counts).
std::optional<Wiped> wipedAt(const void* where) {
    std::scoped_lock lock(wipedMutex);
    for (auto it = wiped.rbegin(); it != wiped.rend(); ++it)
        if (it->first == where) return it->second;
    return std::nullopt;
}

void forgetWipes() {
    std::scoped_lock lock(wipedMutex);
    wiped.clear();
}

std::vector<uint8_t> pattern(const std::size_t n) {
    std::vector<uint8_t> out(n);
    std::iota(out.begin(), out.end(), uint8_t{1});
    return out;
}

class WipeObserved : public ::testing::Test {
protected:
    void SetUp() override {
        forgetWipes();
        crypto::setWipeObserverForTesting(recordWipe);
    }
    void TearDown() override { crypto::setWipeObserverForTesting(nullptr); }
};

using SecretBytesTest = WipeObserved;

TEST_F(SecretBytesTest, IsZeroedBeforeItIsFreed) {
    const void* where = nullptr;
    {
        const SecretBytes secret(pattern(48));
        ASSERT_EQ(secret.size(), 48u);
        EXPECT_TRUE(std::ranges::equal(secret.bytes(), pattern(48)));
        where = secret.bytes().data();
    }
    const auto w = wipedAt(where);
    ASSERT_TRUE(w) << "the buffer was freed without passing through the wipe";
    EXPECT_EQ(w->size, 48u);
    EXPECT_TRUE(w->zero);
}

TEST_F(SecretBytesTest, MovingHandsOverTheBufferWithoutACopy) {
    SecretBytes a(pattern(32));
    const auto* where = a.bytes().data();
    SecretBytes b(std::move(a));
    EXPECT_TRUE(a.empty());  // NOLINT(bugprone-use-after-move): the moved-from state is what is tested
    EXPECT_EQ(b.bytes().data(), where);

    SecretBytes c(pattern(16));
    const auto* replaced = c.bytes().data();
    c = std::move(b);
    EXPECT_EQ(c.bytes().data(), where);
    const auto w = wipedAt(replaced);
    ASSERT_TRUE(w) << "assigning over a secret must wipe the one it replaces";
    EXPECT_TRUE(w->zero);
}

TEST_F(SecretBytesTest, RandomFillsLockedMemoryDirectly) {
    const auto a = SecretBytes::random(32);
    const auto b = SecretBytes::random(32);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_FALSE(std::ranges::equal(a.bytes(), b.bytes()));
    EXPECT_THROW((void)SecretBytes::random(0), std::invalid_argument);
}

TEST_F(SecretBytesTest, SecretKeysAndCopiesAreWipedToo) {
    const void* keyAt = nullptr;
    {
        const crypto::SecretKey key(pattern(32));
        keyAt = key.bytes().data();
    }
    ASSERT_TRUE(wipedAt(keyAt));
    EXPECT_TRUE(wipedAt(keyAt)->zero);

    const void* copyAt = nullptr;
    try {
        const WipedKeyCopy copy(pattern(32));
        copyAt = copy.bytes.data();
        throw std::runtime_error("unwind");
    } catch (const std::runtime_error&) {}
    const auto w = wipedAt(copyAt);
    ASSERT_TRUE(w) << "a copy unwound by an exception must still be wiped";
    EXPECT_EQ(w->size, 32u);
    EXPECT_TRUE(w->zero);
}

// The sealing round trips need a backend (swtpm/TPM on Linux, the file or Secure Enclave backend on macOS).
class MasterSecretMemoryTest : public WipeObserved {
protected:
    std::filesystem::path oldBacking, root;

    void SetUp() override {
        WipeObserved::SetUp();
        paths::enableTestMode();
        oldBacking = paths::backingPath;
        root = std::filesystem::temp_directory_path() /
               ("vh_master_memory_" + std::to_string(::getpid()) + "_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root);
        paths::backingPath = root;
        if (const auto why = sealingUnusable()) GTEST_SKIP() << "sealing doesn't round-trip on this host: " << *why;
    }

    void TearDown() override {
        KeyProvider::setUnsealHookForTesting(nullptr);
        paths::backingPath = oldBacking;
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
        WipeObserved::TearDown();
    }

    static std::optional<std::string> sealingUnusable() {
        try {
            std::vector<uint8_t> first;
            {
                KeyProvider probe("test_memory_probe");
                probe.init();
                first.assign(probe.getMasterKey().begin(), probe.getMasterKey().end());
            }
            KeyProvider again("test_memory_probe");
            again.init();
            if (!std::ranges::equal(again.getMasterKey(), first))
                return std::string("the backend returned a different secret");
            return std::nullopt;
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
    }
};

// What the unseal hook saw: where the sealer's copy of the secret was, and (for the test only) its bytes.
const void* unsealedAt = nullptr;
std::vector<uint8_t> unsealedBytes;

void noteUnsealed(const std::span<const uint8_t> unsealed) {
    unsealedAt = unsealed.data();
    unsealedBytes.assign(unsealed.begin(), unsealed.end());
}

void failMidUnseal(const std::span<const uint8_t> unsealed) {
    noteUnsealed(unsealed);
    throw std::runtime_error("injected failure mid-unseal");
}

TEST_F(MasterSecretMemoryTest, TheProvidersBufferIsZeroAfterDestruction) {
    const void* generatedAt = nullptr;
    std::vector<uint8_t> secret;
    {
        KeyProvider provider("test_memory_master");
        provider.init();  // generates and seals
        generatedAt = provider.getMasterKey().data();
        secret.assign(provider.getMasterKey().begin(), provider.getMasterKey().end());
        ASSERT_EQ(secret.size(), 32u);
    }
    auto w = wipedAt(generatedAt);
    ASSERT_TRUE(w) << "the provider's buffer was freed without being wiped";
    EXPECT_EQ(w->size, 32u);
    EXPECT_TRUE(w->zero);

    // The unseal path: the sealer's plain copy is wiped once the locked one is made, and the locked one at the end.
    KeyProvider::setUnsealHookForTesting(noteUnsealed);
    const void* keptAt = nullptr;
    {
        KeyProvider provider("test_memory_master");
        provider.init();
        ASSERT_TRUE(std::ranges::equal(provider.getMasterKey(), secret));
        keptAt = provider.getMasterKey().data();
        EXPECT_NE(keptAt, unsealedAt);
        w = wipedAt(unsealedAt);
        ASSERT_TRUE(w) << "the sealer's copy outlived init()";
        EXPECT_EQ(w->size, 32u);
        EXPECT_TRUE(w->zero);
    }
    w = wipedAt(keptAt);
    ASSERT_TRUE(w);
    EXPECT_TRUE(w->zero);
}

TEST_F(MasterSecretMemoryTest, ReplacingTheSecretWipesTheOldOne) {
    KeyProvider provider("test_memory_replace");
    provider.init();
    const auto* oldAt = provider.getMasterKey().data();
    const auto replacement = pattern(32);
    provider.updateMasterKey(replacement);
    EXPECT_TRUE(std::ranges::equal(provider.getMasterKey(), replacement));
    const auto w = wipedAt(oldAt);
    ASSERT_TRUE(w) << "the replaced secret was not wiped";
    EXPECT_TRUE(w->zero);

    KeyProvider again("test_memory_replace");
    again.init();
    EXPECT_TRUE(std::ranges::equal(again.getMasterKey(), replacement)) << "the replacement is what is sealed";
}

TEST_F(MasterSecretMemoryTest, AThrowMidUnsealLeavesNoCopy) {
    std::vector<uint8_t> secret;
    {
        KeyProvider provider("test_memory_unseal");
        provider.init();
        secret.assign(provider.getMasterKey().begin(), provider.getMasterKey().end());
    }

    KeyProvider::setUnsealHookForTesting(failMidUnseal);
    KeyProvider again("test_memory_unseal");
    EXPECT_THROW(again.init(), std::runtime_error);
    EXPECT_TRUE(again.getMasterKey().empty()) << "a failed unseal keeps nothing";
    // The failure came after the sealer had handed over the real secret...
    EXPECT_TRUE(std::ranges::equal(unsealedBytes, secret));
    // ...and that copy was wiped as the exception unwound.
    const auto w = wipedAt(unsealedAt);
    ASSERT_TRUE(w) << "the unsealed copy was freed without being wiped";
    EXPECT_EQ(w->size, secret.size());
    EXPECT_TRUE(w->zero);

    // Nothing was lost: without the injected failure the same secret unseals.
    KeyProvider::setUnsealHookForTesting(nullptr);
    again.init();
    EXPECT_TRUE(std::ranges::equal(again.getMasterKey(), secret));
}

}
