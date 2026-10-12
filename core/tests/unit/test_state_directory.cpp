// platform::state::restrictToService (platform/StateDirectory.hpp): the macOS daemon refuses to start unless its
// backing/state root is private to it; on Linux it changes nothing (the package owns those modes).
#include "platform/StateDirectory.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <random>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace stdfs = std::filesystem;

namespace vh::platform::state::test {

namespace {

// Under /tmp (canonical /private/tmp on macOS, root-owned and sticky), not $TMPDIR.
stdfs::path scratch() {
    std::mt19937_64 rng(std::random_device{}());
    auto dir = stdfs::path("/tmp") / ("vh_state_dir_" + std::to_string(::getpid()) + "_" + std::to_string(rng()));
    stdfs::create_directories(dir);
    stdfs::permissions(dir, stdfs::perms::owner_all, stdfs::perm_options::replace);
    return dir;
}

mode_t modeOf(const stdfs::path& p) {
    struct stat st{};
    ::lstat(p.c_str(), &st);
    return st.st_mode & 07777;
}

}

class StateDirectoryTest : public ::testing::Test {
protected:
    stdfs::path dir = scratch();
    void TearDown() override {
        std::error_code ec;
        stdfs::permissions(dir / "open", stdfs::perms::owner_all, stdfs::perm_options::replace, ec);
        stdfs::remove_all(dir, ec);
    }
};

#if defined(__APPLE__)

TEST_F(StateDirectoryTest, CreatesAPrivateRoot) {
    const auto root = dir / "state";
    EXPECT_EQ(restrictToService(root), "");
    EXPECT_EQ(modeOf(root), 0700);
}

TEST_F(StateDirectoryTest, TightensAnExistingRoot) {
    const auto root = dir / "state";
    stdfs::create_directories(root);
    stdfs::permissions(root, stdfs::perms::all, stdfs::perm_options::replace);
    EXPECT_EQ(restrictToService(root), "");
    EXPECT_EQ(modeOf(root), 0700);
}

TEST_F(StateDirectoryTest, RefusesASymlinkedRoot) {
    stdfs::create_directories(dir / "elsewhere");
    stdfs::permissions(dir / "elsewhere", stdfs::perms::owner_all | stdfs::perms::group_read | stdfs::perms::group_exec,
                    stdfs::perm_options::replace);
    stdfs::create_directory_symlink(dir / "elsewhere", dir / "state");
    const auto problem = restrictToService(dir / "state");
    EXPECT_NE(problem.find("symlink"), std::string::npos) << problem;
    EXPECT_EQ(modeOf(dir / "elsewhere"), 0750) << "the symlink's target is left alone";
}

TEST_F(StateDirectoryTest, RefusesAnAncestorOtherAccountsCanWrite) {
    stdfs::create_directories(dir / "open");
    stdfs::permissions(dir / "open", stdfs::perms::all, stdfs::perm_options::replace);  // 0777, not sticky
    const auto problem = restrictToService(dir / "open" / "state");
    EXPECT_NE(problem.find("writable by other accounts"), std::string::npos) << problem;
}

TEST_F(StateDirectoryTest, RefusesARootOwnedBySomeoneElse) {
    if (::geteuid() == 0) GTEST_SKIP() << "running as root";
    const auto problem = restrictToService("/private/var/empty");  // root-owned on every Mac
    EXPECT_NE(problem.find("owned by uid 0"), std::string::npos) << problem;
}

#else

TEST_F(StateDirectoryTest, IsANoOpOnLinux) {
    const auto root = dir / "state";
    stdfs::create_directories(root);
    stdfs::permissions(root, stdfs::perms::owner_all | stdfs::perms::group_read | stdfs::perms::group_exec,
                    stdfs::perm_options::replace);  // 0750, as the package leaves /var/lib/vaulthalla
    EXPECT_EQ(restrictToService(root), "");
    EXPECT_EQ(modeOf(root), 0750);
}

#endif

}
