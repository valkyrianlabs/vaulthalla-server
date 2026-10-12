// A test-mode database connection takes all five VH_TEST_DB_* values from the environment or refuses. Before, a
// missing one fell back to the production path (the configured database and /run/vaulthalla/db_password), which on a
// dev box is the dev database; the legacy integration runner then truncated it. DB-free: the refusal comes before any
// connection, file or TPM access.

#include "db/DBConnection.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <array>
#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>

namespace vh::test_db_test_mode_connection {

constexpr std::array kKeys{"VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_HOST", "VH_TEST_DB_PORT", "VH_TEST_DB_NAME"};

class TestModeConnection : public ::testing::Test {
protected:
    std::array<std::optional<std::string>, kKeys.size()> saved_{};

    void SetUp() override {
        for (std::size_t i = 0; i < kKeys.size(); ++i)
            if (const char* v = std::getenv(kKeys[i])) saved_[i] = v;
        paths::enableTestMode();
    }

    void TearDown() override {
        for (std::size_t i = 0; i < kKeys.size(); ++i) {
            if (saved_[i]) ::setenv(kKeys[i], saved_[i]->c_str(), 1);
            else ::unsetenv(kKeys[i]);
        }
    }
};

TEST_F(TestModeConnection, AnyMissingSettingRefusesInsteadOfFallingBack) {
    for (std::size_t missing = 0; missing < kKeys.size(); ++missing) {
        for (std::size_t i = 0; i < kKeys.size(); ++i) ::setenv(kKeys[i], "x", 1);
        ::unsetenv(kKeys[missing]);
        try {
            db::Connection c;
            FAIL() << kKeys[missing] << " missing: a connection was opened";
        } catch (const std::runtime_error& e) {
            EXPECT_NE(std::string(e.what()).find("refusing to fall back"), std::string::npos)
                << kKeys[missing] << " missing: " << e.what();
        }
    }
}

}
