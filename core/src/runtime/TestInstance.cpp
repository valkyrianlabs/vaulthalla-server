#include "runtime/TestInstance.hpp"

#include <array>
#include <filesystem>
#include <string_view>

namespace vh::runtime::test_instance {

namespace {

// Every one of these must come from the environment itself: the DB keys would otherwise fall back to the repo's
// env file one key at a time (db/Connection.cpp), and the paths to the system defaults.
constexpr std::array kRequired{
    "VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_HOST", "VH_TEST_DB_PORT", "VH_TEST_DB_NAME",
    "VH_TEST_BACKING_PATH", "VH_TEST_MOUNT_PATH", "VH_TEST_LOG_PATH", "VH_PATH_TO_SUPERADMIN_UID",
    "VH_PATH_TO_CONFIG", "VH_TEST_CLI_SOCKET",
};

// The directories a test instance may own: FUSE refuses test mounts outside /tmp/ too (fuse/Service.cpp).
constexpr std::array kPrivatePathVars{
    "VH_TEST_BACKING_PATH", "VH_TEST_MOUNT_PATH", "VH_TEST_LOG_PATH", "VH_PATH_TO_SUPERADMIN_UID",
    "VH_PATH_TO_CONFIG", "VH_TEST_CLI_SOCKET",
};

bool underTmp(const std::string_view value) {
    const auto normal = std::filesystem::path(value).lexically_normal().string();
    return normal.starts_with("/tmp/") && normal.size() > 5 && normal.find("/../") == std::string::npos;
}

bool safeDatabaseName(const std::string_view name) {
    if (name.empty() || name == "vaulthalla" || name == "postgres" || name.starts_with("template")) return false;
    return name.starts_with("vh_harness_") || name.find("test") != std::string_view::npos;
}

}

bool requested(const EnvLookup& env) {
    const char* v = env("VH_TEST_MODE");
    return v && std::string_view(v) == "1";
}

std::optional<std::string> refusal(const EnvLookup& env) {
    for (const auto* key : kRequired) {
        const char* v = env(key);
        if (!v || !*v) return std::string(key) + " is not set";
    }
    for (const auto* key : kPrivatePathVars)
        if (!underTmp(env(key))) return std::string(key) + " must be a private path under /tmp/";

    const std::string_view mount = env("VH_TEST_MOUNT_PATH");
    const std::string_view backing = env("VH_TEST_BACKING_PATH");
    if (std::filesystem::path(mount).lexically_normal() == std::filesystem::path(backing).lexically_normal())
        return "VH_TEST_MOUNT_PATH and VH_TEST_BACKING_PATH must differ";

    if (!safeDatabaseName(env("VH_TEST_DB_NAME")))
        return "VH_TEST_DB_NAME must be a test database (vh_harness_* or a name containing \"test\")";

    return std::nullopt;
}

}
