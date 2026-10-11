#pragma once

#include "cli/Config.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vh::test::integration {

// VH_TEST_NEGATIVE_CONTROL: inject one deliberately wrong expectation; the run must then fail. `assertion` adds a
// stdout needle no `role info` output can contain (and proves role expectations apply at all); `oracle` adds a state
// check that a user who was never created exists in the DB.
enum class NegativeControl { None, Assertion, Oracle };

inline constexpr std::string_view kNegativeControlNeedle = "VH-NEGATIVE-CONTROL";

struct RunOptions {
    // Pipeline order; VH_TEST_STAGES selects a subset (seed is implied by every CLI stage that needs entities).
    static constexpr std::array<std::string_view, 7> kStages{"seed", "assign", "read", "update", "validate", "fuse",
                                                             "teardown"};

    cli::Config config = cli::Config::Minimal();
    std::string configName = "minimal";
    std::vector<std::string> stages;
    NegativeControl negativeControl = NegativeControl::None;
    uint64_t seed = 0;
    bool seedFromEnv = false;
    uint32_t uidBase = 0;
    unsigned int seedThreads = 1;
    std::string reportDir;
    bool legacySharedEnv = false;

    [[nodiscard]] bool has(std::string_view stage) const;
    [[nodiscard]] std::string stagesText() const;
    [[nodiscard]] std::string negativeControlText() const;

    // Reads VH_TEST_SEED, VH_TEST_CONFIG, VH_TEST_STAGES, VH_TEST_NEGATIVE_CONTROL, VH_TEST_UID_BASE,
    // VH_TEST_SEED_THREADS, VH_TEST_REPORT_DIR and VH_TEST_LEGACY_SHARED_ENV. Unknown values are an error, never a
    // silent default.
    static std::optional<RunOptions> fromEnv(std::string& error);
};

}
