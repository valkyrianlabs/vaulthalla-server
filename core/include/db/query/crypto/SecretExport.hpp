#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

namespace vh::db::query::crypto {

// Records that `vh secret export all` was taken (migration 132, #351): when, by whom, which secrets. Never the secrets.
struct SecretExport {
    static void record(std::optional<uint32_t> actorId, const std::string& actorName,
                       const std::vector<std::string>& secrets);
    // The most recent export (Unix seconds), none if there never was one.
    [[nodiscard]] static std::optional<std::time_t> lastAt();
    // Tests: backdates every record by `seconds`.
    static void ageForTesting(long long seconds);
    static void clearForTesting();
};

}
