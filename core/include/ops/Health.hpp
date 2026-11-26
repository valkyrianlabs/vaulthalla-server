#pragma once

#include "health/Findings.hpp"
#include "ops/Actor.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>

// Health findings and what operators say about them (design/health/findings.md): the one layer behind ws health.*
// and `vh health`. Reading needs admin.stats.view, as the dashboard does; acknowledging, silencing and turning a
// class back on need admin.stats.manage, because they change what every operator is told. Each change is recorded
// in the audit trail (health.finding.acknowledge / .silence / .unsilence).
namespace vh::ops::health {

[[nodiscard]] bool canManage(const Actor& actor);

// The health answer: the snapshot (vh::health::to_json), `can_manage` for this actor, and with `includeCatalog`
// every finding class.
[[nodiscard]] nlohmann::json list(const Actor& actor, bool includeCatalog = false);

struct SilenceRequest {
    std::string cls;
    std::string subject{};
    std::optional<std::uint64_t> forSeconds{};  // from now
    std::optional<std::uint64_t> until{};       // epoch seconds; neither: until turned back on
    std::optional<std::string> severity{};      // what it covers; default: the class's current or worst severity
    std::optional<std::string> note{};
};

// "I have seen this occurrence": refused (Conflict) when the class is not active now. Returns the new answer.
nlohmann::json acknowledge(const Actor& actor, const std::string& cls, const std::string& subject,
                           const std::optional<std::string>& note);
// "Do not tell me about this class", whether or not it is active. Returns the new answer.
nlohmann::json silence(const Actor& actor, const SilenceRequest& request);
// Removes whatever mark the class has (a silence, or an acknowledgement). NotFound when it has none.
nlohmann::json unsilence(const Actor& actor, const std::string& cls, const std::string& subject);

inline constexpr std::size_t kMaxNoteLength = 500;
inline constexpr std::uint64_t kMinSilenceSeconds = 60;
inline constexpr std::uint64_t kMaxSilenceSeconds = 366ull * 24 * 3600;

}
