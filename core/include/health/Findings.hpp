#pragma once

#include "health/Catalog.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace vh::stats::model { struct DashboardOverview; }

// Health findings with what an operator said about them (design/health/findings.md §3). The dashboard computes the
// findings (stats::model::DashboardOverview); this adds the stored state (migration 170, db::query::health) under
// fixed rules, and never changes a severity or a count: a silenced error is still an error, only no longer one that
// asks for a person.
namespace vh::health {

// A row of health_finding_state.
struct Mark {
    std::string cls;
    std::string subject;   // "" for the whole server
    std::string state;     // "acknowledged" | "silenced"
    std::string severity;  // the class's severity when the mark was set: "warning" | "error"
    std::optional<std::uint32_t> setBy{};
    std::string setByName;
    std::uint64_t setAt = 0;                 // epoch seconds
    std::optional<std::uint64_t> expiresAt{};  // epoch seconds; never for an acknowledgement
    std::optional<std::string> note{};
};

// A finding as a card raised it.
struct Active {
    std::string code;
    std::string subject;
    std::string cardId;
    std::string severity;  // "warning" | "error"
    std::string title;     // the card's
    std::string message;
    std::optional<std::string> href{};
    std::optional<std::string> metricKey{};
};

struct Finding {
    Active raised;
    std::string state = "active";  // "active" | "acknowledged" | "silenced"
    std::optional<Mark> mark{};      // the mark behind `state`, when it isn't "active"
};

using Key = std::pair<std::string, std::string>;  // class, subject

struct Resolution {
    std::vector<Finding> findings;  // every active finding, in the order given
    std::vector<Mark> silences;     // silences whose class isn't active now
    std::vector<Key> stale;         // marks to delete: expired, or acknowledgements whose occurrence is over
    std::uint32_t unattendedErrors = 0;
    std::uint32_t unattendedWarnings = 0;
};

// The rules, pure:
//  - a mark past its expiry no longer exists;
//  - an acknowledgement covers the occurrence it was made for: it ends when the finding clears, and when the
//    finding's severity rises above the one acknowledged;
//  - a silence covers its class while the severity is no higher than the one silenced, and survives the finding
//    clearing and returning;
//  - "unattended" counts the findings no mark covers.
[[nodiscard]] Resolution resolve(const std::vector<Active>& active, const std::vector<Mark>& marks, std::uint64_t now);

// 2 error, 1 warning, 0 anything else.
[[nodiscard]] int severityRank(std::string_view severity) noexcept;

struct Snapshot {
    std::string overallStatus;
    std::uint32_t errorCount = 0;
    std::uint32_t warningCount = 0;
    std::uint32_t unattendedErrorCount = 0;
    std::uint32_t unattendedWarningCount = 0;
    std::uint64_t checkedAt = 0;
    std::vector<Finding> findings{};
    std::vector<Mark> silences{};
};

// The findings of an overview as `resolve` takes them.
[[nodiscard]] std::vector<Active> activeFindings(const stats::model::DashboardOverview& overview);

// The current findings with their state: evaluates the dashboard (severity only: no trend series), reads the marks,
// applies the rules and deletes the stale marks. Reads the database.
[[nodiscard]] Snapshot snapshot();
// The same for an overview already built (stats.dashboard.overview): sets each attention item's state and the
// overview's unattended counts. If the marks can't be read, nothing is marked: every finding stays unattended.
void annotate(stats::model::DashboardOverview& overview);

// Tests only: what the cards raise comes from `source` instead of the dashboard, until reset with an empty function.
void setActiveSourceForTesting(std::function<std::vector<Active>()> source);

// A value that changes exactly when what a client would show changes: the findings, their severities and states.
[[nodiscard]] std::string digest(const Snapshot& snapshot);

void to_json(nlohmann::json& j, const Mark& mark);
void to_json(nlohmann::json& j, const Finding& finding);
void to_json(nlohmann::json& j, const Snapshot& snapshot);

}
