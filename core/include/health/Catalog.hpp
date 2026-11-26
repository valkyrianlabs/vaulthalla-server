#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The classes of health finding (design/health/findings.md §2, §8). A finding's class is the code its dashboard card
// raises it under (core/src/stats/model/DashboardOverview.cpp, dashboardOverviewAddIssue); the codes are a contract:
// one is never reused for another meaning. The catalog says, per class, whether it is worth interrupting someone
// (`notifies`) and what can be done about it (`remedies`). It is code, not data: a card that raises a code the
// catalog lacks fails HealthCatalog.CoversEveryCodeTheCardsRaise.
namespace vh::health {

// Something a person can do about a finding. It only names an existing place or command: whoever runs it goes
// through that command's own permission check, confirmation and audit. There is no remedy endpoint.
struct Remedy {
    std::string id;                      // stable within its class
    std::string label;
    std::string kind;                    // "open" | "command"
    std::optional<std::string> href;     // open: the console's route ("/cost#budget-alerts")
    std::optional<std::string> command;  // command: an existing ws command
    nlohmann::json payload = nullptr;    // command: its payload
    std::optional<std::string> effect;   // command: read | write | destructive (the ws book's)
};

struct FindingClass {
    std::string code;
    std::string cardId;
    std::string title;
    std::string maxSeverity;  // the worst severity the class is raised with: "warning" | "error"
    bool notifies = true;
    std::vector<Remedy> remedies;
};

[[nodiscard]] const std::vector<FindingClass>& catalog();
// nullptr for a code no card raises.
[[nodiscard]] const FindingClass* findClass(std::string_view code);

void to_json(nlohmann::json& j, const Remedy& remedy);
void to_json(nlohmann::json& j, const FindingClass& cls);

}
