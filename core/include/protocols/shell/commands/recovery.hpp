#pragma once

#include "ops/Recovery.hpp"
#include "protocols/shell/Fwd.hpp"
#include "protocols/shell/types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Shared by the file-recovery CLI adapters: `vh recovery …` (recovery.cpp, which defines these), `vh snapshot …`
// (snapshot.cpp) and `vh vault recovery …` (vault/recovery.cpp). Human formatting of the ops::recovery results;
// --json prints the shared shapes from ops/RecoveryJson.hpp instead.
namespace vh::protocols::shell::commands::recovery_cli {

// The positional vault (name with --owner, or id) as an id; ops::Invalid when it doesn't resolve.
[[nodiscard]] uint32_t vaultIdFrom(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage,
                                   const std::string& prefix, std::size_t index = 0);

// "12.50 USD", or "cannot be estimated (<reason>)" when unknown; never a made-up zero.
[[nodiscard]] std::string formatMoney(const std::optional<vh::recovery::Money>& money,
                                      const std::optional<std::string>& reason = std::nullopt);
[[nodiscard]] std::string formatFigure(const vh::recovery::CostFigure& figure);

[[nodiscard]] std::string formatPoints(const std::vector<vh::recovery::RecoveryPoint>& points);
[[nodiscard]] std::string formatDetail(const ops::recovery::PointDetail& detail);
[[nodiscard]] std::string formatPlan(const vh::recovery::Plan& plan);
[[nodiscard]] std::string formatResult(const vh::recovery::RestoreResult& result);
[[nodiscard]] std::string formatStatus(const vh::recovery::Status& status);
[[nodiscard]] std::string formatCosts(const vh::recovery::CostReport& report);
[[nodiscard]] std::string formatDisclosure(const vh::recovery::Disclosure& disclosure);

// JSON text (pretty, newline-terminated) of anything ops/RecoveryJson.hpp serializes.
[[nodiscard]] std::string jsonText(const vh::recovery::Plan& v);
[[nodiscard]] std::string jsonText(const vh::recovery::RestoreResult& v);
[[nodiscard]] std::string jsonText(const vh::recovery::Status& v);
[[nodiscard]] std::string jsonText(const vh::recovery::CostReport& v);
[[nodiscard]] std::string jsonText(const vh::recovery::Disclosure& v);
[[nodiscard]] std::string jsonText(const ops::recovery::PointDetail& v);
[[nodiscard]] std::string jsonText(const std::vector<vh::recovery::RecoveryPoint>& v);

// Runs `op(confirmed)`; a NeedsConfirmation{code} is asked at the terminal (the person types `word`) or answered by
// --yes, then the op runs again confirmed. Without a terminal and --yes it refuses with the op's text and how to
// re-run. Any other refusal is exit 2 with "<prefix>: <reason>".
CommandResult runConfirmedText(const CommandCall& call, const std::string& prefix, const std::string& code,
                               const std::string& word, const std::function<std::string(bool confirmed)>& op);

}
