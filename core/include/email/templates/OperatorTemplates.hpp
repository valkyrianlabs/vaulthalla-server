#pragma once

#include "email/RenderedEmail.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vh::email::templates {

struct TestEmailContext {
    std::string provider;
    std::string instance;
    std::string from;
    std::string recipient;
    bool dryRun = true;
    std::optional<std::string> baseUrl;
};

struct WatchdogEmailContext {
    std::string instance;
    std::string status;
    std::string severity;
    std::string fingerprint;
    std::uint64_t checkedAt = 0;
    std::size_t servicesReady = 0;
    std::size_t servicesTotal = 0;
    std::size_t depsReady = 0;
    std::size_t depsTotal = 0;
    std::size_t protocolsReady = 0;
    std::size_t protocolsTotal = 0;
    std::vector<std::string> failedServices;
    std::vector<std::string> missingDependencies;
    std::vector<std::string> protocolIssues;
    std::optional<std::string> baseUrl;
};

struct WeeklyDigestSection {
    std::string title;
    std::string severity;
    std::string summary;
    std::uint32_t warningCount = 0;
    std::uint32_t errorCount = 0;
};

struct WeeklyDigestAttentionItem {
    std::string title;
    std::string severity;
    std::string message;
};

struct WeeklyDigestEmailContext {
    std::string instance;
    std::string weekStart;
    std::string weekEnd;
    std::string scheduledWeekday;
    std::uint32_t scheduledHourUtc = 0;
    std::string timezone;
    std::uint64_t checkedAt = 0;
    std::string systemStatus;
    std::string dashboardStatus;
    std::uint32_t warningCount = 0;
    std::uint32_t errorCount = 0;
    std::size_t servicesReady = 0;
    std::size_t servicesTotal = 0;
    std::size_t depsReady = 0;
    std::size_t depsTotal = 0;
    std::size_t protocolsReady = 0;
    std::size_t protocolsTotal = 0;
    bool dashboardAvailable = true;
    std::optional<std::string> dashboardUnavailableReason;
    std::vector<WeeklyDigestSection> sections;
    std::vector<WeeklyDigestAttentionItem> attention;
    std::optional<std::string> baseUrl;
};

struct SecurityAlertEmailContext {
    std::string instance;
    std::string action;
    std::string severity;
    std::uint64_t occurredAt = 0;
    std::uint32_t roleId = 0;
    std::string roleName;
    std::string roleDescription;
    std::string actor;
    std::string source;
    std::vector<std::string> permissionFlags;
    std::optional<std::string> baseUrl;
};

// An account-security notice (#360; MFA design note section 7): a recovery-code sign-in, an MFA reset, a factor change,
// repeated second-factor failures, an MFA policy weakened. Sent to the security recipients and, in a second message,
// to the account's own address. `facts` are label/value rows (ids, counts, times): never codes, secrets or paths.
struct AccountSecurityEmailContext {
    std::string instance;
    std::string title;    // "Recovery code used", "MFA reset", ...
    std::string summary;  // one sentence
    std::string severity = "warning";
    std::uint64_t occurredAt = 0;
    std::vector<std::pair<std::string, std::string>> facts;
    std::optional<std::string> advice;  // what the reader should do if it wasn't them
    std::optional<std::string> baseUrl;
};

[[nodiscard]] std::string escapeHtml(std::string_view value);
[[nodiscard]] RenderedEmail renderTestEmail(const TestEmailContext& ctx);
[[nodiscard]] RenderedEmail renderWatchdogAlertEmail(const WatchdogEmailContext& ctx);
[[nodiscard]] RenderedEmail renderWatchdogRecoveryEmail(const WatchdogEmailContext& ctx);
[[nodiscard]] RenderedEmail renderWeeklyDigestEmail(const WeeklyDigestEmailContext& ctx);
[[nodiscard]] RenderedEmail renderSecurityAlertEmail(const SecurityAlertEmailContext& ctx);
[[nodiscard]] RenderedEmail renderAccountSecurityEmail(const AccountSecurityEmailContext& ctx);

}
