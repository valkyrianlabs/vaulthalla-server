#include "health/Findings.hpp"

#include "db/query/health/FindingState.hpp"
#include "log/Registry.hpp"
#include "stats/model/DashboardOverview.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <functional>
#include <map>
#include <mutex>

namespace vh::health {

namespace {

std::uint64_t nowSeconds() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
}

nlohmann::json nullable(const std::optional<std::string>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

// The marks as stored, or nothing when they can't be read: then no finding is marked, which hides nothing.
std::vector<Mark> readMarks() {
    try {
        return db::query::health::FindingState::list();
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[health] finding state unavailable: {}", e.what());
        return {};
    }
}

// The findings as the cards raise them now, with the dashboard's own status and counts.
struct Raised {
    std::string status;
    std::uint32_t errors = 0;
    std::uint32_t warnings = 0;
    std::uint64_t checkedAt = 0;
    std::vector<Active> active;
};

std::function<std::vector<Active>()>& testSource() {
    static std::function<std::vector<Active>()> source;
    return source;
}

Raised raisedNow() {
    Raised out;
    if (const auto& source = testSource()) {
        out.active = source();
        out.checkedAt = nowSeconds();
        for (const auto& finding : out.active) {
            if (finding.severity == "error") ++out.errors;
            else ++out.warnings;
        }
        out.status = out.errors > 0 ? "error" : out.warnings > 0 ? "warning" : "healthy";
        return out;
    }
    const auto overview = stats::model::DashboardOverview::severity();
    out.status = overview.overallStatus;
    out.errors = overview.errorCount;
    out.warnings = overview.warningCount;
    out.checkedAt = overview.checkedAt;
    out.active = activeFindings(overview);
    return out;
}

void forget(const std::vector<Key>& stale) {
    if (stale.empty()) return;
    try {
        db::query::health::FindingState::remove(stale);
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[health] stale finding state not removed: {}", e.what());
    }
}

}

int severityRank(const std::string_view severity) noexcept {
    if (severity == "error") return 2;
    if (severity == "warning") return 1;
    return 0;
}

Resolution resolve(const std::vector<Active>& active, const std::vector<Mark>& marks, const std::uint64_t now) {
    Resolution out;
    std::map<Key, const Mark*> live;
    for (const auto& mark : marks) {
        if (mark.expiresAt && *mark.expiresAt <= now) {
            out.stale.emplace_back(mark.cls, mark.subject);
            continue;
        }
        live[{mark.cls, mark.subject}] = &mark;
    }

    std::map<Key, bool> seen;
    out.findings.reserve(active.size());
    for (const auto& raised : active) {
        const Key key{raised.code, raised.subject};
        seen[key] = true;
        Finding finding{.raised = raised};
        if (const auto it = live.find(key); it != live.end()) {
            const auto& mark = *it->second;
            const bool covered = severityRank(raised.severity) <= severityRank(mark.severity);
            if (covered) {
                finding.state = mark.state;
                finding.mark = mark;
            } else if (mark.state == "acknowledged") {
                // It got worse than what was acknowledged: that acknowledgement is over.
                out.stale.push_back(key);
            }
            // A silence the severity outgrew stays: it still covers the class at the severity it was set for.
        }
        if (finding.state == "active") {
            if (raised.severity == "error") ++out.unattendedErrors;
            else ++out.unattendedWarnings;
        }
        out.findings.push_back(std::move(finding));
    }

    for (const auto& [key, mark] : live) {
        if (seen.contains(key)) continue;
        if (mark->state == "acknowledged") out.stale.push_back(key);  // its occurrence is over
        else out.silences.push_back(*mark);
    }
    return out;
}

std::vector<Active> activeFindings(const stats::model::DashboardOverview& overview) {
    std::vector<Active> out;
    out.reserve(overview.attention.size());
    for (const auto& item : overview.attention)
        out.push_back({.code = item.code,
                       .subject = "",
                       .cardId = item.cardId,
                       .severity = item.severity,
                       .title = item.title,
                       .message = item.message,
                       .href = item.href,
                       .metricKey = item.metricKey});
    return out;
}

namespace {

struct HealthStateListener {
    std::mutex mutex;
    std::function<void()> listener;
};

HealthStateListener& healthStateListener() {
    static HealthStateListener held;
    return held;
}

}

void stateChanged() noexcept {
    try {
        std::function<void()> listener;
        {
            auto& held = healthStateListener();
            std::scoped_lock lock(held.mutex);
            listener = held.listener;
        }
        if (listener) listener();
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[health] state change not passed on: {}", e.what());
    } catch (...) {
        log::Registry::vaulthalla()->warn("[health] state change not passed on");
    }
}

void setStateListener(std::function<void()> listener) {
    auto& held = healthStateListener();
    std::scoped_lock lock(held.mutex);
    held.listener = std::move(listener);
}

void setActiveSourceForTesting(std::function<std::vector<Active>()> source) { testSource() = std::move(source); }

Snapshot snapshot() {
    const auto raised = raisedNow();
    auto resolved = resolve(raised.active, readMarks(), nowSeconds());
    forget(resolved.stale);
    return {.overallStatus = raised.status,
            .errorCount = raised.errors,
            .warningCount = raised.warnings,
            .unattendedErrorCount = resolved.unattendedErrors,
            .unattendedWarningCount = resolved.unattendedWarnings,
            .checkedAt = raised.checkedAt,
            .findings = std::move(resolved.findings),
            .silences = std::move(resolved.silences)};
}

void annotate(stats::model::DashboardOverview& overview) {
    auto resolved = resolve(activeFindings(overview), readMarks(), nowSeconds());
    forget(resolved.stale);
    // resolve() keeps the order of activeFindings(), which is the attention list's.
    for (std::size_t i = 0; i < overview.attention.size() && i < resolved.findings.size(); ++i)
        overview.attention[i].state = resolved.findings[i].state;
    overview.unattendedErrorCount = resolved.unattendedErrors;
    overview.unattendedWarningCount = resolved.unattendedWarnings;
}

std::string digest(const Snapshot& snapshot) {
    std::vector<std::string> parts;
    parts.reserve(snapshot.findings.size() + snapshot.silences.size());
    for (const auto& finding : snapshot.findings)
        parts.push_back(finding.raised.code + "\x1f" + finding.raised.subject + "\x1f" + finding.raised.severity + "\x1f" +
                        finding.state);
    for (const auto& mark : snapshot.silences)
        parts.push_back("~" + mark.cls + "\x1f" + mark.subject + "\x1f" + mark.severity + "\x1f" +
                        std::to_string(mark.expiresAt.value_or(0)));
    std::ranges::sort(parts);
    std::string out = snapshot.overallStatus;
    for (const auto& part : parts) {
        out.push_back('\x1e');
        out += part;
    }
    return out;
}

void to_json(nlohmann::json& j, const Mark& mark) {
    j = nlohmann::json{
        {"class", mark.cls},
        {"subject", mark.subject},
        {"state", mark.state},
        {"severity", mark.severity},
        {"set_by", mark.setBy ? nlohmann::json(*mark.setBy) : nlohmann::json(nullptr)},
        {"set_by_name", mark.setByName},
        {"set_at", mark.setAt},
        {"expires_at", mark.expiresAt ? nlohmann::json(*mark.expiresAt) : nlohmann::json(nullptr)},
        {"note", nullable(mark.note)},
    };
}

void to_json(nlohmann::json& j, const Finding& finding) {
    const auto* cls = findClass(finding.raised.code);
    j = nlohmann::json{
        {"class", finding.raised.code},
        {"subject", finding.raised.subject},
        {"card_id", finding.raised.cardId},
        {"severity", finding.raised.severity},
        {"title", finding.raised.title},
        {"class_title", cls ? cls->title : finding.raised.title},
        {"message", finding.raised.message},
        {"href", nullable(finding.raised.href)},
        {"metric_key", nullable(finding.raised.metricKey)},
        // A class the catalog doesn't know is still shown, and is worth a person's attention until it is known.
        {"notifies", cls ? cls->notifies : true},
        {"state", finding.state},
        {"mark", finding.mark ? nlohmann::json(*finding.mark) : nlohmann::json(nullptr)},
        {"remedies", cls ? nlohmann::json(cls->remedies) : nlohmann::json::array()},
    };
}

void to_json(nlohmann::json& j, const Snapshot& snapshot) {
    j = nlohmann::json{
        {"overall_status", snapshot.overallStatus},
        {"error_count", snapshot.errorCount},
        {"warning_count", snapshot.warningCount},
        {"unattended_error_count", snapshot.unattendedErrorCount},
        {"unattended_warning_count", snapshot.unattendedWarningCount},
        {"checked_at", snapshot.checkedAt},
        {"findings", snapshot.findings},
        {"silences", snapshot.silences},
    };
}

}
