#include "email/templates/OperatorTemplates.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace vh::email::templates {

namespace {

std::string formatUnixTime(const std::uint64_t ts) {
    if (ts == 0) return "unknown";
    const auto raw = static_cast<std::time_t>(ts);
    std::tm utc{};
    gmtime_r(&raw, &utc);

    std::ostringstream out;
    out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

void appendMetricRow(std::ostringstream& html, const std::string& label, const std::string& value) {
    html << "<tr><td style=\"padding:10px 0;color:#5a6778;width:160px;\">"
         << escapeHtml(label) << "</td><td style=\"padding:10px 0;font-weight:600;\">"
         << escapeHtml(value) << "</td></tr>";
}

void appendListHtml(std::ostringstream& html, const std::string& title, const std::vector<std::string>& items) {
    if (items.empty()) return;

    html << "<h2 style=\"margin:22px 0 8px;font-size:16px;line-height:1.3;\">"
         << escapeHtml(title) << "</h2>"
         << "<ul style=\"margin:0;padding-left:20px;font-size:14px;line-height:1.6;\">";
    for (const auto& item : items)
        html << "<li>" << escapeHtml(item) << "</li>";
    html << "</ul>";
}

void appendListText(std::ostringstream& text, const std::string& title, const std::vector<std::string>& items) {
    if (items.empty()) return;

    text << "\n" << title << ":\n";
    for (const auto& item : items)
        text << "- " << item << "\n";
}

std::string severityAccent(const std::string& severity) {
    if (severity == "critical") return "#b42318";
    if (severity == "warning") return "#b54708";
    return "#027a48";
}

std::string readiness(std::size_t ready, std::size_t total) {
    return std::to_string(ready) + "/" + std::to_string(total);
}

std::string statusAccent(const std::string& status) {
    if (status == "error" || status == "critical") return "#b42318";
    if (status == "warning" || status == "degraded") return "#b54708";
    if (status == "healthy") return "#027a48";
    return "#5a6778";
}

void appendDigestSectionHtml(std::ostringstream& html, const WeeklyDigestSection& section) {
    html << "<tr>"
         << "<td style=\"padding:12px 0;border-top:1px solid #e6edf5;font-weight:600;\">"
         << escapeHtml(section.title) << "</td>"
         << "<td style=\"padding:12px 0;border-top:1px solid #e6edf5;color:"
         << statusAccent(section.severity) << ";font-weight:600;\">"
         << escapeHtml(section.severity) << "</td>"
         << "<td style=\"padding:12px 0;border-top:1px solid #e6edf5;color:#5a6778;\">"
         << escapeHtml(section.summary) << "</td>"
         << "<td style=\"padding:12px 0;border-top:1px solid #e6edf5;text-align:right;\">"
         << section.warningCount << "/" << section.errorCount << "</td>"
         << "</tr>";
}

void appendDigestAttentionHtml(std::ostringstream& html, const std::vector<WeeklyDigestAttentionItem>& items) {
    if (items.empty()) return;

    html << "<h2 style=\"margin:24px 0 8px;font-size:16px;line-height:1.3;\">Attention</h2>"
         << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px;\">";
    for (const auto& item : items) {
        html << "<tr>"
             << "<td style=\"padding:10px 0;border-top:1px solid #e6edf5;color:"
             << statusAccent(item.severity) << ";font-weight:600;width:90px;\">"
             << escapeHtml(item.severity) << "</td>"
             << "<td style=\"padding:10px 0;border-top:1px solid #e6edf5;\">"
             << "<div style=\"font-weight:600;\">" << escapeHtml(item.title) << "</div>"
             << "<div style=\"color:#5a6778;line-height:1.5;\">" << escapeHtml(item.message) << "</div>"
             << "</td></tr>";
    }
    html << "</table>";
}

void appendDigestSectionsText(std::ostringstream& text, const std::vector<WeeklyDigestSection>& sections) {
    if (sections.empty()) return;

    text << "\nSections:\n";
    for (const auto& section : sections) {
        text << "- " << section.title
             << " [" << section.severity << "] "
             << section.summary
             << " (warnings/errors: " << section.warningCount << "/" << section.errorCount << ")\n";
    }
}

void appendDigestAttentionText(std::ostringstream& text, const std::vector<WeeklyDigestAttentionItem>& items) {
    if (items.empty()) return;

    text << "\nAttention:\n";
    for (const auto& item : items)
        text << "- [" << item.severity << "] " << item.title << ": " << item.message << "\n";
}

std::string securityActionTitle(const std::string& action) {
    if (action == "created") return "Admin role created";
    if (action == "updated") return "Admin role updated";
    if (action == "deleted") return "Admin role deleted";
    return "Admin role changed";
}

RenderedEmail renderWatchdogEmail(const WatchdogEmailContext& ctx, const bool recovery) {
    const auto checkedAt = formatUnixTime(ctx.checkedAt);
    const auto accent = recovery ? std::string("#027a48") : severityAccent(ctx.severity);
    const auto title = recovery ? "Runtime recovered" : "Runtime health alert";
    const auto intro = recovery
        ? "Vaulthalla runtime health has returned to a healthy state."
        : "Vaulthalla runtime health needs operator attention.";

    std::ostringstream html;
    html
        << "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;color:#172033;"
        << "font-family:Inter,Segoe UI,Arial,sans-serif;\">"
        << "<div style=\"max-width:680px;margin:0 auto;padding:32px 20px;\">"
        << "<div style=\"background:#ffffff;border:1px solid #d9e1ec;border-radius:8px;overflow:hidden;\">"
        << "<div style=\"background:#172033;color:#ffffff;padding:20px 24px;border-top:5px solid "
        << accent << ";\">"
        << "<div style=\"font-size:13px;letter-spacing:0;text-transform:uppercase;color:#a7b5c8;\">"
        << "Vaulthalla operator email</div>"
        << "<h1 style=\"margin:8px 0 0;font-size:24px;line-height:1.25;\">" << title << "</h1>"
        << "</div>"
        << "<div style=\"padding:24px;\">"
        << "<p style=\"margin:0 0 18px;font-size:15px;line-height:1.6;\">"
        << intro << "</p>"
        << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px;\">";

    appendMetricRow(html, "Instance", ctx.instance);
    appendMetricRow(html, "Status", ctx.status);
    appendMetricRow(html, "Severity", ctx.severity);
    appendMetricRow(html, "Checked at", checkedAt);
    appendMetricRow(html, "Services", readiness(ctx.servicesReady, ctx.servicesTotal));
    appendMetricRow(html, "Dependencies", readiness(ctx.depsReady, ctx.depsTotal));
    appendMetricRow(html, "Protocols", readiness(ctx.protocolsReady, ctx.protocolsTotal));
    appendMetricRow(html, "Fingerprint", ctx.fingerprint);

    html << "</table>";
    appendListHtml(html, "Failed services", ctx.failedServices);
    appendListHtml(html, "Missing dependencies", ctx.missingDependencies);
    appendListHtml(html, "Protocol issues", ctx.protocolIssues);

    if (ctx.baseUrl)
        html << "<p style=\"margin:22px 0 0;font-size:14px;line-height:1.6;\">"
             << "<a href=\"" << escapeHtml(*ctx.baseUrl) << "\" style=\"color:#0b62b4;\">Open Vaulthalla</a>"
             << "</p>";

    html << "</div></div></div></body></html>";

    std::ostringstream text;
    text << "[Vaulthalla] " << title << "\n\n"
         << intro << "\n\n"
         << "Instance: " << ctx.instance << "\n"
         << "Status: " << ctx.status << "\n"
         << "Severity: " << ctx.severity << "\n"
         << "Checked at: " << checkedAt << "\n"
         << "Services: " << readiness(ctx.servicesReady, ctx.servicesTotal) << "\n"
         << "Dependencies: " << readiness(ctx.depsReady, ctx.depsTotal) << "\n"
         << "Protocols: " << readiness(ctx.protocolsReady, ctx.protocolsTotal) << "\n"
         << "Fingerprint: " << ctx.fingerprint << "\n";
    appendListText(text, "Failed services", ctx.failedServices);
    appendListText(text, "Missing dependencies", ctx.missingDependencies);
    appendListText(text, "Protocol issues", ctx.protocolIssues);
    if (ctx.baseUrl) text << "\nURL: " << *ctx.baseUrl << "\n";

    return {
        .subject = recovery
            ? "[Vaulthalla] Runtime recovered"
            : "[Vaulthalla] Runtime " + ctx.severity + ": " + ctx.status,
        .html = html.str(),
        .text = text.str()
    };
}

}

std::string escapeHtml(const std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

RenderedEmail renderTestEmail(const TestEmailContext& ctx) {
    const auto provider = escapeHtml(ctx.provider);
    const auto instance = escapeHtml(ctx.instance);
    const auto from = escapeHtml(ctx.from);
    const auto recipient = escapeHtml(ctx.recipient);
    const auto mode = ctx.dryRun ? "Dry run" : "Send";

    std::ostringstream html;
    html
        << "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;color:#172033;"
        << "font-family:Inter,Segoe UI,Arial,sans-serif;\">"
        << "<div style=\"max-width:640px;margin:0 auto;padding:32px 20px;\">"
        << "<div style=\"background:#ffffff;border:1px solid #d9e1ec;border-radius:8px;"
        << "overflow:hidden;\">"
        << "<div style=\"background:#172033;color:#ffffff;padding:20px 24px;\">"
        << "<div style=\"font-size:13px;letter-spacing:0;text-transform:uppercase;"
        << "color:#a7b5c8;\">Vaulthalla operator email</div>"
        << "<h1 style=\"margin:8px 0 0;font-size:24px;line-height:1.25;\">Test email</h1>"
        << "</div>"
        << "<div style=\"padding:24px;\">"
        << "<p style=\"margin:0 0 18px;font-size:15px;line-height:1.6;\">"
        << "This is a rendered operator email preview for " << instance << ".</p>"
        << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;"
        << "font-size:14px;\">"
        << "<tr><td style=\"padding:10px 0;color:#5a6778;width:140px;\">Mode</td>"
        << "<td style=\"padding:10px 0;font-weight:600;\">" << mode << "</td></tr>"
        << "<tr><td style=\"padding:10px 0;color:#5a6778;\">Provider</td>"
        << "<td style=\"padding:10px 0;font-weight:600;\">" << provider << "</td></tr>"
        << "<tr><td style=\"padding:10px 0;color:#5a6778;\">From</td>"
        << "<td style=\"padding:10px 0;font-weight:600;\">" << from << "</td></tr>"
        << "<tr><td style=\"padding:10px 0;color:#5a6778;\">Recipient</td>"
        << "<td style=\"padding:10px 0;font-weight:600;\">" << recipient << "</td></tr>"
        << "</table>";

    if (ctx.baseUrl)
        html << "<p style=\"margin:20px 0 0;font-size:14px;line-height:1.6;\">"
             << "<a href=\"" << escapeHtml(*ctx.baseUrl) << "\" style=\"color:#0b62b4;\">Open Vaulthalla</a>"
             << "</p>";

    html
        << "</div></div></div></body></html>";

    std::ostringstream text;
    text << "[Vaulthalla] Test operator email\n\n"
         << "Instance: " << ctx.instance << "\n"
         << "Mode: " << mode << "\n"
         << "Provider: " << ctx.provider << "\n"
         << "From: " << ctx.from << "\n"
         << "Recipient: " << ctx.recipient << "\n";
    if (ctx.baseUrl) text << "URL: " << *ctx.baseUrl << "\n";

    return {
        .subject = "[Vaulthalla] Test operator email",
        .html = html.str(),
        .text = text.str()
    };
}

RenderedEmail renderWatchdogAlertEmail(const WatchdogEmailContext& ctx) {
    return renderWatchdogEmail(ctx, false);
}

RenderedEmail renderWatchdogRecoveryEmail(const WatchdogEmailContext& ctx) {
    return renderWatchdogEmail(ctx, true);
}

RenderedEmail renderWeeklyDigestEmail(const WeeklyDigestEmailContext& ctx) {
    const auto checkedAt = formatUnixTime(ctx.checkedAt);
    const auto accent = statusAccent(ctx.dashboardStatus);

    std::ostringstream html;
    html
        << "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;color:#172033;"
        << "font-family:Inter,Segoe UI,Arial,sans-serif;\">"
        << "<div style=\"max-width:720px;margin:0 auto;padding:32px 20px;\">"
        << "<div style=\"background:#ffffff;border:1px solid #d9e1ec;border-radius:8px;overflow:hidden;\">"
        << "<div style=\"background:#172033;color:#ffffff;padding:20px 24px;border-top:5px solid "
        << accent << ";\">"
        << "<div style=\"font-size:13px;letter-spacing:0;text-transform:uppercase;color:#a7b5c8;\">"
        << "Vaulthalla operator digest</div>"
        << "<h1 style=\"margin:8px 0 0;font-size:24px;line-height:1.25;\">Weekly digest</h1>"
        << "</div>"
        << "<div style=\"padding:24px;\">"
        << "<p style=\"margin:0 0 18px;font-size:15px;line-height:1.6;\">"
        << "Summary for " << escapeHtml(ctx.instance) << " covering "
        << escapeHtml(ctx.weekStart) << " through " << escapeHtml(ctx.weekEnd) << ".</p>"
        << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px;\">";

    appendMetricRow(html, "Dashboard", ctx.dashboardStatus);
    appendMetricRow(html, "System health", ctx.systemStatus);
    appendMetricRow(html, "Warnings/errors", std::to_string(ctx.warningCount) + "/" + std::to_string(ctx.errorCount));
    appendMetricRow(html, "Services", readiness(ctx.servicesReady, ctx.servicesTotal));
    appendMetricRow(html, "Dependencies", readiness(ctx.depsReady, ctx.depsTotal));
    appendMetricRow(html, "Protocols", readiness(ctx.protocolsReady, ctx.protocolsTotal));
    appendMetricRow(html, "Checked at", checkedAt);
    appendMetricRow(html, "Schedule", ctx.scheduledWeekday + " " + std::to_string(ctx.scheduledHourUtc) + ":00 UTC");
    appendMetricRow(html, "Configured timezone", ctx.timezone);
    html << "</table>";

    if (!ctx.dashboardAvailable) {
        html << "<p style=\"margin:20px 0 0;padding:12px 14px;background:#fff7ed;border:1px solid #fed7aa;"
             << "border-radius:6px;color:#9a3412;font-size:14px;line-height:1.5;\">"
             << "Dashboard data unavailable";
        if (ctx.dashboardUnavailableReason)
            html << ": " << escapeHtml(*ctx.dashboardUnavailableReason);
        html << "</p>";
    }

    appendDigestAttentionHtml(html, ctx.attention);

    if (!ctx.sections.empty()) {
        html << "<h2 style=\"margin:24px 0 8px;font-size:16px;line-height:1.3;\">Sections</h2>"
             << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px;\">"
             << "<tr><th align=\"left\" style=\"padding:8px 0;color:#5a6778;font-weight:600;\">Section</th>"
             << "<th align=\"left\" style=\"padding:8px 0;color:#5a6778;font-weight:600;\">Status</th>"
             << "<th align=\"left\" style=\"padding:8px 0;color:#5a6778;font-weight:600;\">Summary</th>"
             << "<th align=\"right\" style=\"padding:8px 0;color:#5a6778;font-weight:600;\">W/E</th></tr>";
        for (const auto& section : ctx.sections)
            appendDigestSectionHtml(html, section);
        html << "</table>";
    }

    if (ctx.baseUrl)
        html << "<p style=\"margin:22px 0 0;font-size:14px;line-height:1.6;\">"
             << "<a href=\"" << escapeHtml(*ctx.baseUrl) << "\" style=\"color:#0b62b4;\">Open Vaulthalla</a>"
             << "</p>";

    html << "</div></div></div></body></html>";

    std::ostringstream text;
    text << "[Vaulthalla] Weekly digest\n\n"
         << "Instance: " << ctx.instance << "\n"
         << "Week: " << ctx.weekStart << " through " << ctx.weekEnd << "\n"
         << "Dashboard: " << ctx.dashboardStatus << "\n"
         << "System health: " << ctx.systemStatus << "\n"
         << "Warnings/errors: " << ctx.warningCount << "/" << ctx.errorCount << "\n"
         << "Services: " << readiness(ctx.servicesReady, ctx.servicesTotal) << "\n"
         << "Dependencies: " << readiness(ctx.depsReady, ctx.depsTotal) << "\n"
         << "Protocols: " << readiness(ctx.protocolsReady, ctx.protocolsTotal) << "\n"
         << "Checked at: " << checkedAt << "\n"
         << "Schedule: " << ctx.scheduledWeekday << " " << ctx.scheduledHourUtc << ":00 UTC\n"
         << "Configured timezone: " << ctx.timezone << "\n";
    if (!ctx.dashboardAvailable) {
        text << "Dashboard data unavailable";
        if (ctx.dashboardUnavailableReason)
            text << ": " << *ctx.dashboardUnavailableReason;
        text << "\n";
    }
    appendDigestAttentionText(text, ctx.attention);
    appendDigestSectionsText(text, ctx.sections);
    if (ctx.baseUrl) text << "\nURL: " << *ctx.baseUrl << "\n";

    return {
        .subject = "[Vaulthalla] Weekly digest: " + ctx.dashboardStatus,
        .html = html.str(),
        .text = text.str()
    };
}

RenderedEmail renderSecurityAlertEmail(const SecurityAlertEmailContext& ctx) {
    const auto occurredAt = formatUnixTime(ctx.occurredAt);
    const auto accent = severityAccent(ctx.severity);
    const auto title = securityActionTitle(ctx.action);
    const auto roleLabel = ctx.roleName.empty()
        ? std::string("role #") + std::to_string(ctx.roleId)
        : ctx.roleName;

    std::ostringstream html;
    html
        << "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;color:#172033;"
        << "font-family:Inter,Segoe UI,Arial,sans-serif;\">"
        << "<div style=\"max-width:680px;margin:0 auto;padding:32px 20px;\">"
        << "<div style=\"background:#ffffff;border:1px solid #d9e1ec;border-radius:8px;overflow:hidden;\">"
        << "<div style=\"background:#172033;color:#ffffff;padding:20px 24px;border-top:5px solid "
        << accent << ";\">"
        << "<div style=\"font-size:13px;letter-spacing:0;text-transform:uppercase;color:#a7b5c8;\">"
        << "Vaulthalla security alert</div>"
        << "<h1 style=\"margin:8px 0 0;font-size:24px;line-height:1.25;\">"
        << escapeHtml(title) << "</h1>"
        << "</div>"
        << "<div style=\"padding:24px;\">"
        << "<p style=\"margin:0 0 18px;font-size:15px;line-height:1.6;\">"
        << "An administrative role was " << escapeHtml(ctx.action)
        << " on " << escapeHtml(ctx.instance) << ".</p>"
        << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px;\">";

    appendMetricRow(html, "Instance", ctx.instance);
    appendMetricRow(html, "Severity", ctx.severity);
    appendMetricRow(html, "Occurred at", occurredAt);
    appendMetricRow(html, "Action", ctx.action);
    appendMetricRow(html, "Role", roleLabel);
    appendMetricRow(html, "Role ID", std::to_string(ctx.roleId));
    appendMetricRow(html, "Actor", ctx.actor);
    appendMetricRow(html, "Source", ctx.source);
    if (!ctx.roleDescription.empty())
        appendMetricRow(html, "Description", ctx.roleDescription);
    html << "</table>";

    appendListHtml(html, "Permission flags", ctx.permissionFlags);

    if (ctx.baseUrl)
        html << "<p style=\"margin:22px 0 0;font-size:14px;line-height:1.6;\">"
             << "<a href=\"" << escapeHtml(*ctx.baseUrl) << "\" style=\"color:#0b62b4;\">Open Vaulthalla</a>"
             << "</p>";

    html << "</div></div></div></body></html>";

    std::ostringstream text;
    text << "[Vaulthalla] Security alert: " << title << "\n\n"
         << "An administrative role was " << ctx.action << " on " << ctx.instance << ".\n\n"
         << "Instance: " << ctx.instance << "\n"
         << "Severity: " << ctx.severity << "\n"
         << "Occurred at: " << occurredAt << "\n"
         << "Action: " << ctx.action << "\n"
         << "Role: " << roleLabel << "\n"
         << "Role ID: " << ctx.roleId << "\n"
         << "Actor: " << ctx.actor << "\n"
         << "Source: " << ctx.source << "\n";
    if (!ctx.roleDescription.empty())
        text << "Description: " << ctx.roleDescription << "\n";
    appendListText(text, "Permission flags", ctx.permissionFlags);
    if (ctx.baseUrl) text << "\nURL: " << *ctx.baseUrl << "\n";

    return {
        .subject = "[Vaulthalla] Security alert: admin role " + ctx.action,
        .html = html.str(),
        .text = text.str()
    };
}

RenderedEmail renderAccountSecurityEmail(const AccountSecurityEmailContext& ctx) {
    const auto occurredAt = formatUnixTime(ctx.occurredAt);
    const auto accent = severityAccent(ctx.severity);

    std::ostringstream html;
    html
        << "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;color:#172033;"
        << "font-family:Inter,Segoe UI,Arial,sans-serif;\">"
        << "<div style=\"max-width:680px;margin:0 auto;padding:32px 20px;\">"
        << "<div style=\"background:#ffffff;border:1px solid #d9e1ec;border-radius:8px;overflow:hidden;\">"
        << "<div style=\"background:#172033;color:#ffffff;padding:20px 24px;border-top:5px solid "
        << accent << ";\">"
        << "<div style=\"font-size:13px;letter-spacing:0;text-transform:uppercase;color:#a7b5c8;\">"
        << "Vaulthalla account security</div>"
        << "<h1 style=\"margin:8px 0 0;font-size:24px;line-height:1.25;\">"
        << escapeHtml(ctx.title) << "</h1>"
        << "</div>"
        << "<div style=\"padding:24px;\">"
        << "<p style=\"margin:0 0 18px;font-size:15px;line-height:1.6;\">"
        << escapeHtml(ctx.summary) << "</p>"
        << "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;font-size:14px;\">";

    appendMetricRow(html, "Instance", ctx.instance);
    appendMetricRow(html, "Occurred at", occurredAt);
    for (const auto& [label, value] : ctx.facts) appendMetricRow(html, label, value);
    html << "</table>";

    if (ctx.advice)
        html << "<p style=\"margin:22px 0 0;font-size:14px;line-height:1.6;\">" << escapeHtml(*ctx.advice) << "</p>";
    if (ctx.baseUrl)
        html << "<p style=\"margin:22px 0 0;font-size:14px;line-height:1.6;\">"
             << "<a href=\"" << escapeHtml(*ctx.baseUrl) << "\" style=\"color:#0b62b4;\">Open Vaulthalla</a>"
             << "</p>";
    html << "</div></div></div></body></html>";

    std::ostringstream text;
    text << "[Vaulthalla] " << ctx.title << "\n\n" << ctx.summary << "\n\n"
         << "Instance: " << ctx.instance << "\n"
         << "Occurred at: " << occurredAt << "\n";
    for (const auto& [label, value] : ctx.facts) text << label << ": " << value << "\n";
    if (ctx.advice) text << "\n" << *ctx.advice << "\n";
    if (ctx.baseUrl) text << "\nURL: " << *ctx.baseUrl << "\n";

    return {.subject = "[Vaulthalla] " + ctx.title, .html = html.str(), .text = text.str()};
}

}
