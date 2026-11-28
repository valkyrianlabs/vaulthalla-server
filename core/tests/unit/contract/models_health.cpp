// Contract models: health findings against their declared shapes (see model_suites.hpp): vh::health::to_json for the
// remedy, the mark, the finding, the class and the snapshot (HealthFindings, with ops::health::list's additions).

#include "model_suites.hpp"

#include "health/Catalog.hpp"
#include "health/Findings.hpp"

namespace vh::test::contract_models {

using json = nlohmann::json;

void checkHealthModels(Checker& c) {
    const health::Remedy open{.id = "open", .label = "Open storage", .kind = "open", .href = "/health/storage"};
    const health::Remedy command{.id = "sync",
                                 .label = "Sync now",
                                 .kind = "command",
                                 .command = "storage.vault.sync",
                                 .payload = json{{"id", 3}},
                                 .effect = "write"};
    c.check(json(open), "HealthRemedy", "a place to open");
    c.check(json(command), "HealthRemedy", "a command to run");

    const health::Mark silenced{.cls = "system.operations.active_work",
                                .subject = "",
                                .state = "silenced",
                                .severity = "warning",
                                .setBy = 7,
                                .setByName = "admin",
                                .setAt = 1795700000,
                                .expiresAt = 1795786400,
                                .note = "Uploads all night."};
    const health::Mark acknowledged{.cls = "system.fuse.error_rate_high",
                                    .subject = "",
                                    .state = "acknowledged",
                                    .severity = "error",
                                    .setByName = "gone"};
    c.check(json(silenced), "HealthFindingMark", "a silence with an expiry and a note");
    c.check(json(acknowledged), "HealthFindingMark", "an acknowledgement by an account that is gone");

    const health::Active raised{.code = "system.fuse.error_rate_high",
                                .subject = "",
                                .cardId = "system.fuse",
                                .severity = "error",
                                .title = "FUSE Filesystem",
                                .message = "FUSE alertable error rate is above 10%.",
                                .href = "/health/filesystem#fuse",
                                .metricKey = "alertable_error_rate"};
    const health::Finding active{.raised = raised};
    const health::Finding marked{.raised = raised, .state = "acknowledged", .mark = acknowledged};
    health::Active unknown = raised;
    unknown.code = "system.not_in_the_catalog";
    unknown.href = std::nullopt;
    unknown.metricKey = std::nullopt;
    c.check(json(active), "HealthFinding", "an active finding");
    c.check(json(marked), "HealthFinding", "an acknowledged finding");
    c.check(json(health::Finding{.raised = unknown}), "HealthFinding", "a finding of a class the catalog lacks");

    for (const auto& cls : health::catalog()) c.check(json(cls), "HealthFindingClass", cls.code);

    health::Snapshot snapshot{.overallStatus = "error",
                              .errorCount = 1,
                              .warningCount = 0,
                              .unattendedErrorCount = 0,
                              .unattendedWarningCount = 0,
                              .checkedAt = 1795700000,
                              .findings = {marked},
                              .silences = {silenced}};
    json answer = snapshot;
    answer["can_manage"] = true;
    c.check(answer, "HealthFindings", "health.findings.list");
    answer["catalog"] = health::catalog();
    c.check(answer, "HealthFindings", "health.findings.list with the catalog");
    json empty = health::Snapshot{.overallStatus = "healthy"};
    empty["can_manage"] = false;
    c.check(empty, "HealthFindings", "nothing to report");
}

}
