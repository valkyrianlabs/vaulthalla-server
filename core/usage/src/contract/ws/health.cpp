// ws book: health.* (core/src/protocols/ws/handler/Health.cpp → ops::health; design/health/findings.md). Shapes:
// vh::health::to_json (core/src/health/Findings.cpp, Catalog.cpp) and ops::health::list.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField findingClass() {
    return str("class")
        .gen(gen::pattern("system.fuse.error_rate_high"))
        .desc("The finding's class: the code its dashboard card raises it under (\"system.fuse.error_rate_high\").");
}

WsField findingSubject() {
    return str("subject").opt().desc("What the finding is about when it is not the whole server. Every finding today "
                                     "is about the whole server: leave it out.");
}

WsField findingNote() { return str("note").opt().nullable().desc("Up to 500 characters, shown with the mark."); }

}

std::vector<WsCommandUsage> healthCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "health.findings.list",
        .description = "The health findings that are active now, each with what an operator said about it (active, "
                       "acknowledged, silenced), whether it is worth a notification, and its remedies; the silences "
                       "whose class is not active; and the counts with and without acknowledged and silenced "
                       "findings. Severity is never changed by a mark. Needs admin.stats.view.",
        .payload = {boolean("include_catalog").opt().desc("Also return every finding class (`catalog`).")},
        .response = {object("health", "HealthFindings")},
        .refusal_codes = {"denied", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "health.finding.acknowledge",
        .description = "\"I have seen this occurrence\": marks an active finding acknowledged. The mark ends when the "
                       "finding clears or its severity rises. Refused (conflict) when the class is not active or is "
                       "silenced. Needs admin.stats.manage; recorded in the audit trail. Never available to agents "
                       "or scoped devices.",
        .payload = {findingClass(), findingSubject(), findingNote()},
        .response = {object("health", "HealthFindings")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "health.finding.silence",
        .description = "\"Do not tell me about this class\": silences a finding class, active or not, for a time or "
                       "until it is turned back on. A silence does not cover a severity above the one it was set "
                       "for. Needs admin.stats.manage; recorded in the audit trail. Never available to agents or "
                       "scoped devices.",
        .payload = {findingClass(), findingSubject(),
                    uinteger("for_seconds").opt().nullable().min(60).max(31622400).desc(
                        "How long, from now (one minute to 366 days). Neither this nor until: until turned back on."),
                    uinteger("until").opt().nullable().desc("When it ends (epoch seconds), instead of for_seconds."),
                    str("severity").oneOf({"warning", "error"}).opt().nullable().desc(
                        "The highest severity it covers. Default: the class's severity now, or the worst it can "
                        "have when it is not active."),
                    findingNote()},
        .response = {object("health", "HealthFindings")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "health.finding.unsilence",
        .description = "Turns a finding class back on: removes its silence or acknowledgement. Refused (not_found) "
                       "when it has neither. Needs admin.stats.manage; recorded in the audit trail. Never available "
                       "to agents or scoped devices.",
        .payload = {findingClass(), findingSubject()},
        .response = {object("health", "HealthFindings")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
