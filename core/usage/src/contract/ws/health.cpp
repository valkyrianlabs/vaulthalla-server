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

    out.push_back({
        .command = "health.subscribe",
        .description = "Follow the health findings by push (design/health/findings.md §6): whenever the findings or "
                       "their state change, the session gets an unsolicited frame {\"command\": \"health.changed\", "
                       "\"data\": {\"revision\", \"overall_status\", \"error_count\", \"warning_count\", "
                       "\"unattended_error_count\", \"unattended_warning_count\"}} (no requestId) and calls "
                       "health.findings.list; the event carries no findings. Findings are evaluated every 15 seconds "
                       "while anyone is subscribed; an acknowledge, silence or unsilence is pushed at once. Needs "
                       "admin.stats.view, re-checked every 30 seconds: a session that lost it gets one last event "
                       "{\"revision\", \"subscribed\": false}. One pending event per session, the newest wins, held "
                       "while the session is slow to read. Subscribing again is harmless; the subscription ends with "
                       "the session.",
        .input = "none",
        .response = {uinteger("revision").desc("The findings' revision now; each health.changed carries a higher one.")},
        .refusal_codes = {"unauthorized", "denied"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "health.unsubscribe",
        .description = "Stop following the health findings by push (health.subscribe). Harmless when not subscribed.",
        .input = "none",
        .response = {boolean("subscribed").desc("Always false.")},
        .refusal_codes = {"unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
