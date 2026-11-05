// ws book: audit.* (core/src/protocols/ws/handler/Audit.cpp → ops::audit, #323). Shapes: ops::audit::toJson.

#include "fields.hpp"

namespace vh::contract::ws::detail {

std::vector<WsCommandUsage> auditCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "audit.list",
        .description = "The tamper-evident audit trail, newest first, filtered. Needs admin.audits.view; the first "
                       "page is itself recorded (audit.view).",
        .payload = {uinteger("before_seq").opt().nullable().desc("Paging: events older than this seq (next_before)."),
                    uinteger("since_us").opt().nullable().desc("Events at or after this time (µs since the epoch)."),
                    uinteger("until_us").opt().nullable().desc("Events before this time (µs since the epoch)."),
                    str("action").opt().nullable().desc("Action prefix: \"auth.\" matches auth.login.success."),
                    uinteger("actor_id").opt().nullable(),
                    uinteger("vault_id").opt().nullable(),
                    str("outcome").oneOf({"success", "failure", "denied", "info"}).opt().nullable(),
                    uinteger("limit").opt().desc("1..1000 (default 100).")},
        .response = {objectArray("events", "AuditEvent"),
                     uinteger("next_before").nullable().desc("Pass as before_seq for older events; null at the end.")},
        .refusal_codes = {"unauthorized", "denied", "invalid"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "audit.verify",
        .description = "Recomputes the whole retained hash chain and checks every signed head (signature, and that "
                       "the chain still holds the hash it signed). Needs admin.audits.view; recorded as "
                       "audit.verify (or audit.verify.failed).",
        .input = "none",
        .response = {object("verification", "AuditVerification")},
        .refusal_codes = {"unauthorized", "denied"},
        .client_timeout = std::chrono::seconds(120),
    });

    out.push_back({
        .command = "audit.export",
        .description = "The events in [since_us, until_us) as NDJSON (vh-audit-export-v1: a header line, the events "
                       "with their hashes, then the signed heads that cover them), verifiable offline. Up to 32 MiB; "
                       "use `vh audit export` for more. Needs admin.audits.view; recorded as audit.export.",
        .payload = {uinteger("since_us").opt().nullable(), uinteger("until_us").opt().nullable()},
        .response = {str("ndjson"), uinteger("events")},
        .refusal_codes = {"unauthorized", "denied", "invalid"},
        .client_timeout = std::chrono::seconds(120),
    });

    return out;
}

}
