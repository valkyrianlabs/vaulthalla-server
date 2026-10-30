// The ws envelope every command travels in (enforced by core/include/protocols/ws/Envelope.hpp and the handler
// templates): the request and answer frames and the frame that answers a message the daemon can't route.

#include "fields.hpp"

namespace vh::contract::ws {

WsEnvelope envelope() {
    using detail::boolean;
    using detail::object;
    using detail::str;
    const auto requestId = WsField{.name = "requestId", .types = {"string", "integer"}}
                               .alternatives({detail::alt({"string"}), detail::alt({"integer"})})
                               .opt();
    return {
        .request = {
            str("command").desc("The command name (\"fs.dir.list\")."),
            object("payload").opt().nullable().desc(
                "The command's payload (its `payload` fields). Commands whose input is \"payload\" read it; a "
                "missing payload reads as {} (daemons before 1.16 refused a frame without one). Commands whose input "
                "is \"none\" or \"token\" ignore it."),
            requestId.desc("Echoed in the answer so the client can match it; a string (a UUID) or an integer, "
                           "anything else is not echoed."),
            str("token").opt().nullable().desc(
                "The access token. Commands with auth \"human\" need a valid one (else the answer's status is "
                "UNAUTHORIZED); \"token\"-input commands read it."),
        },
        .response = {
            str("command").desc("\"<command>.response\"."),
            str("status").oneOf({"OK", "ERROR", "UNAUTHORIZED"}).desc(
                "OK: done, `data` holds the response. UNAUTHORIZED: the router refused before running it (no or "
                "expired token; refresh and retry once). ERROR: a refusal (data.code: one of `error_codes`, or a "
                "code from the command's `refusal_kinds` or `confirmations`) or a fault (no data.code; internal "
                "faults answer the request's own command too)."),
            requestId.desc("The request's requestId, when it had one."),
            object("data").opt().desc(
                "OK: the command's response members. Omitted when the result is empty ({}, [] or null): read a "
                "missing data as {}. ERROR: {code} for typed refusals."),
            str("error").opt().desc("ERROR / UNAUTHORIZED: a human-readable message."),
            str("token").opt().desc("auth.login / auth.refresh: the new access token."),
        },
        .error_frame = {
            str("command").oneOf({"error"}),
            str("status").oneOf({"parse_error", "internal_error"}).desc(
                "parse_error: the text was not JSON, not an object, had no non-empty string `command`, or a "
                "non-string `token`. internal_error: a binary (upload) frame failed."),
            str("error").desc("What was wrong."),
            str("message").desc("The same text, for clients written before error frames carried `error`."),
            requestId.desc("The frame's requestId when it had one (parse_error only)."),
        },
        .error_codes = {
            {.code = "conflict", .description = "The request collides with existing state."},
            {.code = "denied", .description = "RBAC or a business rule refused the actor."},
            {.code = "device_unknown",
             .description = "The device listener: this connection's key is not a paired device; it may only pair "
                            "(device.pair.*) and say hello (meta.hello, meta.contract.get)."},
            {.code = "invalid", .description = "The request itself is malformed (a bad name, an out-of-range value)."},
            {.code = "not_found", .description = "What the request names doesn't exist (or isn't visible to the actor)."},
            {.code = "unknown_command",
             .description = "No command by that name on this daemon (web and device sessions; the text stays "
                            "\"Unknown command\"). meta.hello's `commands` lists the ones it has."},
        },
    };
}

}
