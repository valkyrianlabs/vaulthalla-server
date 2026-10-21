// ws book: email.* — operator email administration (core/src/protocols/ws/handler/Email.cpp; settings writes go
// through ops::config). Every command is super-admin only (a handler gate that throws ops::Denied).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// Whether each provider secret is stored (never the values). available is false without a secrets manager.
WsField emailSecretStatus() {
    return object("secrets", "", {boolean("available"), boolean("resend_api_key"), boolean("ses_access_key_id"),
                                  boolean("ses_secret_access_key")})
        .desc("Which provider secrets are stored (presence only, never the values).");
}

std::vector<WsField> emailConfigResponse() {
    return {object("email", "EmailConfig"), object("operator_emails", "OperatorEmailsConfig"), emailSecretStatus()};
}

}

std::vector<WsCommandUsage> emailCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "email.config.get",
        .description = "The email provider settings, the operator email policy and which provider secrets are stored.",
        .input = "none",
        .response = emailConfigResponse(),
        .refusal_codes = {"denied", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "email.config.update",
        .description = "Merge-patch the email and operator_emails settings sections (RFC 7386; other sections are "
                       "ignored) and save them through the same validation as settings.update.",
        .payload = {object("email", "EmailConfig").opt().patch().desc("Partial email section."),
                    object("operator_emails", "OperatorEmailsConfig").opt().patch().desc(
                        "Partial operator_emails section.")},
        .response = emailConfigResponse(),
        .refusal_codes = {"denied", "invalid", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "email.provider.secret.set",
        .description = "Store provider credentials in the secrets manager: resend needs api_key; ses takes "
                       "access_key_id and/or secret_access_key (at least one). Values are write-only.",
        .payload = {str("provider").oneOf({"resend", "ses"}),
                    str("api_key").opt().desc("resend: required, non-empty."),
                    str("access_key_id").opt().desc("ses."),
                    str("secret_access_key").opt().desc("ses.")},
        .response = {emailSecretStatus()},
        .refusal_codes = {"denied", "invalid", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "email.test.send",
        .description = "Send (or, with dry_run, only render and record) a test email. Without to, a dry run goes to "
                       "the first alerts recipient. status says which happened. Email disabled or provider none is a "
                       "'conflict'; a failing provider answers without a code. Both are recorded in the history.",
        .payload = {str("to").opt().gen(gen::email()).desc("Recipient address; required unless dry_run has a "
                                                            "configured alerts recipient."),
                    boolean("dry_run").opt()},
        .response = {str("status").oneOf({"dry_run", "sent"}),
                     str("to"),
                     str("subject"),
                     uinteger("html_bytes").opt().desc("dry_run only."),
                     str("text").opt().desc("dry_run only: the rendered text body."),
                     str("provider").opt().desc("sent only."),
                     str("provider_message_id").opt().nullable().desc("sent only."),
                     str("history_warning").nullable().desc("Why the delivery history could not be recorded.")},
        .refusal_codes = {"denied", "invalid", "conflict", "unauthorized", "error"},
        .client_timeout = 60s,
    });

    out.push_back({
        .command = "email.history",
        .description = "Operator email delivery history, newest first.",
        .payload = {uinteger("limit").opt().desc("Clamped to 1..500 (default 100).")},
        .response = {objectArray("history", "EmailDeliveryRecord")},
        .refusal_codes = {"denied", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
