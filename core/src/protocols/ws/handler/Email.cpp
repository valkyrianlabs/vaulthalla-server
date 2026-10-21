#include "protocols/ws/handler/Email.hpp"
#include "ops/Error.hpp"

#include "config/Registry.hpp"
#include "crypto/secrets/Manager.hpp"
#include "db/encoding/timestamp.hpp"
#include "email/Message.hpp"
#include "email/ProviderFactory.hpp"
#include "email/providers/ResendProvider.hpp"
#include "email/providers/SesProvider.hpp"
#include "email/templates/OperatorTemplates.hpp"
#include "identities/User.hpp"
#include "notifications/OperatorNotification.hpp"
#include "notifications/OperatorNotificationState.hpp"
#include "ops/Config.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <exception>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <unistd.h>

namespace vh::protocols::ws::handler {

namespace {

void requireSuperAdmin(const std::shared_ptr<Session>& session) {
    if (!session || !session->user || !session->user->isSuperAdmin())
        throw vh::ops::Denied("Permission denied: operator email administration requires super-admin");
}

// A parser's std::invalid_argument on client input (an unknown provider, a malformed address) is a typed refusal.
template <class Fn>
auto invalidOnBadInput(Fn&& fn) {
    try {
        return fn();
    } catch (const std::invalid_argument& e) {
        throw vh::ops::Invalid(e.what());
    }
}

std::string instanceName() {
    char host[256]{};
    if (::gethostname(host, sizeof(host) - 1) == 0 && host[0] != '\0')
        return host;
    return "vaulthalla";
}

json secretStatus() {
    auto& deps = runtime::Deps::get();
    if (!deps.secretsManager) {
        return {
            {"available", false},
            {"resend_api_key", false},
            {"ses_access_key_id", false},
            {"ses_secret_access_key", false}
        };
    }

    return {
        {"available", true},
        {"resend_api_key", deps.secretsManager->hasSecret(::vh::email::providers::ResendProvider::kApiKeySecret)},
        {"ses_access_key_id", deps.secretsManager->hasSecret(::vh::email::providers::SesProvider::kAccessKeySecret)},
        {"ses_secret_access_key", deps.secretsManager->hasSecret(::vh::email::providers::SesProvider::kSecretKeySecret)}
    };
}

std::optional<std::string> recordDryRun(
    const ::vh::notifications::OperatorNotification& notification,
    const std::string& provider,
    const std::uint32_t recipientCount
) {
    try {
        ::vh::notifications::OperatorNotificationState::recordDryRun(notification, provider, recipientCount);
    } catch (const std::exception& e) {
        return e.what();
    }
    return std::nullopt;
}

std::optional<std::string> recordSent(
    const ::vh::notifications::OperatorNotification& notification,
    const std::string& provider,
    const std::uint32_t recipientCount,
    const ::vh::email::SendResult& result
) {
    try {
        ::vh::notifications::OperatorNotificationState::recordSent(notification, provider, recipientCount, result);
    } catch (const std::exception& e) {
        return e.what();
    }
    return std::nullopt;
}

std::optional<std::string> recordFailed(
    const ::vh::notifications::OperatorNotification& notification,
    const std::string& provider,
    const std::uint32_t recipientCount,
    const std::string& error
) {
    try {
        ::vh::notifications::OperatorNotificationState::recordFailed(notification, provider, recipientCount, error);
    } catch (const std::exception& e) {
        return e.what();
    }
    return std::nullopt;
}

std::optional<std::string> recordSuppressed(
    const ::vh::notifications::OperatorNotification& notification,
    const std::string& provider,
    const std::uint32_t recipientCount,
    const std::string& reason
) {
    try {
        ::vh::notifications::OperatorNotificationState::recordSuppressed(notification, provider, recipientCount, reason);
    } catch (const std::exception& e) {
        return e.what();
    }
    return std::nullopt;
}

}

json Email::deliveryRecordJson(const ::vh::email::DeliveryRecord& row) {
    return {
        {"id", row.id},
        {"event_key", row.eventKey},
        {"event_type", row.eventType},
        {"severity", row.severity},
        {"provider", row.provider},
        {"subject", row.subject},
        {"recipient_group", row.recipientGroup ? json(*row.recipientGroup) : json(nullptr)},
        {"recipient_count", row.recipientCount},
        {"provider_message_id", row.providerMessageId ? json(*row.providerMessageId) : json(nullptr)},
        {"status", row.status},
        {"error_summary", row.errorSummary ? json(*row.errorSummary) : json(nullptr)},
        {"fingerprint", row.fingerprint},
        {"first_seen_at", db::encoding::timestampToString(row.firstSeenAt)},
        {"last_seen_at", db::encoding::timestampToString(row.lastSeenAt)},
        {"sent_at", row.sentAt ? json(db::encoding::timestampToString(*row.sentAt)) : json(nullptr)},
        {"created_at", db::encoding::timestampToString(row.createdAt)}
    };
}

json Email::config(const std::shared_ptr<Session>& session) {
    requireSuperAdmin(session);
    const auto& cfg = ::vh::config::Registry::get();
    return {
        {"email", cfg.email},
        {"operator_emails", cfg.operator_emails},
        {"secrets", secretStatus()}
    };
}

json Email::updateConfig(const json& payload, const std::shared_ptr<Session>& session) {
    requireSuperAdmin(session);
    if (!payload.is_object()) throw vh::ops::Invalid("email.config.update payload must be an object");

    // Only the email sections, patched onto the current settings and saved through ops::config (the same
    // validation the CLI and settings.update get).
    nlohmann::json settings = ::vh::config::Registry::get();
    for (const auto* section : {"email", "operator_emails"})
        if (payload.contains(section)) settings[section].merge_patch(payload.at(section));
    const auto cfg = ops::config::saveSettings(session->user, settings);

    return {
        {"email", cfg.email},
        {"operator_emails", cfg.operator_emails},
        {"secrets", secretStatus()}
    };
}

json Email::setProviderSecret(const json& payload, const std::shared_ptr<Session>& session) {
    requireSuperAdmin(session);
    if (!payload.is_object()) throw vh::ops::Invalid("email.provider.secret.set payload must be an object");

    auto& deps = runtime::Deps::get();
    if (!deps.secretsManager) throw std::runtime_error("secrets manager is unavailable");

    const auto provider = invalidOnBadInput([&] {
        return ::vh::config::emailProviderKindFromString(payload.at("provider").get<std::string>());
    });
    if (provider == ::vh::config::EmailProviderKind::Resend) {
        const auto apiKey = payload.at("api_key").get<std::string>();
        if (apiKey.empty()) throw vh::ops::Invalid("Resend API key cannot be empty");
        deps.secretsManager->setSecret(::vh::email::providers::ResendProvider::kApiKeySecret, apiKey);
    } else if (provider == ::vh::config::EmailProviderKind::Ses) {
        bool wrote = false;
        if (payload.contains("access_key_id") && !payload.at("access_key_id").get<std::string>().empty()) {
            deps.secretsManager->setSecret(
                ::vh::email::providers::SesProvider::kAccessKeySecret,
                payload.at("access_key_id").get<std::string>()
            );
            wrote = true;
        }
        if (payload.contains("secret_access_key") && !payload.at("secret_access_key").get<std::string>().empty()) {
            deps.secretsManager->setSecret(
                ::vh::email::providers::SesProvider::kSecretKeySecret,
                payload.at("secret_access_key").get<std::string>()
            );
            wrote = true;
        }
        if (!wrote) throw vh::ops::Invalid("SES secret update requires access_key_id or secret_access_key");
    } else {
        throw vh::ops::Invalid("provider secrets are only supported for resend and ses");
    }

    return {{"secrets", secretStatus()}};
}

json Email::testSend(const json& payload, const std::shared_ptr<Session>& session) {
    requireSuperAdmin(session);
    if (!payload.is_object()) throw vh::ops::Invalid("email.test.send payload must be an object");

    const auto& cfg = ::vh::config::Registry::get();
    const auto dryRun = payload.value("dry_run", false);
    std::string recipient = payload.value("to", std::string{});
    if (dryRun && recipient.empty() && !cfg.operator_emails.recipients.alerts.empty())
        recipient = cfg.operator_emails.recipients.alerts.front();
    if (recipient.empty()) throw vh::ops::Invalid("email.test.send requires to");

    const auto from = ::vh::email::parseAddress(cfg.email.from);
    const auto to = invalidOnBadInput([&] { return ::vh::email::parseAddress(recipient); });
    const auto rendered = ::vh::email::templates::renderTestEmail({
        .provider = ::vh::config::emailProviderKindToString(cfg.email.provider),
        .instance = instanceName(),
        .from = ::vh::email::formatAddress(from),
        .recipient = ::vh::email::formatAddress(to),
        .dryRun = dryRun,
        .baseUrl = cfg.email.base_url
    });
    ::vh::notifications::OperatorNotification notification{
        .eventKey = "operator-test",
        .eventType = "test",
        .severity = "info",
        .recipientGroup = "test",
        .explicitRecipients = {recipient},
        .fingerprint = "manual:" + recipient,
        .rendered = rendered,
        .tags = {{"event_type", "test"}, {"severity", "info"}}
    };

    ::vh::email::Message message{
        .from = from,
        .to = {to},
        .replyTo = cfg.email.reply_to ? std::optional(::vh::email::parseAddress(*cfg.email.reply_to)) : std::nullopt,
        .subject = rendered.subject,
        .html = rendered.html,
        .text = rendered.text,
        .idempotencyKey = dryRun ? "operator-test:dry-run" : "operator-test:web",
        .tags = {}
    };
    ::vh::email::validateMessage(message);

    if (dryRun) {
        const auto historyWarning = recordDryRun(notification, ::vh::config::emailProviderKindToString(cfg.email.provider), 1);
        return {
            {"status", "dry_run"},
            {"subject", rendered.subject},
            {"to", ::vh::email::formatAddress(to)},
            {"html_bytes", rendered.html.size()},
            {"text", rendered.text},
            {"history_warning", historyWarning ? json(*historyWarning) : json(nullptr)}
        };
    }

    if (!cfg.email.enabled) {
        recordSuppressed(notification, ::vh::config::emailProviderKindToString(cfg.email.provider), 1, "email.enabled is false");
        throw vh::ops::Conflict("email.enabled is false");
    }
    if (cfg.email.provider == ::vh::config::EmailProviderKind::None) {
        recordSuppressed(notification, "none", 1, "email.provider is none");
        throw vh::ops::Conflict("email.provider is none");
    }
    if (!runtime::Deps::get().secretsManager) {
        recordFailed(notification, ::vh::config::emailProviderKindToString(cfg.email.provider), 1, "secrets manager is unavailable");
        throw std::runtime_error("secrets manager is unavailable");
    }

    auto provider = ::vh::email::makeProvider(cfg.email, runtime::Deps::get().secretsManager);
    if (!provider) {
        recordFailed(notification, ::vh::config::emailProviderKindToString(cfg.email.provider), 1, "no provider is configured");
        throw std::runtime_error("no provider is configured");
    }

    const auto result = provider->send(message);
    if (!result.ok) {
        std::ostringstream err;
        err << "provider " << provider->name() << " failed";
        if (result.httpStatus) err << " (HTTP " << result.httpStatus << ")";
        if (result.errorSummary) err << ": " << *result.errorSummary;
        recordFailed(notification, provider->name(), 1, err.str());
        throw std::runtime_error(err.str());
    }

    const auto historyWarning = recordSent(notification, provider->name(), 1, result);
    return {
        {"status", "sent"},
        {"provider", provider->name()},
        {"to", ::vh::email::formatAddress(to)},
        {"subject", rendered.subject},
        {"provider_message_id", result.providerMessageId ? json(*result.providerMessageId) : json(nullptr)},
        {"history_warning", historyWarning ? json(*historyWarning) : json(nullptr)}
    };
}

json Email::history(const json& payload, const std::shared_ptr<Session>& session) {
    requireSuperAdmin(session);
    std::uint32_t limit = 100;
    if (payload.is_object() && payload.contains("limit")) {
        const auto requested = payload.at("limit").get<std::uint32_t>();
        limit = std::clamp<std::uint32_t>(requested, 1, 500);
    }

    const auto rows = ::vh::notifications::OperatorNotificationState::history(limit);
    json records = json::array();
    for (const auto& row : rows) records.push_back(deliveryRecordJson(row));
    return {{"history", records}};
}

}
