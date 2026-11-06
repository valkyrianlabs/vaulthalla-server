#include "notifications/AccountSecurity.hpp"

#include "config/Registry.hpp"
#include "email/templates/OperatorTemplates.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "notifications/OperatorNotification.hpp"
#include "notifications/OperatorNotificationBus.hpp"

#include <chrono>
#include <exception>
#include <mutex>
#include <unistd.h>

namespace vh::notifications::account {

namespace {

std::mutex& accountNoticeSinkMutex() {
    static std::mutex m;
    return m;
}

Sink& accountNoticeSink() {
    static Sink sink;
    return sink;
}

std::string accountNoticeInstance() {
    char host[256]{};
    if (::gethostname(host, sizeof(host) - 1) == 0 && host[0] != '\0') return host;
    return "vaulthalla";
}

void accountNoticeEnqueue(const Notice& notice, const std::string& group, std::vector<std::string> recipients,
                          const email::templates::AccountSecurityEmailContext& ctx) {
    const auto minute = ctx.occurredAt / 60;
    OperatorNotification n{
        .eventKey = "security." + notice.event,
        .eventType = "security",
        .severity = notice.severity,
        .recipientGroup = group,
        .explicitRecipients = std::move(recipients),
        .fingerprint = notice.event + ":user:" + (notice.user_id ? std::to_string(*notice.user_id) : "none") + ":" +
                       group + ":minute:" + std::to_string(minute),
        .rendered = email::templates::renderAccountSecurityEmail(ctx),
        .tags = {{"event_type", "security"}, {"severity", notice.severity}, {"security_event", notice.event}}};
    if (!OperatorNotificationBus::instance().enqueue(std::move(n)))
        log::Registry::runtime()->warn("[notifications::account] dropped the {} notice: the queue is full", notice.event);
}

}

void send(const Notice& notice) noexcept {
    try {
        {
            std::lock_guard lock(accountNoticeSinkMutex());
            if (const auto& sink = accountNoticeSink()) {
                sink(notice);
                return;
            }
        }
        const auto& cfg = config::Registry::get();
        if (!cfg.operator_emails.enabled) return;

        email::templates::AccountSecurityEmailContext ctx{
            .instance = accountNoticeInstance(),
            .title = notice.title,
            .summary = notice.summary,
            .severity = notice.severity,
            .occurredAt = static_cast<std::uint64_t>(
                std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())),
            .facts = notice.facts,
            .advice = notice.advice,
            .baseUrl = cfg.email.base_url && !cfg.email.base_url->empty() ? cfg.email.base_url : std::nullopt};

        std::optional<std::string> account;
        if (notice.user_id)
            if (const auto user = vh::identities::manager().user(*notice.user_id)) {
                ctx.facts.insert(ctx.facts.begin(), {"Account", user->name()});
                account = user->email();
            }

        if (notice.to_security && cfg.operator_emails.security_alerts.enabled)
            accountNoticeEnqueue(notice, "security", {}, ctx);
        if (notice.to_user && account && !account->empty()) accountNoticeEnqueue(notice, "account", {*account}, ctx);
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[notifications::account] the {} notice failed: {}", notice.event, e.what());
    } catch (...) {
        log::Registry::runtime()->warn("[notifications::account] the {} notice failed", notice.event);
    }
}

void setSinkForTesting(Sink sink) {
    std::lock_guard lock(accountNoticeSinkMutex());
    accountNoticeSink() = std::move(sink);
}

}
