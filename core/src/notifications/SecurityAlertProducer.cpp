#include "notifications/SecurityAlertProducer.hpp"

#include "config/Registry.hpp"
#include "email/templates/OperatorTemplates.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "notifications/OperatorNotification.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "rbac/role/Admin.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <exception>
#include <sstream>
#include <utility>
#include <unistd.h>

namespace vh::notifications {

namespace {

constexpr const char* kSecurityEventType = "security";
constexpr const char* kCreatedEventKey = "security.admin_role.created";
constexpr const char* kUpdatedEventKey = "security.admin_role.updated";
constexpr const char* kDeletedEventKey = "security.admin_role.deleted";

std::uint64_t securityAlertNowUnix() {
    return static_cast<std::uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
    );
}

std::string securityAlertInstanceName() {
    char host[256]{};
    if (::gethostname(host, sizeof(host) - 1) == 0 && host[0] != '\0')
        return host;
    return "vaulthalla";
}

bool securityAlertAdminRoleChangesEnabled() {
    const auto& cfg = config::Registry::get();
    return cfg.operator_emails.enabled
        && cfg.operator_emails.security_alerts.enabled
        && cfg.operator_emails.security_alerts.admin_role_changes;
}

std::string securityAlertActorSummary(const SecurityAlertActor& actor) {
    if (!actor.userName.empty() && actor.userId)
        return actor.userName + " (user id " + std::to_string(*actor.userId) + ")";
    if (!actor.userName.empty())
        return actor.userName;
    if (actor.userId)
        return "user id " + std::to_string(*actor.userId);
    return "unknown";
}

std::string securityAlertActorFingerprintKey(const SecurityAlertActor& actor) {
    if (actor.userId)
        return "user-" + std::to_string(*actor.userId);
    if (!actor.userName.empty())
        return actor.userName;
    return "unknown";
}

std::string securityAlertFingerprintComponent(std::string value) {
    for (auto& ch : value) {
        const auto c = static_cast<unsigned char>(ch);
        if (!std::isalnum(c) && ch != '.' && ch != '_' && ch != '-' && ch != ':')
            ch = '_';
    }
    if (value.size() > 80)
        value.resize(80);
    return value;
}

std::vector<std::string> securityAlertPermissionSummary(const rbac::role::Admin& role) {
    auto flags = role.getFlags();
    std::ranges::sort(flags);
    if (flags.empty())
        return {"none"};

    constexpr std::size_t kMaxFlags = 24;
    if (flags.size() > kMaxFlags) {
        const auto originalSize = flags.size();
        flags.resize(kMaxFlags);
        flags.push_back("... " + std::to_string(originalSize - kMaxFlags) + " more");
    }
    return flags;
}

std::string securityAlertFingerprintFor(
    const std::string& action,
    const rbac::role::Admin& role,
    const SecurityAlertActor& actor,
    const std::uint64_t occurredAt
) {
    std::ostringstream out;
    out << action
        << ":role:" << role.id
        << ":" << securityAlertFingerprintComponent(role.name)
        << ":source:" << securityAlertFingerprintComponent(actor.source.empty() ? "unknown" : actor.source)
        << ":actor:" << securityAlertFingerprintComponent(securityAlertActorFingerprintKey(actor))
        << ":minute:" << (occurredAt / 60);
    return out.str();
}

void enqueueAdminRoleAlert(
    const std::shared_ptr<rbac::role::Admin>& role,
    const SecurityAlertActor& actor,
    const std::string& action,
    const std::string& eventKey
) {
    if (!role) return;

    try {
        if (!securityAlertAdminRoleChangesEnabled()) return;

        const auto& cfg = config::Registry::get();
        const auto occurredAt = securityAlertNowUnix();
        email::templates::SecurityAlertEmailContext ctx{
            .instance = securityAlertInstanceName(),
            .action = action,
            .severity = "warning",
            .occurredAt = occurredAt,
            .roleId = role->id,
            .roleName = role->name,
            .roleDescription = role->description,
            .actor = securityAlertActorSummary(actor),
            .source = actor.source.empty() ? "unknown" : actor.source,
            .permissionFlags = securityAlertPermissionSummary(*role),
            .baseUrl = cfg.email.base_url && !cfg.email.base_url->empty()
                ? cfg.email.base_url
                : std::nullopt
        };

        auto notification = OperatorNotification{
            .eventKey = eventKey,
            .eventType = kSecurityEventType,
            .severity = "warning",
            .recipientGroup = "security",
            .explicitRecipients = {},
            .fingerprint = securityAlertFingerprintFor(action, *role, actor, occurredAt),
            .rendered = email::templates::renderSecurityAlertEmail(ctx),
            .tags = {
                {"event_type", kSecurityEventType},
                {"severity", "warning"},
                {"security_event", "admin_role"},
                {"role_action", action}
            }
        };

        if (!OperatorNotificationBus::instance().enqueue(std::move(notification)))
            log::Registry::runtime()->warn(
                "[SecurityAlertProducer] Dropped admin role {} alert because notification queue is full",
                action
            );
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn(
            "[SecurityAlertProducer] Failed to enqueue admin role {} alert: {}",
            action,
            e.what()
        );
    } catch (...) {
        log::Registry::runtime()->warn(
            "[SecurityAlertProducer] Failed to enqueue admin role {} alert",
            action
        );
    }
}

}

SecurityAlertActor actorFromUser(
    std::string source,
    const std::shared_ptr<identities::User>& user
) {
    SecurityAlertActor actor{
        .source = std::move(source),
        .userId = std::nullopt,
        .userName = {}
    };

    if (user) {
        actor.userId = user->id;
        actor.userName = user->name();
    }

    return actor;
}

void enqueueAdminRoleCreated(
    const std::shared_ptr<rbac::role::Admin>& role,
    const SecurityAlertActor& actor
) {
    enqueueAdminRoleAlert(role, actor, "created", kCreatedEventKey);
}

void enqueueAdminRoleUpdated(
    const std::shared_ptr<rbac::role::Admin>& role,
    const SecurityAlertActor& actor
) {
    enqueueAdminRoleAlert(role, actor, "updated", kUpdatedEventKey);
}

void enqueueAdminRoleDeleted(
    const std::shared_ptr<rbac::role::Admin>& role,
    const SecurityAlertActor& actor
) {
    enqueueAdminRoleAlert(role, actor, "deleted", kDeletedEventKey);
}

}
