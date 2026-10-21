#include "protocols/ws/handler/share/Links.hpp"
#include "protocols/ws/handler/RequestErrors.hpp"
#include "ops/Error.hpp"

#include "db/encoding/timestamp.hpp"
#include "db/model/ListQueryParams.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/Actor.hpp"
#include "rbac/fs/glob/model/Pattern.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/permission/Permission.hpp"
#include "share/Link.hpp"
#include "share/Manager.hpp"
#include "share/Types.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler::share {
namespace {
[[nodiscard]] std::shared_ptr<vh::share::Manager> defaultManager() {
    return std::make_shared<vh::share::Manager>();
}

[[nodiscard]] Links::ManagerFactory& managerFactory() {
    static Links::ManagerFactory factory = defaultManager;
    return factory;
}

[[nodiscard]] std::shared_ptr<vh::share::Manager> manager() {
    auto instance = managerFactory()();
    if (!instance) throw std::runtime_error("Share manager is unavailable");
    return instance;
}

[[nodiscard]] const json& objectPayload(const json& payload) {
    if (!payload.is_object()) throw std::invalid_argument("Share link payload must be an object");
    return payload;
}

[[nodiscard]] vh::rbac::Actor actorFromSession(const std::shared_ptr<Session>& session) {
    if (!session || !session->user)
        throw vh::ops::Denied("Share management requires an authenticated user");
    return vh::rbac::Actor::human(session->user);
}

[[nodiscard]] std::string requiredString(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null())
        throw std::invalid_argument(std::string("Missing required share field: ") + field);
    return payload.at(field).get<std::string>();
}

[[nodiscard]] uint32_t requiredUint32(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null())
        throw std::invalid_argument(std::string("Missing required share field: ") + field);
    return payload.at(field).get<uint32_t>();
}

[[nodiscard]] std::string lowercase(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

[[nodiscard]] uint32_t parseAllowedOps(const json& value) {
    if (value.is_number_unsigned() || value.is_number_integer()) return value.get<uint32_t>();
    if (!value.is_array()) throw std::invalid_argument("allowed_ops must be a bitmask or array");

    uint32_t ops = 0;
    for (const auto& op : value) {
        if (!op.is_string()) throw std::invalid_argument("allowed_ops entries must be strings");
        ops |= vh::share::bit(vh::share::operation_from_string(op.get<std::string>()));
    }
    return ops;
}

[[nodiscard]] vh::rbac::permission::Override parsePermissionOverride(const json& value) {
    if (!value.is_object()) throw std::invalid_argument("permission override must be an object");

    vh::rbac::permission::Override override;
    if (value.contains("permission_id") && !value.at("permission_id").is_null())
        override.permission.id = value.at("permission_id").get<uint32_t>();
    if (value.contains("permission_qualified") && !value.at("permission_qualified").is_null())
        override.permission.qualified_name = value.at("permission_qualified").get<std::string>();
    else if (value.contains("qualified") && !value.at("qualified").is_null())
        override.permission.qualified_name = value.at("qualified").get<std::string>();
    if (override.permission.id == 0 && override.permission.qualified_name.empty())
        throw std::invalid_argument("permission override requires permission_id or permission_qualified");

    override.enabled = !value.contains("enabled") || value.at("enabled").is_null()
                           ? true
                           : value.at("enabled").get<bool>();
    override.effect = vh::rbac::permission::overrideOptFromString(
        value.value("effect", std::string{"allow"})
    );
    const auto pattern = value.value("glob_path", value.value("pattern", std::string{"/"}));
    override.pattern = vh::rbac::fs::glob::model::Pattern::make(pattern.empty() ? "/" : pattern);
    return override;
}

[[nodiscard]] std::vector<vh::rbac::permission::Override> parsePermissionOverrides(
    const json& payload,
    const char* field
) {
    if (!payload.contains(field) || payload.at(field).is_null()) return {};
    const auto& value = payload.at(field);
    if (!value.is_array()) throw std::invalid_argument(std::string(field) + " must be an array");

    std::vector<vh::rbac::permission::Override> overrides;
    overrides.reserve(value.size());
    for (const auto& item : value) overrides.push_back(parsePermissionOverride(item));
    return overrides;
}

[[nodiscard]] std::optional<vh::share::RoleAssignmentRequest> parseRoleAssignment(
    const json& payload,
    const char* field
) {
    if (!payload.contains(field) || payload.at(field).is_null()) return std::nullopt;
    const auto& value = payload.at(field);
    if (!value.is_object()) throw std::invalid_argument(std::string(field) + " must be an object");

    vh::share::RoleAssignmentRequest request;
    if (value.contains("vault_role_id") && !value.at("vault_role_id").is_null())
        request.vault_role_id = value.at("vault_role_id").get<uint32_t>();
    if (value.contains("vault_role_name") && !value.at("vault_role_name").is_null())
        request.vault_role_name = value.at("vault_role_name").get<std::string>();
    if (!request.vault_role_id && !request.vault_role_name)
        throw std::invalid_argument(std::string(field) + " requires vault_role_id or vault_role_name");
    request.overrides = parsePermissionOverrides(value, "permission_overrides");
    return request;
}

[[nodiscard]] std::vector<vh::share::RecipientRoleAssignmentRequest> parseRecipientAssignments(
    const json& payload,
    const char* field
) {
    if (!payload.contains(field) || payload.at(field).is_null()) return {};
    const auto& value = payload.at(field);
    if (!value.is_array()) throw std::invalid_argument(std::string(field) + " must be an array");

    std::vector<vh::share::RecipientRoleAssignmentRequest> recipients;
    recipients.reserve(value.size());
    for (const auto& item : value) {
        if (!item.is_object()) throw std::invalid_argument(std::string(field) + " entries must be objects");
        auto role = parseRoleAssignment(item, "role_assignment");
        if (!role) role = parseRoleAssignment(item, "role");
        if (!role) throw std::invalid_argument("recipient assignment requires role_assignment");
        recipients.push_back({
            .email = requiredString(item, "email"),
            .role = std::move(*role)
        });
    }
    return recipients;
}

[[nodiscard]] std::optional<std::time_t> parseOptionalTime(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null()) return std::nullopt;
    const auto& value = payload.at(field);
    if (value.is_number_integer()) return value.get<std::time_t>();
    if (value.is_string()) return db::encoding::parsePostgresTimestamp(value.get<std::string>());
    throw std::invalid_argument(std::string(field) + " must be a timestamp string or epoch seconds");
}

[[nodiscard]] std::optional<std::string> parseOptionalString(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null()) return std::nullopt;
    return payload.at(field).get<std::string>();
}

template<typename T>
[[nodiscard]] std::optional<T> parseOptionalNumber(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null()) return std::nullopt;
    return payload.at(field).get<T>();
}

[[nodiscard]] std::vector<std::string> parseStringArray(const json& payload, const char* field) {
    if (!payload.contains(field) || payload.at(field).is_null()) return {};
    const auto& value = payload.at(field);
    if (!value.is_array()) throw std::invalid_argument(std::string(field) + " must be an array");

    std::vector<std::string> out;
    out.reserve(value.size());
    for (const auto& item : value) {
        if (!item.is_string()) throw std::invalid_argument(std::string(field) + " entries must be strings");
        out.push_back(item.get<std::string>());
    }
    return out;
}

void applyStringArrayIfPresent(std::vector<std::string>& target, const json& payload, const char* field) {
    if (payload.contains(field)) target = parseStringArray(payload, field);
}

void applyOptionalStringIfPresent(std::optional<std::string>& target, const json& payload, const char* field) {
    if (payload.contains(field)) target = parseOptionalString(payload, field);
}

template<typename T>
void applyOptionalNumberIfPresent(std::optional<T>& target, const json& payload, const char* field) {
    if (payload.contains(field)) target = parseOptionalNumber<T>(payload, field);
}

void applyOptionalTimeIfPresent(std::optional<std::time_t>& target, const json& payload, const char* field) {
    if (payload.contains(field)) target = parseOptionalTime(payload, field);
}

void applyMetadataIfPresent(std::string& metadata, const json& payload) {
    if (!payload.contains("metadata")) return;
    const auto& value = payload.at("metadata");
    metadata = value.is_string() ? value.get<std::string>() : value.dump();
}

void applyMutableFields(vh::share::Link& link, const json& payload) {
    if (payload.contains("link_type") && !payload.at("link_type").is_null())
        link.link_type = vh::share::link_type_from_string(payload.at("link_type").get<std::string>());
    if (payload.contains("access_mode") && !payload.at("access_mode").is_null())
        link.access_mode = vh::share::access_mode_from_string(payload.at("access_mode").get<std::string>());
    if (payload.contains("allowed_ops") && !payload.at("allowed_ops").is_null())
        link.allowed_ops = parseAllowedOps(payload.at("allowed_ops"));

    applyOptionalStringIfPresent(link.name, payload, "name");
    applyOptionalStringIfPresent(link.public_label, payload, "public_label");
    applyOptionalStringIfPresent(link.description, payload, "description");
    applyOptionalTimeIfPresent(link.expires_at, payload, "expires_at");
    applyOptionalNumberIfPresent<uint32_t>(link.max_downloads, payload, "max_downloads");
    applyOptionalNumberIfPresent<uint32_t>(link.max_upload_files, payload, "max_upload_files");
    applyOptionalNumberIfPresent<uint64_t>(link.max_upload_size_bytes, payload, "max_upload_size_bytes");
    applyOptionalNumberIfPresent<uint64_t>(link.max_upload_total_bytes, payload, "max_upload_total_bytes");

    if (payload.contains("duplicate_policy") && !payload.at("duplicate_policy").is_null())
        link.duplicate_policy = vh::share::duplicate_policy_from_string(payload.at("duplicate_policy").get<std::string>());

    applyStringArrayIfPresent(link.allowed_mime_types, payload, "allowed_mime_types");
    applyStringArrayIfPresent(link.blocked_mime_types, payload, "blocked_mime_types");
    applyStringArrayIfPresent(link.allowed_extensions, payload, "allowed_extensions");
    applyStringArrayIfPresent(link.blocked_extensions, payload, "blocked_extensions");
    applyMetadataIfPresent(link.metadata, payload);
}

[[nodiscard]] vh::share::Link linkFromCreatePayload(const json& payload) {
    vh::share::Link link;
    link.vault_id = requiredUint32(payload, "vault_id");
    link.root_entry_id = requiredUint32(payload, "root_entry_id");
    link.root_path = requiredString(payload, "root_path");
    link.target_type = vh::share::target_type_from_string(requiredString(payload, "target_type"));
    link.link_type = vh::share::link_type_from_string(requiredString(payload, "link_type"));
    link.access_mode = vh::share::access_mode_from_string(requiredString(payload, "access_mode"));

    if (!payload.contains("allowed_ops") || payload.at("allowed_ops").is_null())
        throw std::invalid_argument("Missing required share field: allowed_ops");
    link.allowed_ops = parseAllowedOps(payload.at("allowed_ops"));

    applyMutableFields(link, payload);
    return link;
}

void rejectImmutableUpdateFields(const json& payload) {
    constexpr std::array immutableFields{
        "token_lookup_id",
        "token_hash",
        "created_by",
        "updated_by",
        "revoked_by",
        "vault_id",
        "root_entry_id",
        "root_path",
        "target_type",
        "created_at",
        "updated_at",
        "revoked_at",
        "disabled_at",
        "last_accessed_at",
        "access_count",
        "download_count",
        "upload_count"
    };

    for (const auto field : immutableFields)
        if (payload.contains(field)) throw std::invalid_argument(std::string("Immutable share field cannot be updated: ") + field);
}

[[nodiscard]] db::model::ListQueryParams listParamsFromPayload(const json& payload) {
    db::model::ListQueryParams params;
    if (payload.contains("sort") && !payload.at("sort").is_null()) params.sort = payload.at("sort").get<std::string>();
    if (payload.contains("filter") && !payload.at("filter").is_null()) params.filter = payload.at("filter").get<std::string>();
    if (payload.contains("limit") && !payload.at("limit").is_null()) params.limit = payload.at("limit").get<uint64_t>();
    if (payload.contains("page") && !payload.at("page").is_null()) params.page = payload.at("page").get<uint64_t>();
    if (payload.contains("offset") && !payload.at("offset").is_null() && params.limit) {
        const auto offset = payload.at("offset").get<uint64_t>();
        params.page = (offset / *params.limit) + 1;
    }
    if (payload.contains("direction") && !payload.at("direction").is_null()) {
        const auto direction = lowercase(payload.at("direction").get<std::string>());
        if (direction == "asc") params.direction = db::model::SortDirection::ASC;
        else if (direction == "desc") params.direction = db::model::SortDirection::DESC;
        else throw std::invalid_argument("Invalid list direction");
    }
    return params;
}

[[nodiscard]] json safeLinkJson(const vh::share::Link& link) { return Links::managementJson(link); }

[[nodiscard]] json safeLinksJson(const std::vector<std::shared_ptr<vh::share::Link>>& links) {
    auto out = json::array();
    for (const auto& link : links)
        if (link) out.push_back(safeLinkJson(*link));
    return out;
}
}

json Links::managementJson(const vh::share::Link& link) {
    auto out = link.toManagementJson();
    out.erase("token_lookup_id");
    out.erase("token_hash");
    return out;
}

json Links::create(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto& body = objectPayload(payload);
    const auto actor = actorFromSession(session);
    auto mgr = manager();
    auto result = mgr->createLink(actor, {
        .link = linkFromCreatePayload(body),
        .public_role = parseRoleAssignment(body, "public_role_assignment"),
        .recipients = parseRecipientAssignments(body, "recipient_role_assignments")
    });
    return {
        {"share", safeLinkJson(*result.link)},
        {"public_token", result.public_token},
        {"public_url_path", result.public_url_path}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Links::get(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto& body = objectPayload(payload);
    const auto actor = actorFromSession(session);
    auto mgr = manager();
    const auto link = mgr->getLinkForManagement(actor, requiredString(body, "id"));
    return {{"share", safeLinkJson(*link)}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Links::list(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto& body = objectPayload(payload);
    const auto actor = actorFromSession(session);
    auto mgr = manager();
    const auto params = listParamsFromPayload(body);
    if (body.contains("vault_id") && !body.at("vault_id").is_null()) {
        return {{"shares", safeLinksJson(mgr->listLinksForVault(actor, body.at("vault_id").get<uint32_t>(), params))}};
    }
    return {{"shares", safeLinksJson(mgr->listLinksForUser(actor, params))}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Links::update(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto& body = objectPayload(payload);
    rejectImmutableUpdateFields(body);
    const auto actor = actorFromSession(session);
    auto mgr = manager();

    auto link = mgr->getLinkForManagement(actor, requiredString(body, "id"));
    auto updated = std::make_shared<vh::share::Link>(*link);
    applyMutableFields(*updated, body);

    std::optional<std::vector<vh::share::RecipientRoleAssignmentRequest>> recipients;
    if (body.contains("recipient_role_assignments"))
        recipients = parseRecipientAssignments(body, "recipient_role_assignments");

    auto saved = mgr->updateLink(actor, {
        .link = std::move(updated),
        .public_role = parseRoleAssignment(body, "public_role_assignment"),
        .recipients = std::move(recipients)
    });
    return {{"share", safeLinkJson(*saved)}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Links::revoke(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto& body = objectPayload(payload);
    const auto actor = actorFromSession(session);
    auto mgr = manager();
    mgr->revokeLink(actor, requiredString(body, "id"));
    return {{"revoked", true}};
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

json Links::rotateToken(const json& payload, const std::shared_ptr<Session>& session) try {
    const auto& body = objectPayload(payload);
    const auto actor = actorFromSession(session);
    auto mgr = manager();
    auto result = mgr->rotateLinkToken(actor, requiredString(body, "id"));
    return {
        {"share", safeLinkJson(*result.link)},
        {"public_token", result.public_token},
        {"public_url_path", result.public_url_path}
    };
} catch (...) {
    rethrowRequestErrorsAsInvalid();
}

void Links::setManagerFactoryForTesting(ManagerFactory factory) {
    if (!factory) throw std::invalid_argument("Share manager factory is required");
    managerFactory() = std::move(factory);
}

void Links::resetManagerFactoryForTesting() {
    managerFactory() = defaultManager;
}

}
