#pragma once

#include "ops/Upstream.hpp"

#include <nlohmann/json_fwd.hpp>

// One JSON representation of the upstream control plane, shared by the ws handlers and `vh upstream … --json`.
// Field names are the struct member names; times are ISO-8601 UTC strings (db::encoding::timestampToString) or null;
// enums are lower-case strings (BucketState "managed|adopted|unmanaged|protected", Versioning
// "unversioned|enabled|suspended|unknown").
namespace vh::storage::s3::provider::admin {

[[nodiscard]] std::string to_string(Versioning v);
void to_json(nlohmann::json& j, const AccountIdentity& v);
void to_json(nlohmann::json& j, const Capability& v);
void to_json(nlohmann::json& j, const Capabilities& v);
void from_json(const nlohmann::json& j, Capabilities& v);
void to_json(nlohmann::json& j, const LifecycleRule& v);
void to_json(nlohmann::json& j, const NotificationRule& v);
void to_json(nlohmann::json& j, const BucketConfiguration& v);

}

namespace vh::ops::upstream {

void to_json(nlohmann::json& j, const AdminStatus& v);
void to_json(nlohmann::json& j, const BucketRow& v);
void to_json(nlohmann::json& j, const Inventory& v);
void to_json(nlohmann::json& j, const Inspection& v);
void to_json(nlohmann::json& j, const AdmissionReport& v);
void to_json(nlohmann::json& j, const ChannelStatus& v);
void to_json(nlohmann::json& j, const EventStatus& v);
void to_json(nlohmann::json& j, const CleanupPlan& v);
void to_json(nlohmann::json& j, const CleanupResult& v);
void to_json(nlohmann::json& j, const AuditEntry& v);

}
