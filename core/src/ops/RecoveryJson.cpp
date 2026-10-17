#include "ops/RecoveryJson.hpp"

#include "db/encoding/timestamp.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <stdexcept>

namespace vh::recovery {

namespace {

nlohmann::json rjTime(const std::time_t t) {
    return t ? nlohmann::json(db::encoding::timestampToString(t)) : nlohmann::json(nullptr);
}

nlohmann::json rjTime(const std::optional<std::time_t>& t) { return t ? rjTime(*t) : nlohmann::json(nullptr); }

template <typename T>
nlohmann::json rjOpt(const std::optional<T>& v) {
    return v ? nlohmann::json(*v) : nlohmann::json(nullptr);
}

}

void to_json(nlohmann::json& j, const Mode v) { j = to_string(v); }
void to_json(nlohmann::json& j, const Backend v) { j = to_string(v); }
void to_json(nlohmann::json& j, const PointKind v) { j = to_string(v); }
void to_json(nlohmann::json& j, const ItemAction v) { j = to_string(v); }
void to_json(nlohmann::json& j, const RecoveryId& v) { j = v.str(); }

void to_json(nlohmann::json& j, const Money& v) { j = {{"amount", v.amount}, {"currency", v.currency}}; }

void to_json(nlohmann::json& j, const EncryptionContext& v) {
    j = {{"encrypted", v.encrypted}, {"key_version", v.key_version}, {"key_available", v.key_available},
         {"key_current", v.key_current}};
}

void to_json(nlohmann::json& j, const Retention& v) {
    j = {{"policy", v.policy}, {"expires_at", rjTime(v.expires_at)}, {"note", rjOpt(v.note)}};
}

void to_json(nlohmann::json& j, const RecoveryPoint& v) {
    j = {{"id", v.id},
         {"backend", v.backend},
         {"vault_id", v.vault_id},
         {"path", v.path},
         {"original_entry_id", rjOpt(v.original_entry_id)},
         {"kind", v.kind},
         {"name", rjOpt(v.name)},
         {"created_at", rjTime(v.created_at)},
         {"valid_from", rjTime(v.valid_from)},
         {"valid_until", rjTime(v.valid_until)},
         {"size_bytes", rjOpt(v.size_bytes)},
         {"content_hash", rjOpt(v.content_hash)},
         {"encryption", v.encryption},
         {"retention", v.retention},
         {"estimated_monthly_cost", rjOpt(v.estimated_monthly_cost)},
         {"is_current", v.is_current},
         {"is_delete_marker", v.is_delete_marker},
         {"origin", rjOpt(v.origin)},
         {"reason", rjOpt(v.reason)},
         {"upstream_state", rjOpt(v.upstream_state)},
         {"storage_class", rjOpt(v.storage_class)},
         {"file_count", rjOpt(v.file_count)},
         {"restorable", v.restorable},
         {"unavailable_reason", rjOpt(v.unavailable_reason)}};
}

void to_json(nlohmann::json& j, const PlanItem& v) {
    j = {{"source_id", v.source_id},
         {"source_path", v.source_path},
         {"destination_path", v.destination_path},
         {"action", v.action},
         {"size_bytes", rjOpt(v.size_bytes)},
         {"destination_source_id", rjOpt(v.destination_source_id)},
         {"method", v.method},
         {"notes", v.notes}};
}

void to_json(nlohmann::json& j, const RequestEstimate& v) {
    j = {{"get_requests", v.get_requests},
         {"head_requests", v.head_requests},
         {"put_requests", v.put_requests},
         {"copy_requests", v.copy_requests},
         {"list_requests", v.list_requests},
         {"download_bytes", v.download_bytes},
         {"upload_bytes", v.upload_bytes},
         {"cost", rjOpt(v.cost)},
         {"unpriced_reason", rjOpt(v.unpriced_reason)}};
}

void to_json(nlohmann::json& j, const Plan& v) {
    j = {{"id", v.id},
         {"vault_id", v.vault_id},
         {"token", v.token},
         {"source_label", v.source_label},
         {"point_in_time", v.point_in_time},
         {"at", rjTime(v.at)},
         {"atomic", v.atomic},
         {"consistency_note", v.consistency_note},
         {"destination", rjOpt(v.destination)},
         {"prune", v.prune},
         {"items", v.items},
         {"creates", v.creates},
         {"overwrites", v.overwrites},
         {"skips", v.skips},
         {"conflicts", v.conflicts},
         {"removals", v.removals},
         {"unavailable", v.unavailable},
         {"estimate", v.estimate},
         {"warnings", v.warnings},
         {"blockers", v.blockers},
         {"created_at", rjTime(v.created_at)},
         {"expires_at", rjTime(v.expires_at)},
         {"state", v.state}};
}

void to_json(nlohmann::json& j, const ItemOutcome& v) {
    j = {{"destination_path", v.destination_path}, {"outcome", v.outcome}, {"error", rjOpt(v.error)}};
}

void to_json(nlohmann::json& j, const RestoreResult& v) {
    j = {{"plan_id", v.plan_id}, {"state", v.state},       {"items", v.items},     {"restored", v.restored},
         {"skipped", v.skipped}, {"conflicts", v.conflicts}, {"failed", v.failed}, {"removed", v.removed},
         {"unavailable", v.unavailable}};
}

void to_json(nlohmann::json& j, const ProviderRetention& v) {
    j = {{"indefinite", v.indefinite},
         {"days", v.indefinite ? nlohmann::json(nullptr) : nlohmann::json(v.days)},
         {"value", v.str()}};
}

void to_json(nlohmann::json& j, const LocalVersioningPolicy& v) {
    j = {{"enabled", v.enabled},
         {"keep_last", rjOpt(v.keep_last)},
         {"max_age_days", rjOpt(v.max_age_days)},
         {"quota_bytes", rjOpt(v.quota_bytes)}};
}

void to_json(nlohmann::json& j, const ProviderVersioningState& v) {
    j = {{"supported", v.supported},
         {"unsupported_reason", v.unsupported_reason},
         {"provider", rjOpt(v.provider)},
         {"bucket", rjOpt(v.bucket)},
         {"region", rjOpt(v.region)},
         {"storage_class", rjOpt(v.storage_class)},
         {"bucket_state", v.bucket_state},
         {"status", v.status},
         {"enabled_by_vaulthalla", v.enabled_by_vaulthalla},
         {"enabled_at", rjTime(v.enabled_at)},
         {"settles_at", rjTime(v.settles_at)},
         {"checked_at", rjTime(v.checked_at)},
         {"settled", v.settled},
         {"object_lock", rjOpt(v.object_lock)},
         {"mfa_delete", rjOpt(v.mfa_delete)},
         {"retention_mode", v.retention_mode},
         {"retention_days", rjOpt(v.retention_days)},
         {"foreign_noncurrent_rules", v.foreign_noncurrent_rules},
         {"effective_noncurrent_days", rjOpt(v.effective_noncurrent_days)},
         {"warnings", v.warnings}};
}

void to_json(nlohmann::json& j, const Backlog& v) {
    j = {{"pending_versions", v.pending_versions},
         {"pending_bytes", v.pending_bytes},
         {"oldest_pending_at", rjTime(v.oldest_pending_at)},
         {"failing", v.failing},
         {"last_error", rjOpt(v.last_error)}};
}

void to_json(nlohmann::json& j, const StoreUsage& v) {
    j = {{"count", v.count}, {"stored_bytes", v.stored_bytes}, {"plaintext_bytes", v.plaintext_bytes}};
}

void to_json(nlohmann::json& j, const Status& v) {
    j = {{"vault_id", v.vault_id},
         {"mode", v.mode},
         {"snapshot_quota_bytes", rjOpt(v.snapshot_quota_bytes)},
         {"cost_alert_monthly", rjOpt(v.cost_alert_monthly)},
         {"local_versioning", v.local_versioning},
         {"provider", v.provider},
         {"snapshots", v.snapshots},
         {"versions", v.versions},
         {"backlog", v.backlog},
         {"retained_key_versions", v.retained_key_versions},
         {"warnings", v.warnings}};
}

void to_json(nlohmann::json& j, const CostFigure& v) {
    j = {{"expected", rjOpt(v.expected)},
         {"low", rjOpt(v.low)},
         {"high", rjOpt(v.high)},
         {"basis", v.basis},
         {"reason", rjOpt(v.reason)}};
}

void to_json(nlohmann::json& j, const AccumulationPoint& v) {
    j = {{"month", v.month}, {"noncurrent_bytes", v.noncurrent_bytes}, {"monthly_cost", v.monthly_cost}};
}

void to_json(nlohmann::json& j, const RetentionScenario& v) {
    j = {{"retention", v.retention},
         {"steady_noncurrent_bytes", v.steady_noncurrent_bytes},
         {"monthly_cost", v.monthly_cost},
         {"notes", v.notes}};
}

void to_json(nlohmann::json& j, const Assumption& v) { j = {{"kind", v.kind}, {"text", v.text}}; }

void to_json(nlohmann::json& j, const CostReport::Catalog& v) {
    j = {{"version", rjOpt(v.version)},
         {"source", rjOpt(v.source)},
         {"verified", v.verified},
         {"stale", v.stale},
         {"age_seconds", rjOpt(v.age_seconds)},
         {"note", rjOpt(v.note)}};
}

void to_json(nlohmann::json& j, const CostReport::Observation& v) {
    j = {{"window_days", v.window_days},
         {"first_day", rjOpt(v.first_day)},
         {"last_day", rjOpt(v.last_day)},
         {"sufficient", v.sufficient},
         {"put_requests", v.put_requests},
         {"copy_requests", v.copy_requests},
         {"delete_requests", v.delete_requests},
         {"get_requests", v.get_requests},
         {"list_requests", v.list_requests},
         {"first_put_objects", v.first_put_objects},
         {"overwrite_objects", v.overwrite_objects},
         {"deleted_objects", v.deleted_objects},
         {"overwritten_bytes", v.overwritten_bytes},
         {"deleted_bytes", v.deleted_bytes},
         {"uploaded_bytes", v.uploaded_bytes},
         {"overwritten_bytes_per_day", v.overwritten_bytes_per_day}};
}

void to_json(nlohmann::json& j, const CostReport::Current& v) {
    j = {{"objects", v.objects}, {"bytes", v.bytes}, {"monthly_storage", rjOpt(v.monthly_storage)}};
}

void to_json(nlohmann::json& j, const CostReport::History& v) {
    j = {{"known_noncurrent_versions", v.known_noncurrent_versions},
         {"known_noncurrent_bytes", v.known_noncurrent_bytes},
         {"delete_markers", v.delete_markers},
         {"unknown_size_versions", v.unknown_size_versions},
         {"unaccounted_history", v.unaccounted_history},
         {"inventoried_at", rjTime(v.inventoried_at)}};
}

void to_json(nlohmann::json& j, const CostReport::Alert& v) {
    j = {{"threshold", rjOpt(v.threshold)}, {"exceeded", v.exceeded}};
}

void to_json(nlohmann::json& j, const CostReport& v) {
    j = {{"vault_id", v.vault_id},
         {"phase", v.phase},
         {"priced", v.priced},
         {"unpriced_reason", rjOpt(v.unpriced_reason)},
         {"provider", rjOpt(v.provider)},
         {"bucket", rjOpt(v.bucket)},
         {"region", rjOpt(v.region)},
         {"storage_class", rjOpt(v.storage_class)},
         {"currency", rjOpt(v.currency)},
         {"catalog", v.catalog},
         {"confidence", v.confidence},
         {"confidence_reasons", v.confidence_reasons},
         {"observation", v.observation},
         {"current", v.current},
         {"history", v.history},
         {"pre_activation_monthly", v.pre_activation_monthly},
         {"current_month_to_date", v.current_month_to_date},
         {"current_month_projected", v.current_month_projected},
         {"projected_monthly", v.projected_monthly},
         {"accumulation", v.accumulation},
         {"scenarios", v.scenarios},
         {"recovery_per_gb", v.recovery_per_gb},
         {"recovery_per_object", v.recovery_per_object},
         {"unmodeled", v.unmodeled},
         {"assumptions", v.assumptions},
         {"retention", rjOpt(v.retention)},
         {"alert", v.alert},
         {"computed_at", rjTime(v.computed_at)}};
}

void to_json(nlohmann::json& j, const Disclosure& v) {
    j = {{"report", v.report},
         {"consequences", v.consequences},
         {"required_acknowledgements", v.required_acknowledgements},
         {"token", v.token},
         {"expires_at", rjTime(v.expires_at)}};
}

ItemAction itemActionFromString(const std::string& s) {
    if (s == "create") return ItemAction::Create;
    if (s == "overwrite") return ItemAction::Overwrite;
    if (s == "skip") return ItemAction::Skip;
    if (s == "conflict") return ItemAction::Conflict;
    if (s == "remove") return ItemAction::Remove;
    if (s == "unavailable") return ItemAction::Unavailable;
    throw std::invalid_argument("unknown plan item action '" + s + "'");
}

}

namespace vh::ops::recovery {

namespace {

const nlohmann::json* rjMember(const nlohmann::json& j, const char* name) {
    const auto it = j.find(name);
    if (it == j.end() || it->is_null()) return nullptr;
    return &*it;
}

void rjRequireObject(const nlohmann::json& j, const char* what) {
    if (!j.is_object()) throw Invalid(std::string(what) + " must be an object");
}

std::optional<std::string> rjString(const nlohmann::json& j, const char* name) {
    const auto* v = rjMember(j, name);
    if (!v) return std::nullopt;
    if (!v->is_string()) throw Invalid(std::string(name) + " must be a string");
    return v->get<std::string>();
}

std::optional<bool> rjBool(const nlohmann::json& j, const char* name) {
    const auto* v = rjMember(j, name);
    if (!v) return std::nullopt;
    if (!v->is_boolean()) throw Invalid(std::string(name) + " must be a boolean");
    return v->get<bool>();
}

std::optional<uint64_t> rjUint(const nlohmann::json& j, const char* name, const uint64_t min = 0,
                               const uint64_t max = static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    const auto* v = rjMember(j, name);
    if (!v) return std::nullopt;
    if (!v->is_number_integer()) throw Invalid(std::string(name) + " must be an integer");
    if (v->is_number_unsigned()) {
        const auto u = v->get<uint64_t>();
        if (u < min || u > max) throw Invalid(std::string(name) + " is out of range");
        return u;
    }
    const auto i = v->get<int64_t>();
    if (i < 0 || static_cast<uint64_t>(i) < min || static_cast<uint64_t>(i) > max)
        throw Invalid(std::string(name) + " is out of range");
    return static_cast<uint64_t>(i);
}

std::optional<unsigned int> rjUint32(const nlohmann::json& j, const char* name, const unsigned int min,
                                     const unsigned int max) {
    const auto v = rjUint(j, name, min, max);
    return v ? std::make_optional(static_cast<unsigned int>(*v)) : std::nullopt;
}

// 1..12 integer digits, optionally '.' and 1..8 fraction digits (NUMERIC(20, 8)).
bool rjDecimal(const std::string& s) {
    const auto dot = s.find('.');
    const auto intPart = s.substr(0, dot);
    if (intPart.empty() || intPart.size() > 12) return false;
    for (const char c : intPart)
        if (c < '0' || c > '9') return false;
    if (dot == std::string::npos) return true;
    const auto frac = s.substr(dot + 1);
    if (frac.empty() || frac.size() > 8) return false;
    for (const char c : frac)
        if (c < '0' || c > '9') return false;
    return true;
}

std::time_t rjAt(const nlohmann::json& v) {
    if (v.is_number_integer()) {
        const auto t = v.get<int64_t>();
        if (t < 0) throw Invalid("at must not be negative");
        return static_cast<std::time_t>(t);
    }
    if (!v.is_string()) throw Invalid("at must be an ISO-8601 time or epoch seconds");
    try {
        return db::encoding::parsePostgresTimestamp(v.get<std::string>());
    } catch (const std::exception&) {
        throw Invalid("at must be an ISO-8601 time (e.g. 2026-10-01T12:00:00Z) or epoch seconds");
    }
}

}

void to_json(nlohmann::json& j, const PointDetail& v) {
    j = {{"point", v.point},
         {"members", v.members},
         {"members_truncated", v.members_truncated},
         {"created_by", v.created_by ? nlohmann::json(*v.created_by) : nlohmann::json(nullptr)},
         {"skipped", v.skipped}};
}

ProviderRetention providerRetentionFromJson(const nlohmann::json& j) {
    try {
        if (j.is_string()) return ProviderRetention::parse(j.get<std::string>());
        if (j.is_number_integer()) {
            const auto days = j.get<int64_t>();
            if (days < 1 || days > 36500) throw Invalid("provider_retention must be 1..36500 days or indefinite");
            return {.indefinite = false, .days = static_cast<unsigned int>(days)};
        }
        if (j.is_object()) {
            if (rjBool(j, "indefinite").value_or(false)) return {.indefinite = true, .days = 0};
            const auto days = rjUint32(j, "days", 1, 36500);
            if (!days) throw Invalid("provider_retention needs days (1..36500) or indefinite");
            return {.indefinite = false, .days = *days};
        }
    } catch (const std::invalid_argument& e) {
        throw Invalid(e.what());
    }
    throw Invalid("provider_retention must be \"<days>d\", a number of days or \"indefinite\"");
}

LocalVersioningPolicy localVersioningPolicyFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "local_versioning");
    LocalVersioningPolicy p;
    p.enabled = rjBool(j, "enabled").value_or(false);
    p.keep_last = rjUint32(j, "keep_last", 1, 10000);
    p.max_age_days = rjUint32(j, "max_age_days", 1, 36500);
    p.quota_bytes = rjUint(j, "quota_bytes");
    return p;
}

vh::recovery::LocalVersioningPatch localVersioningPatchFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "local_versioning");
    vh::recovery::LocalVersioningPatch p;
    p.enabled = rjBool(j, "enabled");
    // Unlike the other readers, null is meaningful here: it clears a limit (absent leaves it unchanged).
    const auto present = [&](const char* name) -> const nlohmann::json* {
        const auto it = j.find(name);
        return it == j.end() ? nullptr : &*it;
    };
    const auto limit = [&](const char* name, const unsigned int max) -> std::optional<unsigned int> {
        const auto* m = present(name);
        if (!m) return std::nullopt;
        if (m->is_null()) return 0u;
        if (!m->is_number_integer() || m->get<int64_t>() < 0 || m->get<int64_t>() > static_cast<int64_t>(max))
            throw Invalid(std::string(name) + " must be a whole number from 0 (no limit) to " + std::to_string(max));
        return static_cast<unsigned int>(m->get<int64_t>());
    };
    p.keep_last = limit("keep_last", 10000);
    p.max_age_days = limit("max_age_days", 36500);
    if (const auto* q = present("quota_bytes")) {
        if (q->is_null()) p.quota_bytes = 0;
        else if (!q->is_number_integer() || q->get<int64_t>() < 0)
            throw Invalid("quota_bytes must be a whole number of bytes (0 = no limit)");
        else p.quota_bytes = static_cast<uint64_t>(q->get<int64_t>());
    }
    return p;
}

Update updateFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "recovery update");
    Update u;
    if (const auto mode = rjString(j, "mode")) {
        try {
            u.mode = vh::recovery::modeFromString(*mode);
        } catch (const std::invalid_argument& e) {
            throw Invalid(e.what());
        }
    }
    if (const auto* r = rjMember(j, "provider_retention")) u.provider_retention = providerRetentionFromJson(*r);
    u.snapshot_quota_bytes = rjUint(j, "snapshot_quota_bytes");
    if (const auto* alert = rjMember(j, "cost_alert_monthly")) {
        if (!alert->is_string()) throw Invalid("cost_alert_monthly must be a decimal string (e.g. \"25.00\"), not a number");
        const auto value = alert->get<std::string>();
        if (!value.empty() && !rjDecimal(value))
            throw Invalid("cost_alert_monthly must be a non-negative decimal (up to 12 digits and 8 decimals)");
        u.cost_alert_monthly = value;
    }
    if (const auto* lv = rjMember(j, "local_versioning")) u.local_versioning = localVersioningPatchFromJson(*lv);
    u.disclosure_token = rjString(j, "disclosure_token");
    u.accept_unpriced = rjBool(j, "accept_unpriced").value_or(false);
    u.accept_retention_shortening = rjBool(j, "accept_retention_shortening").value_or(false);
    u.accept_adoption = rjBool(j, "accept_adoption").value_or(false);
    return u;
}

ListQuery listQueryFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "recovery list query");
    ListQuery q;
    q.path = rjString(j, "path");
    q.refresh_provider = rjBool(j, "refresh_provider").value_or(q.refresh_provider);
    q.include_snapshots = rjBool(j, "include_snapshots").value_or(q.include_snapshots);
    q.include_versions = rjBool(j, "include_versions").value_or(q.include_versions);
    q.include_provider = rjBool(j, "include_provider").value_or(q.include_provider);
    q.limit = rjUint32(j, "limit", 1, 10000).value_or(q.limit);
    return q;
}

SnapshotRequest snapshotRequestFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "snapshot request");
    SnapshotRequest r;
    const auto path = rjString(j, "path");
    if (!path || path->empty()) throw Invalid("path is required");
    r.path = *path;
    r.name = rjString(j, "name");
    if (r.name && (r.name->empty() || r.name->size() > 200)) throw Invalid("name must be 1..200 characters");
    return r;
}

PlanRequest planRequestFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "restore plan request");
    PlanRequest r;
    r.recovery_id = rjString(j, "recovery_id");
    if (const auto vault = rjUint(j, "vault_id", 1, std::numeric_limits<uint32_t>::max()))
        r.vault_id = static_cast<uint32_t>(*vault);
    r.path = rjString(j, "path");
    if (const auto* at = rjMember(j, "at")) r.at = rjAt(*at);
    r.destination = rjString(j, "destination");
    r.prune = rjBool(j, "prune").value_or(r.prune);
    r.refresh_provider = rjBool(j, "refresh_provider").value_or(r.refresh_provider);
    return r;
}

RestoreRequest restoreRequestFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "restore request");
    RestoreRequest r;
    const auto plan = rjUint(j, "plan_id", 1);
    if (!plan) throw Invalid("plan_id is required");
    r.plan_id = *plan;
    r.token = rjString(j, "token");
    r.accept_unverified = rjBool(j, "accept_unverified").value_or(false);
    return r;
}

std::vector<vh::recovery::PlanItem> planItemsFromJson(const nlohmann::json& j) {
    if (!j.is_array()) throw Invalid("plan items must be an array");
    std::vector<vh::recovery::PlanItem> items;
    items.reserve(j.size());
    for (const auto& e : j) {
        rjRequireObject(e, "plan item");
        vh::recovery::PlanItem item;
        item.source_id = rjString(e, "source_id").value_or("");
        item.source_path = rjString(e, "source_path").value_or("");
        item.destination_path = rjString(e, "destination_path").value_or("");
        try {
            item.action = vh::recovery::itemActionFromString(rjString(e, "action").value_or("unavailable"));
        } catch (const std::invalid_argument& ex) {
            throw Invalid(ex.what());
        }
        item.size_bytes = rjUint(e, "size_bytes");
        item.destination_source_id = rjString(e, "destination_source_id");
        item.method = rjString(e, "method").value_or("none");
        if (const auto* notes = rjMember(e, "notes")) {
            if (!notes->is_array()) throw Invalid("notes must be an array");
            for (const auto& n : *notes)
                if (n.is_string()) item.notes.push_back(n.get<std::string>());
        }
        items.push_back(std::move(item));
    }
    return items;
}

vh::recovery::RestoreResult restoreResultFromJson(const nlohmann::json& j) {
    rjRequireObject(j, "restore result");
    vh::recovery::RestoreResult r;
    r.plan_id = rjUint(j, "plan_id").value_or(0);
    r.state = rjString(j, "state").value_or("");
    if (const auto* items = rjMember(j, "items")) {
        if (!items->is_array()) throw Invalid("items must be an array");
        for (const auto& e : *items) {
            rjRequireObject(e, "restore outcome");
            r.items.push_back({.destination_path = rjString(e, "destination_path").value_or(""),
                               .outcome = rjString(e, "outcome").value_or(""),
                               .error = rjString(e, "error")});
        }
    }
    r.restored = rjUint(j, "restored").value_or(0);
    r.skipped = rjUint(j, "skipped").value_or(0);
    r.conflicts = rjUint(j, "conflicts").value_or(0);
    r.failed = rjUint(j, "failed").value_or(0);
    r.removed = rjUint(j, "removed").value_or(0);
    r.unavailable = rjUint(j, "unavailable").value_or(0);
    return r;
}

}
