#include "sync/model/RemotePolicy.hpp"
#include "db/encoding/timestamp.hpp"

#include <pqxx/row>
#include "db/encoding/interval.hpp"
#include "sync/model/Conflict.hpp"
#include "fs/model/File.hpp"
#include "sync/Cloud.hpp"
#include "storage/Engine.hpp"
#include "storage/CloudEngine.hpp"
#include "sync/model/Event.hpp"
#include "storage/s3/Controller.hpp"

#include <sstream>
#include <stdexcept>
#include <cctype>
#include <nlohmann/json.hpp>

using namespace vh::sync::model;
using namespace vh::fs::model;
using namespace vh::concurrency;
using namespace vh::db::encoding;

namespace {
    std::optional<uint64_t> optional_uint64(pqxx::row_ref row, const char* name) {
        const auto field = row[name];
        if (field.is_null()) return std::nullopt;
        return field.as<uint64_t>();
    }

    std::optional<std::chrono::seconds> optional_seconds(pqxx::row_ref row, const char* name) {
        const auto raw = optional_uint64(row, name);
        if (!raw) return std::nullopt;
        return std::chrono::seconds(*raw);
    }

    void add_budget_hash(std::string& hash, const char* name, const std::optional<uint64_t>& value) {
        hash += ";";
        hash += name;
        hash += "=";
        hash += value ? std::to_string(*value) : "null";
    }

    void add_duration_hash(std::string& hash, const char* name, const std::optional<std::chrono::seconds>& value) {
        hash += ";";
        hash += name;
        hash += "=";
        hash += value ? std::to_string(value->count()) : "null";
    }

    std::optional<uint64_t> json_budget_value(const nlohmann::json& j, const char* name) {
        if (!j.contains(name) || j.at(name).is_null()) return std::nullopt;
        return j.at(name).get<uint64_t>();
    }

    nlohmann::json json_budget_value(const std::optional<uint64_t>& value) {
        if (!value) return nullptr;
        return *value;
    }

    std::string budgetToString(const std::optional<uint64_t>& value) {
        return value ? std::to_string(*value) : "unlimited";
    }

    std::string durationToString(const std::optional<std::chrono::seconds>& value) {
        return value ? intervalToString(*value) : "unlimited";
    }

    bool sameBudgetValue(const std::optional<uint64_t>& a, const std::optional<uint64_t>& b) {
        return a == b;
    }

    bool sameBudget(
        const vh::storage::s3::S3RequestBudget& a,
        const vh::storage::s3::S3RequestBudget& b) {
        return sameBudgetValue(a.max_list_requests, b.max_list_requests) &&
               sameBudgetValue(a.max_head_requests, b.max_head_requests) &&
               sameBudgetValue(a.max_get_requests, b.max_get_requests) &&
               sameBudgetValue(a.max_put_requests, b.max_put_requests) &&
               sameBudgetValue(a.max_copy_requests, b.max_copy_requests) &&
               sameBudgetValue(a.max_delete_requests, b.max_delete_requests) &&
               sameBudgetValue(a.max_downloaded_bytes, b.max_downloaded_bytes);
    }
}

vh::storage::s3::S3RequestBudget vh::sync::model::s3RequestBudgetForPreset(const S3BudgetPreset preset) {
    using Budget = vh::storage::s3::S3RequestBudget;
    switch (preset) {
    case S3BudgetPreset::Conservative:
        return Budget{
            .max_list_requests = 10,
            .max_head_requests = 100,
            .max_get_requests = 100,
            .max_put_requests = 100,
            .max_copy_requests = 20,
            .max_delete_requests = 100,
            .max_downloaded_bytes = 1024ull * 1024ull * 1024ull
        };
    case S3BudgetPreset::Balanced:
        return Budget{
            .max_list_requests = 100,
            .max_head_requests = 1000,
            .max_get_requests = 1000,
            .max_put_requests = 1000,
            .max_copy_requests = 100,
            .max_delete_requests = 1000,
            .max_downloaded_bytes = 10ull * 1024ull * 1024ull * 1024ull
        };
    case S3BudgetPreset::Bulk:
        return Budget{
            .max_list_requests = 1000,
            .max_head_requests = 10000,
            .max_get_requests = 10000,
            .max_put_requests = 10000,
            .max_copy_requests = 1000,
            .max_delete_requests = 10000,
            .max_downloaded_bytes = 100ull * 1024ull * 1024ull * 1024ull
        };
    case S3BudgetPreset::Unlimited:
        return Budget{};
    }
    return Budget{};
}

S3BudgetPreset vh::sync::model::s3BudgetPresetFromString(const std::string& str) {
    if (str == "conservative") return S3BudgetPreset::Conservative;
    if (str == "balanced") return S3BudgetPreset::Balanced;
    if (str == "bulk") return S3BudgetPreset::Bulk;
    if (str == "unlimited") return S3BudgetPreset::Unlimited;
    throw std::invalid_argument("Unknown S3 budget preset: " + str);
}

std::string vh::sync::model::to_string(const S3BudgetPreset preset) {
    switch (preset) {
    case S3BudgetPreset::Conservative: return "conservative";
    case S3BudgetPreset::Balanced: return "balanced";
    case S3BudgetPreset::Bulk: return "bulk";
    case S3BudgetPreset::Unlimited: return "unlimited";
    }
    return "unknown";
}

bool vh::sync::model::s3BudgetIsUnlimited(const vh::storage::s3::S3RequestBudget& budget) {
    return sameBudget(budget, s3RequestBudgetForPreset(S3BudgetPreset::Unlimited));
}

std::string vh::sync::model::s3BudgetPresetName(const vh::storage::s3::S3RequestBudget& budget) {
    for (const auto preset : {
             S3BudgetPreset::Conservative,
             S3BudgetPreset::Balanced,
             S3BudgetPreset::Bulk,
             S3BudgetPreset::Unlimited
         }) {
        if (sameBudget(budget, s3RequestBudgetForPreset(preset))) return to_string(preset);
    }
    return "custom";
}

std::optional<std::chrono::seconds> vh::sync::model::remoteIndexAgeFromString(const std::string& str) {
    const auto normalized = [&] {
        std::string out;
        out.reserve(str.size());
        for (const auto c : str) {
            if (!std::isspace(static_cast<unsigned char>(c)))
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        return out;
    }();
    if (normalized.empty() || normalized == "none" || normalized == "null" || normalized == "unlimited")
        return std::nullopt;
    return parseSyncInterval(str);
}

RemotePolicy::RemotePolicy() {
    s3_request_budget = s3RequestBudgetForPreset(S3BudgetPreset::Balanced);
}

RemotePolicy::RemotePolicy(pqxx::row_ref row)
    : Policy(row),
      strategy(strategyFromString(row.at("strategy").as<std::string>())),
      conflict_policy(rsConflictPolicyFromString(row.at("conflict_policy").as<std::string>())) {
    s3_request_budget.max_list_requests = optional_uint64(row, "s3_budget_list_requests");
    s3_request_budget.max_head_requests = optional_uint64(row, "s3_budget_head_requests");
    s3_request_budget.max_get_requests = optional_uint64(row, "s3_budget_get_requests");
    s3_request_budget.max_put_requests = optional_uint64(row, "s3_budget_put_requests");
    s3_request_budget.max_copy_requests = optional_uint64(row, "s3_budget_copy_requests");
    s3_request_budget.max_delete_requests = optional_uint64(row, "s3_budget_delete_requests");
    s3_request_budget.max_downloaded_bytes = optional_uint64(row, "s3_budget_downloaded_bytes");
    max_remote_index_age = optional_seconds(row, "max_remote_index_age_seconds");
    rehash_config();
}

void RemotePolicy::rehash_config() {
    config_hash = "vault_id=" + std::to_string(vault_id) +
                  ";interval=" + std::to_string(interval.count()) +
                  ";enabled=" + (enabled ? "true" : "false") +
                  ";strategy=" + to_string(strategy) +
                  ";conflict_policy=" + to_string(conflict_policy);
    add_budget_hash(config_hash, "s3_budget_list_requests", s3_request_budget.max_list_requests);
    add_budget_hash(config_hash, "s3_budget_head_requests", s3_request_budget.max_head_requests);
    add_budget_hash(config_hash, "s3_budget_get_requests", s3_request_budget.max_get_requests);
    add_budget_hash(config_hash, "s3_budget_put_requests", s3_request_budget.max_put_requests);
    add_budget_hash(config_hash, "s3_budget_copy_requests", s3_request_budget.max_copy_requests);
    add_budget_hash(config_hash, "s3_budget_delete_requests", s3_request_budget.max_delete_requests);
    add_budget_hash(config_hash, "s3_budget_downloaded_bytes", s3_request_budget.max_downloaded_bytes);
    add_duration_hash(config_hash, "max_remote_index_age_seconds", max_remote_index_age);
}

bool RemotePolicy::resolve_conflict(const std::shared_ptr<Conflict>& conflict) const {
    if (conflict_policy == ConflictPolicy::Ask) return false;

    if (conflict_policy == ConflictPolicy::KeepLocal) conflict->resolution = Conflict::Resolution::KEPT_LOCAL;
    else if (conflict_policy == ConflictPolicy::KeepRemote) conflict->resolution = Conflict::Resolution::KEPT_REMOTE;
    else if (conflict_policy == ConflictPolicy::KeepNewest) {
        if (conflict->artifacts.local.file->updated_at == std::time_t{0} || conflict->artifacts.upstream.file->updated_at == std::time_t{0})
            return false; // If either timestamp is missing, we can't determine which is newer, so we ask the user.

        if (conflict->artifacts.local.file->updated_at > conflict->artifacts.upstream.file->updated_at) conflict->resolution = Conflict::Resolution::KEPT_LOCAL;
        else conflict->resolution = Conflict::Resolution::KEPT_REMOTE;
    }

    return true;
}

bool RemotePolicy::wantsEnsureDirectories() const {
    if (strategy == Strategy::Mirror) return false;
    return true;
}

bool RemotePolicy::downloadRemoteOnly() const {
    switch (strategy) {
    case Strategy::Cache:
        // Cache pulls remote content as-needed to satisfy cache state
        return true;
    case Strategy::Sync:
        // Sync pulls remote-only files to make local complete
        return true;
    case Strategy::Mirror:
        // Mirror depends on direction.
        // KeepRemote mirror should pull remote-only.
        // KeepLocal mirror does NOT pull remote-only in your old behavior (it deletes them remotely).
        // KeepNewest is ambiguous; safest is "pull remote-only" = true? but that can surprise.
        switch (conflict_policy) {
        case ConflictPolicy::KeepRemote: return true;
        case ConflictPolicy::KeepLocal:  return false;
        case ConflictPolicy::KeepNewest: return true; // reasonable default: preserve data by downloading
        case ConflictPolicy::Ask:        return true; // preserve, user can delete later
        }
    }
    return false;
}

bool RemotePolicy::uploadLocalOnly() const {
    switch (strategy) {
    case Strategy::Cache:
        // Cache treats local as authoritative for what's present locally
        // (your old CacheSyncTask uploads local-only)
        return true;
    case Strategy::Sync:
        // Sync uploads local-only to remote
        return true;
    case Strategy::Mirror:
        // Mirror depends on direction:
        // KeepLocal: push local-only to remote to match local image.
        // KeepRemote: do NOT upload local-only; it'll be deleted locally.
        // KeepNewest/Ask: safest is upload local-only? I'd say NO for KeepNewest (ambiguous),
        // YES for Ask? I'd avoid surprises: don't upload unless explicitly KeepLocal.
        switch (conflict_policy) {
        case ConflictPolicy::KeepLocal:  return true;
        case ConflictPolicy::KeepRemote: return false;
        case ConflictPolicy::KeepNewest: return false;
        case ConflictPolicy::Ask:        return false;
        }
    }
    return false;
}

bool RemotePolicy::deleteRemoteLeftovers() const {
    if (strategy != Strategy::Mirror) return false;

    // Old MirrorKeepLocal deleted remote leftovers (remote files not present locally)
    // MirrorKeepRemote did not delete remote leftovers.
    switch (conflict_policy) {
    case ConflictPolicy::KeepLocal:  return true;
    case ConflictPolicy::KeepRemote: return false;
    case ConflictPolicy::KeepNewest: return false; // safest default
    case ConflictPolicy::Ask:        return false;
    }
    return false;
}

bool RemotePolicy::deleteLocalLeftovers() const {
    if (strategy != Strategy::Mirror) return false;

    // Old MirrorKeepRemote deleted local leftovers
    switch (conflict_policy) {
    case ConflictPolicy::KeepRemote: return true;
    case ConflictPolicy::KeepLocal:  return false;
    case ConflictPolicy::KeepNewest: return false; // safest default
    case ConflictPolicy::Ask:        return false;
    }
    return false;
}

// NOTE: This method should ONLY decide action type for entries where BOTH local and remote exist.
// It should NOT do hashing or conflict construction; keep it pure.
// It assumes the planner already knows:
// - whether content is equal (fast-path) OR
// - whether localNewer/remoteNewer (mtime compare)
//
// If you want this function to incorporate mtime compare, LocalInfo/RemoteInfo need those fields accessible.
// I’m assuming LocalInfo/RemoteInfo expose file->updated_at etc.
std::optional<ActionType> RemotePolicy::decideForBoth(const std::shared_ptr<File>& L, const std::shared_ptr<File>& R) const {
    // If content is equal, planner should skip before calling this.
    // We'll still be defensive if you pipe equality info in later.
    const auto lts = L->updated_at;
    const auto rts = R->updated_at;

    switch (strategy) {
    case Strategy::Cache:
        // Cache downloads if remote is newer; never uploads local-newer
        if (lts == std::time_t{0} || rts == std::time_t{0}) {
            // Without timestamps, safest cache behavior is "do nothing" (avoid overwrite)
            return std::nullopt;
        }
        if (rts > lts) return ActionType::Download;
        return std::nullopt;

    case Strategy::Sync:
        // Two-way sync: newest wins by mtime unless conflict system intervenes elsewhere
        if (lts == std::time_t{0} || rts == std::time_t{0}) {
            // Without timestamps, avoid destructive overwrite; prefer download to preserve remote?
            // For "sync" I'd pick download (remote source of truth) to avoid pushing bad local.
            return ActionType::Download;
        }
        if (lts > rts) return ActionType::Upload;
        if (rts > lts) return ActionType::Download;
        return std::nullopt;

    case Strategy::Mirror:
        // Mirror is explicit direction unless KeepNewest
        switch (conflict_policy) {
        case ConflictPolicy::KeepLocal:
            return ActionType::Upload;
        case ConflictPolicy::KeepRemote:
            return ActionType::Download;
        case ConflictPolicy::KeepNewest:
            if (lts == std::time_t{0} || rts == std::time_t{0}) return std::nullopt;
            if (lts > rts) return ActionType::Upload;
            if (rts > lts) return ActionType::Download;
            return std::nullopt;
        case ConflictPolicy::Ask:
            // planner should create Conflict and bail earlier; but we’ll no-op here too
            return std::nullopt;
        }
    }
    return std::nullopt;
}

void RemotePolicy::preflightSpaceForPlan(const std::weak_ptr<Cloud>& ctx, const std::vector<Action>& plan) const {
    auto task = ctx.lock();
    if (!task) return; // nothing we can enforce

    // Gather planned downloads
    std::vector<std::shared_ptr<File>> downloads;
    downloads.reserve(plan.size());

    for (const auto& a : plan) {
        if (a.type != ActionType::Download) continue;
        if (a.freeAfterDownload) continue;

        // Prefer remote artifact when present; fall back to local if your planner uses that.
        if (a.remote) downloads.push_back(a.remote);
        else if (a.local) downloads.push_back(a.local);
    }

    if (downloads.empty()) return;

    uintmax_t requiredBodyDownloadBytes = 0;
    for (const auto& file : downloads) {
        if (!file) continue;
        requiredBodyDownloadBytes += file->size_bytes;
    }

    if (s3_request_budget.max_downloaded_bytes) {
        const auto metrics = task->cloudEngine()->s3RequestMetrics();
        const auto used = metrics.downloaded_bytes;
        const auto limit = *s3_request_budget.max_downloaded_bytes;
        const auto remaining = used >= limit ? uint64_t{0} : limit - used;
        if (requiredBodyDownloadBytes > remaining) {
            const auto reason =
                "S3 downloaded-byte budget would be exceeded by planned body downloads. Planned: " +
                std::to_string(requiredBodyDownloadBytes) + ", Remaining: " + std::to_string(remaining);
            if (task->event) {
                task->event->status = Event::Status::STALLED;
                task->event->stall_reason = reason;
            }
            throw vh::storage::s3::RequestBudgetExceeded(reason);
        }
    }

    // Decide enforcement strictness by strategy
    // - Sync: hard requirement (Safe behavior)
    // - Cache: you probably want eviction-based behavior; until that's centralized, you can choose:
    //          (a) hard gate (deterministic) OR
    //          (b) allow and let cache layer evict during execution
    // - Mirror: if downloads are planned (KeepRemote/KeepNewest), it should still gate.
    const bool hardGate =
        (strategy == Strategy::Sync) ||
        (strategy == Strategy::Mirror) ||
        (strategy == Strategy::Cache /* set false later if you centralize eviction */);

    if (!hardGate) return;

    // Compute required bytes. Prefer your existing helper if it exists.
    uintmax_t required = 0;

    // If SyncTask exposes computeReqFreeSpaceForDownload(downloads), use it.
    // (This was in your Safe/Cache tasks originally.)
    if constexpr (requires { Cloud::computeReqFreeSpaceForDownload(downloads); }) {
        required = Cloud::computeReqFreeSpaceForDownload(downloads);
    } else {
        // Fallback: sum sizes. Less accurate (doesn't include temp overhead),
        // but deterministic and safe enough as a baseline.
        required = requiredBodyDownloadBytes;
    }

    const auto available = task->engine->freeSpace();

    if (available >= required) return;

    // Decorate event for observability (if present)
    if (task->event) {
        task->event->error_code = "Insufficient Disk Space";
        std::ostringstream oss;
        oss << "Not enough free space for planned downloads. Required: "
            << required << ", Available: " << available;
        task->event->error_message = oss.str();
        task->event->stall_reason = task->event->error_code;
    }

    throw std::runtime_error(
        "[RemotePolicy::preflightSpaceForPlan] Not enough free space. Required: " +
        std::to_string(required) + ", Available: " + std::to_string(available));
}

void vh::sync::model::to_json(nlohmann::json& j, const RemotePolicy& s) {
    to_json(j, static_cast<const Policy&>(s));
    j["strategy"] = to_string(s.strategy);
    j["conflict_policy"] = to_string(s.conflict_policy);
    j["s3_request_budget"] = {
        {"list_requests", json_budget_value(s.s3_request_budget.max_list_requests)},
        {"head_requests", json_budget_value(s.s3_request_budget.max_head_requests)},
        {"get_requests", json_budget_value(s.s3_request_budget.max_get_requests)},
        {"put_requests", json_budget_value(s.s3_request_budget.max_put_requests)},
        {"copy_requests", json_budget_value(s.s3_request_budget.max_copy_requests)},
        {"delete_requests", json_budget_value(s.s3_request_budget.max_delete_requests)},
        {"downloaded_bytes", json_budget_value(s.s3_request_budget.max_downloaded_bytes)}
    };
    j["max_remote_index_age_seconds"] = s.max_remote_index_age ? nlohmann::json(s.max_remote_index_age->count()) : nlohmann::json(nullptr);
}

void vh::sync::model::from_json(const nlohmann::json& j, RemotePolicy& s) {
    from_json(j, static_cast<Policy&>(s));
    s.strategy = strategyFromString(j.at("strategy").get<std::string>());
    s.conflict_policy = rsConflictPolicyFromString(j.at("conflict_policy").get<std::string>());
    if (j.contains("s3_request_budget") && j.at("s3_request_budget").is_object()) {
        const auto& budget = j.at("s3_request_budget");
        s.s3_request_budget.max_list_requests = json_budget_value(budget, "list_requests");
        s.s3_request_budget.max_head_requests = json_budget_value(budget, "head_requests");
        s.s3_request_budget.max_get_requests = json_budget_value(budget, "get_requests");
        s.s3_request_budget.max_put_requests = json_budget_value(budget, "put_requests");
        s.s3_request_budget.max_copy_requests = json_budget_value(budget, "copy_requests");
        s.s3_request_budget.max_delete_requests = json_budget_value(budget, "delete_requests");
        s.s3_request_budget.max_downloaded_bytes = json_budget_value(budget, "downloaded_bytes");
    }
    if (j.contains("max_remote_index_age_seconds")) {
        if (j.at("max_remote_index_age_seconds").is_null()) s.max_remote_index_age = std::nullopt;
        else s.max_remote_index_age = std::chrono::seconds(j.at("max_remote_index_age_seconds").get<int64_t>());
    }
    s.rehash_config();
}

std::string vh::sync::model::to_string(const RemotePolicy::Strategy& s) {
    switch (s) {
    case RemotePolicy::Strategy::Cache: return "cache";
    case RemotePolicy::Strategy::Sync: return "sync";
    case RemotePolicy::Strategy::Mirror: return "mirror";
    default: throw std::invalid_argument("Unknown sync strategy");
    }
}

std::string vh::sync::model::to_string(const RemotePolicy::ConflictPolicy& cp) {
    switch (cp) {
    case RemotePolicy::ConflictPolicy::KeepLocal: return "keep_local";
    case RemotePolicy::ConflictPolicy::KeepRemote: return "keep_remote";
    case RemotePolicy::ConflictPolicy::KeepNewest: return "keep_newest";
    case RemotePolicy::ConflictPolicy::Ask: return "ask";
    default: throw std::invalid_argument("Unknown conflict policy");
    }
}

RemotePolicy::Strategy vh::sync::model::strategyFromString(const std::string& str) {
    if (str == "cache") return RemotePolicy::Strategy::Cache;
    if (str == "sync") return RemotePolicy::Strategy::Sync;
    if (str == "mirror") return RemotePolicy::Strategy::Mirror;
    throw std::invalid_argument("Unknown sync strategy: " + str);
}

RemotePolicy::ConflictPolicy vh::sync::model::rsConflictPolicyFromString(const std::string& str) {
    if (str == "keep_local") return RemotePolicy::ConflictPolicy::KeepLocal;
    if (str == "keep_remote") return RemotePolicy::ConflictPolicy::KeepRemote;
    if (str == "keep_newest") return RemotePolicy::ConflictPolicy::KeepNewest;
    if (str == "ask") return RemotePolicy::ConflictPolicy::Ask;
    throw std::invalid_argument("Unknown conflict policy: " + str);
}

std::string vh::sync::model::to_string(const std::shared_ptr<RemotePolicy>& sync) {
    if (!sync) return "null";
    const auto unlimitedBudgetWarning = s3BudgetIsUnlimited(sync->s3_request_budget)
        ? std::string(
              "    Warning: unlimited/legacy budget; no S3 request or downloaded-byte guardrails are enforced. "
              "Run 'vh vault sync set <vault> --s3-budget-preset balanced' to enable them.\n")
        : std::string{};

    return "Remote Vault Sync Configuration:\n"
           "  Vault ID: " + std::to_string(sync->vault_id) + "\n"
           "  Interval: " + intervalToString(sync->interval) + "\n"
           "  Enabled: " + (sync->enabled ? "true" : "false") + "\n"
           "  Strategy: " + to_string(sync->strategy) + "\n"
           "  Conflict Policy: " + to_string(sync->conflict_policy) + "\n"
           "  S3 Request Budget:\n"
           "    Preset: " + s3BudgetPresetName(sync->s3_request_budget) + "\n"
           + unlimitedBudgetWarning +
           "    LIST: " + budgetToString(sync->s3_request_budget.max_list_requests) + "\n"
           "    HEAD: " + budgetToString(sync->s3_request_budget.max_head_requests) + "\n"
           "    GET: " + budgetToString(sync->s3_request_budget.max_get_requests) + "\n"
           "    PUT: " + budgetToString(sync->s3_request_budget.max_put_requests) + "\n"
           "    COPY: " + budgetToString(sync->s3_request_budget.max_copy_requests) + "\n"
           "    DELETE: " + budgetToString(sync->s3_request_budget.max_delete_requests) + "\n"
           "    Downloaded Bytes: " + budgetToString(sync->s3_request_budget.max_downloaded_bytes) + "\n"
           "  Max Remote Index Age: " + durationToString(sync->max_remote_index_age) + "\n"
           "  Last Sync At: " + timestampToString(sync->last_sync_at) + "\n"
           "  Last Success At: " + timestampToString(sync->last_success_at) + "\n"
           "  Created At: " + timestampToString(sync->created_at) + "\n"
           "  Updated At: " + timestampToString(sync->updated_at);
}
