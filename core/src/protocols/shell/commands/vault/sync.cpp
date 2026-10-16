#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "runtime/Deps.hpp"
#include "sync/Controller.hpp"
#include "sync/Cloud.hpp"
#include "sync/Planner.hpp"
#include "storage/Engine.hpp"
#include "identities/User.hpp"
#include "vault/model/Vault.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/Policy.hpp"
#include "db/encoding/interval.hpp"
#include "db/query/vault/Vault.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/encoding/timestamp.hpp"
#include "CommandUsage.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/ScopedS3RequestBudget.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "fs/model/File.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "ops/Upstream.hpp"
#include "sync/events/Applier.hpp"
#include "sync/events/Event.hpp"
#include "sync/events/Ingest.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

using namespace vh;
using namespace vh::protocols::shell;
using namespace vh::protocols::shell::commands::vault;
using namespace vh::vault::model;
using namespace vh::storage;
using namespace vh::sync::model;
using namespace vh::db::encoding;

namespace {
    constexpr std::array<std::string_view, 20> DEFAULT_S3_INVENTORY_SCHEMA = {
        "bucket",
        "key",
        "version_id",
        "is_latest",
        "is_delete_marker",
        "size",
        "last_modified_date",
        "etag",
        "storage_class",
        "is_multipart_uploaded",
        "replication_status",
        "encryption_status",
        "object_lock_retain_until_date",
        "object_lock_retention_mode",
        "object_lock_legal_hold_status",
        "intelligent_tiering_access_tier",
        "bucket_key_status",
        "checksum_algorithm",
        "object_access_control_list",
        "object_owner"
    };

    std::string trim(std::string value) {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
        return value;
    }

    std::string stripQuotes(std::string value) {
        value = trim(std::move(value));
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
            return value.substr(1, value.size() - 2);
        return value;
    }

    std::string canonicalColumn(std::string value) {
        value = trim(std::move(value));
        std::string out;
        out.reserve(value.size());
        for (const auto c : value) {
            if (std::isalnum(static_cast<unsigned char>(c)))
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        return out;
    }

    bool truthy(std::string value) {
        value = canonicalColumn(std::move(value));
        return value == "true" || value == "1" || value == "yes";
    }

    std::vector<std::string> parseCsvRow(const std::string& line) {
        std::vector<std::string> fields;
        std::string current;
        bool quoted = false;

        for (size_t i = 0; i < line.size(); ++i) {
            const char c = line[i];
            if (c == '"') {
                if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
                    current.push_back('"');
                    ++i;
                } else quoted = !quoted;
            } else if (c == ',' && !quoted) {
                fields.push_back(trim(std::move(current)));
                current.clear();
            } else current.push_back(c);
        }

        fields.push_back(trim(std::move(current)));
        return fields;
    }

    std::vector<std::string> parseSchema(const std::string& schema) {
        std::vector<std::string> columns;
        std::string token;
        std::istringstream input(schema);
        while (std::getline(input, token, ',')) columns.push_back(canonicalColumn(token));
        return columns;
    }

    std::vector<std::string> defaultInventorySchema() {
        std::vector<std::string> schema;
        schema.reserve(DEFAULT_S3_INVENTORY_SCHEMA.size());
        for (const auto column : DEFAULT_S3_INVENTORY_SCHEMA)
            schema.emplace_back(canonicalColumn(std::string(column)));
        return schema;
    }

    std::optional<size_t> findColumn(
        const std::vector<std::string>& columns,
        const std::initializer_list<std::string_view> aliases) {
        for (const auto alias : aliases) {
            const auto canonical = canonicalColumn(std::string(alias));
            const auto it = std::ranges::find(columns, canonical);
            if (it != columns.end()) return static_cast<size_t>(std::distance(columns.begin(), it));
        }
        return std::nullopt;
    }

    std::string fieldAt(const std::vector<std::string>& row, const std::optional<size_t> index) {
        if (!index || *index >= row.size()) return {};
        return stripQuotes(row[*index]);
    }

    std::optional<uint64_t> parseUint64(const std::string& value) {
        const auto trimmed = trim(value);
        if (trimmed.empty()) return std::nullopt;
        uint64_t parsed = 0;
        for (const auto c : trimmed) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
            parsed = (parsed * 10) + static_cast<uint64_t>(c - '0');
        }
        return parsed;
    }

    std::optional<std::time_t> parseObjectTime(const std::string& value) {
        if (trim(value).empty()) return std::nullopt;
        try {
            return parsePostgresTimestamp(value);
        } catch (...) {
            return std::nullopt;
        }
    }

    std::vector<std::shared_ptr<vh::fs::model::File>> parseInventoryCsv(
        const std::filesystem::path& filePath,
        const std::optional<std::string>& schemaOpt,
        const bool forceHeader,
        size_t& skippedRows) {
        std::ifstream input(filePath);
        if (!input) throw std::runtime_error("unable to open inventory CSV: " + filePath.string());

        std::vector<std::string> columns;
        std::vector<std::shared_ptr<vh::fs::model::File>> files;
        bool columnsReady = false;

        if (schemaOpt) {
            columns = parseSchema(*schemaOpt);
            columnsReady = true;
        }

        const auto keyIdxFor = [&]() { return findColumn(columns, {"key", "object_key", "objectkey"}); };
        const auto sizeIdxFor = [&]() { return findColumn(columns, {"size", "size_bytes", "sizebytes"}); };

        std::string line;
        while (std::getline(input, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (trim(line).empty()) continue;

            auto row = parseCsvRow(line);
            if (!columnsReady) {
                auto header = row;
                for (auto& column : header) column = canonicalColumn(column);
                const bool looksLikeHeader =
                    findColumn(header, {"key", "object_key", "objectkey"}) &&
                    findColumn(header, {"size", "size_bytes", "sizebytes"});

                if (forceHeader || looksLikeHeader) {
                    columns = std::move(header);
                    columnsReady = true;
                    continue;
                }

                columns = defaultInventorySchema();
                columnsReady = true;
            }

            const auto keyIdx = keyIdxFor();
            const auto sizeIdx = sizeIdxFor();
            if (!keyIdx || !sizeIdx) throw std::runtime_error("inventory schema must include key and size columns");

            const auto deleteMarker = fieldAt(row, findColumn(columns, {"is_delete_marker", "isdeletemarker"}));
            if (truthy(deleteMarker)) {
                ++skippedRows;
                continue;
            }

            const auto key = fieldAt(row, keyIdx);
            const auto size = parseUint64(fieldAt(row, sizeIdx));
            if (key.empty() || !size || remote_manifest::isVaulthallaManifestKey(key)) {
                ++skippedRows;
                continue;
            }

            auto file = std::make_shared<vh::fs::model::File>(
                key,
                *size,
                parseObjectTime(fieldAt(row, findColumn(columns, {
                    "last_modified_date",
                    "lastmodifieddate",
                    "last_modified",
                    "lastmodified"
                }))));

            if (auto etag = fieldAt(row, findColumn(columns, {"etag", "e_tag"})); !etag.empty())
                file->remote_etag = etag;
            if (auto version = fieldAt(row, findColumn(columns, {"version_id", "versionid"})); !version.empty())
                file->remote_version_id = version;

            if (auto storageClass = fieldAt(row, findColumn(columns, {"storage_class", "storageclass"}));
                !storageClass.empty())
                file->remote_storage_class = storageClass;

            if (auto tier = fieldAt(row, findColumn(columns, {
                    "intelligent_tiering_access_tier",
                    "intelligenttieringaccesstier"
                }));
                !tier.empty()) {
                if (!file->remote_storage_class) file->remote_storage_class = "INTELLIGENT_TIERING";
                const auto canonicalTier = canonicalColumn(tier);
                if (canonicalTier != "frequentaccess" && canonicalTier != "frequent")
                    file->remote_restore_status = "IntelligentTieringAccessTier=" + tier;
            }

            files.push_back(std::move(file));
        }

        return files;
    }

    void collectS3EventRecords(const nlohmann::json& payload, std::vector<nlohmann::json>& records) {
        if (!payload.is_object()) return;

        if (payload.contains("Records") && payload.at("Records").is_array()) {
            for (const auto& record : payload.at("Records")) {
                if (record.contains("s3")) records.push_back(record);
                else if (record.contains("body") && record.at("body").is_string()) {
                    try {
                        collectS3EventRecords(nlohmann::json::parse(record.at("body").get<std::string>()), records);
                    } catch (...) {}
                } else if (record.contains("Sns") && record.at("Sns").contains("Message") &&
                           record.at("Sns").at("Message").is_string()) {
                    try {
                        collectS3EventRecords(nlohmann::json::parse(record.at("Sns").at("Message").get<std::string>()), records);
                    } catch (...) {}
                }
            }
            return;
        }

        if (payload.contains("s3")) records.push_back(payload);
    }

    // S3 event notification records from a file (a notification, an SQS dump, an SNS envelope), one JSON text each,
    // for ops::upstream::ingestEventRecords (the same durable inbox and applier as queue deliveries, #96).
    std::vector<std::string> readS3EventRecords(const std::filesystem::path& filePath) {
        std::ifstream input(filePath);
        if (!input) throw std::runtime_error("unable to open S3 event JSON: " + filePath.string());
        const auto payload = nlohmann::json::parse(input);
        std::vector<nlohmann::json> records;
        collectS3EventRecords(payload, records);
        std::vector<std::string> out;
        out.reserve(records.size());
        for (const auto& r : records) out.push_back(r.dump());
        return out;
    }

    // The vault's pass lease for a command that rewrites the remote index (a reconcile LIST, an inventory import), so
    // it never interleaves with an event batch or a sync pass (#96).
    struct IndexLease {
        unsigned int vaultId;
        bool held = false;
        explicit IndexLease(const unsigned int id) : vaultId(id) {
            const auto& controller = runtime::Deps::get().syncController;
            held = !controller || controller->tryAcquirePass(vaultId);
        }
        ~IndexLease() {
            if (!held) return;
            if (const auto& controller = runtime::Deps::get().syncController) controller->releasePass(vaultId);
        }
        IndexLease(const IndexLease&) = delete;
        IndexLease& operator=(const IndexLease&) = delete;
    };

    std::string remoteIndexSummaryString(
        const db::query::sync::RemoteIndexSummary& summary,
        const std::optional<std::chrono::seconds>& maxAge) {
        const auto optionalTime = [](const std::optional<std::time_t>& value) {
            return value ? timestampToString(*value) : std::string("unknown");
        };

        std::ostringstream out;
        out << "\n  Remote Index:\n"
            << "    Source: " << summary.source.value_or(summary.object_count > 0 ? "mixed" : "none") << "\n"
            << "    Indexed At: " << optionalTime(summary.indexed_at) << "\n"
            << "    Object Count: " << summary.object_count << "\n"
            << "    Freshness: " << (summary.isStale(maxAge) ? "stale" : "fresh") << "\n"
            << "    Manifest ETag: " << summary.manifest_etag.value_or("unknown") << "\n"
            << "    Manifest Generated At: " << optionalTime(summary.manifest_generated_at) << "\n"
            << "    Manifest Object Count: "
            << (summary.manifest_object_count ? std::to_string(*summary.manifest_object_count) : std::string("unknown"));
        return out.str();
    }

    std::string s3CostEstimateString(const S3CostEstimate& estimate) {
        std::ostringstream out;
        out << "  Estimated S3 requests:\n"
            << "    LIST: " << estimate.list_requests << "\n"
            << "    HEAD: " << estimate.head_requests << "\n"
            << "    GET: " << estimate.get_requests << "\n"
            << "    PUT: " << estimate.put_requests << "\n"
            << "    COPY: " << estimate.copy_requests << "\n"
            << "    DELETE: " << estimate.delete_requests << "\n"
            << "  Estimated traffic:\n"
            << "    Body download bytes: " << estimate.planned_body_download_bytes << "\n"
            << "    Upload bytes: " << estimate.planned_upload_bytes << "\n"
            << "    Cache/index-only objects: " << estimate.remote_index_objects << "\n"
            << "    Archive-tier body downloads skipped: " << estimate.archive_tier_downloads_skipped;
        return out.str();
    }

    uint64_t countPlanActions(const std::vector<Action>& plan, const ActionType type) {
        return static_cast<uint64_t>(std::ranges::count_if(plan, [type](const auto& action) {
            return action.type == type;
        }));
    }

    bool hasUsableLocalRemoteIndex(const db::query::sync::RemoteIndexSummary& summary) {
        return summary.indexed_at.has_value() ||
               summary.manifest_updated_at.has_value() ||
               summary.manifest_object_count.has_value();
    }
}

static CommandResult handle_vault_sync(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "sync"});
    validatePositionals(call, usage);

    const auto vLkp = resolveVault(call, call.positionals[0], usage, "vault sync");
    if (!vLkp || !vLkp.ptr) return invalid(vLkp.error);
    const auto vault = vLkp.ptr;
    const auto label = "'" + vault->name + "' (ID: " + std::to_string(vault->id) + ")";

    return runOp("vault sync", [&] { return ops::vaults::triggerSync(call.user, vault->id); },
        [&](const auto started) {
            if (started == ops::vaults::SyncStart::Started) return "Vault sync initiated for " + label;
            return "Vault sync already running for " + label + "; queued an immediate rerun after it finishes";
        });
}

static CommandResult handle_vault_sync_update(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "sync", "update"});
    validatePositionals(call, usage);

    const auto vLkp = resolveVault(call, call.positionals[0], usage, "vault sync update");
    if (!vLkp || !vLkp.ptr) return invalid(vLkp.error);
    const auto vault = vLkp.ptr;

    return runOp("vault sync update", [&] { return ops::vaults::updateSync(call.user, vault->id, syncPatchFromOptions(call)); },
        [&](const auto& policy) -> std::string {
            if (const auto remote = std::dynamic_pointer_cast<RemotePolicy>(policy))
                return "Successfully updated S3 vault sync configuration!\n" + to_string(remote);
            return "Successfully updated local vault sync configuration!\n" +
                   to_string(std::static_pointer_cast<LocalPolicy>(policy));
        });
}

static CommandResult handle_vault_sync_reconcile(const CommandCall& call) {
    constexpr const auto* ERR = "vault sync reconcile";

    const auto usage = resolveUsage({"vault", "sync", "reconcile"});
    validatePositionals(call, usage);

    const auto eLkp = resolveEngine(call, call.positionals[0], usage, ERR);
    if (!eLkp || !eLkp.ptr) return invalid(eLkp.error);
    const auto engine = eLkp.ptr;

    using Perm = rbac::permission::vault::sync::SyncActionPermissions;
    if (!rbac::resolver::Vault::has<Perm>({
        .user = call.user,
        .permission = Perm::Trigger,
        .vault_id = engine->vault->id
    })) return invalid("vault sync reconcile: you do not have permission to reconcile this vault");

    if (engine->vault->type != VaultType::S3)
        return invalid("vault sync reconcile: remote reconciliation is only available for S3 vaults");

    const auto cloud = std::static_pointer_cast<CloudEngine>(engine);
    const auto policy = cloud->remote_policy();
    const auto priorIndexedObjects = db::query::sync::RemoteObjectIndex::countForVault(engine->vault->id);
    const auto estimatedListRequests = priorIndexedObjects > 0 ? ((priorIndexedObjects + 999) / 1000) : uint64_t{0};

    if (!policy->s3_request_budget.max_list_requests &&
        !hasFlag(call, std::vector<std::string>{"allow-list-scan"})) {
        return invalid(
            "vault sync reconcile: full bucket LIST scans require --allow-list-scan or a configured --s3-budget-list.\n"
            "  Pre-run LIST estimate: " + (
                priorIndexedObjects > 0
                    ? std::to_string(estimatedListRequests) + " based on " + std::to_string(priorIndexedObjects) + " indexed objects"
                    : std::string("unknown; no prior remote index was available")));
    }

    const IndexLease lease(engine->vault->id);
    if (!lease.held)
        return invalid("vault sync reconcile: a sync pass or event batch of this vault is running; try again shortly");

    try {
        const ScopedS3RequestBudget s3Budget(cloud, policy->s3_request_budget);

        const auto listStartedAt = std::time(nullptr);
        const auto remoteMap = cloud->getGroupedFilesFromS3();
        std::vector<std::shared_ptr<vh::fs::model::File>> files;
        files.reserve(remoteMap.size());
        for (const auto& [_, file] : remoteMap) files.push_back(file);
        db::query::sync::RemoteObjectIndex::replaceFromListObjects(engine->vault->id, files);
        cloud->publishRemoteIndexManifestWithRetry();
        // A full listing: the event subscription's new baseline (older events are superseded by it).
        try {
            vh::sync::events::Applier::onBaselineListed(engine->vault->id, listStartedAt);
        } catch (const std::exception&) {}

        const auto metrics = s3Budget.metrics();

        return ok(
            "Remote index reconciled for '" + engine->vault->name + "' (ID: " + std::to_string(engine->vault->id) + ")\n"
            "  Pre-run LIST estimate: " + (
                priorIndexedObjects > 0
                    ? std::to_string(estimatedListRequests) + " based on " + std::to_string(priorIndexedObjects) + " indexed objects"
                    : std::string("unknown; no prior remote index was available")) + "\n"
            "  Objects indexed: " + std::to_string(files.size()) + "\n"
            "  LIST requests: " + std::to_string(metrics.list_requests) + " (S3 returns up to 1,000 objects per request)\n"
            "  HEAD requests: " + std::to_string(metrics.head_requests) + "\n"
            "  GET requests: " + std::to_string(metrics.get_requests) + "\n"
            "  PUT requests: " + std::to_string(metrics.put_requests) + "\n"
            "  COPY requests: " + std::to_string(metrics.copy_requests) + "\n"
            "  DELETE requests: " + std::to_string(metrics.delete_requests) + "\n"
            "  Downloaded bytes: " + std::to_string(metrics.downloaded_bytes));
    } catch (const std::exception& e) {
        return invalid("vault sync reconcile: " + std::string(e.what()));
    }
}

static CommandResult handle_vault_sync_inventory(const CommandCall& call) {
    constexpr const auto* ERR = "vault sync inventory";

    const auto usage = resolveUsage({"vault", "sync", "inventory"});
    validatePositionals(call, usage);

    const auto eLkp = resolveEngine(call, call.positionals[0], usage, ERR);
    if (!eLkp || !eLkp.ptr) return invalid(eLkp.error);
    const auto engine = eLkp.ptr;

    using Perm = rbac::permission::vault::sync::SyncActionPermissions;
    if (!rbac::resolver::Vault::has<Perm>({
        .user = call.user,
        .permission = Perm::Trigger,
        .vault_id = engine->vault->id
    })) return invalid("vault sync inventory: you do not have permission to import inventory for this vault");

    if (engine->vault->type != VaultType::S3)
        return invalid("vault sync inventory: inventory import is only available for S3 vaults");

    const auto fileOpt = optVal(call, usage->resolveRequired("file")->option_tokens);
    if (!fileOpt || fileOpt->empty()) return invalid("vault sync inventory: --file is required");

    const auto inventoryPath = std::filesystem::path(*fileOpt);
    if (!std::filesystem::exists(inventoryPath))
        return invalid("vault sync inventory: file does not exist: " + inventoryPath.string());

    const auto cloud = std::static_pointer_cast<CloudEngine>(engine);
    const auto policy = cloud->remote_policy();

    const IndexLease lease(engine->vault->id);
    if (!lease.held)
        return invalid("vault sync inventory: a sync pass or event batch of this vault is running; try again shortly");

    try {
        size_t skippedRows = 0;
        const auto schemaOpt = optVal(call, usage->resolveOptional("schema")->option_tokens);
        const auto files = parseInventoryCsv(
            inventoryPath,
            schemaOpt,
            hasFlag(call, std::vector<std::string>{"has-header", "header"}),
            skippedRows);

        db::query::sync::RemoteObjectIndex::replace(engine->vault->id, files, "inventory");

        const ScopedS3RequestBudget s3Budget(cloud, policy->s3_request_budget);
        cloud->publishRemoteIndexManifestWithRetry();
        const auto metrics = s3Budget.metrics();

        return ok(
            "S3 inventory imported for '" + engine->vault->name + "' (ID: " + std::to_string(engine->vault->id) + ")\n"
            "  Objects indexed: " + std::to_string(files.size()) + "\n"
            "  Rows skipped: " + std::to_string(skippedRows) + "\n"
            "  Manifest PUT requests: " + std::to_string(metrics.put_requests) + "\n"
            "  Manifest HEAD requests: " + std::to_string(metrics.head_requests));
    } catch (const std::exception& e) {
        return invalid("vault sync inventory: " + std::string(e.what()));
    }
}

static CommandResult handle_vault_sync_events(const CommandCall& call) {
    constexpr const auto* ERR = "vault sync events";

    const auto usage = resolveUsage({"vault", "sync", "events"});
    validatePositionals(call, usage);

    const auto eLkp = resolveEngine(call, call.positionals[0], usage, ERR);
    if (!eLkp || !eLkp.ptr) return invalid(eLkp.error);
    const auto engine = eLkp.ptr;

    using Perm = rbac::permission::vault::sync::SyncActionPermissions;
    if (!rbac::resolver::Vault::has<Perm>({
        .user = call.user,
        .permission = Perm::Trigger,
        .vault_id = engine->vault->id
    })) return invalid("vault sync events: you do not have permission to ingest event notifications for this vault");

    if (engine->vault->type != VaultType::S3)
        return invalid("vault sync events: S3 event ingestion is only available for S3 vaults");

    const auto fileOpt = optVal(call, usage->resolveRequired("file")->option_tokens);
    if (!fileOpt || fileOpt->empty()) return invalid("vault sync events: --file is required");

    const auto eventPath = std::filesystem::path(*fileOpt);
    if (!std::filesystem::exists(eventPath))
        return invalid("vault sync events: file does not exist: " + eventPath.string());

    try {
        const auto records = readS3EventRecords(eventPath);
        if (records.empty()) return invalid("vault sync events: no S3 event records found");
        const auto r = ops::upstream::ingestEventRecords(call.user, engine->vault->id, records);

        std::string pass = r.pass_started ? "started" : r.busy ? "queued (another pass is running)" : r.held
            ? "held until the baseline listing completes" : "not needed";
        return ok(
            "S3 event notifications ingested for '" + engine->vault->name + "' (ID: " + std::to_string(engine->vault->id) + ")\n"
            "  Records read: " + std::to_string(r.records) + "\n"
            "  Events stored: " + std::to_string(r.inserted) + " new, " +
                std::to_string(r.events - r.inserted) + " already known\n"
            "  Records skipped: " + std::to_string(r.skipped) + "\n"
            "  Applied to the remote index: " + std::to_string(r.applied) + "\n"
            "  Vaulthalla's own writes: " + std::to_string(r.self) + "\n"
            "  Superseded or unchanged: " + std::to_string(r.superseded) + "\n"
            "  Scoped sync pass: " + pass);
    } catch (const ops::Error& e) {
        return invalid("vault sync events: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return invalid("vault sync events: " + std::string(e.what()));
    }
}

static CommandResult handle_vault_sync_info(const CommandCall& call) {
    constexpr const auto* ERR = "vault sync info";

    const auto usage = resolveUsage({"vault", "sync", "info"});
    validatePositionals(call, usage);

    const auto eLkp = resolveEngine(call, call.positionals[0], usage, ERR);
    if (!eLkp || !eLkp.ptr) return invalid(eLkp.error);
    const auto engine = eLkp.ptr;

    using Perm = rbac::permission::vault::sync::SyncConfigPermissions;
    if (!rbac::resolver::Vault::has<Perm>({
        .user = call.user,
        .permission = Perm::View,
        .vault_id = engine->vault->id
    })) return invalid("vault sync info: you do not have permission to view the sync configuration for this vault");

    if (!engine->sync) return invalid("vault sync info: vault does not have a sync configuration");

    if (engine->vault->type == VaultType::S3) {
        const auto rsync = std::static_pointer_cast<RemotePolicy>(engine->sync);
        const auto summary = db::query::sync::RemoteObjectIndex::summaryForVault(engine->vault->id);
        return ok(to_string(rsync) + remoteIndexSummaryString(summary, rsync->max_remote_index_age));
    }

    return ok(to_string(engine->sync));
}

static CommandResult handle_vault_sync_dry_run(const CommandCall& call) {
    constexpr const auto* ERR = "vault sync dry-run";

    const auto usage = resolveUsage({"vault", "sync", "dry-run"});
    validatePositionals(call, usage);

    const auto eLkp = resolveEngine(call, call.positionals[0], usage, ERR);
    if (!eLkp || !eLkp.ptr) return invalid(eLkp.error);
    const auto engine = eLkp.ptr;

    using Perm = rbac::permission::vault::sync::SyncConfigPermissions;
    if (!rbac::resolver::Vault::has<Perm>({
        .user = call.user,
        .permission = Perm::View,
        .vault_id = engine->vault->id
    })) return invalid("vault sync dry-run: you do not have permission to view this vault's sync plan");

    if (engine->vault->type != VaultType::S3)
        return invalid("vault sync dry-run: S3 cost dry-run is only available for S3 vaults");

    const auto cloud = std::static_pointer_cast<CloudEngine>(engine);
    const auto policy = cloud->remote_policy();
    const bool refreshIndex = hasFlag(call, std::vector<std::string>{"refresh-index", "refresh-remote-index"});
    const bool refreshPricing = hasFlag(call, "refresh-pricing");
    const bool noPricing = hasFlag(call, "no-pricing");

    if (refreshIndex) {
        using ActionPerm = rbac::permission::vault::sync::SyncActionPermissions;
        if (!rbac::resolver::Vault::has<ActionPerm>({
            .user = call.user,
            .permission = ActionPerm::Trigger,
            .vault_id = engine->vault->id
        })) return invalid("vault sync dry-run: you do not have permission to refresh this vault's remote index");
    }

    try {
        const ScopedS3RequestBudget s3Budget(cloud, policy->s3_request_budget);
        const bool manifestRefreshed = refreshIndex
            ? cloud->refreshRemoteIndexFromManifestIfChanged()
            : false;
        const auto summary = db::query::sync::RemoteObjectIndex::summaryForVault(engine->vault->id);

        if (!hasUsableLocalRemoteIndex(summary))
            return invalid("vault sync dry-run: no remote index is available; run reconcile, inventory import, event ingestion, or dry-run --refresh-index.");

        if (!manifestRefreshed && summary.isStale(policy->max_remote_index_age))
            return invalid("vault sync dry-run: remote index is stale; run dry-run --refresh-index, reconcile, inventory import, or event ingestion.");

        auto ctx = std::make_shared<sync::Cloud>(cloud);
        ctx->event = std::make_shared<Event>();
        ctx->event->vault_id = engine->vault->id;
        ctx->localFiles = db::query::fs::File::listFilesInDir(engine->vault->id);
        ctx->localMap = vh::fs::model::groupEntriesByPath(ctx->localFiles);
        ctx->s3Files = db::query::sync::RemoteObjectIndex::listFilesForVault(engine->vault->id);
        ctx->s3Map = vh::fs::model::groupEntriesByPath(ctx->s3Files);

        S3CostEstimate planningNotes;
        const auto plan = vh::sync::Planner::build(ctx, policy, &planningNotes);
        auto estimate = vh::sync::Planner::estimateS3Cost(plan);
        estimate.archive_tier_downloads_skipped = planningNotes.archive_tier_downloads_skipped;
        const auto priceEstimate = vh::storage::s3::pricing::estimatePlannedS3Sync(
            *cloud,
            estimate,
            {.force_refresh = refreshPricing, .disabled = noPricing});
        const auto budgetPriceEstimate = vh::storage::s3::pricing::estimatePlannedS3Sync(
            *cloud,
            estimate,
            {
                .force_refresh = refreshPricing,
                .disabled = noPricing,
                .mode = vh::storage::s3::pricing::PriceEstimateMode::BudgetConservative
            });
        const auto profile = cloud->s3ProviderProfile();
        const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
        const auto providerKey = costProfileId
            ? *costProfileId
            : (profile ? profile->id() : std::string{"unknown"});
        const bool providerSupported = costProfileId &&
            vh::storage::s3::pricing::isSupportedPriceBudgetProvider(*costProfileId);
        const vh::storage::s3::pricing::PriceBudgetService priceBudgetService;
        const auto priceBudgetDecision = priceBudgetService.preflight({
            .vault_id = engine->vault->id,
            .run_uuid = ctx->event->run_uuid,
            .provider_key = providerKey,
            .provider_supported = providerSupported,
            .estimate = budgetPriceEstimate,
            .dry_run = true,
            .override_policy_ids = {},
            .gateway_credential_id = {},
            .request_uuid = {},
            .operation = {},
            .object_key = {},
            .gateway_scopes_only = false,
            .synthetic = false,
            .usage_source = {}
        });

        const auto metrics = s3Budget.metrics();
        std::ostringstream out;
        out << "S3 sync dry-run for '" << engine->vault->name << "' (ID: " << engine->vault->id << ")\n";
        if (refreshIndex)
            out << "  Note: --refresh-index may refresh the remote index manifest before planning.\n";
        if (refreshPricing)
            out << "  Note: --refresh-pricing may refresh cached storage-rate profile data before estimating.\n";
        out << "  Plan actions:\n"
            << "    Upload: " << countPlanActions(plan, ActionType::Upload) << "\n"
            << "    Download: " << countPlanActions(plan, ActionType::Download) << "\n"
            << "    Index remote-only: " << countPlanActions(plan, ActionType::IndexRemoteOnly) << "\n"
            << "    Delete remote: " << countPlanActions(plan, ActionType::DeleteRemote) << "\n"
            << "    Delete local: " << countPlanActions(plan, ActionType::DeleteLocal) << "\n"
            << s3CostEstimateString(estimate) << "\n"
            << "  Planning S3 requests used:\n"
            << "    HEAD: " << metrics.head_requests << "\n"
            << "    GET: " << metrics.get_requests << "\n"
            << "    LIST: " << metrics.list_requests << "\n"
            << vh::storage::s3::pricing::formatPriceEstimateForDryRun(
                priceEstimate,
                "Reporting estimate") << "\n"
            << vh::storage::s3::pricing::formatPriceEstimateForDryRun(
                budgetPriceEstimate,
                "Budget-safe estimate") << "\n"
            << vh::storage::s3::pricing::formatPriceBudgetDecisionForDryRun(priceBudgetDecision) << "\n"
            << remoteIndexSummaryString(summary, policy->max_remote_index_age);

        return ok(out.str());
    } catch (const std::exception& e) {
        return invalid("vault sync dry-run: " + std::string(e.what()));
    }
}

static bool isVaultSyncMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"vault", "sync", cmd}, input);
}

CommandResult commands::vault::handle_sync(const CommandCall& call) {
    const auto [arg, subcall] = descend(call);
    if (call.positionals.size() == 1) return handle_vault_sync(call);
    if (isVaultSyncMatch("update", arg)) return handle_vault_sync_update(subcall);
    if (isVaultSyncMatch("reconcile", arg)) return handle_vault_sync_reconcile(subcall);
    if (isVaultSyncMatch("inventory", arg)) return handle_vault_sync_inventory(subcall);
    if (isVaultSyncMatch("events", arg)) return handle_vault_sync_events(subcall);
    if (isVaultSyncMatch("info", arg)) return handle_vault_sync_info(subcall);
    if (isVaultSyncMatch("dry-run", arg) || isVaultSyncMatch("dryrun", arg) || isVaultSyncMatch("plan", arg))
        return handle_vault_sync_dry_run(subcall);

    return invalid(call.constructFullArgs(), "vault sync: unknown subcommand: '" + std::string(arg) + "'");
}
