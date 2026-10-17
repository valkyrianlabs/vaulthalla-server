#include "sync/ConflictResolver.hpp"

#include "db/query/fs/File.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "recovery/local/Backlog.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/RemoteFetch.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "sync/Planner.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Baseline.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/Vault.hpp"

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fmt/format.h>

#include <mutex>
#include <set>

namespace vh::sync {

namespace {

namespace pricing = storage::s3::pricing;
using ConflictRecord = db::query::sync::ConflictRecord;
using FilePtr = std::shared_ptr<fs::model::File>;

constexpr uint64_t kGcmTagBytes = 16;

std::mutex& inFlightMutex() {
    static std::mutex m;
    return m;
}

std::set<uint32_t>& inFlight() {
    static std::set<uint32_t> ids;
    return ids;
}

// One decision per conflict at a time in this process; the conditional close in the DB settles the rest.
class Claim {
public:
    explicit Claim(const uint32_t id) : id_(id) {
        std::scoped_lock lock(inFlightMutex());
        if (!inFlight().insert(id).second) throw ConflictStale("this conflict is already being resolved");
    }
    ~Claim() {
        std::scoped_lock lock(inFlightMutex());
        inFlight().erase(id_);
    }
    Claim(const Claim&) = delete;
    Claim& operator=(const Claim&) = delete;

private:
    uint32_t id_;
};

std::string newRequestId() {
    thread_local boost::uuids::random_generator generator;
    return boost::uuids::to_string(generator());
}

// Price preflight for one resolution, the way a sync run does it (BudgetConservative estimate, PriceBudgetService
// over global/provider/vault scopes). Refusal -> ContentUnavailable before any request is sent.
class PriceGuard {
public:
    PriceGuard(const storage::CloudEngine& engine, const model::S3CostEstimate& planned, const std::string& operation,
               const std::string& objectKey)
        : estimate_(pricing::estimatePlannedS3Sync(engine, planned,
                                                   {.mode = pricing::PriceEstimateMode::BudgetConservative})) {
        const auto profile = engine.s3ProviderProfile();
        const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
        const auto providerKey = costProfileId ? *costProfileId : (profile ? profile->id() : std::string{"unknown"});
        const auto id = newRequestId();
        const pricing::PriceBudgetPreflightRequest request{
            .vault_id = engine.vault->id,
            .run_uuid = id,
            .provider_key = providerKey,
            .provider_supported = costProfileId && pricing::isSupportedPriceBudgetProvider(*costProfileId),
            .estimate = estimate_,
            .dry_run = false,
            .override_policy_ids = {},
            .gateway_credential_id = {},
            .request_uuid = id,
            .operation = operation,
            .object_key = objectKey,
            .gateway_scopes_only = false,
            .synthetic = false,
            .usage_source = operation
        };
        const auto decision = service_.preflight(request);
        service_.recordPreflightNotifications(request, decision);
        for (const auto& warning : decision.warnings)
            log::Registry::sync()->warn("[ConflictResolver] S3 price budget warning for vault {} ({} {}): {}",
                                        engine.vault->id, operation, objectKey, warning);
        if (!decision.allowed)
            throw storage::ContentUnavailable(fmt::format(
                "S3 price budget refused {} of {}: {}", operation, objectKey,
                decision.reason.empty() ? "budget would be exceeded" : decision.reason));
        reservations_ = decision.reservations;
    }

    ~PriceGuard() {
        if (settled_) return;
        // Remote requests may have been sent: charge the reservation (conservative), as a failed sync run does.
        try {
            service_.commit(reservations_, std::nullopt);
        } catch (const std::exception& e) {
            log::Registry::sync()->error("[ConflictResolver] Could not settle a price reservation: {}", e.what());
        }
    }

    void commit() {
        settled_ = true;
        service_.commit(reservations_, estimate_.available ? std::make_optional(estimate_.estimated_cost) : std::nullopt);
    }

    void release() {
        settled_ = true;
        service_.release(reservations_);
    }

    PriceGuard(const PriceGuard&) = delete;
    PriceGuard& operator=(const PriceGuard&) = delete;

private:
    pricing::PriceBudgetService service_{};
    pricing::PriceEstimateReport estimate_;
    std::vector<pricing::PriceBudgetReservation> reservations_;
    bool settled_{false};
};

FilePtr currentLocal(const storage::CloudEngine& engine, const ConflictRecord& conflict) {
    auto file = db::query::fs::File::getFileById(conflict.file_id);
    if (!file || file->vault_id != engine.vault->id)
        throw ConflictStale("the file no longer exists; the conflict will be closed by the next sync");
    if (!db::query::sync::sideMatches(conflict.local, file->content_hash, file->size_bytes, std::nullopt))
        throw ConflictStale("the local copy changed after the conflict was recorded; the next sync refreshes it, then "
                            "decide again");
    return file;
}

// The remote object as the index describes it (encryption metadata a sync download trusts), else as recorded.
FilePtr remoteFileFor(const storage::CloudEngine& engine, const ConflictRecord& conflict, const fs::model::File& local) {
    if (auto indexed = db::query::sync::RemoteObjectIndex::getFile(engine.vault->id, local.path)) return indexed;
    auto f = std::make_shared<fs::model::File>(local.path.string(), conflict.remote.size_bytes,
                                               conflict.remote.modified_at);
    f->content_hash = conflict.remote.content_hash;
    f->remote_etag = conflict.remote.etag;
    f->remote_encrypted = conflict.remote.encrypted;
    if (conflict.remote.encryption_iv) f->encryption_iv = *conflict.remote.encryption_iv;
    if (conflict.remote.key_version) f->encrypted_with_key_version = *conflict.remote.key_version;
    return f;
}

// The object's own encryption metadata (from its HEAD) wins over the index row, so the decrypt never needs a second
// HEAD.
void adoptHead(fs::model::File& remote, const storage::CloudEngine::RemoteObjectHead& head) {
    remote.remote_encrypted = head.encrypted;
    if (head.encrypted && !head.iv_b64.empty() && head.key_version) {
        remote.encryption_iv = head.iv_b64;
        remote.encrypted_with_key_version = head.key_version;
    }
    if (!head.etag.empty()) remote.remote_etag = head.etag;
}

// One HEAD: the bucket must still hold the recorded remote version.
storage::CloudEngine::RemoteObjectHead requireRemoteUnchanged(const storage::CloudEngine& engine, const ConflictRecord& conflict,
                                   const std::filesystem::path& path) {
    const auto head = engine.headRemoteObject(path);
    if (!head) throw ConflictStale("the remote object no longer exists; the next sync closes this conflict");
    const auto& recorded = conflict.remote;
    bool same;
    if (recorded.etag && !head->etag.empty()) same = *recorded.etag == head->etag;
    else if (recorded.content_hash && head->content_hash) same = *recorded.content_hash == *head->content_hash;
    else if (head->content_length)
        same = *head->content_length == recorded.size_bytes ||
               (head->encrypted && *head->content_length == recorded.size_bytes + kGcmTagBytes);
    else same = true;  // nothing to compare against: the GET below is still pinned with If-Match
    if (!same)
        throw ConflictStale("the remote object changed after the conflict was recorded; the next sync refreshes it, "
                            "then decide again");
    if (head->requires_restore)
        throw storage::ContentUnavailable("the remote object is in an archive tier and needs a restore first");
    return *head;
}

model::S3CostEstimate plannedFor(const model::Action& action) {
    auto estimate = Planner::estimateS3Cost({action});
    ++estimate.head_requests;  // the staleness check
    return estimate;
}

std::shared_ptr<model::RemotePolicy> policyOf(const storage::CloudEngine& engine) {
    auto policy = engine.remote_policy();
    if (!policy) throw std::invalid_argument("vault has no remote sync policy");
    return policy;
}

}

const char* toString(const ConflictDecision d) {
    return d == ConflictDecision::KeepLocal ? "keep_local" : "keep_remote";
}

const char* resolutionFor(const ConflictDecision d) {
    return d == ConflictDecision::KeepLocal ? "kept_local" : "kept_remote";
}

void ConflictResolver::resolve(const std::shared_ptr<storage::CloudEngine>& engine, const ConflictRecord& conflict,
                               const ConflictDecision decision) {
    if (!engine || !engine->vault) throw std::invalid_argument("conflict resolution needs a remote vault engine");
    if (!conflict.open()) throw ConflictStale("this conflict was already closed (" + conflict.resolution + ")");
    const Claim claim(conflict.id);

    const auto local = currentLocal(*engine, conflict);
    const auto remote = remoteFileFor(*engine, conflict, *local);
    const auto policy = policyOf(*engine);
    const auto key = local->path.string();

    std::optional<model::Baseline> baseline;
    if (decision == ConflictDecision::KeepLocal) {
        const model::Action action{model::ActionType::Upload, {local->path.u8string()}, local, remote};
        PriceGuard price(*engine, plannedFor(action), "conflict_resolve", key);
        {
            const storage::ScopedS3RequestUsageCapture capture(*engine, policy->s3_request_budget);
            (void)requireRemoteUnchanged(*engine, conflict, local->path);
            // The file's unsent local versions first, as a sync upload does (the price preflight above counts them:
            // Planner::estimateS3Cost adds the planned replays); a replay that fails leaves the conflict open.
            if (const auto replay = recovery::local::backlog::replayBeforeUpload(*engine, *local); replay.blocked)
                throw std::runtime_error("earlier versions could not be replayed upstream first: " +
                                         replay.error.value_or("unknown"));
            engine->upload(local);
            engine->applyRemoteIndexMutation({action});
        }
        price.commit();
        baseline = model::Baseline::afterUpload(*local);
    } else {
        if (remote->requiresArchiveRestoreForBodyGet())
            throw storage::ContentUnavailable("the remote object is in an archive tier and needs a restore first");
        const auto expectedSourceId = storage::generationOf(*local).sourceId();
        const model::Action action{model::ActionType::Download, {local->path.u8string()}, local, remote};
        PriceGuard price(*engine, plannedFor(action), "conflict_resolve", key);
        FilePtr replaced;
        {
            const storage::ScopedS3RequestUsageCapture capture(*engine, policy->s3_request_budget);
            const auto head = requireRemoteUnchanged(*engine, conflict, local->path);
            adoptHead(*remote, head);
            std::vector<uint8_t> plaintext;
            try {
                plaintext = engine->fetchRemotePlaintext(
                    remote, head.etag.empty() ? std::nullopt : std::make_optional(head.etag), std::nullopt);
            } catch (const storage::s3::ConditionalRequestFailed&) {
                throw ConflictStale("the remote object changed while it was being downloaded; decide again");
            } catch (const storage::s3::ObjectNotFound&) {
                throw ConflictStale("the remote object no longer exists; the next sync closes this conflict");
            }
            try {
                replaced = engine->replaceLocalContent(local->path, plaintext, expectedSourceId);
            } catch (const fs::ContentConflict&) {
                throw ConflictStale("the local copy changed (or is open for writing) while the remote version was "
                                    "being downloaded; nothing was replaced");
            }
        }
        price.commit();
        if (replaced) baseline = model::Baseline::afterDownload(*replaced, *remote);
    }

    if (!db::query::sync::Conflict::finishResolution(conflict.id, resolutionFor(decision), baseline, engine->vault->id))
        log::Registry::sync()->warn("[ConflictResolver] Conflict {} was closed by someone else while it was resolved",
                                    conflict.id);
    log::Registry::sync()->info("[ConflictResolver] Vault {} conflict {} on '{}' resolved: {}", engine->vault->id,
                                conflict.id, key, toString(decision));
}

std::vector<uint8_t> ConflictResolver::fetchRemoteForPreview(const std::shared_ptr<storage::CloudEngine>& engine,
                                                             const ConflictRecord& conflict, const uint64_t maxBytes) {
    if (!engine || !engine->vault) throw std::invalid_argument("conflict preview needs a remote vault engine");
    auto local = db::query::fs::File::getFileById(conflict.file_id);
    if (!local || local->vault_id != engine->vault->id) throw ConflictStale("the file no longer exists");
    const auto remote = remoteFileFor(*engine, conflict, *local);
    const auto recordedSize = conflict.remote.size_bytes;
    if (recordedSize > maxBytes + kGcmTagBytes)
        throw ContentTooLarge("the remote copy is too large to preview", maxBytes);
    if (remote->requiresArchiveRestoreForBodyGet())
        throw storage::ContentUnavailable("the remote object is in an archive tier and needs a restore first");

    const auto policy = policyOf(*engine);
    model::S3CostEstimate planned;
    planned.head_requests = 1;
    planned.get_requests = 1;
    planned.planned_body_download_bytes = recordedSize;
    planned.remote_index_objects = 1;
    PriceGuard price(*engine, planned, "conflict_preview", local->path.string());

    std::vector<uint8_t> plaintext;
    {
        // One HEAD, one GET, at most the cap plus the GCM tag, inside the vault's request budget.
        auto budget = policy->s3_request_budget;
        budget.max_head_requests = 1;
        budget.max_get_requests = 1;
        budget.max_downloaded_bytes = maxBytes + kGcmTagBytes;
        const storage::ScopedS3RequestUsageCapture capture(*engine, budget);
        const auto head = engine->headRemoteObject(local->path);
        if (!head) throw ConflictStale("the remote object no longer exists");
        if (head->requires_restore)
            throw storage::ContentUnavailable("the remote object is in an archive tier and needs a restore first");
        if (head->content_length && *head->content_length > maxBytes + kGcmTagBytes)
            throw ContentTooLarge("the remote copy is too large to preview", maxBytes);
        adoptHead(*remote, *head);
        try {
            plaintext = engine->fetchRemotePlaintext(
                remote, head->etag.empty() ? std::nullopt : std::make_optional(head->etag), maxBytes + kGcmTagBytes);
        } catch (const storage::s3::ConditionalRequestFailed&) {
            throw ConflictStale("the remote object changed while it was being fetched; try again");
        }
    }
    if (plaintext.size() > maxBytes) throw ContentTooLarge("the remote copy is too large to preview", maxBytes);
    price.commit();
    return plaintext;
}

}
