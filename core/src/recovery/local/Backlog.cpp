#include "recovery/local/Backlog.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/u8.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/sync/Conflict.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "recovery/Store.hpp"
#include "recovery/local/Versions.hpp"
#include "recovery/provider/State.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Baseline.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>

#include <algorithm>
#include <functional>
#include <set>

namespace vh::recovery::local::backlog {

namespace {

namespace rq = db::query::recovery;

std::string backlogVaultPath(const std::filesystem::path& p) {
    auto s = db::encoding::to_utf8_string(p.generic_u8string());
    if (s.empty() || s.front() != '/') s.insert(s.begin(), '/');
    return s;
}

std::string backlogKey(const std::filesystem::path& p) { return backlogVaultPath(p).substr(1); }

// What both sides last agreed on for the file: the provider holds that content already.
std::optional<std::string> agreedContentHash(const uint32_t vaultId, const uint32_t fileId) {
    return db::Transactions::read("recovery::backlog::agreedContentHash", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec("SELECT content_hash FROM sync_file_baseline WHERE vault_id = $1 AND file_id = $2",
                                  pqxx::params{vaultId, fileId});
        if (res.empty() || res.one_row_ref()[0].is_null()) return std::optional<std::string>{};
        return std::make_optional(res.one_row_ref()[0].as<std::string>());
    });
}

bool anyPendingFor(const uint32_t vaultId, const std::optional<uint32_t> fileId, const std::string& key) {
    return db::Transactions::read("recovery::backlog::anyPendingFor", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(
            "SELECT EXISTS (SELECT 1 FROM file_versions WHERE vault_id = $1 AND upstream_state = 'pending' "
            "AND (file_id = $2 OR upstream_key = $3))",
            pqxx::params{vaultId, fileId, key});
        return res.one_row_ref()[0].as<bool>();
    });
}

// Pending generations retained under `key` at `vaultPath` (any incarnation of the file), in capture order.
std::vector<rq::GenerationRow> pendingUnderKey(const uint32_t vaultId, const std::string& vaultPath,
                                               const std::string& key) {
    std::vector<rq::GenerationRow> out;
    for (auto& g : rq::Generation::listByPath(vaultId, vaultPath, rq::Origin::Version, 10000))
        if (g.upstream_state == rq::UpstreamState::Pending && g.upstream_key == key) out.push_back(std::move(g));
    return out;
}

bool heldBy(const rq::GenerationRow& g, const rq::ObjectVersionRow& v) {
    if (v.is_delete_marker) return false;
    if (g.encryption_iv && !g.encryption_iv->empty() && v.encryption_iv && *g.encryption_iv == *v.encryption_iv &&
        g.key_version && v.key_version && *g.key_version == *v.key_version)
        return true;
    return g.content_hash && v.content_hash && *g.content_hash == *v.content_hash;
}

bool smartCache(const storage::CloudEngine& engine) {
    const auto policy = engine.remote_policy();
    return policy && policy->strategy == sync::model::RemotePolicy::Strategy::Cache;
}

// The provider holds the generation now: its local body goes, unless a snapshot still references the blob.
void releaseBody(const store::VaultRef& ref, const int64_t generationId, ReplayReport& report) noexcept {
    try {
        const auto freed = db::Transactions::exec("recovery::backlog::release", [&](pqxx::work& txn) {
            return rq::Generation::releaseBlob(txn, generationId);
        });
        ++report.released;
        if (freed) static_cast<void>(store::removeBlobs(ref, {*freed}));
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[LocalVersions] Vault {}: could not release the local copy of version {}: {}",
                                       ref.id, generationId, e.what());
    }
}

// The replay PUT made generation `g` the key's current object. The remote index learns it (with the PUT's ETag and
// version id), and the live file's sync baseline records "remote = what we put, local = unpublished history", so a
// pass that runs before the rest of the backlog and the current content are uploaded sees Vaulthalla's own write and
// finishes the publication (sync::model::Baseline::publishing) instead of a remote change: no spurious conflict, and
// never the stale generation downloaded over the live file. Best effort (logged): a failure leaves the old state.
void recordReplayed(const storage::CloudEngine& engine, const rq::GenerationRow& g, const std::string& etag,
                    const std::optional<std::string>& versionId, const std::optional<uint32_t> liveFileId) noexcept {
    try {
        const auto vaultId = engine.vault->id;
        auto f = std::make_shared<fs::model::File>();
        f->vault_id = static_cast<int32_t>(vaultId);
        f->path = g.path;
        f->name = std::filesystem::path(g.path).filename().string();
        f->size_bytes = g.size_bytes;
        f->content_hash = g.content_hash;
        f->updated_at = g.source_updated_at.value_or(g.created_at);
        if (!etag.empty()) f->remote_etag = etag;
        if (versionId && !versionId->empty() && *versionId != "null") f->remote_version_id = versionId;
        f->remote_storage_class = engine.writeStorageClass();
        const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(engine.vault);
        if (s3 && s3->encrypt_upstream && g.encryption_iv && g.key_version) {
            f->remote_encrypted = true;
            f->encryption_iv = *g.encryption_iv;
            f->encrypted_with_key_version = *g.key_version;
        } else {
            f->remote_encrypted = false;
            f->encryption_iv.clear();
            f->encrypted_with_key_version = 0;
        }
        db::query::sync::RemoteObjectIndex::upsertFile(vaultId, f);
        if (liveFileId)
            db::query::sync::Conflict::upsertBaseline(
                vaultId, sync::model::Baseline::afterReplay(*liveFileId, g.content_hash, g.size_bytes,
                                                            etag.empty() ? std::nullopt : std::make_optional(etag)));
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[LocalVersions] Vault {}: the replay of version {} of {} was not recorded in "
                                       "the sync state: {}", engine.vault->id, g.version_number, g.path, e.what());
    }
}

void skipOne(const rq::GenerationRow& g, const std::string& why, ReplayReport& report) {
    rq::Generation::recordFailure(g.id, why);
    report.skipped += rq::Generation::markSkipped({g.id});
    log::Registry::storage()->warn("[LocalVersions] Vault {}: version {} of {} can't be replayed upstream ({}); skipped",
                                   g.vault_id.value_or(0), g.version_number, g.path, why);
}

ReplayReport replay(const storage::CloudEngine& engine, const std::string& key, std::vector<rq::GenerationRow> rows,
                    const std::optional<std::string>& agreedHash, const std::optional<uint32_t> liveFileId) {
    ReplayReport report;
    if (rows.empty()) return report;
    const auto vaultId = engine.vault->id;
    std::ranges::sort(rows, {}, &rq::GenerationRow::id);   // capture order (inserts of one key are serialized)

    if (!provider::bucketVersioningForVault(vaultId).keepsHistory()) {
        std::vector<int64_t> ids;
        for (const auto& g : rows) ids.push_back(g.id);
        report.skipped += rq::Generation::markSkipped(ids);
        return report;
    }

    const auto ref = store::vaultRef(*engine.vault);
    const bool release = smartCache(engine);
    std::vector<rq::ObjectVersionRow> known;
    try {
        known = rq::ObjectVersion::listForKey(vaultId, key, false, 1000);
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[LocalVersions] Vault {}: version index of '{}' unavailable: {}", vaultId, key,
                                       e.what());
    }

    for (const auto& g : rows) {
        if (const auto it = std::ranges::find_if(known, [&](const auto& v) { return heldBy(g, v); }); it != known.end()) {
            if (rq::Generation::markSent(g.id, it->version_id)) {
                ++report.already_upstream;
                if (release) releaseBody(ref, g.id, report);
            }
            continue;
        }
        if (agreedHash && g.content_hash && *g.content_hash == *agreedHash) {
            // Uploaded (or downloaded) when both sides last agreed, before Vaulthalla knew its version id.
            ++report.already_upstream;
            report.skipped += rq::Generation::markSkipped({g.id});
            continue;
        }
        if (!g.blob_id || !g.storage_name) {
            skipOne(g, "no local copy of this version", report);
            continue;
        }

        std::optional<std::string> versionId;
        try {
            versionId = engine.uploadGeneration(key, store::blobPath(ref, *g.storage_name), g);
            recordReplayed(engine, g, storage::s3::Controller::lastPutOutcome().etag, versionId, liveFileId);
        } catch (const storage::ContentUnavailable& e) {
            skipOne(g, e.what(), report);
            continue;
        } catch (const storage::IntegrityError& e) {
            skipOne(g, e.what(), report);
            continue;
        } catch (const std::exception& e) {
            // The provider didn't take it: keep it pending, in order, and hold the key's next write back.
            rq::Generation::recordFailure(g.id, e.what());
            ++report.failed;
            report.blocked = true;
            report.error = e.what();
            break;
        }

        if (!versionId || versionId->empty() || *versionId == "null") {
            ++report.skipped;
            static_cast<void>(rq::Generation::markSkipped({g.id}));
            log::Registry::storage()->warn("[LocalVersions] Vault {}: the bucket kept no version for '{}'", vaultId, key);
            continue;
        }
        if (rq::Generation::markSent(g.id, *versionId)) {
            ++report.sent;
            if (release) releaseBody(ref, g.id, report);
        }
    }

    if (report.sent || report.failed || report.already_upstream)
        log::Registry::storage()->info(
            "[LocalVersions] Vault {} '{}': replayed {}, already upstream {}, skipped {}, released {}{}", vaultId, key,
            report.sent, report.already_upstream, report.skipped, report.released,
            report.blocked ? ", blocked: " + report.error.value_or("") : std::string{});
    return report;
}

ReplayReport guarded(const char* what, const std::function<ReplayReport()>& fn) {
    try {
        return fn();
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[LocalVersions] Backlog {} failed: {}", what, e.what());
        ReplayReport report;
        report.blocked = true;
        report.error = e.what();
        return report;
    }
}

}

ReplayReport replayBeforeUpload(const storage::CloudEngine& engine, const fs::model::File& file) {
    if (!engine.vault || file.id == 0) return {};
    return guarded("replay before upload", [&] {
        const auto vaultId = engine.vault->id;
        const auto vaultPath = backlogVaultPath(file.path);
        const auto key = backlogKey(file.path);
        if (!mayHaveBacklog(vaultId) || !anyPendingFor(vaultId, file.id, key)) return ReplayReport{};

        ReplayReport renamedAway;
        std::vector<rq::GenerationRow> rows;
        std::set<int64_t> seen;
        std::vector<int64_t> otherKey;
        for (auto& g : rq::Generation::listPendingForFile(file.id)) {
            if (g.upstream_key != key) {
                otherKey.push_back(g.id);   // retained before a rename: the old key's history isn't this one
                continue;
            }
            seen.insert(g.id);
            rows.push_back(std::move(g));
        }
        for (auto& g : pendingUnderKey(vaultId, vaultPath, key))
            if (!seen.contains(g.id)) rows.push_back(std::move(g));
        if (!otherKey.empty()) renamedAway.skipped = rq::Generation::markSkipped(otherKey);

        auto report = replay(engine, key, std::move(rows), agreedContentHash(vaultId, file.id), file.id);
        report.skipped += renamedAway.skipped;
        return report;
    });
}

ReplayReport replayBeforeRemoteDelete(const storage::CloudEngine& engine, const std::filesystem::path& vaultPath) {
    if (!engine.vault) return {};
    return guarded("replay before remote delete", [&] {
        const auto key = backlogKey(vaultPath);
        if (!mayHaveBacklog(engine.vault->id) || !anyPendingFor(engine.vault->id, std::nullopt, key)) return ReplayReport{};
        return replay(engine, key, pendingUnderKey(engine.vault->id, backlogVaultPath(vaultPath), key), std::nullopt,
                      std::nullopt);
    });
}

void addPlannedReplays(const uint32_t vaultId, const std::vector<sync::model::Action>& plan,
                       sync::model::S3CostEstimate& estimate) noexcept {
    try {
        auto keys = nlohmann::json::array();
        for (const auto& a : plan) {
            if (a.type == sync::model::ActionType::Upload && a.local) keys.push_back(backlogKey(a.local->path));
            else if (a.type == sync::model::ActionType::DeleteRemote && a.remote) keys.push_back(backlogKey(a.remote->path));
        }
        if (keys.empty()) return;

        const auto [count, bytes] = db::Transactions::read("recovery::backlog::planned", [&](pqxx::transaction_base& txn) {
            const auto res = txn.exec(R"SQL(
                SELECT count(*), COALESCE(sum(COALESCE(b.cipher_bytes, fv.size_bytes)), 0)::bigint
                FROM file_versions fv LEFT JOIN recovery_blob b ON b.id = fv.blob_id
                WHERE fv.vault_id = $1 AND fv.upstream_state = 'pending'
                  AND fv.upstream_key IN (SELECT jsonb_array_elements_text($2::jsonb))
            )SQL", pqxx::params{vaultId, keys.dump()});
            const auto row = res.one_row_ref();
            return std::pair{row[0].as<uint64_t>(), row[1].as<uint64_t>()};
        });
        if (count == 0 || !provider::bucketVersioningForVault(vaultId).keepsHistory()) return;
        estimate.put_requests += count;
        estimate.planned_upload_bytes += bytes;
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[LocalVersions] Vault {}: backlog replays left out of the estimate: {}", vaultId,
                                       e.what());
    }
}

Backlog summary(const uint32_t vaultId) {
    const auto b = rq::Generation::backlog(vaultId);
    return {.pending_versions = b.pending, .pending_bytes = b.pending_bytes, .oldest_pending_at = b.oldest_pending_at,
            .failing = b.failing, .last_error = b.last_error};
}

}
