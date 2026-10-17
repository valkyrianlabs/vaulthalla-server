#include "recovery/local/Points.hpp"

#include "db/query/recovery/Blob.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/recovery/Snapshot.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "log/Registry.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <unordered_set>

namespace vh::recovery::local::points {

namespace {

namespace rq = db::query::recovery;

std::shared_ptr<storage::Engine> liveEngine(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    return manager ? manager->getEngine(vaultId) : nullptr;
}

// Every key version the vault's retained blobs use is still held (what a snapshot's encryption context can say
// without walking its members).
bool everyRetainedKeyHeld(const uint32_t vaultId, const storage::Engine* engine) {
    if (!engine || !engine->encryptionManager) return false;
    try {
        const auto versions = rq::Blob::keyVersions(vaultId);
        return std::ranges::all_of(versions, [&](const unsigned int v) {
            return v == 0 || engine->encryptionManager->hasKeyVersion(v);
        });
    } catch (const std::exception& e) {
        log::Registry::storage()->debug("[recovery::points] key versions of vault {} unavailable: {}", vaultId, e.what());
        return false;
    }
}

RecoveryPoint snapshotPoint(const rq::SnapshotRow& row, const bool keysHeld) {
    RecoveryPoint p;
    p.id = RecoveryId{.type = RecoveryId::Type::Snapshot, .id = static_cast<uint64_t>(row.id)}.str();
    p.backend = Backend::LocalSnapshot;
    p.vault_id = row.vault_id;
    p.path = row.root_path;
    p.original_entry_id = row.root_entry_id;
    p.kind = row.root_type;
    p.name = row.name;
    p.created_at = row.created_at;
    p.size_bytes = row.plaintext_bytes;
    p.file_count = row.file_count;
    p.encryption = {.encrypted = true, .key_version = 0, .key_available = keysHeld, .key_current = false};
    p.retention = {.policy = "snapshot", .expires_at = std::nullopt, .note = "kept until deleted"};
    p.restorable = row.state == "ready";
    if (!p.restorable)
        p.unavailable_reason = "snapshot is " + row.state + (row.error ? ": " + *row.error : std::string());
    return p;
}

Retention versionRetention(const rq::GenerationRow& row, const rq::PolicyRow& policy) {
    if (row.origin == rq::Origin::Snapshot)
        return {.policy = "snapshot", .expires_at = std::nullopt,
                .note = "kept with " + RecoveryId{.type = RecoveryId::Type::Snapshot,
                                                  .id = static_cast<uint64_t>(row.snapshot_id.value_or(0))}.str() +
                        " until the snapshot is deleted"};
    const auto& lv = policy.local_versioning;
    Retention r;
    std::vector<std::string> notes;
    if (lv.keep_last) r.policy = "keep_last:" + std::to_string(*lv.keep_last);
    if (lv.max_age_days) {
        if (r.policy.empty()) r.policy = "max_age_days:" + std::to_string(*lv.max_age_days);
        else notes.push_back("and at most " + std::to_string(*lv.max_age_days) + " days");
        r.expires_at = row.created_at + static_cast<std::time_t>(*lv.max_age_days) * 86400;
    }
    if (r.policy.empty()) r.policy = "indefinite";
    if (lv.quota_bytes) notes.push_back("oldest pruned first beyond " + std::to_string(*lv.quota_bytes) + " bytes");
    if (row.upstream_state == rq::UpstreamState::Pending) notes.emplace_back("never pruned while pending upstream");
    if (!notes.empty()) {
        std::string joined;
        for (const auto& n : notes) joined += (joined.empty() ? "" : "; ") + n;
        r.note = joined;
    }
    return r;
}

}

RecoveryPoint fromSnapshot(const rq::SnapshotRow& row) {
    const auto engine = liveEngine(row.vault_id);
    return snapshotPoint(row, everyRetainedKeyHeld(row.vault_id, engine.get()));
}

RecoveryPoint fromGeneration(const rq::GenerationRow& row, const rq::PolicyRow& policy, const storage::Engine* engine) {
    RecoveryPoint p;
    p.id = RecoveryId{.type = RecoveryId::Type::LocalGeneration, .id = static_cast<uint64_t>(row.id)}.str();
    p.backend = row.origin == rq::Origin::Snapshot ? Backend::LocalSnapshot : Backend::LocalVersion;
    p.vault_id = row.vault_id.value_or(0);
    p.path = row.path;
    p.original_entry_id = row.file_id;
    p.kind = PointKind::File;
    p.created_at = row.created_at;
    p.valid_from = row.source_updated_at;
    if (row.origin == rq::Origin::Version) p.valid_until = row.created_at;
    p.size_bytes = row.size_bytes;
    p.content_hash = row.content_hash;
    p.retention = versionRetention(row, policy);
    if (row.origin == rq::Origin::Version) {
        p.reason = row.reason;
        p.upstream_state = rq::to_string(row.upstream_state);
    }

    const auto iv = row.encryption_iv.value_or("");
    const auto keyVersion = row.key_version.value_or(0);
    const auto* em = engine ? engine->encryptionManager.get() : nullptr;
    if (iv.empty()) {
        p.encryption = {.encrypted = false, .key_version = 0, .key_available = true, .key_current = false};
    } else {
        p.encryption = {.encrypted = true, .key_version = keyVersion,
                        .key_available = em && em->hasKeyVersion(keyVersion),
                        .key_current = em && em->get_key_version() == keyVersion};
    }

    // Restorable: the body is here, and the key that opens it.
    if (!row.blob_id) {
        p.restorable = false;
        p.unavailable_reason = row.upstream_state == rq::UpstreamState::Sent
                                   ? "the body is held only by the provider (sent upstream)"
                                   : "no retained body";
    } else if (!engine || !engine->vault) {
        p.restorable = false;
        p.unavailable_reason = "the vault is not available";
    } else {
        const auto handle = store::open(store::vaultRef(*engine->vault), *row.blob_id);
        if (!handle || !handle->present) {
            p.restorable = false;
            p.unavailable_reason = "blob missing";
        } else if (!iv.empty() && !p.encryption.key_available) {
            p.restorable = false;
            p.unavailable_reason = "key version " + std::to_string(keyVersion) + " is no longer held by the vault";
        }
    }
    return p;
}

std::vector<RecoveryPoint> list(const uint32_t vaultId, const Query& query) {
    const auto engine = liveEngine(vaultId);
    const auto policy = rq::Policy::get(vaultId);
    std::optional<bool> keysHeld;
    const auto keys = [&] {
        if (!keysHeld) keysHeld = everyRetainedKeyHeld(vaultId, engine.get());
        return *keysHeld;
    };

    std::vector<RecoveryPoint> out;
    std::unordered_set<std::string> seen;
    const auto addSnapshots = [&](const std::vector<rq::SnapshotRow>& rows) {
        for (const auto& row : rows)
            if (row.state != "deleting" && seen.insert("snap-" + std::to_string(row.id)).second)
                out.push_back(snapshotPoint(row, keys()));
    };
    const auto addGenerations = [&](const std::vector<rq::GenerationRow>& rows) {
        for (const auto& row : rows) {
            if (!query.versions && row.origin == rq::Origin::Version) continue;
            if (!query.snapshots && row.origin == rq::Origin::Snapshot) continue;
            if (seen.insert("lv-" + std::to_string(row.id)).second) out.push_back(fromGeneration(row, policy, engine.get()));
        }
    };

    if (!query.path) {
        if (query.snapshots) addSnapshots(rq::Snapshot::listByVault(vaultId, query.limit));
        if (query.versions) addGenerations(rq::Generation::listVersionsUnder(vaultId, "/", query.limit));
    } else {
        auto path = std::filesystem::path(*query.path).lexically_normal().string();
        while (path.size() > 1 && path.back() == '/') path.pop_back();
        std::shared_ptr<fs::model::Entry> live;
        if (engine) live = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
        const bool liveDir = live && live->isDirectory();
        const bool liveFile = live && !live->isDirectory();

        if (!liveDir && (query.snapshots || query.versions)) {
            // A file's history, deleted or not.
            std::optional<rq::Origin> origin;
            if (!query.snapshots) origin = rq::Origin::Version;
            else if (!query.versions) origin = rq::Origin::Snapshot;
            addGenerations(rq::Generation::listByPath(vaultId, path, origin, query.limit));
        }
        if (query.snapshots) {
            if (!liveFile) addSnapshots(rq::Snapshot::listUnderPath(vaultId, path, query.limit));
            addSnapshots(rq::Snapshot::listContainingPath(vaultId, path, query.limit));
        }
        if (!liveFile && query.versions) addGenerations(rq::Generation::listVersionsUnder(vaultId, path, query.limit));
    }

    std::ranges::stable_sort(out, [](const RecoveryPoint& a, const RecoveryPoint& b) { return a.created_at > b.created_at; });
    return out;
}

std::optional<RecoveryPoint> get(const RecoveryId& id) {
    if (id.type == RecoveryId::Type::Snapshot) {
        const auto row = rq::Snapshot::get(static_cast<int64_t>(id.id));
        if (!row) return std::nullopt;
        return fromSnapshot(*row);
    }
    if (id.type == RecoveryId::Type::LocalGeneration) {
        const auto row = rq::Generation::get(static_cast<int64_t>(id.id));
        if (!row || !row->vault_id) return std::nullopt;
        const auto engine = liveEngine(*row->vault_id);
        return fromGeneration(*row, rq::Policy::get(*row->vault_id), engine.get());
    }
    return std::nullopt;
}

std::optional<ops::recovery::PointDetail> detail(const RecoveryId& id, const std::string& afterRelPath,
                                                 const unsigned int memberLimit) {
    if (id.type == RecoveryId::Type::LocalGeneration) {
        auto point = get(id);
        if (!point) return std::nullopt;
        ops::recovery::PointDetail d;
        d.point = std::move(*point);
        return d;
    }
    if (id.type != RecoveryId::Type::Snapshot) return std::nullopt;

    const auto row = rq::Snapshot::get(static_cast<int64_t>(id.id));
    if (!row) return std::nullopt;
    const auto engine = liveEngine(row->vault_id);
    const auto policy = rq::Policy::get(row->vault_id);

    ops::recovery::PointDetail d;
    d.point = snapshotPoint(*row, everyRetainedKeyHeld(row->vault_id, engine.get()));
    d.created_by = row->created_by_name;
    auto members = rq::Generation::listSnapshotMembers(row->id, afterRelPath, memberLimit + 1);
    if (members.size() > memberLimit) {
        d.members_truncated = true;
        members.resize(memberLimit);
    }
    for (const auto& m : members) d.members.push_back(fromGeneration(m, policy, engine.get()));
    try {
        for (const auto& s : nlohmann::json::parse(row->skipped_json)) {
            std::string line = s.value("path", std::string()) + ": " + s.value("reason", std::string());
            if (s.contains("detail") && s["detail"].is_string()) line += " (" + s["detail"].get<std::string>() + ")";
            d.skipped.push_back(std::move(line));
        }
    } catch (const std::exception& e) {
        d.skipped.push_back(std::string("(skipped entries unreadable: ") + e.what() + ")");
    }
    return d;
}

}
