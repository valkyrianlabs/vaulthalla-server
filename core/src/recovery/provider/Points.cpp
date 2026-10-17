#include "recovery/provider/Points.hpp"

#include "db/query/recovery/ObjectVersion.hpp"
#include "recovery/provider/Versions.hpp"
#include "storage/CloudEngine.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <cctype>

namespace vh::recovery::provider::points {

namespace {

constexpr uint64_t kPointGcmTagBytes = 16;
constexpr std::time_t kPointDaySeconds = 24 * 60 * 60;

}

RetentionInfo RetentionInfo::from(const ProviderVersioningState& state) {
    if (state.effective_noncurrent_days) return {.kind = Kind::Days, .days = *state.effective_noncurrent_days};
    if (state.retention_mode == "indefinite" && state.foreign_noncurrent_rules.empty()) return {.kind = Kind::Indefinite};
    return {};
}

bool isArchiveClass(const std::optional<std::string>& storageClass) {
    if (!storageClass) return false;
    std::string upper = *storageClass;
    std::ranges::transform(upper, upper.begin(), [](const unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return upper == "GLACIER" || upper == "DEEP_ARCHIVE";
}

RecoveryPoint fromRow(const db::query::recovery::ObjectVersionRow& row, const vault::EncryptionManager* keys,
                      const RetentionInfo& retention) {
    RecoveryPoint p;
    p.id = RecoveryId{.type = RecoveryId::Type::ProviderVersion, .id = static_cast<uint64_t>(row.id)}.str();
    p.backend = Backend::ProviderVersion;
    p.vault_id = row.vault_id;
    p.path = versions::vaultPathOf(row.object_key).string();
    p.kind = PointKind::File;
    p.created_at = row.last_modified.value_or(row.first_seen_at);
    p.valid_from = row.last_modified;
    p.valid_until = row.became_noncurrent_at;
    p.is_current = row.is_latest && !row.gone_at;
    p.is_delete_marker = row.is_delete_marker;
    p.origin = row.origin;
    p.storage_class = row.storage_class;
    p.content_hash = row.content_hash;

    const bool encrypted = row.encrypted.value_or(false);
    if (row.plaintext_bytes) p.size_bytes = row.plaintext_bytes;
    else if (row.size_bytes && encrypted && *row.size_bytes >= kPointGcmTagBytes) p.size_bytes = *row.size_bytes - kPointGcmTagBytes;
    else if (row.size_bytes && row.encrypted && !encrypted) p.size_bytes = row.size_bytes;
    // An observed version without metadata: its stored size is all that is known (ciphertext when it is sealed).

    p.encryption.encrypted = encrypted;
    if (encrypted && row.key_version) {
        p.encryption.key_version = *row.key_version;
        if (keys) {
            try {
                p.encryption.key_available = keys->hasKeyVersion(*row.key_version);
                p.encryption.key_current = keys->get_key_version() == *row.key_version;
            } catch (const std::exception&) {
                p.encryption.key_available = false;
            }
        }
    }

    // Retention applies to noncurrent versions: a provider lifecycle rule counts NoncurrentDays from when the
    // version stopped being current (AWS rounds to the next midnight UTC; expiry is asynchronous after that).
    switch (retention.kind) {
    case RetentionInfo::Kind::Days:
        p.retention.policy = "provider_days:" + std::to_string(retention.days);
        if (!p.is_current && row.became_noncurrent_at)
            p.retention.expires_at = *row.became_noncurrent_at + static_cast<std::time_t>(retention.days) * kPointDaySeconds;
        else if (p.is_current)
            p.retention.note = "kept while current; the retention period starts when a newer version replaces it";
        else
            p.retention.note = "when this version stopped being current is unknown";
        break;
    case RetentionInfo::Kind::Indefinite:
        p.retention.policy = "indefinite";
        break;
    case RetentionInfo::Kind::Unknown:
        p.retention.policy = "unknown";
        break;
    }

    if (row.gone_at) {
        p.restorable = false;
        p.unavailable_reason = "the provider no longer lists this version (expired or deleted)";
    } else if (row.is_delete_marker) {
        p.restorable = false;
        p.unavailable_reason = "delete marker: the file was absent at this time";
    } else if (row.is_latest) {
        p.restorable = false;
        p.unavailable_reason = "this is the current version: nothing to restore";
    } else if (isArchiveClass(row.storage_class)) {
        p.restorable = false;
        p.unavailable_reason = "archived storage class (" + *row.storage_class + "): the provider must restore it first";
    } else if (encrypted && row.key_version && !p.encryption.key_available) {
        p.restorable = false;
        p.unavailable_reason = "sealed under key version " + std::to_string(*row.key_version) +
                               ", which this vault no longer holds";
    }
    return p;
}

std::vector<RecoveryPoint> forPath(const std::shared_ptr<storage::CloudEngine>& engine,
                                   const std::filesystem::path& vaultPath, const bool directory,
                                   const RetentionInfo& retention, const unsigned int limit, const bool includeGone) {
    if (!engine || !engine->vault) throw std::invalid_argument("provider recovery points need a cloud vault engine");
    const auto vaultId = engine->vault->id;
    const auto* keys = engine->encryptionManager.get();
    std::vector<db::query::recovery::ObjectVersionRow> rows;
    if (directory) rows = db::query::recovery::ObjectVersion::listUnderPrefix(vaultId, versions::directoryPrefixOf(vaultPath),
                                                                              includeGone, limit);
    else rows = db::query::recovery::ObjectVersion::listForKey(vaultId, versions::objectKeyOf(vaultPath), includeGone, limit);

    std::vector<RecoveryPoint> out;
    out.reserve(rows.size());
    for (const auto& row : rows)
        if (!versions::isInternalKey(row.object_key)) out.push_back(fromRow(row, keys, retention));
    return out;
}

std::optional<RecoveryPoint> byId(const std::shared_ptr<storage::CloudEngine>& engine, const uint64_t id,
                                  const RetentionInfo& retention) {
    if (!engine || !engine->vault) throw std::invalid_argument("provider recovery points need a cloud vault engine");
    const auto row = db::query::recovery::ObjectVersion::get(static_cast<int64_t>(id));
    if (!row || row->vault_id != engine->vault->id || versions::isInternalKey(row->object_key)) return std::nullopt;
    return fromRow(*row, engine->encryptionManager.get(), retention);
}

}
