#include "db/query/vault/BucketCapability.hpp"

#include "db/Transactions.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>

namespace vh::db::query::vault {

namespace bucket_capability_query {

using storage::s3::WriteCapability;

BucketCapability::Stored storedFrom(const pqxx::row_ref row) {
    BucketCapability::Stored out;
    if (row["bucket_probe"].is_null()) return out;
    const auto probe = nlohmann::json::parse(row["bucket_probe"].as<std::string>(), nullptr, false);
    if (probe.is_discarded() || !probe.is_object()) return out;
    if (probe.contains("capability")) out.probe = storage::s3::probeResultFromJson(probe);
    if (const auto it = probe.find("changed_at"); it != probe.end() && it->is_number_integer())
        out.changed_at = static_cast<std::time_t>(it->get<int64_t>());
    if (const auto it = probe.find("changed_detail"); it != probe.end() && it->is_string())
        out.changed_detail = it->get<std::string>();
    const auto mode = row["manifest_publish"].is_null()
        ? std::nullopt
        : storage::s3::publishModeFromString(row["manifest_publish"].as<std::string>());
    if (mode) out.capability = *mode;
    else if (out.probe) out.capability = out.probe->capability == WriteCapability::Unknown
        ? WriteCapability::Unknown : WriteCapability::Insufficient;
    return out;
}

}

BucketCapability::Stored BucketCapability::get(const uint32_t vaultId) {
    return Transactions::exec("BucketCapability::get", [&](pqxx::work& txn) {
        const auto res = txn.exec("SELECT manifest_publish, bucket_probe::text AS bucket_probe FROM s3 WHERE vault_id = $1",
                                  pqxx::params{vaultId});
        if (res.empty()) return Stored{};
        return bucket_capability_query::storedFrom(res.one_row_ref());
    });
}

void BucketCapability::record(const uint32_t vaultId, const storage::s3::ProbeResult& probe) {
    using storage::s3::WriteCapability;
    std::optional<std::string> mode;
    if (probe.capability == WriteCapability::Conditional || probe.capability == WriteCapability::VersionLog)
        mode = std::string(storage::s3::to_string(probe.capability));
    Transactions::exec("BucketCapability::record", [&](pqxx::work& txn) {
        txn.exec("UPDATE s3 SET manifest_publish = $2, bucket_probe = $3::jsonb WHERE vault_id = $1",
                 pqxx::params{vaultId, mode, storage::s3::toJson(probe).dump()});
    });
}

bool BucketCapability::markChanged(const uint32_t vaultId, const std::string& detail) {
    return Transactions::exec("BucketCapability::markChanged", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "UPDATE s3 SET bucket_probe = COALESCE(bucket_probe, '{}'::jsonb) "
            "  || jsonb_build_object('changed_at', $2::bigint, 'changed_detail', $3::text) "
            "WHERE vault_id = $1 AND manifest_publish = 'conditional' AND NOT bucket_probe ? 'changed_at' "
            "RETURNING vault_id",
            pqxx::params{vaultId, static_cast<int64_t>(std::time(nullptr)), detail});
        return !res.empty();
    });
}

void BucketCapability::clearForKey(const uint32_t apiKeyId) {
    Transactions::exec("BucketCapability::clearForKey", [&](pqxx::work& txn) {
        txn.exec("UPDATE s3 SET manifest_publish = NULL, bucket_probe = NULL WHERE api_key_id = $1",
                 pqxx::params{apiKeyId});
    });
}

std::vector<BucketCapability::Unpublishable> BucketCapability::unpublishable() {
    return Transactions::exec("BucketCapability::unpublishable", [&](pqxx::work& txn) {
        std::vector<Unpublishable> out;
        const auto res = txn.exec(
            "SELECT v.id, v.name, s.manifest_publish, s.bucket_probe::text AS bucket_probe "
            "FROM vault v JOIN s3 s ON s.vault_id = v.id "
            "WHERE v.deleted_at IS NULL AND s.storage_layout = 'opaque_v1' AND s.bucket_probe IS NOT NULL "
            "  AND (s.manifest_publish IS NULL OR s.bucket_probe ? 'changed_at') "
            "ORDER BY v.id");
        for (const auto row : res) {
            const auto stored = bucket_capability_query::storedFrom(row);
            Unpublishable u{.vault_id = row["id"].as<uint32_t>(), .vault_name = row["name"].as<std::string>(),
                            .reason = {}, .detail = {}};
            if (stored.changed_at) {
                u.reason = "bucket_capability_changed";
                u.detail = "the bucket refused a conditional write although its probe found support (" +
                           stored.changed_detail.value_or("") + "); check the endpoint, then run vh vault storage probe " +
                           std::to_string(u.vault_id);
            } else {
                u.reason = "bucket_capability_insufficient";
                u.detail = stored.probe ? stored.probe->reason : std::string("the bucket probe found it insufficient");
            }
            out.push_back(std::move(u));
        }
        return out;
    });
}

}
