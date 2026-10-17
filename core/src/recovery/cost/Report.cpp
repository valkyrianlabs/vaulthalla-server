#include "recovery/cost/Report.hpp"

#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/recovery/Usage.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "log/Registry.hpp"
#include "recovery/usage/Ledger.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/pricing/PriceProfileResolver.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <pqxx/pqxx>

#include <mutex>

namespace vh::recovery::cost {

namespace {

namespace pricing = storage::s3::pricing;

struct CostCatalogState {
    std::mutex mutex;
    std::shared_ptr<pricing::IPriceCatalogStore> store;
    std::shared_ptr<pricing::IPriceCatalogStore> testStore;
};

CostCatalogState& costCatalog() {
    static CostCatalogState s;
    return s;
}

struct CostCurrentObjects {
    uint64_t objects = 0, bytes = 0;
    std::optional<uint64_t> average_key_bytes;
};

// Current objects of the vault as the remote index knows them; Vaulthalla's own manifest (.vaulthalla/) is not data.
CostCurrentObjects costCurrentObjects(const uint32_t vaultId) {
    return db::Transactions::read("recovery::cost::currentObjects", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(
            "SELECT COUNT(*) AS objects, COALESCE(SUM(size_bytes), 0) AS bytes, "
            "AVG(octet_length(object_key))::bigint AS key_bytes "
            "FROM remote_object_index WHERE vault_id = $1 AND object_key NOT LIKE '.vaulthalla/%'",
            pqxx::params{vaultId});
        CostCurrentObjects out;
        const auto row = res.one_row_ref();
        out.objects = static_cast<uint64_t>(std::max<int64_t>(0, row["objects"].as<int64_t>()));
        out.bytes = static_cast<uint64_t>(std::max<int64_t>(0, row["bytes"].as<int64_t>()));
        if (!row["key_bytes"].is_null()) out.average_key_bytes = static_cast<uint64_t>(std::max<int64_t>(0, row["key_bytes"].as<int64_t>()));
        return out;
    });
}

std::time_t costMonthStart(const std::time_t now) {
    std::tm tm{};
    gmtime_r(&now, &tm);
    tm.tm_mday = 1;
    tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
    return timegm(&tm);
}

}

CatalogInfo lookupProfile(const pricing::PriceProfileTarget& target) {
    CatalogInfo info;
    try {
        auto& s = costCatalog();
        std::scoped_lock lock(s.mutex);
        auto store = s.testStore;
        if (!store) {
            if (!s.store) s.store = std::make_shared<pricing::PriceCatalogStore>(config::Registry::get().pricing.storage_rates_api);
            store = s.store;
        }
        const auto result = store->getProfile(target);
        info.verified = result.signature_verified;
        info.stale = result.stale;
        info.age_seconds = result.age_seconds;
        info.source = result.source;
        if (!result.ok) {
            info.error = result.error.empty() ? "pricing profile unavailable: " + target.profileId() : result.error;
            return info;
        }
        info.profile = result.profile;
        if (!info.verified)
            info.note = "the price catalog's signature was not verified (no public key configured, or verification is "
                        "warning-only)";
    } catch (const std::exception& e) {
        info.profile.reset();
        info.error = std::string("pricing catalog unavailable: ") + e.what();
    }
    return info;
}

void setCatalogStoreForTesting(std::shared_ptr<pricing::IPriceCatalogStore> store) {
    auto& s = costCatalog();
    std::scoped_lock lock(s.mutex);
    s.testStore = std::move(store);
}

Inputs gather(const uint32_t vaultId, const GatherOptions& options, const std::time_t now) {
    Inputs in;
    in.vault_id = vaultId;
    in.now = now;
    in.retention = options.retention;
    in.foreign_noncurrent_days = options.foreign_noncurrent_days;

    // Usage: the last 30 UTC days, and when measuring began.
    const auto today = usage::utcDay(now);
    const auto from = usage::utcDay(now - 29 * 24 * 3600);
    in.usage = db::query::recovery::Usage::range(vaultId, from, today);
    in.first_usage_day = db::query::recovery::Usage::totals(vaultId).first_day;
    in.history = db::query::recovery::ObjectVersion::noncurrentSummary(vaultId);

    const auto policy = db::query::recovery::Policy::get(vaultId);
    in.alert_threshold = policy.cost_alert_monthly;
    const bool providerMode = policy.mode == Mode::ProviderVersioning;

    const auto& deps = runtime::Deps::get();
    const auto vault = deps.storageManager ? deps.storageManager->getVault(vaultId) : nullptr;
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    if (!s3) {
        in.unpriced_reason = "provider versioning applies to S3 vaults only";
        return in;
    }
    in.bucket = s3->bucket;

    const auto current = costCurrentObjects(vaultId);
    in.current_objects = current.objects;
    in.current_bytes = current.bytes;
    in.average_key_bytes = current.average_key_bytes;

    // The bucket's recorded versioning state and Vaulthalla's retention.
    const auto engine = std::dynamic_pointer_cast<storage::CloudEngine>(deps.storageManager->getEngine(vaultId));
    const auto key = engine ? engine->s3ApiKey() : nullptr;
    if (key) {
        in.provider = storage::s3::provider::admin::providerIdentity(*key);
        in.region = key->region.empty() ? std::nullopt : std::make_optional(key->region);
        try {
            const auto id = storage::upstream::identityFor(*key, s3->bucket);
            if (id.account_ref)
                if (const auto row = db::query::upstream::Bucket::getByIdentity(id.provider, *id.account_ref, id.bucket))
                    if (const auto v = db::query::upstream::Bucket::getVersioning(row->id)) {
                        in.versioning_status = v->status.value_or("unknown");
                        in.enabled_by_vaulthalla = v->enabled_by_vaulthalla;
                        if (!in.retention) {
                            if (v->retention_mode == "days" && v->retention_days)
                                in.retention = ProviderRetention{.indefinite = false, .days = *v->retention_days};
                            else if (v->retention_mode == "indefinite")
                                in.retention = ProviderRetention{.indefinite = true, .days = 0};
                        }
                    }
        } catch (const std::exception& e) {
            log::Registry::storage()->debug("[recovery::cost] vault {}: bucket state unavailable: {}", vaultId, e.what());
        }
    }
    if (options.versioning_status) in.versioning_status = *options.versioning_status;
    in.active = providerMode && in.versioning_status == "enabled";
    if (in.versioning_status == "enabled" || in.versioning_status == "suspended")
        in.month_to_date_byte_hours =
            db::query::recovery::ObjectVersion::noncurrentByteHours(vaultId, costMonthStart(now), now).byte_hours;

    // Price profile.
    if (!config::Registry::get().pricing.enabled) {
        in.unpriced_reason = "pricing is disabled in the configuration";
        return in;
    }
    if (!engine) {
        in.unpriced_reason = "the vault's storage engine is not running";
        return in;
    }
    const auto target = pricing::resolvePriceProfileTarget(engine->s3ProviderProfile(), key, engine->resolvedStorageTier());
    if (!target) {
        in.unpriced_reason = "no price profile exists for this provider or storage class";
        return in;
    }
    in.provider = target->provider;
    in.region = target->region;
    in.storage_class = target->storage_class;
    in.catalog = lookupProfile(*target);
    return in;
}

CostReport reportForVault(const uint32_t vaultId, const GatherOptions& options, const std::time_t now) {
    return estimate(gather(vaultId, options, now));
}

}
