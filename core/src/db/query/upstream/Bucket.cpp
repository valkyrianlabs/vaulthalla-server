#include "db/query/upstream/Bucket.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"

#include <pqxx/result>

#include <ctime>
#include <stdexcept>

namespace vh::db::query::upstream {

namespace {

namespace bmodel = storage::upstream::model;

const std::string& requireAccount(const storage::upstream::BucketIdentity& id) {
    if (!id.account_ref || id.account_ref->empty())
        throw std::invalid_argument("upstream bucket identity has no resolved account for '" + id.bucket + "'");
    if (id.provider.empty() || id.bucket.empty()) throw std::invalid_argument("upstream bucket identity is incomplete");
    return *id.account_ref;
}

std::optional<BucketModel> firstRow(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return BucketModel(res.one_row_ref());
}

bool busy(const BucketModel& b, const std::string& token) {
    const bool inFlight = b.provisioning_state == bmodel::ProvisioningState::Creating ||
                          b.provisioning_state == bmodel::ProvisioningState::Configuring;
    if (!inFlight || b.operation_token == token) return false;
    const auto age = std::time(nullptr) - b.updated_at;
    return age < std::chrono::duration_cast<std::chrono::seconds>(Bucket::kStaleProvisioning).count();
}

}

std::optional<BucketModel> Bucket::get(const int64_t id) {
    return Transactions::exec("upstream::Bucket::get", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_get"}, pqxx::params{id});
        return firstRow(res);
    });
}

std::optional<BucketModel> Bucket::getByIdentity(const std::string& provider, const std::string& accountRef,
                                                 const std::string& bucket) {
    return Transactions::exec("upstream::Bucket::getByIdentity", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_get_by_identity"},
                                  pqxx::params{provider, accountRef, bucket});
        return firstRow(res);
    });
}

std::optional<BucketModel> Bucket::getForVault(const uint32_t vaultId) {
    return Transactions::exec("upstream::Bucket::getForVault", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_get_for_vault"}, pqxx::params{vaultId});
        return firstRow(res);
    });
}

std::vector<BucketModel> Bucket::listForAccount(const std::string& provider, const std::string& accountRef) {
    return Transactions::exec("upstream::Bucket::listForAccount", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_list_for_account"}, pqxx::params{provider, accountRef});
        return rowsAs<BucketModel>(res);
    });
}

std::vector<BucketModel> Bucket::findProtectedByName(const std::string& provider, const std::string& bucket) {
    return Transactions::exec("upstream::Bucket::findProtectedByName", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_find_protected_by_name"}, pqxx::params{provider, bucket});
        return rowsAs<BucketModel>(res);
    });
}

void Bucket::recordSeen(const std::string& provider, const std::string& accountRef, const std::optional<uint32_t> apiKeyId,
                        const std::vector<SeenBucket>& buckets) {
    if (buckets.empty()) return;
    if (provider.empty() || accountRef.empty()) throw std::invalid_argument("recordSeen needs a provider and account");
    Transactions::exec("upstream::Bucket::recordSeen", [&](pqxx::work& txn) {
        for (const auto& b : buckets) {
            if (b.bucket.empty()) continue;
            txn.exec(pqxx::prepped{"upstream_bucket_record_seen"},
                     pqxx::params{provider, accountRef, b.bucket, b.region, apiKeyId});
        }
    });
}

std::optional<ClaimOutcome> Bucket::claimForCreate(const storage::upstream::BucketIdentity& id,
                                                   const std::optional<std::string>& region,
                                                   const std::optional<uint32_t> apiKeyId,
                                                   const std::string& operationToken) {
    const auto& account = requireAccount(id);
    if (operationToken.empty()) throw std::invalid_argument("claimForCreate needs an operation token");
    return Transactions::exec("upstream::Bucket::claimForCreate", [&](pqxx::work& txn) -> std::optional<ClaimOutcome> {
        const auto inserted = txn.exec(pqxx::prepped{"upstream_bucket_claim_insert"},
                                       pqxx::params{id.provider, account, id.bucket, region, operationToken, apiKeyId});
        if (!inserted.empty()) return ClaimOutcome{.bucket = BucketModel(inserted.one_row_ref()), .reclaimed = false};

        const double staleSeconds = std::chrono::duration<double>(kStaleProvisioning).count();
        const auto retried = txn.exec(pqxx::prepped{"upstream_bucket_claim_retry"},
                                      pqxx::params{id.provider, account, id.bucket, operationToken, region, apiKeyId,
                                                   staleSeconds});
        if (!retried.empty()) return ClaimOutcome{.bucket = BucketModel(retried.one_row_ref()), .reclaimed = true};
        return std::nullopt;
    });
}

AdoptOutcome Bucket::upsertAdopted(const storage::upstream::BucketIdentity& id, const std::optional<std::string>& region,
                                   const std::optional<uint32_t> apiKeyId, const std::string& operationToken) {
    const auto& account = requireAccount(id);
    if (operationToken.empty()) throw std::invalid_argument("upsertAdopted needs an operation token");
    return Transactions::exec("upstream::Bucket::upsertAdopted", [&](pqxx::work& txn) -> AdoptOutcome {
        const auto locked = txn.exec(pqxx::prepped{"upstream_bucket_lock_by_identity"},
                                     pqxx::params{id.provider, account, id.bucket});
        if (locked.empty()) {
            const auto inserted = txn.exec(pqxx::prepped{"upstream_bucket_insert_adopted"},
                                           pqxx::params{id.provider, account, id.bucket, region, operationToken, apiKeyId});
            return {.result = AdoptResult::Adopted, .bucket = BucketModel(inserted.one_row_ref())};
        }

        const BucketModel current(locked.one_row_ref());
        if (current.is_protected) return {.result = AdoptResult::Protected, .bucket = current};
        if (current.vault_id) return {.result = AdoptResult::BoundElsewhere, .bucket = current};
        if (busy(current, operationToken)) return {.result = AdoptResult::Busy, .bucket = current};

        const auto taken = txn.exec(pqxx::prepped{"upstream_bucket_take_for_adoption"},
                                    pqxx::params{current.id, operationToken, region, apiKeyId});
        return {.result = AdoptResult::Adopted, .bucket = BucketModel(taken.one_row_ref())};
    });
}

bool Bucket::setProvisioningState(const int64_t id, const bmodel::ProvisioningState state,
                                  const std::optional<std::string>& expectedToken,
                                  const std::optional<std::string>& lastError) {
    return Transactions::exec("upstream::Bucket::setProvisioningState", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_set_provisioning_state"},
                                  pqxx::params{id, bmodel::to_string(state), expectedToken, lastError});
        return !res.empty();
    });
}

void Bucket::bindVault(const int64_t id, const uint32_t vaultId, const bmodel::Ownership ownership) {
    Transactions::exec("upstream::Bucket::bindVault", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_bucket_bind_vault"}, pqxx::params{id, vaultId, bmodel::to_string(ownership)});
    });
}

void Bucket::unbindVault(const int64_t id) {
    Transactions::exec("upstream::Bucket::unbindVault", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_bucket_unbind_vault"}, pqxx::params{id});
    });
}

void Bucket::setOwnership(const int64_t id, const bmodel::Ownership ownership, const bmodel::ProvisioningState state) {
    Transactions::exec("upstream::Bucket::setOwnership", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_bucket_set_ownership"},
                 pqxx::params{id, bmodel::to_string(ownership), bmodel::to_string(state)});
    });
}

void Bucket::setRegion(const int64_t id, const std::string& region) {
    Transactions::exec("upstream::Bucket::setRegion", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_bucket_set_region"}, pqxx::params{id, region});
    });
}

BucketModel Bucket::protect(const storage::upstream::BucketIdentity& id, const std::optional<std::string>& region,
                            const std::optional<uint32_t> userId, const std::optional<std::string>& userName,
                            const std::string& reason) {
    const auto& account = requireAccount(id);
    return Transactions::exec("upstream::Bucket::protect", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_protect"},
                                  pqxx::params{id.provider, account, id.bucket, region, userId, userName, reason});
        return BucketModel(res.one_row_ref());
    });
}

std::optional<BucketModel> Bucket::unprotect(const storage::upstream::BucketIdentity& id) {
    const auto& account = requireAccount(id);
    return Transactions::exec("upstream::Bucket::unprotect", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_unprotect"}, pqxx::params{id.provider, account, id.bucket});
        return firstRow(res);
    });
}

std::vector<BucketModel> Bucket::listStaleProvisioning(const std::chrono::seconds olderThan) {
    return Transactions::exec("upstream::Bucket::listStaleProvisioning", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_bucket_list_stale_provisioning"},
                                  pqxx::params{static_cast<double>(olderThan.count())});
        return rowsAs<BucketModel>(res);
    });
}

}
