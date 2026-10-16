#include "storage/upstream/Guard.hpp"

#include "db/Transactions.hpp"
#include "log/Registry.hpp"
#include "vault/model/APIKey.hpp"

#include <paths.h>

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace vh::storage::upstream::guard {

namespace {

// provider + '\n' + bucket → the protected accounts for that name. Keyed by name first so an identity with an
// unknown account can fail closed with one lookup.
struct State {
    std::shared_mutex mutex;
    std::unordered_map<std::string, std::unordered_set<std::string>> locked;
    bool loaded = false;
    bool testOverride = false;
    std::atomic<uint64_t> epoch{0};
};

State& state() {
    static State s;
    return s;
}

std::string nameKey(const std::string& provider, const std::string& bucket) { return provider + '\n' + bucket; }

void ensureLoaded() {
    auto& s = state();
    {
        std::shared_lock lock(s.mutex);
        if (s.loaded) return;
    }
    // DB-free unit tests build S3 controllers too; their protection set is whatever setForTesting()/reload() put
    // there. The daemon loads at startup, and a failed load there throws instead of reading "unprotected".
    if (paths::testMode) return;
    reload();
}

}

void reload() {
    auto& s = state();
    {
        std::shared_lock lock(s.mutex);
        if (s.testOverride) return;
    }
    std::unordered_map<std::string, std::unordered_set<std::string>> next;
    db::Transactions::exec("upstream::guard::reload", [&](pqxx::work& txn) {
        const auto res = txn.exec("SELECT provider, account_ref, bucket FROM upstream_bucket WHERE is_protected");
        for (const auto& row : res)
            next[nameKey(row["provider"].as<std::string>(), row["bucket"].as<std::string>())]
                .insert(row["account_ref"].as<std::string>());
    });
    {
        std::unique_lock lock(s.mutex);
        s.locked = std::move(next);
        s.loaded = true;
    }
    s.epoch.fetch_add(1, std::memory_order_acq_rel);
}

uint64_t epoch() { return state().epoch.load(std::memory_order_acquire); }

bool isProtected(const BucketIdentity& id) {
    if (id.bucket.empty()) return false;   // account-level calls (ListBuckets, credential probes)
    // A failed load must not open the gate: callers see the DB error, never "unprotected".
    ensureLoaded();
    auto& s = state();
    std::shared_lock lock(s.mutex);
    const auto it = s.locked.find(nameKey(id.provider, id.bucket));
    if (it == s.locked.end()) return false;
    if (!id.account_ref) return true;      // unknown account: any lock on this name applies (fail closed)
    return it->second.contains(*id.account_ref);
}

void require(const BucketIdentity& id) {
    if (isProtected(id)) throw BucketProtected(id);
}

void require(const vault::model::APIKey& key, const std::string& bucket) { require(identityFor(key, bucket)); }

void setForTesting(const std::vector<BucketIdentity>& protectedIds) {
    auto& s = state();
    {
        std::unique_lock lock(s.mutex);
        s.locked.clear();
        for (const auto& id : protectedIds) s.locked[nameKey(id.provider, id.bucket)].insert(id.account_ref.value_or(""));
        s.loaded = true;
        s.testOverride = true;
    }
    s.epoch.fetch_add(1, std::memory_order_acq_rel);
}

void clearForTesting() {
    auto& s = state();
    {
        std::unique_lock lock(s.mutex);
        s.locked.clear();
        s.loaded = false;
        s.testOverride = false;
    }
    s.epoch.fetch_add(1, std::memory_order_acq_rel);
}

}
