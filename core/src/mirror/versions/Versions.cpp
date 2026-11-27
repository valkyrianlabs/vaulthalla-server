#include "mirror/versions/Versions.hpp"

#include "db/query/mirror/Versions.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>

namespace vh::mirror::versions {

namespace mirror_versions_detail {

using Map = std::map<uint32_t, vh::recovery::LocalVersioningPolicy>;

std::atomic<bool>& loaded() {
    static std::atomic<bool> v{false};
    return v;
}
// When the rows were read (steady clock, ns): read again after kReloadAfter, so a role a planned switch changed (a
// mirror that became the core keeps its setting dormant; a core that became the mirror again uses it) is seen without
// a hook in the switch.
std::atomic<int64_t>& loadedAt() {
    static std::atomic<int64_t> v{0};
    return v;
}
constexpr std::chrono::seconds kReloadAfter{10};

std::atomic<bool>& anyOn() {
    static std::atomic<bool> v{false};
    return v;
}
std::mutex& mapMutex() {
    static std::mutex m;
    return m;
}
std::shared_ptr<const Map>& published() {
    static std::shared_ptr<const Map> m = std::make_shared<Map>();
    return m;
}

vh::recovery::LocalVersioningPolicy policyOf(const nlohmann::json& j) {
    vh::recovery::LocalVersioningPolicy p;
    if (!j.is_object()) return p;
    p.enabled = j.value("enabled", false);
    if (j.contains("keep_last") && j.at("keep_last").is_number_unsigned()) p.keep_last = j.at("keep_last").get<unsigned>();
    if (j.contains("max_age_days") && j.at("max_age_days").is_number_unsigned())
        p.max_age_days = j.at("max_age_days").get<unsigned>();
    if (j.contains("quota_bytes") && j.at("quota_bytes").is_number_unsigned())
        p.quota_bytes = j.at("quota_bytes").get<uint64_t>();
    return p;
}

nlohmann::json jsonOf(const vh::recovery::LocalVersioningPolicy& p) {
    nlohmann::json j{{"enabled", p.enabled}};
    if (p.keep_last) j["keep_last"] = *p.keep_last;
    if (p.max_age_days) j["max_age_days"] = *p.max_age_days;
    if (p.quota_bytes) j["quota_bytes"] = *p.quota_bytes;
    return j;
}

void load() {
    auto map = std::make_shared<Map>();
    for (const auto& [vaultId, j] : vh::db::query::mirror::MirrorVersions::all())
        if (const auto p = policyOf(j); p.enabled) map->emplace(vaultId, p);
    std::scoped_lock lock(mapMutex());
    anyOn().store(!map->empty(), std::memory_order_release);
    published() = std::move(map);
    loadedAt().store(std::chrono::steady_clock::now().time_since_epoch().count(), std::memory_order_release);
    loaded().store(true, std::memory_order_release);
}

}

Setting get(const uint32_t vaultId) {
    using namespace mirror_versions_detail;
    Setting s;
    const auto row = vh::db::query::mirror::MirrorVersions::get(vaultId);
    if (!row) return s;
    s.policy = policyOf(row->policy);
    s.set_by = row->set_by;
    s.set_at = row->set_at;
    return s;
}

Setting set(const uint32_t vaultId, const vh::recovery::LocalVersioningPatch& patch, const std::optional<uint32_t> by) {
    using namespace mirror_versions_detail;
    auto next = get(vaultId).policy;
    if (patch.enabled) next.enabled = *patch.enabled;
    const auto limit = [](auto& field, const auto& given) {
        if (!given) return;
        if (*given == 0) field.reset();
        else field = *given;
    };
    limit(next.keep_last, patch.keep_last);
    limit(next.max_age_days, patch.max_age_days);
    limit(next.quota_bytes, patch.quota_bytes);
    if (next.enabled && !patch.keep_last && !next.keep_last) next.keep_last = kDefaultKeepLast;
    if (next.enabled && !patch.max_age_days && !next.max_age_days) next.max_age_days = kDefaultMaxAgeDays;
    if (next.enabled && !next.keep_last && !next.max_age_days && !next.quota_bytes)
        throw ops::Invalid("keep at least one limit (keep_last, max_age_days or quota_bytes): a mirror never "
                           "accumulates versions without a bound");
    if (next.keep_last && *next.keep_last > 10000) throw ops::Invalid("keep_last is at most 10000");
    if (!vh::db::query::mirror::MirrorVersions::set(vaultId, jsonOf(next), by))
        throw ops::Conflict("vault " + std::to_string(vaultId) + " is not held here as another server's mirror");
    invalidate();
    return get(vaultId);
}

std::optional<vh::recovery::LocalVersioningPolicy> policyFor(const uint32_t vaultId) {
    using namespace mirror_versions_detail;
    const auto age = std::chrono::steady_clock::now().time_since_epoch().count() - loadedAt().load(std::memory_order_acquire);
    if (!loaded().load(std::memory_order_acquire) ||
        age > std::chrono::duration_cast<std::chrono::steady_clock::duration>(kReloadAfter).count()) {
        try {
            load();
        } catch (const std::exception&) {
            return std::nullopt;   // asked again next time; a version not kept never fails the apply
        }
    }
    if (!anyOn().load(std::memory_order_acquire)) return std::nullopt;
    std::shared_ptr<const Map> map;
    {
        std::scoped_lock lock(mapMutex());
        map = published();
    }
    if (const auto it = map->find(vaultId); it != map->end()) return it->second;
    return std::nullopt;
}

void invalidate() noexcept { mirror_versions_detail::loaded().store(false, std::memory_order_release); }

}
