#include "ops/VaultLayout.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "db/query/vault/LayoutMigration.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "runtime/Deps.hpp"
#include "storage/BucketCapability.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <ctime>

namespace vh::ops::vault_layout {

namespace vault_layout_detail {

using Q = db::query::vault::LayoutMigration;
namespace lm = vault::layout;

void requireView(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin() || actor->encryptionKeysPerms().canView()) return;
    throw Denied("only super admins or users with the view encryption keys permission can inspect bucket layouts");
}

void requireMigrate(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin() || actor->encryptionKeysPerms().canRotate()) return;
    throw Denied("only super admins or users with the rotate encryption keys permission can migrate a bucket layout");
}

std::shared_ptr<vault::model::Vault> liveVault(const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(vaultId));
    return vault;
}

std::shared_ptr<storage::CloudEngine> cloudEngineFor(const unsigned int vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    return manager ? std::dynamic_pointer_cast<storage::CloudEngine>(manager->getEngine(vaultId)) : nullptr;
}

void count(ItemCounts& c, const lm::ItemState state) {
    switch (state) {
    case lm::ItemState::Pending: ++c.pending; break;
    case lm::ItemState::Verified: ++c.verified; break;
    case lm::ItemState::Superseded: ++c.superseded; break;
    case lm::ItemState::Skipped: ++c.skipped; break;
    case lm::ItemState::Failed: ++c.failed; break;
    }
}

Status statusOf(const vault::model::Vault& v) {
    Status s{.vault_id = v.id, .vault_name = v.name, .layout = "local", .migration = std::nullopt, .versions = {},
             .markers = {}, .backlog = {}, .current = {}, .legacy_listed = 0, .legacy_deleted = 0, .blocked = {},
             .blocked_total = 0};
    if (const auto* s3 = dynamic_cast<const vault::model::S3Vault*>(&v))
        s.layout = std::string(vault::model::to_string(s3->storage_layout));
    s.migration = Q::get(v.id);
    if (!s.migration) return s;
    for (const auto& it : Q::items(v.id)) {
        switch (it.kind) {
        case lm::ItemKind::Version: count(s.versions, it.state); break;
        case lm::ItemKind::Marker: count(s.markers, it.state); break;
        case lm::ItemKind::Backlog: count(s.backlog, it.state); break;
        case lm::ItemKind::Current: count(s.current, it.state); break;
        case lm::ItemKind::Index: break;
        }
        if (!it.legacy()) continue;
        if (it.cleanup_state == std::optional<std::string>("deleted")) {
            ++s.legacy_deleted;
            continue;
        }
        if (it.state != lm::ItemState::Superseded || !it.reason || !it.reason->starts_with("gone")) ++s.legacy_listed;
        const bool kept = it.state == lm::ItemState::Skipped || it.cleanup_state == std::optional<std::string>("blocked");
        if (!kept) continue;
        ++s.blocked_total;
        if (s.blocked.size() >= 200) continue;
        s.blocked.push_back({.key = *it.legacy_key, .version_id = it.legacy_version_id,
                             .delete_marker = it.kind == lm::ItemKind::Marker, .size = it.legacy_size.value_or(0),
                             .last_modified = it.legacy_last_modified,
                             .reason = it.cleanup_reason.value_or(it.reason.value_or("kept")),
                             .retain_until = it.retain_until});
    }
    return s;
}

nlohmann::json countsJson(const ItemCounts& c) {
    return {{"pending", c.pending}, {"verified", c.verified}, {"superseded", c.superseded}, {"skipped", c.skipped},
            {"failed", c.failed}};
}

std::string utc(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    return std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm) ? std::string(buf) : std::string("?");
}

nlohmann::json optTime(const std::optional<std::time_t>& t) { return t ? nlohmann::json(*t) : nlohmann::json(nullptr); }

nlohmann::json planJson(const lm::CleanupPlan& p) {
    nlohmann::json kept = nlohmann::json::array();
    for (const auto& e : p.kept) kept.push_back(lm::toJson(e));
    nlohmann::json deletable = nlohmann::json::array();
    for (const auto& e : p.deletable_entries) deletable.push_back(lm::toJson(e));
    return {{"complete_listing", p.complete_listing}, {"deletable", p.deletable},
            {"deletable_bytes", p.deletable_bytes},   {"deletable_markers", p.deletable_markers},
            {"oldest", optTime(p.oldest)},            {"newest", optTime(p.newest)},
            {"already_gone", p.already_gone},         {"kept", kept},
            {"deletable_entries", deletable}};
}

}

std::vector<Status> status(const Actor& actor, const std::optional<unsigned int> vaultId) {
    namespace d = vault_layout_detail;
    d::requireView(actor);
    std::vector<Status> out;
    if (vaultId) {
        out.push_back(d::statusOf(*d::liveVault(*vaultId)));
        return out;
    }
    for (const auto& vault : db::query::vault::Vault::listLiveVaults())
        if (std::dynamic_pointer_cast<vault::model::S3Vault>(vault)) out.push_back(d::statusOf(*vault));
    return out;
}

nlohmann::json toJson(const Status& s) {
    namespace d = vault_layout_detail;
    nlohmann::json migration = nullptr;
    if (s.migration) {
        const auto& m = *s.migration;
        migration = {{"state", std::string(vault::layout::to_string(m.state))},
                     {"started_at", m.started_at},
                     {"started_by", m.started_by ? nlohmann::json(*m.started_by) : nlohmann::json(nullptr)},
                     {"attempts", m.attempts},
                     {"versioned", m.versioned ? nlohmann::json(*m.versioned) : nlohmann::json(nullptr)},
                     {"wait_days", m.wait_days},
                     {"accept_unpriced", m.accept_unpriced},
                     {"verified_at", d::optTime(m.verified_at)},
                     {"cutover_at", d::optTime(m.cutover_at)},
                     {"cleanup_after", d::optTime(m.cleanup_after)},
                     {"manifest_verified_at", d::optTime(m.manifest_verified_at)},
                     {"cleanup_confirmed_at", d::optTime(m.cleanup_confirmed_at)},
                     {"cleanup_run_at", d::optTime(m.cleanup_run_at)},
                     {"completed_at", d::optTime(m.completed_at)},
                     {"estimate", m.estimate ? *m.estimate : nlohmann::json(nullptr)},
                     {"usage", m.usage ? *m.usage : nlohmann::json(nullptr)},
                     {"last_error", m.last_error ? nlohmann::json(*m.last_error) : nlohmann::json(nullptr)}};
    }
    nlohmann::json blocked = nlohmann::json::array();
    for (const auto& e : s.blocked) blocked.push_back(vault::layout::toJson(e));
    return {{"vault_id", s.vault_id},
            {"vault_name", s.vault_name},
            {"layout", s.layout},
            {"migration", migration},
            {"items", {{"versions", d::countsJson(s.versions)}, {"delete_markers", d::countsJson(s.markers)},
                       {"backlog", d::countsJson(s.backlog)}, {"current", d::countsJson(s.current)}}},
            {"legacy_remaining", s.legacy_listed},
            {"legacy_deleted", s.legacy_deleted},
            {"blocked", blocked},
            {"blocked_total", s.blocked_total}};
}

Status start(const Actor& actor, const StartRequest& request) {
    namespace d = vault_layout_detail;
    d::requireMigrate(actor);
    const auto vault = d::liveVault(request.vault_id);
    const auto engine = d::cloudEngineFor(vault->id);
    if (!engine) throw Conflict("vault '" + vault->name + "' is not an S3 or R2 vault loaded on this host");
    if (const auto existing = d::Q::get(vault->id); existing && existing->state != vault::layout::State::Failed)
        throw Conflict(fmt::format("vault '{}' already has a layout migration ({})", vault->name,
                                   vault::layout::to_string(existing->state)));
    try {
        // The capability as the bucket answers now, not as a probe once recorded it (spec 01 §6.1 step 5).
        (void)storage::bucket_capability::reprobe(vault->id, *engine->s3Controller());
        vault::layout::requirePreconditions(*engine);
    } catch (const std::exception& e) {
        throw Conflict(fmt::format("vault '{}' can't migrate now: {}", vault->name, e.what()));
    }
    auth::stepup::require(auth::stepup::Family::Keys, "vault.layout.migrate:" + std::to_string(vault->id));
    const auto waitDays = config::Registry::get().vaults.layout_migration.cleanup_wait_days;
    const auto row = d::Q::start(vault->id, actor->id, waitDays, request.accept_unpriced);
    if (!row) throw Conflict("vault '" + vault->name + "' already has a layout migration");
    vh::audit::record({.action = "vault.layout.migrate", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .vault_id = vault->id,
                       .details = {{"attempt", static_cast<int64_t>(row->attempts) + 1},
                                   {"wait_days", static_cast<int64_t>(waitDays)},
                                   {"accept_unpriced", request.accept_unpriced}}},
                      fmt::format("[ops::vault_layout] {} started the bucket layout migration of vault {} "
                                  "(path_v0 -> opaque_v1; legacy objects kept {} day(s) after the cutover)",
                                  actor->name(), vault->id, waitDays));
    return d::statusOf(*vault);
}

CleanupAnswer cleanup(const Actor& actor, const CleanupRequest& request) {
    namespace d = vault_layout_detail;
    using vault::layout::State;
    d::requireMigrate(actor);
    const auto vault = d::liveVault(request.vault_id);
    const auto engine = d::cloudEngineFor(vault->id);
    if (!engine) throw Conflict("vault '" + vault->name + "' is not loaded on this host");
    const auto row = d::Q::get(vault->id);
    if (!row || vault::layout::beforeCutover(row->state))
        throw Conflict("vault '" + vault->name + "' has not cut over to opaque_v1; there is nothing to clean up yet");
    if (row->state == State::Complete) throw Conflict("vault '" + vault->name + "' has no legacy objects left");

    CleanupAnswer out;
    out.cleanup_after = row->cleanup_after;
    try {
        out.plan = vault::layout::planCleanup(*engine, *row);
    } catch (const std::exception& e) {
        throw Conflict(std::string("the bucket could not be listed completely: ") + e.what());
    }
    if (!request.confirm) return out;

    out.dry_run = false;
    if (*request.confirm != vault->name)
        throw Invalid("the confirmation must be the vault's name exactly ('" + vault->name + "')");
    if (!row->cleanup_after || std::time(nullptr) < *row->cleanup_after)
        throw Conflict(fmt::format("the legacy objects stay untouched until the waiting period ends ({})",
                                   row->cleanup_after ? vault_layout_detail::utc(*row->cleanup_after)
                                                      : std::string("unknown")));
    if (!row->manifest_verified_at)
        throw Conflict("the bucket's encrypted manifest has not been verified yet; nothing is deleted before it is");
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    if (const auto key = engine->s3ApiKey(); key && s3)
        if (storage::upstream::guard::isProtected(storage::upstream::identityFor(*key, s3->bucket)))
            throw Denied("bucket '" + s3->bucket + "' has a protection lock: nothing in it is deleted");
    auth::stepup::require(auth::stepup::Family::DataDestroy, "vault.layout.cleanup:" + std::to_string(vault->id));
    d::Q::confirmCleanup(vault->id, actor->id);
    out.started = true;
    vh::audit::record({.action = "vault.layout.cleanup", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .vault_id = vault->id,
                       .details = {{"deletable", static_cast<int64_t>(out.plan.deletable)},
                                   {"deletable_bytes", static_cast<int64_t>(out.plan.deletable_bytes)},
                                   {"kept", static_cast<int64_t>(out.plan.kept.size())}}},
                      fmt::format("[ops::vault_layout] {} confirmed the cleanup of vault {}: {} legacy version(s) "
                                  "({} bytes) are deleted by version id, {} stay",
                                  actor->name(), vault->id, out.plan.deletable, out.plan.deletable_bytes,
                                  out.plan.kept.size()));
    return out;
}

nlohmann::json toJson(const CleanupAnswer& a) {
    namespace d = vault_layout_detail;
    return {{"dry_run", a.dry_run}, {"started", a.started}, {"cleanup_after", d::optTime(a.cleanup_after)},
            {"plan", d::planJson(a.plan)}};
}

}
