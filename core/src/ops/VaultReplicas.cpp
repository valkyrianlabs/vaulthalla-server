#include "ops/VaultReplicas.hpp"

#include "audit/Trail.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "identities/User.hpp"
#include "ops/CloudStorage.hpp"
#include "ops/Error.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "sync/vault_manifest/Replicas.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <vl/keykit/uid.hpp>

#include <algorithm>

namespace vh::ops::vault_replicas {

namespace vault_replicas_detail {

namespace mf = sync::manifest;

void requireAllowed(const Actor& actor, const Channel channel, const std::string_view what) {
    sync::replicas::requireExperimental(what);
    if (!actor) throw Denied(std::string(what) + ": no caller");
    if (channel == Channel::Agent || channel == Channel::Console)
        throw Denied(std::string(what) + ": only from the local CLI or a paired device, never an agent or a browser "
                                         "session");
    if (!actor->isSuperAdmin()) throw Denied(std::string(what) + ": super admins only");
}

std::shared_ptr<storage::CloudEngine> manifestEngine(const unsigned int vaultId, const std::string_view what) {
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = std::dynamic_pointer_cast<storage::CloudEngine>(manager ? manager->getEngine(vaultId) : nullptr);
    if (!engine) throw NotFound(fmt::format("{}: vault {} is not an S3 or R2 vault running on this server", what, vaultId));
    if (!engine->opaqueLayout())
        throw Conflict(fmt::format("{}: vault {} has no encrypted manifest (opaque_v1); only such a vault is replicated",
                                   what, vaultId));
    return engine;
}

bool named(const std::vector<std::string>& writers, const std::string& node) {
    return std::ranges::find(writers, node) != writers.end();
}

// Publishes the writers change now and checks the recorded root shows it. A publish that fails drops the change: the
// vault stays as it was, and nothing half-done is carried by later passes.
uint64_t publishChange(const std::shared_ptr<storage::CloudEngine>& engine, const unsigned int vaultId,
                       const mf::WritersChange& change, const std::string_view what) {
    db::query::sync::Manifest::setWritersChange(vaultId, change);
    try {
        engine->publishRemoteIndexManifest();
    } catch (const std::exception& e) {
        db::query::sync::Manifest::setWritersChange(vaultId, std::nullopt);
        throw Conflict(fmt::format("{}: the manifest root could not be published ({}); nothing changed", what, e.what()));
    }
    const auto state = db::query::sync::Manifest::state(vaultId);
    if (!change.satisfiedBy(state.writers) || !state.epoch) {
        db::query::sync::Manifest::setWritersChange(vaultId, std::nullopt);
        throw Conflict(fmt::format("{}: the published root does not show the change; nothing changed", what));
    }
    return *state.epoch;
}

}  // namespace vault_replicas_detail

vault_recover::Result join(const Actor& actor, vault_recover::Request request, const Channel channel) {
    vault_replicas_detail::requireAllowed(actor, channel, "vault join");
    request.join = true;
    return vault_recover::recover(actor, request, channel);
}

LeaveResult leave(const Actor& actor, const unsigned int vaultId, const bool deleteLocal, const Channel channel) {
    using namespace vault_replicas_detail;
    constexpr std::string_view what = "vault leave";
    requireAllowed(actor, channel, what);
    const auto engine = manifestEngine(vaultId, what);
    const auto self = db::query::device::Devices::nodeId();
    const auto state = db::query::sync::Manifest::state(vaultId);
    LeaveResult r;
    r.vault_id = vaultId;
    if (named(state.writers, self)) {
        if (state.writers.size() < 2)
            throw Refused("last_writer", fmt::format("vault {} has no other writer: the last one can't leave; delete it "
                                                     "(vh vault delete) or detach it (vh vault remote detach) as a solo "
                                                     "vault",
                                                     vaultId));
        r.published_epoch = publishChange(engine, vaultId, {mf::WritersChange::Kind::Remove, self}, what);
    } else {
        r.note = "this server was no longer one of the vault's writers; only its copy here changes";
    }
    // Stop syncing: a pass would be refused anyway (superseded), but nothing should try.
    vaults::SyncPatch off;
    off.enabled = false;
    (void)vaults::updateSync(actor, vaultId, off);
    // The cloud's replica set (the join contract, 6), when this server is linked.
    if (engine->vault && engine->vault->uid) {
        std::string error;
        if (!cloud_storage::reportLeft(vl::keykit::toBase32(*engine->vault->uid), error))
            r.note += (r.note.empty() ? "" : "; ") +
                      ("Vaulthalla Cloud wasn't told (" + error + "): run vh vault leave again to tell it");
    }
    if (deleteLocal) {
        (void)vaults::remove(actor, {.id = vaultId, .now = true, .delete_upstream = false, .confirm_now = true,
                                     .accept_key_loss = true});
        r.deleted_local = true;
    }
    audit::record({.action = "vault.leave", .outcome = audit::Outcome::Success, .actor_id = actor->id,
                   .actor = actor->name(), .vault_id = vaultId,
                   .details = {{"published_epoch", r.published_epoch ? nlohmann::json(*r.published_epoch) : nlohmann::json(nullptr)},
                               {"delete_local", deleteLocal}}},
                  fmt::format("[ops::vault_replicas] {} took this server out of vault {}'s writers{}", actor->name(),
                              vaultId, deleteLocal ? " and deleted its copy here (the bucket is untouched)" : ""),
                  spdlog::level::warn);
    return r;
}

RemoveResult removeReplica(const Actor& actor, const unsigned int vaultId, const std::string& node,
                           const Channel channel) {
    using namespace vault_replicas_detail;
    constexpr std::string_view what = "vault replica remove";
    requireAllowed(actor, channel, what);
    const auto engine = manifestEngine(vaultId, what);
    const auto self = db::query::device::Devices::nodeId();
    if (node == self) throw Invalid("vault replica remove: that is this server; use vh vault leave");
    const auto state = db::query::sync::Manifest::state(vaultId);
    if (!named(state.writers, self))
        throw Refused("not_a_writer", fmt::format("this server is not one of vault {}'s writers", vaultId));
    if (!named(state.writers, node))
        throw NotFound(fmt::format("vault replica remove: {} is not one of vault {}'s writers", node, vaultId));
    RemoveResult r;
    r.vault_id = vaultId;
    r.node = node;
    r.published_epoch = publishChange(engine, vaultId, {mf::WritersChange::Kind::Remove, node}, what);
    r.solo = !sync::replicas::replicated(vaultId);
    audit::record({.action = "vault.replica.remove", .outcome = audit::Outcome::Success, .actor_id = actor->id,
                   .actor = actor->name(), .vault_id = vaultId,
                   .details = {{"node", node}, {"published_epoch", r.published_epoch}, {"solo", r.solo}}},
                  fmt::format("[ops::vault_replicas] {} removed writer {} from vault {}", actor->name(), node, vaultId),
                  spdlog::level::warn);
    return r;
}

nlohmann::json toJson(const LeaveResult& r) {
    return {{"vault_id", r.vault_id},
            {"published_epoch", r.published_epoch ? nlohmann::json(*r.published_epoch) : nlohmann::json(nullptr)},
            {"deleted_local", r.deleted_local},
            {"note", r.note.empty() ? nlohmann::json(nullptr) : nlohmann::json(r.note)}};
}

nlohmann::json toJson(const RemoveResult& r) {
    return {{"vault_id", r.vault_id}, {"node", r.node}, {"published_epoch", r.published_epoch}, {"solo", r.solo}};
}

}
