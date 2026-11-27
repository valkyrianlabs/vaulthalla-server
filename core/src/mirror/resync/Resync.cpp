#include "mirror/resync/Resync.hpp"

#include "audit/Trail.hpp"
#include "db/Transactions.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Resync.hpp"
#include "log/Registry.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/submit/Submit.hpp"
#include "ops/Error.hpp"
#include "paths.h"

#include <fmt/format.h>
#include <pqxx/pqxx>

#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <system_error>

namespace vh::mirror::resync {

namespace {

namespace mq = vh::db::query::mirror;
using json = nlohmann::json;

[[noreturn]] void resyncNotFound() { throw vh::ops::NotFound("Not found"); }

std::string resyncVaultUid(const json& payload) {
    const auto it = payload.find("vault_uid");
    if (it == payload.end() || !it->is_string() || it->get<std::string>().size() > 64)
        throw vh::ops::Invalid("vault_uid is the vault's uid");
    return it->get<std::string>();
}

}

json serveResync(const uint32_t callerPeerId, const json& payload) {
    if (!payload.is_object()) throw vh::ops::Invalid("the payload is an object");
    const auto mv = mq::MirrorVaults::byVaultUid(resyncVaultUid(payload));
    // A `starting` row of this very mirror is a resync that did not complete: asked again, it runs again.
    if (!mv || mv->peer_id != callerPeerId || mv->role != "core") resyncNotFound();
    if (mv->state == "paused")
        throw vh::ops::Refused("mirror_paused", "following this vault is paused on its core server; resume it there first");
    const auto vaultId = mv->vault_id;
    const auto term = mv->term + 1;
    if (!mq::Resync::prepareCoreRebaseline(vaultId, callerPeerId)) resyncNotFound();
    mq::MirrorVault fresh;
    try {
        fresh = mq::MirrorVaults::startCore(vaultId, callerPeerId, term);
    } catch (const std::exception& e) {
        mq::Resync::restoreCoreRow(vaultId, callerPeerId, mv->term, e.what());
        vh::log::Registry::sync()->warn("[MirrorResync] Vault {}: the baseline could not be taken again: {}", vaultId,
                                        e.what());
        throw vh::ops::Refused("mirror_resync_failed",
                               std::string("the core could not take its tree again now; ask again: ") + e.what());
    }
    mq::Resync::recordCoreResync(vaultId);
    const auto entries = fresh.baseline_digest ? fresh.baseline_digest->entries : 0;
    audit::record({.action = "mirror.resync", .outcome = audit::Outcome::Info, .vault_id = vaultId,
                   .details = {{"peer", callerPeerId}, {"side", "core"}, {"term", fresh.term},
                               {"was", mv->state}, {"stop_reason", mv->stop_reason.value_or("")},
                               {"entries", entries}}},
                  fmt::format("[mirror] linked server {} started its copy of vault {} over: the baseline was taken again "
                              "in term {} ({} entries)",
                              callerPeerId, vaultId, fresh.term, entries));
    json baseline = nullptr;
    if (fresh.baseline) baseline = {{"term", fresh.baseline->term}, {"seq", fresh.baseline->seq}};
    return {{"term", fresh.term}, {"baseline", baseline}, {"entries", entries}};
}

json start(const uint32_t vaultId, const uint32_t actorId, const std::string& actorName,
           vh::mirror::follow::Transport& transport) {
    const auto mv = mq::MirrorVaults::get(vaultId);
    if (!mv || mv->role != "mirror")
        throw vh::ops::NotFound("vault " + std::to_string(vaultId) + " is not held here as another server's copy");
    if (mv->state != "diverged" && mv->state != "expired" && mv->state != "stopped")
        throw vh::ops::Refused("mirror_not_stopped",
                               "the copy is " + mv->state + "; only a diverged, expired or stopped copy starts over");
    const auto vaultUid = mq::MirrorVaults::vaultUidOf(vaultId);
    if (!vaultUid) throw vh::ops::NotFound("no such vault");
    if (!transport.connected(mv->peer_id))
        throw vh::ops::Refused("mirror_core_unreachable", "the link to the vault's core server is down; try again later");
    const auto answer = transport.request(mv->peer_id, "peer.mirror.resync", {{"vault_uid", *vaultUid}});
    if (!answer) throw vh::ops::Refused("mirror_core_unreachable", "the vault's core server did not answer; try again");
    if (!answer->ok) {
        if (answer->code == "not_found")
            throw vh::ops::Refused("mirror_core_gone",
                                   "the core server no longer mirrors this vault with this server; end or detach it");
        throw vh::ops::Refused(answer->code.empty() ? std::string("mirror_resync_refused") : answer->code,
                               answer->error.empty() ? std::string("the core refused to start over") : answer->error);
    }

    // The core holds a new baseline: this server starts its copy over. What was pending here can no longer be
    // confirmed as it is: held, with its bytes.
    const auto held = vh::mirror::submit::holdAllPending(
        vaultId, "mirror_resync", "the copy started over from the core's tree before the core confirmed the change");
    {
        std::scoped_lock local(vh::mirror::submit::vaultMutex(vaultId));
        vh::db::Transactions::exec("mirror::resync start", [&](pqxx::work& txn) {
            if (!mq::Resync::resetMirror(txn, vaultId, actorId)) resyncNotFound();
        });
    }
    vh::mirror::access::reload();
    vh::mirror::follow::Follower::instance()->wake(vaultId);
    const auto term = answer->data.value("term", uint64_t{0});
    audit::record({.action = "mirror.resync", .actor_id = actorId, .actor = actorName, .vault_id = vaultId,
                   .details = {{"peer", mv->peer_id}, {"side", "mirror"}, {"was", mv->state},
                               {"stop_reason", mv->stop_reason.value_or("")}, {"term", term}, {"held", held}}},
                  fmt::format("[mirror] {} started vault {}'s copy over from its core, linked server {} (it was {}; {} "
                              "pending change(s) kept as held)",
                              actorName.empty() ? std::string("someone") : actorName, vaultId, mv->peer_id, mv->state,
                              held));
    return {{"vault_id", vaultId}, {"state", "live"}, {"copy_finished", false}, {"term", term}, {"held", held},
            {"entries", answer->data.value("entries", int64_t{0})}};
}

bool scrub(const uint32_t vaultId) {
    mq::ScrubFinding found;
    {
        // On a mirror the applier and a change made here hold it: neither is half done while the scrub reads.
        std::scoped_lock local(vh::mirror::submit::vaultMutex(vaultId));
        found = mq::Resync::scrub(vaultId);
    }
    if (found.differences == 0 && !found.digestDrift) return true;
    json first = json::array();
    for (const auto& d : found.first)
        first.push_back({{"uid", d.uid}, {"tables", d.tables ? json(*d.tables) : json(nullptr)},
                         {"recorded", d.recorded ? json(*d.recorded) : json(nullptr)}});
    const json detail{{"differences", found.differences}, {"digest_drift", found.digestDrift}, {"first", first},
                      {"why", "the vault's entries are not what this server recorded for them"}};
    (void)mq::MirrorVaults::stop(vaultId, "diverged", "mirror_scrub_mismatch", detail);
    audit::record({.action = "mirror.scrub", .outcome = audit::Outcome::Info, .vault_id = vaultId,
                   .details = {{"differences", found.differences}, {"digest_drift", found.digestDrift}}},
                  fmt::format("[mirror] vault {}: the scrub found {} entr{} that differ from what was recorded{}; the "
                              "vault stopped as diverged",
                              vaultId, found.differences, found.differences == 1 ? "y" : "ies",
                              found.digestDrift ? " and a running digest that drifted" : ""),
                  spdlog::level::warn);
    return false;
}

bool scrubNowForTesting() {
    if (!vh::paths::testMode) return false;
    const char* dir = std::getenv("VH_TEST_FAULT_DIR");
    if (!dir) return false;
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(dir) / "mirror-scrub-now", ec);
}

std::size_t scrubDue(const std::chrono::hours every) {
    std::size_t n = 0;
    for (const auto vaultId : mq::Resync::scrubDue(every)) {
        try {
            (void)scrub(vaultId);
            ++n;
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorResync] Vault {}: the scrub failed: {}", vaultId, e.what());
        }
    }
    return n;
}

}
