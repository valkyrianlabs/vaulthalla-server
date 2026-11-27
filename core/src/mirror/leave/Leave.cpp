#include "mirror/leave/Leave.hpp"

#include "audit/Trail.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/Pending.hpp"
#include "db/query/mirror/Start.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/tree_apply/TreeApply.hpp"
#include "log/Registry.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/versions/Versions.hpp"
#include "ops/Error.hpp"
#include "rbac/Mirrored.hpp"
#include "recovery/local/Versions.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/uid.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <filesystem>
#include <mutex>

namespace vh::mirror::leave {

namespace mirror_leave_detail {

namespace mq = vh::db::query::mirror;

const json& field(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key)) throw ops::Invalid(std::string(key) + " is required");
    return payload.at(key);
}

uint64_t number(const json& v, const char* key) {
    if (!v.is_number_unsigned() && !(v.is_number_integer() && v.get<int64_t>() >= 0))
        throw ops::Invalid(std::string(key) + " must be a non-negative integer");
    const auto n = v.get<uint64_t>();
    if (n > (uint64_t{1} << 62)) throw ops::Invalid(std::string(key) + " is out of range");
    return n;
}

std::string vaultUuidOf(const json& payload) {
    const auto& v = field(payload, "vault_uid");
    if (!v.is_string() || v.get<std::string>().size() != 26) throw ops::Invalid("vault_uid is not a uid (26 base32 symbols)");
    const auto uid = vl::keykit::fromBase32(v.get<std::string>());
    if (!uid) throw ops::Invalid("vault_uid is not a uid (26 base32 symbols)");
    return vh::crypto::id::toUuid(*uid);
}

// A write applied here whose bytes the file still holds is an ordinary change now; one the file no longer holds (the
// core's state came back over it while it waited) stays the person's: a held change with its pending bytes.
mq::DetachChanges changesOf(const uint32_t vaultId) {
    mq::DetachChanges out;
    for (const auto& p : mq::Pending::list(vaultId)) {
        const bool write = p.op == "write" && p.args.value("size", uint64_t{0}) > 0;
        if (!write) {
            out.dropped.push_back(p.id);
            continue;
        }
        std::error_code ec;
        const bool bytes = std::filesystem::exists(vh::mirror::submit::contents::pendingBlob(vaultId, p.id), ec);
        std::optional<std::string> now;
        if (const auto fileId = mq::SealedObjects::fileIdOf(vaultId, vh::crypto::id::fromUuid(p.entry_uid)))
            now = mq::SealedObjects::generationOf(*fileId);
        if (!bytes || (now && *now == p.args.value("generation", std::string{}))) {
            out.dropped.push_back(p.id);
            continue;
        }
        mq::HeldChange h;
        h.vault_id = vaultId;
        h.kind = "held";
        h.request_id = p.request_id;
        h.op = p.op;
        h.entry_uid = p.entry_uid;
        h.args = p.args;
        h.actor = p.actor;
        h.reason_code = "mirror_detached";
        h.reason = "the vault was detached before its core confirmed this version; the file holds another one";
        if (const auto where = vh::fs::tree_apply::locate(vaultId, p.entry_uid)) h.path = where->path;
        out.held.emplace_back(p.id, std::move(h));
    }
    return out;
}

std::string positionText(const mq::Position& p) { return fmt::format("({}, {})", p.term, p.seq); }

}

Preview preview(const uint32_t vaultId) {
    namespace mq = vh::db::query::mirror;
    const auto row = mq::MirrorVaults::get(vaultId);
    if (!row || (row->role != "mirror" && row->role != "orphaned"))
        throw ops::Refused("mirror_not_held", "vault " + std::to_string(vaultId) +
                                                  " is not held here as another server's copy: there is nothing to detach");
    const auto vault = vh::db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw ops::NotFound("no vault with ID " + std::to_string(vaultId));
    Preview p;
    p.vault_id = vaultId;
    p.vault_name = vault->name;
    p.role = row->role;
    p.state = row->state;
    p.stop_reason = row->stop_reason;
    p.peer = vh::db::query::peer::Peers::byId(row->peer_id);
    if (const auto f = vh::mirror::access::facts(vaultId)) p.link_up = f->link_up;
    p.copy_finished = row->copy_finished;
    p.copy_cursor = row->copy_cursor;
    p.baseline_rows = row->baseline_rows;
    p.applied = row->position();
    p.confirmed = row->acked;
    if (row->state == "diverged") p.digest_matched = false;
    else if (row->acked) p.digest_matched = true;
    p.pending_changes = mq::Pending::list(vaultId).size();
    p.held_changes = mq::Pending::heldChanges(vaultId).size();
    p.missing = mq::MirrorDetach::missing(vaultId);
    p.owner_id = vault->owner_id;
    return p;
}

Detached detach(const uint32_t vaultId, const uint32_t ownerId, const std::optional<uint32_t> actorId,
                const std::string& actorName) {
    using namespace mirror_leave_detail;
    Detached out;
    mq::DetachOutcome done;
    {
        // The start's steps and every change of the vault here (the applier's pages and groups, a person's change)
        // wait for this, and this for them: nothing of the vault moves while it becomes local.
        std::scoped_lock step(vh::mirror::start::stepMutex());
        std::scoped_lock local(vh::mirror::submit::vaultMutex(vaultId));
        out.before = preview(vaultId);
        const auto changes = changesOf(vaultId);
        const bool tell = out.before.role == "mirror" && out.before.peer && !out.before.peer->revoked();
        done = mq::MirrorDetach::detach({.vault_id = vaultId, .owner_id = ownerId, .actor_id = actorId,
                                         .changes = changes, .tell_core = tell});
        out.core_told_later = tell;
    }
    // Before anything else serves the vault: no gate, no backstop, the owner's ordinary resolution.
    vh::rbac::mirrored::reload();
    vh::mirror::access::reload();
    for (const auto& [pendingId, heldId] : done.held)
        vh::mirror::submit::contents::moveBlob(vh::mirror::submit::contents::pendingBlob(vaultId, pendingId),
                                               vh::mirror::submit::contents::heldBlob(vaultId, heldId));
    for (const auto pendingId : done.dropped)
        vh::mirror::submit::contents::dropBlob(vh::mirror::submit::contents::pendingBlob(vaultId, pendingId));
    vh::recovery::local::invalidatePolicy(vaultId);
    vh::mirror::versions::invalidate();   // its versions belong to the local vault now (its own policy)
    try {
        if (const auto& manager = runtime::Deps::get().storageManager) manager->reloadEngine(vaultId);
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[mirror] vault {} was detached but its engine did not reload: {}", vaultId,
                                        e.what());
    }
    out.record = done.record;
    out.owner_id = ownerId;
    out.missing = done.missing;
    out.pending_held = done.held.size();
    out.pending_kept = done.dropped.size();

    const auto& b = out.before;
    audit::record({.action = "mirror.detach", .actor_id = actorId, .actor = actorName, .vault_id = vaultId,
                   .details = {{"peer", done.was.peer_id},
                               {"role", b.role},
                               {"state", b.state},
                               {"fork", {{"term", b.applied.term}, {"seq", b.applied.seq}}},
                               {"confirmed", b.confirmed ? json{{"term", b.confirmed->term}, {"seq", b.confirmed->seq}}
                                                         : json(nullptr)},
                               {"digest_matched", b.digest_matched ? json(*b.digest_matched) : json(nullptr)},
                               {"missing", out.missing},
                               {"pending_kept", out.pending_kept},
                               {"pending_held", out.pending_held},
                               {"owner", ownerId},
                               {"previous_owner", done.previous_owner ? json(*done.previous_owner) : json(nullptr)},
                               {"core_told", out.core_told_later ? "when_reachable" : "no"}}},
                  fmt::format("[mirror] {} detached vault {} from linked server {}: it is a standalone vault here now "
                              "(fork point {}, {} file(s) whose contents never arrived, owner {}); it shares its uid and "
                              "keys with the original until the re-key pass runs",
                              actorName.empty() ? std::string("this server") : actorName, vaultId, done.was.peer_id,
                              positionText(b.applied), out.missing, ownerId),
                  spdlog::level::warn);
    vh::mirror::start::Service::instance()->wake();
    return out;
}

json detachedPayload(const vh::db::query::mirror::Offer& offer) {
    namespace mq = vh::db::query::mirror;
    json at{{"term", 0}, {"seq", 0}};
    uint64_t missing = 0;
    if (offer.vault_id)
        if (const auto rec = mq::MirrorDetach::forVault(*offer.vault_id)) {
            at = {{"term", rec->fork.term}, {"seq", rec->fork.seq}};
            missing = rec->missing;
        }
    return {{"offer_uid", offer.offer_uid}, {"vault_uid", vl::keykit::toBase32(offer.vault_uid)}, {"at", at},
            {"missing", missing}};
}

json detachedReceived(const vh::peer::Record& from, const json& payload) {
    using namespace mirror_leave_detail;
    const auto vaultUuid = vaultUuidOf(payload);
    mq::Position at{};
    if (payload.contains("at") && payload.at("at").is_object())
        at = {number(field(payload.at("at"), "term"), "term"), number(field(payload.at("at"), "seq"), "seq")};
    const auto missing = payload.contains("missing") ? number(payload.at("missing"), "missing") : 0;

    const auto vaultId = mq::MirrorStart::vaultWithUid(vh::crypto::id::fromUuid(vaultUuid));
    if (!vaultId) return {{"recorded", false}};
    const auto row = mq::MirrorVaults::get(*vaultId);
    const auto latest = mq::MirrorStart::latestOffer(vh::crypto::id::fromUuid(vaultUuid), "core");
    const bool mirroredWithIt = row && row->role == "core" && row->peer_id == from.id;
    // Only the server this one mirrored the vault with (now or last) can say it left with a copy of it.
    if (!mirroredWithIt && !(latest && latest->peer_id == from.id)) return {{"recorded", false}};
    if (mirroredWithIt)
        (void)vh::mirror::start::cancelOnCore(*vaultId, "peer_detached", false, false, std::nullopt, "");
    if (const auto now = mq::MirrorStart::latestOffer(vh::crypto::id::fromUuid(vaultUuid), "core"); now && now->peer_id == from.id)
        (void)mq::MirrorStart::recordCopyOutcome(now->id, "detached");
    const auto rec = mq::MirrorDetach::recordCore(*vaultId, from.id, at, missing);
    audit::record({.action = "mirror.detached", .outcome = audit::Outcome::Info, .vault_id = *vaultId,
                   .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "core"},
                               {"fork", {{"term", at.term}, {"seq", at.seq}}}, {"missing", missing},
                               {"ended_here", mirroredWithIt}}},
                  fmt::format("[mirror] linked server {} detached its copy of vault {} (its fork point {}): the "
                              "mirror is ended here; this server's vault is unaffected. Both servers hold the vault's "
                              "keys: a key rotation here is recommended",
                              from.node_id, *vaultId, positionText(at)),
                  spdlog::level::warn);
    return {{"recorded", true}, {"record", rec.id}};
}

std::optional<std::pair<std::string, std::string>> offerRefusal(const std::string& vaultUuid, const uint32_t peerId) {
    const auto rec = vh::db::query::mirror::MirrorDetach::between(vaultUuid, peerId);
    if (!rec) return std::nullopt;
    return std::make_pair(
        std::string("mirror_detached_copy"),
        std::string(rec->side == "mirror"
                        ? "this vault was detached from that server, which holds the original: the two share the "
                          "vault's uid and keys, so they can't mirror it with each other until the re-key pass runs"
                        : "that server detached its copy of this vault: the two share the vault's uid and keys, so they "
                          "can't mirror it with each other until it runs the re-key pass"));
}

json toJson(const Preview& p) {
    json missing = json::array();
    for (const auto& m : p.missing)
        missing.push_back({{"file_id", m.file_id}, {"uid", m.uid}, {"path", m.path}, {"size_bytes", m.size_bytes},
                           {"state", m.state},
                           {"last_error", m.last_error ? json(*m.last_error) : json(nullptr)}});
    const auto pos = [](const vh::db::query::mirror::Position& x) { return json{{"term", x.term}, {"seq", x.seq}}; };
    return {{"vault_id", p.vault_id},
            {"vault_name", p.vault_name},
            {"role", p.role},
            {"state", p.state},
            {"stop_reason", p.stop_reason ? json(*p.stop_reason) : json(nullptr)},
            {"peer", p.peer ? json{{"id", p.peer->id}, {"node_id", p.peer->node_id}, {"name", p.peer->name},
                                   {"revoked", p.peer->revoked()}}
                            : json(nullptr)},
            {"link_up", p.link_up},
            {"first_copy", {{"finished", p.copy_finished}, {"entries_copied", p.copy_cursor},
                            {"entries_total", p.baseline_rows}}},
            {"applied", pos(p.applied)},
            {"confirmed", p.confirmed ? pos(*p.confirmed) : json(nullptr)},
            {"digest_matched", p.digest_matched ? json(*p.digest_matched) : json(nullptr)},
            {"pending_changes", p.pending_changes},
            {"held_changes", p.held_changes},
            {"missing_count", p.missing.size()},
            {"missing", std::move(missing)},
            {"owner_id", p.owner_id}};
}

json toJson(const vh::db::query::mirror::DetachRecord& r) {
    return {{"id", r.id},
            {"side", r.side},
            {"vault_id", r.vault_id},
            {"peer_id", r.peer_id},
            {"fork", {{"term", r.fork.term}, {"seq", r.fork.seq}}},
            {"digest_matched", r.digest_matched ? json(*r.digest_matched) : json(nullptr)},
            {"was_state", r.was_state ? json(*r.was_state) : json(nullptr)},
            {"missing", r.missing},
            {"owner_id", r.owner_id ? json(*r.owner_id) : json(nullptr)},
            {"detached_by", r.detached_by ? json(*r.detached_by) : json(nullptr)},
            {"detached_at", static_cast<int64_t>(r.detached_at)},
            {"rekeyed_at", r.rekeyed_at ? json(static_cast<int64_t>(*r.rekeyed_at)) : json(nullptr)},
            {"rekey_recommended", !r.rekeyed_at}};
}

json toJson(const Detached& d) {
    auto before = toJson(d.before);
    return {{"vault_id", d.before.vault_id},
            {"owner_id", d.owner_id},
            {"missing", d.missing},
            {"pending_kept", d.pending_kept},
            {"pending_held", d.pending_held},
            {"core_told", d.core_told_later ? "when_reachable" : "no"},
            {"record", toJson(d.record)},
            {"before", std::move(before)}};
}

}
