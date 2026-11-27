#include "mirror/switching/Switch.hpp"

#include "audit/Trail.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "log/Registry.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Local.hpp"
#include "ops/Error.hpp"
#include "rbac/permission/vault/Filesystem.hpp"

#include <fmt/format.h>

#include <atomic>
#include <ctime>
#include <map>
#include <mutex>
#include <thread>

namespace vh::mirror::switching {

namespace {

namespace mq = vh::db::query::mirror;
using json = nlohmann::json;
using SteadyClock = std::chrono::steady_clock;

std::atomic<int64_t>& switchTimeoutOverride() {
    static std::atomic<int64_t> seconds{0};
    return seconds;
}

std::atomic<bool>& switchNoTellPause() {
    static std::atomic<bool> none{false};
    return none;
}

// When each decision was last told (so a mirror that does not answer is asked every kTellEvery, not every pass).
std::mutex& switchToldMutex() {
    static std::mutex m;
    return m;
}

std::map<uint64_t, SteadyClock::time_point>& switchToldAt() {
    static std::map<uint64_t, SteadyClock::time_point> at;
    return at;
}

// One step of a switch at a time in this process (the follower's pass, a test).
std::mutex& switchStepMutex() {
    static std::mutex m;
    return m;
}

[[noreturn]] void switchNotFound() { throw vh::ops::NotFound("Not found"); }

std::string switchText(const json& payload, const char* key, const std::size_t max = 64) {
    const auto it = payload.find(key);
    if (it == payload.end() || !it->is_string() || it->get<std::string>().empty() || it->get<std::string>().size() > max)
        throw vh::ops::Invalid(std::string(key) + " is required");
    return it->get<std::string>();
}

uint64_t switchCount(const json& payload, const char* key) {
    const auto it = payload.find(key);
    if (it == payload.end() || !(it->is_number_unsigned() || (it->is_number_integer() && it->get<int64_t>() >= 0)))
        throw vh::ops::Invalid(std::string(key) + " must be a non-negative integer");
    return it->get<uint64_t>();
}

vh::mirror::Digest switchDigestOf(const json& payload) {
    try {
        return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(switchText(payload, "digest")),
                                             static_cast<int64_t>(switchCount(payload, "entries")));
    } catch (const std::invalid_argument&) {
        throw vh::ops::Invalid("digest is 64 hex digits");
    }
}

json switchPosition(const uint64_t term, const uint64_t seq) { return {{"term", term}, {"seq", seq}}; }

// The person who asked, as the wire carries them: their home server's node id, their id there and a display name.
json switchByJson(const mq::Switch& sw) {
    if (!sw.asked_by) return nullptr;
    return {{"node", sw.asked_by->node}, {"id", sw.asked_by->id}, {"name", sw.asked_by_name}, {"on", sw.asked_on}};
}

mq::SwitchAsked switchAskedFrom(const json& payload, const std::string& on, const std::string& peerNode) {
    mq::SwitchAsked asked{.on = on};
    const auto by = payload.find("by");
    if (by == payload.end() || !by->is_object()) return asked;
    if (by->contains("id") && (*by)["id"].is_number_unsigned()) {
        const auto node = by->contains("node") && (*by)["node"].is_string() ? (*by)["node"].get<std::string>() : peerNode;
        asked.by = mq::Account{.node = node.substr(0, 64), .id = (*by)["id"].get<uint32_t>()};
    }
    if (by->contains("name") && (*by)["name"].is_string()) asked.name = (*by)["name"].get<std::string>().substr(0, 255);
    if (by->contains("on") && (*by)["on"].is_string() && ((*by)["on"] == "core" || (*by)["on"] == "mirror"))
        asked.on = (*by)["on"].get<std::string>();
    return asked;
}

// A role as an audit detail: its name ("" for none).
std::string switchRoleName(const json& role) {
    return role.is_object() ? role.value("role_name", std::string{}) : std::string{};
}

// The role this server gives the linked server on the vault (its policy: the per-vault assignment or the link's
// default; null for none or "no access").
json switchPeerRole(const uint32_t peerId, const uint32_t vaultId) {
    try {
        return vh::mirror::start::grantFor(peerId, vaultId);
    } catch (const std::exception&) {
        return nullptr;
    }
}

std::string switchPeerNode(const uint32_t peerId) {
    const auto peer = vh::db::query::peer::Peers::byId(peerId);
    return peer ? peer->node_id : std::string{};
}

void switchAudit(const mq::Switch& sw, const std::string& outcome, const std::string& message,
                 const json& extra = json::object()) {
    json details{{"switch_id", sw.switch_id}, {"peer", sw.peer_id}, {"side", sw.side}, {"outcome", outcome},
                 {"term", sw.term}, {"asked_on", sw.asked_on}};
    if (sw.seq) details["seq"] = *sw.seq;
    if (sw.reason) details["reason"] = *sw.reason;
    if (sw.asked_by) {
        details["asked_by_node"] = sw.asked_by->node;
        details["asked_by_id"] = sw.asked_by->id;
    }
    for (const auto& [k, v] : extra.items()) details[k] = v;
    std::optional<uint32_t> actorId;
    if (sw.asked_by && sw.asked_by->node == vh::db::query::device::Devices::nodeId()) actorId = sw.asked_by->id;
    audit::record({.action = "mirror.switch",
                   .outcome = outcome == "abandoned" ? audit::Outcome::Failure : audit::Outcome::Info,
                   .actor_id = actorId,
                   .actor = sw.asked_by_name,
                   .vault_id = sw.vault_id,
                   .details = details},
                  message, outcome == "abandoned" ? spdlog::level::warn : spdlog::level::info);
}

// Abandons the core's switch with a reason, audits it and tells the mirror soon.
bool switchAbandon(const mq::Switch& sw, const std::string& reason, const json& detail) {
    if (!mq::Switches::abandonCore(sw.id, reason, detail)) return false;
    const auto now = mq::Switches::get(sw.id).value_or(sw);
    switchAudit(now, "abandoned",
                fmt::format("[mirror] the switch of vault {} with linked server {} was abandoned ({}): nothing changed, "
                            "this server is still its core",
                            sw.vault_id, sw.peer_id, reason));
    return true;
}

// Tells the mirror the core's decision. True once it was told.
bool switchTell(const mq::Switch& sw, vh::mirror::follow::Transport& transport) {
    if (!transport.connected(sw.peer_id)) return false;
    {
        std::scoped_lock lock(switchToldMutex());
        auto& at = switchToldAt()[sw.id];
        if (!switchNoTellPause().load() && at != SteadyClock::time_point{} && SteadyClock::now() - at < kTellEvery)
            return false;
        at = SteadyClock::now();
    }
    const auto uid = mq::MirrorVaults::vaultUidOf(sw.vault_id);
    if (!uid) return false;
    json payload{{"vault_uid", *uid}, {"switch_id", sw.switch_id}, {"outcome", sw.phase}};
    if (sw.reason) payload["reason"] = *sw.reason;
    const auto a = transport.request(sw.peer_id, "peer.mirror.switch.commit", payload);
    if (!a) return false;
    if (sw.phase == "switched" && !a->ok) {
        // The mirror cannot take the role it prepared for (it left, or its row moved): this server stays read-only as
        // the mirror of a core that is not there; told again later (known limit: design doc).
        vh::log::Registry::sync()->warn("[MirrorSwitch] Vault {}: linked server {} refused the switch it prepared: {} {}",
                                        sw.vault_id, sw.peer_id, a->code, a->error);
        return false;
    }
    (void)mq::Switches::told(sw.id);
    {
        std::scoped_lock lock(switchToldMutex());
        switchToldAt().erase(sw.id);
    }
    if (sw.phase == "switched") {
        const auto peerRole = a->data.contains("peer_role") ? a->data["peer_role"] : json(nullptr);
        mq::Switches::noteDetail(sw.id, {{"peer_role", peerRole}, {"new_term", a->data.value("term", sw.term + 1)},
                                         {"accepted_no_access", sw.accept_no_access && !peerRole.is_object()}});
        switchAudit(sw, "switched",
                    fmt::format("[mirror] vault {}: linked server {} is its core now (term {}); this server is its mirror "
                                "and follows it",
                                sw.vault_id, sw.peer_id, sw.term + 1),
                    {{"peer_role", switchRoleName(peerRole)}, {"peer_access", accessWord(peerRole)}});
        vh::mirror::follow::Follower::instance()->wake(sw.vault_id);
    }
    return true;
}

// The freeze and what follows it at once (Switch.hpp begin).
mq::Switch switchBegin(const uint32_t vaultId, const mq::SwitchAsked& asked,
                       const std::optional<std::string>& switchId, const bool acceptNoAccess) {
    auto sw = mq::Switches::freeze(vaultId, asked, timeout(), switchId, acceptNoAccess);
    // Every writer that may have changed the vault before the freeze was visible to it: waited for before the
    // position is taken (each commits, and the sequencer numbers it, or rolls back).
    const auto writers = mq::Switches::writersNow();
    mq::Switches::recordWriters(sw.id, writers);
    sw.writers = writers;
    switchAudit(sw, "begun",
                fmt::format("[mirror] the switch of vault {} with linked server {} began (asked on the {}): the vault is "
                            "read-only on both servers until it ends",
                            vaultId, sw.peer_id, sw.asked_on));
    vh::mirror::follow::Follower::instance()->wake(vaultId);
    return sw;
}

}

std::chrono::seconds timeout() {
    const auto s = switchTimeoutOverride().load();
    return s > 0 ? std::chrono::seconds(s) : kTimeout;
}

void setTimeoutForTesting(const std::chrono::seconds t) { switchTimeoutOverride().store(t.count()); }

void setTellPauseForTesting(const bool none) { switchNoTellPause().store(none); }

bool following(const uint32_t vaultId) { return mq::Switches::following(vaultId); }

// ---- the core ----------------------------------------------------------------------------------------------------------

mq::Switch begin(const uint32_t vaultId, const mq::SwitchAsked& asked, vh::mirror::follow::Transport& transport,
                 const bool acceptNoAccess) {
    const auto mv = mq::MirrorVaults::get(vaultId);
    if (!mv || mv->role != "core") throw vh::ops::NotFound("this server is not the vault's core");
    if (!transport.connected(mv->peer_id))
        throw vh::ops::Refused("peer_link_down", "the link to the vault's mirror is down; a switch needs it up");
    return switchBegin(vaultId, asked, std::nullopt, acceptNoAccess);
}

json serveRequest(const uint32_t callerPeerId, const json& payload) {
    if (!payload.is_object()) throw vh::ops::Invalid("the payload is an object");
    const auto mv = mq::MirrorVaults::byVaultUid(switchText(payload, "vault_uid"));
    if (!mv || mv->peer_id != callerPeerId || mv->role != "core" || mv->state == "starting") switchNotFound();
    auto asked = switchAskedFrom(payload, "mirror", switchPeerNode(callerPeerId));
    asked.on = "mirror";
    if (asked.by) asked.by->node = switchPeerNode(callerPeerId);   // the mirror's own person: its node, never a field
    const bool acceptNoAccess = payload.contains("accept_no_access") && payload["accept_no_access"].is_boolean() &&
                                payload["accept_no_access"].get<bool>();
    const auto sw = switchBegin(mv->vault_id, asked, std::nullopt, acceptNoAccess);
    return {{"switch_id", sw.switch_id}, {"term", sw.term}};
}

bool advance(const uint64_t id, vh::mirror::follow::Transport& transport) {
    std::scoped_lock step(switchStepMutex());
    auto sw = mq::Switches::get(id);
    if (!sw) return false;
    if (sw->side != "core") {
        // The mirror waits for the core's decision; a request the core never prepared ends at its deadline.
        return mq::Switches::expireRequested() > 0;
    }
    if (sw->open()) {
        const auto mv = mq::MirrorVaults::get(sw->vault_id);
        if (!mv || mv->role != "core" || mv->state != "switching")
            return switchAbandon(*sw, "mirror_switch_interrupted",
                                 {{"why", "the vault's mirror record changed meanwhile"},
                                  {"state", mv ? json(mv->state) : json(nullptr)},
                                  {"stop_reason", mv && mv->stop_reason ? json(*mv->stop_reason) : json(nullptr)}});
        if (std::time(nullptr) >= sw->deadline) {
            json detail{{"why", "the mirror was not ready in time"}, {"last_answer", sw->detail}};
            return switchAbandon(*sw, "mirror_switch_timeout", detail);
        }
        if (sw->phase == "draining") {
            if (mq::Switches::anyRunning(sw->writers)) return false;
            (void)vh::db::query::mirror::Log::sequence(sw->vault_id);
            const auto d = mq::Switches::drained(id);
            if (!d.sw) return false;   // a row still waits for its number: the next pass
            sw = d.sw;
            vh::log::Registry::sync()->info("[MirrorSwitch] Vault {}: the switch's last change is ({}, {}), digest {}",
                                            sw->vault_id, sw->term, sw->seq.value_or(0),
                                            sw->digest ? sw->digest->hex() : std::string("-"));
        }
        if (sw->phase == "preparing") {
            if (!transport.connected(sw->peer_id)) return false;
            const auto uid = mq::MirrorVaults::vaultUidOf(sw->vault_id);
            if (!uid || !sw->seq || !sw->digest) return false;
            json payload{{"vault_uid", *uid},        {"switch_id", sw->switch_id},      {"term", sw->term},
                         {"seq", *sw->seq},          {"digest", sw->digest->hex()},     {"entries", sw->digest->entries},
                         {"by", switchByJson(*sw)}};
            const auto a = transport.request(sw->peer_id, "peer.mirror.switch.prepare", payload);
            if (!a) return false;
            if (!a->ok)
                return switchAbandon(*sw, a->code.empty() ? std::string("mirror_switch_refused") : a->code,
                                     {{"why", a->error}, {"by", "the mirror"}});
            mq::Switches::noteDetail(id, a->data);
            if (!a->data.value("ready", false)) return false;
            // The old core keeps the vault only through the new core's policy for it: none, and nobody here could read
            // the vault after the switch. Not without the person's word.
            const auto peerRole = a->data.contains("peer_role") ? a->data["peer_role"] : json(nullptr);
            if (!peerRole.is_object() && !sw->accept_no_access)
                return switchAbandon(
                    *sw, "mirror_switch_no_role",
                    {{"why", "after the switch this server would hold no role on the vault: its people could not read it "
                             "here; set this server's role on the other server first (vh peer policy set <this server> "
                             "<role> there), or switch with --accept-no-access"},
                     {"peer_role", nullptr}});
            // The decision, durable before anything is told.
            if (const auto why = mq::Switches::commitCore(id); !why.empty())
                return switchAbandon(*sw, "mirror_switch_moved", {{"why", why}});
            sw = mq::Switches::get(id);
            if (!sw) return true;
            vh::log::Registry::sync()->info("[MirrorSwitch] Vault {}: switched; this server is its mirror in term {} "
                                            "once linked server {} confirms",
                                            sw->vault_id, sw->term + 1, sw->peer_id);
        }
    }
    if (sw->notify) return switchTell(*sw, transport);
    return false;
}

std::size_t tick(vh::mirror::follow::Transport& transport) {
    std::size_t n = 0;
    (void)mq::Switches::expireRequested();
    for (const auto& sw : mq::Switches::active()) {
        if (sw.side != "core") continue;
        try {
            if (advance(sw.id, transport)) ++n;
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorSwitch] Vault {}: the switch's step failed: {}", sw.vault_id,
                                            e.what());
        }
    }
    return n;
}

// ---- the mirror --------------------------------------------------------------------------------------------------------

json servePrepare(const uint32_t callerPeerId, const json& payload) {
    if (!payload.is_object()) throw vh::ops::Invalid("the payload is an object");
    const auto mv = mq::MirrorVaults::byVaultUid(switchText(payload, "vault_uid"));
    if (!mv || mv->peer_id != callerPeerId || mv->role != "mirror") switchNotFound();
    const auto switchId = switchText(payload, "switch_id", 36);
    const auto term = switchCount(payload, "term");
    const auto seq = switchCount(payload, "seq");
    const auto digest = switchDigestOf(payload);
    const auto vaultId = mv->vault_id;
    // The role the core will hold here once this server is its core (this server's policy for it).
    const auto peerRole = switchPeerRole(callerPeerId, mv->vault_id);
    const auto waiting = [&](const std::string& why) {
        const auto now = mq::MirrorVaults::get(vaultId);
        return json{{"ready", false}, {"waiting", why},
                    {"at", now ? switchPosition(now->term, now->last_seq) : json(nullptr)},
                    {"digest", now ? json(now->digest.hex()) : json(nullptr)},
                    {"entries", now ? json(now->digest.entries) : json(nullptr)}, {"peer_role", peerRole}};
    };

    // Under the vault's local-change lock (never waited for on a link thread): a change being made here is either done
    // (its pending row counted below) or begins after the freeze is published and is refused.
    std::unique_lock local(vh::mirror::submit::vaultMutex(vaultId), std::try_to_lock);
    if (!local.owns_lock()) return waiting("busy");
    mq::Switch sw;
    try {
        sw = mq::Switches::prepareMirror(vaultId, callerPeerId, switchId, term, seq, digest,
                                         switchAskedFrom(payload, "core", switchPeerNode(callerPeerId)), timeout());
    } catch (const vh::ops::Conflict&) {
        return waiting("busy");
    }
    if (sw.phase == "prepared")
        return {{"ready", true}, {"at", switchPosition(term, seq)}, {"digest", digest.hex()}, {"entries", digest.entries},
                {"peer_role", peerRole}};

    const auto refuse = [&](const std::string& code, const std::string& text) {
        (void)mq::Switches::abandonMirror(sw.id, code, {{"why", text}});
        local.unlock();
        throw vh::ops::Refused(code, text);
    };
    const auto obstacles = mq::Switches::obstacles(vaultId);
    if (obstacles.pending > 0 || obstacles.dirty > 0)
        refuse("mirror_pending_changes",
               fmt::format("{} change(s) made on the mirror still wait for the core; switch once they are confirmed",
                           obstacles.pending));
    if (obstacles.contents > 0)
        refuse("mirror_contents_missing",
               fmt::format("the contents of {} file(s) have not arrived on the mirror yet; switch once they have",
                           obstacles.contents));
    const auto now = mq::MirrorVaults::get(vaultId);
    if (!now) switchNotFound();
    const mq::Position at{term, seq};
    if (now->position() < at) {
        local.unlock();
        vh::mirror::follow::Follower::instance()->wake(vaultId);
        return waiting("applying");
    }
    if (now->position() != at)
        refuse("mirror_ahead", fmt::format("the mirror applied ({}, {}), past the core's ({}, {})", now->term,
                                           now->last_seq, term, seq));
    if (now->digest != digest)
        refuse("mirror_digest_mismatch", "the mirror's digest at the core's last change is not the core's");
    (void)mq::Switches::markPrepared(sw.id);
    vh::log::Registry::sync()->info("[MirrorSwitch] Vault {}: prepared to take the core role at ({}, {}); waiting for "
                                    "linked server {}'s decision",
                                    vaultId, term, seq, callerPeerId);
    return {{"ready", true}, {"at", switchPosition(term, seq)}, {"digest", digest.hex()}, {"entries", digest.entries},
            {"peer_role", peerRole}};
}

json serveCommit(const uint32_t callerPeerId, const json& payload) {
    if (!payload.is_object()) throw vh::ops::Invalid("the payload is an object");
    const auto mv = mq::MirrorVaults::byVaultUid(switchText(payload, "vault_uid"));
    if (!mv || mv->peer_id != callerPeerId) switchNotFound();
    const auto switchId = switchText(payload, "switch_id", 36);
    const auto outcome = switchText(payload, "outcome", 16);
    const auto sw = mq::Switches::bySwitchId(switchId, "mirror");

    if (outcome == "abandoned") {
        if (sw && sw->open()) {
            const auto reason = payload.contains("reason") && payload["reason"].is_string()
                                    ? payload["reason"].get<std::string>().substr(0, 64)
                                    : std::string("mirror_switch_abandoned");
            if (mq::Switches::abandonMirror(sw->id, reason, {{"why", "the core abandoned the switch"}})) {
                const auto now = mq::Switches::get(sw->id).value_or(*sw);
                switchAudit(now, "abandoned",
                            fmt::format("[mirror] linked server {} abandoned the switch of vault {} ({}): nothing changed, "
                                        "this server is still its mirror",
                                        callerPeerId, mv->vault_id, reason));
                vh::mirror::follow::Follower::instance()->wake(mv->vault_id);
            }
        }
        return {{"outcome", "abandoned"}};
    }
    if (outcome != "switched") throw vh::ops::Invalid("outcome is switched or abandoned");

    // Told again after it took the role: the same answer.
    if (mv->role == "core" && sw && sw->phase == "switched")
        return {{"outcome", "switched"}, {"term", mv->term}, {"peer_role", switchPeerRole(callerPeerId, mv->vault_id)}};
    if (mv->role != "mirror") switchNotFound();
    if (!sw) throw vh::ops::Refused("mirror_not_prepared", "this server never prepared that switch");
    if (const auto why = mq::Switches::becomeCore(sw->id); !why.empty())
        throw vh::ops::Refused("mirror_not_prepared", why);
    const auto now = mq::MirrorVaults::get(mv->vault_id);
    const auto term = now ? now->term : sw->term + 1;
    const auto peerRole = switchPeerRole(callerPeerId, mv->vault_id);
    mq::Switches::noteDetail(sw->id, {{"peer_role", peerRole}, {"new_term", term}});
    switchAudit(mq::Switches::get(sw->id).value_or(*sw), "switched",
                fmt::format("[mirror] vault {}: this server is its core now (term {}); linked server {} is its mirror",
                            mv->vault_id, term, callerPeerId),
                {{"peer_role", switchRoleName(peerRole)}, {"peer_access", accessWord(peerRole)}});
    // The grant goes to the new mirror, and the old core's role here is the ceiling of what it may submit.
    vh::mirror::start::Service::instance()->wake();
    return {{"outcome", "switched"}, {"term", term}, {"peer_role", peerRole}};
}

// ---- a person's request ------------------------------------------------------------------------------------------------

json request(const uint32_t vaultId, const uint32_t actorId, const std::string& actorName,
             vh::mirror::follow::Transport& transport, const std::chrono::milliseconds wait, const bool acceptNoAccess) {
    const auto mv = mq::MirrorVaults::get(vaultId);
    if (!mv) throw vh::ops::NotFound("vault " + std::to_string(vaultId) + " is not mirrored");
    if (mv->role == "orphaned")
        throw vh::ops::Refused("mirror_orphaned", "this copy's core ended the mirror; there is no core to switch with");
    const mq::SwitchAsked asked{.on = mv->role == "core" ? "core" : "mirror",
                                .by = mq::Account{.node = vh::db::query::device::Devices::nodeId(), .id = actorId},
                                .name = actorName};
    mq::Switch sw;
    if (mv->role == "core") {
        sw = begin(vaultId, asked, transport, acceptNoAccess);
    } else {
        if (mv->state != "live")
            throw vh::ops::Refused("mirror_not_live", "the copy is " + mv->state + " here; a switch needs it live");
        if (!mv->copy_finished)
            throw vh::ops::Refused("mirror_first_copy", "the first copy of the vault has not finished here");
        const auto obstacles = mq::Switches::obstacles(vaultId);
        if (obstacles.pending > 0 || obstacles.dirty > 0)
            throw vh::ops::Refused("mirror_pending_changes",
                                   fmt::format("{} change(s) made here still wait for the core; switch once they are "
                                               "confirmed (vh mirror info)",
                                               obstacles.pending));
        if (obstacles.contents > 0)
            throw vh::ops::Refused("mirror_contents_missing",
                                   fmt::format("the contents of {} file(s) have not arrived here yet; switch once they "
                                               "have",
                                               obstacles.contents));
        // Asked here, the role the core would hold here afterwards is known here: none, and refused before the core is
        // asked (the core checks it again with the mirror's prepare).
        if (!acceptNoAccess && !switchPeerRole(mv->peer_id, vaultId).is_object())
            throw vh::ops::Refused("mirror_switch_no_role",
                                   "after the switch the other server would hold no role on the vault here: its people "
                                   "could not read it there; give it one first (vh peer policy set <server> <role>), or "
                                   "switch with --accept-no-access");
        if (!transport.connected(mv->peer_id))
            throw vh::ops::Refused("peer_link_down", "the link to the vault's core is down; a switch needs it up");
        const auto uid = mq::MirrorVaults::vaultUidOf(vaultId);
        if (!uid) throw vh::ops::NotFound("no such vault");
        const auto a = transport.request(mv->peer_id, "peer.mirror.switch.request",
                                         {{"vault_uid", *uid}, {"by", {{"id", actorId}, {"name", actorName}}},
                                          {"accept_no_access", acceptNoAccess}});
        if (!a) throw vh::ops::Refused("mirror_core_unreachable", "the vault's core did not answer; try again");
        if (!a->ok) {
            if (a->code == "not_found")
                throw vh::ops::Refused("mirror_core_gone", "the core no longer mirrors this vault with this server");
            throw vh::ops::Refused(a->code.empty() ? std::string("mirror_switch_refused") : a->code,
                                   a->error.empty() ? std::string("the core refused the switch") : a->error);
        }
        const auto switchId = a->data.value("switch_id", std::string{});
        if (switchId.empty()) throw vh::ops::Refused("mirror_switch_refused", "the core named no switch");
        sw = mq::Switches::requested(vaultId, mv->peer_id, switchId, mv->term, asked,
                                     timeout() + std::chrono::seconds(15), acceptNoAccess);
        switchAudit(sw, "asked",
                    fmt::format("[mirror] {} asked linked server {} to hand vault {}'s core role to this server",
                                actorName.empty() ? std::string("someone") : actorName, mv->peer_id, vaultId));
    }

    // The decision comes from the follower's pass (the core's steps, the mirror's commit handler).
    const auto until = SteadyClock::now() + wait;
    auto now = mq::Switches::bySwitchId(sw.switch_id, sw.side).value_or(sw);
    while (SteadyClock::now() < until && (now.open() || now.notify)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        now = mq::Switches::bySwitchId(sw.switch_id, sw.side).value_or(now);
    }
    return outcome(vaultId, now.switch_id, now.side);
}

json outcome(const uint32_t vaultId, const std::string& switchId, const std::string& side) {
    const auto found = mq::Switches::bySwitchId(switchId, side);
    if (!found) throw vh::ops::NotFound("no such switch here");
    const auto& now = *found;
    const auto row = mq::MirrorVaults::get(vaultId);
    json out = toJson(now);
    out["vault_id"] = vaultId;
    out["outcome"] = now.open() ? std::string("running") : now.phase;
    out["role"] = row ? json(row->role) : json(nullptr);
    out["role_term"] = row ? json(row->term) : json(nullptr);
    // The old core's role on the vault on the new core (from the prepare's answer, the commit's or this server's own
    // policy), and what it allows.
    const auto peerRole = now.detail.contains("peer_role") ? now.detail["peer_role"] : json(nullptr);
    out["peer_role"] = peerRole.is_object() ? peerRole : json(nullptr);
    out["peer_access"] = accessWord(peerRole);
    return out;
}

std::string accessWord(const json& role) {
    if (!role.is_object() || !role.contains("files") || !role["files"].is_number_unsigned()) return "none";
    namespace pv = vh::rbac::permission::vault;
    const pv::fs::Files files(static_cast<pv::fs::Files::Mask>(role["files"].get<uint64_t>()));
    const pv::fs::Directories dirs(static_cast<pv::fs::Directories::Mask>(role.value("directories", uint64_t{0})));
    using F = pv::fs::FilePermissions;
    for (const auto p : {F::Upload, F::Overwrite, F::Rename, F::Delete, F::Move})
        if (files.has(p)) return "read-write";
    if (files.raw() == 0 && dirs.raw() == 0) return "none";
    return "read-only";
}

json toJson(const mq::Switch& sw) {
    return {{"switch_id", sw.switch_id},
            {"side", sw.side},
            {"phase", sw.phase},
            {"term", sw.term},
            {"seq", sw.seq ? json(*sw.seq) : json(nullptr)},
            {"digest", sw.digest ? json(sw.digest->hex()) : json(nullptr)},
            {"entries", sw.digest ? json(sw.digest->entries) : json(nullptr)},
            {"told", !sw.notify},
            {"asked_on", sw.asked_on},
            {"asked_by", sw.asked_by ? json{{"node", sw.asked_by->node}, {"id", sw.asked_by->id},
                                            {"name", sw.asked_by_name}}
                                     : json(nullptr)},
            {"reason", sw.reason ? json(*sw.reason) : json(nullptr)},
            {"detail", sw.detail},
            {"deadline", static_cast<int64_t>(sw.deadline)},
            {"created_at", static_cast<int64_t>(sw.created_at)},
            {"ended_at", sw.ended_at ? json(static_cast<int64_t>(*sw.ended_at)) : json(nullptr)}};
}

}
