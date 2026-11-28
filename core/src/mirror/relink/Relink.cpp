#include "mirror/relink/Relink.hpp"

#include "audit/Trail.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Pending.hpp"
#include "db/query/mirror/Relink.hpp"
#include "db/query/mirror/Resync.hpp"
#include "db/query/mirror/Start.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/tree_apply/TreeApply.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "mirror/Hash.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/resync/Resync.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"
#include "rbac/Mirrored.hpp"
#include "runtime/Deps.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <pqxx/pqxx>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <thread>
#include <utility>

namespace vh::mirror::relink {

namespace {

namespace mq = vh::db::query::mirror;
namespace ta = vh::fs::tree_apply;
using json = nlohmann::json;

// ---- small helpers -------------------------------------------------------------------------------------------------

json relinkPos(const std::optional<mq::Position>& p) {
    return p ? json{{"term", p->term}, {"seq", p->seq}} : json(nullptr);
}

std::optional<mq::Position> relinkPosOf(const json& j) {
    if (!j.is_object() || !j.contains("term") || !j.contains("seq") || !j["term"].is_number_unsigned() ||
        !j["seq"].is_number_unsigned())
        return std::nullopt;
    return mq::Position{j["term"].get<uint64_t>(), j["seq"].get<uint64_t>()};
}

bool relinkUuid(const std::string& s) {
    static const std::regex re("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    return std::regex_match(s, re);
}

std::string relinkUidField(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || !payload.at(key).is_string() ||
        !relinkUuid(payload.at(key).get<std::string>()))
        throw vh::ops::Invalid(std::string(key) + " is a uuid");
    return payload.at(key).get<std::string>();
}

std::string relinkStr(const json& j, const char* key) {
    return j.is_object() && j.contains(key) && j[key].is_string() ? j[key].get<std::string>() : std::string{};
}

std::string relinkNameOf(const std::string& path) {
    const auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string relinkParentPath(const std::string& path) {
    const auto slash = path.find_last_of('/');
    if (slash == std::string::npos || slash == 0) return "/";
    return path.substr(0, slash);
}

std::string relinkJoin(const std::string& folder, const std::string& name) {
    return folder == "/" ? "/" + name : folder + "/" + name;
}

// One entry's version, as both servers describe it (the wire's and the plan's form).
json relinkSummaryOf(const mq::RelinkTreeRow& r) {
    const auto& s = r.state;
    const auto kind = s.value("type", std::string("file"));
    json out{{"kind", kind}, {"trashed", r.trashed}, {"path", r.path}, {"hash", r.hash}};
    if (r.trashed) {
        out["name"] = relinkNameOf(r.path);
        out["parent"] = nullptr;
    } else {
        out["name"] = s.value("name", std::string{});
        out["parent"] = s.contains("parent") && s["parent"].is_string() ? s["parent"] : json(nullptr);
    }
    if (kind == "file") {
        out["generation"] = r.generation.empty() ? s.value("generation", std::string{}) : r.generation;
        out["size"] = s.value("size", uint64_t{0});
        out["key_version"] = s.value("key_version", uint64_t{0});
        out["content_hash"] = s.value("content_hash", std::string{});
        if (s.contains("mime") && s["mime"].is_string()) out["mime"] = s["mime"];
    }
    if (kind == "symlink") out["target"] = s.value("target", std::string{});
    if (s.contains("mode")) out["mode"] = s["mode"];
    return out;
}

bool relinkLive(const json& st) { return st.is_object() && !st.value("trashed", false); }
bool relinkTrashed(const json& st) { return st.is_object() && st.value("trashed", false); }
bool relinkIsFile(const json& st) { return st.is_object() && st.value("kind", std::string{}) == "file"; }
bool relinkIsDir(const json& st) { return st.is_object() && st.value("kind", std::string{}) == "directory"; }
bool relinkPlaceDiffers(const json& a, const json& b) {
    return relinkStr(a, "parent") != relinkStr(b, "parent") || relinkStr(a, "name") != relinkStr(b, "name");
}

// ---- this server's hold on the vault ---------------------------------------------------------------------------------

std::string relinkOwnNode() { return vh::db::query::device::Devices::nodeId(); }

struct Local {
    json state;          // the wire's form
    bool related{false};
    bool elsewhere{false};
};

Local relinkLocal(const uint32_t vaultId, const std::string& peerNode) {
    const auto f = mq::Relinks::facts(vaultId, peerNode);
    Local out;
    std::string status = "unrelated";
    std::optional<mq::Position> agreed;
    std::string rowState;
    if (f.row) {
        const bool samePeer = f.row_peer_node && *f.row_peer_node == peerNode;
        out.related = samePeer;
        out.elsewhere = !samePeer;
        rowState = f.row->state;
        if (f.row->role == "core") {
            status = f.row->state == "rejoining" ? "rejoining" : f.row->state == "forked" ? "forked" : "core";
            agreed = f.rejoin_fork ? f.rejoin_fork : f.takeover_fork ? f.takeover_fork : f.row->acked;
        } else {
            status = f.row->role;   // mirror | orphaned
            agreed = f.row->position();
        }
    } else if (f.detach_id) {
        status = "detached";
        out.related = true;
        agreed = f.detach_fork;
    } else if (f.base_mark && f.base_peer_node && *f.base_peer_node == peerNode) {
        status = "ended";
        out.related = true;
        agreed = f.base_mark;
    }
    json keys = json::array();
    for (const auto& k : mq::Relinks::keys(vaultId))
        keys.push_back({{"version", k.version}, {"current", k.current},
                        {"check", k.check ? json(*k.check) : json(nullptr)},
                        {"origin", k.origin_node ? json{{"node", *k.origin_node},
                                                        {"vault_id", k.origin_vault.value_or(0)},
                                                        {"check", k.origin_check.value_or("")}}
                                                 : json(nullptr)}});
    const auto digest = mq::Relinks::digest(vaultId);
    const auto vault = vh::db::query::vault::Vault::getVault(vaultId);
    out.state = {{"vault_id", vaultId},
                 {"vault_uid", mq::MirrorVaults::vaultUidOf(vaultId).value_or("")},
                 {"vault_name", vault ? vault->name : std::string{}},
                 {"node", relinkOwnNode()},
                 {"status", status},
                 {"row_state", rowState.empty() ? json(nullptr) : json(rowState)},
                 {"term", f.max_term},
                 {"agreed", relinkPos(agreed)},
                 {"pending", f.pending + f.unnumbered + f.submissions},
                 {"switch_running", f.switch_running},
                 {"start_running", f.start_running || f.copy_running},
                 {"deleting", f.deleting},
                 {"contents_missing", f.contents_missing},
                 {"mirrored_elsewhere", out.elsewhere},
                 {"digest", digest.hex()},
                 {"entries", digest.entries},
                 {"keys", keys}};
    return out;
}

// The vault here with this uid that the caller's server is related to; NotFound otherwise.
uint32_t relinkVaultForPeer(const json& payload, const uint32_t callerPeerId, vh::peer::Record& peerOut) {
    const auto uid = relinkUidField(payload, "vault_uid");
    const auto peer = vh::db::query::peer::Peers::byId(callerPeerId);
    if (!peer || peer->revoked()) throw vh::ops::Refused("peer_revoked", "this link is unlinked");
    const auto vaultId = mq::MirrorStart::vaultWithUid(vh::crypto::id::fromUuid(uid));
    if (!vaultId) throw vh::ops::NotFound("this server holds no vault with that uid");
    peerOut = *peer;
    return *vaultId;
}

// ---- comparing two keys' sets without the keys -------------------------------------------------------------------------

json relinkKeys(const json& mine, const json& theirs, const std::set<uint64_t>& used) {
    const auto find = [](const json& st, const uint64_t v) -> const json* {
        for (const auto& k : st.at("keys"))
            if (k.value("version", uint64_t{0}) == v) return &k;
        return nullptr;
    };
    const auto current = [](const json& st) -> uint64_t {
        for (const auto& k : st.at("keys"))
            if (k.value("current", false)) return k.value("version", uint64_t{0});
        return 0;
    };
    // The same key when one server's own key check is what the other recorded as its origin's (node, vault id, check).
    const auto deliveredFrom = [](const json& holder, const json& owner, const json& ownerState) {
        const auto& o = holder.contains("origin") ? holder["origin"] : json(nullptr);
        if (!o.is_object() || !owner.contains("check") || !owner["check"].is_string()) return false;
        return o.value("node", std::string{}) == ownerState.value("node", std::string{}) &&
               o.value("vault_id", uint64_t{0}) == ownerState.value("vault_id", uint64_t{0}) &&
               o.value("check", std::string{}) == owner["check"].get<std::string>();
    };
    std::set<uint64_t> needed = used;
    const auto a = current(mine), b = current(theirs);
    needed.insert(a);
    needed.insert(b);
    json mismatched = json::array();
    for (const auto v : needed) {
        if (v == 0) continue;
        const auto* x = find(mine, v);
        const auto* y = find(theirs, v);
        if (!x || !y || !(deliveredFrom(*y, *x, mine) || deliveredFrom(*x, *y, theirs))) mismatched.push_back(v);
    }
    return {{"match", mismatched.empty() && a == b}, {"current", {{"this", a}, {"theirs", b}}},
            {"mismatched", mismatched}};
}

// ---- what refuses a relink now ---------------------------------------------------------------------------------------

json relinkBlockers(const json& mine, const json& theirs, const json& keys) {
    json out = json::array();
    const auto add = [&](const std::string& code, const std::string& side, const std::string& why) {
        out.push_back({{"code", code}, {"side", side}, {"message", why}});
    };
    for (const auto& [side, st] : {std::pair<std::string, const json*>{"this", &mine}, {"theirs", &theirs}}) {
        const auto& s = *st;
        const auto server = side == "this" ? std::string("this server") : std::string("the other server");
        const auto status = s.value("status", std::string{});
        if (s.value("mirrored_elsewhere", false))
            add("mirror_relink_mirrored", side, server + " mirrors the vault with another server");
        else if (status == "mirror")
            add("mirror_relink_mirrored", side, server + " holds the vault as the other's mirror still: use "
                                                     "`vh mirror resync` or `vh mirror switch`, not a relink");
        if (s.value("pending", uint64_t{0}) > 0)
            add("mirror_relink_pending", side, server + " has changes not yet confirmed or numbered; wait for them");
        if (s.value("switch_running", false)) add("mirror_relink_switch", side, server + " is switching the vault's core");
        if (s.value("start_running", false))
            add("mirror_relink_busy", side, server + " is starting a mirror of the vault or copying it");
        if (s.value("deleting", false)) add("mirror_relink_deleting", side, server + " is deleting the vault");
    }
    if (!keys.value("match", false))
        add("mirror_relink_keys", "both", "the two servers do not hold the same keys for the vault (a key version was "
                                          "rotated or replaced on one since the mirror ended); a relink moves no keys");
    return out;
}

// ---- trees ---------------------------------------------------------------------------------------------------------------

struct Side {
    std::map<std::string, std::pair<json, std::optional<std::string>>> entries;   // uid -> (summary or null, base)
    bool base{false};
    json baseInfo;
};

json relinkBaseInfo(const mq::RelinkBase& b) {
    return {{"available", b.available}, {"source", b.source}, {"at", relinkPos(b.at)}};
}

std::vector<json> relinkOwnTree(const uint32_t vaultId, const std::optional<mq::Position> since, json& baseInfo) {
    const auto base = mq::Relinks::base(vaultId, since);
    baseInfo = relinkBaseInfo(base);
    std::vector<json> out;
    std::set<std::string> seen;
    for (const auto& r : mq::Relinks::tree(vaultId)) {
        seen.insert(r.uid);
        const auto b = base.hashes.find(r.uid);
        out.push_back({{"uid", r.uid}, {"state", relinkSummaryOf(r)},
                       {"base", b != base.hashes.end() ? json(b->second) : json(nullptr)}});
    }
    for (const auto& [uid, h] : base.hashes)
        if (!seen.contains(uid)) out.push_back({{"uid", uid}, {"state", nullptr}, {"base", h}});
    std::ranges::sort(out, {}, [](const json& j) { return j.at("uid").get<std::string>(); });
    return out;
}

void relinkFill(Side& side, const std::vector<json>& list, const json& baseInfo) {
    side.base = baseInfo.value("available", false);
    side.baseInfo = baseInfo;
    for (const auto& e : list) {
        std::optional<std::string> base;
        if (e.contains("base") && e["base"].is_string()) base = e["base"].get<std::string>();
        side.entries[e.at("uid").get<std::string>()] = {e.contains("state") ? e["state"] : json(nullptr), base};
    }
}

// The served trees, by (vault uid, relink uid): a comparison reads the tree once, then pages it.
struct Served {
    std::chrono::steady_clock::time_point at{};
    std::vector<json> entries;
    json base;
};
std::mutex& relinkServedMutex() {
    static std::mutex m;
    return m;
}
std::map<std::string, Served>& relinkServed() {
    static std::map<std::string, Served> m;
    return m;
}

// ---- the plan ----------------------------------------------------------------------------------------------------------

// The entry's resolution: core (the core's version stays), mirror (the future mirror's is brought onto the core), both.
std::string relinkResolve(const mq::RelinkEntry& e, const mq::Relink& r) {
    const auto choice = e.choice ? *e.choice : r.default_choice ? *r.default_choice : r.core;
    if (choice == "both") return "both";
    return choice == r.core ? "core" : "mirror";
}

json relinkGains(const mq::Relink& r, const std::vector<mq::RelinkEntry>& entries) {
    struct Count {
        uint64_t takes{}, keeps{}, copies{};
    } core, mirror;
    uint64_t chosenCore = 0, chosenMirror = 0, chosenBoth = 0;
    for (const auto& e : entries) {
        const auto res = relinkResolve(e, r);
        const auto& c = r.core == "this" ? e.this_state : e.theirs_state;
        const auto& m = r.core == "this" ? e.theirs_state : e.this_state;
        if (res == "core") {
            ++chosenCore;
            if (!c.is_null()) ++mirror.takes;
            if (!m.is_null()) ++mirror.keeps;
        } else if (res == "mirror") {
            ++chosenMirror;
            if (!m.is_null()) ++core.takes;
            if (!c.is_null()) ++core.keeps;
        } else {
            ++chosenBoth;
            if (relinkIsFile(m) && relinkLive(m) && relinkLive(c)) {
                ++core.copies;
                ++mirror.copies;
                ++mirror.takes;
            } else if (c.is_null()) {
                ++core.takes;
            } else if (!m.is_null()) {
                ++mirror.takes;
                ++mirror.keeps;
            }
        }
    }
    const auto j = [](const Count& c) { return json{{"takes", c.takes}, {"keeps_held", c.keeps}, {"conflict_copies", c.copies}}; };
    const auto thisSide = r.core == "this" ? j(core) : j(mirror);
    const auto theirSide = r.core == "this" ? j(mirror) : j(core);
    return {{"this", thisSide}, {"theirs", theirSide},
            {"chosen", {{"core", chosenCore}, {"mirror", chosenMirror}, {"both", chosenBoth}}}};
}

json relinkEntryJson(const mq::RelinkEntry& e, const mq::Relink& r) {
    return {{"uid", e.uid}, {"kind", e.kind}, {"aspects", e.aspects}, {"path", e.path},
            {"this", e.this_state}, {"theirs", e.theirs_state},
            {"choice", e.choice ? json(*e.choice) : json(nullptr)},
            {"resolution", relinkResolve(e, r)},
            {"outcome", e.outcome ? json(*e.outcome) : json(nullptr)},
            {"outcome_note", e.outcome_note ? json(*e.outcome_note) : json(nullptr)}};
}

json relinkRowJson(const mq::Relink& r) {
    const auto t = [](const std::optional<std::time_t>& x) { return x ? json(static_cast<int64_t>(*x)) : json(nullptr); };
    return {{"id", r.id}, {"relink_uid", r.relink_uid}, {"side", r.side}, {"phase", r.phase}, {"mode", r.mode},
            {"core", r.core}, {"default_choice", r.default_choice ? json(*r.default_choice) : json(nullptr)},
            {"role", r.role ? json(*r.role) : json(nullptr)}, {"term", r.term ? json(*r.term) : json(nullptr)},
            {"error", r.error ? json(*r.error) : json(nullptr)},
            {"by", {{"node", r.by_node.value_or("")}, {"id", r.by_id ? json(*r.by_id) : json(nullptr)},
                    {"name", r.by_name.value_or("")}}},
            {"created_at", static_cast<int64_t>(r.created_at)}, {"applied_at", t(r.applied_at)},
            {"finished_at", t(r.finished_at)}};
}

// ---- the handshake: what each side is asked to agree to ----------------------------------------------------------------

std::time_t relinkNow() { return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); }

json relinkTime(const std::optional<std::time_t>& t) { return t ? json(static_cast<int64_t>(*t)) : json(nullptr); }

// One drifted entry of a plan, seen from the server it is sent to (the responder): its choice, and both versions' hashes.
struct PlanRow {
    std::string uid, choice, here, there;
};

// The plan's hash, as both servers compute it from the responder's side: which server becomes the core there, the
// mode, both trees' digests as compared, and each drifted entry's choice and versions. The approval is bound to it.
std::string relinkPlanHash(const std::string& core, const std::string& mode, const std::string& hereDigest,
                           const std::string& thereDigest, std::vector<PlanRow> rows) {
    std::ranges::sort(rows, {}, &PlanRow::uid);
    std::string text = "vh.mirror.relink.plan/1\n" + core + "\n" + mode + "\n" + hereDigest + "\n" + thereDigest + "\n";
    for (const auto& r : rows) text += r.uid + " " + r.choice + " " + r.here + " " + r.there + "\n";
    vh::mirror::Hash h{};
    crypto_hash_sha256(h.data(), reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return vh::mirror::toHex(h);
}

std::string relinkStateHash(const json& st) { return st.is_null() ? std::string("-") : relinkStr(st, "hash"); }

json relinkGainsJson(const json& g) {
    return {{"takes", g.value("takes", uint64_t{0})}, {"keeps_held", g.value("keeps_held", uint64_t{0})},
            {"conflict_copies", g.value("conflict_copies", uint64_t{0})}};
}

bool relinkSameGains(const json& a, const json& b) {
    for (const auto* k : {"takes", "keeps_held", "conflict_copies"})
        if (a.value(k, uint64_t{0}) != b.value(k, uint64_t{0})) return false;
    return true;
}

// The outcome a responder's super admin is asked to approve, in plain words (seen from the responder: "this server").
std::string relinkOutcomeText(const json& p, const std::string& peer) {
    if (!p.is_object()) return {};
    const auto other = "server '" + peer + "'";
    const bool coreHere = p.value("core", std::string{}) == "this";
    std::string out = coreHere ? "This server becomes the vault's core and " + other + " its mirror"
                               : other + " becomes the vault's core and this server its mirror";
    out += p.value("mode", std::string{}) == "override"
               ? "; " + (coreHere ? std::string("this server's") : other + "'s") + " tree wins everywhere."
               : "; a plan decides each drifted entry.";
    const auto here = p.contains("this") ? p["this"] : json::object();
    const auto n = [&](const char* k) { return here.value(k, uint64_t{0}); };
    const auto entries = [](const uint64_t v) { return std::to_string(v) + (v == 1 ? " entry" : " entries"); };
    out += fmt::format(" Here: {} take{} {}'s version (replaced, added or removed here); {} of this server's versions "
                       "leave its tree and are kept as held changes (with their bytes) or in the core's trash; {} conflict "
                       "cop{} added. Nothing is dropped.",
                       entries(n("takes")), n("takes") == 1 ? "s" : "", other, n("keeps_held"), n("conflict_copies"),
                       n("conflict_copies") == 1 ? "y is" : "ies are");
    return out;
}

// What accepting a request lets the asking server see.
std::string relinkDisclosure(const std::string& peer) {
    return "Accepting lets server '" + peer + "' read this vault's file and folder names, their places, sizes and "
           "hashes, and what is in its trash (never a file's contents), to compare them with its copy. Nothing changes "
           "here until you approve an outcome it proposes.";
}

json relinkHandshakeJson(const mq::Relink& r) {
    const auto peerName = r.summary.contains("peer") && r.summary["peer"].is_object()
                              ? r.summary["peer"].value("name", std::string{})
                              : std::string{};
    std::optional<std::string> waiting;
    if (r.phase == "requested" || r.phase == "proposed") waiting = r.side == "initiator" ? "other_admin" : "this_admin";
    else if (r.phase == "accepted") waiting = r.side == "initiator" ? "this_compare" : "other_compare";
    json proposal = nullptr;
    if (r.proposal.is_object()) {
        // The initiator keeps the proposal as it sent it (the responder's side); shown from its own side here.
        proposal = r.proposal;
        if (r.side == "initiator") {
            proposal["core"] = r.proposal.value("core", std::string{}) == "this" ? "theirs" : "this";
            proposal["this"] = r.proposal.contains("theirs") ? r.proposal["theirs"] : json::object();
            proposal["theirs"] = r.proposal.contains("this") ? r.proposal["this"] : json::object();
        }
        proposal.erase("by");
        proposal.erase("digest");
        proposal.erase("their_digest");
    }
    return {{"waiting_for", waiting ? json(*waiting) : json(nullptr)},
            {"expires_at", relinkTime(r.expires_at)},
            {"accepted_at", relinkTime(r.accepted_at)},
            {"accepted_by", r.accepted_by ? json(*r.accepted_by) : json(nullptr)},
            {"approved_at", relinkTime(r.approved_at)},
            {"approved_by", r.approved_by ? json(*r.approved_by) : json(nullptr)},
            {"proposal", proposal},
            {"outcome", r.side == "responder" && r.proposal.is_object() ? json(relinkOutcomeText(r.proposal, peerName))
                                                                        : json(nullptr)},
            {"discloses", r.side == "responder" ? json(relinkDisclosure(peerName)) : json(nullptr)}};
}

json relinkStatusOf(const mq::Relink& r) {
    const auto entries = mq::Relinks::entries(r.id);
    json out{{"vault_id", r.vault_id}, {"relink", relinkRowJson(r)}};
    const auto& s = r.summary;
    for (const auto* k : {"peer", "this", "theirs", "counts", "keys", "base", "blockers"})
        out[k] = s.contains(k) ? s[k] : json(nullptr);
    if (!out["blockers"].is_array()) out["blockers"] = json::array();
    if (!out["counts"].is_object()) out["counts"] = json::object();
    out["plan"] = relinkGains(r, entries);
    out["plan"]["core"] = r.core;
    out["plan"]["default_choice"] = r.default_choice ? json(*r.default_choice) : json(nullptr);
    json progress{{"bring_total", 0}, {"bring_done", 0}, {"executed", 0}, {"refused", 0}, {"kept", 0}};
    if (s.contains("bring") && s["bring"].is_array()) {
        progress["bring_total"] = s["bring"].size();
        progress["bring_done"] = s.value("bring_at", uint64_t{0});
    }
    for (const auto& e : entries) {
        if (!e.outcome) continue;
        if (*e.outcome == "executed") progress["executed"] = progress["executed"].get<uint64_t>() + 1;
        else if (*e.outcome == "refused") progress["refused"] = progress["refused"].get<uint64_t>() + 1;
        else if (*e.outcome == "kept") progress["kept"] = progress["kept"].get<uint64_t>() + 1;
    }
    if (const auto mv = mq::MirrorVaults::get(r.vault_id); mv && r.role) {
        progress["row"] = {{"role", mv->role}, {"state", mv->state}, {"copy_finished", mv->copy_finished},
                           {"copy_cursor", mv->copy_cursor}, {"term", mv->term},
                           {"stop_reason", mv->stop_reason ? json(*mv->stop_reason) : json(nullptr)}};
    }
    out["progress"] = progress;
    out["handshake"] = relinkHandshakeJson(r);
    return out;
}

// ---- held changes the relink keeps -------------------------------------------------------------------------------------

mq::Account relinkAccount(const json& by) {
    return {.node = by.value("node", relinkOwnNode()), .id = by.value("id", 0u)};
}

void relinkHold(pqxx::work& txn, const uint32_t vaultId, const std::string& uid, const std::string& op, json args,
                const std::string& path, const mq::Account& actor, const std::string& code, const std::string& why,
                const std::filesystem::path& bytes, const std::string& kind = "held") {
    mq::HeldChange h;
    h.vault_id = vaultId;
    h.kind = kind;
    h.request_id = vh::mirror::submit::newRequestId();
    h.op = op;
    h.entry_uid = uid;
    h.args = std::move(args);
    h.path = path;
    h.actor = actor;
    h.reason_code = code;
    h.reason = why;
    if (kind == "conflict") h.copy_name = h.args.value("copy_name", std::string{});
    const auto id = mq::Pending::hold(txn, h);
    std::error_code ec;
    if (!bytes.empty() && std::filesystem::is_regular_file(bytes, ec))
        vh::mirror::submit::contents::keep(bytes, vh::mirror::submit::contents::heldBlob(vaultId, id));
}

// A live file here: its bytes, generation, key version and facts.
struct FileHere {
    std::filesystem::path backing{};
    std::string generation{};
    uint32_t key_version{};
    uint64_t size{};
    std::string content_hash{};
    std::optional<std::string> mime{};
};

std::optional<FileHere> relinkFileHere(const uint32_t vaultId, const std::string& uid) {
    const auto at = ta::locate(vaultId, uid);
    if (!at) return std::nullopt;
    if (at->trashed) {
        const auto b = vh::db::Transactions::exec("relink trash backing", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT backing_path, size_bytes FROM files_trashed WHERE id = $1", pqxx::params{at->id});
            return r.empty() ? std::pair<std::string, uint64_t>{} : std::pair{r[0][0].as<std::string>(), r[0][1].as<uint64_t>()};
        });
        if (b.first.empty()) return std::nullopt;
        return FileHere{.backing = b.first, .size = b.second};
    }
    const auto file = std::dynamic_pointer_cast<vh::fs::model::File>(vh::db::query::fs::Entry::getFSEntryById(at->id));
    if (!file) return std::nullopt;
    return FileHere{.backing = file->backing_path, .generation = file->encryption_iv,
                    .key_version = file->encrypted_with_key_version, .size = static_cast<uint64_t>(file->size_bytes),
                    .content_hash = file->content_hash.value_or(""), .mime = file->mime_type};
}

json relinkWriteArgs(const std::string& uid, const json& st, const FileHere& f) {
    json args{{"uid", uid}, {"parent_uid", st.contains("parent") ? st["parent"] : json(nullptr)},
              {"name", relinkStr(st, "name")}, {"generation", f.generation}, {"key_version", f.key_version},
              {"size", f.size}, {"content_hash", f.content_hash}};
    if (f.mime) args["mime"] = *f.mime;
    if (relinkTrashed(st)) args["trashed"] = true;
    return args;
}

// ---- the person a server's own changes are made by --------------------------------------------------------------------

Who relinkPerson(const uint32_t vaultId, const json& by) {
    const auto& manager = vh::runtime::Deps::get().identityManager;
    if (by.value("node", std::string{}) == relinkOwnNode() && by.contains("id") && by["id"].is_number_unsigned())
        return {.id = by["id"].get<uint32_t>(), .name = by.value("name", std::string{})};
    if (manager) {
        if (const auto v = vh::db::query::vault::Vault::getVault(vaultId))
            if (const auto u = manager->user(v->owner_id); u && u->authorizing() && !u->remote())
                return {.id = u->id, .name = u->name()};
        std::optional<Who> best;
        for (const auto& u : manager->users())
            if (u && u->isSuperAdmin() && !u->remote() && (!best || u->id < best->id)) best = Who{.id = u->id, .name = u->name()};
        if (best) return *best;
    }
    throw vh::ops::Refused("mirror_relink_no_person", "this server has no local account to make its changes as");
}

std::shared_ptr<vh::identities::User> relinkUser(const Who& w) {
    const auto& manager = vh::runtime::Deps::get().identityManager;
    auto u = manager ? manager->user(w.id) : nullptr;
    if (!u) throw vh::ops::Refused("mirror_relink_no_person", "this server's account " + std::to_string(w.id) + " is gone");
    return u;
}

// ---- preparing each side ---------------------------------------------------------------------------------------------

// Who may use the vault here and what its gate says follow its rows (rbac::mirrored, mirror::access).
void relinkRepublish() {
    vh::rbac::mirrored::reload();
    vh::mirror::access::reload();
}

// The future core: its records end, its versions the plan replaces are kept as held changes, and it starts the pair.
void relinkPrepareCore(const mq::Relink& r, const uint32_t peerId, const uint64_t term, const json& by) {
    const auto vaultId = r.vault_id;
    const auto entries = mq::Relinks::entries(r.id);
    const auto actor = relinkAccount(by);
    std::vector<std::pair<std::string, std::optional<FileHere>>> files;
    for (const auto& e : entries)
        if (relinkResolve(e, r) == "mirror" && relinkLive(e.this_state) && relinkIsFile(e.this_state))
            files.emplace_back(e.uid, relinkFileHere(vaultId, e.uid));
    {
        std::scoped_lock step(vh::mirror::start::stepMutex());
        std::scoped_lock local(vh::mirror::submit::vaultMutex(vaultId));
        vh::db::Transactions::exec("mirror::relink prepare core", [&](pqxx::work& txn) {
            mq::Relinks::release(txn, vaultId, r.id, false);
            for (const auto& e : entries) {
                if (relinkResolve(e, r) != "mirror" || !relinkLive(e.this_state)) continue;
                const auto& c = e.this_state;
                const auto& m = e.theirs_state;
                if (relinkIsFile(c) && relinkLive(m) && relinkStr(c, "generation") != relinkStr(m, "generation")) {
                    const auto f = std::ranges::find(files, e.uid, &std::pair<std::string, std::optional<FileHere>>::first);
                    if (f != files.end() && f->second)
                        relinkHold(txn, vaultId, e.uid, "write", relinkWriteArgs(e.uid, c, *f->second),
                                   relinkStr(c, "path"), actor, "mirror_relink_replaced",
                                   "this server's version of the file before a relink took the other server's",
                                   f->second->backing);
                }
                if (relinkLive(m) && relinkPlaceDiffers(c, m))
                    relinkHold(txn, vaultId, e.uid, "move", {{"parent_uid", c["parent"]}, {"name", relinkStr(c, "name")}},
                               relinkStr(c, "path"), actor, "mirror_relink_replaced",
                               "where this server held the entry before a relink took the other server's place for it",
                               {});
            }
        });
    }
    relinkRepublish();
    (void)mq::MirrorVaults::startCore(vaultId, peerId, term);
    mq::Relinks::setApplied(r.id, "core", term, r.mode);
    (void)mq::Relinks::setPhase(r.id, {"approved", "prepared"}, "copying");
    vh::mirror::start::Service::instance()->wake();
}

json relinkOp(const std::string& uid, const std::string& op, json args, const std::string& note = {}) {
    json out{{"uid", uid}, {"op", op}, {"args", std::move(args)}};
    if (!note.empty()) out["note"] = note;
    return out;
}

// The future mirror: its records end, what the core's tree replaces without a trace is kept as held changes, the
// conflict copies are made, the mirror row holds it (stopped) and the changes it brings are listed.
void relinkPrepareMirror(const mq::Relink& r, const uint32_t peerId, const uint64_t term, const json& by) {
    const auto vaultId = r.vault_id;
    const auto entries = mq::Relinks::entries(r.id);
    const auto person = relinkPerson(vaultId, by);
    const mq::Account actor{.node = relinkOwnNode(), .id = person.id};
    const auto vaultUid = mq::MirrorVaults::vaultUidOf(vaultId).value_or("");
    std::map<std::string, std::optional<FileHere>> files;
    for (const auto& e : entries)
        if (relinkIsFile(e.this_state)) files[e.uid] = relinkFileHere(vaultId, e.uid);
    {
        std::scoped_lock step(vh::mirror::start::stepMutex());
        std::scoped_lock local(vh::mirror::submit::vaultMutex(vaultId));
        vh::db::Transactions::exec("mirror::relink prepare mirror", [&](pqxx::work& txn) {
            mq::Relinks::release(txn, vaultId, r.id, true);
            for (const auto& e : entries) {
                const auto& m = e.this_state;
                const auto& c = e.theirs_state;
                if (m.is_null()) continue;
                const auto res = relinkResolve(e, r);
                const auto f = files.find(e.uid);
                const bool bytes = f != files.end() && f->second;
                // A trashed version here, or a live one the core trashed: the copy would end it without a trace.
                if (relinkIsFile(m) && !c.is_null() && bytes &&
                    (relinkTrashed(m) || relinkTrashed(c)) && relinkStr(m, "hash") != relinkStr(c, "hash")) {
                    relinkHold(txn, vaultId, e.uid, "write", relinkWriteArgs(e.uid, m, *f->second), relinkStr(m, "path"),
                               actor, "mirror_relink_replaced",
                               relinkTrashed(m) ? "in this server's trash when a relink made it the other's mirror"
                                                : "this server's version of the file; the core holds it in its trash",
                               f->second->backing);
                    continue;
                }
                // Its place here, when the core's stays.
                if (res == "core" && relinkLive(m) && relinkLive(c) && relinkPlaceDiffers(m, c))
                    relinkHold(txn, vaultId, e.uid, "move", {{"parent_uid", m["parent"]}, {"name", relinkStr(m, "name")}},
                               relinkStr(m, "path"), actor, "mirror_relink_replaced",
                               "where this server held the entry when a relink made it the other's mirror", {});
            }
        });
    }
    relinkRepublish();

    // Conflict copies: this server's version of a file both hold, beside its own, under a new uid.
    std::map<std::string, std::string> copies;   // uid -> the copy's uid
    for (const auto& e : entries) {
        if (relinkResolve(e, r) != "both" || !relinkIsFile(e.this_state) || !relinkLive(e.this_state) ||
            !relinkLive(e.theirs_state))
            continue;
        const auto& m = e.this_state;
        const auto from = relinkStr(m, "path");
        const auto copyName = vh::mirror::submit::conflictName(relinkStr(m, "name"), e.uid, false);
        const auto to = relinkJoin(relinkParentPath(from), copyName);
        try {
            vh::ops::fs::copy(relinkUser(person), vaultId, from, to);
            const auto uid = vh::db::Transactions::exec("relink copy uid", [&](pqxx::work& txn) {
                const auto res = txn.exec("SELECT f.object_uid::text FROM fs_entry x JOIN files f ON f.fs_entry_id = x.id "
                                          "WHERE x.vault_id = $1 AND x.path = $2",
                                          pqxx::params{vaultId, to});
                return res.empty() || res[0][0].is_null() ? std::string{} : res[0][0].as<std::string>();
            });
            if (uid.empty()) throw std::runtime_error("the copy has no uid");
            copies[e.uid] = uid;
            vh::db::Transactions::exec("relink conflict record", [&](pqxx::work& txn) {
                relinkHold(txn, vaultId, e.uid, "copy", {{"copy_uid", uid}, {"copy_name", copyName}}, from, actor,
                           "mirror_relink_both", "both versions kept: this server's as a conflict copy beside the core's",
                           {}, "conflict");
            });
            mq::Relinks::setOutcome(r.id, e.uid, std::nullopt, "copied", uid);
        } catch (const std::exception& ex) {
            mq::Relinks::setOutcome(r.id, e.uid, std::nullopt, "kept",
                                    std::string("the conflict copy could not be made; this version is kept as a held "
                                                "change: ") + ex.what());
        }
    }

    // What this server brings onto the core (in order: folders, places, files, removals).
    std::set<std::string> liveDirsOnCore{vaultUid};
    std::map<std::string, const mq::RelinkEntry*> byUid;
    for (const auto& e : entries) byUid[e.uid] = &e;
    const auto liveHere = [&](const std::string& uid) {
        const auto at = ta::locate(vaultId, uid);
        return at && !at->trashed && at->kind == ta::Located::Kind::Directory;
    };
    std::vector<json> dirs, moves, writes, removes;
    std::set<std::string> broughtDirs;
    std::function<bool(const std::string&)> ensureParent = [&](const std::string& parent) -> bool {
        if (parent == vaultUid || broughtDirs.contains(parent)) return true;
        const auto it = byUid.find(parent);
        if (it == byUid.end()) return liveHere(parent);   // the same on both servers
        const auto& pe = *it->second;
        if (relinkIsDir(pe.theirs_state) && relinkLive(pe.theirs_state)) return true;
        if (!relinkIsDir(pe.this_state) || !relinkLive(pe.this_state) || !pe.theirs_state.is_null()) return false;
        if (!ensureParent(relinkStr(pe.this_state, "parent"))) return false;
        dirs.push_back(relinkOp(pe.uid, "mkdir", {{"parent_uid", pe.this_state["parent"]},
                                                  {"name", relinkStr(pe.this_state, "name")}},
                                "brought with what it holds"));
        broughtDirs.insert(pe.uid);
        return true;
    };
    std::vector<std::pair<std::string, std::string>> skipped;
    for (const auto& e : entries) {
        const auto res = relinkResolve(e, r);
        const auto& m = e.this_state;
        const auto& c = e.theirs_state;
        if (res == "both" && copies.contains(e.uid)) {
            const auto uid = copies[e.uid];
            const auto f = relinkFileHere(vaultId, uid);
            if (!f) continue;
            const auto name = vh::mirror::submit::conflictName(relinkStr(m, "name"), e.uid, false);
            json st{{"parent", c["parent"]}, {"name", name}};
            if (!ensureParent(relinkStr(c, "parent"))) continue;
            auto args = relinkWriteArgs(uid, st, *f);
            writes.push_back(relinkOp(uid, "write", std::move(args), "the conflict copy of " + e.uid));
            continue;
        }
        if (res == "core" || (res == "both" && !(c.is_null() && relinkLive(m)))) continue;
        // This server's version onto the core.
        if (m.is_null() || relinkTrashed(m)) {
            if (relinkLive(c)) removes.push_back(relinkOp(e.uid, "remove", json::object()));
            continue;
        }
        if (relinkTrashed(c)) {
            skipped.emplace_back(e.uid, "the core holds it in its trash: restoring is not brought over; this "
                                        "server's version is kept as a held change");
            continue;
        }
        const auto kind = relinkStr(m, "kind");
        const auto parent = relinkStr(m, "parent");
        if (kind == "symlink") {
            skipped.emplace_back(e.uid, "a symlink is not brought over; it is kept as a held change");
            continue;
        }
        if (!ensureParent(parent)) {
            skipped.emplace_back(e.uid, "its folder is not on the core; it is kept as a held change");
            continue;
        }
        if (c.is_null()) {
            if (kind == "directory") {
                if (!broughtDirs.contains(e.uid)) {
                    dirs.push_back(relinkOp(e.uid, "mkdir", {{"parent_uid", m["parent"]}, {"name", relinkStr(m, "name")}}));
                    broughtDirs.insert(e.uid);
                }
            } else if (const auto f = files.find(e.uid); f != files.end() && f->second) {
                writes.push_back(relinkOp(e.uid, "write", relinkWriteArgs(e.uid, m, *f->second)));
            }
            continue;
        }
        if (relinkPlaceDiffers(m, c))
            moves.push_back(relinkOp(e.uid, "move", {{"parent_uid", m["parent"]}, {"name", relinkStr(m, "name")}}));
        if (kind == "file" && relinkStr(m, "generation") != relinkStr(c, "generation"))
            if (const auto f = files.find(e.uid); f != files.end() && f->second) {
                auto args = relinkWriteArgs(e.uid, m, *f->second);
                args["base"] = relinkStr(c, "generation");
                writes.push_back(relinkOp(e.uid, "write", std::move(args)));
            }
    }
    for (const auto& [uid, why] : skipped) mq::Relinks::setOutcome(r.id, uid, std::nullopt, "kept", why);
    // Folders before what they hold: a brought folder's parent was pushed first by ensureParent.
    json bring = json::array();
    for (auto* list : {&dirs, &moves, &writes}) for (auto& op : *list) bring.push_back(std::move(op));
    std::ranges::reverse(removes);
    for (auto& op : removes) bring.push_back(std::move(op));

    (void)mq::MirrorVaults::startMirror(vaultId, peerId, term);
    (void)mq::MirrorVaults::stop(vaultId, "stopped", "mirror_relinking",
                                 {{"why", "a relink makes this server the vault's mirror; its copy starts once the changes "
                                          "it keeps are on the core (or ask `vh mirror resync`)"}});
    auto summary = r.summary;
    summary["bring"] = bring;
    summary["bring_at"] = 0;
    summary["person"] = {{"id", person.id}, {"name", person.name}};
    mq::Relinks::setSummary(r.id, summary);
    mq::Relinks::setApplied(r.id, "mirror", term, r.mode);
    (void)mq::Relinks::setPhase(r.id, {"approved"}, "prepared");
    relinkRepublish();
}

// The future mirror goes: its copy starts over at once when it brings nothing, else the follower's pass brings first.
void relinkGo(const mq::Relink& r) {
    if (r.role.value_or("") != "mirror") throw vh::ops::Conflict("this server is not the relink's future mirror");
    if (r.phase != "prepared") {
        if (r.phase == "bring" || r.phase == "copying" || r.phase == "done") return;   // told again
        throw vh::ops::Conflict("the relink is " + r.phase);
    }
    const auto bring = r.summary.contains("bring") ? r.summary["bring"] : json::array();
    if (!bring.empty()) {
        (void)mq::Relinks::setPhase(r.id, {"prepared"}, "bring");
        vh::mirror::follow::Follower::instance()->wake(r.vault_id);
        return;
    }
    const auto personId = r.summary.contains("person") ? r.summary["person"].value("id", 0u) : 0u;
    {
        std::scoped_lock local(vh::mirror::submit::vaultMutex(r.vault_id));
        vh::db::Transactions::exec("mirror::relink go", [&](pqxx::work& txn) {
            if (!mq::Resync::resetMirror(txn, r.vault_id, personId))
                throw vh::ops::Conflict("the vault has no mirror row here");
        });
    }
    (void)mq::Relinks::setPhase(r.id, {"prepared"}, "copying");
    relinkRepublish();
    vh::mirror::follow::Follower::instance()->wake(r.vault_id);
}

// A side that prepared and must not go on: its new row goes (the vault is this server's own again); what it settled
// stays settled.
void relinkAbortLocal(const mq::Relink& r, const std::string& why) {
    if (r.role) {
        std::scoped_lock step(vh::mirror::start::stepMutex());
        (void)mq::MirrorVaults::remove(r.vault_id);
    }
    (void)mq::Relinks::setPhase(r.id, {"approved", "prepared", "bring", "copying"}, "failed", why);
    relinkRepublish();
}

void relinkAudit(const std::string& action, const mq::Relink& r, const json& by, const json& extra,
                 const std::string& message) {
    json details{{"relink", r.relink_uid}, {"peer", r.peer_id}, {"side", r.side}, {"mode", r.mode},
                 {"role", r.role.value_or("")}, {"term", r.term.value_or(0)}};
    for (const auto& [k, v] : extra.items()) details[k] = v;
    const bool here = by.value("node", std::string{}) == relinkOwnNode();
    audit::record({.action = action, .outcome = audit::Outcome::Info,
                   .actor_id = here && by.contains("id") && by["id"].is_number_unsigned()
                                   ? std::optional<uint32_t>(by["id"].get<uint32_t>())
                                   : std::nullopt,
                   .actor = by.value("name", std::string{}), .vault_id = r.vault_id, .details = details},
                  message);
}

// ---- the handshake on both sides -----------------------------------------------------------------------------------------

const std::vector<std::string>& relinkAsking() {
    static const std::vector<std::string> phases{"requested", "accepted", "open", "proposed", "approved"};
    return phases;
}

// Requests and acceptances past their time end (nothing was applied), audited where they end.
void relinkExpire() {
    for (const auto& r : mq::Relinks::expire())
        relinkAudit("mirror.relink.expired", r, json::object(), {},
                    fmt::format("[mirror] vault {}: the relink {} with linked server {} ({}) expired before it was "
                                "answered or carried out; neither vault changed",
                                r.vault_id, r.relink_uid, r.peer_id,
                                r.side == "responder" ? "asked by that server" : "asked by this server"));
}

json relinkPersonJson(const Who& who) { return {{"node", relinkOwnNode()}, {"id", who.id}, {"name", who.name}}; }

std::string relinkPeerName(const mq::Relink& r) {
    if (r.summary.contains("peer") && r.summary["peer"].is_object())
        if (const auto n = r.summary["peer"].value("name", std::string{}); !n.empty()) return n;
    const auto p = vh::db::query::peer::Peers::byId(r.peer_id);
    return p ? p->name : std::to_string(r.peer_id);
}

// Tells the other server what happened to the relink here (best effort: it asks again when it compares or applies).
void relinkTell(vh::mirror::follow::Transport& t, const mq::Relink& r, const std::string& command, json payload) {
    const auto vaultUid = mq::MirrorVaults::vaultUidOf(r.vault_id);
    if (!vaultUid) return;
    payload["vault_uid"] = *vaultUid;
    payload["relink_uid"] = r.relink_uid;
    const auto a = t.request(r.peer_id, command, payload);
    if (!a || !a->ok)
        vh::log::Registry::sync()->info("[MirrorRelink] Vault {}: server {} was not told ({}: {}); it learns when it asks "
                                        "again",
                                        r.vault_id, r.peer_id, command, a ? a->error : std::string("no answer"));
}

// The asking server's relink of the vault here, once this server's super admin accepted it; refused otherwise.
mq::Relink relinkAccepted(const uint32_t vaultId, const json& payload, const uint32_t callerPeerId) {
    relinkExpire();
    const auto uid = relinkUidField(payload, "relink_uid");
    const auto r = mq::Relinks::byUid(vaultId, uid);
    const bool ours = r && r->side == "responder" && r->peer_id == callerPeerId;
    if (ours && (r->phase == "accepted" || r->phase == "proposed" || r->phase == "approved")) return *r;
    throw vh::ops::Refused("mirror_relink_not_accepted",
                           ours && r->phase == "requested"
                               ? std::string("this server's super admin has not accepted the relink yet")
                           : ours ? "this server's relink with the asking server is " + r->phase + ": ask again"
                                  : std::string("this server's super admin has not accepted a relink of this vault with "
                                                "the asking server: ask first"));
}

// What the responder answers of its relink (its phase, who answered, the approved plan's hash).
json relinkAnswerOf(const mq::Relink& r) {
    return {{"relink_uid", r.relink_uid}, {"phase", r.phase}, {"expires_at", relinkTime(r.expires_at)},
            {"accepted_by", r.accepted_by ? json(*r.accepted_by) : json(nullptr)},
            {"approved_by", r.approved_by ? json(*r.approved_by) : json(nullptr)},
            {"plan_hash", r.phase == "approved" && r.proposal.is_object() ? json(r.proposal.value("plan_hash", std::string{}))
                                                                          : json(nullptr)}};
}

// The outcome, as the responder is asked to approve it (its side: "this" is the responder).
json relinkProposalOf(const mq::Relink& r, const json& by) {
    const auto entries = mq::Relinks::entries(r.id);
    std::vector<PlanRow> rows;
    rows.reserve(entries.size());
    for (const auto& e : entries) {
        const auto res = relinkResolve(e, r);
        const auto choice = res == "both" ? std::string("both")
                                          : (res == "core") == (r.core == "this") ? std::string("theirs")
                                                                                  : std::string("this");
        rows.push_back({.uid = e.uid, .choice = choice, .here = relinkStateHash(e.theirs_state),
                        .there = relinkStateHash(e.this_state)});
    }
    const auto gains = relinkGains(r, entries);
    const auto theirCore = r.core == "this" ? std::string("theirs") : std::string("this");
    const auto hex = [](const std::optional<vh::mirror::Digest>& d) { return d ? d->hex() : std::string{}; };
    const auto count = [](const std::optional<vh::mirror::Digest>& d) { return d ? d->entries : int64_t{0}; };
    return {{"plan_hash", relinkPlanHash(theirCore, r.mode, hex(r.theirs_digest), hex(r.this_digest), rows)},
            {"core", theirCore},
            {"mode", r.mode},
            {"this", gains["theirs"]},
            {"theirs", gains["this"]},
            {"chosen", gains["chosen"]},
            {"entries", entries.size()},
            {"digest", {{"digest", hex(r.theirs_digest)}, {"entries", count(r.theirs_digest)}}},
            {"their_digest", {{"digest", hex(r.this_digest)}, {"entries", count(r.this_digest)}}},
            {"by", by}};
}

// One apply at a time on this server (a person's and the follower's pass).
std::mutex& relinkCarryMutex() {
    static std::mutex m;
    return m;
}

// ---- the initiator's side of the wire ----------------------------------------------------------------------------------

json relinkAsk(vh::mirror::follow::Transport& t, const uint32_t peerId, const std::string& command, const json& payload) {
    const auto a = t.request(peerId, command, payload);
    if (!a) throw vh::ops::Refused("mirror_core_unreachable", "the other server did not answer; try again");
    if (!a->ok) {
        if (a->code == "not_found")
            throw vh::ops::Refused("mirror_relink_no_vault", a->error.empty()
                                                                ? std::string("the other server holds no such vault")
                                                                : a->error);
        throw vh::ops::Refused(a->code.empty() ? std::string("mirror_relink_refused") : a->code,
                               a->error.empty() ? std::string("the other server refused") : a->error);
    }
    return a->data;
}

vh::peer::Record relinkLinked(const uint32_t peerId, vh::mirror::follow::Transport& t) {
    const auto peer = vh::db::query::peer::Peers::byId(peerId);
    if (!peer) throw vh::ops::NotFound("no such linked server");
    if (peer->revoked())
        throw vh::ops::Refused("peer_not_linked", "server '" + peer->name + "' is unlinked: link it again first");
    if (!t.connected(peerId))
        throw vh::ops::Refused("peer_link_down", "the link to server '" + peer->name + "' is down; try again once it is up");
    return *peer;
}

std::string relinkVaultUid(const uint32_t vaultId) {
    const auto uid = mq::MirrorVaults::vaultUidOf(vaultId);
    if (!uid) throw vh::ops::NotFound("no such vault");
    return *uid;
}

void relinkRequireConfirm(const uint32_t vaultId, const std::string& confirm) {
    const auto vault = vh::db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw vh::ops::NotFound("no such vault");
    if (confirm != vault->name)
        throw vh::ops::Refused("mirror_name_mismatch", "type the vault's name exactly to relink it");
}

// Sends the plan's entries to the other server, its part named (role), in pages; the last page prepares it there.
void relinkSendPrepare(vh::mirror::follow::Transport& t, const mq::Relink& r, const std::string& vaultUid,
                       const std::string& role, const uint64_t term, const json& by, const json& theirDigest) {
    const auto entries = mq::Relinks::entries(r.id);
    std::size_t at = 0;
    std::size_t part = 0;
    do {
        json list = json::array();
        for (; at < entries.size() && list.size() < kPreparePage; ++at) {
            const auto& e = entries[at];
            const auto res = relinkResolve(e, r);
            // Seen from the other server: its own version is `theirs` here.
            const auto choice = res == "both" ? std::string("both")
                                              : (res == "core") == (r.core == "this") ? std::string("theirs")
                                                                                      : std::string("this");
            list.push_back({{"uid", e.uid}, {"kind", e.kind}, {"aspects", e.aspects}, {"path", e.path},
                            {"yours", e.theirs_state}, {"mine", e.this_state}, {"choice", choice}});
        }
        const bool more = at < entries.size();
        (void)relinkAsk(t, r.peer_id, "peer.mirror.relink.prepare",
                        {{"vault_uid", vaultUid}, {"relink_uid", r.relink_uid}, {"role", role}, {"term", term},
                         {"mode", r.mode}, {"part", part++}, {"more", more}, {"entries", list}, {"by", by},
                         {"digest", theirDigest}});
        if (!more) break;
    } while (true);
}

json relinkCompareInto(const uint32_t vaultId, const uint32_t peerId, const Who& who,
                       vh::mirror::follow::Transport& transport, const std::string& mode, const std::string& core) {
    relinkExpire();
    const auto peer = relinkLinked(peerId, transport);
    const auto vaultUid = relinkVaultUid(vaultId);
    const auto mine = relinkLocal(vaultId, peer.node_id);
    if (!mine.related && !mine.elsewhere)
        throw vh::ops::Refused("mirror_relink_unrelated", "this server has no record of mirroring this vault with server '" +
                                                              peer.name + "'");
    const json by = relinkPersonJson(who);

    // One relink of the vault at a time here: a linked server's request waits for this server's answer first.
    const auto current = mq::Relinks::openOf(vaultId);
    if (current && current->side == "responder")
        throw vh::ops::Refused("mirror_relink_asked", "server '" + relinkPeerName(*current) + "' asked to relink this "
                                                      "vault: answer its request first (vh mirror pending)");
    if (current && !current->handshaking())
        throw vh::ops::Refused("mirror_relink_running", "a relink of this vault is being applied (" + current->phase + ")");
    // The same relink asked again: after the other server's answer, or a plan gone stale while the acceptance holds.
    std::optional<mq::Relink> asked;
    if (current && current->peer_id == peerId) {
        asked = current;
    } else if (!current) {
        if (const auto latest = mq::Relinks::latestOf(vaultId);
            latest && latest->side == "initiator" && latest->peer_id == peerId && latest->phase == "stale" &&
            latest->accepted_at && latest->expires_at && *latest->expires_at > relinkNow())
            asked = latest;
    }
    if (!asked) {
        mq::NewRelink n;
        n.vault_id = vaultId;
        n.peer_id = peerId;
        n.phase = "requested";
        n.mode = mode;
        n.core = core;
        n.this_status = mine.state.value("status", std::string{});
        n.by_node = relinkOwnNode();
        n.by_id = who.id;
        n.by_name = who.name;
        n.expires_at = relinkNow() + std::chrono::duration_cast<std::chrono::seconds>(kRequestHolds).count();
        n.summary = {{"peer", {{"id", peer.id}, {"name", peer.name}, {"node", peer.node_id}}}};
        asked = mq::Relinks::create(n);   // ends a relink this server asked of another linked server
        if (current) relinkTell(transport, *current, "peer.mirror.relink.cancel", {{"why", "replaced by a new request"}});
        relinkAudit("mirror.relink.request", *asked, by, {{"to", peer.name}},
                    fmt::format("[mirror] {} asked linked server '{}' to relink vault {} (relink {}): its super admin "
                                "decides whether this server may compare the two trees",
                                who.name.empty() ? std::string("someone") : who.name, peer.name, vaultId,
                                asked->relink_uid));
    }
    const auto answer = relinkAsk(transport, peerId, "peer.mirror.relink.request",
                                  {{"vault_uid", vaultUid}, {"relink_uid", asked->relink_uid}, {"by", by}});
    const auto theirPhase = relinkStr(answer, "phase");
    if (theirPhase == "declined" || theirPhase == "expired" || theirPhase == "cancelled") {
        (void)mq::Relinks::setPhase(asked->id, relinkAsking(), theirPhase,
                                    "server '" + peer.name + "' answered the request: " + theirPhase);
        return relinkStatusOf(*mq::Relinks::get(asked->id));
    }
    if (theirPhase == "requested") {
        if (asked->phase != "requested")
            (void)mq::Relinks::unapprove(asked->id, {"accepted", "open", "proposed", "approved"}, "requested",
                                         "server '" + peer.name + "' waits for its super admin's answer");
        return relinkStatusOf(*mq::Relinks::get(asked->id));
    }
    if (theirPhase != "accepted" && theirPhase != "proposed" && theirPhase != "approved")
        throw vh::ops::Refused("mirror_relink_refused", "server '" + peer.name + "' answered the request: " + theirPhase);
    const auto acceptedBy = relinkStr(answer, "accepted_by");
    if (asked->phase == "requested")
        relinkAudit("mirror.relink.accepted", *asked, json{{"name", acceptedBy}}, {{"from", peer.name}},
                    fmt::format("[mirror] linked server '{}' accepted the relink {} of vault {} ({}): this server may "
                                "compare the two trees",
                                peer.name, asked->relink_uid, vaultId, acceptedBy.empty() ? "its super admin" : acceptedBy));
    const auto theirs = relinkAsk(transport, peerId, "peer.mirror.relink.state",
                                  {{"vault_uid", vaultUid}, {"relink_uid", asked->relink_uid}});
    if (!theirs.value("accepted", false))
        throw vh::ops::Refused("mirror_relink_not_accepted", "server '" + peer.name + "' no longer accepts the relink");

    // A new row: the comparison (the relink's uid and its acceptance carried over; its uid names the served tree).
    mq::NewRelink n;
    n.relink_uid = asked->relink_uid;
    n.vault_id = vaultId;
    n.peer_id = peerId;
    n.mode = mode;
    n.core = core;
    n.this_status = mine.state.value("status", std::string{});
    n.theirs_status = theirs.value("status", std::string{});
    n.by_node = relinkOwnNode();
    n.by_id = who.id;
    n.by_name = who.name;
    n.accepted_at = asked->accepted_at.value_or(relinkNow());
    n.accepted_by = acceptedBy.empty() ? asked->accepted_by : std::optional<std::string>(acceptedBy);
    n.expires_at = asked->phase == "requested" || !asked->expires_at
                       ? relinkNow() + std::chrono::duration_cast<std::chrono::seconds>(kRequestHolds).count()
                       : *asked->expires_at;
    const auto digestOf = [](const json& st) {
        return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(st.value("digest", std::string(64, '0'))),
                                             st.value("entries", int64_t{0}));
    };
    n.this_digest = digestOf(mine.state);
    n.theirs_digest = digestOf(theirs);
    auto row = mq::Relinks::create(n);

    // Both trees, by uid; each side's base against the other's agreed position.
    Side a, b;
    json ownBase;
    relinkFill(a, relinkOwnTree(vaultId, relinkPosOf(theirs.value("agreed", json(nullptr))), ownBase), ownBase);
    {
        std::vector<json> list;
        json baseInfo;
        uint64_t after = 0;
        for (int guard = 0; guard < 100'000; ++guard) {
            const auto page = relinkAsk(transport, peerId, "peer.mirror.relink.tree",
                                        {{"vault_uid", vaultUid}, {"relink_uid", row.relink_uid},
                                         {"since", mine.state.value("agreed", json(nullptr))}, {"after", after},
                                         {"limit", kTreePage}});
            if (page.contains("base")) baseInfo = page["base"];
            for (const auto& e : page.value("entries", json::array())) list.push_back(e);
            after = page.value("next", after);
            if (!page.value("more", false)) break;
        }
        relinkFill(b, list, baseInfo);
    }

    std::set<std::string> uids;
    for (const auto& [u, _] : a.entries) uids.insert(u);
    for (const auto& [u, _] : b.entries) uids.insert(u);
    std::vector<mq::RelinkEntry> drift;
    std::set<uint64_t> used;
    json counts{{"only_this", 0}, {"only_theirs", 0}, {"changed_this", 0}, {"changed_theirs", 0}, {"changed_both", 0},
                {"differs", 0}, {"total", 0}, {"same", 0}};
    const auto bump = [&](const std::string& k) { counts[k] = counts[k].get<uint64_t>() + 1; };
    const bool bothBases = a.base && b.base;
    for (const auto& uid : uids) {
        const auto ia = a.entries.find(uid);
        const auto ib = b.entries.find(uid);
        const json curA = ia != a.entries.end() ? ia->second.first : json(nullptr);
        const json curB = ib != b.entries.end() ? ib->second.first : json(nullptr);
        const std::optional<std::string> baseA = ia != a.entries.end() ? ia->second.second : std::nullopt;
        const std::optional<std::string> baseB = ib != b.entries.end() ? ib->second.second : std::nullopt;
        for (const auto* st : {&curA, &curB})
            if (relinkIsFile(*st) && st->value("key_version", uint64_t{0}) > 0 && !relinkStr(*st, "generation").empty())
                used.insert(st->value("key_version", uint64_t{0}));
        if (curA.is_null() && curB.is_null()) continue;
        if (!curA.is_null() && !curB.is_null() && relinkStr(curA, "hash") == relinkStr(curB, "hash")) {
            bump("same");
            continue;
        }
        const bool known = bothBases && ((baseA && baseB && *baseA == *baseB) || (!baseA && !baseB));
        const auto hashOr = [](const json& st) { return st.is_null() ? std::optional<std::string>() : relinkStr(st, "hash"); };
        const bool changedA = known && hashOr(curA) != baseA;
        const bool changedB = known && hashOr(curB) != baseB;
        mq::RelinkEntry e;
        e.uid = uid;
        e.this_state = curA;
        e.theirs_state = curB;
        e.path = !curA.is_null() ? relinkStr(curA, "path") : relinkStr(curB, "path");
        const auto by = [&] {
            return changedA && changedB ? std::string("by_both") : changedA ? std::string("by_this") : std::string("by_theirs");
        };
        if (curB.is_null()) {
            e.kind = "only_this";
            if (known) e.aspects = {curA.is_null() ? "removed" : (baseA ? "removed" : "created"), by()};
        } else if (curA.is_null()) {
            e.kind = "only_theirs";
            if (known) e.aspects = {baseB ? "removed" : "created", by()};
        } else {
            e.kind = !known ? "differs" : changedA && changedB ? "changed_both" : changedA ? "changed_this" : "changed_theirs";
            if (relinkTrashed(curA) != relinkTrashed(curB)) e.aspects.emplace_back("trashed");
            if (relinkPlaceDiffers(curA, curB) || (relinkTrashed(curA) && relinkTrashed(curB) &&
                                                   relinkStr(curA, "path") != relinkStr(curB, "path")))
                e.aspects.emplace_back("place");
            if (relinkStr(curA, "generation") != relinkStr(curB, "generation") ||
                curA.value("size", uint64_t{0}) != curB.value("size", uint64_t{0}) ||
                relinkStr(curA, "content_hash") != relinkStr(curB, "content_hash"))
                e.aspects.emplace_back("contents");
            if (relinkStr(curA, "target") != relinkStr(curB, "target")) e.aspects.emplace_back("target");
            if (e.aspects.empty()) e.aspects.emplace_back("attributes");
        }
        bump(e.kind);
        bump("total");
        drift.push_back(std::move(e));
    }
    mq::Relinks::addEntries(row.id, drift);
    const auto keys = relinkKeys(mine.state, theirs, used);
    auto blockers = relinkBlockers(mine.state, theirs, keys);
    const auto subset = [](const json& st) {
        json o = st;
        o.erase("keys");
        return o;
    };
    json summary{{"peer", {{"id", peer.id}, {"name", peer.name}, {"node", peer.node_id}}},
                 {"this", subset(mine.state)}, {"theirs", subset(theirs)}, {"counts", counts}, {"keys", keys},
                 {"base", {{"this", a.baseInfo}, {"theirs", b.baseInfo}, {"both", bothBases}}},
                 {"blockers", blockers}};
    mq::Relinks::setSummary(row.id, summary);
    return relinkStatusOf(*mq::Relinks::get(row.id));
}

json relinkApplyOpen(const uint32_t vaultId, const Who& who, vh::mirror::follow::Transport& transport) {
    relinkExpire();
    std::scoped_lock carry(relinkCarryMutex());
    auto r = mq::Relinks::openOf(vaultId);
    if (!r || r->side != "initiator" || !(r->phase == "open" || r->phase == "proposed" || r->phase == "approved")) {
        if (r && r->side == "responder")
            throw vh::ops::Refused("mirror_relink_no_plan", "server '" + relinkPeerName(*r) + "' asked for this relink: "
                                                            "its plan is applied from there, once approved here");
        if (r && (r->phase == "requested" || r->phase == "accepted"))
            throw vh::ops::Refused("mirror_relink_no_plan",
                                   r->phase == "requested"
                                       ? "server '" + relinkPeerName(*r) + "'s super admin has not accepted the relink yet"
                                       : std::string("the other server accepted the relink: compare the vault first"));
        throw vh::ops::Refused("mirror_relink_no_plan", r ? "the vault's relink is " + r->phase + " already"
                                                          : "compare the vault with the other server first");
    }
    const auto peer = relinkLinked(r->peer_id, transport);
    const auto vaultUid = relinkVaultUid(vaultId);
    const auto mine = relinkLocal(vaultId, peer.node_id);
    const auto theirs = relinkAsk(transport, r->peer_id, "peer.mirror.relink.state",
                                  {{"vault_uid", vaultUid}, {"relink_uid", r->relink_uid}});
    if (!theirs.value("accepted", false)) {
        const auto why = "server '" + peer.name + "' no longer accepts this relink (declined, cancelled or expired there): "
                         "compare again to ask again";
        (void)mq::Relinks::setPhase(r->id, relinkAsking(), "cancelled", why);
        throw vh::ops::Refused("mirror_relink_not_accepted", why);
    }
    const auto keys = r->summary.contains("keys") ? r->summary["keys"] : json{{"match", false}};
    const auto blockers = relinkBlockers(mine.state, theirs, keys);
    if (!blockers.empty())
        throw vh::ops::Refused(blockers[0].value("code", std::string("mirror_relink_refused")),
                               blockers[0].value("message", std::string{}));
    // A tree that changed under the plan: compare again (an approval of it is void).
    const auto changed = [](const json& now, const std::optional<vh::mirror::Digest>& then,
                            const std::optional<std::string>& status) {
        return !then || now.value("digest", std::string{}) != then->hex() || now.value("entries", int64_t{0}) != then->entries ||
               now.value("status", std::string{}) != status.value_or("");
    };
    const bool hereChanged = changed(mine.state, r->this_digest, r->this_status);
    const bool thereChanged = changed(theirs, r->theirs_digest, r->theirs_status);
    const auto goStale = [&](const std::string& why) {
        (void)mq::Relinks::setPhase(r->id, {"open", "proposed", "approved"}, "stale", why);
        relinkTell(transport, *r, "peer.mirror.relink.propose", {{"withdraw", true}, {"why", why}});
        return vh::ops::Refused("mirror_relink_stale", why);
    };
    if (hereChanged || thereChanged) {
        const auto where = hereChanged && thereChanged ? std::string("on both servers")
                           : hereChanged              ? std::string("on this server")
                                                      : "on server '" + peer.name + "'";
        throw goStale("the vault changed " + where + " since it was compared: the plan no longer describes it; compare "
                      "again");
    }
    const json by = relinkPersonJson(who);

    // The outcome goes to the other server's super admin; it is carried out once approved there.
    auto proposal = relinkProposalOf(*r, by);
    const auto hash = proposal["plan_hash"].get<std::string>();
    const bool asked = r->proposal.is_object() && r->proposal.value("plan_hash", std::string{}) == hash;
    if (!asked) {
        (void)mq::Relinks::propose(r->id, {"open", "proposed", "approved"}, proposal);
        r = mq::Relinks::get(r->id);
        relinkAudit("mirror.relink.propose", *r, by,
                    {{"plan_hash", hash}, {"core", r->core}, {"to", peer.name}},
                    fmt::format("[mirror] {} proposed the relink {} of vault {} to linked server '{}' ({} the core, {}): "
                                "it is carried out once that server's super admin approves it",
                                who.name.empty() ? std::string("someone") : who.name, r->relink_uid, vaultId, peer.name,
                                r->core == "this" ? std::string("this server") : "server '" + peer.name + "'", r->mode));
    } else {
        proposal = r->proposal;
    }
    json answer;
    try {
        answer = relinkAsk(transport, r->peer_id, "peer.mirror.relink.propose",
                           {{"vault_uid", vaultUid}, {"relink_uid", r->relink_uid}, {"proposal", proposal}});
    } catch (const vh::ops::Refused& e) {
        if (e.code == "mirror_relink_stale") throw goStale(e.what());
        throw;
    }
    const auto theirPhase = relinkStr(answer, "phase");
    if (theirPhase != "approved" || relinkStr(answer, "plan_hash") != hash) {
        if (theirPhase == "declined" || theirPhase == "cancelled" || theirPhase == "expired")
            (void)mq::Relinks::setPhase(r->id, relinkAsking(), theirPhase,
                                        "server '" + peer.name + "' answered the outcome: " + theirPhase);
        else if (r->phase == "approved")
            (void)mq::Relinks::propose(r->id, {"approved"}, proposal);   // waits for the approval again
        return relinkStatusOf(*mq::Relinks::get(r->id));
    }
    if (r->phase == "proposed") (void)mq::Relinks::approve(r->id, relinkStr(answer, "approved_by"), hash);
    r = mq::Relinks::get(r->id);
    if (!r || r->phase != "approved") throw vh::ops::Conflict("the relink changed while it was being applied");

    // Approved on both: carried out.
    const auto term = std::max(mine.state.value("term", uint64_t{0}), theirs.value("term", uint64_t{0})) + 1;
    const bool coreHere = r->core == "this";
    const json theirDigest{{"digest", r->theirs_digest->hex()}, {"entries", r->theirs_digest->entries}};
    if (coreHere) {
        try {
            relinkSendPrepare(transport, *r, vaultUid, "mirror", term, by, theirDigest);
        } catch (const vh::ops::Refused& e) {
            // Nothing changed here yet: an approval the other server voided is asked again.
            if (e.code == "mirror_relink_stale") throw goStale(e.what());
            if (e.code == "mirror_relink_not_approved")
                (void)mq::Relinks::unapprove(r->id, {"approved"}, "open", e.what());
            throw;
        }
        try {
            relinkPrepareCore(*r, r->peer_id, term, by);
        } catch (const std::exception& e) {
            (void)transport.request(r->peer_id, "peer.mirror.relink.abort",
                                    {{"vault_uid", vaultUid}, {"relink_uid", r->relink_uid}, {"why", e.what()}});
            (void)mq::Relinks::setPhase(r->id, {"approved", "prepared", "copying"}, "failed", e.what());
            throw;
        }
        const auto told = transport.request(r->peer_id, "peer.mirror.relink.go",
                                            {{"vault_uid", vaultUid}, {"relink_uid", r->relink_uid}});
        if (!told || !told->ok)
            vh::log::Registry::sync()->warn("[MirrorRelink] Vault {}: the mirror was not told to go ({}); it waits stopped "
                                            "and `vh mirror resync` on it starts its copy",
                                            vaultId, told ? told->error : std::string("no answer"));
    } else {
        relinkPrepareMirror(*r, r->peer_id, term, by);
        try {
            relinkSendPrepare(transport, *mq::Relinks::get(r->id), vaultUid, "core", term, by, theirDigest);
        } catch (const std::exception& e) {
            relinkAbortLocal(*mq::Relinks::get(r->id), e.what());
            throw;
        }
        relinkGo(*mq::Relinks::get(r->id));
    }
    r = mq::Relinks::get(r->id);
    relinkAudit("mirror.relink", *r, by, {{"core", coreHere ? "this" : "theirs"}, {"entries", r->summary.value("counts", json::object()).value("total", 0)},
                                          {"approved_by", r->approved_by.value_or("")}},
                fmt::format("[mirror] {} relinked vault {} with linked server {} (relink {}, approved there by {}): {} is "
                            "its core in term {}, the other its mirror; what the mirror held that differs is kept as held "
                            "changes",
                            who.name.empty() ? std::string("someone") : who.name, vaultId, r->peer_id, r->relink_uid,
                            r->approved_by.value_or("its super admin"),
                            coreHere ? std::string("this server") : "server '" + peer.name + "'", term));
    return relinkStatusOf(*r);
}

// ---- the future mirror's pass: bringing its versions onto the core ------------------------------------------------------

enum class Brought { Done, Wait };

Brought relinkBringOne(const mq::Relink& r, json& op, const std::string& vaultUid, const uint32_t peerId,
                       const Who& person, vh::mirror::follow::Transport& t,
                       const std::chrono::steady_clock::time_point deadline) {
    const auto uid = op.at("uid").get<std::string>();
    const auto kind = op.at("op").get<std::string>();
    // Which drifted entry it records the outcome on (a conflict copy's on the entry it copies).
    std::string entryUid = uid;
    if (const auto note = op.value("note", std::string{}); note.starts_with("the conflict copy of "))
        entryUid = note.substr(std::string("the conflict copy of ").size());
    if (!op.contains("request_id")) op["request_id"] = vh::mirror::submit::newRequestId();
    const auto rid = op["request_id"].get<std::string>();
    auto args = op.at("args");
    const auto finish = [&](const std::string& outcome, const std::string& note) {
        op["outcome"] = outcome;
        mq::Relinks::setOutcome(r.id, entryUid, rid, outcome, note);
        return Brought::Done;
    };
    if (kind == "write" && args.value("size", uint64_t{0}) > 0 && !op.value("sent", false)) {
        const auto f = relinkFileHere(r.vault_id, uid);
        if (!f || f->generation != args.value("generation", std::string{}))
            return finish("kept", "the file changed here before it was brought over; this version is kept");
        const vh::mirror::follow::Transport::Content content{
            .vault_uid = vaultUid, .object_uid = uid, .generation = f->generation, .key_version = f->key_version,
            .size = f->size, .content_hash = f->content_hash, .path = f->backing.string()};
        const auto sent = t.sendContent(peerId, content);
        if (!sent.ok) {
            if (sent.retry) return Brought::Wait;
            return finish("refused", (sent.code.empty() ? std::string("invalid_contents") : sent.code) + ": " + sent.error);
        }
        op["sent"] = true;
    }
    json payload{{"vault_uid", vaultUid}, {"request_id", rid}, {"person", {{"node", relinkOwnNode()}, {"id", person.id}}},
                 {"at", {{"term", r.term.value_or(1)}, {"seq", 0}}}, {"op", kind}, {"entry_uid", uid}, {"args", args}};
    if (args.contains("base") && args["base"].is_string()) payload["base_generation"] = args["base"];
    while (true) {
        const auto a = t.request(peerId, "peer.mirror.submit", payload);
        if (!a) return Brought::Wait;
        if (!a->ok) {
            if (a->code == "contents_missing") {
                op["sent"] = false;
                return Brought::Wait;
            }
            if (a->code == "not_found" || a->code == "mirror_not_live" || a->code == "peer_revoked") return Brought::Wait;
            return finish("refused", a->code + ": " + a->error);
        }
        const auto status = a->data.value("status", std::string{});
        if (status == "executed") return finish("executed", "");
        if (status == "refused")
            return finish("refused", a->data.value("code", std::string("refused")) + ": " +
                                         a->data.value("error", std::string{}));
        if (std::chrono::steady_clock::now() + std::chrono::milliseconds(50) >= deadline) return Brought::Wait;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

bool relinkBring(const mq::Relink& r, vh::mirror::follow::Transport& t) {
    const auto mv = mq::MirrorVaults::get(r.vault_id);
    if (!mv || mv->role != "mirror") {
        (void)mq::Relinks::setPhase(r.id, {"bring"}, "failed", "the vault's mirror row went before its changes were brought");
        return true;
    }
    if (!t.connected(mv->peer_id)) return false;
    const auto vaultUid = mq::MirrorVaults::vaultUidOf(r.vault_id);
    if (!vaultUid) return false;
    auto summary = r.summary;
    auto& bring = summary["bring"];
    auto at = summary.value("bring_at", uint64_t{0});
    const Who person{.id = summary.contains("person") ? summary["person"].value("id", 0u) : 0u,
                     .name = summary.contains("person") ? summary["person"].value("name", std::string{}) : std::string{}};
    const auto deadline = std::chrono::steady_clock::now() + kStepBudget;
    bool moved = false;
    while (at < bring.size() && std::chrono::steady_clock::now() < deadline) {
        auto& op = bring[at];
        const auto done = relinkBringOne(r, op, *vaultUid, mv->peer_id, person, t, deadline);
        summary["bring_at"] = at;
        mq::Relinks::setSummary(r.id, summary);
        if (done == Brought::Wait) return moved;
        // A place the core refused: kept where this server had it (the copy moves it to the core's).
        if (op.value("outcome", std::string{}) == "refused" && op.value("op", std::string{}) == "move") {
            const auto e = mq::Relinks::entry(r.id, op.at("uid").get<std::string>());
            if (e && relinkLive(e->this_state))
                vh::db::Transactions::exec("mirror::relink keep place", [&](pqxx::work& txn) {
                    relinkHold(txn, r.vault_id, e->uid, "move",
                               {{"parent_uid", e->this_state["parent"]}, {"name", relinkStr(e->this_state, "name")}},
                               relinkStr(e->this_state, "path"), {.node = relinkOwnNode(), .id = person.id},
                               "mirror_relink_refused", "the core refused this server's place for the entry", {});
                });
        }
        ++at;
        moved = true;
    }
    summary["bring_at"] = at;
    mq::Relinks::setSummary(r.id, summary);
    if (at < bring.size()) return moved;
    // Everything brought: the copy starts over from the core's tree as it is now (which holds them).
    try {
        (void)vh::mirror::resync::start(r.vault_id, person.id, person.name, t);
    } catch (const vh::ops::Refused& e) {
        if (e.code == "mirror_core_unreachable") return moved;
        (void)mq::Relinks::setPhase(r.id, {"bring"}, "failed", std::string(e.code) + ": " + e.what());
        return true;
    }
    (void)mq::Relinks::setPhase(r.id, {"bring"}, "copying");
    return true;
}

bool relinkCopying(const mq::Relink& r) {
    const auto mv = mq::MirrorVaults::get(r.vault_id);
    const auto role = r.role.value_or("");
    const json by{{"node", r.by_node.value_or("")}, {"id", r.by_id ? json(*r.by_id) : json(nullptr)},
                  {"name", r.by_name.value_or("")}};
    if (!mv || mv->role != role) {
        (void)mq::Relinks::setPhase(r.id, {"copying"}, "failed", "the vault's mirror row went before its copy completed");
        return true;
    }
    bool done = false;
    if (role == "mirror") {
        if (mv->state == "live" && mv->copy_finished) done = true;
        else if (mv->state != "live" && mv->stop_reason.value_or("") != "mirror_relinking") {
            (void)mq::Relinks::setPhase(r.id, {"copying"}, "failed",
                                        "the copy stopped (" + mv->state + ", " + mv->stop_reason.value_or("") +
                                            "): `vh mirror resync` starts it again");
            return true;
        }
    } else if (mv->state == "live" && mv->acked && (!mv->baseline || *mv->acked >= *mv->baseline)) {
        // The core: its mirror acknowledged the baseline (or later) with an equal digest.
        done = true;
    }
    if (!done) return false;
    if (!mq::Relinks::setPhase(r.id, {"copying"}, "done")) return false;
    relinkAudit("mirror.relink.done", r, by, {{"digest", mv->digest.hex()}},
                fmt::format("[mirror] vault {}: the relink {} completed: this server is its {} in term {}, both trees "
                            "equal",
                            r.vault_id, r.relink_uid, role, mv->term));
    return true;
}

}

// ---- the person's commands -----------------------------------------------------------------------------------------------

json compare(const uint32_t vaultId, const uint32_t peerId, const Who& who, vh::mirror::follow::Transport& transport) {
    return relinkCompareInto(vaultId, peerId, who, transport, "plan", "this");
}

json status(const uint32_t vaultId) {
    relinkExpire();
    const auto r = mq::Relinks::openOf(vaultId);
    const auto latest = r ? r : mq::Relinks::latestOf(vaultId);
    if (!latest) return {{"vault_id", vaultId}, {"relink", nullptr}};
    return relinkStatusOf(*latest);
}

json entries(const uint32_t vaultId, const std::string& kind, const uint64_t offset, const uint64_t limit) {
    static const std::set<std::string> kinds{"", "only_this", "only_theirs", "changed_this", "changed_theirs",
                                             "changed_both", "differs"};
    if (!kinds.contains(kind)) throw vh::ops::Invalid("kind is one of only_this, only_theirs, changed_this, changed_theirs, "
                                                      "changed_both, differs");
    const auto r = mq::Relinks::openOf(vaultId) ? mq::Relinks::openOf(vaultId) : mq::Relinks::latestOf(vaultId);
    if (!r) throw vh::ops::NotFound("no relink of this vault here: compare it first");
    uint64_t total = 0;
    json list = json::array();
    for (const auto& e : mq::Relinks::page(r->id, kind, offset, std::clamp<uint64_t>(limit, 1, 500), total))
        list.push_back(relinkEntryJson(e, *r));
    return {{"vault_id", vaultId}, {"relink_id", r->id}, {"total", total}, {"offset", offset}, {"entries", list}};
}

json plan(const uint32_t vaultId, const PlanEdit& edit, vh::mirror::follow::Transport& transport) {
    relinkExpire();
    const auto r = mq::Relinks::openOf(vaultId);
    if (edit.discard) {
        if (!r || r->side != "initiator" || !r->handshaking())
            throw vh::ops::Refused("mirror_relink_no_plan", r ? "the vault's relink is " + r->phase + ": it can no longer "
                                                                "be discarded here"
                                                              : "the vault has no relink to discard");
        (void)mq::Relinks::setPhase(r->id, relinkAsking(), "cancelled", "discarded");
        relinkTell(transport, *r, "peer.mirror.relink.cancel", {{"why", "discarded by a super admin of the other server"}});
        relinkAudit("mirror.relink.cancel", *r, json{{"node", relinkOwnNode()}}, {},
                    fmt::format("[mirror] the relink {} of vault {} with linked server {} was discarded here; neither "
                                "vault changed",
                                r->relink_uid, vaultId, r->peer_id));
        return relinkStatusOf(*mq::Relinks::get(r->id));
    }
    if (!r || r->side != "initiator" || !(r->phase == "open" || r->phase == "proposed" || r->phase == "approved"))
        throw vh::ops::Refused("mirror_relink_no_plan", r ? "the vault's relink is " + r->phase + ": it can not be changed now"
                                                          : "compare the vault with the other server first");
    static const std::set<std::string> sides{"this", "theirs"};
    static const std::set<std::string> choices{"this", "theirs", "both"};
    if (edit.core && !sides.contains(*edit.core)) throw vh::ops::Invalid("core is this or theirs");
    if (edit.default_choice && !edit.default_choice->empty() && !choices.contains(*edit.default_choice))
        throw vh::ops::Invalid("default is this, theirs or both");
    const auto fileOnly = [](const mq::RelinkEntry& e) {
        return relinkIsFile(e.this_state) || relinkIsFile(e.theirs_state);
    };
    for (const auto& one : edit.set) {
        if (one.choice && !choices.contains(*one.choice)) throw vh::ops::Invalid("a choice is this, theirs or both");
        const auto e = mq::Relinks::entry(r->id, one.uid);
        if (!e) throw vh::ops::NotFound("the plan holds no drifted entry " + one.uid);
        if (one.choice && *one.choice == "both" && !fileOnly(*e))
            throw vh::ops::Invalid("both versions are kept for files only; a folder's place is one or the other");
    }
    for (const auto& k : edit.by_kind)
        if (k.choice && !choices.contains(*k.choice)) throw vh::ops::Invalid("a choice is this, theirs or both");
    mq::Relinks::setPlan(r->id, edit.core,
                         edit.default_choice && !edit.default_choice->empty() ? edit.default_choice : std::nullopt,
                         edit.default_choice && edit.default_choice->empty());
    for (const auto& k : edit.by_kind) {
        if (k.choice && *k.choice == "both") {
            // Files only: a folder keeps the default.
            for (const auto& e : mq::Relinks::entries(r->id))
                if ((k.kind.empty() || e.kind == k.kind) && fileOnly(e)) (void)mq::Relinks::setChoice(r->id, e.uid, k.choice);
        } else {
            (void)mq::Relinks::setChoiceByKind(r->id, k.kind, k.choice);
        }
    }
    for (const auto& one : edit.set) (void)mq::Relinks::setChoice(r->id, one.uid, one.choice);
    // A plan proposed (or approved) and changed since: the other server is asked again.
    if (r->phase != "open") {
        const auto now = relinkProposalOf(*mq::Relinks::get(r->id), json::object());
        if (now.value("plan_hash", std::string{}) != r->proposal.value("plan_hash", std::string{})) {
            const auto why = std::string("the plan changed after it was proposed: the other server's approval is void; "
                                         "propose it again");
            (void)mq::Relinks::unapprove(r->id, {"proposed", "approved"}, "open", why);
            relinkTell(transport, *r, "peer.mirror.relink.propose", {{"withdraw", true}, {"why", why}});
        }
    }
    return relinkStatusOf(*mq::Relinks::get(r->id));
}

json apply(const uint32_t vaultId, const std::string& confirm, const Who& who, vh::mirror::follow::Transport& transport) {
    relinkRequireConfirm(vaultId, confirm);
    return relinkApplyOpen(vaultId, who, transport);
}

json override(const uint32_t vaultId, const uint32_t peerId, const std::string& keep, const std::string& confirm,
              const Who& who, vh::mirror::follow::Transport& transport) {
    if (keep != "this" && keep != "theirs") throw vh::ops::Invalid("keep is this or theirs");
    relinkRequireConfirm(vaultId, confirm);
    const auto compared = relinkCompareInto(vaultId, peerId, who, transport, "override", keep);
    // Asked and not accepted yet (or declined): the answer is the relink as it stands.
    if (!compared.at("relink").is_object() || compared.at("relink").value("phase", std::string{}) != "open")
        return compared;
    if (const auto& b = compared.at("blockers"); !b.empty())
        throw vh::ops::Refused(b[0].value("code", std::string("mirror_relink_refused")),
                               b[0].value("message", std::string{}));
    return relinkApplyOpen(vaultId, who, transport);
}

// ---- the other server's super admin ---------------------------------------------------------------------------------------

namespace {

json relinkRequestJson(const mq::Relink& r) {
    const auto vault = vh::db::query::vault::Vault::getVault(r.vault_id);
    const auto peer = vh::db::query::peer::Peers::byId(r.peer_id);
    return {{"vault_id", r.vault_id},
            {"vault_name", vault ? vault->name : std::string{}},
            {"relink_uid", r.relink_uid},
            {"phase", r.phase},
            {"peer", {{"id", r.peer_id}, {"name", peer ? peer->name : relinkPeerName(r)},
                      {"node", peer ? peer->node_id : std::string{}}}},
            {"asked_by", r.by_name.value_or("")},
            {"status", r.this_status.value_or("")},
            {"created_at", static_cast<int64_t>(r.created_at)},
            {"handshake", relinkHandshakeJson(r)}};
}

mq::Relink relinkAsked(const uint32_t vaultId, const std::vector<std::string>& phases, const std::string& none) {
    relinkExpire();
    const auto r = mq::Relinks::openOf(vaultId);
    if (!r || r->side != "responder" || std::ranges::find(phases, r->phase) == phases.end())
        throw vh::ops::Refused("mirror_relink_no_request",
                               r && r->side == "responder" ? "the vault's relink is " + r->phase + ": " + none : none);
    return *r;
}

}

json requests() {
    relinkExpire();
    json out = json::array();
    for (const auto& r : mq::Relinks::requests()) out.push_back(relinkRequestJson(r));
    return out;
}

json accept(const uint32_t vaultId, const Who& who, vh::mirror::follow::Transport& transport) {
    const auto r = relinkAsked(vaultId, {"requested"}, "no relink request for this vault waits here (vh mirror pending)");
    if (!mq::Relinks::accept(r.id, {"requested"}, who.name,
                             std::chrono::duration_cast<std::chrono::seconds>(kRequestHolds)))
        throw vh::ops::Conflict("the request changed while it was being accepted");
    const auto now = *mq::Relinks::get(r.id);
    relinkAudit("mirror.relink.accept", now, relinkPersonJson(who), {{"from", relinkPeerName(now)}},
                fmt::format("[mirror] {} accepted linked server '{}''s request to relink vault {} (relink {}): it may "
                            "compare the two trees (names, places and hashes; no contents); nothing changes here until an "
                            "outcome is approved",
                            who.name.empty() ? std::string("someone") : who.name, relinkPeerName(now), vaultId,
                            now.relink_uid));
    relinkTell(transport, now, "peer.mirror.relink.answer", {{"answer", "accepted"}, {"by", who.name}});
    return relinkRequestJson(now);
}

json decline(const uint32_t vaultId, const Who& who, vh::mirror::follow::Transport& transport) {
    const auto r = relinkAsked(vaultId, {"requested", "accepted", "proposed", "approved"},
                               "no relink of this vault waits here (vh mirror pending)");
    if (!mq::Relinks::setPhase(r.id, {"requested", "accepted", "proposed", "approved"}, "declined",
                               "declined by " + (who.name.empty() ? std::string("a super admin") : who.name)))
        throw vh::ops::Conflict("the relink changed while it was being declined");
    const auto now = *mq::Relinks::get(r.id);
    relinkAudit("mirror.relink.decline", now, relinkPersonJson(who), {{"from", relinkPeerName(now)}, {"was", r.phase}},
                fmt::format("[mirror] {} declined linked server '{}''s relink of vault {} (relink {}, {}); neither vault "
                            "changed",
                            who.name.empty() ? std::string("someone") : who.name, relinkPeerName(now), vaultId,
                            now.relink_uid, r.phase));
    relinkTell(transport, now, "peer.mirror.relink.answer", {{"answer", "declined"}, {"by", who.name}});
    return relinkRequestJson(now);
}

json approve(const uint32_t vaultId, const std::string& confirm, const Who& who, vh::mirror::follow::Transport& transport) {
    relinkRequireConfirm(vaultId, confirm);
    const auto r = relinkAsked(vaultId, {"proposed"}, "no relink outcome waits for approval for this vault");
    const auto& p = r.proposal;
    // The tree here is still the one the outcome was compared against.
    const auto digest = mq::Relinks::digest(vaultId);
    const auto seen = p.contains("digest") ? p["digest"] : json::object();
    if (seen.value("digest", std::string{}) != digest.hex() || seen.value("entries", int64_t{0}) != digest.entries) {
        const auto why = std::string("the vault changed here since the other server compared it: the outcome no longer "
                                     "describes it; it is asked again once compared again");
        (void)mq::Relinks::unapprove(r.id, {"proposed"}, "accepted", why);
        relinkTell(transport, r, "peer.mirror.relink.answer", {{"answer", "voided"}, {"why", why}});
        throw vh::ops::Refused("mirror_relink_stale", why);
    }
    const auto hash = p.value("plan_hash", std::string{});
    if (!mq::Relinks::approve(r.id, who.name, hash))
        throw vh::ops::Conflict("the outcome changed while it was being approved: look at it again");
    auto summary = r.summary;
    summary["approver"] = {{"id", who.id}, {"name", who.name}};
    mq::Relinks::setSummary(r.id, summary);
    const auto now = *mq::Relinks::get(r.id);
    relinkAudit("mirror.relink.approve", now, relinkPersonJson(who),
                {{"from", relinkPeerName(now)}, {"plan_hash", hash}, {"core", p.value("core", std::string{})},
                 {"mode", p.value("mode", std::string{})}, {"gains", p.contains("this") ? p["this"] : json(nullptr)}},
                fmt::format("[mirror] {} approved linked server '{}''s relink of vault {} (relink {}): {}",
                            who.name.empty() ? std::string("someone") : who.name, relinkPeerName(now), vaultId,
                            now.relink_uid, relinkOutcomeText(p, relinkPeerName(now))));
    relinkTell(transport, now, "peer.mirror.relink.answer",
               {{"answer", "approved"}, {"by", who.name}, {"plan_hash", hash}});
    return relinkRequestJson(now);
}

std::size_t tick(vh::mirror::follow::Transport& transport) {
    std::size_t n = 0;
    // Requests and acceptances past their time, once a minute (every read of them expires them too).
    static std::atomic<int64_t> lastExpired{0};
    const auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
    if (auto last = lastExpired.load(); nowSec - last >= 60 && lastExpired.compare_exchange_strong(last, nowSec)) try {
            relinkExpire();
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorRelink] Expiring requests: {}", e.what());
        }
    for (const auto& r : mq::Relinks::inPhase("bring")) {
        try {
            if (r.role.value_or("") == "mirror" && relinkBring(r, transport)) ++n;
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorRelink] Vault {}: bringing its changes failed: {}", r.vault_id, e.what());
        }
    }
    for (const auto& r : mq::Relinks::inPhase("copying")) {
        try {
            if (relinkCopying(r)) ++n;
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorRelink] Vault {}: {}", r.vault_id, e.what());
        }
    }
    // An outcome the other server's super admin approved: carried out by this server, which asked for it (last: what
    // it starts moves on at the next pass).
    for (const auto& r : mq::Relinks::inPhase("approved")) {
        if (r.side != "initiator") continue;
        const auto by = r.proposal.contains("by") && r.proposal["by"].is_object() ? r.proposal["by"] : json::object();
        const Who who{.id = by.contains("id") && by["id"].is_number_unsigned() ? by["id"].get<uint32_t>() : 0u,
                      .name = by.value("name", std::string{})};
        try {
            (void)relinkApplyOpen(r.vault_id, who, transport);
            ++n;
        } catch (const vh::ops::Refused& e) {
            if (e.code == "mirror_core_unreachable" || e.code == "peer_link_down") continue;   // the next pass
            // Anything else waits for a person here (apply again); the reason is kept.
            if (mq::Relinks::propose(r.id, {"approved"}, r.proposal))
                (void)mq::Relinks::setPhase(r.id, {"proposed"}, "proposed", std::string(e.code) + ": " + e.what());
            vh::log::Registry::sync()->warn("[MirrorRelink] Vault {}: the approved relink was not carried out: {}",
                                            r.vault_id, e.what());
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorRelink] Vault {}: carrying the approved relink out: {}", r.vault_id,
                                            e.what());
        }
    }
    return n;
}

// ---- the wire ------------------------------------------------------------------------------------------------------------

json serveRequest(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto mine = relinkLocal(vaultId, peer.node_id);
    if (!mine.related) throw vh::ops::NotFound("this server has no record of mirroring that vault with the asking server");
    relinkExpire();
    const auto uid = relinkUidField(payload, "relink_uid");
    const json by = payload.contains("by") && payload["by"].is_object() ? payload["by"] : json::object();
    auto r = mq::Relinks::byUid(vaultId, uid);
    if (r && (r->side != "responder" || r->peer_id != callerPeerId)) throw vh::ops::Conflict("no such relink here");
    if (!r) {
        if (const auto open = mq::Relinks::openOf(vaultId)) {
            if (open->side == "initiator" || !open->handshaking())
                throw vh::ops::Refused("mirror_relink_running",
                                       open->side == "initiator"
                                           ? std::string("this server's super admin is relinking the vault already: "
                                                         "answer that request instead")
                                           : "a relink of this vault is being applied here (" + open->phase + ")");
            if (open->peer_id != callerPeerId)
                throw vh::ops::Refused("mirror_relink_running", "another linked server's relink of this vault waits here");
        }
        mq::NewRelink n;
        n.relink_uid = uid;
        n.vault_id = vaultId;
        n.peer_id = callerPeerId;
        n.side = "responder";
        n.phase = "requested";
        n.this_status = mine.state.value("status", std::string{});
        n.by_node = by.value("node", std::string{}).substr(0, 64);
        if (by.contains("id") && by["id"].is_number_unsigned()) n.by_id = by["id"].get<uint32_t>();
        n.by_name = by.value("name", std::string{}).substr(0, 255);
        n.expires_at = relinkNow() + std::chrono::duration_cast<std::chrono::seconds>(kRequestHolds).count();
        n.summary = {{"peer", {{"id", peer.id}, {"name", peer.name}, {"node", peer.node_id}}}};
        r = mq::Relinks::create(n);   // replaces the same server's older request
        relinkAudit("mirror.relink.request", *r, json{{"name", *n.by_name}}, {{"from", peer.name}},
                    fmt::format("[mirror] linked server '{}' ({}) asks to relink vault {} (relink {}): nothing of its tree "
                                "is shown to it until a super admin here accepts (vh mirror pending)",
                                peer.name, n.by_name->empty() ? std::string("someone") : *n.by_name, vaultId, uid));
    }
    return relinkAnswerOf(*r);
}

json serveAnswer(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto r = mq::Relinks::byUid(vaultId, relinkUidField(payload, "relink_uid"));
    if (!r || r->side != "initiator" || r->peer_id != callerPeerId) throw vh::ops::NotFound("no such relink here");
    const auto answer = relinkStr(payload, "answer");
    const auto by = relinkStr(payload, "by").substr(0, 255);
    bool moved = false;
    if (answer == "accepted") {
        moved = mq::Relinks::accept(r->id, {"requested"}, by, std::chrono::duration_cast<std::chrono::seconds>(kRequestHolds));
    } else if (answer == "approved") {
        moved = r->phase == "proposed" && mq::Relinks::approve(r->id, by, relinkStr(payload, "plan_hash"));
        if (moved) vh::mirror::follow::Follower::instance()->wake(r->vault_id);   // the pass carries it out
    } else if (answer == "declined") {
        moved = mq::Relinks::setPhase(r->id, relinkAsking(), "declined",
                                      "server '" + peer.name + "'s super admin" + (by.empty() ? "" : " (" + by + ")") +
                                          " declined the relink");
    } else if (answer == "voided") {
        moved = mq::Relinks::unapprove(r->id, {"proposed", "approved"}, "open",
                                       "server '" + peer.name + "' voided the proposal: " +
                                           relinkStr(payload, "why").substr(0, 400));
    } else {
        throw vh::ops::Invalid("answer is accepted, approved, declined or voided");
    }
    if (moved)
        relinkAudit("mirror.relink.answer", *mq::Relinks::get(r->id), json{{"name", by}},
                    {{"answer", answer}, {"from", peer.name}},
                    fmt::format("[mirror] linked server '{}' answered the relink {} of vault {}: {}{}", peer.name,
                                r->relink_uid, vaultId, answer, by.empty() ? std::string{} : " (" + by + ")"));
    return {{"phase", mq::Relinks::get(r->id)->phase}};
}

json servePropose(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto r = relinkAccepted(vaultId, payload, callerPeerId);
    if (payload.value("withdraw", false)) {
        if (mq::Relinks::unapprove(r.id, {"proposed", "approved"}, "accepted",
                                   "the other server withdrew its proposal: " + relinkStr(payload, "why").substr(0, 400)))
            relinkAudit("mirror.relink.withdrawn", r, json::object(), {{"from", peer.name}},
                        fmt::format("[mirror] linked server '{}' withdrew its proposal for the relink {} of vault {}",
                                    peer.name, r.relink_uid, vaultId));
        return relinkAnswerOf(*mq::Relinks::get(r.id));
    }
    const auto in = payload.contains("proposal") && payload["proposal"].is_object() ? payload["proposal"] : json::object();
    static const std::regex hex("^[0-9a-f]{64}$");
    const auto hash = relinkStr(in, "plan_hash");
    const auto core = relinkStr(in, "core");
    const auto mode = relinkStr(in, "mode");
    if (!std::regex_match(hash, hex)) throw vh::ops::Invalid("plan_hash is 64 hex digits");
    if (core != "this" && core != "theirs") throw vh::ops::Invalid("core is this or theirs");
    if (mode != "plan" && mode != "override") throw vh::ops::Invalid("mode is plan or override");
    const auto digestOf = [](const json& d) {
        const auto o = d.is_object() ? d : json::object();
        return json{{"digest", relinkStr(o, "digest")},
                    {"entries", o.contains("entries") && o["entries"].is_number_integer() ? o["entries"].get<int64_t>() : 0}};
    };
    // What this server's super admin approves: only what it can read (counts, sides, digests, the hash).
    const auto chosen = in.contains("chosen") && in["chosen"].is_object() ? in["chosen"] : json::object();
    const json proposal{{"plan_hash", hash}, {"core", core}, {"mode", mode},
                        {"this", relinkGainsJson(in.contains("this") && in["this"].is_object() ? in["this"] : json::object())},
                        {"theirs", relinkGainsJson(in.contains("theirs") && in["theirs"].is_object() ? in["theirs"]
                                                                                                     : json::object())},
                        {"chosen", {{"core", chosen.value("core", uint64_t{0})}, {"mirror", chosen.value("mirror", uint64_t{0})},
                                    {"both", chosen.value("both", uint64_t{0})}}},
                        {"entries", in.value("entries", uint64_t{0})},
                        {"digest", digestOf(in.contains("digest") ? in["digest"] : json())},
                        {"their_digest", digestOf(in.contains("their_digest") ? in["their_digest"] : json())},
                        {"by", {{"name", in.contains("by") && in["by"].is_object() ? relinkStr(in["by"], "name").substr(0, 255)
                                                                                   : std::string{}}}}};
    // The tree here is still the one the other server compared.
    const auto digest = mq::Relinks::digest(vaultId);
    if (proposal["digest"].value("digest", std::string{}) != digest.hex() ||
        proposal["digest"].value("entries", int64_t{0}) != digest.entries) {
        (void)mq::Relinks::unapprove(r.id, {"proposed", "approved"}, "accepted",
                                     "the vault changed here since the other server compared it");
        throw vh::ops::Refused("mirror_relink_stale", "the vault changed on this server since it was compared: compare "
                                                      "again");
    }
    // The same outcome again (its apply asks before it goes): an approval of it stands.
    if ((r.phase == "approved" || r.phase == "proposed") && r.proposal.is_object() &&
        r.proposal.value("plan_hash", std::string{}) == hash)
        return relinkAnswerOf(r);
    if (!mq::Relinks::propose(r.id, {"accepted", "proposed", "approved"}, proposal))
        throw vh::ops::Conflict("the relink changed while the outcome was proposed");
    mq::Relinks::setPlan(r.id, core, std::nullopt, true);
    const auto now = *mq::Relinks::get(r.id);
    relinkAudit("mirror.relink.propose", now, json{{"name", proposal["by"].value("name", std::string{})}},
                {{"from", peer.name}, {"plan_hash", hash}},
                fmt::format("[mirror] linked server '{}' proposes an outcome for the relink {} of vault {}, waiting for a "
                            "super admin's approval here: {}",
                            peer.name, r.relink_uid, vaultId, relinkOutcomeText(proposal, peer.name)));
    return relinkAnswerOf(now);
}

json serveCancel(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto r = mq::Relinks::byUid(vaultId, relinkUidField(payload, "relink_uid"));
    if (!r || r->side != "responder" || r->peer_id != callerPeerId) throw vh::ops::NotFound("no such relink here");
    if (mq::Relinks::setPhase(r->id, {"requested", "accepted", "proposed", "approved"}, "cancelled",
                              "the other server cancelled it: " + relinkStr(payload, "why").substr(0, 400)))
        relinkAudit("mirror.relink.cancel", *mq::Relinks::get(r->id), json::object(), {{"from", peer.name}},
                    fmt::format("[mirror] linked server '{}' cancelled its relink {} of vault {}; this vault did not change",
                                peer.name, r->relink_uid, vaultId));
    return {{"phase", mq::Relinks::get(r->id)->phase}};
}

json serveState(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto mine = relinkLocal(vaultId, peer.node_id);
    if (!mine.related)
        throw vh::ops::NotFound("this server has no record of mirroring that vault with the asking server");
    // Before this server's super admin accepted the relink: that it holds the vault, and how. Nothing else.
    bool accepted = false;
    if (payload.is_object() && payload.contains("relink_uid")) try {
            (void)relinkAccepted(vaultId, payload, callerPeerId);
            accepted = true;
        } catch (const vh::ops::Refused&) {
        }
    if (!accepted)
        return {{"vault_uid", mine.state.value("vault_uid", std::string{})}, {"status", mine.state.value("status", std::string{})},
                {"accepted", false}};
    auto out = mine.state;
    out["accepted"] = true;
    return out;
}

json serveTree(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto mine = relinkLocal(vaultId, peer.node_id);
    if (!mine.related) throw vh::ops::NotFound("this server has no record of mirroring that vault with the asking server");
    const auto relinkUid = relinkAccepted(vaultId, payload, callerPeerId).relink_uid;
    const auto after = payload.value("after", uint64_t{0});
    const auto limit = std::clamp<uint64_t>(payload.value("limit", uint64_t{kTreePage}), 1, 10'000);
    const auto key = std::to_string(vaultId) + ":" + relinkUid;
    std::scoped_lock lock(relinkServedMutex());
    auto& served = relinkServed();
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(served, [&](const auto& kv) { return now - kv.second.at > std::chrono::minutes(10); });
    auto it = served.find(key);
    if (it == served.end() || after == 0) {
        Served s;
        s.at = now;
        s.entries = relinkOwnTree(vaultId, relinkPosOf(payload.value("since", json(nullptr))), s.base);
        it = served.insert_or_assign(key, std::move(s)).first;
    }
    const auto& all = it->second.entries;
    json list = json::array();
    const auto end = std::min<uint64_t>(all.size(), after + limit);
    for (auto i = after; i < end; ++i) list.push_back(all[i]);
    json out{{"entries", list}, {"more", end < all.size()}, {"next", end}, {"total", all.size()}};
    if (after == 0) out["base"] = it->second.base;
    if (end >= all.size()) served.erase(it);
    return out;
}

json servePrepare(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    auto r = std::optional<mq::Relink>(relinkAccepted(vaultId, payload, callerPeerId));
    const auto relinkUid = r->relink_uid;
    if (r->phase != "approved")
        throw vh::ops::Refused("mirror_relink_not_approved", "this server's super admin has not approved an outcome for "
                                                             "this relink: propose it and wait for the approval");
    const auto role = relinkStr(payload, "role");
    if (role != "core" && role != "mirror") throw vh::ops::Invalid("role is core or mirror");
    const auto term = payload.value("term", uint64_t{0});
    if (term < 1) throw vh::ops::Invalid("term is at least 1");
    const auto part = payload.value("part", uint64_t{0});
    const auto mode = relinkStr(payload, "mode") == "override" ? std::string("override") : std::string("plan");
    const auto approved = r->proposal;
    const auto voidIt = [&](const std::string& code, const std::string& why) {
        (void)mq::Relinks::unapprove(r->id, {"approved"}, "accepted", why);
        relinkAudit("mirror.relink.voided", *r, json::object(), {{"from", peer.name}, {"why", why}},
                    fmt::format("[mirror] vault {}: the approval of linked server '{}''s relink {} is void: {}", vaultId,
                                peer.name, relinkUid, why));
        return vh::ops::Refused(code, why);
    };
    // The approved outcome only: this server's part, the mode.
    if ((role == "core") != (approved.value("core", std::string{}) == "this") || mode != approved.value("mode", std::string{}))
        throw voidIt("mirror_relink_not_approved", "the outcome asked for is not the one approved here: ask again");
    // Who makes this server's changes: the super admin who approved them.
    const auto approver = r->summary.contains("approver") ? r->summary["approver"] : json::object();
    const json by{{"node", relinkOwnNode()},
                  {"id", approver.contains("id") && approver["id"].is_number_unsigned() ? json(approver["id"]) : json(nullptr)},
                  {"name", approver.value("name", r->approved_by.value_or(""))}};
    if (part == 0) {
        const auto mine = relinkLocal(vaultId, peer.node_id);
        if (!mine.related) throw vh::ops::NotFound("this server has no record of mirroring that vault with the asking server");
        // The digest the other server compared against, and the one approved here: a change here since voids it.
        const auto seen = payload.contains("digest") ? payload["digest"] : json::object();
        const auto ok = approved.contains("digest") ? approved["digest"] : json::object();
        if (seen.value("digest", std::string{}) != mine.state.value("digest", std::string{}) ||
            seen.value("entries", int64_t{0}) != mine.state.value("entries", int64_t{0}) ||
            ok.value("digest", std::string{}) != mine.state.value("digest", std::string{}) ||
            ok.value("entries", int64_t{0}) != mine.state.value("entries", int64_t{0}))
            throw voidIt("mirror_relink_stale", "the vault changed on this server since it was compared and approved: "
                                                "compare again");
        const auto blockers = relinkBlockers(mine.state, json{{"status", "detached"}}, json{{"match", true}});
        for (const auto& b : blockers)
            if (b.value("side", std::string{}) == "this")
                throw vh::ops::Refused(b.value("code", std::string{}), b.value("message", std::string{}));
        mq::Relinks::clearEntries(r->id);
        auto summary = r->summary;
        summary["peer"] = {{"id", peer.id}, {"name", peer.name}, {"node", peer.node_id}};
        summary["this"] = [&] { auto o = mine.state; o.erase("keys"); return o; }();
        mq::Relinks::setSummary(r->id, summary);
    }
    std::vector<mq::RelinkEntry> list;
    for (const auto& e : payload.value("entries", json::array())) {
        mq::RelinkEntry x;
        x.uid = relinkStr(e, "uid");
        if (!relinkUuid(x.uid)) throw vh::ops::Invalid("an entry's uid is a uuid");
        const auto k = relinkStr(e, "kind");
        x.kind = k == "only_this" ? "only_theirs" : k == "only_theirs" ? "only_this" : k == "changed_this" ? "changed_theirs"
                 : k == "changed_theirs" ? "changed_this" : k == "changed_both" ? "changed_both" : "differs";
        for (const auto& a : e.value("aspects", json::array()))
            if (a.is_string()) {
                const auto s = a.get<std::string>();
                x.aspects.push_back(s == "by_this" ? "by_theirs" : s == "by_theirs" ? "by_this" : s);
            }
        x.path = relinkStr(e, "path");
        x.this_state = e.contains("yours") ? e["yours"] : json(nullptr);
        x.theirs_state = e.contains("mine") ? e["mine"] : json(nullptr);
        const auto c = relinkStr(e, "choice");
        if (c != "this" && c != "theirs" && c != "both") throw vh::ops::Invalid("a choice is this, theirs or both");
        x.choice = c;
        list.push_back(std::move(x));
    }
    mq::Relinks::addEntries(r->id, list);
    if (payload.value("more", false)) return {{"prepared", false}, {"part", part}};

    // The plan received is the plan approved: its hash, and what it does to this vault.
    mq::Relinks::setPlan(r->id, role == "core" ? std::string("this") : std::string("theirs"), std::nullopt, true);
    r = mq::Relinks::get(r->id);
    const auto entries = mq::Relinks::entries(r->id);
    std::vector<PlanRow> rows;
    rows.reserve(entries.size());
    for (const auto& e : entries)
        rows.push_back({.uid = e.uid, .choice = e.choice.value_or(""), .here = relinkStateHash(e.this_state),
                        .there = relinkStateHash(e.theirs_state)});
    const auto there = approved.contains("their_digest") ? approved["their_digest"] : json::object();
    const auto got = relinkPlanHash(r->core, mode, approved["digest"].value("digest", std::string{}),
                                    there.value("digest", std::string{}), rows);
    const auto gains = relinkGains(*r, entries);
    if (got != approved.value("plan_hash", std::string{}) || !relinkSameGains(gains["this"], approved["this"]) ||
        !relinkSameGains(gains["theirs"], approved["theirs"]))
        throw voidIt("mirror_relink_not_approved", "the plan sent is not the one approved here (its entries or what it "
                                                   "does to this vault differ): the approval is void; ask again");
    try {
        if (role == "core") relinkPrepareCore(*r, callerPeerId, term, by);
        else relinkPrepareMirror(*r, callerPeerId, term, by);
    } catch (const vh::ops::Error&) {
        (void)mq::Relinks::setPhase(r->id, {"approved"}, "failed", "the preparation was refused");
        throw;
    }
    r = mq::Relinks::get(r->id);
    relinkAudit("mirror.relink", *r, by, {{"core", role == "core" ? "this" : "theirs"}, {"from", peer.name}},
                fmt::format("[mirror] linked server {} relinked vault {} (relink {}, approved here by {}): this server "
                            "becomes its {} in term {}",
                            peer.id, vaultId, relinkUid, r->approved_by.value_or("a super admin"), role, term));
    return {{"prepared", true}, {"part", part}, {"phase", r->phase}};
}

json serveGo(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto r = mq::Relinks::byUid(vaultId, relinkUidField(payload, "relink_uid"));
    if (!r || r->peer_id != callerPeerId) throw vh::ops::NotFound("no such relink here");
    if (r->side != "responder" || !r->approved_at)
        throw vh::ops::Refused("mirror_relink_not_accepted", "this server's super admin has not approved that relink");
    relinkGo(*r);
    return {{"phase", mq::Relinks::get(r->id)->phase}};
}

json serveAbort(const uint32_t callerPeerId, const json& payload) {
    vh::peer::Record peer;
    const auto vaultId = relinkVaultForPeer(payload, callerPeerId, peer);
    const auto r = mq::Relinks::byUid(vaultId, relinkUidField(payload, "relink_uid"));
    if (!r || r->peer_id != callerPeerId) throw vh::ops::NotFound("no such relink here");
    if (r->phase == "done" || r->phase == "failed") return {{"phase", r->phase}};
    relinkAbortLocal(*r, "the other server stopped the relink: " + relinkStr(payload, "why").substr(0, 400));
    return {{"phase", "failed"}};
}

void resetForTesting() {
    std::scoped_lock lock(relinkServedMutex());
    relinkServed().clear();
}

}
