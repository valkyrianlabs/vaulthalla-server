#include "mirror/follow/Protocol.hpp"

#include "db/query/mirror/Apply.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "mirror/follow/Follower.hpp"
#include "ops/Error.hpp"

#include <atomic>
#include <optional>
#include <string>

namespace vh::mirror::follow {

namespace mq = vh::db::query::mirror;
using json = nlohmann::json;

namespace {

std::atomic<std::size_t>& followAnswerBytesOverride() {
    static std::atomic<std::size_t> bytes{0};
    return bytes;
}

// The sealed lane's answer for anything a peer may not learn about (protocols::device::peer_object).
[[noreturn]] void followNotFound() { throw ops::NotFound("Not found"); }

std::string followText(const json& payload, const char* key) {
    const auto it = payload.find(key);
    if (it == payload.end() || !it->is_string() || it->get<std::string>().empty())
        throw ops::Invalid(std::string(key) + " is required");
    return it->get<std::string>();
}

uint64_t followCount(const json& payload, const char* key, const bool required = true) {
    const auto it = payload.find(key);
    if (it == payload.end()) {
        if (required) throw ops::Invalid(std::string(key) + " is required");
        return 0;
    }
    if (!it->is_number_unsigned() && !(it->is_number_integer() && it->get<int64_t>() >= 0))
        throw ops::Invalid(std::string(key) + " must be a non-negative integer");
    return it->get<uint64_t>();
}

// The vault the caller is the linked server of, with this server in `role`; else the lane's "not found".
mq::MirrorVault followVaultFor(const uint32_t callerPeerId, const json& payload, const char* role) {
    const auto mv = mq::MirrorVaults::byVaultUid(followText(payload, "vault_uid"));
    if (!mv || mv->peer_id != callerPeerId || mv->role != role || mv->state == "starting") followNotFound();
    return *mv;
}

json followHashOrNull(const std::optional<vh::mirror::Hash>& h) { return h ? json(vh::mirror::toHex(*h)) : json(nullptr); }

std::optional<vh::mirror::Hash> followHashFrom(const json& j, const char* key) {
    const auto it = j.find(key);
    if (it == j.end() || it->is_null()) return std::nullopt;
    return vh::mirror::hashFromHex(it->get<std::string>());
}

json followGroupHead(const uint64_t term, const uint64_t txid, const uint64_t first, const uint64_t last) {
    return {{"term", term}, {"txid", txid}, {"first_seq", first}, {"last_seq", last}};
}

// A part of one group: its rows from `rows`, as many as fit.
json followPart(json head, const std::vector<mq::Row>& rows, const uint64_t groupLast) {
    json out = std::move(head);
    out["rows"] = json::array();
    std::size_t bytes = 256;
    for (const auto& r : rows) {
        auto j = toJson(r);
        const auto size = j.dump().size();
        if (!out["rows"].empty() && bytes + size > answerBytes()) break;
        bytes += size;
        out["rows"].push_back(std::move(j));
    }
    out["complete"] = !out["rows"].empty() && out["rows"].back()["seq"].get<uint64_t>() == groupLast;
    return {{"part", std::move(out)}};
}

}

void setAnswerBytesForTesting(const std::size_t bytes) { followAnswerBytesOverride().store(bytes); }

std::size_t answerBytes() {
    const auto o = followAnswerBytesOverride().load();
    return o ? o : kAnswerBytes;
}

json toJson(const mq::Row& row) {
    return {{"seq", row.seq},
            {"op", row.op},
            {"uid", row.entry_uid ? json(*row.entry_uid) : json(nullptr)},
            {"type", row.entry_type ? json(*row.entry_type) : json(nullptr)},
            {"state", row.state},
            {"entry_hash", followHashOrNull(row.entry_hash)},
            {"prev_hash", followHashOrNull(row.prev_hash)},
            {"actor", row.actor ? json{{"node", row.actor->node}, {"id", row.actor->id}} : json(nullptr)}};
}

vh::mirror::apply::LogRow rowFromJson(const json& j) {
    vh::mirror::apply::LogRow r;
    r.seq = j.at("seq").get<uint64_t>();
    r.op = j.at("op").get<std::string>();
    if (j.contains("uid") && j["uid"].is_string()) r.uid = j["uid"].get<std::string>();
    if (j.contains("type") && j["type"].is_string()) r.type = j["type"].get<std::string>();
    r.state = j.value("state", json::object());
    r.entry_hash = followHashFrom(j, "entry_hash");
    r.prev_hash = followHashFrom(j, "prev_hash");
    return r;
}

vh::mirror::apply::LogGroup groupFromJson(const json& j) {
    vh::mirror::apply::LogGroup g;
    g.term = j.at("term").get<uint64_t>();
    g.txid = j.at("txid").get<uint64_t>();
    g.first_seq = j.at("first_seq").get<uint64_t>();
    g.last_seq = j.at("last_seq").get<uint64_t>();
    for (const auto& r : j.at("rows")) g.rows.push_back(rowFromJson(r));
    return g;
}

vh::mirror::apply::TreePage treePageFromJson(const json& j) {
    vh::mirror::apply::TreePage p;
    p.baseline = {j.at("baseline").at("term").get<uint64_t>(), j.at("baseline").at("seq").get<uint64_t>()};
    p.digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(j.at("digest").get<std::string>()),
                                             j.at("entries").get<int64_t>());
    p.rows = j.value("rows", uint64_t{0});
    p.vault = j.value("vault", json::object());
    for (const auto& item : j.at("items")) p.items.push_back({.ord = item.at("ord").get<uint64_t>(), .state = item.at("state")});
    p.more = j.value("more", false);
    return p;
}

json serveTree(const uint32_t callerPeerId, const json& payload) {
    const auto mv = followVaultFor(callerPeerId, payload, "core");
    const auto after = followCount(payload, "after", false);
    // The states' share of the answer: what the envelope and (on the first page) the vault's document leave.
    const auto vaultBytes = after == 0 ? mq::Baseline::page(mv.vault_id, 0, 1, 0).vault.dump().size() : 0;
    const auto overhead = 1024 + vaultBytes;
    const auto budget = answerBytes() > 2 * overhead ? answerBytes() - overhead : answerBytes() / 2;
    const auto page = mq::Baseline::page(mv.vault_id, after, kTreePageRows, budget);
    if (!page.exists) return {{"expired", true}, {"core_state", mv.state}};
    json items = json::array();
    for (const auto& item : page.items) items.push_back({{"ord", item.ord}, {"state", json::parse(item.state)}});
    return {{"baseline", {{"term", page.position.term}, {"seq", page.position.seq}}},
            {"digest", page.digest.hex()},
            {"entries", page.digest.entries},
            {"rows", page.rows},
            {"vault", after == 0 ? page.vault : json::object()},
            {"items", std::move(items)},
            {"more", page.more},
            {"core_state", mv.state}};
}

json serveLog(const uint32_t callerPeerId, const json& payload) {
    const auto mv = followVaultFor(callerPeerId, payload, "core");
    const mq::Position after{followCount(payload, "term"), followCount(payload, "seq")};

    if (const auto part = payload.find("part"); part != payload.end() && part->is_object()) {
        const auto txid = followCount(*part, "txid");
        const auto heldThrough = followCount(*part, "after_seq");
        // The group is the one right after `after` (its first row is after.seq + 1), still in the log: retention never
        // passes what the mirror has not acknowledged.
        const auto span = mq::Log::groupSpan(mv.vault_id, after.term, txid);
        const auto rows = mq::Log::groupRows(mv.vault_id, after.term, txid, heldThrough, kLogPageRows);
        if (!span || span->first != after.seq + 1 || rows.empty()) return {{"expired", true}, {"core_state", mv.state}};
        auto out = followPart(followGroupHead(after.term, txid, span->first, span->second), rows, span->second);
        out["core_state"] = mv.state;
        return out;
    }

    const auto page = mq::Log::groupsAfter(mv.vault_id, after, kLogPageRows);
    if (page.expired) return {{"expired", true}, {"core_state", mv.state}};
    json groups = json::array();
    std::size_t bytes = 512;
    mq::Position last = after;
    bool cut = false;
    for (const auto& g : page.groups) {
        json group = followGroupHead(g.term, g.txid, g.first_seq, g.last_seq);
        group["rows"] = json::array();
        for (const auto& r : g.rows) group["rows"].push_back(toJson(r));
        const auto size = group.dump().size();
        if (bytes + size > answerBytes()) {
            if (groups.empty()) {
                // One group larger than an answer: its first part.
                auto out = followPart(followGroupHead(g.term, g.txid, g.first_seq, g.last_seq), g.rows, g.last_seq);
                out["core_state"] = mv.state;
                return out;
            }
            cut = true;
            break;
        }
        bytes += size;
        groups.push_back(std::move(group));
        last = {g.term, g.last_seq};
    }
    return {{"groups", std::move(groups)},
            {"last", {{"term", last.term}, {"seq", last.seq}}},
            {"more", cut || page.more},
            {"core_state", mv.state}};
}

json serveAck(const uint32_t callerPeerId, const json& payload) {
    const auto mv = followVaultFor(callerPeerId, payload, "core");
    const mq::Position at{followCount(payload, "term"), followCount(payload, "seq")};
    vh::mirror::Digest theirs;
    try {
        theirs = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(followText(payload, "digest")),
                                               payload.value("entries", int64_t{0}));
    } catch (const std::invalid_argument&) {
        throw ops::Invalid("digest must be 64 hex digits");
    }
    const auto out = mq::MirrorVaults::acknowledgeChecked(mv.vault_id, at, theirs);
    return {{"known", out.known},
            {"match", out.match},
            {"recorded", out.recorded},
            {"core_digest", out.known ? json(out.core_digest.hex()) : json(nullptr)},
            {"core_entries", out.known ? json(out.core_digest.entries) : json(nullptr)}};
}

json receiveNotify(const uint32_t callerPeerId, const json& payload) {
    const auto mv = followVaultFor(callerPeerId, payload, "mirror");
    if (const auto& follower = Follower::instance()) follower->wake(mv.vault_id);
    return json::object();
}

}
