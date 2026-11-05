#include "ops/Audit.hpp"

#include "audit/Trail.hpp"
#include "db/query/device/Device.hpp"
#include "identities/User.hpp"
#include "rbac/permission/admin/Audits.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "vault/KeyAttestation.hpp"

#include <ctime>
#include <map>

namespace vh::ops::audit {

namespace {

constexpr std::size_t kVerifyBatch = 5000;

std::string isoUtc(const uint64_t us) {
    const auto secs = static_cast<std::time_t>(us / 1'000'000);
    std::tm tm{};
    gmtime_r(&secs, &tm);
    char buf[96];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%06uZ", tm.tm_year + 1900, tm.tm_mon + 1,
                  tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<unsigned>(us % 1'000'000));
    return buf;
}

void requireView(const Actor& actor) {
    requireActor(actor);
    if (!canView(actor)) throw Denied("reading the audit trail needs the admin.audits.view permission");
}

void recordAccess(const Actor& actor, const std::string& action, const std::string& what, nlohmann::json details) {
    vh::audit::record({.action = action, .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .details = std::move(details)},
                      "[audit] " + actor->name() + " " + what);
}

}

bool canView(const Actor& actor) {
    if (!actor) return false;
    using Perm = rbac::permission::admin::AuditPermissions;
    return rbac::resolver::Admin::has<Perm>({.user = actor, .permission = Perm::View});
}

Page list(const Actor& actor, const Filter& filter, const std::size_t limit) {
    requireView(actor);
    if (limit < 1 || limit > 1000) throw Invalid("limit must be 1..1000");
    Page page;
    page.events = db::query::audit::Trail::list(filter, limit);
    if (page.events.size() == limit && page.events.back().seq > 1) page.next_before = page.events.back().seq;
    // Paging through the viewer records one event per first page, not one per page.
    if (!filter.before_seq) recordAccess(actor, "audit.view", "viewed the audit trail", nlohmann::json::object());
    return page;
}

Verification verify(const Actor& actor) {
    requireView(actor);
    Verification out;

    const auto anchor = db::query::audit::Trail::checkpoint();
    if (anchor) out.anchor_seq = anchor->seq;
    const auto heads = db::query::audit::Trail::heads();
    std::map<uint64_t, std::vector<const vh::audit::SignedHead*>> headsAt;
    for (const auto& h : heads) headsAt[h.seq].push_back(&h);

    // Walk the chain; check each signed head against the hash the chain actually has at its seq.
    vh::audit::ChainVerifier chain(anchor);
    const auto nodeId = db::query::device::Devices::nodeId();
    const auto checkHead = [&](const vh::audit::SignedHead& h, const vh::audit::Hash* chainHash) {
        const auto verdict = vault::attestation::checkNodeMessage(
            {.key_id = h.key_id, .signature = h.signature},
            vh::audit::headMessage(h.node_id, h.seq, h.hash, h.signed_us));
        std::string problem;
        if (verdict != vault::attestation::Verdict::Valid)
            problem = "signature " + vault::attestation::to_string(verdict);
        else if (!chainHash)
            problem = "names event " + std::to_string(h.seq) + ", which is missing (events were removed from the end)";
        else if (*chainHash != h.hash)
            problem = "does not match the chain at event " + std::to_string(h.seq) + " (history was rewritten)";
        else if (h.node_id != nodeId)
            problem = "was signed by another node (" + h.node_id + ")";
        if (problem.empty()) {
            ++out.heads_valid;
            out.last_signed_seq = std::max(out.last_signed_seq.value_or(0), h.seq);
        } else {
            ++out.heads_invalid;
            out.head_problems.push_back("head at event " + std::to_string(h.seq) + ": " + problem);
        }
    };

    uint64_t after = anchor ? anchor->seq : 0;
    for (;;) {
        const auto batch = db::query::audit::Trail::range(after, kVerifyBatch);
        if (batch.empty()) break;
        for (const auto& r : batch) {
            if (!out.first_seq) out.first_seq = r.seq;
            if (!chain.feed(r)) break;
            if (const auto it = headsAt.find(r.seq); it != headsAt.end()) {
                for (const auto* h : it->second) checkHead(*h, &r.hash);
                headsAt.erase(it);
            }
        }
        if (chain.result().broken_at) break;
        after = batch.back().seq;
    }
    const auto& result = chain.result();
    out.events_checked = result.checked;
    if (result.checked > 0) out.last_seq = result.last_seq;
    out.broken_at = result.broken_at;
    out.problem = result.problem;
    // Heads beyond the end of the chain (or before the anchor) were not matched above.
    for (const auto& [seq, list] : headsAt)
        for (const auto* h : list) {
            if (anchor && seq <= anchor->seq) continue;  // purged with its events
            if (!result.broken_at) checkHead(*h, nullptr);
        }
    out.unsigned_events = out.last_seq ? *out.last_seq - out.last_signed_seq.value_or(anchor ? anchor->seq : 0) : 0;
    out.ok = !out.broken_at && out.heads_invalid == 0;

    recordAccess(actor, out.ok ? "audit.verify" : "audit.verify.failed",
                 out.ok ? "verified the audit trail" : "verified the audit trail: it FAILED verification",
                 {{"events_checked", out.events_checked}, {"ok", out.ok}});
    return out;
}

uint64_t exportNdjson(const Actor& actor, const std::optional<uint64_t> sinceUs, const std::optional<uint64_t> untilUs,
                      const std::function<void(std::string_view)>& write) {
    requireView(actor);
    const auto anchor = db::query::audit::Trail::checkpoint();
    write(nlohmann::json{{"type", "export"},
                         {"format", "vh-audit-export-v1"},
                         {"node_id", db::query::device::Devices::nodeId()},
                         {"since_us", sinceUs ? nlohmann::json(*sinceUs) : nlohmann::json(nullptr)},
                         {"until_us", untilUs ? nlohmann::json(*untilUs) : nlohmann::json(nullptr)},
                         {"anchor", anchor ? nlohmann::json{{"seq", anchor->seq},
                                                            {"hash", vh::audit::toHex(anchor->hash)}}
                                           : nlohmann::json(nullptr)}}.dump());
    uint64_t written = 0, firstSeq = 0, lastSeq = 0;
    uint64_t after = anchor ? anchor->seq : 0;
    bool reachedUntil = false;
    while (!reachedUntil) {
        const auto batch = db::query::audit::Trail::range(after, kVerifyBatch);
        if (batch.empty()) break;
        for (const auto& r : batch) {
            if (untilUs && r.occurred_us >= *untilUs) {
                reachedUntil = true;
                break;
            }
            if (sinceUs && r.occurred_us < *sinceUs) continue;
            auto line = toJson(r);
            line["type"] = "event";
            write(line.dump());
            if (!firstSeq) firstSeq = r.seq;
            lastSeq = r.seq;
            ++written;
        }
        after = batch.back().seq;
    }
    for (const auto& h : db::query::audit::Trail::heads()) {
        if (written == 0 || h.seq < firstSeq) continue;
        auto line = toJson(h);
        line["type"] = "head";
        write(line.dump());
    }
    recordAccess(actor, "audit.export", "exported " + std::to_string(written) + " audit event(s)",
                 {{"events", written}, {"first_seq", firstSeq}, {"last_seq", lastSeq}});
    return written;
}

nlohmann::json toJson(const vh::audit::Record& r) {
    // `details` stays the exact string that was hashed, so an export verifies byte for byte.
    return {{"seq", r.seq},
            {"occurred_us", r.occurred_us},
            {"occurred_at", isoUtc(r.occurred_us)},
            {"level", r.level},
            {"action", r.action},
            {"outcome", r.outcome},
            {"actor_id", r.actor_id ? nlohmann::json(*r.actor_id) : nlohmann::json(nullptr)},
            {"actor", r.actor},
            {"origin", r.origin},
            {"vault_id", r.vault_id ? nlohmann::json(*r.vault_id) : nlohmann::json(nullptr)},
            {"entry_id", r.entry_id ? nlohmann::json(*r.entry_id) : nlohmann::json(nullptr)},
            {"message", r.message},
            {"details", r.details},
            {"prev_hash", vh::audit::toHex(r.prev_hash)},
            {"hash", vh::audit::toHex(r.hash)}};
}

nlohmann::json toJson(const vh::audit::SignedHead& h) {
    return {{"seq", h.seq},
            {"hash", vh::audit::toHex(h.hash)},
            {"signed_us", h.signed_us},
            {"signed_at", isoUtc(h.signed_us)},
            {"node_id", h.node_id},
            {"key_id", h.key_id},
            {"signature", vh::audit::toHex(h.signature)}};
}

nlohmann::json toJson(const Verification& v) {
    const auto opt = [](const std::optional<uint64_t>& x) { return x ? nlohmann::json(*x) : nlohmann::json(nullptr); };
    return {{"ok", v.ok},
            {"events_checked", v.events_checked},
            {"first_seq", opt(v.first_seq)},
            {"last_seq", opt(v.last_seq)},
            {"anchor_seq", opt(v.anchor_seq)},
            {"broken_at", opt(v.broken_at)},
            {"problem", v.problem},
            {"heads_valid", v.heads_valid},
            {"heads_invalid", v.heads_invalid},
            {"last_signed_seq", opt(v.last_signed_seq)},
            {"unsigned_events", v.unsigned_events},
            {"head_problems", v.head_problems}};
}

}
