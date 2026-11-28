#include "ops/Health.hpp"

#include "audit/Trail.hpp"
#include "db/query/health/FindingState.hpp"
#include "identities/User.hpp"
#include "ops/Stats.hpp"
#include "rbac/permission/admin/Stats.hpp"
#include "rbac/resolver/admin/all.hpp"

#include <algorithm>
#include <chrono>

namespace vh::ops::health {

namespace {

std::uint64_t nowSeconds() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
}

void requireManage(const Actor& actor, const std::string_view what) {
    requireActor(actor);
    if (!canManage(actor))
        throw Denied(std::string(what) + " a health finding needs the admin.stats.manage permission");
}

const vh::health::FindingClass& knownClass(const std::string& cls) {
    const auto* known = vh::health::findClass(cls);
    if (!known) throw NotFound("no health finding class '" + cls + "'");
    return *known;
}

// Every finding today is about the whole server.
void requireNoSubject(const std::string& subject) {
    if (!subject.empty()) throw Invalid("health findings have no subjects yet: leave subject empty");
}

std::optional<std::string> cleanNote(const std::optional<std::string>& note) {
    if (!note) return std::nullopt;
    auto text = *note;
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return std::nullopt;
    text = text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
    if (text.size() > kMaxNoteLength)
        throw Invalid("a note is at most " + std::to_string(kMaxNoteLength) + " characters");
    return text;
}

const vh::health::Finding* activeFinding(const vh::health::Snapshot& snapshot, const std::string& cls,
                                         const std::string& subject) {
    const auto it = std::ranges::find_if(snapshot.findings, [&](const auto& finding) {
        return finding.raised.code == cls && finding.raised.subject == subject;
    });
    return it == snapshot.findings.end() ? nullptr : &*it;
}

void record(const Actor& actor, const std::string& action, const std::string& what, const vh::health::Mark& mark) {
    nlohmann::json details{{"class", mark.cls}, {"severity", mark.severity}, {"note", mark.note.has_value()}};
    if (!mark.subject.empty()) details["subject"] = mark.subject;
    if (mark.expiresAt) details["expires_at"] = *mark.expiresAt;
    vh::audit::record({.action = action, .actor_id = actor->id, .actor = actor->name(), .details = std::move(details)},
                      "[health] " + actor->name() + " " + what + " " + mark.cls);
}

nlohmann::json answer(const Actor& actor, const bool includeCatalog) {
    nlohmann::json j = vh::health::snapshot();
    j["can_manage"] = canManage(actor);
    if (includeCatalog) j["catalog"] = vh::health::catalog();
    return j;
}

}

bool canManage(const Actor& actor) {
    if (!actor) return false;
    using Perm = rbac::permission::admin::StatsPermissions;
    return rbac::resolver::Admin::has<Perm>({.user = actor, .permission = Perm::Manage});
}

nlohmann::json list(const Actor& actor, const bool includeCatalog) {
    stats::requireSystem(actor, "health findings");
    return answer(actor, includeCatalog);
}

nlohmann::json acknowledge(const Actor& actor, const std::string& cls, const std::string& subject,
                           const std::optional<std::string>& note) {
    requireManage(actor, "acknowledging");
    knownClass(cls);
    requireNoSubject(subject);
    const auto cleaned = cleanNote(note);

    const auto snapshot = vh::health::snapshot();
    const auto* finding = activeFinding(snapshot, cls, subject);
    if (!finding)
        throw Conflict("'" + cls + "' is not active now, so there is nothing to acknowledge. To stop hearing about "
                       "it when it returns, silence it.");
    if (finding->state == "silenced") throw Conflict("'" + cls + "' is silenced already");

    const auto mark = db::query::health::FindingState::put({.cls = cls,
                                                            .subject = subject,
                                                            .state = "acknowledged",
                                                            .severity = finding->raised.severity,
                                                            .setBy = actor->id,
                                                            .setByName = actor->name(),
                                                            .note = cleaned});
    record(actor, "health.finding.acknowledge", "acknowledged", mark);
    vh::health::stateChanged();
    return answer(actor, false);
}

nlohmann::json silence(const Actor& actor, const SilenceRequest& request) {
    requireManage(actor, "silencing");
    const auto& known = knownClass(request.cls);
    requireNoSubject(request.subject);
    const auto cleaned = cleanNote(request.note);
    if (request.forSeconds && request.until) throw Invalid("give for_seconds or until, not both");

    const auto now = nowSeconds();
    std::optional<std::uint64_t> expiresAt;
    if (request.forSeconds) {
        if (*request.forSeconds < kMinSilenceSeconds || *request.forSeconds > kMaxSilenceSeconds)
            throw Invalid("a silence lasts between one minute and 366 days; leave the time out to silence until "
                          "it is turned back on");
        expiresAt = now + *request.forSeconds;
    } else if (request.until) {
        if (*request.until <= now + kMinSilenceSeconds || *request.until > now + kMaxSilenceSeconds)
            throw Invalid("until must be between one minute and 366 days from now");
        expiresAt = *request.until;
    }

    // What the silence covers: what was asked, else the severity the class has now, else the worst it can have.
    std::string severity;
    if (request.severity) {
        if (*request.severity != "warning" && *request.severity != "error")
            throw Invalid("severity is \"warning\" or \"error\"");
        severity = *request.severity;
    } else {
        const auto snapshot = vh::health::snapshot();
        const auto* finding = activeFinding(snapshot, request.cls, request.subject);
        severity = finding ? finding->raised.severity : known.maxSeverity;
    }

    const auto mark = db::query::health::FindingState::put({.cls = request.cls,
                                                            .subject = request.subject,
                                                            .state = "silenced",
                                                            .severity = severity,
                                                            .setBy = actor->id,
                                                            .setByName = actor->name(),
                                                            .expiresAt = expiresAt,
                                                            .note = cleaned});
    record(actor, "health.finding.silence", "silenced", mark);
    vh::health::stateChanged();
    return answer(actor, false);
}

nlohmann::json unsilence(const Actor& actor, const std::string& cls, const std::string& subject) {
    requireManage(actor, "turning back on");
    knownClass(cls);
    requireNoSubject(subject);
    if (!db::query::health::FindingState::remove(cls, subject))
        throw NotFound("'" + cls + "' is neither silenced nor acknowledged");
    record(actor, "health.finding.unsilence", "turned back on",
           {.cls = cls, .subject = subject, .state = "", .severity = vh::health::findClass(cls)->maxSeverity});
    vh::health::stateChanged();
    return answer(actor, false);
}

}
