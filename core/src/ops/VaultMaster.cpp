#include "ops/VaultMaster.hpp"

#include "audit/Trail.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "identities/User.hpp"
#include "vault/Master.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

namespace vh::ops::vault_master {

namespace {

namespace rw = vault::master::rewrap;

constexpr std::chrono::seconds kMaxWindow{std::chrono::hours(24 * 90)};

void auditAs(const Actor& actor, const std::string& action, const vh::audit::Outcome outcome, nlohmann::json details,
             const std::string& message, const spdlog::level::level_enum level = spdlog::level::info) {
    vh::audit::record({.action = action, .outcome = outcome, .actor_id = actor ? std::optional<uint32_t>(actor->id)
                                                                                : std::nullopt,
                       .actor = actor ? actor->name() : std::string{}, .details = std::move(details)},
                      "[ops::vault_master] " + (actor ? actor->name() : std::string("?")) + " " + message, level);
}

void requireSuperAdmin(const Actor& actor, const std::string& action) {
    requireActor(actor);
    if (actor->isSuperAdmin()) return;
    auditAs(actor, action, vh::audit::Outcome::Denied, nlohmann::json::object(),
            "was refused " + action + ": super admins only", spdlog::level::warn);
    throw Denied("only super admins can manage the vault master");
}

// Runs one step, auditing a refusal or failure (with its code) before it propagates.
template <class Fn>
auto audited(const Actor& actor, const std::string& action, Fn&& fn) {
    try {
        return fn();
    } catch (const NeedsConfirmation&) {
        throw;
    } catch (const Refused& e) {
        auditAs(actor, action, vh::audit::Outcome::Failure, {{"code", e.code}}, action + " refused: " + e.what(),
                spdlog::level::warn);
        throw;
    } catch (const std::exception& e) {
        auditAs(actor, action, vh::audit::Outcome::Failure, {{"code", "fault"}}, action + " failed: " + e.what(),
                spdlog::level::err);
        throw;
    }
}

std::optional<std::string> isoOf(const std::optional<std::time_t>& t) {
    if (!t) return std::nullopt;
    std::tm tm{};
    gmtime_r(&*t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

nlohmann::json orNull(const std::optional<std::string>& s) { return s ? nlohmann::json(*s) : nlohmann::json(nullptr); }
nlohmann::json orNull(const std::optional<unsigned int>& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); }

}

rw::Status status(const Actor& actor) {
    requireSuperAdmin(actor, "secrets.master.status");
    return rw::status();
}

rw::RotateResult rotate(const Actor& actor, const RotateRequest& request) {
    constexpr const char* action = "secrets.master.rotate";
    requireSuperAdmin(actor, action);
    rw::Options options;
    if (request.window) {
        if (*request.window < std::chrono::hours(1) || *request.window > kMaxWindow)
            throw Invalid("the recovery window is 1 hour to 90 days");
        options.window = *request.window;
    }
    if (request.batch) {
        if (*request.batch < 1 || *request.batch > 10000) throw Invalid("the batch size is 1 to 10000 rows");
        options.batch = *request.batch;
    }
    if (!request.confirmed)
        throw NeedsConfirmation(
            "vault_master_rotate",
            fmt::format("This replaces the vault master (sealed with '{}' sealing) that wraps every vault key. File "
                        "contents are not re-encrypted. The old master stays for a recovery window of {} hours, "
                        "during which `vh secret master rollback` returns to it; after that it is deleted. Database "
                        "backups taken before the rotation need the old master: once it is deleted, they restore only "
                        "through the vault key exports (vh vault keys export). Continue?",
                        crypto::secrets::KeyProvider::posture(),
                        std::chrono::duration_cast<std::chrono::hours>(options.window).count()));
    auditAs(actor, action, vh::audit::Outcome::Info, {{"window_seconds", options.window.count()}},
            "started a vault master rotation");
    return audited(actor, action, [&] {
        auto r = rw::rotate(options);
        auditAs(actor, action, vh::audit::Outcome::Success,
                {{"from", r.from}, {"to", r.to}, {"rows", r.rows}, {"staged", r.staged_now},
                 {"caught_up", r.caught_up}, {"batches", r.batches}, {"resumed", r.resumed},
                 {"window_until", r.window_until}},
                fmt::format("rotated the vault master from version {} to {}: {} key row(s) rewrapped and verified, "
                            "{} staged now in {} batch(es){}, {} caught up at the switch; the previous master is "
                            "kept until {}",
                            r.from, r.to, r.rows, r.staged_now, r.batches, r.resumed ? " (resumed)" : "", r.caught_up,
                            isoOf(r.window_until).value_or("?")),
                spdlog::level::warn);
        return r;
    });
}

rw::FinalizeResult finalize(const Actor& actor, const bool confirmed) {
    constexpr const char* action = "secrets.master.finalize";
    requireSuperAdmin(actor, action);
    if (!confirmed) {
        const auto st = rw::state();
        if (st.previous_version)
            throw NeedsConfirmation(
                "vault_master_finalize",
                fmt::format("This ends the recovery window now: the previous vault master (version {}) is deleted "
                            "for good, after every key row is verified under version {}. A rollback is no longer "
                            "possible, and database backups from before the rotation then restore only through the "
                            "vault key exports. Continue?",
                            *st.previous_version, st.version));
    }
    return audited(actor, action, [&] {
        auto r = rw::finalize();
        if (r.finalized)
            auditAs(actor, action, vh::audit::Outcome::Success,
                    {{"previous", *r.previous}, {"rows", r.rows}, {"deleted", r.deleted}},
                    fmt::format("finalized the vault master rotation: {} key row(s) verified, previous version {} "
                                "deleted", r.rows, *r.previous),
                    spdlog::level::warn);
        else
            auditAs(actor, action, vh::audit::Outcome::Info, {{"deleted", r.deleted}},
                    "ran a vault master finalize with no recovery window open");
        return r;
    });
}

rw::RollbackResult rollback(const Actor& actor, const bool confirmed) {
    constexpr const char* action = "secrets.master.rollback";
    requireSuperAdmin(actor, action);
    if (!confirmed) {
        const auto st = rw::state();
        if (st.previous_version)
            throw NeedsConfirmation(
                "vault_master_rollback",
                fmt::format("This returns every vault key to the previous vault master (version {}) and deletes "
                            "version {}. Continue?",
                            *st.previous_version, st.version));
        if (st.staging_version)
            throw NeedsConfirmation("vault_master_rollback",
                                    fmt::format("This abandons the staged vault master version {} (nothing was "
                                                "switched to it yet). Continue?",
                                                *st.staging_version));
    }
    return audited(actor, action, [&] {
        auto r = rw::rollback();
        const bool abandoned = r.kind == rw::RollbackResult::Kind::AbandonedStaging;
        auditAs(actor, action, vh::audit::Outcome::Success,
                {{"kind", abandoned ? "abandoned_staging" : "reverted"}, {"from", r.from}, {"to", r.to},
                 {"rows", r.rows}, {"rewrapped", r.rewrapped}},
                abandoned ? fmt::format("abandoned the staged vault master version {}", r.from)
                          : fmt::format("rolled the vault master back from version {} to {}: {} key row(s) restored "
                                        "from their retained wrap, {} rewrapped",
                                        r.from, r.to, r.rows, r.rewrapped),
                spdlog::level::warn);
        return r;
    });
}

nlohmann::json toJson(const rw::Status& s) {
    nlohmann::json byMaster = nlohmann::json::object();
    for (const auto& [v, n] : s.by_master) byMaster[std::to_string(v)] = n;
    std::string phase = "idle";
    if (s.state.staging_version) phase = "staging";
    if (s.state.previous_version) phase = "recovery_window";
    return {
        {"phase", phase},
        {"version", s.state.version},
        {"slot", vault::master::slotName(s.state.version)},
        {"posture", std::string(crypto::secrets::KeyProvider::posture())},
        {"backend", std::string(crypto::secrets::KeyProvider::backend())},
        {"current_sealed", s.current_sealed},
        {"staging_version", orNull(s.state.staging_version)},
        {"staging_started_at", orNull(isoOf(s.state.staging_started_at))},
        {"staging_sealed", s.state.staging_version ? nlohmann::json(s.staging_sealed) : nlohmann::json(nullptr)},
        {"staged_rows", s.staged},
        {"previous_version", orNull(s.state.previous_version)},
        {"previous_sealed", s.state.previous_version ? nlohmann::json(s.previous_sealed) : nlohmann::json(nullptr)},
        {"switched_at", orNull(isoOf(s.state.switched_at))},
        {"window_until", orNull(isoOf(s.state.window_until))},
        {"retained_rows", s.retained},
        {"rows", s.rows},
        {"rows_by_master_version", byMaster},
        {"pending_deletions", s.state.discard_versions},
    };
}

nlohmann::json toJson(const rw::RotateResult& r) {
    return {{"from", r.from},           {"to", r.to},           {"rows", r.rows},
            {"staged", r.staged_now},   {"caught_up", r.caught_up}, {"batches", r.batches},
            {"resumed", r.resumed},     {"window_until", orNull(isoOf(r.window_until))}};
}

nlohmann::json toJson(const rw::FinalizeResult& r) {
    return {{"finalized", r.finalized}, {"previous", orNull(r.previous)}, {"rows", r.rows}, {"deleted", r.deleted}};
}

nlohmann::json toJson(const rw::RollbackResult& r) {
    return {{"kind", r.kind == rw::RollbackResult::Kind::AbandonedStaging ? "abandoned_staging" : "reverted"},
            {"from", r.from},
            {"to", r.to},
            {"rows", r.rows},
            {"rewrapped", r.rewrapped}};
}

}
