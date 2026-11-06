#include "ops/MasterSecrets.hpp"
#include "auth/stepup/StepUp.hpp"

#include "audit/Trail.hpp"
#include "auth/session/Manager.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Manager.hpp"
#include "db/query/device/Device.hpp"
#include "device/Pairing.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/User.hpp"
#include "protocols/device/Service.hpp"
#include "runtime/Deps.hpp"
#include "runtime/Manager.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

namespace vh::ops::master_secrets {

namespace {

namespace rw = crypto::secrets::rewrap;
namespace vs = crypto::secrets::versioned;

constexpr std::chrono::seconds kMaxWindow{std::chrono::hours(24 * 90)};

void auditAs(const Actor& actor, const std::string& action, const vh::audit::Outcome outcome, nlohmann::json details,
             const std::string& message, const spdlog::level::level_enum level = spdlog::level::info) {
    vh::audit::record({.action = action, .outcome = outcome, .actor_id = actor ? std::optional<uint32_t>(actor->id)
                                                                                : std::nullopt,
                       .actor = actor ? actor->name() : std::string{}, .details = std::move(details)},
                      "[ops::master_secrets] " + (actor ? actor->name() : std::string("?")) + " " + message, level);
}

void requireSuperAdmin(const Actor& actor, const std::string& action, const std::string& what,
                       nlohmann::json details = nlohmann::json::object()) {
    requireActor(actor);
    if (actor->isSuperAdmin()) return;
    auditAs(actor, action, vh::audit::Outcome::Denied, std::move(details),
            "was refused " + action + ": super admins only", spdlog::level::warn);
    throw Denied("only super admins can manage the " + what);
}

// Runs one step, auditing a refusal or failure (with its code) before it propagates.
template <class Fn>
auto audited(const Actor& actor, const std::string& action, nlohmann::json details, Fn&& fn) {
    try {
        return fn();
    } catch (const NeedsConfirmation&) {
        throw;
    } catch (const Refused& e) {
        details["code"] = e.code;
        auditAs(actor, action, vh::audit::Outcome::Failure, details, action + " refused: " + e.what(),
                spdlog::level::warn);
        throw;
    } catch (const std::exception& e) {
        details["code"] = "fault";
        auditAs(actor, action, vh::audit::Outcome::Failure, details, action + " failed: " + e.what(),
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

std::string slotId(const Slot slot) { return std::string(vs::id(slot)); }
std::string nounOf(const Slot slot) { return std::string(vs::noun(slot)); }
nlohmann::json slotDetails(const Slot slot) { return {{"slot", slotId(slot)}}; }

std::string masterCommand(const Slot slot, const std::string_view op) {
    auto out = fmt::format("vh secret master {}", op);
    if (slot != Slot::VaultMaster) out += fmt::format(" --slot {}", vs::cliName(slot));
    return out;
}

// What the slot's rows are, and what a database backup from before the rotation needs once the old master is gone.
std::string rotationWarning(const Slot slot, const std::chrono::seconds window) {
    const auto hours = std::chrono::duration_cast<std::chrono::hours>(window).count();
    const auto posture = crypto::secrets::KeyProvider::posture();
    const auto rollbackCmd = masterCommand(slot, "rollback");
    switch (slot) {
        case Slot::VaultMaster:
            return fmt::format("This replaces the vault master (sealed with '{}' sealing) that wraps every vault key. "
                               "File contents are not re-encrypted. The old master stays for a recovery window of {} "
                               "hours, during which `{}` returns to it; after that it is deleted. Database backups "
                               "taken before the rotation need the old master: once it is deleted, they restore only "
                               "through the vault key exports (vh vault keys export). Continue?",
                               posture, hours, rollbackCmd);
        case Slot::ApiKeyMaster:
            return fmt::format("This replaces the API key master (sealed with '{}' sealing) that wraps every provider "
                               "API key's secret and provider token. The secrets themselves don't change and nothing "
                               "is sent to the providers. The old master stays for a recovery window of {} hours, "
                               "during which `{}` returns to it; after that it is deleted. Database backups taken "
                               "before the rotation need the old master: once it is deleted, the API keys in such a "
                               "backup have to be entered again. Continue?",
                               posture, hours, rollbackCmd);
        case Slot::GatewayMaster:
            return fmt::format("This replaces the S3 gateway master (sealed with '{}' sealing) that wraps every S3 "
                               "gateway credential's secret. Clients keep their access keys and secrets. The old "
                               "master stays for a recovery window of {} hours, during which `{}` returns to it; after "
                               "that it is deleted. Database backups taken before the rotation need the old master: "
                               "once it is deleted, the credentials in such a backup have to be reissued. Continue?",
                               posture, hours, rollbackCmd);
    }
    return "Continue?";
}

}

// ---- the staged rewrap of a data-wrapping master ----------------------------------------------------------------

rw::Status status(const Actor& actor, const Slot slot) {
    requireSuperAdmin(actor, "secrets.master.status", nounOf(slot), slotDetails(slot));
    return rw::status(slot);
}

rw::RotateResult rotate(const Actor& actor, const RotateRequest& request) {
    constexpr const char* action = "secrets.master.rotate";
    const auto slot = request.slot;
    requireSuperAdmin(actor, action, nounOf(slot), slotDetails(slot));
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
    if (!request.confirmed) throw NeedsConfirmation(slotId(slot) + "_rotate", rotationWarning(slot, options.window));
    auto details = slotDetails(slot);
    details["window_seconds"] = options.window.count();
    auditAs(actor, action, vh::audit::Outcome::Info, details, "started a " + nounOf(slot) + " rotation");
    auth::stepup::require(auth::stepup::Family::Secrets);  // #359
    return audited(actor, action, slotDetails(slot), [&] {
        auto r = rw::rotate(slot, options);
        auditAs(actor, action, vh::audit::Outcome::Success,
                {{"slot", slotId(slot)}, {"from", r.from}, {"to", r.to}, {"rows", r.rows}, {"staged", r.staged_now},
                 {"caught_up", r.caught_up}, {"batches", r.batches}, {"resumed", r.resumed},
                 {"window_until", r.window_until}},
                fmt::format("rotated the {} from version {} to {}: {} row(s) rewrapped and verified, {} staged now "
                            "in {} batch(es){}, {} caught up at the switch; the previous master is kept until {}",
                            nounOf(slot), r.from, r.to, r.rows, r.staged_now, r.batches,
                            r.resumed ? " (resumed)" : "", r.caught_up, isoOf(r.window_until).value_or("?")),
                spdlog::level::warn);
        return r;
    });
}

rw::FinalizeResult finalize(const Actor& actor, const Slot slot, const bool confirmed) {
    constexpr const char* action = "secrets.master.finalize";
    requireSuperAdmin(actor, action, nounOf(slot), slotDetails(slot));
    if (!confirmed) {
        const auto st = rw::state(slot);
        if (st.previous_version)
            throw NeedsConfirmation(
                slotId(slot) + "_finalize",
                fmt::format("This ends the recovery window now: the previous {} (version {}) is deleted for good, "
                            "after every row is verified under version {}. A rollback is no longer possible, and "
                            "database backups from before the rotation then need {}. Continue?",
                            nounOf(slot), *st.previous_version, st.version,
                            slot == Slot::VaultMaster  ? "the vault key exports"
                            : slot == Slot::ApiKeyMaster ? "their API keys entered again"
                                                         : "their gateway credentials reissued"));
    }
    auth::stepup::require(auth::stepup::Family::Secrets);  // #359
    return audited(actor, action, slotDetails(slot), [&] {
        auto r = rw::finalize(slot);
        if (r.finalized)
            auditAs(actor, action, vh::audit::Outcome::Success,
                    {{"slot", slotId(slot)}, {"previous", *r.previous}, {"rows", r.rows}, {"deleted", r.deleted}},
                    fmt::format("finalized the {} rotation: {} row(s) verified, previous version {} deleted",
                                nounOf(slot), r.rows, *r.previous),
                    spdlog::level::warn);
        else
            auditAs(actor, action, vh::audit::Outcome::Info, {{"slot", slotId(slot)}, {"deleted", r.deleted}},
                    "ran a " + nounOf(slot) + " finalize with no recovery window open");
        return r;
    });
}

rw::RollbackResult rollback(const Actor& actor, const Slot slot, const bool confirmed) {
    constexpr const char* action = "secrets.master.rollback";
    requireSuperAdmin(actor, action, nounOf(slot), slotDetails(slot));
    if (!confirmed) {
        const auto st = rw::state(slot);
        if (st.previous_version)
            throw NeedsConfirmation(slotId(slot) + "_rollback",
                                    fmt::format("This returns every row to the previous {} (version {}) and deletes "
                                                "version {}. Continue?",
                                                nounOf(slot), *st.previous_version, st.version));
        if (st.staging_version)
            throw NeedsConfirmation(slotId(slot) + "_rollback",
                                    fmt::format("This abandons the staged {} version {} (nothing was switched to it "
                                                "yet). Continue?",
                                                nounOf(slot), *st.staging_version));
    }
    auth::stepup::require(auth::stepup::Family::Secrets);  // #359
    return audited(actor, action, slotDetails(slot), [&] {
        auto r = rw::rollback(slot);
        const bool abandoned = r.kind == rw::RollbackResult::Kind::AbandonedStaging;
        auditAs(actor, action, vh::audit::Outcome::Success,
                {{"slot", slotId(slot)}, {"kind", abandoned ? "abandoned_staging" : "reverted"}, {"from", r.from},
                 {"to", r.to}, {"rows", r.rows}, {"rewrapped", r.rewrapped}},
                abandoned ? fmt::format("abandoned the staged {} version {}", nounOf(slot), r.from)
                          : fmt::format("rolled the {} back from version {} to {}: {} row(s) restored from their "
                                        "retained wrap, {} rewrapped",
                                        nounOf(slot), r.from, r.to, r.rows, r.rewrapped),
                spdlog::level::warn);
        return r;
    });
}

// ---- the JWT secret ---------------------------------------------------------------------------------------------

JwtRotation rotateJwtSecret(const Actor& actor, const bool confirmed) {
    constexpr const char* action = "secrets.jwt.rotate";
    requireSuperAdmin(actor, action, "JWT secret");
    if (!confirmed)
        throw NeedsConfirmation(
            "jwt_secret_rotate",
            "This replaces the JWT secret that signs every session. Everyone is signed out at once: every refresh "
            "token is revoked and every open console connection is closed, so every user signs in again (paired "
            "devices reconnect by themselves with their device keys; share-link visitors keep their share sessions). "
            "There is no rollback: the old secret is discarded. Continue?");
    auditAs(actor, action, vh::audit::Outcome::Info, nlohmann::json::object(), "started a JWT secret rotation");
    auth::stepup::require(auth::stepup::Family::Secrets);  // #359
    return audited(actor, action, nlohmann::json::object(), [&] {
        const auto& deps = runtime::Deps::get();
        if (!deps.secretsManager) throw std::runtime_error("the secrets manager is not running");
        JwtRotation out;
        // One transaction: the new secret and the revocation of every stored refresh token. From its commit on, no
        // token signed before verifies, in memory or in the database.
        out.refresh_tokens_revoked = deps.secretsManager->rotateJWTSecret();
        if (deps.sessionManager) out.sessions_ended = deps.sessionManager->endAll();
        auditAs(actor, action, vh::audit::Outcome::Success,
                {{"refresh_tokens_revoked", out.refresh_tokens_revoked}, {"sessions_ended", out.sessions_ended}},
                fmt::format("rotated the JWT secret: {} refresh token(s) revoked, {} live session(s) ended; everyone "
                            "signs in again",
                            out.refresh_tokens_revoked, out.sessions_ended),
                spdlog::level::warn);
        return out;
    });
}

// ---- the device listener identity -------------------------------------------------------------------------------

DeviceIdentityRotation rotateDeviceIdentity(const Actor& actor, const bool confirmed) {
    constexpr const char* action = "secrets.device_identity.rotate";
    requireSuperAdmin(actor, action, "device identity");
    using Devices = db::query::device::Devices;
    if (!confirmed)
        throw NeedsConfirmation(
            "device_identity_rotate",
            fmt::format("This replaces the device listener's identity: the TLS key every paired Desktop pins. Every "
                        "paired device ({} now) is revoked and disconnected and has to pair again with a new pairing "
                        "code; pairing requests in progress are dropped. There is no rollback: the old key is "
                        "deleted. Continue?",
                        Devices::countActive()));
    auditAs(actor, action, vh::audit::Outcome::Info, nlohmann::json::object(),
            "started a device identity rotation");
    auth::stepup::require(auth::stepup::Family::Secrets);  // #359
    return audited(actor, action, nlohmann::json::object(), [&] {
        auto& pairing = vh::device::Pairing::instance();
        DeviceIdentityRotation out;
        // Requests in flight were bound to the old key: none of them may complete against either one.
        out.pairing_requests_dropped = pairing.abandonAll();
        const auto r = vh::device::rotateServerIdentity();  // revokes every paired device with the switch
        out.from = r.from;
        out.to = r.to;
        out.spki_sha256 = r.identity->spkiHex();
        out.previous_spki_sha256 = r.previous_spki_sha256;
        out.devices_revoked = r.devices_revoked;
        if (const auto service = runtime::Manager::instance().getDeviceServer()) {
            service->replaceIdentity(r.identity);
            out.listener_updated = service->isRunning();
        } else if (vh::device::currentServerIdentity()) {
            vh::device::setCurrentServerIdentity(r.identity);
        }
        out.pairing_requests_dropped += pairing.abandonAll();
        out.sessions_closed = protocols::device::closeAllDeviceListenerSessions();
        // A pairing approved between the switch and the swap was still bound to the old key.
        out.devices_revoked += Devices::revokeAll();
        auditAs(actor, action, vh::audit::Outcome::Success,
                {{"from", out.from}, {"to", out.to}, {"spki_sha256", out.spki_sha256},
                 {"previous_spki_sha256", out.previous_spki_sha256}, {"devices_revoked", out.devices_revoked},
                 {"sessions_closed", out.sessions_closed}, {"pairing_requests_dropped", out.pairing_requests_dropped},
                 {"listener_updated", out.listener_updated}},
                fmt::format("rotated the device identity from version {} to {} (SPKI sha256 {}): {} paired device(s) "
                            "revoked, {} connection(s) closed; every device pairs again",
                            out.from, out.to, out.spki_sha256, out.devices_revoked, out.sessions_closed),
                spdlog::level::warn);
        return out;
    });
}

// ---- JSON ---------------------------------------------------------------------------------------------------------

nlohmann::json toJson(const rw::Status& s) {
    nlohmann::json byMaster = nlohmann::json::object();
    for (const auto& [v, n] : s.by_master) byMaster[std::to_string(v)] = n;
    std::string phase = "idle";
    if (s.state.staging_version) phase = "staging";
    if (s.state.previous_version) phase = "recovery_window";
    return {
        {"slot", slotId(s.slot)},
        {"phase", phase},
        {"version", s.state.version},
        {"sealed_name", vs::slotName(s.slot, s.state.version)},
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

nlohmann::json toJson(const JwtRotation& r) {
    return {{"refresh_tokens_revoked", r.refresh_tokens_revoked}, {"sessions_ended", r.sessions_ended}};
}

nlohmann::json toJson(const DeviceIdentityRotation& r) {
    return {{"from", r.from},
            {"to", r.to},
            {"spki_sha256", r.spki_sha256},
            {"previous_spki_sha256", r.previous_spki_sha256.empty() ? nlohmann::json(nullptr)
                                                                     : nlohmann::json(r.previous_spki_sha256)},
            {"devices_revoked", r.devices_revoked},
            {"sessions_closed", r.sessions_closed},
            {"pairing_requests_dropped", r.pairing_requests_dropped},
            {"listener_updated", r.listener_updated}};
}

}
