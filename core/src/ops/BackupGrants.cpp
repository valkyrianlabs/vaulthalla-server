#include "ops/BackupGrants.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Recovery.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/device/Device.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "notifications/AccountSecurity.hpp"
#include "ops/Devices.hpp"
#include "ops/VaultKeys.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/permission/admin/keys/Encryption.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <deque>
#include <iterator>
#include <mutex>
#include <span>
#include <unordered_map>
#include <utility>

namespace vh::ops::backup_grants {

namespace {

using Grants = db::query::device::BackupGrants;
using DeviceRows = db::query::device::Devices;
using SteadyClock = std::chrono::steady_clock;

// A vault list longer than this is refused (a grant names vaults one by one; thousands is not a backup scope).
constexpr std::size_t kMaxGrantVaults = 4096;

// ---- the export cap ---------------------------------------------------------------------------------------------------

struct GrantExportWindows {
    std::mutex mutex;
    std::unordered_map<uint32_t, std::deque<SteadyClock::time_point>> uses;
};

GrantExportWindows& grantExportWindows() {
    static GrantExportWindows w;
    return w;
}

// Reserves `n` exports in the grant's sliding hour; false (nothing reserved) when that would exceed the cap.
bool grantReserveExports(const uint32_t grantId, const std::size_t n) {
    auto& w = grantExportWindows();
    std::scoped_lock lock(w.mutex);
    auto& q = w.uses[grantId];
    const auto now = SteadyClock::now();
    while (!q.empty() && now - q.front() >= kExportWindow) q.pop_front();
    if (q.size() + n > kMaxExportsPerHour) return false;
    for (std::size_t i = 0; i < n; ++i) q.push_back(now);
    return true;
}

void grantClearExports(const uint32_t grantId) {
    auto& w = grantExportWindows();
    std::scoped_lock lock(w.mutex);
    w.uses.erase(grantId);
}

std::mutex& grantNoticeMutex() {
    static std::mutex m;
    return m;
}

SuspendNotice& grantNoticeSink() {
    static SuspendNotice sink;
    return sink;
}

// ---- helpers ----------------------------------------------------------------------------------------------------------

std::optional<int64_t> grantUnix(const std::optional<std::time_t>& t) {
    return t ? std::optional<int64_t>(static_cast<int64_t>(*t)) : std::nullopt;
}

nlohmann::json grantOptJson(const std::optional<int64_t>& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); }

void grantAudit(const std::string& action, const Grant& g, const std::optional<uint32_t> actorId,
                const std::string& actorName, nlohmann::json extra, const std::string& message,
                const spdlog::level::level_enum level = spdlog::level::info) {
    nlohmann::json details{{"grant_id", g.id}, {"device", g.device_id}, {"user_id", g.user_id},
                           {"vault_count", static_cast<int64_t>(g.vault_ids.size())}};
    for (auto& [k, v] : extra.items()) details[k] = std::move(v);
    vh::audit::record({.action = action, .actor_id = actorId, .actor = actorName, .details = std::move(details)},
                      message, level);
}

std::string grantActorName(const std::optional<uint32_t> actorId) {
    if (!actorId) return "vaulthalla";
    const auto u = identities::manager().user(*actorId);
    return u ? u->name() : std::string("user ") + std::to_string(*actorId);
}

// Ascending, unique, positive, bounded.
std::vector<uint32_t> grantVaultList(std::vector<uint32_t> ids) {
    if (ids.empty()) throw Invalid("vault_ids must name at least one vault");
    if (ids.size() > kMaxGrantVaults) throw Invalid("vault_ids names too many vaults");
    std::ranges::sort(ids);
    const auto [first, last] = std::ranges::unique(ids);
    ids.erase(first, last);
    if (ids.front() == 0) throw Invalid("vault IDs must be positive integers");
    return ids;
}

std::string grantVaultTarget(const std::string& prefix, const std::vector<uint32_t>& ids) {
    std::string list;
    for (const auto id : ids) {
        if (!list.empty()) list += ',';
        list += std::to_string(id);
    }
    if (prefix.size() + list.size() <= auth::stepup::kMaxTargetLength) return prefix + list;
    const auto digest = vh::device::crypto::sha256(std::span(reinterpret_cast<const uint8_t*>(list.data()), list.size()));
    return prefix + "sha256:" + vh::device::crypto::toHex(digest).substr(0, 32);
}

void requireHolder(const Actor& actor) {
    requireActor(actor);
    if (actor->systemOnly() || !mayHold(*actor))
        throw Denied("only super admins or users with the export encryption keys permission can hold key-backup grants");
}

// Every vault must be one the actor may export now.
void requireExportable(const Actor& actor, const std::vector<uint32_t>& ids) {
    const auto mine = vault_keys::exportableVaults(actor);
    for (const auto id : ids)
        if (!std::ranges::binary_search(mine, static_cast<unsigned int>(id)))
            throw NotFound("no vault with ID " + std::to_string(id) + " that you may export");
}

// The calling device's live row (its own session), or the actor's own device named by `ref` (a console session).
vh::device::Device grantDeviceOf(const Actor& actor, const vh::device::Peer* self, const std::optional<std::string>& ref) {
    std::optional<vh::device::Device> row;
    if (self) {
        if (!self->deviceRowId) throw Refused("device_unknown", "this device is not paired with this node");
        row = DeviceRows::byId(*self->deviceRowId);
        if (ref && !ref->empty()) {
            const auto named = devices::get(actor, *ref);
            if (!row || named.id != row->id) throw Denied("a device manages its own key-backup grant only");
        }
    } else {
        if (!ref || ref->empty()) throw Invalid("device_id is required (the device the grant is for)");
        row = devices::get(actor, *ref);
    }
    if (!row || row->revoked() || row->user_id != actor->id)
        throw NotFound("no paired device of yours " + (ref ? "'" + *ref + "'" : std::string("here")));
    return *row;
}

// A live grant the actor may manage: their own (on a device's session, that device's only); super admins may revoke
// anyone's (revocation only).
Grant grantOf(const Actor& actor, const vh::device::Peer* self, const uint32_t grantId, const bool adminMay) {
    const auto g = Grants::byId(grantId);
    const bool owner = g && g->user_id == actor->id;
    if (!g || (!owner && !(adminMay && actor->isSuperAdmin())))
        throw NotFound("no key-backup grant " + std::to_string(grantId));
    if (self && (!self->deviceRowId || g->device_id != *self->deviceRowId))
        throw NotFound("no key-backup grant " + std::to_string(grantId) + " on this device");
    if (!g->live()) throw Conflict("key-backup grant " + std::to_string(grantId) + " was revoked");
    return *g;
}

// How the person approved the device.trust step-up that is about to be spent (read before require() spends it).
std::optional<std::string> grantApprovalMethod(const std::string& target) {
    const auto* scope = auth::stepup::Scope::current();
    if (!scope || !scope->session()) return std::nullopt;
    for (const auto& g : scope->session()->stepUp().grants())
        if (g.family == auth::stepup::Family::DeviceTrust && g.target == target) {
            if (g.method == "webauthn" || g.method == "password_totp" ||
                g.method == auth::stepup::kDeviceApprovalMethod || g.method == auth::stepup::kConsoleApprovalMethod)
                return g.method;
            return std::nullopt;
        }
    return std::nullopt;
}

[[noreturn]] void grantRefuseCooldown(const int64_t until, const std::string& why) {
    throw RecoveryCooldown("device.trust", until, "This account recently recovered its sign-in: " + why);
}

std::string grantDeviceShort(const uint32_t deviceId) {
    const auto d = DeviceRows::byId(deviceId);
    return d ? d->spki_sha256.substr(0, 16) + " ('" + d->name + "')" : "#" + std::to_string(deviceId);
}

void grantNotifySuspended(const Grant& g) {
    SuspendNotice sink;
    {
        std::scoped_lock lock(grantNoticeMutex());
        sink = grantNoticeSink();
    }
    try {
        if (sink) {
            sink(g);
            return;
        }
        notifications::account::send({
            .event = "keys.backup_grant_suspended",
            .title = "Automatic key backup paused on a device",
            .summary = "A paired device exported more than " + std::to_string(kMaxExportsPerHour) +
                       " vault keys within an hour, so its automatic key backup was suspended.",
            .user_id = g.user_id,
            .facts = {{"Grant", std::to_string(g.id)}, {"Device", grantDeviceShort(g.device_id)},
                      {"Vaults", std::to_string(g.vault_ids.size())}},
            .advice = std::string("If this was not a key backup you expected, revoke the device in Devices. Otherwise "
                                  "confirm its key backup there to resume it."),
        });
    } catch (const std::exception& e) {
        log::Registry::auth()->warn("[ops::backup_grants] suspension notice failed: {}", e.what());
    }
}

// The trigger that holds for a live grant now, if any.
std::optional<Revocation> grantTriggerFor(const Grant& g, const std::time_t now) {
    const auto device = DeviceRows::byId(g.device_id);
    if (!device || device->revoked()) return Revocation::DeviceRevoked;
    const auto seen = device->last_seen_at.value_or(device->created_at);
    if (now - seen > std::chrono::duration_cast<std::chrono::seconds>(kDeviceIdle).count()) return Revocation::DeviceIdle;
    const auto user = identities::manager().user(g.user_id);
    if (!user || user->deleted() || !user->authorizing() || user->systemOnly()) return Revocation::UserInactive;
    if (!mayHold(*user)) return Revocation::ExportPermission;
    return std::nullopt;
}

}

std::string_view to_string(const Revocation why) noexcept {
    switch (why) {
        case Revocation::Manual: return "manual";
        case Revocation::DeviceRevoked: return "device_revoked";
        case Revocation::UserInactive: return "user_inactive";
        case Revocation::ExportPermission: return "export_permission";
        case Revocation::RecoveryCode: return "recovery_code";
        case Revocation::AdminReset: return "admin_reset";
        case Revocation::CliReset: return "cli_reset";
        case Revocation::DeviceIdle: return "device_idle";
    }
    return "manual";
}

nlohmann::json toJson(const Grant& g) { return toJson(g, DeviceRows::byId(g.device_id)); }

nlohmann::json toJson(const Grant& g, const std::optional<vh::device::Device>& device) {
    return {{"id", g.id},
            {"device_id", device ? nlohmann::json(device->spki_sha256) : nlohmann::json(nullptr)},
            {"device_name", device ? nlohmann::json(device->name) : nlohmann::json(nullptr)},
            {"origin", g.origin},
            {"approved_via", g.approved_via ? nlohmann::json(*g.approved_via) : nlohmann::json(nullptr)},
            {"vault_ids", g.vault_ids},
            {"created_at", static_cast<int64_t>(g.created_at)},
            {"confirmed_at", grantOptJson(grantUnix(g.confirmed_at))},
            {"last_used_at", grantOptJson(grantUnix(g.last_used_at))},
            {"suspended_at", grantOptJson(grantUnix(g.suspended_at))},
            {"revoked_at", grantOptJson(grantUnix(g.revoked_at))},
            {"revoked_reason", g.revoked_reason ? nlohmann::json(*g.revoked_reason) : nlohmann::json(nullptr)},
            {"active", g.active()}};
}

bool mayHold(const identities::User& user) {
    return user.authorizing() && (user.isSuperAdmin() || user.encryptionKeysPerms().canExport());
}

std::string createTarget(const uint32_t deviceRowId, std::vector<uint32_t> vaultIds) {
    return grantVaultTarget("device.backup.grant.create:" + std::to_string(deviceRowId) + ":",
                            grantVaultList(std::move(vaultIds)));
}

std::string extendTarget(const uint32_t grantId, std::vector<uint32_t> vaultIds) {
    return grantVaultTarget("device.backup.grant.extend:" + std::to_string(grantId) + ":",
                            grantVaultList(std::move(vaultIds)));
}

std::string confirmTarget(const uint32_t grantId) { return "device.backup.grant.confirm:" + std::to_string(grantId); }

bool recoveryRecreateTarget(const uint32_t deviceRowId, const std::string& target) {
    if (!target.starts_with("device.backup.grant.create:" + std::to_string(deviceRowId) + ":")) return false;
    if (Grants::liveForDevice(deviceRowId)) return false;
    const auto last = Grants::lastRevokedForDevice(deviceRowId);
    return last && last->revoked_reason == std::string(to_string(Revocation::RecoveryCode)) &&
           Grants::approvalKeyPredatesRevocation(deviceRowId, last->id);
}

// ---- commands ---------------------------------------------------------------------------------------------------------

std::vector<Grant> list(const Actor& actor, const vh::device::Peer* self) {
    requireActor(actor);
    // What the console shows is the truth now: a trigger that holds ends the grant before it is listed.
    (void)reconcile(std::vector<uint32_t>{actor->id});
    auto out = Grants::listForUser(actor->id);
    if (self) std::erase_if(out, [&](const Grant& g) { return !self->deviceRowId || g.device_id != *self->deviceRowId; });
    return out;
}

Grant create(const Actor& actor, const vh::device::Peer* self, const std::optional<std::string>& device,
             const std::vector<uint32_t>& vaultIds) {
    requireHolder(actor);
    const auto ids = grantVaultList(vaultIds);
    const auto row = grantDeviceOf(actor, self, device);
    requireExportable(actor, ids);
    if (Grants::liveForDevice(row.id))
        throw Conflict("this device already has a key-backup grant: extend it instead");
    const auto target = createTarget(row.id, ids);

    std::optional<std::string> via;
    bool recreated = false;
    if (const auto until = auth::mfa::recovery::cooldownUntil(actor->id)) {
        // D4, the one exception to the recovery cooldown (auth::stepup refuses device.trust while it runs, before any
        // grant counts): the same device re-creates the grant the recovery-code sign-in revoked, with its approval key
        // registered before the recovery, for vaults that grant named. Nothing else: no console approval (a passkey
        // may have been enrolled during the recovery), no other device, no wider vault set, no MFA reset.
        if (!self)
            grantRefuseCooldown(*until, "a key-backup grant can only be re-created on the device itself until the "
                                        "cooldown ends");
        const auto last = Grants::lastRevokedForDevice(row.id);
        if (!last || last->revoked_reason != std::string(to_string(Revocation::RecoveryCode)))
            grantRefuseCooldown(*until, "new key-backup grants wait until the recovery cooldown ends");
        if (!std::ranges::includes(last->vault_ids, ids))
            grantRefuseCooldown(*until, "the re-created grant may only name vaults the revoked one named");
        if (!Grants::approvalKeyPredatesRevocation(row.id, last->id))
            grantRefuseCooldown(*until, "only this device's approval key registered before the recovery can re-create "
                                        "its grant");
        const auto* scope = auth::stepup::Scope::current();
        const auto& session = scope ? scope->session() : nullptr;
        bool approved = !scope;  // no request: the daemon's own callers and tests
        if (session) {
            const auto mine = session->stepUp().grants();
            const bool byKey = std::ranges::any_of(mine, [&](const auth::stepup::Grant& g) {
                return g.family == auth::stepup::Family::DeviceTrust && g.target == target &&
                       g.method == auth::stepup::kDeviceApprovalMethod;
            });
            approved = byKey &&
                       session->stepUp().use(actor->id, {}, auth::stepup::Family::DeviceTrust, target).has_value();
        }
        if (!approved)
            auth::stepup::refuse(auth::stepup::Family::DeviceTrust, target,
                                 {std::string(auth::stepup::kDeviceApprovalMethod)},
                                 "Approve re-creating this device's key backup with its approval key (Touch ID)");
        if (session) via = std::string(auth::stepup::kDeviceApprovalMethod);
        recreated = true;
    } else {
        via = grantApprovalMethod(target);
        auth::stepup::require(auth::stepup::Family::DeviceTrust, target);
    }

    auto g = Grants::create({.device_id = row.id, .user_id = actor->id, .origin = "approved", .approved_via = via,
                             .vault_ids = ids});
    grantAudit("keys.backup.grant.create", g, actor->id, actor->name(),
               {{"via", via ? nlohmann::json(*via) : nlohmann::json(nullptr)}, {"recovery_recreate", recreated}},
               "[ops::backup_grants] " + actor->name() + " turned on key backup for " + std::to_string(ids.size()) +
                   " vault(s) on device " + grantDeviceShort(row.id) + (recreated ? " (re-created after recovery)" : ""));
    return g;
}

Grant extend(const Actor& actor, const vh::device::Peer* self, const uint32_t grantId,
             const std::vector<uint32_t>& vaultIds) {
    requireHolder(actor);
    const auto ids = grantVaultList(vaultIds);
    const auto g = grantOf(actor, self, grantId, false);
    requireExportable(actor, ids);
    std::vector<uint32_t> added;
    std::ranges::set_difference(ids, g.vault_ids, std::back_inserter(added));
    if (added.empty()) throw Conflict("the grant already names every one of these vaults");
    const auto target = extendTarget(g.id, ids);
    const auto via = grantApprovalMethod(target);
    auth::stepup::require(auth::stepup::Family::DeviceTrust, target);
    const auto next = Grants::addVaults(g.id, added);
    if (!next) throw Conflict("key-backup grant " + std::to_string(grantId) + " was revoked");
    grantAudit("keys.backup.grant.extend", *next, actor->id, actor->name(),
               {{"added", static_cast<int64_t>(added.size())}, {"via", via ? nlohmann::json(*via) : nlohmann::json(nullptr)}},
               "[ops::backup_grants] " + actor->name() + " added " + std::to_string(added.size()) +
                   " vault(s) to the key-backup grant of device " + grantDeviceShort(g.device_id));
    return *next;
}

Grant confirm(const Actor& actor, const vh::device::Peer* self, const uint32_t grantId) {
    requireHolder(actor);
    const auto g = grantOf(actor, self, grantId, false);
    const auto target = confirmTarget(g.id);
    const auto via = grantApprovalMethod(target);
    auth::stepup::require(auth::stepup::Family::DeviceTrust, target);
    const auto next = Grants::confirm(g.id, via);
    if (!next) throw Conflict("key-backup grant " + std::to_string(grantId) + " was revoked");
    grantClearExports(g.id);
    grantAudit("keys.backup.grant.confirm", *next, actor->id, actor->name(),
               {{"from", g.origin}, {"was_suspended", g.suspended_at.has_value()},
                {"via", via ? nlohmann::json(*via) : nlohmann::json(nullptr)}},
               "[ops::backup_grants] " + actor->name() + " confirmed the key-backup grant of device " +
                   grantDeviceShort(g.device_id));
    return *next;
}

Grant revoke(const Actor& actor, const vh::device::Peer* self, const uint32_t grantId) {
    requireActor(actor);
    const auto g = grantOf(actor, self, grantId, true);
    const auto revoked = Grants::revoke(g.id, std::string(to_string(Revocation::Manual)));
    if (!revoked) throw Conflict("key-backup grant " + std::to_string(grantId) + " was revoked");
    grantClearExports(g.id);
    auditRevoked({*revoked}, Revocation::Manual, actor->id);
    return *revoked;
}

// ---- the export path --------------------------------------------------------------------------------------------------

std::optional<Use> covering(const std::vector<uint32_t>& vaultIds) {
    const auto* scope = auth::stepup::Scope::current();
    if (!scope || scope->channel() != auth::stepup::Channel::Device) return std::nullopt;
    const auto& session = scope->session();
    if (!session || !session->user || !session->devicePeer() || !session->devicePeer()->deviceRowId) return std::nullopt;
    const auto& user = session->user;
    const auto g = Grants::liveForDevice(*session->devicePeer()->deviceRowId);
    if (!g || g->user_id != user->id) return std::nullopt;
    // The triggers, at the moment of use.
    if (const auto why = grantTriggerFor(*g, std::time(nullptr))) {
        (void)revokeForDevice(g->device_id, *why);
        return std::nullopt;
    }
    if (!g->active()) return std::nullopt;
    if (!std::ranges::all_of(vaultIds, [&](const uint32_t v) { return g->names(v); })) return std::nullopt;
    if (!grantReserveExports(g->id, vaultIds.size())) {
        if (const auto suspended = Grants::suspend(g->id)) {
            grantClearExports(g->id);
            grantAudit("keys.backup.grant.suspend", *suspended, std::nullopt, "vaulthalla",
                       {{"reason", "export_cap"}, {"cap_per_hour", static_cast<int64_t>(kMaxExportsPerHour)}},
                       "[ops::backup_grants] the key-backup grant of device " + grantDeviceShort(g->device_id) + " (" +
                           user->name() + ") was suspended: more than " + std::to_string(kMaxExportsPerHour) +
                           " vault key exports in an hour. Confirm it again to resume automatic backup.",
                       spdlog::level::warn);
            grantNotifySuspended(*suspended);
        }
        return std::nullopt;
    }
    return Use{.grant_id = g->id, .device_id = g->device_id, .user_id = user->id, .user_name = user->name()};
}

void recordUse(const Use& use, const uint32_t vaultId, const std::vector<unsigned int>& versions) {
    try {
        Grants::touch(use.grant_id);
    } catch (const std::exception& e) {
        log::Registry::auth()->warn("[ops::backup_grants] last_used_at of grant {} not recorded: {}", use.grant_id, e.what());
    }
    std::string list;
    for (const auto v : versions) {
        if (!list.empty()) list += ',';
        list += std::to_string(v);
    }
    vh::audit::record({.action = "keys.backup.export", .actor_id = use.user_id, .actor = use.user_name,
                       .vault_id = vaultId,
                       .details = {{"grant_id", use.grant_id}, {"device", use.device_id}, {"versions", list}}},
                      "[ops::backup_grants] device " + grantDeviceShort(use.device_id) + " backed up the key(s) of vault " +
                          std::to_string(vaultId) + " (version(s) " + list + ") under key-backup grant " +
                          std::to_string(use.grant_id));
}

// ---- automatic revocation ---------------------------------------------------------------------------------------------

void auditRevoked(const std::vector<Grant>& grants, const Revocation why, const std::optional<uint32_t> actorId) {
    const auto actorName = grantActorName(actorId);
    for (const auto& g : grants) {
        grantClearExports(g.id);
        grantAudit("keys.backup.grant.revoke", g, actorId, actorName, {{"reason", std::string(to_string(why))}},
                   "[ops::backup_grants] the key-backup grant of device " + grantDeviceShort(g.device_id) +
                       " was revoked (" + std::string(to_string(why)) + ")");
    }
}

std::vector<Grant> revokeForDevice(const uint32_t deviceId, const Revocation why, const std::optional<uint32_t> actorId) {
    auto out = Grants::revokeForDevice(deviceId, std::string(to_string(why)));
    auditRevoked(out, why, actorId);
    return out;
}

std::vector<Grant> revokeForUser(const uint32_t userId, const Revocation why, const std::optional<uint32_t> actorId) {
    auto out = Grants::revokeForUser(userId, std::string(to_string(why)));
    auditRevoked(out, why, actorId);
    return out;
}

bool revokeIfIdle(const vh::device::Device& device, const std::time_t now) {
    if (device.revoked()) return false;
    const auto seen = device.last_seen_at.value_or(device.created_at);
    if (now - seen <= std::chrono::duration_cast<std::chrono::seconds>(kDeviceIdle).count()) return false;
    return !revokeForDevice(device.id, Revocation::DeviceIdle).empty();
}

std::size_t reconcile(const std::optional<std::vector<uint32_t>>& userIds) {
    const auto live = userIds ? Grants::listLiveForUsers(*userIds) : Grants::listLive();
    std::size_t revoked = 0;
    const auto now = std::time(nullptr);
    for (const auto& g : live)
        if (const auto why = grantTriggerFor(g, now)) revoked += revokeForDevice(g.device_id, *why).size();
    return revoked;
}

void installIdentityHook() {
    identities::Manager::setPublishedHook([](const std::vector<uint32_t>& userIds, const bool everyone) {
        if (everyone) (void)reconcile();
        else if (!userIds.empty()) (void)reconcile(userIds);
    });
}

// ---- D1 ---------------------------------------------------------------------------------------------------------------

std::size_t migratePending() {
    std::size_t made = 0;
    for (const auto& p : Grants::pendingMigration()) {
        std::optional<std::vector<uint32_t>> vaults;
        std::shared_ptr<identities::User> user;
        if (p.device_live) user = identities::manager().user(p.user_id);
        if (user && !user->systemOnly() && mayHold(*user)) {
            const auto exportable = vault_keys::exportableVaults(user);
            vaults = std::vector<uint32_t>(exportable.begin(), exportable.end());
        }
        const auto g = Grants::migrate(p.device_id, p.user_id, vaults);
        if (!g) {
            log::Registry::auth()->info("[ops::backup_grants] D1: device {} gets no key-backup grant (its user may not "
                                        "export vault keys, or it was revoked)",
                                        p.device_id);
            continue;
        }
        if (g->revoked_at) {
            // #360's interim revocation, carried over: a record of what the device could export, granting nothing.
            grantAudit("keys.backup.grant.migrate", *g, std::nullopt, "vaulthalla",
                       {{"reason", "d1"}, {"revoked_reason", g->revoked_reason.value_or("")}},
                       "[ops::backup_grants] D1: device " + grantDeviceShort(g->device_id) + " of " + user->name() +
                           " had its key backup revoked (" + g->revoked_reason.value_or("") +
                           "); its migrated grant is recorded revoked");
            continue;
        }
        ++made;
        grantAudit("keys.backup.grant.migrate", *g, std::nullopt, "vaulthalla", {{"reason", "d1"}},
                   "[ops::backup_grants] D1: device " + grantDeviceShort(g->device_id) + " of " + user->name() +
                       " keeps its automatic key backup through a migrated grant over " +
                       std::to_string(g->vault_ids.size()) + " vault(s); confirm or revoke it in Devices");
    }
    return made;
}

// ---- tests ------------------------------------------------------------------------------------------------------------

void setSuspendNoticeForTesting(SuspendNotice sink) {
    std::scoped_lock lock(grantNoticeMutex());
    grantNoticeSink() = std::move(sink);
}

void resetExportWindowsForTesting() {
    auto& w = grantExportWindows();
    std::scoped_lock lock(w.mutex);
    w.uses.clear();
}

}
