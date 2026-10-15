// ops::upstream event-driven sync control (#96): authorization and refusal mapping over the trusted
// sync::events::subscriptions primitives.

#include "ops/Upstream.hpp"

#include "db/query/upstream/Audit.hpp"
#include "db/query/vault/APIKey.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/permission/admin/Upstream.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/permission/admin/keys/API.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/model/Audit.hpp"
#include "sync/events/Subscriptions.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <nlohmann/json.hpp>

namespace vh::ops::upstream {

namespace {

namespace subs = sync::events::subscriptions;
using EvUpPerm = rbac::permission::admin::UpstreamPermissions;
using EvKeyPerm = rbac::permission::admin::keys::APIPermissions;
using EvVaultPerm = rbac::permission::admin::VaultPermissions;

std::shared_ptr<vault::model::S3Vault> requireS3Vault(const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    const auto vault = runtime::Deps::get().storageManager->getVault(vaultId);
    if (!vault) throw NotFound("vault not found: " + std::to_string(vaultId));
    auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    if (!s3) throw Invalid("event-driven sync applies to S3 vaults only");
    return s3;
}

// The upstream permission, the vault (Edit for changes, View for status) and the vault key's keys.api permission.
std::shared_ptr<vault::model::S3Vault> authorizeVault(const Actor& actor, const unsigned int vaultId, const EvUpPerm up,
                                                      const EvVaultPerm vaultPerm, const EvKeyPerm keyPerm) {
    requireActor(actor);
    if (!rbac::resolver::Admin::has<EvUpPerm>({.user = actor, .permission = up}))
        throw Denied(up == EvUpPerm::View ? "this needs the admin.upstream.view permission"
                                          : "this needs the admin.upstream.configure permission");
    auto vault = requireS3Vault(vaultId);
    if (!rbac::resolver::Admin::has<EvVaultPerm>({.user = actor, .permission = vaultPerm, .vault_id = vaultId}))
        throw Denied("you do not have permission to manage vault '" + vault->name + "'");
    if (!rbac::resolver::Admin::has<EvKeyPerm>({.user = actor, .permission = keyPerm, .api_key_id = vault->api_key_id}))
        throw Denied("you do not have permission to use the API key of vault '" + vault->name + "'");
    return vault;
}

std::string supportGap(const vault::model::S3Vault& vault) {
    const auto key = db::query::vault::APIKey::getAPIKey(vault.api_key_id);
    if (!key) return "the vault's API key no longer exists";
    if (!padmin::supportsAdmin(*key)) return "event-driven sync supports AWS S3 and Cloudflare R2 vaults only";
    if (!key->admin_enabled)
        return "the vault's API key '" + key->name + "' is not enabled for provider administration";
    if (key->provider == vault::model::S3Provider::CloudflareR2 && !key->hasProviderToken())
        return "Cloudflare R2 event notifications need a Cloudflare API token (Account > Queues: Edit, Account > Workers R2 "
               "Storage: Edit) stored on API key '" + key->name + "'";
    return {};
}

EventStatus toStatus(const vault::model::S3Vault& vault, const subs::Status& s) {
    EventStatus out;
    out.vault_id = vault.id;
    out.vault_name = vault.name;
    out.bucket = s.bucket.empty() ? vault.bucket : s.bucket;
    out.unsupported_reason = supportGap(vault);
    out.supported = out.unsupported_reason.empty();
    out.state = s.state;
    out.baseline_state = s.baseline_state;
    out.foreign_objects = s.foreign_objects;
    out.last_error = s.last_error;
    out.rule_ids = s.rule_ids;
    out.foreign_rules = s.foreign_rules;
    if (s.channel) {
        const auto& c = *s.channel;
        out.channel = ChannelStatus{.provider = c.provider, .account_ref = c.account_ref, .region = c.region,
                                    .queue_name = c.queue_name, .state = c.state, .last_poll_at = c.last_poll_at,
                                    .last_message_at = c.last_message_at, .last_error_at = c.last_error_at,
                                    .last_error = c.last_error, .backlog = c.backlog,
                                    .consecutive_failures = c.consecutive_failures};
    }
    out.inbox_pending = s.inbox_pending;
    out.inbox_applied = s.inbox_applied;
    out.inbox_failed = s.inbox_failed;
    out.inbox_done_24h = s.inbox_done_24h;
    out.inbox_self_24h = s.inbox_self_24h;
    out.last_event_at = s.last_event_at;
    return out;
}

template <typename Fn>
auto eventsMapped(Fn&& fn) -> decltype(fn()) {
    try {
        return fn();
    } catch (const Error&) {
        throw;
    } catch (const storage::upstream::BucketProtected& e) {
        throw Denied(e.what());
    } catch (const padmin::CapabilityMissing& e) {
        throw Invalid(e.what());
    } catch (const padmin::ProviderError& e) {
        if (e.accessDenied()) throw Denied(std::string("the provider refused: ") + e.what());
        throw Invalid(std::string("the provider refused the event subscription: ") + e.what());
    } catch (const std::invalid_argument& e) {
        throw Invalid(e.what());
    }
}

void auditEvents(const Actor& actor, const std::string& action, const vault::model::S3Vault& vault,
                 const storage::upstream::model::AuditOutcome outcome, nlohmann::json detail) {
    storage::upstream::model::AuditRecord r;
    if (actor) {
        r.user_id = actor->id;
        r.user_name = actor->name();
    }
    r.action = action;
    if (const auto key = db::query::vault::APIKey::getAPIKey(vault.api_key_id)) {
        const auto id = storage::upstream::identityFor(*key, vault.bucket);
        r.provider = id.provider;
        r.account_ref = id.account_ref.value_or("");
    }
    r.bucket = vault.bucket;
    r.api_key_id = vault.api_key_id;
    r.vault_id = vault.id;
    r.outcome = outcome;
    r.detail_json = detail.is_object() ? detail.dump() : std::string("{}");
    db::query::upstream::Audit::appendNoThrow(r);
}

subs::Status run(const Actor& actor, const std::string& action, const vault::model::S3Vault& vault,
                 const std::function<subs::Status()>& fn) {
    try {
        auto s = eventsMapped(fn);
        auditEvents(actor, action, vault, storage::upstream::model::AuditOutcome::Ok, {{"state", s.state}});
        return s;
    } catch (const std::exception& e) {
        auditEvents(actor, action, vault, storage::upstream::model::AuditOutcome::Failed, {{"error", e.what()}});
        throw;
    }
}

}

EventStatus enableEvents(const Actor& actor, const unsigned int vaultId, const EventsEnable& req) {
    const auto vault = authorizeVault(actor, vaultId, EvUpPerm::Configure, EvVaultPerm::Edit, EvKeyPerm::Consume);
    if (const auto gap = supportGap(*vault); !gap.empty()) throw Invalid(gap);
    const auto foreign = req.foreign_objects.value_or("import");
    if (foreign != "import" && foreign != "ignore") throw Invalid("foreign objects must be import or ignore");
    const auto s = run(actor, "events.enable", *vault, [&] {
        return subs::enable({.vault_id = vaultId, .prefix = req.prefix, .foreign_objects = foreign, .baseline_required = false});
    });
    return toStatus(*vault, s);
}

EventStatus disableEvents(const Actor& actor, const unsigned int vaultId) {
    const auto vault = authorizeVault(actor, vaultId, EvUpPerm::Configure, EvVaultPerm::Edit, EvKeyPerm::Consume);
    return toStatus(*vault, run(actor, "events.disable", *vault, [&] { return subs::disable(vaultId); }));
}

EventStatus repairEvents(const Actor& actor, const unsigned int vaultId) {
    const auto vault = authorizeVault(actor, vaultId, EvUpPerm::Configure, EvVaultPerm::Edit, EvKeyPerm::Consume);
    if (const auto gap = supportGap(*vault); !gap.empty()) throw Invalid(gap);
    return toStatus(*vault, run(actor, "events.repair", *vault, [&] { return subs::repair(vaultId); }));
}

std::vector<EventStatus> eventStatus(const Actor& actor, const std::optional<unsigned int> vaultId) {
    requireActor(actor);
    if (vaultId) {
        const auto vault = authorizeVault(actor, *vaultId, EvUpPerm::View, EvVaultPerm::View, EvKeyPerm::View);
        return {toStatus(*vault, eventsMapped([&] { return subs::status(*vaultId); }))};
    }
    if (!rbac::resolver::Admin::has<EvUpPerm>({.user = actor, .permission = EvUpPerm::View}))
        throw Denied("this needs the admin.upstream.view permission");
    std::vector<EventStatus> out;
    for (const auto& engine : runtime::Deps::get().storageManager->getEngines()) {
        const auto s3 = engine ? std::dynamic_pointer_cast<vault::model::S3Vault>(engine->vault) : nullptr;
        if (!s3) continue;
        if (!rbac::resolver::Admin::has<EvVaultPerm>({.user = actor, .permission = EvVaultPerm::View, .vault_id = s3->id}))
            continue;
        try {
            out.push_back(toStatus(*s3, subs::status(s3->id)));
        } catch (const std::exception& e) {
            EventStatus failed = toStatus(*s3, subs::Status{});
            failed.last_error = e.what();
            out.push_back(std::move(failed));
        }
    }
    std::ranges::sort(out, {}, &EventStatus::vault_id);
    return out;
}

namespace detail {

std::optional<std::string> subscribeNewVault(const Actor& actor, const unsigned int vaultId, const std::string& prefix,
                                             const bool baselineRequired) noexcept {
    try {
        const auto vault = requireS3Vault(vaultId);
        if (const auto gap = supportGap(*vault); !gap.empty()) return "event-driven sync was not enabled: " + gap;
        (void)run(actor, "events.enable", *vault, [&] {
            return subs::enable({.vault_id = vaultId, .prefix = prefix, .foreign_objects = "import",
                                 .baseline_required = baselineRequired});
        });
        return std::nullopt;
    } catch (const std::exception& e) {
        return std::string("event-driven sync was not enabled (repair it from the vault's settings): ") + e.what();
    }
}

}

}
