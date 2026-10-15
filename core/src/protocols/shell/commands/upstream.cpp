// `vh upstream …` (#237, #96): the CLI adapter for ops::upstream. Same authorization and behaviour as the ws
// upstream.* commands; JSON output uses the shared shapes (ops/UpstreamJson.hpp).

#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/lineHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "db/encoding/timestamp.hpp"
#include "identities/User.hpp"
#include "ops/Upstream.hpp"
#include "ops/UpstreamJson.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Vault.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <sodium.h>

#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace vh::protocols::shell::commands::upstream_cli {

namespace {

namespace up = vh::ops::upstream;
namespace padmin = vh::storage::s3::provider::admin;

up::KeyRef keyRef(const std::string& nameOrId) {
    if (const auto id = parseUInt(nameOrId)) return *id;
    return nameOrId;
}

std::string when(const std::optional<std::time_t>& t) {
    return t ? db::encoding::timestampToString(*t) : std::string("-");
}

std::string dash(const std::optional<std::string>& s) { return s && !s->empty() ? *s : std::string("-"); }

template <typename T>
std::string asJson(const T& value) {
    auto out = nlohmann::json(value).dump(4);
    out.push_back('\n');
    return out;
}

std::optional<unsigned int> uintOption(const CommandCall& call, const std::string& name) {
    const auto v = optVal(call, name);
    if (!v) return std::nullopt;
    const auto n = parseUInt(*v);
    if (!n) throw ops::Invalid("--" + name + " must be a whole number");
    return n;
}

// Runs `op(confirmed)`; a NeedsConfirmation{code} is asked at the terminal (the person types `word`) or answered by
// --yes, then the op runs again confirmed. Without a terminal it refuses with the op's text.
template <class Op, class Format>
CommandResult runConfirmed(const CommandCall& call, const std::string& prefix, const std::string& code,
                           const std::string& word, Op&& op, Format&& format) {
    const auto refused = [&](const std::string& why) { return invalid(prefix + ": " + why); };
    bool confirmed = hasFlag(call, "yes");
    try {
        for (;;) {
            try {
                return ok(format(op(confirmed)));
            } catch (const ops::NeedsConfirmation& e) {
                if (e.code != code || confirmed) throw;
                if (!call.io) return refused(std::string(e.what()) + "\nRe-run with --yes to confirm.");
                if (call.io->prompt(std::string(e.what()) + "\nType " + word + " to continue", "no") != word)
                    return refused("not confirmed; nothing was changed");
                confirmed = true;
            }
        }
    } catch (const ops::Error& e) {
        return refused(e.what());
    }
}

// ---- formatting -------------------------------------------------------------------------------------------------

std::string formatAdmin(const up::AdminStatus& s) {
    std::ostringstream out;
    out << "API key: " << (s.key ? s.key->name + " (ID " + std::to_string(s.key->id) + ")" : std::string("-")) << "\n"
        << "  Provider administration: " << (s.supported ? (s.enabled ? "enabled" : "disabled") : "not supported") << "\n";
    if (!s.supported && !s.unsupported_reason.empty()) out << "  " << s.unsupported_reason << "\n";
    out << "  Account: " << dash(s.account_ref) << "\n";
    if (s.key && s.key->provider == vh::vault::model::S3Provider::CloudflareR2)
        out << "  Cloudflare API token: " << (s.has_provider_token ? "stored" : "none") << "\n";
    if (s.capabilities) {
        out << "  Capabilities (checked " << when(s.capabilities->checked_at ? std::optional(s.capabilities->checked_at)
                                                                              : std::nullopt)
            << "):\n";
        for (const auto& c : s.capabilities->items)
            out << "    " << (c.ok ? "[ok]      " : "[missing] ") << c.name << (c.probed ? "" : " (not probed)")
                << (c.detail.empty() ? "" : ": " + c.detail) << "\n";
    }
    return out.str();
}

std::string formatBucket(const up::BucketRow& b) {
    std::ostringstream out;
    out << "Bucket '" << b.name << "': " << up::to_string(b.state) << "\n"
        << "  Region: " << dash(b.region) << "\n"
        << "  Ownership: " << b.ownership << " (provisioning " << b.provisioning_state << ")\n"
        << "  Vault: " << (b.vault_id ? dash(b.vault_name) + " (ID " + std::to_string(*b.vault_id) + ")" : "-") << "\n";
    if (b.is_protected)
        out << "  Protected: by " << dash(b.protected_by) << " at " << when(b.protected_at) << ": "
            << dash(b.protection_reason) << "\n";
    if (b.events_state) out << "  Events: " << *b.events_state << "\n";
    return out.str();
}

std::string formatInventory(const up::Inventory& inv) {
    std::ostringstream out;
    out << "Buckets in " << inv.provider << " account " << inv.account_ref << ":\n";
    if (inv.buckets.empty()) out << "  (none)\n";
    else {
        Table tbl({{"Bucket", Align::Left, 4, 48, false, false},
                   {"State", Align::Left, 4, 10, false, false},
                   {"Region", Align::Left, 4, 14, false, false},
                   {"Vault", Align::Left, 4, 24, false, false},
                   {"Events", Align::Left, 4, 10, false, false}},
                  term_width());
        for (const auto& b : inv.buckets)
            tbl.add_row({b.name, up::to_string(b.state), dash(b.region),
                         b.vault_id ? dash(b.vault_name) + " (" + std::to_string(*b.vault_id) + ")" : "-",
                         dash(b.events_state)});
        out << tbl.render();
    }
    if (!inv.next_token.empty()) out << "More buckets: --page-token " << inv.next_token << "\n";
    return out.str();
}

std::string formatLifecycleRule(const padmin::LifecycleRule& r) {
    std::ostringstream out;
    out << "    " << (r.foreign ? "[other]      " : "[vaulthalla] ") << r.id << (r.enabled ? "" : " (disabled)")
        << (r.prefix.empty() ? "" : " prefix=" + r.prefix);
    if (r.abort_incomplete_multipart_days) out << " abort-multipart=" << *r.abort_incomplete_multipart_days << "d";
    if (r.expire_current_days) out << " expire=" << *r.expire_current_days << "d";
    if (r.expire_noncurrent_days) out << " expire-noncurrent=" << *r.expire_noncurrent_days << "d";
    out << "\n";
    return out.str();
}

std::string formatInspection(const up::Inspection& i) {
    std::ostringstream out;
    out << formatBucket(i.bucket) << "  Versioning: " << padmin::to_string(i.config.versioning) << "\n"
        << "  Object lock: " << (i.config.object_lock ? (*i.config.object_lock ? "enabled" : "off") : "unknown") << "\n"
        << "  Lifecycle rules:" << (i.config.lifecycle_readable ? "" : " (not readable)") << "\n";
    if (i.config.lifecycle.empty()) out << "    (none)\n";
    for (const auto& r : i.config.lifecycle) out << formatLifecycleRule(r);
    out << "  Event notification rules:" << (i.config.notifications_readable ? "" : " (not readable)") << "\n";
    if (i.config.notifications.empty()) out << "    (none)\n";
    for (const auto& n : i.config.notifications) {
        out << "    " << (n.foreign ? "[other]      " : "[vaulthalla] ") << n.id << " -> "
            << (n.destination_name.empty() ? n.destination : n.destination_name);
        if (!n.prefix.empty()) out << " prefix=" << n.prefix;
        if (!n.suffix.empty()) out << " suffix=" << n.suffix;
        out << "\n";
    }
    if (!i.supported_lifecycle_fields.empty()) {
        out << "  Settable lifecycle fields:";
        for (const auto& f : i.supported_lifecycle_fields) out << " " << f;
        out << "\n";
    }
    for (const auto& w : i.config.warnings) out << "  Warning: " << w << "\n";
    return out.str();
}

std::string formatAdmission(const up::AdmissionReport& r) {
    std::ostringstream out;
    out << formatBucket(r.bucket) << "  Objects scanned: " << r.objects_scanned << (r.truncated ? "+ (stopped at the limit)" : "")
        << ", " << r.bytes_scanned << " bytes\n"
        << "  Sample: " << r.sampled << " objects, " << r.sampled_vaulthalla_encrypted << " Vaulthalla-encrypted, "
        << r.sampled_plaintext << " plaintext\n"
        << "  Vaulthalla manifest: " << (r.has_vaulthalla_manifest ? "present (another vault's data)" : "none") << "\n"
        << "  Versioning: " << padmin::to_string(r.versioning) << ", object lock: "
        << (r.object_lock ? (*r.object_lock ? "enabled" : "off") : "unknown") << "\n";
    if (r.recommended_encrypt_upstream)
        out << "  Recommended upstream encryption: " << (*r.recommended_encrypt_upstream ? "on" : "off") << "\n";
    for (const auto& k : r.sample_keys) out << "    " << k << "\n";
    for (const auto& w : r.warnings) out << "  Warning: " << w << "\n";
    for (const auto& b : r.blockers) out << "  Blocked: " << b << "\n";
    out << (r.blockers.empty() ? "Adoption possible.\n" : "Adoption refused.\n");
    return out.str();
}

std::string formatCleanupPlan(const up::CleanupPlan& p) {
    std::ostringstream out;
    out << formatBucket(p.bucket) << "  Would delete: " << p.objects << " objects, " << p.versions << " versions, "
        << p.delete_markers << " delete markers, " << p.bytes << " bytes" << (p.truncated ? " (at least: counting stopped)" : "")
        << "\n  Versioning: " << padmin::to_string(p.versioning) << ", object lock: "
        << (p.object_lock ? (*p.object_lock ? "enabled" : "off") : "unknown") << "\n";
    for (const auto& k : p.sample_keys) out << "    " << k << "\n";
    for (const auto& w : p.warnings) out << "  Warning: " << w << "\n";
    for (const auto& b : p.blockers) out << "  Blocked: " << b << "\n";
    if (p.blockers.empty() && !p.confirm_token.empty())
        out << "  Confirm token: " << p.confirm_token << " (valid until " << when(p.expires_at) << ")\n";
    return out.str();
}

std::string formatCleanupResult(const up::CleanupResult& r) {
    std::ostringstream out;
    out << "Cleanup " << r.outcome << ": " << r.deleted << " deleted, " << r.failed << " failed"
        << (r.bucket_deleted ? ", bucket deleted" : "") << "\n";
    for (const auto& e : r.errors) out << "  " << e << "\n";
    if (r.outcome == "partial") out << "Run the command again to continue.\n";
    return out.str();
}

std::string formatEvents(const up::EventStatus& e) {
    std::ostringstream out;
    out << "Vault '" << e.vault_name << "' (ID " << e.vault_id << ")" << (e.bucket.empty() ? "" : ", bucket " + e.bucket)
        << ":\n";
    if (!e.supported) {
        out << "  Event-driven sync not available: " << e.unsupported_reason << "\n";
        return out.str();
    }
    out << "  State: " << e.state << " (baseline " << e.baseline_state << ", foreign objects " << e.foreign_objects
        << ")\n";
    if (e.last_error) out << "  Last error: " << *e.last_error << "\n";
    if (!e.rule_ids.empty()) {
        out << "  Rules:";
        for (const auto& r : e.rule_ids) out << " " << r;
        out << " (+" << e.foreign_rules << " other applications' rules)\n";
    }
    if (e.channel) {
        const auto& c = *e.channel;
        out << "  Queue: " << c.queue_name << " [" << c.state << "]" << (c.region.empty() ? "" : " in " + c.region) << "\n"
            << "    Last poll: " << when(c.last_poll_at) << ", last message: " << when(c.last_message_at)
            << ", backlog: " << (c.backlog ? std::to_string(*c.backlog) : std::string("unknown")) << "\n";
        if (c.consecutive_failures || c.last_error)
            out << "    Failures in a row: " << c.consecutive_failures << ", last error: " << dash(c.last_error) << " ("
                << when(c.last_error_at) << ")\n";
    }
    out << "  Inbox: " << e.inbox_pending << " pending, " << e.inbox_applied << " applied, " << e.inbox_failed
        << " failed; last 24 h: " << e.inbox_done_24h << " handled, " << e.inbox_self_24h << " own writes\n"
        << "  Last event: " << when(e.last_event_at) << "\n";
    return out.str();
}

std::string formatAudit(const std::vector<up::AuditEntry>& entries) {
    if (entries.empty()) return "No upstream audit entries.\n";
    Table tbl({{"When", Align::Left, 4, 22, false, false},
               {"Who", Align::Left, 4, 16, false, false},
               {"Action", Align::Left, 4, 18, false, false},
               {"Bucket", Align::Left, 4, 40, false, false},
               {"Outcome", Align::Left, 4, 8, false, false}},
              term_width());
    for (const auto& e : entries)
        tbl.add_row({db::encoding::timestampToString(e.at), dash(e.user_name), e.action, e.bucket, e.outcome});
    return tbl.render();
}

unsigned int vaultIdFrom(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage, const std::string& prefix) {
    const auto lookup = vault::resolveVault(call, call.positionals.at(0), usage, prefix);
    if (!lookup || !lookup.ptr) throw ops::Invalid(lookup.error);
    return lookup.ptr->id;
}

// ---- handlers ---------------------------------------------------------------------------------------------------

CommandResult adminEnable(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "admin", "enable"});
    validatePositionals(call, usage);
    up::AdminEnable req;
    req.clear_provider_token = hasFlag(call, "clear-provider-token");
    if (hasFlag(call, "provider-token")) {
        if (req.clear_provider_token) return invalid("upstream admin enable: --provider-token and --clear-provider-token exclude each other");
        if (!call.io) return invalid("upstream admin enable: the Cloudflare API token is asked at a hidden prompt; run it in an interactive terminal");
        auto token = call.io->promptSecret("Cloudflare API token (Queues Edit + Workers R2 Storage Edit):");
        if (token.empty()) return invalid("upstream admin enable: the token cannot be empty");
        req.provider_token = token;
        sodium_memzero(token.data(), token.size());
    }
    auto result = runOp("upstream admin enable", [&] { return up::enableAdmin(call.user, keyRef(call.positionals[0]), req); },
                        formatAdmin);
    if (req.provider_token) sodium_memzero(req.provider_token->data(), req.provider_token->size());
    return result;
}

CommandResult adminDisable(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "admin", "disable"});
    validatePositionals(call, usage);
    return runOp("upstream admin disable", [&] { return up::disableAdmin(call.user, keyRef(call.positionals[0])); },
                 formatAdmin);
}

CommandResult adminStatus(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "admin", "status"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("upstream admin status",
                 [&] { return up::adminStatus(call.user, keyRef(call.positionals[0]), hasFlag(call, "probe")); },
                 [&](const auto& s) { return json ? asJson(s) : formatAdmin(s); });
}

CommandResult handleAdmin(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"upstream", "admin", "enable"}, sub)) return adminEnable(subcall);
    if (isCommandMatch({"upstream", "admin", "disable"}, sub)) return adminDisable(subcall);
    if (isCommandMatch({"upstream", "admin", "status"}, sub)) return adminStatus(subcall);
    return invalid(call.constructFullArgs(), "Unknown upstream admin subcommand: '" + std::string(sub) + "'");
}

CommandResult buckets(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "buckets"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("upstream buckets", [&] {
        up::InventoryQuery q;
        q.token = optVal(call, "page-token").value_or("");
        if (const auto limit = uintOption(call, "limit")) q.max = *limit;
        if (const auto state = optVal(call, "state")) q.state = up::bucketStateFromString(*state);
        q.filter = optVal(call, "filter");
        return up::inventory(call.user, keyRef(call.positionals[0]), q);
    }, [&](const auto& inv) { return json ? asJson(inv) : formatInventory(inv); });
}

CommandResult protect(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "protect"});
    validatePositionals(call, usage);
    return runOp("upstream protect", [&] {
        return up::protect(call.user, keyRef(call.positionals[0]), call.positionals[1], optVal(call, "reason").value_or(""));
    }, [](const auto& b) { return "Protected.\n" + formatBucket(b); });
}

CommandResult unprotect(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "unprotect"});
    validatePositionals(call, usage);
    return runConfirmed(call, "upstream unprotect", up::UNPROTECT_CONFIRM, "UNPROTECT", [&](const bool confirm) {
        return up::unprotect(call.user, keyRef(call.positionals[0]), call.positionals[1], confirm);
    }, [](const auto& b) { return formatBucket(b); });
}

CommandResult inspect(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "inspect"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("upstream inspect", [&] { return up::inspect(call.user, keyRef(call.positionals[0]), call.positionals[1]); },
                 [&](const auto& i) { return json ? asJson(i) : formatInspection(i); });
}

CommandResult lifecycle(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "lifecycle"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    up::LifecyclePatch patch;
    try {
        patch.abort_incomplete_multipart_days = uintOption(call, "abort-multipart-days");
        patch.expire_current_days = uintOption(call, "expire-days");
        patch.expire_noncurrent_days = uintOption(call, "expire-noncurrent-days");
        patch.prefix = optVal(call, "prefix");
        patch.clear = hasFlag(call, "clear");
    } catch (const ops::Error& e) {
        return invalid("upstream lifecycle: " + std::string(e.what()));
    }
    return runConfirmed(call, "upstream lifecycle", up::DESTRUCTIVE_LIFECYCLE, "EXPIRE", [&](const bool confirm) {
        auto attempt = patch;
        attempt.accept_destructive = confirm;
        return up::setLifecycle(call.user, keyRef(call.positionals[0]), call.positionals[1], attempt);
    }, [&](const auto& i) { return json ? asJson(i) : formatInspection(i); });
}

CommandResult adoptCheck(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "adopt-check"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("upstream adopt-check", [&] {
        return up::adoptPreflight(call.user, keyRef(call.positionals[0]), call.positionals[1],
                                  uintOption(call, "max-objects").value_or(10000), uintOption(call, "sample").value_or(16));
    }, [&](const auto& r) { return json ? asJson(r) : formatAdmission(r); });
}

CommandResult detach(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "detach"});
    validatePositionals(call, usage);
    return runOp("upstream detach", [&] { return up::detach(call.user, keyRef(call.positionals[0]), call.positionals[1]); },
                 [](const auto& b) { return "Detached: Vaulthalla no longer manages this bucket. Its data is untouched.\n" +
                                            formatBucket(b); });
}

CommandResult cleanup(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "cleanup"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    const bool deleteBucket = !hasFlag(call, "keep-bucket");
    const auto& bucket = call.positionals[1];
    const auto prefix = std::string("upstream cleanup");
    try {
        const auto key = keyRef(call.positionals[0]);
        auto token = optVal(call, "confirm-token");
        if (!token || hasFlag(call, "preflight")) {
            const auto plan = up::cleanupPreflight(call.user, key, bucket);
            const auto planText = json ? asJson(plan) : formatCleanupPlan(plan);
            if (hasFlag(call, "preflight")) return ok(planText);
            if (!plan.blockers.empty()) return invalid(planText + prefix + ": refused (see the blockers above)");
            if (!call.io)
                return invalid(planText + prefix + ": re-run with --confirm-token " + plan.confirm_token +
                               " to delete the bucket and everything in it");
            call.io->print(planText);
            if (call.io->prompt("Type the bucket name to delete it and everything in it", "") != bucket)
                return invalid(prefix + ": not confirmed; nothing was deleted");
            token = plan.confirm_token;
        }
        const auto result = up::cleanup(call.user, key, bucket, *token, deleteBucket);
        auto out = ok(json ? asJson(result) : formatCleanupResult(result));
        if (result.outcome == "partial" || result.outcome == "refused") out.exit_code = 1;
        return out;
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

CommandResult eventsEnable(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "events", "enable"});
    validatePositionals(call, usage);
    return runOp("upstream events enable", [&] {
        up::EventsEnable req;
        req.prefix = optVal(call, "prefix").value_or("");
        req.foreign_objects = optVal(call, "foreign-objects");
        return up::enableEvents(call.user, vaultIdFrom(call, usage, "upstream events enable"), req);
    }, formatEvents);
}

CommandResult eventsDisable(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "events", "disable"});
    validatePositionals(call, usage);
    return runOp("upstream events disable", [&] {
        return up::disableEvents(call.user, vaultIdFrom(call, usage, "upstream events disable"));
    }, formatEvents);
}

CommandResult eventsRepair(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "events", "repair"});
    validatePositionals(call, usage);
    return runOp("upstream events repair", [&] {
        return up::repairEvents(call.user, vaultIdFrom(call, usage, "upstream events repair"));
    }, formatEvents);
}

CommandResult eventsStatus(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "events", "status"});
    // The vault is optional here: without one, every S3 vault the caller may view.
    if (call.positionals.size() > 1) return invalid("upstream events status: expected at most one vault");
    const bool json = hasFlag(call, "json");
    return runOp("upstream events status", [&] {
        std::optional<unsigned int> vaultId;
        if (!call.positionals.empty()) vaultId = vaultIdFrom(call, usage, "upstream events status");
        return up::eventStatus(call.user, vaultId);
    }, [&](const std::vector<up::EventStatus>& all) {
        if (json) return asJson(all);
        if (all.empty()) return std::string("No S3 vaults.\n");
        std::string out;
        for (const auto& e : all) out += formatEvents(e);
        return out;
    });
}

CommandResult handleEvents(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"upstream", "events", "enable"}, sub)) return eventsEnable(subcall);
    if (isCommandMatch({"upstream", "events", "disable"}, sub)) return eventsDisable(subcall);
    if (isCommandMatch({"upstream", "events", "repair"}, sub)) return eventsRepair(subcall);
    if (isCommandMatch({"upstream", "events", "status"}, sub)) return eventsStatus(subcall);
    return invalid(call.constructFullArgs(), "Unknown upstream events subcommand: '" + std::string(sub) + "'");
}

CommandResult audit(const CommandCall& call) {
    const auto usage = resolveUsage({"upstream", "audit"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("upstream audit", [&] {
        up::AuditQuery q;
        q.bucket = optVal(call, "bucket");
        if (const auto limit = uintOption(call, "limit")) q.limit = *limit;
        return up::audit(call.user, q);
    }, [&](const auto& entries) { return json ? asJson(entries) : formatAudit(entries); });
}

CommandResult handleUpstream(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"upstream", "admin"}, sub)) return handleAdmin(subcall);
    if (isCommandMatch({"upstream", "buckets"}, sub)) return buckets(subcall);
    if (isCommandMatch({"upstream", "protect"}, sub)) return protect(subcall);
    if (isCommandMatch({"upstream", "unprotect"}, sub)) return unprotect(subcall);
    if (isCommandMatch({"upstream", "inspect"}, sub)) return inspect(subcall);
    if (isCommandMatch({"upstream", "lifecycle"}, sub)) return lifecycle(subcall);
    if (isCommandMatch({"upstream", "adopt-check"}, sub)) return adoptCheck(subcall);
    if (isCommandMatch({"upstream", "detach"}, sub)) return detach(subcall);
    if (isCommandMatch({"upstream", "cleanup"}, sub)) return cleanup(subcall);
    if (isCommandMatch({"upstream", "events"}, sub)) return handleEvents(subcall);
    if (isCommandMatch({"upstream", "audit"}, sub)) return audit(subcall);
    return invalid(call.constructFullArgs(), "Unknown upstream subcommand: '" + std::string(sub) + "'");
}

}

}

void vh::protocols::shell::commands::registerUpstreamCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("upstream"), upstream_cli::handleUpstream);
}
