// `vh recovery …`: the CLI adapter for the recovery-point half of ops::recovery (list, inspect, plan, restore,
// delete, costs). Same authorization and behaviour as the ws recovery.* commands; --json prints the shared shapes
// (ops/RecoveryJson.hpp). Also defines the formatting shared with `vh snapshot …` and `vh vault recovery …`
// (protocols/shell/commands/recovery.hpp).

#include "protocols/shell/commands/recovery.hpp"

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
#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "vault/model/Vault.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::protocols::shell::commands::recovery_cli {

namespace {

namespace rec = vh::ops::recovery;
namespace model = vh::recovery;

constexpr std::size_t kRcMaxRows = 200;   // human tables; --json has everything

std::string rcWhen(const std::optional<std::time_t>& t) {
    return t && *t ? db::encoding::timestampToString(*t) : std::string("-");
}

std::string rcWhen(const std::time_t t) { return t ? db::encoding::timestampToString(t) : std::string("-"); }

std::string rcDash(const std::optional<std::string>& s) { return s && !s->empty() ? *s : std::string("-"); }

std::string rcSize(const std::optional<uint64_t>& b) { return b ? human_bytes(*b) : std::string("-"); }

// The CLI spelling of an enum's text form (local_snapshots → local-snapshots).
std::string rcDashed(std::string s) {
    std::ranges::replace(s, '_', '-');
    return s;
}

std::string rcBackend(const model::Backend b) {
    switch (b) {
    case model::Backend::LocalSnapshot: return "snapshot";
    case model::Backend::LocalVersion: return "local";
    case model::Backend::ProviderVersion: return "provider";
    }
    return "?";
}

// A decimal string as the server sent it, without trailing zeros past two decimals ("0.02300000" → "0.023").
std::string rcAmount(std::string amount) {
    const auto dot = amount.find('.');
    if (dot == std::string::npos) return amount;
    while (amount.size() > dot + 3 && amount.back() == '0') amount.pop_back();
    return amount;
}

std::string rcPointInfo(const model::RecoveryPoint& p) {
    std::vector<std::string> parts;
    if (p.name) parts.push_back("\"" + *p.name + "\"");
    if (p.kind == model::PointKind::Directory) parts.emplace_back("directory");
    if (p.file_count) parts.push_back(std::to_string(*p.file_count) + " files");
    if (p.reason) parts.push_back(*p.reason);
    if (p.upstream_state && *p.upstream_state != "none") parts.push_back("upstream " + *p.upstream_state);
    if (p.is_current) parts.emplace_back("current");
    if (p.is_delete_marker) parts.emplace_back("delete marker");
    if (p.origin && *p.origin != "vaulthalla") parts.push_back("written by " + *p.origin);
    if (!p.restorable) parts.push_back("not restorable: " + rcDash(p.unavailable_reason));
    std::string out;
    for (const auto& s : parts) out += (out.empty() ? "" : ", ") + s;
    return out.empty() ? "-" : out;
}

std::string rcPointBlock(const model::RecoveryPoint& p) {
    std::ostringstream out;
    out << p.id << " (" << rcBackend(p.backend) << ", " << model::to_string(p.kind) << ")\n"
        << "  Vault: " << p.vault_id << "\n"
        << "  Path: " << p.path << "\n";
    if (p.name) out << "  Name: " << *p.name << "\n";
    out << "  Created: " << rcWhen(p.created_at) << "\n";
    if (p.valid_from || p.valid_until)
        out << "  Content current: " << rcWhen(p.valid_from) << " to " << (p.valid_until ? rcWhen(p.valid_until) : "now")
            << "\n";
    out << "  Size: " << rcSize(p.size_bytes) << (p.file_count ? ", " + std::to_string(*p.file_count) + " files" : "")
        << "\n";
    if (p.content_hash) out << "  Content hash: " << *p.content_hash << "\n";
    if (p.encryption.encrypted)
        out << "  Encryption: key version " << p.encryption.key_version
            << (p.encryption.key_current ? " (current)" : "")
            << (p.encryption.key_available ? "" : " (KEY NOT AVAILABLE)") << "\n";
    else
        out << "  Encryption: none\n";
    out << "  Retention: " << p.retention.policy;
    if (p.retention.expires_at) out << ", expires " << rcWhen(p.retention.expires_at);
    if (p.retention.note) out << " (" << *p.retention.note << ")";
    out << "\n";
    if (p.storage_class) out << "  Storage class: " << *p.storage_class << "\n";
    if (p.origin) out << "  Written by: " << *p.origin << "\n";
    if (p.reason) out << "  Retained on: " << *p.reason << "\n";
    if (p.upstream_state) out << "  Upstream: " << *p.upstream_state << "\n";
    if (p.is_current) out << "  Current provider version\n";
    if (p.is_delete_marker) out << "  Delete marker (restoring it means the file was absent)\n";
    if (p.estimated_monthly_cost) out << "  Estimated monthly cost: " << formatMoney(p.estimated_monthly_cost) << "\n";
    out << "  Restorable: " << (p.restorable ? std::string("yes") : "no (" + rcDash(p.unavailable_reason) + ")") << "\n";
    return out.str();
}

// ---- costs ------------------------------------------------------------------------------------------------------

std::string rcBucketLine(const model::CostReport& r) {
    std::ostringstream out;
    out << rcDash(r.provider) << " bucket " << rcDash(r.bucket) << " (" << rcDash(r.region) << ", "
        << rcDash(r.storage_class) << ")";
    return out.str();
}

std::string rcCatalogLine(const model::CostReport::Catalog& c) {
    std::ostringstream out;
    out << "Price catalog: " << (c.version ? "version " + *c.version : std::string("none"));
    if (c.source) out << " from " << *c.source;
    out << "; " << (c.verified ? "signature verified" : "NOT verified");
    out << "; " << (c.stale ? "STALE" : "current");
    if (c.age_seconds) out << " (" << (*c.age_seconds / 86400) << " days old)";
    if (c.note) out << "; " << *c.note;
    return out.str();
}

std::string rcConfidence(const model::CostReport& r) {
    std::ostringstream out;
    out << "Confidence: " << r.confidence;
    for (std::size_t i = 0; i < r.confidence_reasons.size(); ++i)
        out << (i ? "; " : " (") << r.confidence_reasons[i] << (i + 1 == r.confidence_reasons.size() ? ")" : "");
    return out.str();
}

std::string rcObservation(const model::CostReport::Observation& o) {
    std::ostringstream out;
    if (o.window_days == 0) {
        out << "Write traffic: not measured yet; the figures use the illustrative assumptions below\n";
        return out.str();
    }
    out << "Write traffic (observed over " << o.window_days << " day" << (o.window_days == 1 ? "" : "s");
    if (o.first_day && o.last_day) out << ", " << *o.first_day << " to " << *o.last_day;
    out << (o.sufficient ? "" : "; fewer than 7 days, so the range is wide") << "):\n"
        << "    " << o.overwrite_objects << " overwrites (" << human_bytes(o.overwritten_bytes) << "), "
        << o.deleted_objects << " deletes (" << human_bytes(o.deleted_bytes) << "), " << o.first_put_objects
        << " new objects; about " << o.overwritten_bytes_per_day << " bytes overwritten per day\n"
        << "    Requests: " << o.put_requests << " PUT, " << o.copy_requests << " COPY, " << o.delete_requests
        << " DELETE, " << o.get_requests << " GET, " << o.list_requests << " LIST\n";
    return out.str();
}

std::string rcScenarios(const std::vector<model::RetentionScenario>& scenarios) {
    if (scenarios.empty()) return "    (none)\n";
    Table tbl({{"Retention", Align::Left, 4, 12, false, false},
               {"Old versions kept", Align::Right, 4, 18, false, false},
               {"Monthly cost", Align::Left, 8, 60, true, false}},
              term_width());
    for (const auto& s : scenarios)
        tbl.add_row({s.retention, human_bytes(s.steady_noncurrent_bytes), formatFigure(s.monthly_cost)});
    std::string out = tbl.render();
    for (const auto& s : scenarios)
        for (const auto& n : s.notes) out += "    " + s.retention + ": " + n + "\n";
    return out;
}

std::string rcAccumulation(const std::vector<model::AccumulationPoint>& points) {
    if (points.empty()) return "    (not estimated)\n";
    Table tbl({{"Month", Align::Right, 5, 5, false, false},
               {"Old versions", Align::Right, 4, 14, false, false},
               {"Monthly cost", Align::Left, 8, 60, true, false}},
              term_width());
    for (const auto& p : points)
        tbl.add_row({std::to_string(p.month), human_bytes(p.noncurrent_bytes), formatFigure(p.monthly_cost)});
    return tbl.render();
}

std::string rcAssumptions(const std::vector<model::Assumption>& assumptions) {
    std::string out;
    for (const auto& a : assumptions) out += "  [" + a.kind + "] " + a.text + "\n";
    return out.empty() ? "  (none)\n" : out;
}

std::string rcUnmodeled(const std::vector<std::string>& unmodeled) {
    std::string out;
    for (const auto& u : unmodeled) out += "  - " + u + "\n";
    return out.empty() ? "  (nothing listed)\n" : out;
}

std::string rcRecoveryOps(const model::CostReport& r) {
    return "  Restore by transfer (GET + PUT + bytes), per GB: " + formatFigure(r.recovery_per_gb) + "\n" +
           "  Restore by provider copy, per object: " + formatFigure(r.recovery_per_object) + "\n";
}

std::string rcHistory(const model::CostReport::History& h) {
    std::ostringstream out;
    out << "  Known old versions: " << h.known_noncurrent_versions << " (" << human_bytes(h.known_noncurrent_bytes)
        << "), " << h.delete_markers << " delete markers";
    if (h.unknown_size_versions) out << ", " << h.unknown_size_versions << " of unknown size";
    out << "\n";
    if (h.unaccounted_history)
        out << "  Versions from before Vaulthalla monitored this bucket are not inventoried and not included"
            << (h.inventoried_at ? " (last inventory " + rcWhen(h.inventoried_at) + ")" : "") << ".\n";
    return out.str();
}

// ---- restore ----------------------------------------------------------------------------------------------------

std::optional<model::RecoveryId> rcRecoveryId(const std::string& s) {
    try {
        return model::RecoveryId::parse(s);
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}

std::string rcRestoreHint(const model::Plan& p) {
    return "vh recovery restore " + std::to_string(p.id) + " --token " + p.token;
}

// Shows the plan, asks (or takes --yes), restores with the plan's token, and reports. Exit 1 unless every item was
// restored or skipped as planned.
CommandResult rcRunPlan(const CommandCall& call, const model::Plan& plan, const bool json) {
    const std::string prefix = "recovery restore";
    const auto preview = json ? jsonText(plan) : formatPlan(plan);
    if (!plan.blockers.empty()) return invalid(preview + prefix + ": refused (see the blockers above)");

    const bool destructive = plan.overwrites + plan.removals > 0;
    if (!hasFlag(call, "yes")) {
        if (!call.io)
            return invalid(preview + prefix + ": not confirmed; nothing was restored. Re-run with --yes, or run " +
                           rcRestoreHint(plan));
        call.io->print(formatPlan(plan));
        if (destructive) {
            const auto what = std::to_string(plan.overwrites) + " file(s) will be overwritten and " +
                              std::to_string(plan.removals) + " removed.";
            if (call.io->prompt(what + " Type RESTORE to continue", "no") != "RESTORE")
                return invalid(prefix + ": not confirmed; nothing was restored");
        } else if (!call.io->confirm("Restore " + std::to_string(plan.creates) + " item(s)?", true)) {
            return invalid(prefix + ": not confirmed; nothing was restored");
        }
    }

    rec::RestoreRequest req{.plan_id = plan.id, .token = plan.token,
                            .accept_unverified = hasFlag(call, "accept-unverified")};
    try {
        for (;;) {
            try {
                const auto result = rec::restore(call.user, req);
                auto out = ok(json ? jsonText(result) : formatResult(result));
                if (result.state != "done" || result.conflicts || result.failed) out.exit_code = 1;
                return out;
            } catch (const ops::NeedsConfirmation& e) {
                if (e.code == rec::UNVERIFIED_VERSION && !req.accept_unverified) {
                    if (!call.io) return invalid(prefix + ": " + e.what() + "\nRe-run with --accept-unverified.");
                    if (call.io->prompt(std::string(e.what()) + "\nType UNVERIFIED to restore them anyway", "no") !=
                        "UNVERIFIED")
                        return invalid(prefix + ": not confirmed; nothing was restored");
                    req.accept_unverified = true;
                    continue;
                }
                if (e.code == rec::RESTORE_CONFIRM)
                    return invalid(prefix + ": " + e.what() + "\nThe plan's token is missing or expired: plan again.");
                throw;
            }
        }
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

// ---- handlers ---------------------------------------------------------------------------------------------------

CommandResult rcList(const CommandCall& call) {
    const auto usage = resolveUsage({"recovery", "list"});
    if (call.positionals.empty() || call.positionals.size() > 2)
        return invalid("recovery list: expected <vault> [path]");
    const bool json = hasFlag(call, "json");
    return runOp("recovery list", [&] {
        const int only = hasFlag(call, "snapshots-only") + hasFlag(call, "versions-only") + hasFlag(call, "provider-only");
        if (only > 1) throw ops::Invalid("--snapshots-only, --versions-only and --provider-only exclude each other");
        nlohmann::json q = {{"refresh_provider", hasFlag(call, "refresh")}};
        if (call.positionals.size() == 2) q["path"] = call.positionals[1];
        if (only) {
            q["include_snapshots"] = hasFlag(call, "snapshots-only");
            q["include_versions"] = hasFlag(call, "versions-only");
            q["include_provider"] = hasFlag(call, "provider-only");
        }
        if (const auto limit = optVal(call, "limit")) {
            const auto n = parseUInt(*limit);
            if (!n) throw ops::Invalid("--limit must be a whole number");
            q["limit"] = *n;
        }
        return rec::list(call.user, vaultIdFrom(call, usage, "recovery list"), rec::listQueryFromJson(q));
    }, [&](const std::vector<model::RecoveryPoint>& points) { return json ? jsonText(points) : formatPoints(points); });
}

CommandResult rcInspect(const CommandCall& call) {
    const auto usage = resolveUsage({"recovery", "inspect"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("recovery inspect", [&] { return rec::inspect(call.user, call.positionals[0]); },
                 [&](const rec::PointDetail& d) { return json ? jsonText(d) : formatDetail(d); });
}

// `plan <recovery-id> [--to]` or `plan <vault> <path> --at <time> [--prune] [--to]`.
CommandResult rcPlan(const CommandCall& call) {
    const auto usage = resolveUsage({"recovery", "plan"});
    const bool json = hasFlag(call, "json");
    if (call.positionals.empty() || call.positionals.size() > 2)
        return invalid("recovery plan: expected <recovery-id>, or <vault> <path> --at <time>");
    return runOp("recovery plan", [&] {
        nlohmann::json req = nlohmann::json::object();
        if (call.positionals.size() == 1) {
            if (optVal(call, "at") || hasFlag(call, "prune"))
                throw ops::Invalid("--at and --prune plan a point in time: give <vault> <path> --at <time>");
            req["recovery_id"] = call.positionals[0];
        } else {
            const auto at = optVal(call, "at");
            if (!at || at->empty()) throw ops::Invalid("a point-in-time plan needs --at <ISO-8601 time>");
            req["vault_id"] = vaultIdFrom(call, usage, "recovery plan");
            req["path"] = call.positionals[1];
            req["at"] = *at;
            req["prune"] = hasFlag(call, "prune");
        }
        if (const auto to = optVal(call, "to")) req["destination"] = *to;
        return rec::plan(call.user, rec::planRequestFromJson(req));
    }, [&](const model::Plan& p) {
        if (json) return jsonText(p);
        return formatPlan(p) + (p.blockers.empty() ? "Restore it with: " + rcRestoreHint(p) + "\n" : std::string());
    });
}

// `restore <plan-id> [--token] [--yes]` or `restore <recovery-id> [--to]` (plans first).
CommandResult rcRestore(const CommandCall& call) {
    const auto usage = resolveUsage({"recovery", "restore"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    const std::string prefix = "recovery restore";
    const auto& arg = call.positionals[0];
    try {
        if (const auto planId = parseUInt(arg)) {
            if (optVal(call, "to")) return invalid(prefix + ": --to applies when planning from a recovery id");
            if (const auto token = optVal(call, "token")) {
                const rec::RestoreRequest req{.plan_id = *planId, .token = *token,
                                              .accept_unverified = hasFlag(call, "accept-unverified")};
                const auto result = rec::restore(call.user, req);
                auto out = ok(json ? jsonText(result) : formatResult(result));
                if (result.state != "done" || result.conflicts || result.failed) out.exit_code = 1;
                return out;
            }
            return rcRunPlan(call, rec::getPlan(call.user, *planId), json);
        }
        if (!rcRecoveryId(arg))
            return invalid(prefix + ": expected a plan id or a recovery id (snap-…, lv-…, pv-…), got '" + arg + "'");
        if (optVal(call, "token")) return invalid(prefix + ": --token goes with a plan id");
        rec::PlanRequest req;
        req.recovery_id = arg;
        req.destination = optVal(call, "to");
        return rcRunPlan(call, rec::plan(call.user, req), json);
    } catch (const ops::NeedsConfirmation& e) {
        if (e.code == rec::UNVERIFIED_VERSION) return invalid(prefix + ": " + e.what() + "\nRe-run with --accept-unverified.");
        return invalid(prefix + ": " + e.what());
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

CommandResult rcDelete(const CommandCall& call) {
    const auto usage = resolveUsage({"recovery", "delete"});
    validatePositionals(call, usage);
    const auto& id = call.positionals[0];
    return runConfirmedText(call, "recovery delete", rec::POINT_DELETE, "DELETE", [&](const bool confirmed) {
        rec::deletePoint(call.user, id, confirmed);
        return "Deleted " + id + ".\n";
    });
}

CommandResult rcCosts(const CommandCall& call) {
    const auto usage = resolveUsage({"recovery", "costs"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("recovery costs", [&] { return rec::costs(call.user, vaultIdFrom(call, usage, "recovery costs")); },
                 [&](const model::CostReport& r) { return json ? jsonText(r) : formatCosts(r); });
}

CommandResult rcHandle(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"recovery", "list"}, sub)) return rcList(subcall);
    if (isCommandMatch({"recovery", "inspect"}, sub)) return rcInspect(subcall);
    if (isCommandMatch({"recovery", "plan"}, sub)) return rcPlan(subcall);
    if (isCommandMatch({"recovery", "restore"}, sub)) return rcRestore(subcall);
    if (isCommandMatch({"recovery", "delete"}, sub)) return rcDelete(subcall);
    if (isCommandMatch({"recovery", "costs"}, sub)) return rcCosts(subcall);
    return invalid(call.constructFullArgs(), "Unknown recovery subcommand: '" + std::string(sub) + "'");
}

template <typename T>
std::string rcJson(const T& value) {
    auto out = nlohmann::json(value).dump(4);
    out.push_back('\n');
    return out;
}

}

// ---- shared helpers ---------------------------------------------------------------------------------------------

uint32_t vaultIdFrom(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage, const std::string& prefix,
                     const std::size_t index) {
    if (call.positionals.size() <= index) throw ops::Invalid("a vault is required");
    const auto lookup = vault::resolveVault(call, call.positionals.at(index), usage, prefix);
    if (!lookup || !lookup.ptr) {
        // resolveVault's text already carries the prefix; ops refusals get it added again by the caller.
        auto why = lookup.error;
        if (why.starts_with(prefix + ": ")) why = why.substr(prefix.size() + 2);
        throw ops::Invalid(why);
    }
    return lookup.ptr->id;
}

std::string formatMoney(const std::optional<model::Money>& money, const std::optional<std::string>& reason) {
    if (!money) return "cannot be estimated" + (reason && !reason->empty() ? " (" + *reason + ")" : std::string());
    return rcAmount(money->amount) + " " + money->currency;
}

std::string formatFigure(const model::CostFigure& f) {
    if (!f.expected) return formatMoney(std::nullopt, f.reason);
    std::string out = formatMoney(f.expected);
    if (f.low && f.high) out += " (range " + rcAmount(f.low->amount) + " to " + formatMoney(f.high) + ")";
    out += " [" + f.basis + "]";
    if (f.reason && !f.reason->empty()) out += " - " + *f.reason;
    return out;
}

std::string formatPoints(const std::vector<model::RecoveryPoint>& points) {
    if (points.empty()) return "No recovery points.\n";
    Table tbl({{"ID", Align::Left, 4, 16, false, false},
               {"Type", Align::Left, 4, 8, false, false},
               {"Created", Align::Left, 4, 22, false, false},
               {"Path", Align::Left, 8, 60, false, true},
               {"Size", Align::Right, 4, 10, false, false},
               {"Details", Align::Left, 8, 60, true, false}},
              term_width());
    std::size_t shown = 0;
    for (const auto& p : points) {
        if (shown++ == kRcMaxRows) break;
        tbl.add_row({p.id, rcBackend(p.backend), rcWhen(p.created_at), p.path, rcSize(p.size_bytes), rcPointInfo(p)});
    }
    auto out = tbl.render();
    if (points.size() > kRcMaxRows)
        out += "... " + std::to_string(points.size() - kRcMaxRows) + " more (use --json or --limit)\n";
    return out;
}

std::string formatDetail(const rec::PointDetail& d) {
    std::ostringstream out;
    out << rcPointBlock(d.point);
    if (d.created_by) out << "  Created by: " << *d.created_by << "\n";
    if (!d.members.empty()) {
        out << "  Members" << (d.members_truncated ? " (first page; use --json for the ids)" : "") << ":\n";
        out << formatPoints(d.members);
    }
    if (!d.skipped.empty()) {
        out << "  Not captured:\n";
        for (const auto& s : d.skipped) out << "    " << s << "\n";
    }
    return out.str();
}

std::string formatPlan(const model::Plan& p) {
    std::ostringstream out;
    out << "Restore plan " << p.id << " for vault " << p.vault_id << ": " << p.source_label << " (" << p.state << ")\n"
        << "  Destination: " << (p.destination ? *p.destination : std::string("the original paths")) << "\n";
    if (p.point_in_time) {
        out << "\n  !! POINT IN TIME " << rcWhen(p.at) << ": a timestamp-based reconstruction from each file's "
            << "version history, NOT an atomic snapshot. Files changed around that time may not be mutually "
            << "consistent.\n";
        if (p.prune) out << "  !! --prune: files that did not exist at that time are removed.\n";
    }
    if (!p.consistency_note.empty()) out << "  Consistency: " << p.consistency_note << "\n";
    out << "\n";

    if (p.items.empty()) {
        out << "  (nothing to restore)\n";
    } else {
        Table tbl({{"Action", Align::Left, 6, 11, false, false},
                   {"Destination", Align::Left, 8, 60, false, true},
                   {"Size", Align::Right, 4, 10, false, false},
                   {"Method", Align::Left, 4, 17, false, false},
                   {"Source", Align::Left, 4, 16, false, false}},
                  term_width());
        std::size_t shown = 0;
        for (const auto& i : p.items) {
            if (shown++ == kRcMaxRows) break;
            tbl.add_row({model::to_string(i.action), i.destination_path, rcSize(i.size_bytes), i.method, i.source_id});
        }
        out << tbl.render();
        if (p.items.size() > kRcMaxRows)
            out << "  ... " << (p.items.size() - kRcMaxRows) << " more items (use --json for all)\n";
        shown = 0;
        for (const auto& i : p.items)
            for (const auto& n : i.notes)
                if (shown++ < kRcMaxRows) out << "  Note (" << i.destination_path << "): " << n << "\n";
    }
    out << "  Totals: " << p.creates << " create, " << p.overwrites << " overwrite, " << p.removals << " remove, "
        << p.skips << " skip, " << p.conflicts << " conflict, " << p.unavailable << " unavailable\n";

    const auto& e = p.estimate;
    out << "  Provider requests: " << e.get_requests << " GET, " << e.head_requests << " HEAD, " << e.put_requests
        << " PUT, " << e.copy_requests << " COPY, " << e.list_requests << " LIST; " << human_bytes(e.download_bytes)
        << " down, " << human_bytes(e.upload_bytes) << " up\n"
        << "  Estimated cost: " << formatMoney(e.cost, e.unpriced_reason) << "\n";
    for (const auto& w : p.warnings) out << "  Warning: " << w << "\n";
    for (const auto& b : p.blockers) out << "  Blocked: " << b << "\n";
    out << "  Plan id: " << p.id << ", token: " << p.token << " (valid until " << rcWhen(p.expires_at) << ")\n";
    return out.str();
}

std::string formatResult(const model::RestoreResult& r) {
    std::ostringstream out;
    out << "Restore " << r.state << " (plan " << r.plan_id << "): " << r.restored << " restored, " << r.removed
        << " removed, " << r.skipped << " skipped, " << r.conflicts << " conflicts, " << r.failed << " failed\n";
    std::size_t shown = 0;
    for (const auto& i : r.items) {
        if (i.outcome == "restored" || i.outcome == "removed" || i.outcome == "skipped") continue;
        if (shown++ == kRcMaxRows) {
            out << "  ... more (use --json)\n";
            break;
        }
        out << "  " << i.outcome << ": " << i.destination_path << (i.error ? " - " + *i.error : "") << "\n";
    }
    if (r.conflicts)
        out << "A conflict means the destination changed after the plan was made; it was left as it is. Plan again "
               "to restore over the new content.\n";
    if (r.state != "done") out << "Run the same restore again to resume; finished items are skipped.\n";
    return out.str();
}

std::string formatStatus(const model::Status& s) {
    std::ostringstream out;
    out << "Vault " << s.vault_id << " recovery\n"
        << "  Mode: " << rcDashed(model::to_string(s.mode)) << "\n"
        << "  Snapshot quota: "
        << (s.snapshot_quota_bytes && *s.snapshot_quota_bytes ? human_bytes(*s.snapshot_quota_bytes) : std::string("none"))
        << "\n"
        << "  Versioning cost alert: "
        << (s.cost_alert_monthly ? formatMoney(s.cost_alert_monthly) + " per month" : std::string("none")) << "\n";
    const auto& lv = s.local_versioning;
    out << "  Local versioning: " << (lv.enabled ? "on" : "off");
    if (lv.enabled || lv.keep_last || lv.max_age_days || lv.quota_bytes) {
        out << " (keep last " << (lv.keep_last ? std::to_string(*lv.keep_last) : std::string("all"))
            << ", max age " << (lv.max_age_days ? std::to_string(*lv.max_age_days) + " days" : std::string("none"))
            << ", quota " << (lv.quota_bytes ? human_bytes(*lv.quota_bytes) : std::string("none")) << ")";
    }
    out << "\n"
        << "  Snapshots: " << s.snapshots.count << " (" << human_bytes(s.snapshots.stored_bytes) << " stored, "
        << human_bytes(s.snapshots.plaintext_bytes) << " of files)\n"
        << "  Local versions: " << s.versions.count << " (" << human_bytes(s.versions.stored_bytes) << " stored, "
        << human_bytes(s.versions.plaintext_bytes) << " of files)\n";
    const auto& b = s.backlog;
    if (b.pending_versions || b.failing || b.last_error) {
        out << "  Upstream backlog: " << b.pending_versions << " versions (" << human_bytes(b.pending_bytes)
            << ") waiting, oldest " << rcWhen(b.oldest_pending_at) << ", " << b.failing << " failing";
        if (b.last_error) out << "; last error: " << *b.last_error;
        out << "\n";
    }

    const auto& p = s.provider;
    out << "  Provider versioning: ";
    if (!p.supported) {
        out << "not available" << (p.unsupported_reason.empty() ? "" : " (" + p.unsupported_reason + ")") << "\n";
    } else {
        out << p.status;
        if (p.status == "enabled") out << (p.settled ? ", settled" : ", propagating until " + rcWhen(p.settles_at));
        if (p.enabled_by_vaulthalla) out << " (enabled by Vaulthalla " << rcWhen(p.enabled_at) << ")";
        out << "\n";
    }
    if (p.bucket)
        out << "    Bucket: " << rcDash(p.provider) << " " << *p.bucket << " (" << rcDash(p.region) << ", "
            << rcDash(p.storage_class) << "), " << p.bucket_state << "\n";
    if (p.supported) {
        out << "    Retention: "
            << (p.retention_mode == "days" && p.retention_days ? std::to_string(*p.retention_days) + " days"
                                                               : p.retention_mode)
            << "\n";
        if (!p.foreign_noncurrent_rules.empty()) {
            out << "    Other applications' old-version expiry:";
            for (const auto& r : p.foreign_noncurrent_rules) out << " " << r;
            out << "\n";
        }
        if (p.effective_noncurrent_days)
            out << "    Old versions are deleted after " << *p.effective_noncurrent_days << " days\n";
        out << "    Object lock: " << (p.object_lock ? (*p.object_lock ? "enabled" : "off") : "unknown")
            << ", MFA delete: " << (p.mfa_delete ? (*p.mfa_delete ? "enabled" : "off") : "unknown") << "\n"
            << "    Checked: " << rcWhen(p.checked_at) << "\n";
    }
    for (const auto& w : p.warnings) out << "    Warning: " << w << "\n";
    if (!s.retained_key_versions.empty()) {
        out << "  Key versions recovery data still needs:";
        for (const auto v : s.retained_key_versions) out << " " << v;
        out << "\n";
    }
    for (const auto& w : s.warnings) out << "  Warning: " << w << "\n";
    return out.str();
}

std::string formatCosts(const model::CostReport& r) {
    std::ostringstream out;
    out << "Recovery costs for vault " << r.vault_id << ": " << rcBucketLine(r) << "\n";
    if (!r.priced)
        out << "  Costs cannot be estimated" << (r.unpriced_reason ? ": " + *r.unpriced_reason : std::string()) << "\n";
    out << "  " << rcCatalogLine(r.catalog) << "\n"
        << "  " << rcConfidence(r) << "\n"
        << "  " << rcObservation(r.observation);
    if (r.retention) out << "  Figures assume retention: " << *r.retention << "\n";

    out << "\nVersioning surcharge (estimate)\n"
        << "  If enabled now (monthly, steady state): " << formatFigure(r.pre_activation_monthly) << "\n"
        << "  This month so far: " << formatFigure(r.current_month_to_date) << "\n"
        << "  This month, projected: " << formatFigure(r.current_month_projected) << "\n"
        << "  Monthly at the observed write rate (steady state): " << formatFigure(r.projected_monthly) << "\n"
        << rcHistory(r.history) << "  By retention:\n"
        << rcScenarios(r.scenarios) << "  Growth over 12 months:\n"
        << rcAccumulation(r.accumulation);
    if (r.alert.threshold)
        out << "  Alert threshold: " << formatMoney(r.alert.threshold) << " per month"
            << (r.alert.exceeded ? " - EXCEEDED" : "") << "\n";

    out << "\nCurrent object storage (context, not part of the surcharge)\n"
        << "  " << r.current.objects << " objects, " << human_bytes(r.current.bytes) << "; monthly storage "
        << formatMoney(r.current.monthly_storage) << "\n"
        << "\nRecovery operations\n"
        << rcRecoveryOps(r) << "\nNot modelled\n"
        << rcUnmodeled(r.unmodeled) << "\nAssumptions\n"
        << rcAssumptions(r.assumptions) << "\nComputed " << rcWhen(r.computed_at)
        << " on this host. Estimates, not provider invoices.\n";
    return out.str();
}

std::string formatDisclosure(const model::Disclosure& d) {
    const auto& r = d.report;
    std::ostringstream out;
    out << "Provider Versioning - Estimated Monthly Cost\n"
        << "  Provider: " << rcDash(r.provider) << "\n"
        << "  Bucket: " << rcDash(r.bucket) << "\n"
        << "  Region: " << rcDash(r.region) << "\n"
        << "  Storage class: " << rcDash(r.storage_class) << "\n"
        << "  Current data: " << r.current.objects << " objects, " << human_bytes(r.current.bytes) << "\n"
        << "  " << rcObservation(r.observation);
    if (!r.priced)
        out << "  COSTS CANNOT BE ESTIMATED" << (r.unpriced_reason ? ": " + *r.unpriced_reason : std::string())
            << ". Recurring charges still apply.\n";
    out << "  Estimated monthly additional storage: " << formatFigure(r.pre_activation_monthly) << "\n"
        << "  Retention: " << (r.retention ? *r.retention : std::string("none chosen (scenarios only)")) << "\n"
        << "  By retention:\n"
        << rcScenarios(r.scenarios) << "  Projected growth over 12 months:\n"
        << rcAccumulation(r.accumulation) << "  " << rcConfidence(r) << "\n"
        << "  " << rcCatalogLine(r.catalog) << "\n"
        << rcHistory(r.history) << "  Recovery operations:\n"
        << rcRecoveryOps(r) << "  Not included:\n"
        << rcUnmodeled(r.unmodeled) << "  Assumptions:\n"
        << rcAssumptions(r.assumptions) << "  Consequences:\n";
    bool aws = r.provider && r.provider->starts_with("aws");
    bool saidIrreversible = false;
    for (const auto& c : d.consequences) {
        out << "  - " << c << "\n";
        if (c.find("unversioned") != std::string::npos) saidIrreversible = true;
    }
    if (aws && !saidIrreversible)
        out << "  - AWS cannot return a bucket to unversioned; it can only be suspended.\n";
    if (!d.required_acknowledgements.empty()) {
        out << "  Acknowledgements required:";
        for (const auto& a : d.required_acknowledgements) out << " " << a;
        out << "\n";
    }
    out << "  Disclosure valid until " << rcWhen(d.expires_at) << ". Estimates, not provider invoices.\n";
    return out.str();
}

std::string jsonText(const model::Plan& v) { return rcJson(v); }
std::string jsonText(const model::RestoreResult& v) { return rcJson(v); }
std::string jsonText(const model::Status& v) { return rcJson(v); }
std::string jsonText(const model::CostReport& v) { return rcJson(v); }
std::string jsonText(const model::Disclosure& v) { return rcJson(v); }
std::string jsonText(const rec::PointDetail& v) { return rcJson(v); }
std::string jsonText(const std::vector<model::RecoveryPoint>& v) { return rcJson(v); }

CommandResult runConfirmedText(const CommandCall& call, const std::string& prefix, const std::string& code,
                               const std::string& word, const std::function<std::string(bool confirmed)>& op) {
    bool confirmed = hasFlag(call, "yes");
    try {
        for (;;) {
            try {
                return ok(op(confirmed));
            } catch (const ops::NeedsConfirmation& e) {
                if (e.code != code || confirmed) throw;
                if (!call.io) return invalid(prefix + ": " + e.what() + "\nRe-run with --yes to confirm.");
                if (call.io->prompt(std::string(e.what()) + "\nType " + word + " to continue", "no") != word)
                    return invalid(prefix + ": not confirmed; nothing was changed");
                confirmed = true;
            }
        }
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

}

void vh::protocols::shell::commands::registerRecoveryCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("recovery"), recovery_cli::rcHandle);
}
