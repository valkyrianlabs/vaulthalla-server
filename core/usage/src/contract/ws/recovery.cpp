// ws book: recovery.* and vault.recovery.* — file recovery (core/src/protocols/ws/handler/Recovery.cpp →
// ops::recovery). Shapes: core/include/ops/RecoveryJson.hpp. Design: .claude/context/recovery.md.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField recoveryId() {
    return str("recovery_id")
        .gen(gen::ref("recovery_point", {"id"}))
        .desc("snap-<id> (snapshot), lv-<id> (local version) or pv-<id> (provider version).");
}

WsField planId() { return uinteger("plan_id").min(1).gen(gen::ref("recovery_plan", {"id"})).desc("Restore plan id."); }

WsField retention() {
    return anyOf("provider_retention", {"string", "integer", "object"})
        .desc("Provider noncurrent-version retention: \"30d\", 30 (days), \"indefinite\" or {indefinite, days}.");
}

std::vector<std::string> recoveryRefusals(std::initializer_list<const char*> codes = {}) {
    auto out = opsRefusals();
    for (const auto* c : codes) out.emplace_back(c);
    return out;
}

WsCommandUsage recoveryCommand(std::string name, std::string description, std::vector<WsField> payload,
                               std::vector<WsField> response, std::vector<std::string> refusalCodes,
                               const std::chrono::milliseconds timeout, std::optional<std::string> operation) {
    return {.command = std::move(name),
            .description = std::move(description),
            .payload = std::move(payload),
            .response = std::move(response),
            .refusal_codes = std::move(refusalCodes),
            .operation = std::move(operation),
            .client_timeout = timeout};
}

}

std::vector<WsCommandUsage> recoveryCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    // ---- recovery points ----
    out.push_back(recoveryCommand("recovery.list",
        "Recovery points of a vault, or of one path (a file's history or the points under a directory): local "
        "snapshots, local versions and provider versions. Points the caller can't read are omitted. refresh_provider "
        "lists the provider's versions first (metadata only, request-budgeted).",
        {vaultId(), vaultPath("path").opt(), boolean("refresh_provider").opt(), boolean("include_snapshots").opt(),
         boolean("include_versions").opt(), boolean("include_provider").opt(), uinteger("limit").min(1).opt()},
        {objectArray("points", "RecoveryPoint")}, recoveryRefusals(), 120s, "recovery.list"));
    out.push_back(recoveryCommand("recovery.inspect",
        "One recovery point with its details; a snapshot lists its members (first page). A point the caller can't "
        "read is not_found.",
        {recoveryId()}, {object("detail", "RecoveryPointDetail")}, recoveryRefusals(), 30s, "recovery.inspect"));
    out.push_back(recoveryCommand("recovery.snapshot.create",
        "Take a named local snapshot of a file or directory tree (vault mode local_snapshots). Needs Read + Copy on "
        "every file and List on every directory of the subtree.",
        {vaultId(), vaultPath("path"), str("name").opt()},
        {object("detail", "RecoveryPointDetail")}, recoveryRefusals(), 300s, "recovery.snapshot.create"));
    out.push_back(recoveryCommand("recovery.point.delete",
        "Delete a snapshot or a local version (filesystem Delete on its path). A refusal with data.code "
        "'recovery_point_delete' asks for confirmation: resend with confirm.",
        {recoveryId(), boolean("confirm").opt()}, {str("recovery_id")},
        recoveryRefusals({"recovery_point_delete"}), 60s, "recovery.point.delete"));

    // ---- restore ----
    out.push_back(recoveryCommand("recovery.plan",
        "Plan a restore (read-only): recovery_id, or vault_id + path + at for a point-in-time reconstruction (never "
        "atomic; see consistency_note). Returns the per-item preview, estimate, warnings, blockers and the token "
        "recovery.restore takes (stored 30 minutes).",
        {recoveryId().opt(), uinteger("vault_id").opt().gen(gen::ref("vault", {"id"})), vaultPath("path").opt(),
         anyOf("at", {"string", "integer"}).opt().desc("ISO-8601 UTC time or epoch seconds."),
         vaultPath("destination").opt(), boolean("prune").opt(), boolean("refresh_provider").opt()},
        {object("plan", "RecoveryPlan")}, recoveryRefusals(), 180s, "recovery.plan"));
    out.push_back(recoveryCommand("recovery.plan.get", "A stored restore plan (its state, items and token).",
        {planId()}, {object("plan", "RecoveryPlan")}, recoveryRefusals(), kDefaultTimeout, std::nullopt));
    out.push_back(recoveryCommand("recovery.restore",
        "Run a restore plan: every item is re-authorized and restored as a new current generation; a destination "
        "that changed since the plan is a 'conflict' outcome. Resumable. Refusals: 'recovery_restore' (token missing "
        "or expired: plan again), 'recovery_unverified_version' (resend with accept_unverified).",
        {planId(), str("token").opt(), boolean("accept_unverified").opt()},
        {object("result", "RecoveryRestoreResult")},
        recoveryRefusals({"recovery_restore", "recovery_unverified_version"}), 1800s, "recovery.restore"));

    // ---- costs and vault policy ----
    out.push_back(recoveryCommand("recovery.costs",
        "The vault's recovery cost panel: versioning surcharge (separate from current object storage), recovery "
        "operations, what is not modelled, ranges, basis and catalog freshness. Unknown money is null.",
        {vaultId()}, {object("costs", "RecoveryCostReport")}, recoveryRefusals(), 60s, "recovery.costs"));
    out.push_back(recoveryCommand("vault.recovery.status",
        "A vault's recovery mode, local versioning, store usage, upstream backlog and provider versioning state; "
        "refresh_provider re-reads the bucket (one admin round trip).",
        {vaultId(), boolean("refresh_provider").opt()}, {object("status", "RecoveryStatus")}, recoveryRefusals(), 60s,
        "recovery.status"));
    out.push_back(recoveryCommand("vault.recovery.update",
        "Change a vault's recovery settings. mode provider_versioning needs disclosure_token from "
        "vault.recovery.disclosure ('recovery_versioning_disclosure'); unpriced costs need accept_unpriced "
        "('recovery_versioning_unpriced'); a shorter retention needs accept_retention_shortening "
        "('recovery_retention_shorten'); the vault's unmanaged bucket needs accept_adoption ('upstream_adoption').",
        {vaultId(), str("mode").opt().oneOf({"off", "local_snapshots", "provider_versioning"}), retention().opt(),
         uinteger("snapshot_quota_bytes").opt().desc("0 = no snapshot quota."),
         str("cost_alert_monthly").opt().desc("Decimal amount in the catalog currency; \"\" clears it."),
         object("local_versioning", "", {boolean("enabled").opt(), uinteger("keep_last").nullable().opt(),
                                         uinteger("max_age_days").nullable().opt(),
                                         uinteger("quota_bytes").nullable().opt()}).opt(),
         str("disclosure_token").opt(), boolean("accept_unpriced").opt(), boolean("accept_retention_shortening").opt(),
         boolean("accept_adoption").opt()},
        {object("status", "RecoveryStatus")},
        recoveryRefusals({"recovery_versioning_disclosure", "recovery_versioning_unpriced", "recovery_retention_shorten",
                          "upstream_adoption"}),
        180s, "recovery.update"));
    out.push_back(recoveryCommand("vault.recovery.disclosure",
        "The cost disclosure a person must see before provider versioning is enabled, with the token "
        "vault.recovery.update needs (10 minutes). Read-only: at most one admin inspect, no object requests.",
        {vaultId(), retention().opt()}, {object("disclosure", "RecoveryDisclosure")}, recoveryRefusals(), 60s,
        "recovery.disclosure"));
    out.push_back(recoveryCommand("vault.recovery.suspend",
        "Suspend versioning on the vault's bucket; existing versions are kept and nothing is deleted. A refusal with "
        "data.code 'recovery_versioning_suspend' asks for confirmation: resend with confirm.",
        {vaultId(), boolean("confirm").opt()}, {object("status", "RecoveryStatus")},
        recoveryRefusals({"recovery_versioning_suspend"}), 60s, "recovery.suspend"));

    return out;
}

}
