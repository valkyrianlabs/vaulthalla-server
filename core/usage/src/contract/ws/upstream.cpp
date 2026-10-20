// ws book: upstream.* — provider administration of upstream S3/R2 accounts (#237) and event-driven sync (#96)
// (core/src/protocols/ws/handler/Upstream.cpp → ops::upstream). Shapes: core/usage/src/contract/models/upstream.cpp
// (serializers in core/src/ops/UpstreamJson.cpp). The handler reads a null member as an absent one, and a member of
// the wrong type is a refusal (invalid), never a fault.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField apiKeyId() { return uinteger("api_key_id").gen(gen::ref("api_key", {"id"})).desc("Upstream API key id."); }
WsField bucketName() {
    return str("bucket").gen(gen::pattern("vh-test-{a}{a}{a}{9}{9}")).desc("Bucket name in the key's account.");
}

std::vector<std::string> refusals(std::initializer_list<const char*> codes = {}) {
    auto out = opsRefusals();
    for (const auto* c : codes) out.emplace_back(c);
    return out;
}

WsCommandUsage command(std::string name, std::string description, std::vector<WsField> payload,
                       std::vector<WsField> response, std::vector<std::string> refusalCodes,
                       const std::chrono::milliseconds timeout = kDefaultTimeout) {
    return {.command = std::move(name),
            .description = std::move(description),
            .payload = std::move(payload),
            .response = std::move(response),
            .refusal_codes = std::move(refusalCodes),
            .client_timeout = timeout};
}

}

std::vector<WsCommandUsage> upstreamCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    // ---- administrative credentials ----
    out.push_back(command("upstream.admin.enable",
        "Turn on provider administration (AWS S3, Cloudflare R2) for an upstream API key after probing it, or store / "
        "clear the Cloudflare API token R2 events need. Idempotent. Needs admin.upstream.configure + key edit.",
        {apiKeyId(),
         str("provider_token").opt().nullable().desc(
             "Cloudflare account API token (Queues Edit + Workers R2 Storage Edit). Write-only; empty is ignored."),
         boolean("clear_provider_token").opt().nullable()},
        {object("admin", "UpstreamAdminStatus")}, refusals(), 60s));
    out.push_back(command("upstream.admin.disable",
        "Turn provider administration off. Refused while an event subscription runs through the key.",
        {apiKeyId()}, {object("admin", "UpstreamAdminStatus")}, refusals()));
    out.push_back(command("upstream.admin.status",
        "Administration status and the last capability probe; probe=true re-checks the credential (configure).",
        {apiKeyId(), boolean("probe").opt().nullable()}, {object("admin", "UpstreamAdminStatus")}, refusals(), 60s));

    // ---- inventory and locks ----
    out.push_back(command("upstream.bucket.list",
        "One page of the account's buckets (ListBuckets) merged with what Vaulthalla knows: managed, adopted, "
        "unmanaged or protected. No bucket-level or object calls.",
        {apiKeyId(), str("token").opt().nullable().desc("next_token of the previous page."),
         uinteger("max").opt().nullable().desc("Page size (default 1000)."),
         str("state").opt().nullable().oneOf({"managed", "adopted", "unmanaged", "protected"}),
         str("filter").opt().nullable().desc("Substring of the bucket name.")},
        {object("inventory", "UpstreamInventory")}, refusals(), 60s));
    out.push_back(command("upstream.bucket.protect",
        "Lock a bucket: Vaulthalla will not probe, adopt, bind, configure, sync, empty or delete it. Audited.",
        {apiKeyId(), bucketName(), str("reason").gen(gen::pattern("test lock {a}{a}{a}"))},
        {object("bucket", "UpstreamBucketRow")}, refusals()));
    out.push_back(command("upstream.bucket.unprotect",
        "Remove a bucket lock (admin.upstream.unprotect). A refusal with data.code 'upstream_unprotect' asks for "
        "confirmation: resend with confirm.",
        {apiKeyId(), bucketName(), boolean("confirm").opt().nullable()},
        {object("bucket", "UpstreamBucketRow")}, refusals({"upstream_unprotect"})));

    // ---- configuration ----
    out.push_back(command("upstream.bucket.inspect",
        "Bucket configuration: region, versioning, object lock, lifecycle and notification rules (ours vs foreign).",
        {apiKeyId(), bucketName()}, {object("inspection", "UpstreamInspection")}, refusals(), 60s));
    out.push_back(command("upstream.bucket.lifecycle.set",
        "Set or clear Vaulthalla's lifecycle rule on a managed or adopted bucket; foreign rules are preserved. "
        "Expiration is destructive: a refusal with data.code 'upstream_destructive_lifecycle' asks for "
        "accept_destructive.",
        {apiKeyId(), bucketName(), uinteger("abort_incomplete_multipart_days").opt().nullable().desc("0 removes it."),
         uinteger("expire_current_days").opt().nullable().desc("0 removes it; destructive."),
         uinteger("expire_noncurrent_days").opt().nullable().desc("0 removes it; destructive; AWS only."),
         str("prefix").opt().nullable(), boolean("clear").opt().nullable().desc("Drop Vaulthalla's rule entirely."),
         boolean("accept_destructive").opt().nullable()},
        {object("inspection", "UpstreamInspection")}, refusals({"upstream_destructive_lifecycle"}), 60s));

    // ---- adoption, detach, cleanup ----
    out.push_back(command("upstream.bucket.adopt.preflight",
        "Read-only admission check of an existing bucket before adoption: object counts, encryption of a sample, "
        "versioning, object lock, Vaulthalla manifest, blockers.",
        {apiKeyId(), bucketName(), uinteger("max_objects").opt().nullable(), uinteger("sample_heads").opt().nullable()},
        {object("report", "UpstreamAdmissionReport")}, refusals(), 180s));
    out.push_back(command("upstream.bucket.detach",
        "Give a managed or adopted bucket that no vault uses back: Vaulthalla removes its own rules; data stays.",
        {apiKeyId(), bucketName()}, {object("bucket", "UpstreamBucketRow")}, refusals(), 60s));
    out.push_back(command("upstream.bucket.cleanup.preflight",
        "What cleanup would delete (objects, versions, delete markers, bytes) and anything that blocks it, with a "
        "confirm_token valid for 10 minutes. Nothing changes.",
        {apiKeyId(), bucketName()}, {object("plan", "UpstreamCleanupPlan")}, refusals(), 180s));
    out.push_back(command("upstream.bucket.cleanup",
        "Delete every object version of a bucket Vaulthalla created and (delete_bucket, default) the bucket. Every "
        "check runs again first. A refusal with data.code 'upstream_cleanup' means the token is missing, expired or "
        "no longer matches the bucket: run the preflight again.",
        {apiKeyId(), bucketName(), str("confirm_token").gen(gen::pattern("{a}{a}{a}{a}{9}{9}{9}{9}")),
         boolean("delete_bucket").opt().nullable()},
        {object("result", "UpstreamCleanupResult")}, refusals({"upstream_cleanup"}), 600s));

    // ---- events ----
    out.push_back(command("upstream.events.enable",
        "Subscribe an S3 vault's bucket for event-driven sync (AWS S3 → SQS, Cloudflare R2 → Queues).",
        {vaultId(), str("prefix").opt().nullable(),
         str("foreign_objects").opt().nullable().oneOf({"import", "ignore"}).desc("Default import.")},
        {object("events", "UpstreamEventStatus")}, refusals(), 120s));
    out.push_back(command("upstream.events.disable",
        "Remove the vault's event rule (and the queue when nothing else uses it and Vaulthalla created it).",
        {vaultId()}, {object("events", "UpstreamEventStatus")}, refusals(), 120s));
    out.push_back(command("upstream.events.repair",
        "Re-create whatever is missing for the vault's subscription and re-arm it. Safe to repeat.",
        {vaultId()}, {object("events", "UpstreamEventStatus")}, refusals(), 120s));
    out.push_back(command("upstream.events.status",
        "Event subscription, queue health and inbox counts for one vault (vault_id) or every S3 vault the caller may "
        "view. A vault without a subscription reports state 'none'.",
        {uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"}))
             .desc("Absent, null or 0: every S3 vault the caller may view.")},
        {objectArray("events", "UpstreamEventStatus")}, refusals()));

    // ---- audit ----
    out.push_back(command("upstream.audit.list",
        "Upstream control-plane audit log (newest first): locks, creations, adoptions, lifecycle, events, cleanup.",
        {str("bucket").opt().nullable(), uinteger("limit").opt().nullable().desc("Default 100; 0 means the default.")},
        {objectArray("entries", "UpstreamAuditEntry")}, refusals()));

    return out;
}

}
