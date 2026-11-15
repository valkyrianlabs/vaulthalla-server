// `vh vault remote attach | status | abort`: the CLI adapter for ops::vault_remote, turning a local vault into an
// S3/R2 vault in place (vault/RemoteAttach.hpp, design/storage/attach-remote.md).

#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "CommandUsage.hpp"

#include "fs/ops/file.hpp"
#include "ops/Error.hpp"
#include "ops/VaultRemote.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <string>

namespace vh::protocols::shell::commands::vault {

namespace remote_cli {

namespace vrops = vh::ops::vault_remote;
namespace ra = vh::vault::remote;

std::string when(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    return std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm) ? std::string(buf) : std::string("-");
}

std::string statusText(const vrops::Status& s) {
    std::string out = fmt::format("vault {} ({}): {} vault, remote {}\n", s.vault_id, s.vault_name, s.type, s.remote);
    if (!s.attach) return out;
    const auto& a = *s.attach;
    out += fmt::format("  state:         {}\n", ra::to_string(a.state));
    out += fmt::format("  bucket:        {} (API key {}{})\n", a.bucket,
                       a.api_key_id ? std::to_string(*a.api_key_id) : std::string("deleted"),
                       a.storage_tier_id ? ", storage tier " + *a.storage_tier_id : std::string{});
    if (a.manifest_publish) out += fmt::format("  publish mode:  {}\n", *a.manifest_publish);
    out += fmt::format("  started:       {} (attempt {})\n", when(a.started_at), a.attempts + 1);
    if (s.progress) {
        const auto& p = *s.progress;
        out += fmt::format("  files:         {} of {} sent ({} of {})\n", p.files_done, p.files_total,
                           vh::fs::ops::bytesToSize(p.bytes_done), vh::fs::ops::bytesToSize(p.bytes_total));
        if (p.bytes_per_second)
            out += fmt::format("  rate:          {}/s{}\n", vh::fs::ops::bytesToSize(*p.bytes_per_second),
                               p.eta_seconds ? fmt::format(", about {} s left", *p.eta_seconds) : std::string{});
        if (p.passes) out += fmt::format("  catch-up:      {} pass(es)\n", p.passes);
    }
    if (s.items.files_failed) out += fmt::format("  failed files:  {}\n", s.items.files_failed);
    if (a.estimate) {
        const auto e = ra::estimateFromJson(*a.estimate);
        out += fmt::format("  estimate:      {} PUT request(s), {} to upload; {}\n", e.put_requests,
                           vh::fs::ops::bytesToSize(e.upload_bytes),
                           e.priced ? "estimated cost " + e.estimated_cost.value_or("?") : std::string("not priced"));
    }
    if (a.verified_at) out += fmt::format("  verified:      {}\n", when(*a.verified_at));
    if (a.cutover_at) out += fmt::format("  cut over:      {}\n", when(*a.cutover_at));
    if (a.done_at) out += fmt::format("  done:          {}\n", when(*a.done_at));
    if (a.first_pass) out += fmt::format("  first pass:    {}\n", a.first_pass->value("status", std::string("?")));
    if (a.abort_requested_at && !a.aborted_at) out += fmt::format("  abort asked:   {}\n", when(*a.abort_requested_at));
    if (a.aborted_at) out += fmt::format("  aborted:       {}\n", when(*a.aborted_at));
    if (a.rotation_queued_at) out += "  a key rotation is queued until the attach has ended\n";
    if (a.last_error) out += "  last error:    " + *a.last_error + "\n";
    switch (a.state) {
    case ra::State::Failed:
        out += "  The vault is still local and untouched. Start the attach again with the same API key and bucket to "
               "resume it, or abort it (vh vault remote abort) to delete what it uploaded.\n";
        break;
    case ra::State::Aborted:
        out += "  The attach was aborted: what it uploaded was deleted, and the vault was never changed.\n";
        break;
    case ra::State::Done:
        break;
    case ra::State::Cutover:
        out += "  The vault now uses its bucket; its first sync pass is running.\n";
        break;
    default:
        out += "  The vault stays local and in use until the cutover.\n";
    }
    return out;
}

CommandResult attachCmd(const CommandCall& call) {
    constexpr const auto* ERR = "vault remote attach";
    const auto book = resolveUsage({"vault", "remote", "attach"});
    validatePositionals(call, book);
    // Where a vault's data goes is decided by a person (the MCP catalog excludes this command; this is the same rule
    // for an agent that reaches the shell another way).
    if (AgentCallScope::active())
        return invalid(std::string(ERR) + ": attaching remote storage to a vault is not available to agents");
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        const auto lookup = resolveVault(call, call.positionals[0], book, ERR);
        if (!lookup || !lookup.ptr) return invalid(lookup.error);
        const auto keyId = apiKeyIdFromOption(call);
        if (!keyId) return invalid(std::string(ERR) + ": --api-key is required");
        const auto bucket = optVal(call, "bucket");
        if (!bucket || bucket->empty()) return invalid(std::string(ERR) + ": --bucket is required");
        const auto status = vrops::attach(
            call.user, {.vault_id = lookup.ptr->id, .api_key_id = *keyId, .bucket = *bucket,
                        .storage_tier = optVal(call, std::vector<std::string>{"storage-tier", "storage-class"}),
                        .accept_unpriced = hasFlag(call, "accept-unpriced")});
        if (json) return ok(vrops::toJson(status).dump(4));
        return ok("Attach started: the vault's files are uploaded in the background while it stays in use.\n" +
                  statusText(status) + "Follow it with: vh vault remote status " + std::to_string(status.vault_id) + "\n");
    } catch (const vh::ops::Error& e) {
        return invalid(std::string(ERR) + ": " + e.what());
    }
}

CommandResult statusCmd(const CommandCall& call) {
    constexpr const auto* ERR = "vault remote status";
    const auto book = resolveUsage({"vault", "remote", "status"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        std::optional<unsigned int> vaultId;
        if (call.positionals[0] != "all") {
            const auto lookup = resolveVault(call, call.positionals[0], book, ERR);
            if (!lookup || !lookup.ptr) return invalid(lookup.error);
            vaultId = lookup.ptr->id;
        }
        const auto statuses = vrops::status(call.user, vaultId);
        if (json) {
            nlohmann::json out = nlohmann::json::array();
            for (const auto& s : statuses) out.push_back(vrops::toJson(s));
            return ok(nlohmann::json{{"vaults", out}}.dump(4));
        }
        if (statuses.empty()) return ok("No vault has a remote attach.");
        std::string out;
        for (const auto& s : statuses) out += statusText(s);
        return ok(out);
    } catch (const vh::ops::Error& e) {
        return invalid(std::string(ERR) + ": " + e.what());
    }
}

CommandResult abortCmd(const CommandCall& call) {
    constexpr const auto* ERR = "vault remote abort";
    const auto book = resolveUsage({"vault", "remote", "abort"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        const auto lookup = resolveVault(call, call.positionals[0], book, ERR);
        if (!lookup || !lookup.ptr) return invalid(lookup.error);
        const auto confirm = optVal(call, "confirm");
        if (!confirm)
            return invalid(std::string(ERR) + ": --confirm <vault name> is required: an abort deletes what the attach "
                                              "uploaded to the bucket");
        const auto status = vrops::abort(call.user, {.vault_id = lookup.ptr->id, .confirm = *confirm});
        if (json) return ok(vrops::toJson(status).dump(4));
        return ok("Abort requested: the objects the attach uploaded are deleted from the bucket in the background; "
                  "the vault was never changed.\n" + statusText(status));
    } catch (const vh::ops::Error& e) {
        return invalid(std::string(ERR) + ": " + e.what());
    }
}

}

CommandResult handle_vault_remote(const CommandCall& call) {
    namespace d = remote_cli;
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const bool known = isCommandMatch({"vault", "remote", "attach"}, sub) ||
                       isCommandMatch({"vault", "remote", "status"}, sub) ||
                       isCommandMatch({"vault", "remote", "abort"}, sub);
    if (!known) return invalid(call.constructFullArgs(), "Unknown vault remote subcommand: '" + std::string(sub) + "'");
    if (subcall.positionals.empty()) return usage(subcall.constructFullArgs());
    if (isCommandMatch({"vault", "remote", "attach"}, sub)) return d::attachCmd(subcall);
    if (isCommandMatch({"vault", "remote", "status"}, sub)) return d::statusCmd(subcall);
    return d::abortCmd(subcall);
}

}
