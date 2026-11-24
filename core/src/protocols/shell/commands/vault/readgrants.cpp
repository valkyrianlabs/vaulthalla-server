// `vh vault read-grant issue|list|show|revoke` and `vh vault read-grant recipient list|add|remove`: parsing and
// rendering only. Who may do what, and what it creates, is ops::read_grants (ops/ReadGrants.hpp).
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "CommandUsage.hpp"

#include "db/encoding/timestamp.hpp"
#include "ops/Error.hpp"
#include "ops/ReadGrants.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace vh::protocols::shell::commands::vault {

namespace read_grants_cli {

namespace rg = vh::ops::read_grants;

CommandResult refusal(const std::string& err, const vh::ops::Error& e, const bool json) {
    if (const auto* r = dynamic_cast<const vh::ops::Refused*>(&e)) {
        if (json) return invalid(nlohmann::json{{"error", r->code}, {"message", r->what()}}.dump(4));
        return invalid(err + ": " + r->what() + " [" + r->code + "]");
    }
    if (json) return invalid(nlohmann::json{{"error", "refused"}, {"message", e.what()}}.dump(4));
    return invalid(err + ": " + e.what());
}

std::vector<std::string> values(const CommandCall& call, const std::string& key) {
    std::vector<std::string> out;
    for (const auto& [k, v] : call.options)
        if (k == key && v) out.push_back(*v);
    return out;
}

std::string grantText(const rg::Grant& g) {
    std::string recipients;
    for (const auto& r : g.recipients) recipients += (recipients.empty() ? "" : ", ") + r;
    std::string out = fmt::format("  {}  vault {} ('{}')  {}{}\n    recipients {}\n    gateway: bucket {}, access key "
                                  "id {}{}\n",
                                  g.grant_id, g.vault_id ? std::to_string(*g.vault_id) : std::string("(deleted)"),
                                  g.vault_name, g.state, g.gateway_only ? " (gateway only)" : "", recipients,
                                  g.gateway_bucket.value_or("-"), g.gateway_access_key.value_or("-"),
                                  g.gateway_credential_id ? "" : " (deleted)");
    if (g.upstream_provider)
        out += fmt::format("    upstream: {} bucket {}, key id {}{}\n", *g.upstream_provider,
                           g.upstream_bucket.value_or("-"), g.upstream_key_id.value_or("-"),
                           g.upstream_key_id ? "" : " (deleted)");
    out += fmt::format("    issued {} by {}{}\n", db::encoding::timestampToString(g.issued_at), g.issued_by_name,
                       g.revoked_at ? fmt::format("; revoked {} by {}", db::encoding::timestampToString(*g.revoked_at),
                                                  g.revoked_by.value_or("?"))
                                    : std::string{});
    if (g.revocation_error) out += "    revocation incomplete: " + *g.revocation_error + "\n";
    return out;
}

std::string recipientText(const rg::Recipient& r) {
    std::string uids;
    for (const auto& u : r.user_ids) uids += (uids.empty() ? "" : "; ") + u;
    return fmt::format("  {}{}{}\n    {}  {}\n    pinned by {} ({}{})\n", r.fingerprint,
                       r.label ? " (" + *r.label + ")" : std::string{}, r.removed_at ? " [removed]" : "",
                       r.algorithm, uids.empty() ? "(no user ID)" : uids, r.pinned_by_name, r.source,
                       r.source_url ? " " + *r.source_url : std::string{});
}

CommandResult issue(const CommandCall& call) {
    const std::string ERR = "vault read-grant issue";
    const auto book = resolveUsage({"vault", "read-grant", "issue"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        const auto lookup = resolveVault(call, call.positionals[0], book, ERR);
        if (!lookup || !lookup.ptr) return invalid(lookup.error);
        const auto r = rg::issue(call.user, {.vault_id = lookup.ptr->id, .recipients = values(call, "recipient"),
                                             .gateway_only = hasFlag(call, "gateway-only")});
        if (json) {
            auto j = rg::toJson(r.grant);
            j["ciphertext"] = r.ciphertext;
            return ok(j.dump(4));
        }
        // The message alone on stdout, so it can be piped to gpg --decrypt; the grant id on stderr.
        CommandResult out = ok(r.ciphertext);
        out.stderr_text = fmt::format("Issued read grant {} for vault {}{}; encrypted to {}.\n", r.grant.grant_id,
                                      lookup.ptr->id, r.grant.gateway_only ? " (S3 gateway only)" : "",
                                      fmt::join(r.grant.recipients, ", "));
        return out;
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult list(const CommandCall& call) {
    const std::string ERR = "vault read-grant list";
    const auto book = resolveUsage({"vault", "read-grant", "list"});
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        std::optional<uint32_t> vaultId;
        if (const auto v = optVal(call, "vault")) {
            const auto lookup = resolveVault(call, *v, book, ERR);
            if (!lookup || !lookup.ptr) return invalid(lookup.error);
            vaultId = lookup.ptr->id;
        }
        const auto grants = rg::list(call.user, vaultId, hasFlag(call, "all"));
        if (json) {
            auto arr = nlohmann::json::array();
            for (const auto& g : grants) arr.push_back(rg::toJson(g));
            return ok(nlohmann::json{{"grants", arr}}.dump(4));
        }
        if (grants.empty()) return ok("No read grants.\n");
        std::string out = "Read grants:\n";
        for (const auto& g : grants) out += grantText(g);
        return ok(out);
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult show(const CommandCall& call) {
    const std::string ERR = "vault read-grant show";
    const auto book = resolveUsage({"vault", "read-grant", "show"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    const bool ciphertext = hasFlag(call, "ciphertext");
    try {
        const auto g = rg::get(call.user, call.positionals[0]);
        if (json) return ok(rg::toJson(g, ciphertext).dump(4));
        if (ciphertext) {
            if (!g.ciphertext) return invalid(ERR + ": read grant " + g.grant_id + " has no stored message");
            return ok(*g.ciphertext);
        }
        return ok(grantText(g));
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult revoke(const CommandCall& call) {
    const std::string ERR = "vault read-grant revoke";
    const auto book = resolveUsage({"vault", "read-grant", "revoke"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        const auto g = rg::revoke(call.user, call.positionals[0]);
        if (json) return ok(rg::toJson(g).dump(4));
        return ok("Revoked read grant " + g.grant_id + ": its S3 gateway credential" +
                  (g.upstream_provider ? " and its upstream key are" : " is") + " deleted.\n");
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult recipientList(const CommandCall& call) {
    const std::string ERR = "vault read-grant recipient list";
    const auto book = resolveUsage({"vault", "read-grant", "recipient", "list"});
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        const auto recipients = rg::listRecipients(call.user, hasFlag(call, "all"));
        if (json) {
            auto arr = nlohmann::json::array();
            for (const auto& r : recipients) arr.push_back(rg::toJson(r));
            return ok(nlohmann::json{{"recipients", arr}}.dump(4));
        }
        if (recipients.empty()) return ok("No read-grant recipients are pinned.\n");
        std::string out = "Read-grant recipients:\n";
        for (const auto& r : recipients) out += recipientText(r);
        return ok(out);
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult recipientAdd(const CommandCall& call) {
    const std::string ERR = "vault read-grant recipient add";
    const auto book = resolveUsage({"vault", "read-grant", "recipient", "add"});
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    const auto fingerprint = optVal(call, "fingerprint");
    if (!fingerprint || fingerprint->empty())
        return invalid(ERR + ": --fingerprint <the key's full 40-hex fingerprint> is required");
    const auto keyserver = optVal(call, "keyserver");
    const bool keyFile = hasKey(call, "key-file");
    if (keyFile == keyserver.has_value())
        return invalid(ERR + ": give --key-file <path|-> or --keyserver <https URL>, one of them");
    // The key file is read by vh on the caller's side (protocols/shell/ClientInput.hpp); the daemon never opens it.
    if (keyFile && !call.input)
        return invalid(ERR + ": the key file did not arrive (is vh older than the daemon?)");
    try {
        const auto r = rg::pinRecipient(call.user, {.fingerprint = *fingerprint,
                                                    .public_key = keyFile ? call.input : std::nullopt,
                                                    .keyserver = keyserver,
                                                    .label = optVal(call, "label")});
        if (json) return ok(rg::toJson(r).dump(4));
        return ok("Pinned read-grant recipient:\n" + recipientText(r));
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult recipientRemove(const CommandCall& call) {
    const std::string ERR = "vault read-grant recipient remove";
    const auto book = resolveUsage({"vault", "read-grant", "recipient", "remove"});
    validatePositionals(call, book);
    const bool json = hasFlag(call, book->resolveFlag("json_output")->aliases);
    try {
        const auto r = rg::removeRecipient(call.user, call.positionals[0]);
        if (json) {
            auto j = rg::toJson(r.recipient);
            j["live_grants"] = r.live_grants;
            return ok(j.dump(4));
        }
        std::string out = "Removed read-grant recipient " + r.recipient.fingerprint + ": no new grant is encrypted to it.\n";
        if (r.live_grants)
            out += std::to_string(r.live_grants) + " grant(s) already encrypted to it are not revoked (vh vault "
                   "read-grant list; revoke them if the key should lose access).\n";
        return ok(out);
    } catch (const vh::ops::Error& e) {
        return refusal(ERR, e, json);
    }
}

CommandResult recipient(const CommandCall& call) {
    if (call.positionals.empty()) return recipientList(call);
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"vault", "read-grant", "recipient", "list"}, sub)) return recipientList(subcall);
    if (isCommandMatch({"vault", "read-grant", "recipient", "add"}, sub)) return recipientAdd(subcall);
    if (isCommandMatch({"vault", "read-grant", "recipient", "remove"}, sub)) return recipientRemove(subcall);
    return invalid("vault read-grant recipient: unknown subcommand '" + std::string(sub) + "'. Use: list | add | remove");
}

}  // namespace read_grants_cli

CommandResult handle_vault_read_grant(const CommandCall& call) {
    using namespace read_grants_cli;
    if (hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    if (call.positionals.empty()) return list(call);
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"vault", "read-grant", "issue"}, sub)) return issue(subcall);
    if (isCommandMatch({"vault", "read-grant", "list"}, sub)) return list(subcall);
    if (isCommandMatch({"vault", "read-grant", "show"}, sub)) return show(subcall);
    if (isCommandMatch({"vault", "read-grant", "revoke"}, sub)) return revoke(subcall);
    if (isCommandMatch({"vault", "read-grant", "recipient"}, sub)) return recipient(subcall);
    return invalid("vault read-grant: unknown subcommand '" + std::string(sub) +
                   "'. Use: issue | list | show | revoke | recipient");
}

}
