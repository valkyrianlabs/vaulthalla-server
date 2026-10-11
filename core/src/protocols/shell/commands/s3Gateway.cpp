#include "protocols/shell/commands/all.hpp"

#include "config/Registry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Config.hpp"
#include "ops/S3Gateway.hpp"
#include "protocols/s3/GatewayService.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "rbac/permission/admin/S3Gateway.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "runtime/Manager.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "vault/model/APIKey.hpp"
#include "usage/include/UsageManager.hpp"
#include "fs/model/File.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <nlohmann/json.hpp>
#include <openssl/md5.h>
#include "crypto/util/digest.hpp"
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// `vh s3-gateway ...`: parsing and rendering only. Who may do what, and what it changes, is ops::s3_gateway.
namespace vh::protocols::shell::commands {

namespace {

namespace gw = ::vh::ops::s3_gateway;

std::vector<std::string> optVals(const CommandCall& call, const std::string& key) {
    std::vector<std::string> values;
    for (const auto& [k, v] : call.options)
        if (k == key && v) values.push_back(*v);
    return values;
}

std::optional<std::time_t> parseExpiresAt(const CommandCall& call) {
    const auto value = optVal(call, "expires");
    if (!value || value->empty()) return std::nullopt;
    const auto suffix = value->back();
    const auto number = (suffix >= '0' && suffix <= '9') ? *value : value->substr(0, value->size() - 1);
    const auto parsed = parseUInt(number);
    if (!parsed || *parsed == 0) throw std::runtime_error("s3-gateway: --expires must be a positive duration such as 30d or 12h");
    std::time_t seconds = *parsed;
    switch (std::tolower(static_cast<unsigned char>(suffix))) {
    case 'd': seconds *= 24 * 60 * 60; break;
    case 'h': seconds *= 60 * 60; break;
    case 'm': seconds *= 60; break;
    case 's': break;
    default:
        if (suffix < '0' || suffix > '9') throw std::runtime_error("s3-gateway: unsupported --expires suffix");
    }
    return std::time(nullptr) + seconds;
}

gw::Ref credentialRef(const std::string& value) { return gw::Ref{value}; }

std::shared_ptr<identities::User> requireUserArg(const std::string& value, const std::string& errPrefix) {
    auto lookup = resolveUser(value, errPrefix);
    if (!lookup || !lookup.ptr) throw std::runtime_error(lookup.error);
    return lookup.ptr;
}

std::optional<uint32_t> userOption(const CommandCall& call) {
    const auto userOpt = optVal(call, "user");
    if (!userOpt || userOpt->empty()) return std::nullopt;
    return requireUserArg(*userOpt, "s3-gateway")->id;
}

// A vault by id, or by name (under --owner when given).
uint32_t vaultArg(const CommandCall& call, const std::string& value) {
    if (const auto id = parseUInt(value)) return *id;
    std::optional<uint32_t> owner;
    if (const auto ownerOpt = optVal(call, "owner")) owner = requireUserArg(*ownerOpt, "s3-gateway")->id;
    return gw::vaultIdByName(call.user, value, owner);
}

std::string vaultName(const uint32_t vaultId) {
    const auto vault = db::query::vault::Vault::getVault(vaultId);
    return vault ? vault->name : std::to_string(vaultId);
}

std::optional<uint32_t> defaultRoleIdFromOptions(const CommandCall& call, const std::string& errPrefix) {
    auto roleValue = optVal(call, "default-role");
    if (!roleValue || roleValue->empty()) roleValue = optVal(call, "default-vault-role");
    if (!roleValue || roleValue->empty()) roleValue = optVal(call, "role");
    if (!roleValue || roleValue->empty()) return std::nullopt;
    const auto role = resolveVaultRole(*roleValue, errPrefix);
    if (!role) throw std::runtime_error(role.error);
    return role.ptr->id;
}

std::vector<uint32_t> selectedVaultIdsFromOptions(const CommandCall& call) {
    std::vector<uint32_t> vaultIds;
    for (const auto& vaultValue : optVals(call, "selected-vault")) vaultIds.push_back(vaultArg(call, vaultValue));
    return vaultIds;
}

// Shorthand flags: listing and reading are on; --write/--delete/--admin add to them.
gw::VaultAccess accessFromFlags(const CommandCall& call, const uint32_t vaultId) {
    return {.vault_id = vaultId, .write = hasFlag(call, "write"), .del = hasFlag(call, "delete"), .admin = hasFlag(call, "admin")};
}

std::vector<gw::VaultAccess> accessFromVaultOptions(const CommandCall& call) {
    std::vector<gw::VaultAccess> access;
    for (const auto& vaultValue : optVals(call, "vault")) access.push_back(accessFromFlags(call, vaultArg(call, vaultValue)));
    return access;
}

gw::OverrideSpec overrideSpecFromOptions(const CommandCall& call, const std::string& errPrefix) {
    gw::OverrideSpec spec;
    spec.permission = optVal(call, "permission").value_or(optVal(call, "perm").value_or(""));
    if (spec.permission.empty()) throw std::runtime_error(errPrefix + ": --permission is required");

    const auto parsedEffect = vault::parseEffectChangeOpt(call, errPrefix);
    if (!parsedEffect.ok) throw std::runtime_error(parsedEffect.error);
    if (parsedEffect.value) spec.effect = ::vh::rbac::permission::to_string(*parsedEffect.value);
    else spec.effect = optVal(call, "effect").value_or("");
    if (spec.effect.empty()) throw std::runtime_error(errPrefix + ": --effect allow|deny is required");

    spec.pattern = optVal(call, "path").value_or(optVal(call, "pattern").value_or(""));
    if (spec.pattern.empty()) throw std::runtime_error(errPrefix + ": --path/--pattern is required");

    const auto enabled = vault::parseEnableDisableOpt(call, errPrefix);
    if (!enabled.ok) throw std::runtime_error(enabled.error);
    spec.enabled = enabled.value.value_or(true);
    return spec;
}

std::string gwValueOrDash(const std::optional<std::string>& value) {
    return value && !value->empty() ? *value : "-";
}

std::string gwValueOrDash(const std::optional<std::uint32_t>& value) {
    return value ? std::to_string(*value) : "-";
}

std::string renderGatewayBudgetPolicies(const std::vector<storage::s3::pricing::PriceBudgetPolicy>& policies) {
    if (policies.empty()) return "No S3 gateway budget policies configured.\n";
    Table table({
        {"ID", Align::Right, 2, 6, false, false},
        {"Scope", Align::Left, 8, 26, false, false},
        {"Key", Align::Right, 1, 8, false, false},
        {"Vault", Align::Right, 1, 8, false, false},
        {"Mode", Align::Left, 3, 8, false, false},
        {"Monthly", Align::Right, 1, 14, false, false},
        {"Currency", Align::Left, 3, 8, false, false},
        {"Active", Align::Left, 3, 6, false, false}
    });
    for (const auto& policy : policies) {
        table.add_row({
            std::to_string(policy.id),
            storage::s3::pricing::toString(policy.scope),
            gwValueOrDash(policy.gateway_credential_id),
            gwValueOrDash(policy.vault_id),
            storage::s3::pricing::toString(policy.mode),
            gwValueOrDash(policy.max_monthly_cost),
            policy.currency,
            yesNo(policy.is_active)
        });
    }
    return table.render();
}

std::string renderGatewayBudgetTrends(const std::vector<storage::s3::pricing::PriceBudgetTrendStats>& trends) {
    if (trends.empty()) return "No S3 gateway budget usage yet.\n";
    Table table({
        {"Policy", Align::Right, 2, 6, false, false},
        {"Scope", Align::Left, 8, 26, false, false},
        {"Key", Align::Right, 1, 8, false, false},
        {"Vault", Align::Right, 1, 8, false, false},
        {"Window", Align::Left, 5, 8, false, false},
        {"Used", Align::Right, 1, 14, false, false},
        {"Remaining", Align::Right, 1, 14, false, false},
        {"Limit", Align::Right, 1, 14, false, false},
        {"Currency", Align::Left, 3, 8, false, false}
    });
    for (const auto& trend : trends) {
        table.add_row({
            std::to_string(trend.policy_id),
            trend.scope,
            gwValueOrDash(trend.gateway_credential_id),
            gwValueOrDash(trend.vault_id),
            trend.window_type,
            trend.total_cost,
            gwValueOrDash(trend.remaining),
            gwValueOrDash(trend.limit),
            trend.currency
        });
    }
    return table.render();
}

std::string renderLedger(const std::vector<storage::s3::pricing::PriceBudgetLedgerEntry>& ledger) {
    std::ostringstream out;
    for (const auto& entry : ledger) {
        out << "- id=" << entry.id
            << " policy=" << entry.policy_id
            << " key=" << gwValueOrDash(entry.gateway_credential_id)
            << " vault=" << entry.vault_id
            << " op=" << gwValueOrDash(entry.operation)
            << " reserved=" << entry.reserved_cost
            << " committed=" << gwValueOrDash(entry.committed_cost)
            << " " << entry.currency
            << " status=" << entry.status;
        if (entry.synthetic) out << " synthetic=true";
        if (entry.usage_source) out << " source=" << *entry.usage_source;
        out << "\n";
    }
    return out.str();
}

bool isGatewayMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"s3-gateway", cmd}, input);
}

std::string gatewayObjectKeyFromPath(const std::filesystem::path& path) {
    auto key = path.lexically_normal().generic_string();
    while (!key.empty() && key.front() == '/') key.erase(key.begin());
    return key;
}

std::string hexDigest(const unsigned char* digest, const std::size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i)
        out << std::setw(2) << static_cast<unsigned int>(digest[i]);
    return out.str();
}

std::vector<uint8_t> readFileBytesForGatewayBackfill(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("unable to read backing file for ETag backfill: " + path.string());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string md5EtagForGatewayBackfill(const std::vector<uint8_t>& bytes) {
    const auto digest = crypto::util::EvpDigest::of(EVP_md5(), bytes.data(), bytes.size());
    return "\"" + hexDigest(digest.data(), digest.size()) + "\"";
}

std::vector<uint8_t> plaintextForGatewayBackfill(
    const std::shared_ptr<storage::Engine>& engine,
    const std::shared_ptr<::vh::fs::model::File>& file) {
    if (!file || file->size_bytes == 0) return {};
    if (file->encryption_iv.empty() || file->encrypted_with_key_version == 0)
        return readFileBytesForGatewayBackfill(file->backing_path);
    return engine->decrypt(file);
}

// Through ops::config (the same apply step settings.update uses), then report the state the gateway reached.
CommandResult setGatewayEnabled(const CommandCall& call, const bool wantEnabled, const std::string& message) {
    try {
        (void)::vh::ops::config::setGatewayEnabled(call.user, wantEnabled);
    } catch (const ::vh::ops::Error& e) {
        return invalid(std::string("s3-gateway: ") + e.what());
    } catch (const std::exception& e) {
        return invalid("s3-gateway config update failed: " + std::string(e.what()));
    }

    // restartService() returns before the listener is up (or has failed to bind); report the state the gateway
    // actually reached instead of assuming success.
    const auto service = runtime::Manager::instance().getS3GatewayService();
    if (!service)
        return ok(message + "Config saved; the S3 gateway service is not managed by this process, so the change "
                            "takes effect on the next daemon restart.\n");

    constexpr auto kSettleTimeout = std::chrono::seconds(5);
    const auto deadline = std::chrono::steady_clock::now() + kSettleTimeout;
    auto status = service->gatewayStatus();
    while (std::chrono::steady_clock::now() < deadline && wantEnabled && !status.ready) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        status = service->gatewayStatus();
    }

    const auto endpoint = status.host + ":" + std::to_string(status.port);
    if (wantEnabled && !status.ready)
        return {1, "",
                "s3-gateway: enabled in config, but the gateway is not listening on " + endpoint + " after " +
                std::to_string(kSettleTimeout.count()) + "s (port in use or bind failure?). "
                "Check the daemon log (journalctl -u vaulthalla) and `vh s3-gateway status`."};
    if (!wantEnabled && status.ready)
        return {1, "", "s3-gateway: disabled in config, but the gateway is still listening on " + endpoint + "."};

    return ok(message + (wantEnabled ? "Listening on " + endpoint + ".\n" : ""));
}

CommandResult handleS3GatewayStatus(const CommandCall& call) {
    const auto status = gw::status(call.user);
    std::ostringstream out;
    out << "s3 gateway\n";
    out << "  running: " << yesNo(status.running) << "\n";
    out << "  configured: " << yesNo(status.configured) << "\n";
    out << "  ready: " << yesNo(status.ready) << "\n";
    out << "  endpoint: " << status.host << ":" << status.port << "\n";
    out << "  active sessions: " << status.activeSessions << "\n";
    out << "  total requests: " << status.totalRequests << "\n";
    out << "  failed requests: " << status.failedRequests << "\n";
    return ok(out.str());
}

CommandResult handleEnable(const CommandCall& call) { return setGatewayEnabled(call, true, "S3 gateway enabled.\n"); }

CommandResult handleDisable(const CommandCall& call) { return setGatewayEnabled(call, false, "S3 gateway disabled.\n"); }

CommandResult handleCredsCreate(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    gw::CreateCredential req{
        .name = call.positionals[0],
        .principal_id = userOption(call),
        .scope_mode = optVal(call, "scope"),
        .description = optVal(call, "description"),
        .expires_at = parseExpiresAt(call),
        .default_role_id = defaultRoleIdFromOptions(call, "s3-gateway creds create"),
        .selected_vault_ids = selectedVaultIdsFromOptions(call),
        .vault_access = accessFromVaultOptions(call),
        .enforce_budget_for_local_requests = hasFlag(call, "enforce-budget-for-local-requests")
    };
    const auto created = gw::createCredential(call.user, req);
    const auto& credential = created.credential;
    const auto principal = vh::identities::manager().user(credential.principal_user_id);

    if (hasFlag(call, "json")) {
        nlohmann::json j = {
            {"user_id", credential.principal_user_id},
            {"principal_user_id", credential.principal_user_id},
            {"created_by", credential.created_by ? nlohmann::json(*credential.created_by) : nlohmann::json(nullptr)},
            {"name", credential.name},
            {"access_key", credential.access_key},
            {"secret_access_key", created.secret_access_key},
            {"scope_mode", credential.scope_mode},
            {"enforce_budget_for_local_requests", credential.enforce_budget_for_local_requests},
            {"expires_at", credential.expires_at ? nlohmann::json(*credential.expires_at) : nlohmann::json(nullptr)}
        };
        return ok(j.dump(4) + "\n");
    }

    std::ostringstream out;
    out << "created S3 gateway credential\n";
    out << "  user: " << (principal ? principal->name() : "-") << " (" << credential.principal_user_id << ")\n";
    out << "  name: " << credential.name << "\n";
    out << "  scope: " << credential.scope_mode << "\n";
    out << "  count local/cache budget usage: " << yesNo(credential.enforce_budget_for_local_requests) << "\n";
    out << "  access key: " << credential.access_key << "\n";
    out << "  secret access key: " << created.secret_access_key << "\n";
    if (!req.vault_access.empty())
        out << "  warning: Boolean scope flags are compatibility shorthand. Gateway authorization uses vault roles.\n";
    out << "store the secret now; it cannot be listed again.\n";
    return ok(out.str());
}

CommandResult handleCredsList(const CommandCall& call) {
    const auto principalId = userOption(call).value_or(call.user->id);
    const auto creds = gw::listCredentials(call.user, principalId);
    const auto principal = vh::identities::manager().user(principalId);

    if (hasFlag(call, "json")) {
        nlohmann::json rows = nlohmann::json::array();
        for (const auto& credential : creds) {
            rows.push_back({
                {"id", credential.id},
                {"user_id", credential.user_id},
                {"principal_user_id", credential.principal_user_id},
                {"created_by", credential.created_by ? nlohmann::json(*credential.created_by) : nlohmann::json(nullptr)},
                {"name", credential.name},
                {"access_key", credential.access_key},
                {"scope_mode", credential.scope_mode},
                {"enforce_budget_for_local_requests", credential.enforce_budget_for_local_requests},
                {"description", credential.description ? nlohmann::json(*credential.description) : nlohmann::json(nullptr)},
                {"enabled", credential.enabled},
                {"created_at", credential.created_at},
                {"last_used_at", credential.last_used_at ? nlohmann::json(*credential.last_used_at) : nlohmann::json(nullptr)},
                {"expires_at", credential.expires_at ? nlohmann::json(*credential.expires_at) : nlohmann::json(nullptr)}
            });
        }
        return ok(rows.dump(4) + "\n");
    }

    std::ostringstream out;
    out << "s3 gateway credentials for " << (principal ? principal->name() : "-") << " (" << principalId << ")\n";
    if (creds.empty()) out << "none\n";
    for (const auto& credential : creds) {
        out << "- " << credential.name << " " << credential.access_key
            << " scope=" << credential.scope_mode
            << " local_budget=" << yesNo(credential.enforce_budget_for_local_requests)
            << " enabled=" << yesNo(credential.enabled);
        if (credential.last_used_at) out << " last_used=" << *credential.last_used_at;
        if (credential.expires_at) out << " expires=" << *credential.expires_at;
        out << "\n";
    }
    return ok(out.str());
}

CommandResult handleCredsRevoke(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    (void)gw::revokeCredential(call.user, credentialRef(call.positionals[0]));
    return ok("S3 gateway credential revoked.\n");
}

std::string renderCredentialScopes(const db::query::s3::GatewayCredential& credential) {
    std::ostringstream out;
    out << "S3 gateway credential policy\n";
    out << "  name: " << credential.name << "\n";
    out << "  access key: " << credential.access_key << "\n";
    out << "  principal: " << credential.principal_user_id << "\n";
    out << "  scope: " << credential.scope_mode << "\n";
    out << "  count local/cache budget usage: " << yesNo(credential.enforce_budget_for_local_requests) << "\n";
    if (credential.scope_mode == "user_access") {
        out << "  gateway vault policy: none; uses principal RBAC\n";
        return out.str();
    }

    const auto defaultRole = db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    if (defaultRole) {
        const auto role = db::query::rbac::role::Vault::get(defaultRole->vault_role_id);
        out << "  default role: " << (role ? role->name : std::to_string(defaultRole->vault_role_id))
            << " enabled=" << yesNo(defaultRole->enabled) << "\n";
    } else {
        out << "  default role: none\n";
    }

    if (credential.scope_mode == "vault_allowlist") {
        const auto selectedVaults = db::query::s3::Gateway::listCredentialSelectedVaults(credential.id);
        out << "  selected vaults:";
        if (selectedVaults.empty()) {
            out << " none\n";
        } else {
            out << "\n";
            for (const auto& selectedVault : selectedVaults)
                out << "  - vault=" << selectedVault.vault_id
                    << " enabled=" << yesNo(selectedVault.enabled) << "\n";
        }
    } else {
        out << "  selected vaults: gateway bucket bindings\n";
    }

    const auto assignments = db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id);
    out << "  per-vault exceptions:";
    if (assignments.empty()) {
        out << " none\n";
    } else {
        out << "\n";
        for (const auto& assignment : assignments) {
            const auto role = db::query::rbac::role::Vault::get(assignment.vault_role_id);
            out << "  - vault=" << assignment.vault_id
                << " role=" << (role ? role->name : std::to_string(assignment.vault_role_id))
                << " enabled=" << yesNo(assignment.enabled) << "\n";
        }
    }
    return out.str();
}

CommandResult showCredentialScopes(const CommandCall& call, const db::query::s3::GatewayCredential& credential) {
    if (!hasFlag(call, "json")) return ok(renderCredentialScopes(credential));
    const auto defaultRole = db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    nlohmann::json selectedVaults = nlohmann::json::array();
    for (const auto& selectedVault : db::query::s3::Gateway::listCredentialSelectedVaults(credential.id))
        selectedVaults.push_back({
            {"credential_id", selectedVault.credential_id},
            {"vault_id", selectedVault.vault_id},
            {"enabled", selectedVault.enabled}
        });
    nlohmann::json roleAssignments = nlohmann::json::array();
    for (const auto& assignment : db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id))
        roleAssignments.push_back({
            {"id", assignment.id},
            {"credential_id", assignment.credential_id},
            {"vault_id", assignment.vault_id},
            {"vault_role_id", assignment.vault_role_id},
            {"enabled", assignment.enabled}
        });
    return ok(nlohmann::json{
        {"credential_id", credential.id},
        {"scope_mode", credential.scope_mode},
        {"enforce_budget_for_local_requests", credential.enforce_budget_for_local_requests},
        {"default_role", defaultRole ? nlohmann::json{
            {"id", defaultRole->id},
            {"credential_id", defaultRole->credential_id},
            {"vault_role_id", defaultRole->vault_role_id},
            {"enabled", defaultRole->enabled}
        } : nlohmann::json(nullptr)},
        {"selected_vaults", selectedVaults},
        {"role_assignments", roleAssignments}
    }.dump(4) + "\n");
}

std::string vaultFromPositionalOrOption(const CommandCall& call) {
    return call.positionals.size() >= 3 ? call.positionals[2] : optVal(call, "vault").value_or("");
}

CommandResult handleCredsScope(const CommandCall& call) {
    if (call.positionals.size() < 2) return usage(call.constructFullArgs());
    const auto ref = credentialRef(call.positionals[0]);
    const auto& action = call.positionals[1];

    if (action == "show" || action == "list") return showCredentialScopes(call, gw::getCredential(call.user, ref));

    if (action == "set") {
        if (hasFlag(call, "enforce-budget-for-local-requests") && hasFlag(call, "no-enforce-budget-for-local-requests"))
            return invalid("s3-gateway creds scope set: local budget enforcement flags are mutually exclusive");
        gw::ScopeUpdate req;
        if (const auto scope = optVal(call, "scope"); scope && !scope->empty()) req.scope_mode = *scope;
        if (hasFlag(call, "enforce-budget-for-local-requests")) req.enforce_budget_for_local_requests = true;
        if (hasFlag(call, "no-enforce-budget-for-local-requests")) req.enforce_budget_for_local_requests = false;
        if (hasKey(call, "description")) req.description = optVal(call, "description");
        if (hasKey(call, "expires")) req.expires_at = parseExpiresAt(call);
        req.principal_id = userOption(call);
        req.default_role_id = defaultRoleIdFromOptions(call, "s3-gateway creds scope set");
        if (!optVals(call, "selected-vault").empty()) req.selected_vault_ids = selectedVaultIdsFromOptions(call);
        (void)gw::updateScope(call.user, ref, req);
        return ok("S3 gateway credential scope updated.\n");
    }

    if (action == "allow-vault") {
        const auto vaultValue = vaultFromPositionalOrOption(call);
        if (vaultValue.empty()) return invalid("s3-gateway creds scope allow-vault: vault is required");
        (void)gw::allowVault(call.user, ref, accessFromFlags(call, vaultArg(call, vaultValue)));
        return ok("S3 gateway selected vault added from boolean shorthand. Gateway authorization uses vault roles.\n");
    }

    if (action == "revoke-vault") {
        const auto vaultValue = vaultFromPositionalOrOption(call);
        if (vaultValue.empty()) return invalid("s3-gateway creds scope revoke-vault: vault is required");
        gw::removeVault(call.user, ref, vaultArg(call, vaultValue));
        return ok("S3 gateway selected vault revoked.\n");
    }

    return invalid(call.constructFullArgs(), "Unknown s3-gateway creds scope action: '" + action + "'");
}

std::string renderCredentialRoleAssignments(const db::query::s3::GatewayCredential& credential,
                                            const std::vector<gw::Assignment>& assignments) {
    std::ostringstream out;
    out << "S3 gateway credential vault roles\n";
    out << "  name: " << credential.name << "\n";
    out << "  access key: " << credential.access_key << "\n";
    out << "  principal: " << credential.principal_user_id << "\n";
    if (assignments.empty()) {
        out << "  roles: none\n";
        return out.str();
    }

    Table table({
        {"Vault", Align::Right, 2, 8, false, false},
        {"Vault Name", Align::Left, 6, 24, false, false},
        {"Role", Align::Right, 2, 8, false, false},
        {"Role Name", Align::Left, 6, 24, false, false},
        {"Enabled", Align::Left, 3, 7, false, false},
        {"Overrides", Align::Right, 1, 9, false, false}
    });
    for (const auto& assignment : assignments) {
        const auto role = db::query::rbac::role::Vault::get(assignment.vault_role_id);
        std::size_t overrideCount = 0;
        try {
            overrideCount = db::query::s3::Gateway::listCredentialVaultRoleOverrides(credential.id, assignment.vault_id).size();
        } catch (const std::exception&) {
        }
        table.add_row({
            std::to_string(assignment.vault_id),
            vaultName(assignment.vault_id),
            std::to_string(assignment.vault_role_id),
            role ? role->name : "-",
            yesNo(assignment.enabled),
            std::to_string(overrideCount)
        });
    }
    out << table.render();
    return out.str();
}

CommandResult handleCredsRoleList(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto ref = credentialRef(call.positionals[0]);
    const auto credential = gw::getCredential(call.user, ref);
    const auto assignments = gw::listRoleAssignments(call.user, ref);
    if (hasFlag(call, "json")) {
        nlohmann::json rows = nlohmann::json::array();
        for (const auto& assignment : assignments) {
            const auto vault = db::query::vault::Vault::getVault(assignment.vault_id);
            const auto role = db::query::rbac::role::Vault::get(assignment.vault_role_id);
            rows.push_back({
                {"id", assignment.id},
                {"credential_id", assignment.credential_id},
                {"vault_id", assignment.vault_id},
                {"vault", vault ? nlohmann::json{{"id", vault->id}, {"name", vault->name}} : nlohmann::json(nullptr)},
                {"vault_role_id", assignment.vault_role_id},
                {"role", role ? nlohmann::json{{"id", role->id}, {"name", role->name}, {"description", role->description}} : nlohmann::json(nullptr)},
                {"enabled", assignment.enabled},
                {"created_by", assignment.created_by ? nlohmann::json(*assignment.created_by) : nlohmann::json(nullptr)},
                {"created_at", assignment.created_at},
                {"updated_at", assignment.updated_at}
            });
        }
        return ok(nlohmann::json{{"credential_id", credential.id}, {"roles", rows}}.dump(4) + "\n");
    }
    return ok(renderCredentialRoleAssignments(credential, assignments));
}

uint32_t requiredVaultOption(const CommandCall& call, const std::string& errPrefix) {
    const auto vaultValue = optVal(call, "vault").value_or("");
    if (vaultValue.empty()) throw std::runtime_error(errPrefix + ": --vault is required");
    return vaultArg(call, vaultValue);
}

CommandResult handleCredsRoleAssign(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto vaultId = requiredVaultOption(call, "s3-gateway creds role assign");
    const auto roleValue = optVal(call, "role").value_or("");
    if (roleValue.empty()) return invalid("s3-gateway creds role assign: --role is required");
    const auto role = resolveVaultRole(roleValue, "s3-gateway creds role assign");
    if (!role) return invalid(role.error);

    const auto credential = gw::getCredential(call.user, credentialRef(call.positionals[0]));
    const auto assignment = gw::assignRole(call.user, credential.id, vaultId, role.ptr->id);
    if (hasFlag(call, "json")) {
        return ok(nlohmann::json{
            {"id", assignment.id},
            {"credential_id", credential.id},
            {"vault_id", vaultId},
            {"vault_role_id", role.ptr->id},
            {"role", {{"id", role.ptr->id}, {"name", role.ptr->name}}},
            {"vault", {{"id", vaultId}, {"name", vaultName(vaultId)}}}
        }.dump(4) + "\n");
    }
    return ok("Assigned role '" + role.ptr->name + "' to S3 gateway credential '" + credential.name +
              "' for vault '" + vaultName(vaultId) + "'.\n");
}

CommandResult handleCredsRoleRevoke(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto vaultId = requiredVaultOption(call, "s3-gateway creds role revoke");
    gw::revokeRole(call.user, credentialRef(call.positionals[0]), vaultId);
    return ok("Revoked S3 gateway credential role for vault '" + vaultName(vaultId) + "'.\n");
}

CommandResult handleCredsRoleOverrideList(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto vaultId = requiredVaultOption(call, "s3-gateway creds role override list");
    const auto credential = gw::getCredential(call.user, credentialRef(call.positionals[0]));
    const auto overrides = gw::listRoleOverrides(call.user, credential.id, vaultId);
    if (hasFlag(call, "json")) {
        nlohmann::json rows = overrides;
        return ok(nlohmann::json{{"credential_id", credential.id}, {"vault_id", vaultId}, {"overrides", rows}}.dump(4) + "\n");
    }
    return ok(::vh::rbac::permission::to_string(overrides) + "\n");
}

CommandResult handleCredsRoleOverrideAdd(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const std::string errPrefix = "s3-gateway creds role override add";
    const auto vaultId = requiredVaultOption(call, errPrefix);
    const auto credential = gw::getCredential(call.user, credentialRef(call.positionals[0]));
    const auto saved = gw::addRoleOverride(call.user, credential.id, vaultId, overrideSpecFromOptions(call, errPrefix));
    if (hasFlag(call, "json")) {
        return ok(nlohmann::json{
            {"id", saved.id},
            {"credential_id", credential.id},
            {"vault_id", vaultId},
            {"permission", saved.permission.qualified_name},
            {"pattern", saved.glob_path()},
            {"effect", ::vh::rbac::permission::to_string(saved.effect)},
            {"enabled", saved.enabled}
        }.dump(4) + "\n");
    }
    return ok("Added S3 gateway credential role override " + std::to_string(saved.id) + ".\n");
}

CommandResult handleCredsRoleOverrideRemove(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto vaultId = requiredVaultOption(call, "s3-gateway creds role override remove");
    const auto overrideValue = optVal(call, std::vector<std::string>{"override-id", "id"})
                                   .value_or(call.positionals.size() >= 2 ? call.positionals[1] : "");
    if (overrideValue.empty()) return invalid("s3-gateway creds role override remove: override id is required");
    const auto overrideId = parseUInt(overrideValue);
    if (!overrideId) return invalid("s3-gateway creds role override remove: override id must be a positive integer");
    gw::removeRoleOverride(call.user, credentialRef(call.positionals[0]), vaultId, *overrideId);
    return ok("Removed S3 gateway credential role override " + std::to_string(*overrideId) + ".\n");
}

CommandResult handleCredsRoleOverride(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"s3-gateway", "creds", "role", "override", "add"}, sub) || sub == "add")
        return handleCredsRoleOverrideAdd(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "role", "override", "list"}, sub) || sub == "list")
        return handleCredsRoleOverrideList(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "role", "override", "remove"}, sub) || sub == "remove")
        return handleCredsRoleOverrideRemove(subcall);
    return invalid(call.constructFullArgs(), "Unknown s3-gateway creds role override action: '" + std::string(sub) + "'");
}

CommandResult handleCredsRole(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"s3-gateway", "creds", "role", "assign"}, sub) || sub == "assign")
        return handleCredsRoleAssign(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "role", "revoke"}, sub) || sub == "revoke")
        return handleCredsRoleRevoke(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "role", "list"}, sub) || sub == "list")
        return handleCredsRoleList(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "role", "override"}, sub) || sub == "override")
        return handleCredsRoleOverride(subcall);
    return invalid(call.constructFullArgs(), "Unknown s3-gateway creds role subcommand: '" + std::string(sub) + "'");
}

CommandResult handleCreds(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"s3-gateway", "creds", "create"}, sub)) return handleCredsCreate(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "list"}, sub)) return handleCredsList(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "revoke"}, sub)) return handleCredsRevoke(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "scope"}, sub) || sub == "scope") return handleCredsScope(subcall);
    if (isCommandMatch({"s3-gateway", "creds", "role"}, sub) || sub == "role") return handleCredsRole(subcall);
    return invalid(call.constructFullArgs(), "Unknown s3-gateway creds subcommand: '" + std::string(sub) + "'");
}

CommandResult handleBucketList(const CommandCall& call) {
    const auto buckets = gw::listBuckets(call.user);
    if (hasFlag(call, "json")) {
        nlohmann::json rows = nlohmann::json::array();
        for (const auto& bucket : buckets) {
            rows.push_back({
                {"bucket", bucket.bucket_name},
                {"vault_id", bucket.vault_id},
                {"mode", bucket.mode},
                {"api_exclusive", bucket.api_exclusive},
                {"created_by", bucket.created_by ? nlohmann::json(*bucket.created_by) : nlohmann::json(nullptr)},
                {"created_at", bucket.created_at},
                {"updated_at", bucket.updated_at}
            });
        }
        return ok(rows.dump(4) + "\n");
    }

    std::ostringstream out;
    out << "s3 gateway buckets\n";
    if (buckets.empty()) out << "none\n";
    for (const auto& bucket : buckets) {
        out << "- " << bucket.bucket_name << " vault=" << bucket.vault_id
            << " mode=" << bucket.mode
            << " api_exclusive=" << yesNo(bucket.api_exclusive) << "\n";
    }
    return ok(out.str());
}

CommandResult handleBucketBind(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto bucket = gw::bindBucket(call.user, {
        .vault_id = requiredVaultOption(call, "s3-gateway bucket bind"),
        .bucket_name = call.positionals[0],
        .mode = optVal(call, "mode"),
        .api_exclusive = hasFlag(call, "api-exclusive")
    });
    return ok("Bound bucket " + bucket.bucket_name + " to vault " + std::to_string(bucket.vault_id) + ".\n");
}

CommandResult handleBucketUnbind(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    gw::unbindBucket(call.user, call.positionals[0]);
    return ok("Unbound bucket " + call.positionals[0] + ".\n");
}

CommandResult handleBucketCreateLocal(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    uintmax_t quota = 0;
    if (const auto quotaOpt = optVal(call, "quota"); quotaOpt && !quotaOpt->empty()) {
        ::vh::vault::model::Vault quotaParser;
        quotaParser.setQuotaFromStr(*quotaOpt);
        quota = quotaParser.quota;
    }
    const auto bucket = gw::createLocalBucket(call.user, {
        .bucket_name = call.positionals[0], .owner_id = userOption(call), .quota = quota});
    return ok("Created local S3 gateway bucket " + bucket.bucket_name + " on vault " + std::to_string(bucket.vault_id) + ".\n");
}

CommandResult handleBucketCreateRemoteCache(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    constexpr auto ERR = "s3-gateway bucket create-remote-cache";
    const auto apiKeyOpt = optVal(call, "api-key");
    const auto upstreamBucketOpt = optVal(call, "upstream-bucket");
    if (!apiKeyOpt || apiKeyOpt->empty()) return invalid(std::string(ERR) + ": --api-key is required");
    if (!upstreamBucketOpt || upstreamBucketOpt->empty()) return invalid(std::string(ERR) + ": --upstream-bucket is required");
    if (hasFlag(call, "encrypt") && hasFlag(call, "no-encrypt"))
        return invalid(std::string(ERR) + ": --encrypt and --no-encrypt are mutually exclusive");
    const auto apiKeyId = parseUInt(*apiKeyOpt);
    const auto apiKey = apiKeyId ? db::query::vault::APIKey::getAPIKey(*apiKeyId) : db::query::vault::APIKey::getAPIKey(*apiKeyOpt);
    if (!apiKey) return invalid(std::string(ERR) + ": upstream API key not found");

    const auto& name = call.positionals[0];
    return vault::runWithWaiver(call, ERR, [&](const bool accept) {
        const auto bucket = gw::createRemoteCacheBucket(call.user, {
            .bucket_name = name, .api_key_id = apiKey->id, .upstream_bucket = *upstreamBucketOpt,
            .encrypt_upstream = !hasFlag(call, "no-encrypt"), .name = name, .accept_waiver = accept});
        return "Created remote-cache S3 gateway bucket " + bucket.bucket_name + " on vault " +
               std::to_string(bucket.vault_id) + ".\n";
    });
}

CommandResult handleBucketBackfill(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto& bucketName = call.positionals[0];
    const auto binding = gw::requireManageableBucket(call.user, bucketName);

    const bool calculateEtags = hasFlag(call, "calculate-etags");
    std::uint64_t calculated = 0;
    if (binding.mode == "remote_cache" || binding.mode == "remote_proxy") {
        db::query::s3::Gateway::backfillObjectStateFromRemoteIndex(binding.vault_id);
    } else {
        db::query::s3::Gateway::backfillObjectStateFromFs(binding.vault_id);
    }

    if (calculateEtags) {
        if (binding.mode != "local")
            return invalid("s3-gateway bucket backfill: --calculate-etags is only supported for local Vaulthalla files");
        auto engine = runtime::Deps::get().storageManager->getEngine(binding.vault_id);
        if (!engine) return invalid("s3-gateway bucket backfill: storage engine not available");
        const auto files = db::query::fs::File::listFilesInDir(binding.vault_id, "/", true);
        for (const auto& file : files) {
            if (!file) continue;
            const auto objectKey = gatewayObjectKeyFromPath(file->path);
            if (objectKey.empty()) continue;
            const auto plaintext = plaintextForGatewayBackfill(engine, file);
            db::query::s3::Gateway::upsertObject({
                .vault_id = binding.vault_id,
                .object_key = objectKey,
                .etag = md5EtagForGatewayBackfill(plaintext),
                .size_bytes = file->size_bytes,
                .content_type = file->mime_type,
                .storage_class = file->remote_storage_class,
                .last_modified = file->updated_at,
                .multipart = false,
                .part_count = std::nullopt
            });
            ++calculated;
        }
    }

    std::ostringstream out;
    out << "Backfilled S3 gateway metadata for bucket " << bucketName << ".\n";
    if (calculateEtags) {
        out << "WARNING: --calculate-etags read/decrypted local object bodies intentionally.\n";
        out << "Calculated plaintext MD5 ETags for " << calculated << " objects.\n";
    } else {
        out << "Metadata-only backfill completed; no object bodies were read or decrypted.\n";
    }
    return ok(out.str());
}

CommandResult handleBucket(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"s3-gateway", "bucket", "list"}, sub) || sub == "list" || sub == "ls")
        return handleBucketList(subcall);
    if (isCommandMatch({"s3-gateway", "bucket", "bind"}, sub) || sub == "bind") return handleBucketBind(subcall);
    if (isCommandMatch({"s3-gateway", "bucket", "unbind"}, sub) || sub == "unbind") return handleBucketUnbind(subcall);
    if (isCommandMatch({"s3-gateway", "bucket", "create-local"}, sub) || sub == "create-local")
        return handleBucketCreateLocal(subcall);
    if (isCommandMatch({"s3-gateway", "bucket", "create-remote-cache"}, sub) || sub == "create-remote-cache")
        return handleBucketCreateRemoteCache(subcall);
    if (isCommandMatch({"s3-gateway", "bucket", "backfill"}, sub) || sub == "backfill") return handleBucketBackfill(subcall);
    return invalid(call.constructFullArgs(), "Unknown s3-gateway bucket subcommand: '" + std::string(sub) + "'");
}

gw::BudgetFilter budgetFilterFromOptions(const CommandCall& call) {
    gw::BudgetFilter filter;
    if (const auto vaultOpt = optVal(call, "vault"); vaultOpt && !vaultOpt->empty()) filter.vault_id = vaultArg(call, *vaultOpt);
    if (const auto keyOpt = optVal(call, "key"); keyOpt && !keyOpt->empty())
        filter.credential_id = gw::getBudgetCredential(call.user, credentialRef(*keyOpt), filter.vault_id).id;
    return filter;
}

uint32_t limitFromOptions(const CommandCall& call, const std::string& errPrefix) {
    const auto limitOpt = optVal(call, "limit");
    if (!limitOpt) return 50;
    const auto parsed = parseUInt(*limitOpt);
    if (!parsed || *parsed == 0) throw std::runtime_error(errPrefix + ": --limit must be a positive integer");
    return *parsed;
}

gw::BudgetSpec budgetSpecFromCall(const CommandCall& call, const gw::BudgetScope scope, const uint32_t credentialId,
                                  const std::optional<uint32_t> vaultId) {
    const auto monthly = optVal(call, "monthly");
    if (!monthly || monthly->empty() || !storage::s3::pricing::isValidPriceBudgetDecimal(*monthly))
        throw std::runtime_error("s3-gateway budget: --monthly must be a non-negative decimal with at most 8 fractional digits");
    return {
        .scope = scope,
        .credential_id = credentialId,
        .vault_id = vaultId,
        .mode = optVal(call, "mode"),
        .currency = optVal(call, "currency"),
        .max_monthly_cost = *monthly,
        .require_verified_catalog = !hasFlag(call, "no-require-verified-catalog"),
        .allow_stale_catalog = hasFlag(call, "allow-stale-catalog")
    };
}

CommandResult handleBudgetSetKey(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto credential = gw::getBudgetCredential(call.user, credentialRef(call.positionals[0]));
    const auto saved = gw::upsertBudget(call.user, budgetSpecFromCall(call, gw::BudgetScope::Key, credential.id, std::nullopt));
    return ok("S3 gateway key budget saved.\n" + renderGatewayBudgetPolicies({saved}));
}

CommandResult handleBudgetSetKeyVault(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto vaultId = requiredVaultOption(call, "s3-gateway budget set-key-vault");
    const auto credential = gw::getBudgetCredential(call.user, credentialRef(call.positionals[0]), vaultId);
    const auto saved = gw::upsertBudget(call.user, budgetSpecFromCall(call, gw::BudgetScope::KeyVault, credential.id, vaultId));
    return ok("S3 gateway key/vault budget saved.\n" + renderGatewayBudgetPolicies({saved}));
}

CommandResult handleGatewayBudgetList(const CommandCall& call) {
    const auto policies = gw::listBudgets(call.user, budgetFilterFromOptions(call));
    if (hasFlag(call, "json")) return ok(nlohmann::json(policies).dump(4) + "\n");
    return ok(renderGatewayBudgetPolicies(policies));
}

CommandResult handleBudgetDisableKey(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto credential = gw::getBudgetCredential(call.user, credentialRef(call.positionals[0]));
    const auto disabled = gw::disableBudget(call.user, gw::BudgetScope::Key, credential.id, std::nullopt);
    return ok(disabled ? "S3 gateway key budget disabled.\n" : "No matching S3 gateway key budget was configured.\n");
}

CommandResult handleBudgetDisableKeyVault(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto vaultId = requiredVaultOption(call, "s3-gateway budget disable-key-vault");
    const auto credential = gw::getBudgetCredential(call.user, credentialRef(call.positionals[0]), vaultId);
    const auto disabled = gw::disableBudget(call.user, gw::BudgetScope::KeyVault, credential.id, vaultId);
    return ok(disabled ? "S3 gateway key/vault budget disabled.\n" : "No matching S3 gateway key/vault budget was configured.\n");
}

CommandResult handleBudgetLedger(const CommandCall& call) {
    const auto limit = limitFromOptions(call, "s3-gateway budget ledger");
    const auto ledger = gw::budgetLedger(call.user, budgetFilterFromOptions(call), limit);
    if (hasFlag(call, "json")) return ok(nlohmann::json(ledger).dump(4) + "\n");
    if (ledger.empty()) return ok("No S3 gateway budget ledger rows.\n");
    return ok(renderLedger(ledger));
}

CommandResult handleBudgetStatus(const CommandCall& call) {
    const auto limit = limitFromOptions(call, "s3-gateway budget status");
    const auto status = gw::budgetStatus(call.user, budgetFilterFromOptions(call), limit);
    if (hasFlag(call, "json")) {
        return ok(nlohmann::json{
            {"policies", status.policies},
            {"ledger", status.ledger},
            {"trends", status.trends}
        }.dump(4) + "\n");
    }

    std::ostringstream out;
    out << "S3 gateway budgets\n" << renderGatewayBudgetPolicies(status.policies)
        << "\nCurrent usage\n" << renderGatewayBudgetTrends(status.trends)
        << "\nRecent ledger rows\n";
    out << (status.ledger.empty() ? "No S3 gateway budget ledger rows.\n" : renderLedger(status.ledger));
    return ok(out.str());
}

CommandResult handleGatewayBudget(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"s3-gateway", "budget", "set-key"}, sub) || sub == "set-key") return handleBudgetSetKey(subcall);
    if (isCommandMatch({"s3-gateway", "budget", "set-key-vault"}, sub) || sub == "set-key-vault") return handleBudgetSetKeyVault(subcall);
    if (isCommandMatch({"s3-gateway", "budget", "list"}, sub) || sub == "list") return handleGatewayBudgetList(subcall);
    if (isCommandMatch({"s3-gateway", "budget", "disable-key"}, sub) || sub == "disable-key") return handleBudgetDisableKey(subcall);
    if (isCommandMatch({"s3-gateway", "budget", "disable-key-vault"}, sub) || sub == "disable-key-vault") return handleBudgetDisableKeyVault(subcall);
    if (isCommandMatch({"s3-gateway", "budget", "ledger"}, sub) || sub == "ledger") return handleBudgetLedger(subcall);
    if (isCommandMatch({"s3-gateway", "budget", "status"}, sub) || sub == "status") return handleBudgetStatus(subcall);
    return invalid(call.constructFullArgs(), "Unknown s3-gateway budget subcommand: '" + std::string(sub) + "'");
}

CommandResult handleS3Gateway(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    // Every refusal (ops::Error) and parse failure is a usage error, exit 2, as before.
    try {
        const auto [sub, subcall] = descend(call);
        if (isGatewayMatch("status", sub)) return handleS3GatewayStatus(subcall);
        if (isGatewayMatch("enable", sub)) return handleEnable(subcall);
        if (isGatewayMatch("disable", sub)) return handleDisable(subcall);
        if (isGatewayMatch("creds", sub)) return handleCreds(subcall);
        if (isGatewayMatch("bucket", sub)) return handleBucket(subcall);
        if (isGatewayMatch("budget", sub) || sub == "budget") return handleGatewayBudget(subcall);
        return invalid(call.constructFullArgs(), "Unknown s3-gateway subcommand: '" + std::string(sub) + "'");
    } catch (const std::exception& e) {
        return invalid(std::string("s3-gateway: ") + e.what());
    }
}

} // namespace

void registerS3GatewayCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("s3-gateway"), handleS3Gateway);
}

} // namespace vh::protocols::shell::commands
