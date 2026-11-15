#include "protocols/shell/commands/all.hpp"

#include "identities/User.hpp"
#include "ops/Cloud.hpp"
#include "ops/CloudKeys.hpp"
#include "ops/CloudRecovery.hpp"
#include "ops/CloudStorage.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "vault/model/Vault.hpp"
#include "ops/Error.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <thread>

// `vh cloud ...`: parsing and rendering only. Who may do what, and what it changes, is ops::cloud.
namespace vh::protocols::shell::commands {

// Named, not anonymous: the unity build joins this file with the other command files of this namespace.
namespace cloud_cli {
namespace {

namespace cloud = ::vh::ops::cloud;

std::string jsonText(const nlohmann::json& j) {
    auto out = j.dump(4);
    out.push_back('\n');
    return out;
}

std::string utc(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

cloud::Channel channel() { return AgentCallScope::active() ? cloud::Channel::Agent : cloud::Channel::Cli; }

nlohmann::json claimJson(const cloud::Claim& c) {
    const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
    return {{"status", c.status},
            {"installation_id", opt(c.installation_id)},
            {"account_id", opt(c.account_id)},
            {"deployment_id", opt(c.deployment_id)},
            {"account_public_id", opt(c.account_public_id)}};
}

namespace keys = ::vh::ops::cloud_keys;

keys::Channel keyChannel() { return AgentCallScope::active() ? keys::Channel::Agent : keys::Channel::Cli; }

std::string generationText(const keys::Generation& g) {
    std::string out = fmt::format("generation {}  {}  ({}", g.generation, g.fingerprint, g.state);
    if (g.link != "initial") out += ", " + g.link;
    if (g.reason == "compromise") out += ", compromise";
    if (g.confirmed_by) out += ", confirmed by " + *g.confirmed_by;
    return out + ")";
}

std::string keyStatusText(const keys::Status& s) {
    if (s.state == "unlinked") return "This server isn't linked to Vaulthalla Cloud; there is no account recovery key.\n";
    std::string out = fmt::format("Account       {}\nState         {}\n", s.account_public_id.value_or("?"), s.state);
    if (s.pinned) out += "Pinned        " + generationText(*s.pinned) + "\n";
    if (s.waiting) out += "Waiting       " + generationText(*s.waiting) + "\n";
    if (s.policy)
        out += fmt::format("Policy        sequence {} (generation {}), {} recipient(s)\n", s.policy->sequence,
                           s.policy->generation, s.policy->recipients.size());
    out += "Offline copy  " + s.offline_copy + "\n";
    for (const auto& v : s.vaults)
        out += fmt::format("Vault {} {}: account key {}, {} policy recipient(s), policy applied {}\n", v.vault_id,
                           v.vault_name,
                           v.account_key_generation ? "generation " + std::to_string(*v.account_key_generation) : "no",
                           v.policy_grants, v.applied_sequence ? std::to_string(*v.applied_sequence) : "never");
    if (s.checked_at)
        out += fmt::format("Last check    {} ({}{})\n", utc(*s.checked_at), s.check.value_or("?"),
                           s.check_detail ? ": " + *s.check_detail : "");
    if (s.next_step) out += "Next          " + *s.next_step + "\n";
    return out;
}

// After `Linked`: show the account recovery key's fingerprint and ask the super admin to compare and confirm it
// (design/cloud/key-manager.md, "Pin"). Anything else leaves it pending for `vh cloud key confirm`.
std::string confirmAfterLink(const CommandCall& call) {
    keys::Status s;
    try {
        s = keys::status(call.user);
    } catch (const ops::Error& e) {
        return std::string("The account recovery key couldn't be read: ") + e.what() + "\n";
    }
    if (!s.waiting || s.waiting->state != "pending") {
        if (s.state == "pinned") return "The account recovery key is already pinned: " + generationText(*s.pinned) + "\n";
        return "No account recovery key was fetched yet (" + s.check.value_or("not checked") +
               "); `vh cloud key refresh`, then `vh cloud key confirm <fingerprint>`.\n";
    }
    auto& io = *call.io;
    io.print(fmt::format("\nYour account's recovery key fingerprint:\n\n    {}\n\nCompare it with the one Vaulthalla "
                         "Desktop (Cloud) or your account page on vaulthalla.cloud shows.\n",
                         s.waiting->fingerprint));
    const auto answer = io.prompt("Type the fingerprint, or yes if they match (anything else keeps it pending): ", "");
    if (answer.empty() || answer == "no" || answer == "n")
        return "Left pending: confirm it later with `vh cloud key confirm <fingerprint>`.\n";
    const auto given = (answer == "yes" || answer == "y") ? s.waiting->fingerprint : answer;
    try {
        const auto c = keys::confirm(call.user, given, keyChannel());
        return "Pinned: " + generationText(c.generation) + "\n";
    } catch (const ops::Error& e) {
        return std::string("Not pinned: ") + e.what() + "\n";
    }
}

std::string claimText(const cloud::Claim& c) {
    if (c.status == "linked")
        return fmt::format("Linked: this server is installation {} of Vaulthalla Cloud account {}.\n",
                           c.installation_id.value_or("?"), c.account_id.value_or(0));
    if (c.status == "denied") return "The link request was denied on vaulthalla.cloud; nothing was linked.\n";
    if (c.status == "expired") return "The link request expired; run `vh cloud link` again.\n";
    return "Still waiting for approval on vaulthalla.cloud (`vh cloud link --finish` checks again).\n";
}

// Polls the pending request until it is decided, the request expires or the caller goes away.
CommandResult waitForApproval(const CommandCall& call) {
    auto& io = *call.io;
    io.print("Waiting for approval... (Ctrl-C to stop; `vh cloud link --finish` picks it up again)\n");
    for (;;) {
        if (!io.peerConnected()) return invalid("cloud link: stopped; the request stays open until it expires");
        cloud::Claim c;
        try {
            c = cloud::claimLink(call.user, channel());
        } catch (const ops::Error& e) {
            return invalid(std::string("cloud link: ") + e.what());
        }
        if (c.status == "linked") return ok(claimText(c) + confirmAfterLink(call));
        if (c.status != "pending") return invalid("cloud link: " + claimText(c));
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

CommandResult handleLink(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "link"}));
    const bool json = hasFlag(call, "json");
    if (hasFlag(call, "finish")) {
        if (json || !call.io)
            return runOp("cloud link", [&] { return cloud::claimLink(call.user, channel()); },
                         [&](const cloud::Claim& c) { return json ? jsonText(claimJson(c)) : claimText(c); });
        return waitForApproval(call);
    }
    cloud::LinkStarted started;
    try {
        started = cloud::startLink(call.user, channel(), optVal(call, "name"));
    } catch (const ops::Error& e) {
        return invalid(std::string("cloud link: ") + e.what());
    }
    if (json)
        return ok(jsonText({{"user_code", started.user_code}, {"fingerprint", started.fingerprint},
                            {"name", started.name}, {"endpoint", started.endpoint}, {"expires_at", started.expires_at}}));
    const auto text = fmt::format(
        "To link \"{}\" to your Vaulthalla Cloud account ({}):\n"
        "  1. Sign in on vaulthalla.cloud and choose Link a server.\n"
        "  2. Enter the code   {}\n"
        "  3. Check that it shows this key fingerprint   {}\n"
        "     then approve it. The code expires at {}.\n",
        started.name, started.endpoint, started.user_code, started.fingerprint, utc(started.expires_at));
    if (!call.io) return ok(text + "Then run `vh cloud link --finish`.\n");
    call.io->print(text);
    return waitForApproval(call);
}

CommandResult handleStatus(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "status"}));
    const bool json = hasFlag(call, "json");
    return runOp("cloud status", [&] { return cloud::status(call.user); }, [&](const cloud::Status& s) {
        const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
        if (json)
            return jsonText({{"state", s.state}, {"endpoint", s.endpoint}, {"name", opt(s.name)},
                             {"fingerprint", opt(s.fingerprint)}, {"installation_id", opt(s.installation_id)},
                             {"account_id", opt(s.account_id)}, {"deployment_id", opt(s.deployment_id)},
                             {"account_public_id", opt(s.account_public_id)}, {"linked_at", opt(s.linked_at)},
                             {"request_expires_at", opt(s.request_expires_at)}, {"requested_by", opt(s.requested_by)},
                             {"cloud", opt(s.cloud)}, {"cloud_detail", opt(s.cloud_detail)}});
        if (s.state == "unlinked")
            return fmt::format("Not linked to Vaulthalla Cloud ({}). `vh cloud link` links it; it is never required.\n",
                               s.endpoint);
        std::string out = fmt::format("Name          {}\nEndpoint      {}\nKey           {}\n", s.name.value_or("?"),
                                      s.endpoint, s.fingerprint.value_or("?"));
        if (s.state == "pending")
            return out + fmt::format("State         waiting for approval on vaulthalla.cloud (requested by {}, "
                                     "until {})\n",
                                     s.requested_by.value_or("?"), s.request_expires_at ? utc(*s.request_expires_at) : "?");
        out += fmt::format("State         linked since {}\nInstallation  {}\nDeployment    {}\nAccount       {}\n",
                           s.linked_at ? utc(*s.linked_at) : "?", s.installation_id.value_or("?"),
                           s.deployment_id.value_or("?"),
                           s.account_public_id.value_or(std::to_string(s.account_id.value_or(0))));
        out += "Cloud         " + s.cloud.value_or("?") + (s.cloud_detail ? " (" + *s.cloud_detail + ")" : "") + "\n";
        return out;
    });
}

CommandResult handleUnlink(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "unlink"}));
    return runOp("cloud unlink", [&] { return cloud::unlink(call.user, channel(), hasFlag(call, "force")); },
                 [](const cloud::Unlinked& u) {
        if (u.was == "unlinked") return std::string("This server wasn't linked to Vaulthalla Cloud.\n");
        if (u.was == "pending") return std::string("The pending link request was discarded.\n");
        return std::string(u.cloud_revoked ? "Unlinked: Vaulthalla Cloud revoked this server, and its identity key is "
                                             "gone.\n"
                                           : "Forgotten here. Vaulthalla Cloud didn't confirm it: revoke this server "
                                             "on vaulthalla.cloud.\n");
    });
}

namespace recovery = ::vh::ops::cloud_recovery;

recovery::Channel keysChannel() { return AgentCallScope::active() ? recovery::Channel::Agent : recovery::Channel::Cli; }

std::string versionList(const std::vector<unsigned int>& versions) {
    std::string out;
    for (const auto v : versions) out += (out.empty() ? "" : ", ") + std::to_string(v);
    return out;
}

// The vault a recovery subcommand names (by ID, or by name with --owner).
std::optional<unsigned int> recoveryVault(const CommandCall& call, const std::string& arg, const std::string& leaf,
                                          std::string& error) {
    const auto lookup = ::vh::protocols::shell::commands::vault::resolveVault(call, arg, resolveUsage({"cloud", "recovery", leaf}), "cloud recovery " + leaf);
    if (!lookup || !lookup.ptr) {
        error = lookup.error;
        return std::nullopt;
    }
    return lookup.ptr->id;
}

CommandResult handleRecoveryEnroll(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "recovery", "enroll"}));
    std::string error;
    const auto vaultId = recoveryVault(call, call.positionals.at(0), "enroll", error);
    if (!vaultId) return invalid(error);
    const bool accountKey = hasFlag(call, "account-key");
    return runOp("cloud recovery enroll",
                 [&] { return recovery::enroll(call.user, *vaultId, keysChannel(), accountKey); },
                 [](const recovery::Enrolled& e) {
        std::string out = fmt::format("{} vault {} ({}) in Vaulthalla Cloud recovery: {} envelope(s) sent, {} new; no "
                                      "keys left this server.\n",
                                      e.created ? "Enrolled" : "Updated", e.vault_id, e.vault_uid, e.envelopes_sent,
                                      e.envelopes_added);
        if (e.coverage.is_object() && e.coverage.contains("ready"))
            out += e.coverage["ready"].get<bool>() ? "The cloud covers every key version it knows of.\n"
                                                   : "The cloud reports versions it can't cover yet (`vh cloud recovery "
                                                     "status`).\n";
        return out;
    });
}

CommandResult handleRecoveryStatus(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "recovery", "status"}));
    const bool json = hasFlag(call, "json");
    std::optional<unsigned int> vaultId;
    if (const auto arg = optVal(call, "vault")) {
        std::string error;
        vaultId = recoveryVault(call, *arg, "status", error);
        if (!vaultId) return invalid(error);
    }
    const bool verify = hasFlag(call, "verify");
    return runOp("cloud recovery status", [&] { return recovery::status(call.user, vaultId, verify); },
                 [&](const std::vector<recovery::VaultCoverage>& list) {
        if (json) {
            auto vaults = nlohmann::json::array();
            for (const auto& c : list)
                vaults.push_back({{"vault_id", c.vault_id}, {"vault_name", c.vault_name}, {"vault_uid", c.vault_uid},
                                  {"state", c.state}, {"not_in_cloud", c.not_in_cloud}, {"enrolled_at", c.enrolled_at},
                                  {"last_upload_at", c.last_upload_at}, {"cloud", c.cloud},
                                  {"automatic", c.automatic}, {"verify", c.verify},
                                  {"detail", c.detail ? nlohmann::json(*c.detail) : nlohmann::json(nullptr)}});
            return jsonText({{"vaults", vaults}});
        }
        if (list.empty()) return std::string("No vault of this server is enrolled in cloud recovery.\n");
        std::string out;
        for (const auto& c : list) {
            out += fmt::format("Vault {} {} ({}): {}", c.vault_id, c.vault_name, c.vault_uid, c.state);
            if (!c.not_in_cloud.empty()) out += "; not in the cloud: version(s) " + versionList(c.not_in_cloud);
            if (c.detail) out += " (" + *c.detail + ")";
            if (c.automatic) out += "; automatic (managed storage)";
            if (c.verify.is_object()) {
                if (c.verify.contains("error")) out += "; verify failed: " + c.verify["error"].get<std::string>();
                else
                    out += fmt::format("; verified {} version(s) in the cloud, {} missing, {} mismatched",
                                       c.verify.value("versions_checked", 0), c.verify["missing"].size(),
                                       c.verify["mismatched"].size());
            }
            out += fmt::format("; enrolled {}, last sent {}\n", utc(c.enrolled_at), utc(c.last_upload_at));
        }
        return out;
    });
}

CommandResult handleRecoveryUnenroll(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "recovery", "unenroll"}));
    std::string error;
    const auto vaultId = recoveryVault(call, call.positionals.at(0), "unenroll", error);
    if (!vaultId) return invalid(error);
    return runOp("cloud recovery unenroll", [&] { recovery::unenroll(call.user, *vaultId, keysChannel()); },
                 [&] { return fmt::format("Vault {} is no longer in cloud recovery; the cloud's records were deleted. "
                                          "Your recovery kit or export still recovers it.\n", *vaultId); });
}

CommandResult handleRecovery(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"cloud", "recovery", name}, sub); };
    if (is("enroll")) return handleRecoveryEnroll(subcall);
    if (is("status")) return handleRecoveryStatus(subcall);
    if (is("unenroll")) return handleRecoveryUnenroll(subcall);
    return invalid(call.constructFullArgs(), "Unknown cloud recovery subcommand: '" + std::string(sub) + "'");
}

CommandResult handleKeyStatus(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "key", "status"}));
    const bool json = hasFlag(call, "json");
    return runOp("cloud key status", [&] { return keys::status(call.user); }, [&](const keys::Status& s) {
        return json ? jsonText(keys::toJson(s)) : keyStatusText(s);
    });
}

CommandResult handleKeyConfirm(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "key", "confirm"}));
    const bool json = hasFlag(call, "json");
    return runOp("cloud key confirm", [&] { return keys::confirm(call.user, call.positionals.at(0), keyChannel()); },
                 [&](const keys::Confirmed& c) {
        if (json) return jsonText(keys::toJson(c));
        std::string out = "Pinned: " + generationText(c.generation) + "\n";
        if (c.replacement) out += "It replaces the earlier pin; vault grants of the old key move to it.\n";
        return out;
    });
}

CommandResult handleKeyRefresh(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "key", "refresh"}));
    const bool json = hasFlag(call, "json");
    return runOp("cloud key refresh", [&] { return keys::refresh(call.user, keyChannel()); }, [&](const keys::Status& s) {
        return json ? jsonText(keys::toJson(s)) : keyStatusText(s);
    });
}

CommandResult handleKeyForget(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"cloud", "key", "forget"}));
    return runOp("cloud key forget", [&] { return keys::forget(call.user, keyChannel()); }, [](const keys::Forgotten& f) {
        return fmt::format("Forgot the account recovery key pin ({} generation(s)); linking again asks for a "
                           "confirmation.\n", f.generations);
    });
}

CommandResult handleKey(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"cloud", "key", name}, sub); };
    if (is("status")) return handleKeyStatus(subcall);
    if (is("confirm")) return handleKeyConfirm(subcall);
    if (is("refresh")) return handleKeyRefresh(subcall);
    if (is("forget")) return handleKeyForget(subcall);
    return invalid(call.constructFullArgs(), "Unknown cloud key subcommand: '" + std::string(sub) + "'");
}

namespace storage = ::vh::ops::cloud_storage;

storage::Channel storageChannel() {
    return AgentCallScope::active() ? storage::Channel::Agent : storage::Channel::Cli;
}

std::string bytesText(const uint64_t b) {
    constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = static_cast<double>(b);
    int u = 0;
    while (v >= 1000.0 && u < 5) {
        v /= 1000.0;
        ++u;
    }
    return u == 0 ? fmt::format("{} B", b) : fmt::format("{:.1f} {}", v, units[u]);
}

std::string storageVaultLine(const storage::VaultEntry& v) {
    std::string out = fmt::format("  {:>4}  {:<24} {:<10} {}", v.vault_id, v.vault_name, bytesText(v.local_bytes), v.summary);
    if (v.retention_pending) out += "; retention pending";
    if (v.recovery == std::optional<std::string>("behind")) out += "; recovery enrollment behind";
    if (v.progress.is_object() && v.progress.contains("bytes_total") && v.progress["bytes_total"].get<uint64_t>() > 0)
        out += fmt::format(" ({}%)", v.progress["bytes_done"].get<uint64_t>() * 100 / v.progress["bytes_total"].get<uint64_t>());
    if (v.lost.is_object() && v.lost.contains("files") && !v.lost["files"].empty())
        out += fmt::format("; {} file(s) held only in the bucket were lost", v.lost["files"].size());
    return out + "\n";
}

std::string storageStatusText(const storage::Status& s) {
    std::string out;
    if (!s.linked) return "This server isn't linked to an account; managed storage needs a link (`vh cloud link`).\n";
    out += fmt::format("Account key   {}\n", s.account_key);
    out += fmt::format("Plan          {}{}\n", s.entitlement.value_or("none"),
                       s.plan && !s.plan->empty() ? " (" + *s.plan + ")" : "");
    if (s.storage_access) out += "Access        " + *s.storage_access + (s.cause ? " (" + *s.cause + ")" : "") + "\n";
    if (s.quota_bytes)
        out += fmt::format("Usage         {} of {}{} (the account's figure); {} held here in managed vaults\n",
                           s.used_bytes ? bytesText(*s.used_bytes) : "?", bytesText(*s.quota_bytes),
                           s.usage_day ? " as of " + *s.usage_day : "", bytesText(s.managed_local_bytes));
    out += std::string("New vaults    ") + (s.new_vaults ? "managed by default" : "local by default") + "\n";
    if (s.ended)
        out += fmt::format("Plan ended    since {}; {}\n", utc(s.ended->since),
                           s.ended->confirmed_by ? "confirmed by " + *s.ended->confirmed_by
                                                 : "vaults become local at " + utc(s.ended->converts_at) +
                                                       " unless confirmed sooner (`vh cloud storage confirm-ended`)");
    if (s.fetched_at) out += "Last checked  " + utc(*s.fetched_at) + (s.fetch_error ? " (" + *s.fetch_error + ")" : "") + "\n";
    if (!s.offered.empty()) {
        out += fmt::format("\n{} vault(s) existed before managed storage was available and wait for a decision (`vh cloud "
                           "storage accept --all|--vaults <ids>` or `decline`):\n", s.offered.size());
        for (const auto& v : s.offered) out += storageVaultLine(v);
    }
    out += "\nVaults:\n";
    for (const auto& v : s.vaults)
        if (v.switch_state != std::optional<std::string>("offered")) out += storageVaultLine(v);
    if (s.next_step) out += "\nNext: " + *s.next_step + "\n";
    return out;
}

std::optional<unsigned int> storageVault(const CommandCall& call, const std::string& leaf, std::string& error) {
    const auto lookup = ::vh::protocols::shell::commands::vault::resolveVault(
        call, call.positionals.at(0), resolveUsage({"cloud", "storage", leaf}), "cloud storage " + leaf);
    if (!lookup || !lookup.ptr) {
        error = lookup.error;
        return std::nullopt;
    }
    return lookup.ptr->id;
}

CommandResult handleStorage(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"cloud", "storage", name}, sub); };
    const auto entryText = [](const storage::VaultEntry& v) { return storageVaultLine(v); };
    if (is("status")) {
        validatePositionals(subcall, resolveUsage({"cloud", "storage", "status"}));
        const bool json = hasFlag(subcall, "json");
        return runOp("cloud storage status", [&] { return storage::status(subcall.user); },
                     [&](const storage::Status& s) { return json ? jsonText(storage::toJson(s)) : storageStatusText(s); });
    }
    if (is("enable") || is("disable") || is("rotate")) {
        const std::string leaf = is("enable") ? "enable" : is("disable") ? "disable" : "rotate";
        validatePositionals(subcall, resolveUsage({"cloud", "storage", leaf}));
        std::string error;
        const auto vaultId = storageVault(subcall, leaf, error);
        if (!vaultId) return invalid(error);
        if (leaf == "rotate")
            return runOp("cloud storage rotate", [&] { return storage::rotate(subcall.user, *vaultId, storageChannel()); },
                         entryText);
        const auto confirm = optVal(subcall, "confirm");
        return runOp("cloud storage " + leaf,
                     [&] { return storage::setSwitch(subcall.user, *vaultId, leaf == "enable", confirm, storageChannel()); },
                     entryText);
    }
    if (is("accept") || is("decline")) {
        const bool accept = is("accept");
        validatePositionals(subcall, resolveUsage({"cloud", "storage", accept ? "accept" : "decline"}));
        std::optional<std::vector<unsigned int>> vaults;
        if (const auto list = optVal(subcall, "vaults")) {
            vaults.emplace();
            std::size_t pos = 0;
            while (pos <= list->size()) {
                const auto end = std::min(list->find(',', pos), list->size());
                const auto part = list->substr(pos, end - pos);
                try {
                    if (!part.empty()) vaults->push_back(static_cast<unsigned int>(std::stoul(part)));
                } catch (const std::exception&) {
                    return invalid("--vaults takes vault IDs, comma-separated");
                }
                pos = end + 1;
            }
        } else if (accept && !hasFlag(subcall, "all")) {
            return invalid("name the vaults (--vaults 3,7) or accept every offered vault (--all)");
        }
        return runOp(accept ? "cloud storage accept" : "cloud storage decline",
                     [&] {
                         return accept ? storage::acceptOffer(subcall.user, vaults, storageChannel())
                                       : storage::declineOffer(subcall.user, vaults, storageChannel());
                     },
                     [&](const storage::OfferResult& r) {
                         return fmt::format("{} {} vault(s){}.\n", accept ? "Accepted" : "Declined", r.vaults.size(),
                                            r.offer_open ? "; others are still offered" : "");
                     });
    }
    if (is("new-vaults")) {
        validatePositionals(subcall, resolveUsage({"cloud", "storage", "new-vaults"}));
        const auto& v = subcall.positionals.at(0);
        if (v != "on" && v != "off") return invalid("new-vaults takes on or off");
        return runOp("cloud storage new-vaults",
                     [&] { return storage::setNewVaultsDefault(subcall.user, v == "on", storageChannel()); },
                     [](const bool on) {
                         return std::string(on ? "New vaults use managed storage by default.\n"
                                               : "New vaults stay local unless switched on.\n");
                     });
    }
    if (is("confirm-ended")) {
        validatePositionals(subcall, resolveUsage({"cloud", "storage", "confirm-ended"}));
        return runOp("cloud storage confirm-ended", [&] { return storage::confirmEnded(subcall.user, storageChannel()); },
                     [](const storage::EndedConfirmation& e) {
                         return fmt::format("Confirmed: {} managed vault(s) become local in place on the next pass.\n",
                                            e.vaults);
                     });
    }
    if (is("billing")) {
        validatePositionals(subcall, resolveUsage({"cloud", "storage", "billing"}));
        const auto kind = optVal(subcall, "kind").value_or("portal");
        const auto plan = optVal(subcall, "plan");
        return runOp("cloud storage billing",
                     [&] { return storage::billingHandoff(subcall.user, kind, plan, storageChannel()); },
                     [](const storage::Handoff& h) { return "Open this address in a browser:\n" + h.url + "\n"; });
    }
    return invalid(call.constructFullArgs(), "Unknown cloud storage subcommand: '" + std::string(sub) + "'");
}

CommandResult handleCloud(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"cloud", name}, sub); };
    if (is("link")) return handleLink(subcall);
    if (is("status")) return handleStatus(subcall);
    if (is("unlink")) return handleUnlink(subcall);
    if (is("recovery")) return handleRecovery(subcall);
    if (is("key")) return handleKey(subcall);
    if (is("storage")) return handleStorage(subcall);
    return invalid(call.constructFullArgs(), "Unknown cloud subcommand: '" + std::string(sub) + "'");
}

}
}

void registerCloudCommands(const std::shared_ptr<Router>& r) {
    r->registerCommand(runtime::Deps::get().shellUsageManager->resolve("cloud"), cloud_cli::handleCloud);
}

}
