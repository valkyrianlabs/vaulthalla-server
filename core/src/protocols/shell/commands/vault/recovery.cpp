// `vh vault recovery status|set|suspend|disclosure`: the CLI adapter for the policy half of ops::recovery. Same
// authorization and behaviour as the ws vault.recovery.* commands. Turning provider versioning on always fetches and
// prints the cost disclosure first; its token is what ops::recovery::update requires, so no caller can skip it.
// (`vh vault restore` is something else: it undeletes a vault.)

#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/commands/recovery.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"
#include "CommandUsage.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::protocols::shell::commands::vault {

namespace {

namespace vrrec = vh::ops::recovery;
namespace vrcli = vh::protocols::shell::commands::recovery_cli;

constexpr const char* kVrEnableWord = "ENABLE VERSIONING";
constexpr const char* kVrUnpricedWord = "ACCEPT UNPRICED";
constexpr const char* kVrShortenWord = "SHORTEN";
constexpr const char* kVrAdoptWord = "ADOPT";

bool vrHas(const std::vector<std::string>& v, const char* code) { return std::ranges::find(v, code) != v.end(); }

// A refusal the person can fix by re-running; carries the text to show.
struct VrRefusal {
    std::string text;
};

// One acknowledgement: already given by `flag` (or --yes for the enable itself), typed at the terminal, or refused
// naming the flag that gives it non-interactively.
void vrAcknowledge(const CommandCall& call, bool& accepted, const std::string& why, const char* word,
                   const std::string& flagHint) {
    if (accepted) return;
    if (!call.io) throw VrRefusal{why + "\nRe-run with " + flagHint + "."};
    if (call.io->prompt(why + "\nType " + word + " to continue", "no") != word)
        throw VrRefusal{"not confirmed; nothing was changed"};
    accepted = true;
}

// Fetches and shows the disclosure, collects every acknowledgement it asks for, and puts its token on the request.
// Returns the disclosure text when it was not shown at a terminal (so the output still carries it).
std::string vrDisclose(const CommandCall& call, const uint32_t vaultId, vrrec::Update& req, const bool json) {
    const auto disclosure = vrrec::versioningDisclosure(call.user, vaultId, req.provider_retention);
    const auto text = vrcli::formatDisclosure(disclosure);
    const bool interactive = call.io != nullptr;
    if (interactive) call.io->print(text);

    try {
        bool enable = hasFlag(call, "yes");
        if (!enable && !interactive)
            throw VrRefusal{"Turning on provider versioning needs your acknowledgement of the disclosure above. "
                                   "Re-run in a terminal, or with --yes" +
                            std::string(disclosure.report.priced ? "" : " --accept-unpriced") + "."};
        vrAcknowledge(call, enable, "Provider versioning keeps every overwritten and deleted version in the bucket and "
                                    "bills for it until retention removes it.", kVrEnableWord, "--yes");

        const bool unpriced = !disclosure.report.priced || vrHas(disclosure.required_acknowledgements, vrrec::VERSIONING_UNPRICED);
        if (unpriced)
            vrAcknowledge(call, req.accept_unpriced,
                          "The recurring cost of versioning this bucket cannot be estimated" +
                              (disclosure.report.unpriced_reason ? " (" + *disclosure.report.unpriced_reason + ")"
                                                                 : std::string()) +
                              ". Charges still apply.",
                          kVrUnpricedWord, "--accept-unpriced");
        if (vrHas(disclosure.required_acknowledgements, vrrec::RETENTION_SHORTEN))
            vrAcknowledge(call, req.accept_retention_shortening,
                          "The new retention is shorter: the provider deletes old versions sooner.", kVrShortenWord,
                          "--accept-retention-shortening");
        if (vrHas(disclosure.required_acknowledgements, vrrec::BUCKET_ADOPTION))
            vrAcknowledge(call, req.accept_adoption, "The vault's bucket is not managed by Vaulthalla yet and will be adopted.",
                          kVrAdoptWord, "--adopt-bucket");
    } catch (VrRefusal& r) {
        if (!interactive) r.text = text + r.text;
        throw;
    }
    req.disclosure_token = disclosure.token;
    return interactive || json ? std::string() : text;
}

std::optional<uint64_t> vrSize(const CommandCall& call, const std::string& name) {
    const auto v = optVal(call, name);
    if (!v) return std::nullopt;
    try {
        if (v->empty()) throw std::invalid_argument("empty");
        return static_cast<uint64_t>(parseSize(*v));
    } catch (const std::exception&) {
        throw ops::Invalid("--" + name + " must be a size such as 1073741824, 500M or 50G");
    }
}

// --keep-last / --max-age-days: a whole number, 0 = no limit (null).
nlohmann::json vrLimit(const CommandCall& call, const std::string& name, const nlohmann::json& current) {
    const auto v = optVal(call, name);
    if (!v) return current;
    const auto n = parseUInt(*v);
    if (!n) throw ops::Invalid("--" + name + " must be a whole number (0 = no limit)");
    return *n ? nlohmann::json(*n) : nlohmann::json(nullptr);
}

// CLI options → the ws payload shape, read by the same RecoveryJson reader (one validation for both surfaces).
vrrec::Update vrUpdateFromOptions(const CommandCall& call, const uint32_t vaultId) {
    nlohmann::json j = nlohmann::json::object();
    if (const auto mode = optVal(call, "mode")) j["mode"] = *mode;
    if (const auto retention = optVal(call, "retention")) j["provider_retention"] = *retention;
    if (const auto quota = vrSize(call, "snapshot-quota")) j["snapshot_quota_bytes"] = *quota;
    if (const auto alert = optVal(call, "cost-alert"))
        j["cost_alert_monthly"] = *alert == "none" || *alert == "off" ? std::string() : *alert;

    const auto lvFlag = optVal(call, "local-versioning");
    if (lvFlag || optVal(call, "keep-last") || optVal(call, "max-age-days") || optVal(call, "version-quota")) {
        // The policy is replaced as a whole: start from what the vault has, change what was given.
        auto lv = nlohmann::json(vrrec::status(call.user, vaultId).local_versioning);
        if (lvFlag) {
            if (*lvFlag != "on" && *lvFlag != "off") throw ops::Invalid("--local-versioning must be on or off");
            lv["enabled"] = *lvFlag == "on";
        }
        lv["keep_last"] = vrLimit(call, "keep-last", lv["keep_last"]);
        lv["max_age_days"] = vrLimit(call, "max-age-days", lv["max_age_days"]);
        if (const auto q = vrSize(call, "version-quota")) lv["quota_bytes"] = *q ? nlohmann::json(*q) : nlohmann::json(nullptr);
        j["local_versioning"] = lv;
    }
    if (j.empty()) throw ops::Invalid("nothing to change (see 'vh vault recovery set --help')");

    j["accept_unpriced"] = hasFlag(call, "accept-unpriced");
    j["accept_retention_shortening"] = hasFlag(call, "accept-retention-shortening");
    j["accept_adoption"] = hasFlag(call, "adopt-bucket");
    return vrrec::updateFromJson(j);
}

CommandResult vrStatus(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "recovery", "status"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("vault recovery status", [&] {
        return vrrec::status(call.user, vrcli::vaultIdFrom(call, usage, "vault recovery status"), hasFlag(call, "refresh"));
    }, [&](const vh::recovery::Status& s) { return json ? vrcli::jsonText(s) : vrcli::formatStatus(s); });
}

CommandResult vrDisclosure(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "recovery", "disclosure"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    return runOp("vault recovery disclosure", [&] {
        std::optional<vh::recovery::ProviderRetention> retention;
        if (const auto r = optVal(call, "retention")) retention = vrrec::providerRetentionFromJson(nlohmann::json(*r));
        return vrrec::versioningDisclosure(call.user, vrcli::vaultIdFrom(call, usage, "vault recovery disclosure"),
                                           retention);
    }, [&](const vh::recovery::Disclosure& d) { return json ? vrcli::jsonText(d) : vrcli::formatDisclosure(d); });
}

CommandResult vrSuspend(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "recovery", "suspend"});
    validatePositionals(call, usage);
    const std::string prefix = "vault recovery suspend";
    try {
        const auto vaultId = vrcli::vaultIdFrom(call, usage, prefix);
        return vrcli::runConfirmedText(call, prefix, vrrec::VERSIONING_SUSPEND, "SUSPEND", [&](const bool confirmed) {
            return "Versioning suspended; existing versions are kept.\n" +
                   vrcli::formatStatus(vrrec::suspendVersioning(call.user, vaultId, confirmed));
        });
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

CommandResult vrSet(const CommandCall& call) {
    const auto usage = resolveUsage({"vault", "recovery", "set"});
    validatePositionals(call, usage);
    const bool json = hasFlag(call, "json");
    const std::string prefix = "vault recovery set";
    try {
        const auto vaultId = vrcli::vaultIdFrom(call, usage, prefix);
        auto req = vrUpdateFromOptions(call, vaultId);
        std::string disclosureText;
        if (req.mode == vh::recovery::Mode::ProviderVersioning) disclosureText = vrDisclose(call, vaultId, req, json);

        // Whatever the op still asks for (a retention change on an already versioned bucket, adoption, …) is asked
        // here the same way: typed at a terminal, or the flag that gives it.
        for (;;) {
            try {
                const auto status = vrrec::update(call.user, vaultId, req);
                if (json) {
                    auto out = ok(vrcli::jsonText(status));
                    out.stderr_text = disclosureText;
                    return out;
                }
                return ok(disclosureText + vrcli::formatStatus(status));
            } catch (const ops::NeedsConfirmation& e) {
                const std::string why = e.what();
                if (e.code == vrrec::VERSIONING_DISCLOSURE && !req.disclosure_token) {
                    disclosureText = vrDisclose(call, vaultId, req, json);
                } else if (e.code == vrrec::VERSIONING_UNPRICED && !req.accept_unpriced) {
                    vrAcknowledge(call, req.accept_unpriced, why, kVrUnpricedWord, "--accept-unpriced");
                } else if (e.code == vrrec::RETENTION_SHORTEN && !req.accept_retention_shortening) {
                    vrAcknowledge(call, req.accept_retention_shortening, why, kVrShortenWord,
                                  "--accept-retention-shortening");
                } else if (e.code == vrrec::BUCKET_ADOPTION && !req.accept_adoption) {
                    vrAcknowledge(call, req.accept_adoption, why, kVrAdoptWord, "--adopt-bucket");
                } else {
                    throw;
                }
            }
        }
    } catch (const VrRefusal& r) {
        return invalid(prefix + ": " + r.text);
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

}

CommandResult handle_vault_recovery(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"vault", "recovery", "status"}, sub)) return vrStatus(subcall);
    if (isCommandMatch({"vault", "recovery", "set"}, sub)) return vrSet(subcall);
    if (isCommandMatch({"vault", "recovery", "suspend"}, sub)) return vrSuspend(subcall);
    if (isCommandMatch({"vault", "recovery", "disclosure"}, sub)) return vrDisclosure(subcall);
    return invalid(call.constructFullArgs(), "Unknown vault recovery subcommand: '" + std::string(sub) + "'");
}

}
