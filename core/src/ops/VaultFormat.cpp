#include "ops/VaultFormat.hpp"

#include "config/Registry.hpp"
#include "db/query/vault/FormatConversion.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/FormatConversionService.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

namespace vh::ops::vault_format {

namespace {

using ConversionQ = db::query::vault::FormatConversion;

void requireView(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin() || actor->encryptionKeysPerms().canView()) return;
    throw Denied("only super admins or users with the view encryption keys permission can inspect vault formats");
}

std::shared_ptr<storage::Engine> engineFor(const unsigned int vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    return manager ? manager->getEngine(vaultId) : nullptr;
}

FormatStatus statusOf(const ::vh::vault::model::Vault& v) {
    FormatStatus s{.vault_id = v.id, .vault_name = v.name};
    const auto engine = engineFor(v.id);
    const auto em = engine ? engine->encryptionManager : nullptr;
    const auto keyVersion = em ? em->get_key_version() : 0u;
    s.converts_live_files = !engine || ::vh::vault::conversion::convertsLiveFiles(*engine);

    const auto left = ConversionQ::remaining(v.id, keyVersion);
    s.files = {.items = left.files, .bytes = left.file_bytes};
    s.blobs = {.items = left.blobs, .bytes = left.blob_bytes};
    s.files_other_key_versions = left.files_other_versions;
    s.total = s.blobs;
    if (s.converts_live_files) s.total = {.items = s.total.items + s.files.items, .bytes = s.total.bytes + s.files.bytes};

    if (const auto p = ::vh::vault::conversion::progressOf(v.id)) {
        LastPass last{.started_at = p->started_at, .finished_at = p->finished_at};
        if (p->last) {
            const auto& r = *p->last;
            last.files = r.files;
            last.blobs = r.blobs;
            last.cleared = r.cleared;
            last.bytes = r.bytes;
            last.failed = r.failed;
            last.deferred = r.deferred;
            last.conflicts = r.conflicts;
            last.blocked = r.blocked;
            if (!r.failures.empty()) last.first_error = r.failures.front().reason;
        }
        s.last_pass = last;
        if (p->running) s.state = "converting";
    }

    if (s.total.items == 0 && s.files_other_key_versions == 0) {
        // Only the live files of an encrypt-upstream vault are left: the bucket's layout migration converts them.
        s.state = !s.converts_live_files && s.files.items > 0 ? "awaiting_layout_migration" : "converted";
    } else if (!engine || !em) {
        s.state = "not_loaded";
    } else if (em->rotation_in_progress()) {
        s.state = "blocked";
        s.blocked_reason = "a key rotation of the vault is in progress";
    } else if (db::query::vault::Key::runningSalvage(v.id)) {
        s.state = "blocked";
        s.blocked_reason = "a key salvage of the vault is running";
    } else if (!::vh::config::Registry::get().vaults.format_conversion.enabled) {
        s.state = "disabled";
    } else if (s.state.empty()) {
        s.state = "pending";
    }
    return s;
}

nlohmann::json remainingJson(const Remaining& r) { return {{"items", r.items}, {"bytes", r.bytes}}; }

nlohmann::json optTime(const std::optional<std::time_t>& t) { return t ? nlohmann::json(*t) : nlohmann::json(nullptr); }

nlohmann::json optStr(const std::optional<std::string>& s) { return s ? nlohmann::json(*s) : nlohmann::json(nullptr); }

}

std::vector<FormatStatus> status(const Actor& actor, const std::optional<unsigned int> vaultId) {
    requireView(actor);
    std::vector<FormatStatus> out;
    if (vaultId) {
        if (*vaultId == 0) throw Invalid("vault ID must be a positive integer");
        const auto vault = db::query::vault::Vault::getVault(*vaultId);
        if (!vault) throw NotFound("no vault with ID " + std::to_string(*vaultId));
        out.push_back(statusOf(*vault));
        return out;
    }
    for (const auto& vault : db::query::vault::Vault::listLiveVaults())
        if (vault) out.push_back(statusOf(*vault));
    return out;
}

nlohmann::json toJson(const FormatStatus& s) {
    nlohmann::json last = nullptr;
    if (s.last_pass) {
        const auto& p = *s.last_pass;
        last = {{"started_at", optTime(p.started_at)}, {"finished_at", optTime(p.finished_at)},
                {"files", p.files}, {"blobs", p.blobs}, {"cleared", p.cleared}, {"bytes", p.bytes},
                {"failed", p.failed}, {"deferred", p.deferred}, {"conflicts", p.conflicts},
                {"blocked", optStr(p.blocked)}, {"first_error", optStr(p.first_error)}};
    }
    const auto& cfg = ::vh::config::Registry::get().vaults.format_conversion;
    return {{"vault_id", s.vault_id},
            {"vault_name", s.vault_name},
            {"state", s.state},
            {"blocked_reason", optStr(s.blocked_reason)},
            {"remaining", {{"files", remainingJson(s.files)}, {"blobs", remainingJson(s.blobs)},
                           {"total", remainingJson(s.total)}}},
            {"files_other_key_versions", s.files_other_key_versions},
            {"converts_live_files", s.converts_live_files},
            {"limits", {{"enabled", cfg.enabled}, {"max_mib_per_second", cfg.max_mib_per_second},
                        {"max_cpu_percent", cfg.max_cpu_percent}}},
            {"last_pass", last}};
}

}
