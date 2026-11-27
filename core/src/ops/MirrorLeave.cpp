#include "ops/MirrorLeave.hpp"

#include "audit/Trail.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/model/File.hpp"
#include "mirror/submit/Contents.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "ops/PeerPolicy.hpp"
#include "rbac/permission/admin/Mirror.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>

namespace vh::ops::mirrors {

namespace ops_mirror_leave_detail {

bool leaveDigits(const std::string& s) {
    return !s.empty() && s.size() <= 9 && std::ranges::all_of(s, [](const unsigned char c) { return std::isdigit(c) != 0; });
}

// A sign-in account of this server: never a remote account (another server's person), never a deactivated one.
std::shared_ptr<identities::User> ownerOf(const Actor& actor, const std::optional<std::string>& ref) {
    std::shared_ptr<identities::User> user;
    if (!ref || ref->empty()) user = actor;
    else if (leaveDigits(*ref)) user = vh::identities::manager().user(static_cast<uint32_t>(std::strtoul(ref->c_str(), nullptr, 10)));
    else user = vh::identities::manager().userByName(*ref);
    if (!user) throw NotFound("no account '" + ref.value_or("") + "' on this server");
    if (user->remote()) throw Invalid("the new owner must be a sign-in account of this server, not another server's person");
    if (!user->isActive()) throw Invalid("account '" + user->name() + "' is deactivated: choose an active account");
    return user;
}

}

bool mayDetach(const Actor& actor) {
    try {
        requireDetacher(actor, "detach mirrored vaults");
        return true;
    } catch (const Error&) {
        return false;
    }
}

void requireDetacher(const Actor& actor, const std::string& what) {
    peer_policy::requirePerson(actor, what);
    if (actor->isSuperAdmin() || actor->mirrorPerms().canDetach()) return;
    throw Denied("only super admins of this server, or people its admin roles let detach mirrored vaults "
                 "(admin.mirror.detach), may " + what);
}

vh::mirror::leave::Preview detachPreview(const Actor& actor, const uint32_t vaultId) {
    requireDetacher(actor, "see what detaching a mirrored vault would give");
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    return vh::mirror::leave::preview(vaultId);
}

vh::mirror::leave::Detached detach(const Actor& actor, const DetachRequest& request) {
    using namespace ops_mirror_leave_detail;
    requireDetacher(actor, "detach a mirrored vault");
    if (request.vault_id == 0) throw Invalid("vault ID must be a positive integer");
    const auto vault = vh::db::query::vault::Vault::getVault(request.vault_id);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(request.vault_id));
    if (request.confirm_name && *request.confirm_name != vault->name)
        throw Invalid("type the vault's name exactly to detach it");
    const auto owner = ownerOf(actor, request.owner);
    return vh::mirror::leave::detach(request.vault_id, owner->id, actor->id, actor->name());
}

// ---- detach a copy ------------------------------------------------------------------------------------------------

vh::mirror::copy::Job detachCopy(const Actor& actor, const CopyRequest& request) {
    using namespace ops_mirror_leave_detail;
    requireDetacher(actor, "copy a mirrored vault into a new vault");
    if (request.vault_id == 0) throw Invalid("vault ID must be a positive integer");
    if (!vh::db::query::vault::Vault::getVault(request.vault_id))
        throw NotFound("no vault with ID " + std::to_string(request.vault_id));
    const auto owner = ownerOf(actor, request.owner);
    return vh::mirror::copy::start({.source_vault_id = request.vault_id, .name = request.name, .owner_id = owner->id},
                                   actor->id, actor->name());
}

std::optional<vh::mirror::copy::Job> copyStatus(const Actor& actor, const uint32_t vaultId) {
    requireDetacher(actor, "see a copy of a mirrored vault");
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    return vh::mirror::copy::latest(vaultId);
}

vh::mirror::copy::Job cancelCopy(const Actor& actor, const uint32_t vaultId) {
    requireDetacher(actor, "cancel a copy of a mirrored vault");
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    return vh::mirror::copy::cancel(vaultId, actor->id, actor->name());
}

// ---- versions on the mirror -----------------------------------------------------------------------------------------

vh::mirror::versions::Setting setVersions(const Actor& actor, const VersionsRequest& request) {
    peer_policy::requirePerson(actor, "decide which versions this server keeps of a mirrored vault");
    if (!actor->isSuperAdmin()) throw Denied("only super admins of this server may decide which versions it keeps");
    if (request.vault_id == 0) throw Invalid("vault ID must be a positive integer");
    const auto row = vh::db::query::mirror::MirrorVaults::get(request.vault_id);
    if (!row || row->role != "mirror")
        throw Refused("mirror_not_held", "vault " + std::to_string(request.vault_id) +
                                             " is not held here as another server's mirror: its versions are its own "
                                             "(vh recovery)");
    const auto before = vh::mirror::versions::get(request.vault_id);
    const auto after = vh::mirror::versions::set(request.vault_id,
                                                 {.enabled = request.enabled, .keep_last = request.keep_last,
                                                  .max_age_days = request.max_age_days,
                                                  .quota_bytes = request.quota_bytes},
                                                 actor->id);
    audit::record({.action = "mirror.versions.set", .actor_id = actor->id, .actor = actor->name(),
                   .vault_id = request.vault_id,
                   .details = {{"enabled", after.policy.enabled}, {"was", before.policy.enabled},
                               {"keep_last", after.policy.keep_last ? nlohmann::json(*after.policy.keep_last) : nlohmann::json(nullptr)},
                               {"max_age_days", after.policy.max_age_days ? nlohmann::json(*after.policy.max_age_days)
                                                                          : nlohmann::json(nullptr)},
                               {"quota_bytes", after.policy.quota_bytes ? nlohmann::json(*after.policy.quota_bytes)
                                                                        : nlohmann::json(nullptr)}}},
                  fmt::format("[mirror] {} turned {} keeping versions of what the core replaces or deletes in vault {}",
                              actor->name(), after.policy.enabled ? "on" : "off", request.vault_id));
    return after;
}

nlohmann::json toJson(const vh::mirror::versions::Setting& s) {
    const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
    return {{"enabled", s.policy.enabled}, {"keep_last", opt(s.policy.keep_last)},
            {"max_age_days", opt(s.policy.max_age_days)}, {"quota_bytes", opt(s.policy.quota_bytes)},
            {"set_by", opt(s.set_by)},
            {"set_at", s.set_at ? nlohmann::json(static_cast<int64_t>(*s.set_at)) : nlohmann::json(nullptr)}};
}

// ---- a held change's bytes ---------------------------------------------------------------------------------------------

HeldContent heldContent(const Actor& actor, const uint64_t id) {
    peer_policy::requirePerson(actor, "read a held change");
    if (!actor->isSuperAdmin()) throw Denied("only super admins of this server may read held changes");
    const auto h = vh::db::query::mirror::Pending::heldChange(id);
    if (!h) throw NotFound("no held change " + std::to_string(id));
    if (h->op != "write" || h->state == "discarded")
        throw Invalid("held change " + std::to_string(id) + " holds no file version (" + h->op + ", " + h->state + ")");
    const auto blob = vh::mirror::submit::contents::heldBlob(h->vault_id, id);
    std::error_code ec;
    if (h->args.value("size", uint64_t{0}) > 0 && !std::filesystem::is_regular_file(blob, ec))
        throw NotFound("the bytes of held change " + std::to_string(id) + " are not on this server");
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(h->vault_id) : nullptr;
    if (!engine) throw NotFound("vault " + std::to_string(h->vault_id) + " is not loaded");
    // The person's sealed bytes, read as the file they would have been (the vault's key, that generation); never a
    // vault entry, so nothing about the vault is asked or changed.
    auto f = std::make_shared<vh::fs::model::File>();
    f->vault_id = static_cast<int32_t>(h->vault_id);
    f->backing_path = blob;
    f->path = h->path.value_or("/" + h->args.value("name", std::string("held")));
    f->encryption_iv = h->args.value("generation", std::string{});
    f->encrypted_with_key_version = h->args.value("key_version", 0u);
    f->size_bytes = h->args.value("size", uint64_t{0});
    HeldContent out{.held = *h, .name = h->args.value("name", std::string("held-" + std::to_string(id))),
                    .size = f->size_bytes, .reader = engine->openPlaintextReader(f)};
    log::Registry::audit()->info("[mirror] {} read held change {} of vault {} ({} bytes)", actor->name(), id, h->vault_id,
                                 out.size);
    return out;
}

}
