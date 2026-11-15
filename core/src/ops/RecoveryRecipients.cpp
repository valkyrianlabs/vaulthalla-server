#include "ops/RecoveryRecipients.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include <vl/keykit/kev1.hpp>
#include "crypto/util/encrypt.hpp"
#include "db/query/cloud/Storage.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/CloudKeys.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <map>

namespace vh::ops::recovery_recipients {

namespace recipients_detail {

using Grants = db::query::vault::RecoveryGrants;
using Channel = vault_keys::Channel;

void requireView(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin() || actor->encryptionKeysPerms().canView()) return;
    throw Denied("only super admins or users with the view encryption keys permission can list recovery recipients");
}

void requireEnroll(const Actor& actor, const Channel channel) {
    requireActor(actor);
    if (!actor->isSuperAdmin() && !actor->encryptionKeysPerms().canExport())
        throw Denied("only super admins or users with the export encryption keys permission can enroll or revoke "
                     "recovery recipients");
    // D4: a recipient is a decryption path for the vault, so it is managed where key material is: the local CLI or a
    // paired device, never a browser session or an agent.
    if (channel == Channel::Console)
        throw Refused("recipient_requires_device",
                      "recovery recipients are enrolled and revoked only through a paired device (Vaulthalla Desktop) "
                      "or the local vh CLI, never through the browser");
    if (channel == Channel::Agent)
        throw Denied("recovery recipients are never managed by agents (D4); the human runs this in a terminal");
}

std::string channelName(const Channel channel) { return channel == Channel::Device ? "device" : "cli"; }

std::string hex(const std::span<const uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 15]);
    }
    return out;
}

// An X25519 public key as base64 (44 characters) or hex (64 digits). Throws Invalid.
std::vector<uint8_t> parsePublicKey(const std::string& text) {
    std::vector<uint8_t> out;
    if (text.size() == 64 && std::ranges::all_of(text, [](const unsigned char c) { return std::isxdigit(c) != 0; })) {
        out.resize(32);
        std::size_t len = 0;
        if (sodium_hex2bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, nullptr) != 0 || len != 32)
            throw Invalid("the public key is not 64 hex digits");
    } else {
        out.resize(text.size());
        std::size_t len = 0;
        if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, nullptr,
                              sodium_base64_VARIANT_ORIGINAL) != 0)
            throw Invalid("the public key is neither base64 nor hex");
        out.resize(len);
    }
    if (out.size() != vl::keykit::kev1::kX25519KeySize)
        throw Invalid("a recovery recipient is an X25519 public key: 32 bytes (base64 or hex)");
    // Refuse a degenerate key (all-zero, small order): no envelope could ever be written to it.
    try {
        (void)vl::keykit::kev1::wrap(crypto::SecretKey::random()->bytes(), vl::keykit::kev1::Suite::X25519, 1, crypto::id::newObjectUid(),
                                 out);
    } catch (const std::exception&) {
        throw Invalid("the public key is not a usable X25519 key (degenerate or small-order point)");
    }
    return out;
}

std::shared_ptr<vault::model::Vault> liveVault(const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(vaultId));
    return vault;
}

std::shared_ptr<storage::Engine> engineFor(const unsigned int vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    if (!manager) return nullptr;
    for (const auto& engine : manager->getEngines())
        if (engine && engine->vault && engine->vault->id == vaultId) return engine;
    return nullptr;
}

Recipient recipientFrom(const db::query::vault::RecoveryGrant& g,
                        const std::map<std::string, std::vector<unsigned int>>& envelopeVersions) {
    Recipient r{.grant_id = g.grant_id, .recipient_id = g.recipient_id,
                .public_key = crypto::util::b64_encode(g.public_key), .suite = g.suite,
                .recipient_class = g.recipient_class, .label = g.label, .added_at = g.added_at,
                .authorized_by = g.authorized_by, .revoked_at = g.revoked_at, .revoked_by = g.revoked_by,
                .envelope_versions = {}, .account_key_generation = g.account_key_generation,
                .account_policy_sequence = g.account_policy_sequence};
    if (const auto it = envelopeVersions.find(g.grant_id); it != envelopeVersions.end())
        r.envelope_versions = it->second;
    return r;
}

std::map<std::string, std::vector<unsigned int>> envelopeVersionsOf(const unsigned int vaultId) {
    std::map<std::string, std::vector<unsigned int>> out;
    for (const auto& e : Grants::envelopes(vaultId)) out[e.grant_id].push_back(e.key_version);
    return out;
}

Recipient recipientOf(const unsigned int vaultId, const std::string& grantId) {
    const auto g = Grants::get(vaultId, grantId);
    if (!g) throw NotFound("vault " + std::to_string(vaultId) + " has no recovery recipient " + grantId);
    return recipientFrom(*g, envelopeVersionsOf(vaultId));
}

// The manifest root lists grants and envelopes: an opaque_v1 vault republishes on its next pass.
void requestPublish(const std::shared_ptr<storage::Engine>& engine) {
    if (const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(engine)) cloud->requestManifestPublish();
}

}

RecipientList list(const Actor& actor, const unsigned int vaultId) {
    using namespace recipients_detail;
    requireView(actor);
    const auto vault = liveVault(vaultId);
    RecipientList out{.vault_id = vault->id, .vault_name = vault->name,
                      .vault_uid = vault->uid ? vl::keykit::toBase32(*vault->uid) : std::string{}, .recipients = {},
                      .recovery = vault_keys::recoveryMaterialOf(vault->id)};
    const auto versions = envelopeVersionsOf(vault->id);
    for (const auto& g : Grants::list(vault->id)) out.recipients.push_back(recipientFrom(g, versions));
    return out;
}

AddResult add(const Actor& actor, const AddRequest& request, const vault_keys::Channel channel) {
    using namespace recipients_detail;
    requireEnroll(actor, channel);
    const auto vault = liveVault(request.vault_id);
    // An S3 vault's envelopes go to its own bucket; a local vault's are kept in the database until a remote is
    // attached (vault/RecoveryEnvelopes.hpp), which copies them into the bucket.
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    const bool local = vault->type == vault::model::VaultType::Local;
    if (!local && (!s3 || s3->bucket.empty()))
        throw Conflict("vault '" + vault->name + "' has no bucket to hold its recovery envelopes");
    if (!vault->uid) throw Conflict("vault '" + vault->name + "' has no uid");
    if (request.label && request.label->size() > 200) throw Invalid("the label is longer than 200 characters");
    std::optional<ops::cloud_keys::PinnedKey> pinned;
    if (request.account_key) {
        if (!request.public_key.empty()) throw Invalid("give either a public key or the account key, not both");
        pinned = ops::cloud_keys::pinnedKey();
        if (!pinned)
            throw Conflict("this server has no confirmed account recovery key: link it and confirm the key's fingerprint "
                           "first (`vh cloud key status`)");
    }
    const auto publicKey = pinned ? std::vector<uint8_t>(pinned->x25519_public.begin(), pinned->x25519_public.end())
                                  : parsePublicKey(request.public_key);
    const auto engine = engineFor(vault->id);
    if (!engine || !engine->encryptionManager)
        throw Conflict("the keys of vault '" + vault->name + "' are not available on this host, so nothing could be "
                       "wrapped to a recipient; restore them first (vh vault keys import)");

    db::query::vault::RecoveryGrant g;
    g.vault_id = vault->id;
    g.grant_id = vl::keykit::toBase32(crypto::id::newObjectUid());
    g.recipient_id = hex(vl::keykit::kev1::recipientId(publicKey));
    g.public_key = publicKey;
    g.suite = static_cast<uint16_t>(vl::keykit::kev1::Suite::X25519);
    g.recipient_class = "customer";
    g.label = request.label;
    g.authorized_by = fmt::format("user:{} via {}", actor->id, channelName(channel));
    if (pinned) {
        g.label = request.label.value_or("Vaulthalla Cloud recovery key (generation " +
                                         std::to_string(pinned->generation) + ")");
        g.account_key_generation = pinned->generation;
        g.authorized_by += fmt::format("; account_key:{} confirmed by {}", pinned->generation, pinned->confirmed_by);
    }
    // Step-up (#359): a recipient is a decryption path for the vault. The host CLI is exempt by design; a paired
    // device needs a person's approval on its session (#361: its approval key or a console passkey approval).
    auth::stepup::require(auth::stepup::Family::Keys, "vault.keys.recipients.add:" + std::to_string(vault->id));
    if (!Grants::add(g))
        throw Conflict("this public key is already an active recovery recipient of vault '" + vault->name + "'");

    AddResult out;
    const auto& keys = *engine->encryptionManager;
    std::vector<uint32_t> versions;
    for (const auto v : keys.retainedKeyVersions()) versions.push_back(v);
    try {
        out.envelopes_written = vault::envelopes::ensure(vault->id, versions, [&](const uint32_t v) -> crypto::SecretKeyPtr {
            try {
                return keys.historicalKeySnapshot(v);
            } catch (const std::exception&) {
                return nullptr;
            }
        });
    } catch (const std::exception& e) {
        out.note = std::string("the recipient is enrolled, but its envelopes could not all be written yet (") +
                   e.what() + (local ? "); attaching a remote writes the missing ones"
                                     : "); the next sync pass writes the missing ones");
        log::Registry::crypto()->warn("[ops::recovery_recipients] vault {}: {}", vault->id, *out.note);
    }
    // The vault is now covered by the account key: the account's recovery policy applies to it too.
    if (pinned) ops::cloud_keys::applyPolicy(vault->id);
    requestPublish(engine);
    out.recipient = recipientOf(vault->id, g.grant_id);
    out.versions = out.recipient.envelope_versions;
    out.recovery = vault_keys::recoveryMaterialOf(vault->id);

    vh::audit::record({.action = "vault.recovery.recipient.add", .outcome = vh::audit::Outcome::Success,
                       .actor_id = actor->id, .actor = actor->name(), .vault_id = vault->id,
                       .details = {{"grant_id", g.grant_id}, {"recipient_id", g.recipient_id},
                                   {"channel", channelName(channel)},
                                   {"envelopes", static_cast<int64_t>(out.envelopes_written)}, {"automatic", false},
                                   {"account_key_generation", pinned ? nlohmann::json(pinned->generation)
                                                                     : nlohmann::json(nullptr)}}},
                      fmt::format("[ops::recovery_recipients] {} enrolled recovery recipient {} (recipient {}) on vault "
                                  "{} through the {}; {} envelope(s) written to the vault's {}",
                                  actor->name(), g.grant_id, g.recipient_id.substr(0, 16), vault->id,
                                  channelName(channel), out.envelopes_written, local ? "database" : "bucket"));
    return out;
}

std::optional<AddResult> addAccountKeyForManagedVault(const unsigned int vaultId) {
    using namespace recipients_detail;
    const auto vault = liveVault(vaultId);
    const auto managed = db::query::cloud::CloudStorage::get(vault->id);
    if (!managed || managed->switch_state != "on")
        throw Conflict("vault '" + vault->name + "' isn't switched on for managed storage: its recovery recipients are "
                       "added by a person (vh vault keys recipient add --account-key)");
    if (!vault->uid) throw Conflict("vault '" + vault->name + "' has no uid");
    const auto pinned = ops::cloud_keys::pinnedKey();
    if (!pinned)
        throw Refused("account_key_unconfirmed", "this server has no confirmed account recovery key: a super admin "
                      "confirms its fingerprint first (`vh cloud key confirm`)");
    const std::vector<uint8_t> publicKey(pinned->x25519_public.begin(), pinned->x25519_public.end());
    for (const auto& existing : Grants::usable(vault->id))
        if (existing.account_key_generation && existing.public_key == publicKey) return std::nullopt;
    const auto engine = engineFor(vault->id);
    if (!engine || !engine->encryptionManager)
        throw Conflict("the keys of vault '" + vault->name + "' are not available on this host");

    db::query::vault::RecoveryGrant g;
    g.vault_id = vault->id;
    g.grant_id = vl::keykit::toBase32(crypto::id::newObjectUid());
    g.recipient_id = hex(vl::keykit::kev1::recipientId(publicKey));
    g.public_key = publicKey;
    g.suite = static_cast<uint16_t>(vl::keykit::kev1::Suite::X25519);
    g.recipient_class = "customer";
    g.label = "Vaulthalla Cloud recovery key (generation " + std::to_string(pinned->generation) + ")";
    g.account_key_generation = pinned->generation;
    g.authorized_by = fmt::format("system:cloud for managed storage; account_key:{} confirmed by {}", pinned->generation,
                                  pinned->confirmed_by);
    if (!Grants::add(g)) return std::nullopt;   // added meanwhile

    AddResult out;
    const auto& keys = *engine->encryptionManager;
    std::vector<uint32_t> versions;
    for (const auto v : keys.retainedKeyVersions()) versions.push_back(v);
    try {
        out.envelopes_written = vault::envelopes::ensure(vault->id, versions, [&](const uint32_t v) -> crypto::SecretKeyPtr {
            try {
                return keys.historicalKeySnapshot(v);
            } catch (const std::exception&) {
                return nullptr;
            }
        });
    } catch (const std::exception& e) {
        out.note = std::string("the account key is a recipient, but its envelopes could not all be written yet (") +
                   e.what() + ")";
        log::Registry::crypto()->warn("[ops::recovery_recipients] vault {}: {}", vault->id, *out.note);
    }
    ops::cloud_keys::applyPolicy(vault->id);
    requestPublish(engine);
    out.recipient = recipientOf(vault->id, g.grant_id);
    out.versions = out.recipient.envelope_versions;
    out.recovery = vault_keys::recoveryMaterialOf(vault->id);
    vh::audit::record({.action = "vault.recovery.recipient.add", .outcome = vh::audit::Outcome::Success,
                       .actor_id = std::nullopt, .actor = "system:cloud", .vault_id = vault->id,
                       .details = {{"grant_id", g.grant_id}, {"recipient_id", g.recipient_id}, {"channel", "system"},
                                   {"envelopes", static_cast<int64_t>(out.envelopes_written)}, {"automatic", true},
                                   {"account_key_generation", pinned->generation},
                                   {"confirmed_by", pinned->confirmed_by}}},
                      fmt::format("[ops::recovery_recipients] system:cloud added the pinned account recovery key "
                                  "(generation {}, confirmed by {}) as recovery recipient {} of managed vault {}; {} "
                                  "envelope(s) written", pinned->generation, pinned->confirmed_by, g.grant_id, vault->id,
                                  out.envelopes_written));
    return out;
}

RevokeResult revoke(const Actor& actor, const unsigned int vaultId, const std::string& grantId,
                    const vault_keys::Channel channel) {
    using namespace recipients_detail;
    requireEnroll(actor, channel);
    const auto vault = liveVault(vaultId);
    const auto existing = Grants::get(vault->id, grantId);
    if (!existing) throw NotFound("vault '" + vault->name + "' has no recovery recipient " + grantId);
    if (existing->revoked_at) throw Conflict("recovery recipient " + grantId + " is already revoked");
    if (existing->account_policy_sequence)
        throw Refused("recovery_policy_account_managed",
                      "recovery recipient " + grantId + " comes from the account's signed recovery policy " +
                          std::to_string(*existing->account_policy_sequence) + "; change the policy from Vaulthalla "
                          "Desktop or your account page instead, and every server revokes it");
    // A managed vault keeps the account key as its recipient: the managed-storage service would only add it again.
    if (existing->account_key_generation && db::query::cloud::CloudStorage::managed(vault->id))
        throw Refused("managed_vault_account_key",
                      "recovery recipient " + grantId + " is the account recovery key of a vault in managed storage, "
                      "which keeps it; switch the vault's managed storage off first (vh cloud storage disable)");
    auth::stepup::require(auth::stepup::Family::Keys, "vault.keys.recipients.revoke:" + std::to_string(vault->id));
    if (!Grants::revoke(vault->id, grantId, fmt::format("user:{} via {}", actor->id, channelName(channel))))
        throw Conflict("recovery recipient " + grantId + " is already revoked");
    requestPublish(engineFor(vault->id));
    RevokeResult out{.recipient = recipientOf(vault->id, grantId), .recovery = vault_keys::recoveryMaterialOf(vault->id)};
    vh::audit::record({.action = "vault.recovery.recipient.revoke", .outcome = vh::audit::Outcome::Success,
                       .actor_id = actor->id, .actor = actor->name(), .vault_id = vault->id,
                       .details = {{"grant_id", grantId}, {"recipient_id", existing->recipient_id},
                                   {"channel", channelName(channel)}, {"rotation_needed", out.recovery.rotation_needed}}},
                      fmt::format("[ops::recovery_recipients] {} revoked recovery recipient {} of vault {} through the "
                                  "{}; no new envelopes are written for it{}",
                                  actor->name(), grantId, vault->id, channelName(channel),
                                  out.recovery.rotation_needed
                                      ? " (it keeps the versions it already has until the key is rotated)" : ""));
    return out;
}

nlohmann::json toJson(const Recipient& r) {
    const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
    return {{"grant_id", r.grant_id},
            {"recipient_id", r.recipient_id},
            {"public_key", r.public_key},
            {"suite", r.suite},
            {"class", r.recipient_class},
            {"label", opt(r.label)},
            {"added_at", static_cast<int64_t>(r.added_at)},
            {"authorized_by", r.authorized_by},
            {"revoked_at", r.revoked_at ? nlohmann::json(static_cast<int64_t>(*r.revoked_at)) : nlohmann::json(nullptr)},
            {"revoked_by", opt(r.revoked_by)},
            {"envelope_versions", r.envelope_versions},
            {"account_key_generation", opt(r.account_key_generation)},
            {"account_policy_sequence", opt(r.account_policy_sequence)}};
}

nlohmann::json toJson(const RecipientList& l) {
    auto recipients = nlohmann::json::array();
    for (const auto& r : l.recipients) recipients.push_back(toJson(r));
    return {{"vault_id", l.vault_id}, {"vault_name", l.vault_name}, {"vault_uid", l.vault_uid},
            {"recipients", std::move(recipients)}, {"recovery", vault_keys::toJson(l.recovery)}};
}

nlohmann::json toJson(const AddResult& r) {
    return {{"recipient", toJson(r.recipient)},
            {"envelopes_written", r.envelopes_written},
            {"versions", r.versions},
            {"note", r.note ? nlohmann::json(*r.note) : nlohmann::json(nullptr)},
            {"recovery", vault_keys::toJson(r.recovery)}};
}

nlohmann::json toJson(const RevokeResult& r) {
    return {{"recipient", toJson(r.recipient)}, {"recovery", vault_keys::toJson(r.recovery)}};
}

}
