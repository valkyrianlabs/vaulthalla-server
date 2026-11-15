#include "ops/CloudKeys.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "cloud/AccountPin.hpp"
#include "cloud/Client.hpp"
#include "cloud/Identity.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/cloud/AccountKey.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/permission/admin/keys/Encryption.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/account_key.hpp>
#include <vl/keykit/base64url.hpp>
#include <vl/keykit/kev1.hpp>
#include <vl/keykit/recovery_policy.hpp>
#include <vl/keykit/uid.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>
#include <mutex>
#include <set>

namespace vh::ops::cloud_keys {

// Named, not anonymous: the unity build joins this file with others.
namespace cloud_keys_detail {

namespace account = vl::keykit::account;
using db::query::cloud::AccountKeyRow;
using db::query::cloud::AccountKeys;
using db::query::cloud::Link;
using db::query::cloud::LinkRow;
using Grants = db::query::vault::RecoveryGrants;

constexpr const char* kSystemActor = "system:cloud";

std::mutex checkMutex;  // one check at a time: the background service, the CLI and a confirmation

std::string hexOf(const std::span<const uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const auto b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 15]);
    }
    return out;
}

std::string channelName(const Channel c) {
    switch (c) {
        case Channel::Cli: return "cli";
        case Channel::Device: return "device";
        case Channel::Console: return "console";
        default: return "agent";
    }
}

void requireView(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin() || actor->encryptionKeysPerms().canView()) return;
    throw Denied("only super admins or users with the view encryption keys permission can see the account recovery key");
}

void requireSuperAdmin(const Actor& actor, const Channel channel, const char* what) {
    requireActor(actor);
    if (channel == Channel::Agent) throw Denied(std::string(what) + " is never done by an agent; run it yourself");
    if (!actor->isSuperAdmin()) throw Denied(std::string("only a super admin can ") + what);
}

void audit(const std::string& action, const ::vh::audit::Outcome outcome, const Actor* actor, nlohmann::json details,
           const std::string& message) {
    ::vh::audit::Event e{.action = action, .outcome = outcome, .details = std::move(details)};
    if (actor && *actor) {
        e.actor_id = (*actor)->id;
        e.actor = (*actor)->name();
    } else {
        e.actor = kSystemActor;
    }
    ::vh::audit::record(e, "[ops::cloud_keys] " + message);
}

std::optional<LinkRow> linkedRow() {
    auto row = Link::get();
    if (!row || row->status != "linked" || !row->installation_id) return std::nullopt;
    return row;
}

template <std::size_t N>
std::optional<std::array<uint8_t, N>> b64uFixed(const nlohmann::json& j) {
    if (!j.is_string()) return std::nullopt;
    const auto bytes = vl::keykit::base64UrlDecode(j.get<std::string>());
    if (!bytes || bytes->size() != N) return std::nullopt;
    std::array<uint8_t, N> out{};
    std::ranges::copy(*bytes, out.begin());
    return out;
}

std::string reasonOf(const AccountKeyRow& r) {
    try {
        return std::string(account::reasonName(account::parseStatement(r.statement).reason));
    } catch (const account::Error&) {
        return "unknown";
    }
}

Generation generationOf(const AccountKeyRow& r) {
    return {.generation = r.generation, .fingerprint = r.fingerprint, .state = r.state, .link = r.link,
            .reason = reasonOf(r), .x25519_public = vl::keykit::base64UrlEncode(r.x25519_public),
            .confirmed_by = r.confirmed_by, .confirmed_at = r.confirmed_at};
}

// A verified generation as a row (unsealed).
AccountKeyRow rowOf(const account::VerifiedGeneration& v, const account::SignedStatement& s, const std::string& state,
                    const std::time_t now) {
    AccountKeyRow r;
    r.account_public_id = v.statement.public_id;
    r.generation = v.statement.generation;
    r.fingerprint = account::fingerprintText(v.fingerprint);
    r.x25519_public = v.statement.x25519_public;
    r.ed25519_public = v.statement.ed25519_public;
    r.statement = s.statement;
    r.signature = s.signature;
    r.previous_signature = s.previous_signature;
    r.link = std::string(account::linkName(v.link));
    r.state = state;
    r.stored_at = now;
    return r;
}

void seal(AccountKeyRow& r) { r.mac = ::vh::cloud::pin::macOf(r, true); }

void copyFloor(AccountKeyRow& to, const AccountKeyRow& from) {
    to.policy_sequence = from.policy_sequence;
    to.policy_sha256 = from.policy_sha256;
    to.policy = from.policy;
    to.policy_signature = from.policy_signature;
}

std::shared_ptr<storage::Engine> engineFor(const unsigned int vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    if (!manager) return nullptr;
    for (const auto& engine : manager->getEngines())
        if (engine && engine->vault && engine->vault->id == vaultId) return engine;
    return nullptr;
}

// Wraps every key version the vault holds to its grants that still lack an envelope (the wrap guard applies). Best
// effort: an unreachable bucket or keys not on this host leave them for the next check or sync pass.
unsigned wrapAll(const unsigned int vaultId) {
    const auto engine = engineFor(vaultId);
    if (!engine || !engine->encryptionManager) return 0;
    const auto& keys = *engine->encryptionManager;
    std::vector<uint32_t> versions;
    for (const auto v : keys.retainedKeyVersions()) versions.push_back(v);
    unsigned written = 0;
    try {
        written = vault::envelopes::ensure(vaultId, versions, [&](const uint32_t v) -> crypto::SecretKeyPtr {
            try {
                return keys.historicalKeySnapshot(v);
            } catch (const std::exception&) {
                return nullptr;
            }
        });
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[ops::cloud_keys] Vault {}: recovery envelopes not all written yet ({}); the "
                                      "next check or sync pass writes them", vaultId, e.what());
    }
    if (const auto cloudEngine = std::dynamic_pointer_cast<storage::CloudEngine>(engine)) cloudEngine->requestManifestPublish();
    return written;
}

std::set<uint32_t> envelopeVersions(const unsigned int vaultId, const std::string& grantId) {
    std::set<uint32_t> out;
    for (const auto& e : Grants::envelopes(vaultId))
        if (e.grant_id == grantId) out.insert(e.key_version);
    return out;
}

std::string accountKeyLabel(const uint32_t generation) {
    return "Vaulthalla Cloud recovery key (generation " + std::to_string(generation) + ")";
}

// The account key's grant moves to the pinned generation on every vault holding one of an earlier generation of the
// same account (a signed rotation, or a confirmed replacement): the new grant is added and wrapped to, and the old one
// revoked once the new one has every version the old one had. Re-run by every check until it converges.
std::vector<unsigned int> regrant(const ::vh::cloud::pin::Checked& checked, const AccountKeyRow& pinned) {
    std::set<std::string> earlierKeys;
    for (const auto& r : checked.rows)
        if (r.state == "superseded") earlierKeys.insert(hexOf(r.x25519_public));
    std::vector<unsigned int> moved;
    if (earlierKeys.empty()) return moved;
    const auto pinnedHex = hexOf(pinned.x25519_public);
    const auto reason = reasonOf(pinned);
    const bool fromChain = pinned.confirmed_by && pinned.confirmed_by->starts_with("chain:");
    for (const auto& g : Grants::accountManaged()) {
        if (!g.account_key_generation || !earlierKeys.contains(hexOf(g.public_key))) continue;
        std::optional<db::query::vault::RecoveryGrant> current;
        for (const auto& other : Grants::usable(g.vault_id))
            if (other.account_key_generation && hexOf(other.public_key) == pinnedHex) current = other;
        if (!current) {
            db::query::vault::RecoveryGrant n;
            n.vault_id = g.vault_id;
            n.grant_id = vl::keykit::toBase32(crypto::id::newObjectUid());
            n.recipient_id = hexOf(vl::keykit::kev1::recipientId(pinned.x25519_public));
            n.public_key.assign(pinned.x25519_public.begin(), pinned.x25519_public.end());
            n.label = accountKeyLabel(pinned.generation);
            n.account_key_generation = pinned.generation;
            n.authorized_by = fromChain ? fmt::format("account_key:{} via {}", pinned.generation, *pinned.confirmed_by)
                                        : fmt::format("account_key:{} confirmed by {}", pinned.generation,
                                                      pinned.confirmed_by.value_or("?"));
            if (!Grants::add(n)) continue;  // the same key as an ordinary grant: nothing to move
            current = n;
            audit("vault.recovery.recipient.add", ::vh::audit::Outcome::Success, nullptr,
                  {{"grant_id", n.grant_id}, {"recipient_id", n.recipient_id}, {"automatic", true},
                   {"account_key_generation", pinned.generation}, {"vault_id", g.vault_id}},
                  fmt::format("vault {}: the account recovery key's grant follows it to generation {} ({})", g.vault_id,
                              pinned.generation, n.authorized_by));
        }
        (void)wrapAll(g.vault_id);
        const auto had = envelopeVersions(g.vault_id, g.grant_id);
        const auto has = envelopeVersions(g.vault_id, current->grant_id);
        if (!std::ranges::includes(has, had)) continue;  // not covered yet: the old grant stays
        const auto revokedBy = (reason == "compromise" ? std::string("account_key_compromise:")
                                                       : std::string(Grants::kRoutineRotationPrefix)) +
                               std::to_string(pinned.generation);
        if (Grants::revoke(g.vault_id, g.grant_id, revokedBy)) {
            moved.push_back(g.vault_id);
            audit("vault.recovery.recipient.revoke", ::vh::audit::Outcome::Success, nullptr,
                  {{"grant_id", g.grant_id}, {"recipient_id", g.recipient_id}, {"automatic", true},
                   {"account_key_generation", *g.account_key_generation}, {"vault_id", g.vault_id},
                   {"rotation_needed", reason == "compromise"}},
                  fmt::format("vault {}: the grant of account key generation {} is replaced by generation {} ({})",
                              g.vault_id, *g.account_key_generation, pinned.generation, revokedBy));
        }
    }
    return moved;
}

struct Applied {
    unsigned added{};
    unsigned revoked{};
};

// Makes one vault's policy grants equal the pinned row's accepted policy. A vault is covered while it holds an active
// account-key grant: only then are recipients added. Policy grants of a vault no longer covered are still revoked
// when the policy drops them.
Applied applyToVault(const unsigned int vaultId, const AccountKeyRow& pinned) {
    Applied out;
    if (!pinned.policy || pinned.policy_sequence == 0) return out;
    const auto policy = account::parsePolicy(*pinned.policy);
    const auto active = Grants::usable(vaultId);
    const bool covered = std::ranges::any_of(active, [](const auto& g) { return g.account_key_generation.has_value(); });
    const bool hasPolicyGrants =
        std::ranges::any_of(active, [](const auto& g) { return g.account_policy_sequence.has_value(); });
    if (!covered && !hasPolicyGrants) return out;
    std::map<std::string, const account::PolicyRecipient*> desired;
    for (const auto& r : policy.recipients) desired[hexOf(r.recipientId())] = &r;
    const auto by = fmt::format("account_policy:{}", policy.sequence);
    for (const auto& g : active) {
        if (!g.account_policy_sequence || desired.contains(g.recipient_id)) continue;
        if (!Grants::revoke(vaultId, g.grant_id, by)) continue;
        ++out.revoked;
        audit("vault.recovery.recipient.revoke", ::vh::audit::Outcome::Success, nullptr,
              {{"grant_id", g.grant_id}, {"recipient_id", g.recipient_id}, {"automatic", true},
               {"account_policy_sequence", policy.sequence}, {"vault_id", vaultId}},
              fmt::format("vault {}: recovery recipient {} revoked, the account's recovery policy {} no longer lists it",
                          vaultId, g.grant_id, policy.sequence));
    }
    if (covered) {
        std::set<std::string> present;
        for (const auto& g : active) present.insert(g.recipient_id);
        for (const auto& [id, r] : desired) {
            if (present.contains(id)) continue;
            db::query::vault::RecoveryGrant n;
            n.vault_id = vaultId;
            n.grant_id = vl::keykit::toBase32(crypto::id::newObjectUid());
            n.recipient_id = id;
            n.public_key.assign(r->x25519_public.begin(), r->x25519_public.end());
            n.label = r->label;
            n.account_policy_sequence = policy.sequence;
            n.authorized_by = fmt::format("account_policy:{} signed by account_key:{}", policy.sequence, policy.generation);
            if (!Grants::add(n)) continue;
            ++out.added;
            audit("vault.recovery.recipient.add", ::vh::audit::Outcome::Success, nullptr,
                  {{"grant_id", n.grant_id}, {"recipient_id", n.recipient_id}, {"automatic", true},
                   {"account_policy_sequence", policy.sequence}, {"vault_id", vaultId}},
                  fmt::format("vault {}: recovery recipient {} added from the account's recovery policy {}", vaultId,
                              n.grant_id, policy.sequence));
        }
        if (out.added) (void)wrapAll(vaultId);
    }
    db::query::cloud::PolicyVaults::applied(vaultId, pinned.account_public_id, policy.sequence);
    return out;
}

// Every vault an account-managed grant names, in order.
std::vector<unsigned int> managedVaults() {
    std::set<unsigned int> ids;
    for (const auto& g : Grants::accountManaged()) ids.insert(g.vault_id);
    return {ids.begin(), ids.end()};
}

Applied applyEverywhere(const AccountKeyRow& pinned) {
    Applied total;
    for (const auto id : managedVaults()) {
        try {
            const auto a = applyToVault(id, pinned);
            total.added += a.added;
            total.revoked += a.revoked;
        } catch (const std::exception& e) {
            log::Registry::crypto()->warn("[ops::cloud_keys] Vault {}: applying the account recovery policy failed: {}",
                                          id, e.what());
        }
    }
    return total;
}

void policyRefused(const std::string& reason, const std::string& detail) {
    audit("cloud.policy.refused", ::vh::audit::Outcome::Denied, nullptr, {{"reason", reason}},
          "the account's recovery policy was refused (" + reason + "): " + detail + "; nothing changed");
}

// The policy the cloud served, against the pinned row's floor. Returns the pinned row as it now is.
AccountKeyRow acceptPolicy(const nlohmann::json& p, AccountKeyRow pinned) {
    if (!p.is_object() || !p.contains("policy") || !p["policy"].is_string()) {
        policyRefused("bad_answer", "the policy isn't text");
        return pinned;
    }
    const auto text = p["policy"].get<std::string>();
    const auto signature = b64uFixed<64>(p.value("signature", nlohmann::json()));
    if (!signature) {
        policyRefused("bad_signature", "the signature isn't 64 bytes of base64url");
        return pinned;
    }
    // The floor's own policy, as served again (also after a rotation, before the account signs it anew): nothing to do.
    if (pinned.policy && *pinned.policy == text) return pinned;
    account::VerifiedPolicy v;
    try {
        v = account::verifyPolicy({.policy = text, .signature = *signature}, account::parseStatement(pinned.statement));
    } catch (const account::Error& e) {
        policyRefused(std::string(account::errorCodeName(e.code())),
                      "it doesn't verify against the pinned account key (generation " + std::to_string(pinned.generation) +
                          ")");
        return pinned;
    }
    account::PolicyFloor floor{.sequence = pinned.policy_sequence, .hash = pinned.policy_sha256.value_or(account::Digest{})};
    switch (account::compareToFloor(v, floor)) {
        case account::SequenceVerdict::Unchanged: return pinned;
        case account::SequenceVerdict::Older:
            policyRefused("rollback", "sequence " + std::to_string(v.policy.sequence) + " is below the accepted " +
                                          std::to_string(floor.sequence));
            return pinned;
        case account::SequenceVerdict::Conflict:
            policyRefused("conflict", "sequence " + std::to_string(v.policy.sequence) +
                                          " was accepted with other bytes");
            return pinned;
        case account::SequenceVerdict::Newer: break;
    }
    pinned.policy_sequence = v.policy.sequence;
    pinned.policy_sha256 = v.hash;
    pinned.policy = text;
    pinned.policy_signature = *signature;
    seal(pinned);
    AccountKeys::put({pinned});
    const auto applied = applyEverywhere(pinned);
    audit("cloud.policy.accepted", ::vh::audit::Outcome::Success, nullptr,
          {{"sequence", v.policy.sequence}, {"generation", v.policy.generation},
           {"recipients", v.policy.recipients.size()}, {"added", applied.added}, {"revoked", applied.revoked},
           {"policy_sha256", hexOf(v.hash)}},
          fmt::format("accepted the account's recovery policy {} (generation {}, {} recipient(s)): {} grant(s) added, {} "
                      "revoked", v.policy.sequence, v.policy.generation, v.policy.recipients.size(), applied.added,
                      applied.revoked));
    return pinned;
}

void keyRefused(const std::string& reason, const std::string& detail) {
    Link::recordKeyCheck("refused", reason + ": " + detail, std::nullopt);
    audit("cloud.key.change_refused", ::vh::audit::Outcome::Denied, nullptr, {{"reason", reason}},
          "the account recovery key from Vaulthalla Cloud was refused (" + reason + "): " + detail +
              "; the pin is unchanged");
}

std::optional<std::time_t> offlineCopyOf(const nlohmann::json& body) {
    const auto pick = [](const nlohmann::json& j) -> std::optional<std::time_t> {
        if (j.is_object() && j.contains("offline_copy_confirmed_at") && j["offline_copy_confirmed_at"].is_number_integer())
            return j["offline_copy_confirmed_at"].get<std::time_t>();
        return std::nullopt;
    };
    if (body.contains("current")) {
        if (const auto t = pick(body["current"])) return t;
    }
    return pick(body);
}

// One GET /v1/keys/account answer, for the linked account `publicId`.
void process(const nlohmann::json& body, const std::string& publicId) {
    if (!body.is_object() || !body.contains("public_id") || !body["public_id"].is_string() ||
        body["public_id"].get<std::string>() != publicId)
        return keyRefused("account_mismatch", "the answer names another account than the one this server is linked to");
    if (!body.contains("chain") || !body["chain"].is_array() || body["chain"].empty())
        return keyRefused("bad_answer", "the answer has no key statement chain");
    std::vector<account::SignedStatement> chain;
    for (const auto& e : body["chain"]) {
        if (!e.is_object() || !e.contains("statement") || !e["statement"].is_string())
            return keyRefused("bad_answer", "a chain entry has no statement");
        const auto sig = b64uFixed<64>(e.value("signature", nlohmann::json()));
        if (!sig) return keyRefused("bad_answer", "a chain entry's signature isn't 64 bytes of base64url");
        account::SignedStatement s{.statement = e["statement"].get<std::string>(), .signature = *sig,
                                   .previous_signature = std::nullopt};
        if (e.contains("previous_signature") && !e["previous_signature"].is_null()) {
            const auto prev = b64uFixed<64>(e["previous_signature"]);
            if (!prev) return keyRefused("bad_answer", "a previous signature isn't 64 bytes of base64url");
            s.previous_signature = *prev;
        }
        chain.push_back(std::move(s));
    }
    std::vector<account::VerifiedGeneration> verified;
    try {
        verified = account::verifyChain(chain, publicId);
    } catch (const account::Error& e) {
        return keyRefused(std::string(account::errorCodeName(e.code())),
                          "the key statement chain doesn't verify" +
                              (e.index() ? " at generation " + std::to_string(*e.index() + 1) : std::string()));
    }

    auto checked = ::vh::cloud::pin::load(publicId);
    if (!checked.ok()) {
        Link::recordKeyCheck("tampered", "a stored account key row fails its MAC; `vh cloud key forget`, then confirm "
                                         "the key again", std::nullopt);
        return;
    }
    const auto now = std::time(nullptr);
    std::vector<AccountKeyRow> writes;
    std::vector<uint32_t> drop;
    const auto* pinned = checked.pinned();
    const auto* waiting = checked.waiting();
    const auto& newest = verified.back();
    const auto newestFp = account::fingerprintText(newest.fingerprint);

    if (pinned) {
        account::FollowResult f;
        try {
            const auto pinFp = account::parseFingerprint(pinned->fingerprint);
            if (!pinFp) throw account::Error(account::ErrorCode::PinMismatch);
            f = account::follow({.generation = pinned->generation, .fingerprint = *pinFp}, verified);
        } catch (const account::Error& e) {
            return keyRefused(std::string(account::errorCodeName(e.code())),
                              e.code() == account::ErrorCode::Rollback
                                  ? "the chain ends below the pinned generation " + std::to_string(pinned->generation)
                                  : "the chain's generation " + std::to_string(pinned->generation) +
                                        " isn't the pinned key");
        }
        if (f.accepted > pinned->generation) {
            AccountKeyRow previous = *pinned;
            for (uint32_t g = pinned->generation + 1; g <= f.accepted; ++g) {
                auto next = rowOf(verified[g - 1], chain[g - 1], "pinned", now);
                next.confirmed_by = "chain:" + std::to_string(g - 1);
                next.confirmed_at = now;
                copyFloor(next, previous);
                previous.state = "superseded";
                writes.push_back(previous);
                audit("cloud.key.chain", ::vh::audit::Outcome::Success, nullptr,
                      {{"generation", g}, {"fingerprint", next.fingerprint}, {"reason", reasonOf(next)}},
                      fmt::format("the account recovery key rotated to generation {} ({}), signed by generation {}", g,
                                  next.fingerprint, g - 1));
                previous = std::move(next);
            }
            writes.push_back(previous);
        }
        if (f.needsConfirmation()) {
            if (!(waiting && waiting->generation == newest.statement.generation && waiting->fingerprint == newestFp)) {
                writes.push_back(rowOf(newest, chain.back(), "refused", now));
                audit("cloud.key.change_refused", ::vh::audit::Outcome::Denied, nullptr,
                      {{"reason", "replacement"}, {"generation", newest.statement.generation},
                       {"fingerprint", newestFp}},
                      fmt::format("generation {} ({}) replaces the account recovery key without the pinned key's "
                                  "signature; this server keeps wrapping to generation {} until a super admin confirms "
                                  "the new fingerprint", newest.statement.generation, newestFp, f.accepted));
            }
        }
        for (const auto& r : checked.rows)
            if ((r.state == "pending" || r.state == "refused") &&
                (!f.needsConfirmation() || r.generation != newest.statement.generation))
                drop.push_back(r.generation);
    } else if (!(waiting && waiting->state == "pending" && waiting->generation == newest.statement.generation &&
                 waiting->fingerprint == newestFp)) {
        writes.push_back(rowOf(newest, chain.back(), "pending", now));
        for (const auto& r : checked.rows)
            if (r.generation != newest.statement.generation) drop.push_back(r.generation);
        audit("cloud.key.pending", ::vh::audit::Outcome::Info, nullptr,
              {{"generation", newest.statement.generation}, {"fingerprint", newestFp}},
              fmt::format("the account recovery key generation {} ({}) verified; it waits for a super admin to confirm "
                          "its fingerprint (`vh cloud key confirm`)", newest.statement.generation, newestFp));
    }
    std::erase_if(drop, [&](const uint32_t g) {
        return std::ranges::any_of(writes, [&](const AccountKeyRow& w) { return w.generation == g; });
    });
    for (auto& w : writes) seal(w);
    if (!writes.empty()) AccountKeys::put(writes, drop);
    else if (!drop.empty()) {
        // Only stale waiting rows to drop: rewrite nothing, delete them.
        std::vector<AccountKeyRow> keep;
        for (const auto& r : checked.rows)
            if (r.state == "pinned") keep.push_back(r);
        if (!keep.empty()) AccountKeys::put(keep, drop);
    }

    Link::recordKeyCheck("ok", std::nullopt, offlineCopyOf(body));

    // The pin as it now is: grants follow it, and the policy is checked against it.
    checked = ::vh::cloud::pin::load(publicId);
    if (!checked.ok() || !checked.pinned()) return;
    auto current = *checked.pinned();
    (void)regrant(checked, current);
    if (body.contains("policy") && !body["policy"].is_null()) current = acceptPolicy(body["policy"], current);
    (void)applyEverywhere(current);
}

bool offerPolicyImpl(const std::string& policy, const std::string& signature, const std::string& source) {
    const auto row = linkedRow();
    if (!row || !row->account_public_id) return false;
    const auto checked = ::vh::cloud::pin::load(*row->account_public_id);
    if (!checked.ok() || !checked.pinned()) return false;
    const auto before = checked.pinned()->policy_sequence;
    const auto after = acceptPolicy({{"policy", policy}, {"signature", signature}}, *checked.pinned());
    if (after.policy_sequence > before)
        log::Registry::crypto()->info("[ops::cloud_keys] accepted the account's recovery policy {} from {}",
                                      after.policy_sequence, source);
    return after.policy_sequence > before;
}

Status build() {
    Status s;
    const auto row = linkedRow();
    if (!row) return s;
    s.account_public_id = row->account_public_id;
    s.checked_at = row->key_checked_at;
    s.check = row->key_check;
    s.check_detail = row->key_check_detail;
    s.offline_copy_at = row->offline_copy_at;
    if (row->key_check == "ok" || row->key_check == "none") s.offline_copy = row->offline_copy_at ? "confirmed" : "none";
    s.state = "unchecked";
    if (!row->account_public_id) {
        s.next_step = "`vh cloud status` records the account this server is linked to, then `vh cloud key refresh`";
        return s;
    }
    const auto checked = ::vh::cloud::pin::load(*row->account_public_id);
    for (const auto& r : checked.rows) s.generations.push_back(generationOf(r));
    if (const auto* p = checked.pinned()) {
        s.pinned = generationOf(*p);
        if (p->policy && p->policy_sha256) {
            try {
                const auto parsed = account::parsePolicy(*p->policy);
                Policy pol{.sequence = parsed.sequence, .generation = parsed.generation, .sha256 = hexOf(*p->policy_sha256),
                           .issued_at = parsed.issued_at, .recipients = {}};
                for (const auto& r : parsed.recipients)
                    pol.recipients.push_back({.recipient_id = hexOf(r.recipientId()), .label = r.label});
                s.policy = std::move(pol);
            } catch (const account::Error&) {
            }
        }
    }
    if (const auto* w = checked.waiting()) s.waiting = generationOf(*w);

    std::map<unsigned int, VaultCoverage> vaults;
    for (const auto& g : Grants::accountManaged()) {
        auto& v = vaults[g.vault_id];
        v.vault_id = g.vault_id;
        if (g.account_key_generation) v.account_key_generation = g.account_key_generation;
        if (g.account_policy_sequence) ++v.policy_grants;
    }
    for (const auto& a : db::query::cloud::PolicyVaults::list())
        if (const auto it = vaults.find(a.vault_id); it != vaults.end()) it->second.applied_sequence = a.sequence;
    for (auto& [id, v] : vaults) {
        if (const auto vault = db::query::vault::Vault::getVault(id)) v.vault_name = vault->name;
        s.vaults.push_back(std::move(v));
    }

    if (!checked.ok()) {
        s.state = "tampered";
        s.issue = "cloud_account_key_tampered";
        s.next_step = "a stored account key row fails its integrity check, so nothing is wrapped to the account key: "
                      "`vh cloud key forget`, then confirm the key again";
    } else if (s.pinned && s.waiting) {
        s.state = "change_pending";
        s.issue = "cloud_account_key_change_pending";
        s.next_step = "the account recovery key was replaced: compare generation " +
                      std::to_string(s.waiting->generation) + "'s fingerprint with the one Vaulthalla Desktop or your "
                      "account page shows, then `vh cloud key confirm <fingerprint>`";
    } else if (s.pinned) {
        s.state = "pinned";
        if (s.offline_copy == "none")
            s.next_step = "no offline copy of the recovery key is recorded: export it from Vaulthalla Desktop";
    } else if (s.waiting) {
        s.state = "pending";
        s.next_step = "compare the fingerprint with the one Vaulthalla Desktop or your account page shows, then "
                      "`vh cloud key confirm <fingerprint>`";
    } else if (row->key_check == "none") {
        s.state = "none";
    }
    return s;
}

}

Status status(const Actor& actor) {
    cloud_keys_detail::requireView(actor);
    return cloud_keys_detail::build();
}

Status check(const std::string& trigger) {
    using namespace cloud_keys_detail;
    std::scoped_lock lock(checkMutex);
    auto row = linkedRow();
    if (!row) throw Conflict("this server isn't linked to Vaulthalla Cloud (`vh cloud link`)");
    const auto seed = vh::cloud::identity::load();
    if (!seed) {
        Link::recordKeyCheck("rejected", "the identity key no longer unseals", std::nullopt);
        return build();
    }
    const auto at = vh::cloud::endpoint(row->endpoint);
    if (!row->account_public_id) {
        const auto reply = vh::cloud::signedCall(at, *row->installation_id, seed->bytes(), "GET", "/v1/installation");
        const auto& b = reply.body;
        if (reply.ok() && b.is_object() && b.contains("account_public_id") && b["account_public_id"].is_string()) {
            const auto id = b["account_public_id"].get<std::string>();
            std::optional<std::string> deployment;
            if (b.contains("deployment_id") && b["deployment_id"].is_string()) deployment = b["deployment_id"].get<std::string>();
            try {
                (void)Link::fillAccount(deployment, id);
            } catch (const std::exception&) {
                // A malformed value fails the column's CHECK: nothing is recorded.
            }
            row = linkedRow();
        }
        if (!row || !row->account_public_id) {
            Link::recordKeyCheck(reply.status == 0 ? "unreachable" : "refused",
                                 "Vaulthalla Cloud didn't report the account's public id", std::nullopt);
            return build();
        }
    }
    const auto reply = vh::cloud::signedCall(at, *row->installation_id, seed->bytes(), "GET", "/v1/keys/account");
    if (reply.status == 0) Link::recordKeyCheck("unreachable", reply.error, std::nullopt);
    else if (reply.status == 404) Link::recordKeyCheck("none", "the account has no recovery key yet", std::nullopt);
    else if (reply.status == 401) Link::recordKeyCheck("rejected", "Vaulthalla Cloud no longer accepts this server", std::nullopt);
    else if (!reply.ok()) Link::recordKeyCheck("refused", reply.error, std::nullopt);
    else {
        try {
            process(reply.body, *row->account_public_id);
        } catch (const ::vh::cloud::pin::KeyLost& e) {
            Link::recordKeyCheck("tampered", e.what(), std::nullopt);
        }
    }
    log::Registry::crypto()->debug("[ops::cloud_keys] Account recovery key check ({}): {}", trigger,
                                   linkedRow() ? linkedRow()->key_check.value_or("?") : "unlinked");
    return build();
}

Status refresh(const Actor& actor, const Channel channel) {
    cloud_keys_detail::requireSuperAdmin(actor, channel, "refresh the account recovery key");
    return check("refresh by " + actor->name());
}

Confirmed confirm(const Actor& actor, const std::string& input, const Channel channel) {
    using namespace cloud_keys_detail;
    requireSuperAdmin(actor, channel, "confirm the account recovery key");
    // Like a recovery recipient: the decryption path every managed vault gets is chosen where key material is (D4).
    if (channel == Channel::Console)
        throw Refused("cloud_key_requires_device",
                      "the account recovery key is confirmed only from a paired device (Vaulthalla Desktop) or the local "
                      "vh CLI, never through the browser");
    const auto fp = account::parseFingerprint(input, true);
    if (!fp) throw Invalid("a fingerprint is eight groups of four hex digits");
    const auto fpText = account::fingerprintText(*fp);
    auto row = linkedRow();
    if (!row) throw Conflict("this server isn't linked to Vaulthalla Cloud (`vh cloud link`)");
    if (channel == Channel::Device) auth::stepup::require(auth::stepup::Family::Keys, "cloud.key.confirm");
    if (channel == Channel::Cli && row->account_public_id) {
        const auto before = ::vh::cloud::pin::load(*row->account_public_id);
        if (before.ok() && !before.waiting()) (void)check("confirm");
    }
    row = linkedRow();
    if (!row || !row->account_public_id) throw Conflict("the account's recovery key hasn't been fetched yet (`vh cloud key refresh`)");

    std::scoped_lock lock(checkMutex);
    auto checked = ::vh::cloud::pin::load(*row->account_public_id);
    if (!checked.ok())
        throw Refused("cloud_account_key_tampered", "a stored account key row fails its integrity check; `vh cloud key "
                                                    "forget`, then confirm again");
    const auto* waiting = checked.waiting();
    if (!waiting) throw Conflict("no account recovery key is waiting for a confirmation (`vh cloud key status`)");
    // The fingerprint is the one computed from the stored statement, never a stored text alone.
    const auto statement = account::parseStatement(waiting->statement);
    const auto computed = account::fingerprintText(account::fingerprint(statement));
    if (computed != waiting->fingerprint || computed != fpText) {
        audit("cloud.key.confirm", ::vh::audit::Outcome::Denied, &actor,
              {{"generation", waiting->generation}, {"channel", channelName(channel)}},
              fmt::format("{} gave a fingerprint that isn't the account recovery key's (generation {}); nothing was "
                          "pinned", actor->name(), waiting->generation));
        throw Refused("cloud_key_mismatch", "that isn't this account's recovery key fingerprint (generation " +
                                                std::to_string(waiting->generation) + "); nothing was pinned. Compare it "
                                                "again with the one Vaulthalla Desktop or your account page shows");
    }
    const auto now = std::time(nullptr);
    AccountKeyRow next = *waiting;
    next.state = "pinned";
    next.confirmed_by = fmt::format("user:{} via {}", actor->id, channelName(channel));
    next.confirmed_at = now;
    std::vector<AccountKeyRow> writes;
    std::vector<uint32_t> drop;
    const auto* old = checked.pinned();
    if (old) {
        copyFloor(next, *old);
        auto superseded = *old;
        superseded.state = "superseded";
        writes.push_back(superseded);
    }
    writes.push_back(next);
    for (const auto& r : checked.rows)
        if ((r.state == "pending" || r.state == "refused") && r.generation != next.generation) drop.push_back(r.generation);
    for (auto& w : writes) seal(w);
    AccountKeys::put(writes, drop);
    audit("cloud.key.confirm", ::vh::audit::Outcome::Success, &actor,
          {{"generation", next.generation}, {"fingerprint", next.fingerprint}, {"channel", channelName(channel)},
           {"replacement", old != nullptr}},
          fmt::format("{} confirmed the account recovery key generation {} ({}) through the {}; it is pinned",
                      actor->name(), next.generation, next.fingerprint, channelName(channel)));
    Confirmed out{.generation = generationOf(next), .replacement = old != nullptr, .vaults = {}};
    checked = ::vh::cloud::pin::load(*row->account_public_id);
    if (checked.ok() && checked.pinned()) {
        out.vaults = regrant(checked, *checked.pinned());
        (void)applyEverywhere(*checked.pinned());
    }
    return out;
}

Forgotten forget(const Actor& actor, const Channel channel) {
    using namespace cloud_keys_detail;
    requireSuperAdmin(actor, channel, "forget the account recovery key pin");
    if (channel != Channel::Cli) throw Denied("the account recovery key pin is forgotten only with the local vh CLI");
    std::scoped_lock lock(checkMutex);
    if (const auto vaults = managedVaults(); !vaults.empty()) {
        std::string list;
        for (const auto v : vaults) list += (list.empty() ? "" : ", ") + std::to_string(v);
        throw Conflict("vault(s) " + list + " still hold a recovery grant that rests on the pin; revoke them first "
                       "(`vh vault keys recipient revoke`), so no vault loses a recovery path silently");
    }
    Forgotten out{.generations = static_cast<unsigned int>(AccountKeys::list("").size())};
    AccountKeys::clear();
    ::vh::cloud::pin::destroy();
    audit("cloud.key.forget", ::vh::audit::Outcome::Success, &actor, {{"generations", out.generations}},
          fmt::format("{} forgot the account recovery key pin ({} generation(s)); the next link asks for a confirmation "
                      "again", actor->name(), out.generations));
    return out;
}

std::optional<PinnedKey> pinnedKey() {
    using namespace cloud_keys_detail;
    const auto row = linkedRow();
    if (!row || !row->account_public_id) return std::nullopt;
    const auto checked = ::vh::cloud::pin::load(*row->account_public_id);
    if (!checked.ok())
        throw Refused("cloud_account_key_tampered", "a stored account key row fails its integrity check; nothing is "
                                                    "wrapped to the account key (`vh cloud key status`)");
    const auto* p = checked.pinned();
    if (!p) return std::nullopt;
    return PinnedKey{.account_public_id = p->account_public_id, .generation = p->generation,
                     .x25519_public = p->x25519_public, .fingerprint = p->fingerprint,
                     .confirmed_by = p->confirmed_by.value_or("?"), .statement = p->statement};
}

void applyPolicy(const unsigned int vaultId) noexcept {
    using namespace cloud_keys_detail;
    try {
        const auto row = linkedRow();
        if (!row || !row->account_public_id) return;
        std::scoped_lock lock(checkMutex);
        const auto checked = ::vh::cloud::pin::load(*row->account_public_id);
        if (!checked.ok() || !checked.pinned()) return;
        (void)applyToVault(vaultId, *checked.pinned());
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[ops::cloud_keys] Vault {}: applying the account recovery policy failed: {}",
                                      vaultId, e.what());
    }
}

std::optional<HealthIssue> health() {
    const auto all = ::vh::cloud::pin::loadAll();
    if (!all.ok() && (!all.tampered.empty()))
        return HealthIssue{.code = "cloud_account_key_tampered",
                           .detail = "a stored account recovery key row fails its integrity check, so nothing is "
                                     "wrapped to the account key; `vh cloud key forget`, then confirm it again"};
    std::set<std::string> pinnedAccounts;
    for (const auto& r : all.rows)
        if (r.state == "pinned") pinnedAccounts.insert(r.account_public_id);
    for (const auto& r : all.rows)
        if (r.state == "refused" && pinnedAccounts.contains(r.account_public_id))
            return HealthIssue{.code = "cloud_account_key_change_pending",
                               .detail = "the account recovery key was replaced (generation " +
                                         std::to_string(r.generation) + "); this server keeps wrapping to its pin until "
                                         "a super admin confirms the new fingerprint (`vh cloud key confirm`)"};
    return std::nullopt;
}

nlohmann::json toJson(const Generation& g) {
    const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
    return {{"generation", g.generation},
            {"fingerprint", g.fingerprint},
            {"state", g.state},
            {"link", g.link},
            {"reason", g.reason},
            {"x25519_public", g.x25519_public},
            {"confirmed_by", opt(g.confirmed_by)},
            {"confirmed_at", g.confirmed_at ? nlohmann::json(static_cast<int64_t>(*g.confirmed_at)) : nlohmann::json(nullptr)}};
}

nlohmann::json toJson(const Status& s) {
    const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
    const auto time = [](const std::optional<std::time_t>& t) {
        return t ? nlohmann::json(static_cast<int64_t>(*t)) : nlohmann::json(nullptr);
    };
    auto generations = nlohmann::json::array();
    for (const auto& g : s.generations) generations.push_back(toJson(g));
    nlohmann::json policy = nullptr;
    if (s.policy) {
        auto recipients = nlohmann::json::array();
        for (const auto& r : s.policy->recipients) recipients.push_back({{"recipient_id", r.recipient_id}, {"label", r.label}});
        policy = {{"sequence", s.policy->sequence}, {"generation", s.policy->generation}, {"sha256", s.policy->sha256},
                  {"issued_at", s.policy->issued_at}, {"recipients", recipients}};
    }
    auto vaults = nlohmann::json::array();
    for (const auto& v : s.vaults)
        vaults.push_back({{"vault_id", v.vault_id}, {"vault_name", v.vault_name},
                          {"account_key_generation", opt(v.account_key_generation)}, {"policy_grants", v.policy_grants},
                          {"applied_sequence", opt(v.applied_sequence)}});
    return {{"state", s.state},
            {"account_public_id", opt(s.account_public_id)},
            {"pinned", s.pinned ? toJson(*s.pinned) : nlohmann::json(nullptr)},
            {"waiting", s.waiting ? toJson(*s.waiting) : nlohmann::json(nullptr)},
            {"generations", generations},
            {"policy", policy},
            {"vaults", vaults},
            {"offline_copy", s.offline_copy},
            {"offline_copy_at", time(s.offline_copy_at)},
            {"checked_at", time(s.checked_at)},
            {"check", opt(s.check)},
            {"check_detail", opt(s.check_detail)},
            {"issue", opt(s.issue)},
            {"next_step", opt(s.next_step)}};
}

nlohmann::json toJson(const Confirmed& c) {
    return {{"generation", toJson(c.generation)}, {"replacement", c.replacement}, {"vaults", c.vaults}};
}

bool offerPolicy(const std::string& policy, const std::string& signature, const std::string& source) noexcept {
    try {
        return cloud_keys_detail::offerPolicyImpl(policy, signature, source);
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[ops::cloud_keys] the recovery policy from {} wasn't considered: {}", source, e.what());
        return false;
    }
}

}
