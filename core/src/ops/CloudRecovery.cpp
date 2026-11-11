#include "ops/CloudRecovery.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "cloud/Client.hpp"
#include "cloud/Identity.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/cloud/RecoveryVault.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "sync/manifest/Store.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/kit.hpp>
#include <vl/keykit/uid.hpp>

#include <set>

namespace vh::ops::cloud_recovery {

// Named, not anonymous: the unity build joins this file with others.
namespace cloud_recovery_detail {

namespace kev1 = vl::keykit::kev1;
using db::query::cloud::Link;
using db::query::cloud::RecoveryVaults;

void requireView(const Actor& actor) {
    requireActor(actor);
    if (actor->isSuperAdmin() || actor->encryptionKeysPerms().canView()) return;
    throw Denied("only super admins or users with the view encryption keys permission can see cloud recovery");
}

void requireEnroll(const Actor& actor, const Channel channel) {
    requireActor(actor);
    if (!actor->isSuperAdmin() && !actor->encryptionKeysPerms().canExport())
        throw Denied("only super admins or users with the export encryption keys permission can enroll vaults in cloud "
                     "recovery");
    // Like a recovery recipient: a vault's recovery path is managed where key material is (D4).
    if (channel == Channel::Console)
        throw Refused("cloud_recovery_requires_device",
                      "cloud recovery is enrolled only through a paired device or the local vh CLI, never the browser");
    if (channel == Channel::Agent)
        throw Denied("cloud recovery is never enrolled by an agent; the human runs this in a terminal");
}

struct Linked {
    vh::cloud::Endpoint endpoint;
    std::string installation;
    crypto::SecretBytes seed;
};

Linked linked() {
    const auto row = Link::get();
    if (!row || row->status != "linked" || !row->installation_id)
        throw Conflict("this server isn't linked to Vaulthalla Cloud (`vh cloud link`)");
    auto seed = vh::cloud::identity::load();
    if (!seed) throw Refused("cloud_identity_lost", "this server's Vaulthalla Cloud identity key no longer unseals; "
                                                    "`vh cloud unlink --force`, then link again");
    return {.endpoint = vh::cloud::endpoint(row->endpoint), .installation = *row->installation_id, .seed = std::move(*seed)};
}

// A refusal for a reply that isn't 2xx (404 is the caller's).
[[noreturn]] void refused(const vh::cloud::Reply& r) {
    if (r.status == 0) throw Refused("cloud_unreachable", r.error);
    if (r.status == 401)
        throw Refused("cloud_link_rejected", "Vaulthalla Cloud no longer accepts this server (`vh cloud status`)");
    if (r.status == 403) throw Refused("cloud_allowance", "Vaulthalla Cloud refused: " + r.error);
    if (r.status == 409) throw Conflict("Vaulthalla Cloud refused: " + r.error);
    throw Refused("cloud_refused", "Vaulthalla Cloud refused: " + r.error);
}

std::shared_ptr<vault::model::Vault> liveVault(const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(vaultId));
    return vault;
}

vault_keys::KeyStatus keyStatus(const Actor& actor, const unsigned int vaultId) {
    auto list = vault_keys::status(actor, vaultId);
    if (list.empty()) throw NotFound("no key status for vault " + std::to_string(vaultId));
    return std::move(list.front());
}

nlohmann::json versionsJson(const vault_keys::KeyStatus& ks) {
    auto out = nlohmann::json::array();
    for (const auto& v : ks.needed_versions) {
        nlohmann::json attestation = nullptr;
        if (v.attestation) {
            attestation = {{"key_id", v.attestation->key_id}, {"signature", v.attestation->signature}};
            if (v.attestation->public_key) attestation["public_key"] = *v.attestation->public_key;
        }
        out.push_back({{"version", v.version},
                       {"key_check", v.key_check ? nlohmann::json(*v.key_check) : nlohmann::json(nullptr)},
                       {"attestation", attestation}});
    }
    return out;
}

// The envelopes of usable grants, read from the vault's bucket and checked against their records: the bucket is
// untrusted (anyone with write access could put an object there), so each one must have the kid its record names
// and be this vault's, for the version recorded.
std::vector<std::vector<uint8_t>> bucketEnvelopes(const vault::model::Vault& vault, const std::string& vaultUid) {
    std::set<std::string> usable;
    for (const auto& g : db::query::vault::RecoveryGrants::usable(vault.id)) usable.insert(g.grant_id);
    const auto uid = vl::keykit::fromBase32(vaultUid);
    if (!uid) throw std::runtime_error("vault " + std::to_string(vault.id) + " has a malformed uid");
    const auto store = vault::envelopes::storeFor(vault.id);
    std::vector<std::vector<uint8_t>> out;
    std::set<std::string> seen;
    for (const auto& e : db::query::vault::RecoveryGrants::envelopes(vault.id)) {
        if (!usable.contains(e.grant_id) || !seen.insert(e.kid).second) continue;
        const auto object = store->get(kev1::objectKey(e.kid));
        if (!object)
            throw Conflict("the recovery envelope " + e.kid + " of key version " + std::to_string(e.key_version) +
                           " is missing from the bucket; the next sync pass writes it again, then retry");
        const auto& bytes = object->bytes;
        try {
            const auto h = kev1::inspect(bytes);
            if (kev1::kid(bytes) != e.kid || h.vault_uid != *uid || h.key_version != e.key_version)
                throw Conflict("the bucket object for recovery envelope " + e.kid + " isn't the envelope this server "
                               "wrote (replaced?); nothing was sent");
        } catch (const kev1::Error& err) {
            throw Conflict("the bucket object for recovery envelope " + e.kid + " isn't a KEV1 envelope (" +
                           std::string(kev1::errorCodeName(err.code())) + "); nothing was sent");
        }
        out.push_back(bytes);
    }
    return out;
}

std::string uidPath(const std::string& vaultUid) { return "/v1/recovery/vaults/" + vaultUid; }

}

Enrolled enroll(const Actor& actor, const unsigned int vaultId, const Channel channel) {
    using namespace cloud_recovery_detail;
    requireEnroll(actor, channel);
    const auto vault = liveVault(vaultId);
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    if (!s3 || s3->bucket.empty())
        throw Conflict("vault '" + vault->name + "' has no bucket: cloud recovery holds the envelopes recovery "
                       "recipients get in a vault's bucket, so it is for S3 vaults");
    auto link = linked();
    const auto ks = keyStatus(actor, vaultId);
    if (!ks.vault_uid) throw Conflict("vault '" + vault->name + "' has no uid");
    if (ks.recovery.recipients == 0)
        throw Conflict("vault '" + vault->name + "' has no recovery recipient: cloud recovery keeps the envelopes "
                       "wrapped to your recipients, so add one first (`vh vault keys recipient add`)");
    if (!ks.recovery.uncovered_versions.empty()) {
        std::string list;
        for (const auto v : ks.recovery.uncovered_versions) list += (list.empty() ? "" : ", ") + std::to_string(v);
        throw Conflict("key version(s) " + list + " of vault '" + vault->name + "' have no recovery envelope yet; the "
                       "next sync pass writes them, then retry");
    }
    // Step-up (#359): a new place recovery records go. The host CLI is exempt; a paired device needs an approval.
    auth::stepup::require(auth::stepup::Family::Keys, "cloud.recovery.enroll:" + std::to_string(vaultId));

    const auto envelopes = bucketEnvelopes(*vault, *ks.vault_uid);
    auto encoded = nlohmann::json::array();
    for (const auto& e : envelopes) encoded.push_back(vl::keykit::base64Encode(e));
    auto anchors = nlohmann::json::array();
    for (const auto& k : ks.attestation_public_keys) anchors.push_back({{"key_id", k.key_id}, {"public_key", k.public_key}});
    nlohmann::json body{{"origin", {{"node_id", ks.node_id}, {"vault_id", vaultId}}},
                        {"attestation_public_keys", anchors},
                        {"key_versions", versionsJson(ks)},
                        {"envelopes", encoded}};
    if (ks.checkpoint) body["checkpoint"] = {{"epoch", ks.checkpoint->epoch}, {"root_sha256", ks.checkpoint->root_sha256}};

    const auto reply = vh::cloud::signedCall(link.endpoint, link.installation, link.seed.bytes(), "PUT",
                                             uidPath(*ks.vault_uid), body);
    if (!reply.ok()) refused(reply);
    const auto r = reply.body.is_object() ? reply.body : nlohmann::json::object();
    Enrolled out{.vault_id = vaultId, .vault_uid = *ks.vault_uid,
                 .created = r.value("created", false), .envelopes_sent = envelopes.size(),
                 .envelopes_added = r.value("envelopes_added", uint64_t{0}),
                 .versions_added = r.value("versions_added", uint64_t{0}),
                 .coverage = r.contains("coverage") ? r["coverage"] : nlohmann::json(nullptr)};
    RecoveryVaults::upsert({.vault_id = vaultId, .vault_uid = *ks.vault_uid, .installation_id = link.installation,
                            .enrolled_by = actor->name()});
    ::vh::audit::record({.action = "cloud.recovery.enroll", .outcome = ::vh::audit::Outcome::Success,
                         .actor_id = actor->id, .actor = actor->name(), .vault_id = vaultId,
                         .details = {{"created", out.created}, {"envelopes_sent", out.envelopes_sent},
                                     {"envelopes_added", out.envelopes_added}, {"versions_added", out.versions_added}}},
                        "[ops::cloud_recovery] " + actor->name() + (out.created ? " enrolled" : " updated") + " vault " +
                            std::to_string(vaultId) + " in Vaulthalla Cloud recovery (" +
                            std::to_string(out.envelopes_sent) + " envelope(s), no keys)");
    return out;
}

std::vector<VaultCoverage> status(const Actor& actor, const std::optional<unsigned int> vaultId) {
    using namespace cloud_recovery_detail;
    requireView(actor);
    std::vector<VaultCoverage> out;
    std::vector<db::query::cloud::RecoveryVaultRow> rows;
    if (vaultId) {
        if (auto row = RecoveryVaults::get(*vaultId)) rows.push_back(std::move(*row));
        else throw NotFound("vault " + std::to_string(*vaultId) + " isn't enrolled in cloud recovery from this server");
    } else {
        rows = RecoveryVaults::list();
    }
    if (rows.empty()) return out;
    std::optional<Linked> link;
    try {
        link = linked();
    } catch (const Error&) {
    }
    for (const auto& row : rows) {
        VaultCoverage c{.vault_id = row.vault_id, .vault_name = {}, .vault_uid = row.vault_uid,
                        .enrolled_at = row.enrolled_at, .last_upload_at = row.last_upload_at, .state = "unreachable",
                        .not_in_cloud = {}, .cloud = nullptr, .detail = std::nullopt};
        std::vector<unsigned int> needed;
        try {
            const auto ks = keyStatus(actor, row.vault_id);
            c.vault_name = ks.vault_name;
            for (const auto& v : ks.needed_versions) needed.push_back(v.version);
        } catch (const Error& e) {
            c.detail = e.what();
        }
        if (!link) {
            c.detail = "this server isn't linked to Vaulthalla Cloud (or its identity key is gone)";
            out.push_back(std::move(c));
            continue;
        }
        const auto reply = vh::cloud::signedCall(link->endpoint, link->installation, link->seed.bytes(), "GET",
                                                 uidPath(row.vault_uid));
        if (reply.status == 404) {
            c.state = "missing";
            c.detail = "Vaulthalla Cloud has no record of this vault (unenrolled elsewhere?); `vh cloud recovery enroll` "
                       "sends it again";
        } else if (!reply.ok()) {
            c.detail = reply.error;
        } else {
            c.cloud = reply.body;
            std::set<unsigned int> covered;
            if (reply.body.contains("versions") && reply.body["versions"].is_array())
                for (const auto& v : reply.body["versions"])
                    if (v.contains("recipients") && v["recipients"].is_array() && !v["recipients"].empty())
                        covered.insert(v.value("version", 0u));
            for (const auto v : needed)
                if (!covered.contains(v)) c.not_in_cloud.push_back(v);
            c.state = c.not_in_cloud.empty() ? "ready" : "behind";
            if (!c.not_in_cloud.empty())
                c.detail = "newer key versions aren't in the cloud yet; `vh cloud recovery enroll` sends them";
        }
        out.push_back(std::move(c));
    }
    return out;
}

void unenroll(const Actor& actor, const unsigned int vaultId, const Channel channel) {
    using namespace cloud_recovery_detail;
    requireEnroll(actor, channel);
    const auto row = RecoveryVaults::get(vaultId);
    if (!row) throw NotFound("vault " + std::to_string(vaultId) + " isn't enrolled in cloud recovery from this server");
    auto link = linked();
    auth::stepup::require(auth::stepup::Family::Keys, "cloud.recovery.unenroll:" + std::to_string(vaultId));
    const auto reply = vh::cloud::signedCall(link.endpoint, link.installation, link.seed.bytes(), "DELETE",
                                             uidPath(row->vault_uid));
    if (!reply.ok() && reply.status != 404) refused(reply);
    (void)RecoveryVaults::remove(vaultId);
    ::vh::audit::record({.action = "cloud.recovery.unenroll", .outcome = ::vh::audit::Outcome::Success,
                         .actor_id = actor->id, .actor = actor->name(), .vault_id = vaultId,
                         .details = {{"cloud_had_it", reply.status != 404}}},
                        "[ops::cloud_recovery] " + actor->name() + " unenrolled vault " + std::to_string(vaultId) +
                            " from Vaulthalla Cloud recovery; the cloud's records were deleted");
}

}
