#include "ops/ReadGrants.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/openpgp/Gpg.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/permission/vault/sync/Action.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>
#include <vl/keykit/uid.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <set>

namespace vh::ops::read_grants {

namespace {

namespace padmin = storage::s3::provider::admin;
namespace pgp = crypto::openpgp;
using Query = db::query::vault::ReadGrants;
using SyncActionPerm = rbac::permission::vault::sync::SyncActionPermissions;
using FsAction = rbac::permission::vault::FilesystemAction;

constexpr const char* kPermission = "vault.sync.action.read_grants";

std::string rgIso(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::array<char, 32> buf{};
    (void)std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf.data();
}

nlohmann::json rgTime(const std::optional<std::time_t>& t) { return t ? nlohmann::json(rgIso(*t)) : nlohmann::json(nullptr); }

void requireLive(const Actor& actor) {
    requireActor(actor);
    if (!actor->authorizing()) throw Denied("your account is not active");
}

bool mayManage(const Actor& actor, const uint32_t vaultId) {
    if (actor->isSuperAdmin()) return true;
    return rbac::resolver::Vault::has<SyncActionPerm>(
        {.user = actor, .permission = SyncActionPerm::ReadGrants, .vault_id = vaultId});
}

void requireManage(const Actor& actor, const uint32_t vaultId) {
    if (!mayManage(actor, vaultId))
        throw Denied(std::string("read grants of vault ") + std::to_string(vaultId) + " need the " + kPermission +
                     " permission on it");
}

bool canFs(const Actor& actor, const uint32_t vaultId, const FsAction action) {
    if (actor->isSuperAdmin()) return true;
    return rbac::resolver::Vault::has<FsAction>({.user = actor, .permission = action, .vault_id = vaultId, .path = "/"});
}

void requireSuperAdmin(const Actor& actor, const char* what) {
    if (!actor->isSuperAdmin()) throw Denied(std::string(what) + " is for super admins: a pinned recipient can receive "
                                             "read grants of any vault");
}

std::string normalized(const std::string& fingerprint) {
    try {
        return pgp::normalizeFingerprint(fingerprint);
    } catch (const std::invalid_argument& e) {
        throw Invalid(std::string(e.what()) + ": '" + fingerprint + "'");
    }
}

std::string keyserverUrl(const std::string& given, const std::string& fingerprint) {
    if (!given.starts_with("https://")) throw Invalid("a keyserver URL must be https://");
    if (given.find_first_of(" \t\r\n") != std::string::npos) throw Invalid("the keyserver URL has whitespace in it");
    std::string upper = given;
    std::ranges::transform(upper, upper.begin(), [](const unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (upper.find(fingerprint) != std::string::npos) return given;   // already names the key by its fingerprint
    auto base = given;
    while (base.ends_with('/')) base.pop_back();
    return base + "/vks/v1/by-fingerprint/" + fingerprint;
}

std::string fetchKey(const std::string& url) {
    storage::s3::curl::http::Request request;
    request.method = "GET";
    request.url = url;
    request.timeout = std::chrono::seconds{30};
    request.max_response_bytes = 1024 * 1024;
    request.headers.emplace_back("Accept", "application/pgp-keys");
    const auto response = storage::s3::curl::http::perform(request);
    if (!response.transport_ok) throw Refused("keyserver_unreachable", "the keyserver could not be reached: " + response.transport_error);
    if (response.status == 404) throw Refused("keyserver_not_found", "the keyserver has no key with that fingerprint");
    if (!response.ok() || response.truncated)
        throw Refused("keyserver_refused", "the keyserver answered HTTP " + std::to_string(response.status));
    return response.body;
}

nlohmann::json documentFor(const Grant& grant, const nlohmann::json& gateway, const nlohmann::json& upstream,
                           const std::vector<std::string>& recipients, const std::optional<std::string>& vaultUid,
                           const std::optional<std::string>& upstreamOmitted) {
    nlohmann::json doc = {
        {"type", kDocumentType},
        {"version", kDocumentVersion},
        {"grant_id", grant.grant_id},
        {"issued_at", rgIso(grant.issued_at)},
        {"issued_by", grant.issued_by_name},
        {"recipients", recipients},
        {"vault", {{"id", grant.vault_id ? nlohmann::json(*grant.vault_id) : nlohmann::json(nullptr)},
                   {"name", grant.vault_name},
                   {"uid", vaultUid ? nlohmann::json(*vaultUid) : nlohmann::json(nullptr)}}},
        {"gateway", gateway},
        {"upstream", upstream},
    };
    if (upstreamOmitted) doc["upstream_omitted"] = *upstreamOmitted;
    return doc;
}

std::string gatewayEndpoint() {
    const auto& cfg = ::vh::config::Registry::get();
    if (!cfg.vaults.read_grants.gateway_endpoint.empty()) return cfg.vaults.read_grants.gateway_endpoint;
    return "http://" + cfg.s3_gateway.host + ":" + std::to_string(cfg.s3_gateway.port);
}

void wipe(std::string& s) {
    std::fill(s.begin(), s.end(), '\0');
    s.clear();
}

std::string actorLabel(const Actor& actor) { return actor->name() + " (user " + std::to_string(actor->id) + ")"; }

// The upstream half's provider client for an API key (decrypted), or why there is none.
std::unique_ptr<padmin::AdminClient> readKeyClient(const vault::model::APIKey& stored) {
    const auto& manager = runtime::Deps::get().apiKeyManager;
    if (!manager) throw std::runtime_error("the API key manager is not available");
    if (const auto why = padmin::adminUnsupportedReason(stored); !why.empty())
        throw Refused("upstream_unsupported", why + "; " + padmin::kReadKeysUnsupported);
    if (!stored.admin_enabled)
        throw Refused("upstream_unsupported",
                      "API key '" + stored.name + "' is not enabled for provider administration, which minting a read "
                      "key is (vh upstream admin enable " + stored.name + ")");
    auto client = padmin::adminFor(manager->getAPIKey(stored.id));
    if (!client || !client->supportsReadKeys())
        throw Refused("upstream_unsupported", padmin::kReadKeysUnsupported);
    return client;
}

void deleteGatewayCredential(const std::optional<uint32_t>& credentialId) {
    if (!credentialId) return;
    if (const auto c = db::query::s3::Gateway::getCredentialById(*credentialId))
        (void)db::query::s3::Gateway::deleteCredentialByAccessKey(c->access_key);
}

void audited(const std::string& action, const Actor& actor, const Grant& g, const std::string& message,
             const ::vh::audit::Outcome outcome = ::vh::audit::Outcome::Success, nlohmann::json extra = nlohmann::json::object()) {
    nlohmann::json details = {{"grant_id", g.grant_id}, {"gateway_only", g.gateway_only}};
    if (g.gateway_credential_id) details["gateway_credential_id"] = *g.gateway_credential_id;
    if (g.gateway_access_key) details["gateway_access_key_id"] = *g.gateway_access_key;
    if (g.upstream_key_id) details["upstream_key_id"] = *g.upstream_key_id;
    if (g.upstream_provider) details["upstream_provider"] = *g.upstream_provider;
    std::string fprs;
    for (const auto& f : g.recipients) fprs += (fprs.empty() ? "" : ",") + f;
    details["recipients"] = fprs;
    for (auto& [k, v] : extra.items()) details[k] = v;
    ::vh::audit::record({.action = action, .outcome = outcome, .actor_id = actor->id, .actor = actor->name(),
                   .vault_id = g.vault_id, .details = details},
                  "[read-grants] " + actor->name() + " " + message + " (grant " + g.grant_id + ")",
                  outcome == ::vh::audit::Outcome::Success ? spdlog::level::info : spdlog::level::warn);
}

}  // namespace

// ------------------------------------------------------------------------------------------------- recipients

std::vector<Recipient> listRecipients(const Actor& actor, const bool includeRemoved) {
    requireLive(actor);
    return Query::listRecipients(includeRemoved);
}

Recipient pinRecipient(const Actor& actor, const PinRequest& req) {
    requireLive(actor);
    requireSuperAdmin(actor, "pinning a read-grant recipient");
    const auto fingerprint = normalized(req.fingerprint);
    if (req.public_key.has_value() == req.keyserver.has_value())
        throw Invalid("give the recipient's public key (a file or standard input) or a keyserver URL, not both");
    if (req.label && req.label->size() > 200) throw Invalid("a recipient label is at most 200 characters");
    if (Query::liveRecipient(fingerprint)) throw Conflict("the key " + fingerprint + " is already pinned");

    Recipient r;
    r.fingerprint = fingerprint;
    r.label = req.label;
    std::string armored;
    if (req.keyserver) {
        r.source = "keyserver";
        r.source_url = keyserverUrl(*req.keyserver, fingerprint);
        armored = fetchKey(*r.source_url);
    } else {
        r.source = "input";
        armored = *req.public_key;
    }

    pgp::KeyInfo info;
    try {
        info = pgp::inspect(armored);
    } catch (const pgp::BadKey& e) {
        throw Refused("recipient_unusable", e.what());
    } catch (const pgp::Unavailable& e) {
        throw Refused("openpgp_unavailable", e.what());
    }
    // The pin is the fingerprint: a key that merely carries the right name or address is never enough.
    if (info.fingerprint != fingerprint)
        throw Refused("fingerprint_mismatch", "the key's fingerprint is " + info.fingerprint + ", not the expected " +
                                                  fingerprint + ": nothing was pinned");
    if (const auto why = info.unusableReason()) throw Refused("recipient_unusable", *why + ": nothing was pinned");

    r.user_ids = info.user_ids;
    r.algorithm = info.algorithm + (info.encryption_algorithms.empty() ? "" : "/" + info.encryption_algorithms.front());
    r.key_created_at = info.created_at ? std::make_optional(info.created_at) : std::nullopt;
    r.key_expires_at = info.expires_at;
    r.public_key = armored;
    r.pinned_by = actor->id;
    r.pinned_by_name = actor->name();

    auth::stepup::require(auth::stepup::Family::Secrets);
    const auto id = Query::pinRecipient(r);
    if (!id) throw Conflict("the key " + fingerprint + " is already pinned");
    auto pinned = Query::liveRecipient(fingerprint);
    if (!pinned) throw std::runtime_error("the pinned recipient is not readable");
    ::vh::audit::record({.action = "vault.read_grant.recipient.pin", .outcome = ::vh::audit::Outcome::Success, .actor_id = actor->id,
                   .actor = actor->name(),
                   .details = {{"fingerprint", fingerprint}, {"source", r.source}, {"algorithm", r.algorithm}}},
                  "[read-grants] " + actor->name() + " pinned read-grant recipient " + fingerprint);
    return *pinned;
}

RemovedRecipient removeRecipient(const Actor& actor, const std::string& fingerprintText) {
    requireLive(actor);
    requireSuperAdmin(actor, "removing a read-grant recipient");
    const auto fingerprint = normalized(fingerprintText);
    auto live = Query::liveRecipient(fingerprint);
    if (!live) throw NotFound("no pinned read-grant recipient has the fingerprint " + fingerprint);
    uint32_t liveGrants = 0;
    for (const auto& g : Query::list(std::nullopt, false))
        if (std::ranges::find(g.recipients, fingerprint) != g.recipients.end()) ++liveGrants;
    auth::stepup::require(auth::stepup::Family::Secrets);
    if (!Query::removeRecipient(fingerprint, actorLabel(actor)))
        throw NotFound("no pinned read-grant recipient has the fingerprint " + fingerprint);
    ::vh::audit::record({.action = "vault.read_grant.recipient.remove", .outcome = ::vh::audit::Outcome::Success,
                   .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"fingerprint", fingerprint}, {"live_grants", liveGrants}}},
                  "[read-grants] " + actor->name() + " removed read-grant recipient " + fingerprint);
    live->removed_at = std::time(nullptr);
    live->removed_by = actorLabel(actor);
    return {.recipient = *live, .live_grants = liveGrants};
}

// ------------------------------------------------------------------------------------------------- grants

Issued issue(const Actor& actor, const IssueRequest& req) {
    requireLive(actor);
    if (req.vault_id == 0) throw Invalid("a vault is required");
    const auto vault = db::query::vault::Vault::getVault(req.vault_id);
    if (!vault) throw NotFound("vault not found: " + std::to_string(req.vault_id));
    requireManage(actor, vault->id);
    // A grant never reaches further than its issuer: the gateway credential acts as the issuer.
    if (!canFs(actor, vault->id, FsAction::List) || !canFs(actor, vault->id, FsAction::Read))
        throw Denied("you can't list and read vault " + std::to_string(vault->id) +
                     " yourself, so you can't grant reading it");

    // Recipients: one or two distinct, pinned and still usable keys.
    if (req.recipients.empty()) throw Invalid("a read grant needs a recipient (--recipient <fingerprint>)");
    if (req.recipients.size() > 2) throw Invalid("a read grant is encrypted to one or two recipients");
    std::vector<Recipient> recipients;
    for (const auto& text : req.recipients) {
        const auto fpr = normalized(text);
        if (std::ranges::any_of(recipients, [&](const Recipient& r) { return r.fingerprint == fpr; }))
            throw Invalid("the recipient " + fpr + " is named twice");
        auto r = Query::liveRecipient(fpr);
        if (!r)
            throw Refused("recipient_not_pinned", "the key " + fpr + " is not a pinned read-grant recipient (a super "
                          "admin pins it: vh vault read-grant recipient add --fingerprint " + fpr + " …)");
        try {
            pgp::requireEncryptable(pgp::inspect(r->public_key));
        } catch (const pgp::BadKey& e) {
            throw Refused("recipient_unusable", std::string(e.what()) + "; pin a current key");
        } catch (const pgp::Unavailable& e) {
            throw Refused("openpgp_unavailable", e.what());
        }
        recipients.push_back(std::move(*r));
    }

    // The upstream half: only where objects upstream are readable as they are.
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    std::optional<std::string> upstreamOmitted;
    std::shared_ptr<vault::model::APIKey> apiKey;
    std::unique_ptr<padmin::AdminClient> client;
    if (vault->type != vault::model::VaultType::S3 || !s3) {
        if (!req.gateway_only)
            throw Refused("local_vault", "vault " + std::to_string(vault->id) + " is a local vault: it has no upstream "
                          "bucket to grant. Pass --gateway-only to issue the S3 gateway half alone");
        upstreamOmitted = "local_vault";
    } else if (s3->encrypt_upstream) {
        if (!req.gateway_only)
            throw Refused("upstream_encrypted", "vault " + std::to_string(vault->id) + " encrypts its objects upstream "
                          "(names and contents are unreadable without this server's keys), so an upstream key would "
                          "be useless to a recovery tool. Pass --gateway-only to issue the S3 gateway half alone");
        upstreamOmitted = "upstream_encrypted";
    } else if (req.gateway_only) {
        upstreamOmitted = "gateway_only";
    } else {
        apiKey = db::query::vault::APIKey::getAPIKey(s3->api_key_id);
        if (!apiKey) throw NotFound("the vault's API key is gone");
        client = readKeyClient(*apiKey);
        try {
            storage::upstream::guard::require(*apiKey, s3->bucket);
        } catch (const storage::upstream::BucketProtected& e) {
            throw Denied(e.what());
        }
    }

    // The gateway half needs the vault exposed by the gateway.
    std::optional<db::query::s3::BucketBinding> binding;
    for (const auto& b : db::query::s3::Gateway::listBuckets())
        if (b.vault_id == vault->id) {
            binding = b;
            break;
        }
    if (!binding)
        throw Refused("no_gateway_bucket", "vault " + std::to_string(vault->id) + " has no S3 gateway bucket; bind one "
                      "first (vh s3-gateway bucket bind <bucket> --vault " + std::to_string(vault->id) + ")");
    const auto reader = db::query::rbac::role::Vault::get("reader");
    if (!reader) throw std::runtime_error("the built-in vault role 'reader' is not seeded");

    // Reserve the slot (the limit is checked under the vault's lock).
    Grant grant;
    grant.grant_id = vl::keykit::toBase32(crypto::id::newObjectUid());
    grant.vault_id = vault->id;
    grant.vault_name = vault->name;
    grant.gateway_only = upstreamOmitted.has_value();
    grant.issued_by = actor->id;
    grant.issued_by_name = actor->name();
    grant.issued_at = std::time(nullptr);
    for (const auto& r : recipients) grant.recipients.push_back(r.fingerprint);
    std::vector<uint32_t> recipientIds;
    for (const auto& r : recipients) recipientIds.push_back(r.id);
    const auto max = ::vh::config::Registry::get().vaults.read_grants.max_per_vault;
    const auto rowId = Query::reserve(grant, recipientIds, max);
    if (!rowId)
        throw Refused("read_grant_limit", "vault " + std::to_string(vault->id) + " already holds " + std::to_string(max) +
                      " read grants that are not revoked (vaults.read_grants.max_per_vault); revoke one first");
    grant.row_id = *rowId;

    std::optional<uint32_t> credentialId;
    std::optional<padmin::ReadKey> readKey;
    // Undo what this call created; true when nothing is left behind.
    const auto rollBack = [&]() -> bool {
        bool clean = true;
        try {
            deleteGatewayCredential(credentialId);
        } catch (const std::exception&) {
            clean = false;
        }
        if (readKey) {
            try {
                client->deleteReadKey(readKey->key_id);
            } catch (const std::exception& e) {
                clean = false;
                Query::markRevocationIncomplete(grant.row_id, std::string("issue rolled back, but the upstream key "
                                                "could not be deleted: ") + e.what());
            }
        }
        if (clean) Query::discard(grant.row_id);
        return clean;
    };

    std::string plaintext;
    try {
        // 1. The gateway credential: read-only, this vault only, acting as the issuer.
        protocols::s3::CredentialCreateOptions options;
        options.created_by = actor->id;
        options.principal_user_id = actor->id;
        options.name = "read-grant-" + grant.grant_id;
        options.scope_mode = "vault_allowlist";
        options.description = "Vault read grant " + grant.grant_id + " (vault " + std::to_string(vault->id) + ")";
        options.default_vault_role_id = reader->id;
        options.selected_vault_ids = {vault->id};
        auto secret = protocols::s3::CredentialManager{}.createCredential(options);
        credentialId = secret.credential.id;
        grant.gateway_credential_id = secret.credential.id;
        grant.gateway_access_key = secret.credential.access_key;
        grant.gateway_bucket = binding->bucket_name;
        Query::recordGateway(grant.row_id, secret.credential.id, secret.credential.access_key, binding->bucket_name);

        const auto& cfg = ::vh::config::Registry::get();
        nlohmann::json gateway = {
            {"endpoint", gatewayEndpoint()},
            {"region", "us-east-1"},
            {"bucket", binding->bucket_name},
            {"addressing_style", cfg.s3_gateway.allow_path_style ? "path" : "virtual"},
            {"access_key_id", secret.credential.access_key},
            {"secret_access_key", secret.secret_access_key},
            {"credential_id", secret.credential.id},
            {"access", "read"},
        };
        wipe(secret.secret_access_key);

        // 2. The upstream key, restricted to the vault's bucket and read-only.
        nlohmann::json upstream = nullptr;
        if (client) {
            try {
                readKey = client->createReadKey({.bucket = s3->bucket, .key_name = "vh-read-" + grant.grant_id});
            } catch (const padmin::CapabilityMissing& e) {
                throw Refused("upstream_key_refused", std::string("the upstream key could not be created: ") + e.what());
            } catch (const padmin::ProviderError& e) {
                throw Refused("upstream_key_failed", std::string("the upstream key could not be created: ") + e.what());
            } catch (const storage::upstream::BucketProtected& e) {
                throw Denied(e.what());
            } catch (const std::invalid_argument& e) {
                throw Invalid(e.what());
            }
            grant.api_key_id = apiKey->id;
            grant.upstream_provider = client->providerId();
            grant.upstream_endpoint = readKey->endpoint;
            grant.upstream_region = readKey->region;
            grant.upstream_bucket = readKey->bucket;
            grant.upstream_key_id = readKey->key_id;
            grant.upstream_key_name = readKey->key_name;
            Query::recordUpstream(grant.row_id, apiKey->id, client->providerId(), readKey->endpoint, readKey->region,
                                  readKey->bucket, readKey->key_id, readKey->key_name);
            upstream = {
                {"provider", client->providerId()},
                {"endpoint", readKey->endpoint},
                {"region", readKey->region},
                {"bucket", readKey->bucket},
                {"bucket_id", readKey->bucket_id},
                {"addressing_style", "path"},
                {"access_key_id", readKey->key_id},
                {"secret_access_key", readKey->secret},
                {"key_name", readKey->key_name},
                {"capabilities", readKey->capabilities},
                {"objects_readable", true},
                {"storage_layout", std::string(vault::model::to_string(s3->storage_layout))},
            };
            wipe(readKey->secret);
        }

        // 3. One document, returned only encrypted.
        std::optional<std::string> uid;
        if (vault->uid) uid = vl::keykit::toBase32(*vault->uid);
        plaintext = documentFor(grant, gateway, upstream, grant.recipients, uid, upstreamOmitted).dump(2);
        gateway.clear();
        upstream.clear();
        std::vector<std::string> keys;
        for (const auto& r : recipients) keys.push_back(r.public_key);
        std::string ciphertext;
        try {
            ciphertext = pgp::encrypt(plaintext, keys);
        } catch (const pgp::BadKey& e) {
            throw Refused("recipient_unusable", e.what());
        } catch (const pgp::Unavailable& e) {
            throw Refused("openpgp_unavailable", e.what());
        }
        wipe(plaintext);

        Query::activate(grant.row_id, ciphertext);
        grant.state = "active";
        grant.ciphertext = ciphertext;
        audited("vault.read_grant.issue", actor, grant,
                "issued a read grant for vault " + std::to_string(vault->id) + (grant.gateway_only ? " (gateway only)" : ""));
        return {.grant = std::move(grant), .ciphertext = std::move(ciphertext)};
    } catch (...) {
        wipe(plaintext);
        const bool clean = rollBack();
        if (!clean)
            log::Registry::vaulthalla()->warn("[read-grants] issuing grant {} failed and its rollback is incomplete; "
                                              "`vh vault read-grant revoke {}` retries it", grant.grant_id, grant.grant_id);
        throw;
    }
}

std::vector<Grant> list(const Actor& actor, const std::optional<uint32_t> vaultId, const bool includeRevoked) {
    requireLive(actor);
    if (vaultId) {
        requireManage(actor, *vaultId);
        return Query::list(vaultId, includeRevoked);
    }
    auto all = Query::list(std::nullopt, includeRevoked);
    std::erase_if(all, [&](const Grant& g) {
        return g.vault_id ? !mayManage(actor, *g.vault_id) : !actor->isSuperAdmin();
    });
    return all;
}

Grant get(const Actor& actor, const std::string& grantId) {
    requireLive(actor);
    auto g = Query::get(grantId);
    if (!g) throw NotFound("no read grant has the id " + grantId);
    if (g->vault_id ? !mayManage(actor, *g->vault_id) : !actor->isSuperAdmin())
        throw NotFound("no read grant has the id " + grantId);
    return *g;
}

Grant revoke(const Actor& actor, const std::string& grantId) {
    auto g = get(actor, grantId);
    if (g.state == "revoked") throw Conflict("read grant " + grantId + " is already revoked");

    // 1. The gateway credential.
    deleteGatewayCredential(g.gateway_credential_id);
    if (g.gateway_credential_id) Query::clearGateway(g.row_id);
    g.gateway_credential_id.reset();

    // 2. The upstream key.
    if (g.upstream_key_id) {
        std::string failure;
        try {
            const auto key = g.api_key_id ? db::query::vault::APIKey::getAPIKey(*g.api_key_id) : nullptr;
            if (!key) {
                failure = "the API key that created the upstream key is gone; delete key " + *g.upstream_key_id +
                          " in the provider's console";
            } else {
                const auto& manager = runtime::Deps::get().apiKeyManager;
                if (!manager) throw std::runtime_error("the API key manager is not available");
                auto client = padmin::adminFor(manager->getAPIKey(key->id));
                if (!client) throw padmin::CapabilityMissing("read_keys", padmin::kReadKeysUnsupported);
                client->deleteReadKey(*g.upstream_key_id);
            }
        } catch (const padmin::ProviderError& e) {
            failure = e.what();
        } catch (const padmin::CapabilityMissing& e) {
            failure = e.what();
        } catch (const std::invalid_argument& e) {
            failure = e.what();
        }
        if (!failure.empty()) {
            const auto message = "the gateway credential is deleted, but the upstream key " + *g.upstream_key_id +
                                 " could not be: " + failure;
            Query::markRevocationIncomplete(g.row_id, message);
            g.state = "revocation_incomplete";
            g.revocation_error = message;
            audited("vault.read_grant.revoke", actor, g, "could not finish revoking a read grant", ::vh::audit::Outcome::Failure,
                    {{"state", "revocation_incomplete"}});
            throw Refused("revocation_incomplete", "read grant " + grantId + " is not revoked yet: " + message +
                                                       ". Run vh vault read-grant revoke " + grantId + " again");
        }
        Query::clearUpstream(g.row_id);
    }

    Query::markRevoked(g.row_id, actorLabel(actor));
    audited("vault.read_grant.revoke", actor, g, "revoked a read grant");
    return get(actor, grantId);
}

// ------------------------------------------------------------------------------------------------- JSON

nlohmann::json toJson(const Recipient& r) {
    return {{"fingerprint", r.fingerprint},
            {"label", r.label ? nlohmann::json(*r.label) : nlohmann::json(nullptr)},
            {"user_ids", r.user_ids},
            {"algorithm", r.algorithm},
            {"key_created_at", rgTime(r.key_created_at)},
            {"key_expires_at", rgTime(r.key_expires_at)},
            {"source", r.source},
            {"source_url", r.source_url ? nlohmann::json(*r.source_url) : nlohmann::json(nullptr)},
            {"pinned_by", r.pinned_by_name},
            {"pinned_at", rgIso(r.pinned_at)},
            {"removed_at", rgTime(r.removed_at)},
            {"removed_by", r.removed_by ? nlohmann::json(*r.removed_by) : nlohmann::json(nullptr)}};
}

nlohmann::json toJson(const Grant& g, const bool withCiphertext) {
    const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
    nlohmann::json j = {
        {"grant_id", g.grant_id},
        {"vault_id", opt(g.vault_id)},
        {"vault_name", g.vault_name},
        {"state", g.state},
        {"gateway_only", g.gateway_only},
        {"recipients", g.recipients},
        {"gateway", {{"credential_id", opt(g.gateway_credential_id)},
                     {"access_key_id", opt(g.gateway_access_key)},
                     {"bucket", opt(g.gateway_bucket)}}},
        {"upstream", g.upstream_provider
                         ? nlohmann::json{{"provider", *g.upstream_provider},
                                          {"endpoint", opt(g.upstream_endpoint)},
                                          {"region", opt(g.upstream_region)},
                                          {"bucket", opt(g.upstream_bucket)},
                                          {"key_id", opt(g.upstream_key_id)},
                                          {"key_name", opt(g.upstream_key_name)},
                                          {"api_key_id", opt(g.api_key_id)}}
                         : nlohmann::json(nullptr)},
        {"issued_by", g.issued_by_name},
        {"issued_at", rgIso(g.issued_at)},
        {"revoked_at", rgTime(g.revoked_at)},
        {"revoked_by", opt(g.revoked_by)},
        {"revocation_error", opt(g.revocation_error)},
    };
    if (withCiphertext) j["ciphertext"] = opt(g.ciphertext);
    return j;
}

}
