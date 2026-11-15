#include "cloud/Storage.hpp"

#include "cloud/Identity.hpp"
#include "db/query/cloud/Link.hpp"

#include <vl/keykit/base64url.hpp>
#include <vl/keykit/kit.hpp>
#include <vl/keykit/storage_credential.hpp>
#include <vl/keykit/uid.hpp>

#include <sodium.h>

#include <array>
#include <string_view>

namespace vh::cloud::storage {

// Named, not anonymous: the unity build joins this file with others.
namespace storage_client_detail {

using nlohmann::json;

std::optional<std::string> optString(const json& j, const char* key) {
    if (!j.is_object() || !j.contains(key) || j[key].is_null()) return std::nullopt;
    if (!j[key].is_string()) throw std::runtime_error(std::string("`") + key + "` isn't a string");
    return j[key].get<std::string>();
}

std::string reqString(const json& j, const char* key) {
    auto v = optString(j, key);
    if (!v) throw std::runtime_error(std::string("`") + key + "` is missing");
    return *v;
}

std::optional<int64_t> optInt(const json& j, const char* key) {
    if (!j.is_object() || !j.contains(key) || j[key].is_null()) return std::nullopt;
    if (!j[key].is_number_integer()) throw std::runtime_error(std::string("`") + key + "` isn't a whole number");
    return j[key].get<int64_t>();
}

bool optBool(const json& j, const char* key) {
    if (!j.is_object() || !j.contains(key) || j[key].is_null()) return false;
    if (!j[key].is_boolean()) throw std::runtime_error(std::string("`") + key + "` isn't true or false");
    return j[key].get<bool>();
}

// The vault uid a path names: what the cloud checks too (26 lower-case base32 symbols).
const std::string& checkedUid(const std::string& uid) {
    if (!vl::keykit::fromBase32(uid) || uid.size() != 26) throw std::invalid_argument("not a vault uid: " + uid);
    return uid;
}

[[noreturn]] void fail(const Reply& r) {
    std::string code, reason;
    if (r.body.is_object() && r.body.contains("error") && r.body["error"].is_object()) {
        const auto& e = r.body["error"];
        if (e.contains("code") && e["code"].is_string()) code = e["code"].get<std::string>();
        if (e.contains("reason") && e["reason"].is_string()) reason = e["reason"].get<std::string>();
    }
    throw CallError(r.status, code, reason, r.error.empty() ? "Vaulthalla Cloud answered HTTP " + std::to_string(r.status)
                                                            : r.error);
}

Reply call(const Linked& link, const std::string& method, const std::string& path,
           const std::optional<json>& body = std::nullopt) {
    auto r = signedCall(link.endpoint, link.installation, link.seed.bytes(), method, path, body);
    if (!r.ok()) fail(r);
    return r;
}

// ---- the contract's announced changes, one place each ----------------------------------------------------------------
namespace contract {

// Renamed to say it is the offline copy's confirmation: the old name until the cloud ships the new one.
bool offlineCopyConfirmedOf(const json& body) {
    for (const auto* name : {"offline_copy_confirmed", "account_key_offline_copy_confirmed", "account_key_confirmed"})
        if (body.is_object() && body.contains(name) && body[name].is_boolean()) return body[name].get<bool>();
    return false;
}

// The ejection portal's address: absent until the cloud returns it.
std::optional<std::string> ejectionPortalOf(const json& body) {
    for (const auto* name : {"ejection_portal_url", "eject_url"})
        if (body.is_object() && body.contains(name) && body[name].is_string()) {
            const auto url = body[name].get<std::string>();
            if (url.starts_with("https://")) return url;
        }
    if (body.is_object() && body.contains("ejection") && body["ejection"].is_object() &&
        body["ejection"].contains("portal_url") && body["ejection"]["portal_url"].is_string())
        return body["ejection"]["portal_url"].get<std::string>();
    return std::nullopt;
}

// Envelopes are base64 today and base64url once the cloud switches: either decodes.
std::optional<std::vector<uint8_t>> decodeEnvelope(const std::string& text) {
    if (auto url = vl::keykit::base64UrlDecode(text)) return url;
    return vl::keykit::base64Decode(text);
}

// Where a moved vault went: absent until the cloud lists it.
std::optional<std::string> movedToOf(const json& v) {
    if (!v.is_object() || !v.contains("moved_to") || v["moved_to"].is_null()) return std::nullopt;
    if (v["moved_to"].is_string()) return v["moved_to"].get<std::string>();
    if (v["moved_to"].is_object()) {
        const auto& m = v["moved_to"];
        if (m.contains("name") && m["name"].is_string()) return m["name"].get<std::string>();
        if (m.contains("deployment_id") && m["deployment_id"].is_string()) return m["deployment_id"].get<std::string>();
    }
    return std::string("another server");
}

}

VaultStorage parseVault(const json& v) {
    if (!v.is_object()) throw std::runtime_error("a vault entry isn't an object");
    VaultStorage out;
    out.vault_uid = reqString(v, "vault_uid");
    out.enabled = optBool(v, "enabled");
    out.state = optString(v, "state").value_or("none");
    out.reason = optString(v, "reason");
    out.bucket = optString(v, "bucket");
    out.bucket_id = optString(v, "bucket_id");
    out.s3_endpoint = optString(v, "s3_endpoint");
    out.region = optString(v, "region");
    if (const auto d = optInt(v, "content_retention_days"); d && *d >= 1 && *d <= 36500)
        out.content_retention_days = static_cast<uint32_t>(*d);
    if (const auto t = optInt(v, "detached_at")) out.detached_at = static_cast<std::time_t>(*t);
    if (const auto t = optInt(v, "converted_at")) out.converted_at = static_cast<std::time_t>(*t);
    out.moved_to = contract::movedToOf(v);
    for (const auto* list : {"replicas", "former_replicas"})
        if (v.contains(list) && v[list].is_array())
            for (const auto& r : v[list]) {
                if (!r.is_object()) continue;
                VaultStorage::Replica rep{.deployment_id = optString(r, "deployment_id").value_or(""),
                                          .name = optString(r, "name").value_or(""),
                                          .node_id = optString(r, "node_id"),
                                          .reason = optString(r, "reason")};
                (std::string_view(list) == "replicas" ? out.replicas : out.former_replicas).push_back(std::move(rep));
            }
    if (v.contains("removed") && v["removed"].is_object())
        out.removed_reason = optString(v["removed"], "reason").value_or("owner");
    if (v.contains("credential") && v["credential"].is_object()) {
        const auto& k = v["credential"];
        out.key_state = optString(k, "state").value_or("none");
        out.key_id = optString(k, "key_id");
        out.key_access = optString(k, "access");
    }
    return out;
}

}

CallError::CallError(const long status, std::string code, std::string reason, const std::string& message)
    : std::runtime_error(message), status_(status), code_(std::move(code)), reason_(std::move(reason)) {}

std::optional<Linked> linked() {
    const auto row = db::query::cloud::Link::get();
    if (!row || row->status != "linked" || !row->installation_id) return std::nullopt;
    auto seed = identity::load();
    if (!seed) return std::nullopt;
    return Linked{.endpoint = endpoint(row->endpoint), .installation = *row->installation_id, .seed = std::move(*seed)};
}

Overview parseOverview(const nlohmann::json& body) {
    namespace d = storage_client_detail;
    if (!body.is_object()) throw std::runtime_error("GET /v1/storage didn't answer an object");
    Overview out;
    if (body.contains("entitlement") && body["entitlement"].is_object()) {
        const auto& e = body["entitlement"];
        out.entitlement.state = d::optString(e, "state");
        out.entitlement.plan = d::optString(e, "plan").value_or("");
        out.entitlement.storage_quota_bytes = static_cast<uint64_t>(std::max<int64_t>(0, d::optInt(e, "storage_quota_bytes").value_or(0)));
        out.entitlement.storage_access = d::optString(e, "storage_access").value_or("none");
        out.entitlement.cause = d::optString(e, "cause").value_or("");
    }
    if (out.entitlement.storage_access != "full" && out.entitlement.storage_access != "read_delete" &&
        out.entitlement.storage_access != "none")
        throw std::runtime_error("unknown storage_access '" + out.entitlement.storage_access + "'");
    if (body.contains("usage") && body["usage"].is_object()) {
        if (const auto b = d::optInt(body["usage"], "stored_bytes"); b && *b >= 0) out.stored_bytes = static_cast<uint64_t>(*b);
        out.usage_date = d::optString(body["usage"], "date");
    }
    out.offline_copy_confirmed = d::contract::offlineCopyConfirmedOf(body);
    out.ejection_portal = d::contract::ejectionPortalOf(body);
    out.ejection = body.contains("ejection") ? body["ejection"] : nlohmann::json(nullptr);
    out.provider = d::optString(body, "provider").value_or("");
    if (body.contains("vaults") && body["vaults"].is_array())
        for (const auto& v : body["vaults"]) out.vaults.push_back(d::parseVault(v));
    return out;
}

Overview overview(const Linked& link) {
    namespace d = storage_client_detail;
    const auto r = d::call(link, "GET", "/v1/storage");
    try {
        return parseOverview(r.body);
    } catch (const std::runtime_error& e) {
        throw CallError(r.status, "malformed", "", std::string("GET /v1/storage: ") + e.what());
    }
}

nlohmann::json billing(const Linked& link) {
    namespace d = storage_client_detail;
    const auto r = d::call(link, "GET", "/v1/billing");
    return r.body.is_object() ? r.body : nlohmann::json(nullptr);
}

bool registerVault(const Linked& link, const std::string& vaultUid, const uint32_t originVaultId) {
    namespace d = storage_client_detail;
    const auto r = d::call(link, "POST", "/v1/vaults",
                           nlohmann::json{{"vault_uid", d::checkedUid(vaultUid)}, {"origin_vault_id", originVaultId}});
    return r.status == 201;
}

void putLabel(const Linked& link, const std::string& vaultUid, const std::vector<uint8_t>& sealedLabel) {
    namespace d = storage_client_detail;
    (void)d::call(link, "PUT", "/v1/vaults/" + d::checkedUid(vaultUid) + "/label",
                  nlohmann::json{{"label", vl::keykit::base64UrlEncode(sealedLabel)}});
}

VaultStorage setVault(const Linked& link, const std::string& vaultUid, const std::optional<bool> enabled,
                      const std::optional<uint32_t> retentionDays) {
    namespace d = storage_client_detail;
    nlohmann::json body = nlohmann::json::object();
    if (enabled) body["enabled"] = *enabled;
    if (retentionDays) body["content_retention_days"] = *retentionDays;
    const auto r = d::call(link, "PUT", "/v1/storage/vaults/" + d::checkedUid(vaultUid), body);
    try {
        return d::parseVault(r.body);
    } catch (const std::runtime_error& e) {
        throw CallError(r.status, "malformed", "", std::string("PUT /v1/storage/vaults: ") + e.what());
    }
}

Credential requestCredential(const Linked& link, const std::string& vaultUid) {
    namespace d = storage_client_detail;
    const auto uid = vl::keykit::fromBase32(d::checkedUid(vaultUid));
    // The one-time key pair: the private half stays in locked memory and is wiped when this returns.
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> pk{};
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> skBytes{};
    crypto_box_keypair(pk.data(), skBytes.data());
    const vl::keykit::SecretBytes sk(skBytes);
    sodium_memzero(skBytes.data(), skBytes.size());

    const auto r = d::call(link, "POST", "/v1/storage/vaults/" + vaultUid + "/credentials",
                           nlohmann::json{{"public_key", vl::keykit::base64UrlEncode(pk)}});
    Credential out;
    std::optional<std::vector<uint8_t>> sealed;
    try {
        out.key_id = d::reqString(r.body, "key_id");
        out.access = d::reqString(r.body, "access");
        out.bucket = d::reqString(r.body, "bucket");
        out.bucket_id = d::optString(r.body, "bucket_id").value_or("");
        out.s3_endpoint = d::reqString(r.body, "s3_endpoint");
        out.region = d::optString(r.body, "region").value_or("");
        sealed = vl::keykit::base64UrlDecode(d::reqString(r.body, "sealed_secret"));
    } catch (const std::runtime_error& e) {
        throw CallError(r.status, "malformed", "", std::string("the credential answer is malformed: ") + e.what());
    }
    if (out.access != "full" && out.access != "read_delete")
        throw CallError(r.status, "malformed", "", "the credential answer names an unknown access '" + out.access + "'");
    if (!sealed) throw CallError(r.status, "malformed", "", "the sealed secret isn't base64url");
    try {
        out.secret = vl::keykit::credential::open(
            *sealed, sk.bytes(), {.installation_id = link.installation, .vault_uid = *uid, .key_id = out.key_id});
    } catch (const vl::keykit::credential::Error& e) {
        throw CallError(r.status, "sealed_credential", std::string(vl::keykit::credential::errorCodeName(e.code())),
                        "the bucket key didn't open for this server, vault and key id (" +
                            std::string(vl::keykit::credential::errorCodeName(e.code())) + ")");
    } catch (const std::invalid_argument& e) {
        throw CallError(r.status, "sealed_credential", "bad_context", std::string("the bucket key didn't open: ") + e.what());
    }
    return out;
}

bool leaveReplica(const Linked& link, const std::string& vaultUid) {
    namespace d = storage_client_detail;
    const auto r = signedCall(link.endpoint, link.installation, link.seed.bytes(), "DELETE",
                              "/v1/vaults/" + d::checkedUid(vaultUid) + "/replica");
    if (r.status == 404) return false;
    if (!r.ok()) d::fail(r);
    return true;
}

void acknowledge(const Linked& link, const std::string& keyId) {
    namespace d = storage_client_detail;
    if (keyId.empty() || keyId.size() > 128 || keyId.find_first_of("/?#% ") != std::string::npos)
        throw std::invalid_argument("not a key id: " + keyId);
    (void)d::call(link, "POST", "/v1/storage/credentials/" + keyId + "/ack");
}

void reportDetached(const Linked& link, const std::string& vaultUid) {
    namespace d = storage_client_detail;
    (void)d::call(link, "POST", "/v1/storage/vaults/" + d::checkedUid(vaultUid) + "/detached");
}

void reportEjected(const Linked& link, const std::string& vaultUid) {
    namespace d = storage_client_detail;
    (void)d::call(link, "POST", "/v1/storage/vaults/" + d::checkedUid(vaultUid) + "/ejected");
}

Handoff billingHandoff(const Linked& link, const std::string& kind, const std::optional<std::string>& plan) {
    namespace d = storage_client_detail;
    nlohmann::json body{{"kind", kind}};
    if (plan) body["plan"] = *plan;
    const auto r = d::call(link, "POST", "/v1/billing/handoffs", body);
    Handoff out;
    try {
        out.url = d::reqString(r.body, "url");
        if (const auto t = d::optInt(r.body, "expires_at")) out.expires_at = static_cast<std::time_t>(*t);
    } catch (const std::runtime_error& e) {
        throw CallError(r.status, "malformed", "", std::string("the billing handoff is malformed: ") + e.what());
    }
    if (!out.url.starts_with("https://") && !out.url.starts_with("http://localhost") &&
        !out.url.starts_with("http://127.0.0.1"))
        throw CallError(r.status, "malformed", "", "the billing handoff isn't an https address");
    return out;
}

std::vector<CloudEnvelope> vaultEnvelopes(const Linked& link, const std::string& vaultUid) {
    namespace d = storage_client_detail;
    const auto r = d::call(link, "GET", "/v1/keys/vaults/" + d::checkedUid(vaultUid) + "/envelopes");
    std::vector<CloudEnvelope> out;
    if (!r.body.is_object() || !r.body.contains("envelopes") || !r.body["envelopes"].is_array())
        throw CallError(r.status, "malformed", "", "the envelopes answer is malformed");
    for (const auto& e : r.body["envelopes"]) {
        CloudEnvelope c;
        const auto version = d::optInt(e, "key_version");
        const auto generation = d::optInt(e, "generation");
        const auto bytes = d::contract::decodeEnvelope(d::optString(e, "envelope").value_or(""));
        if (!version || *version < 1 || !bytes) throw CallError(r.status, "malformed", "", "an envelope entry is malformed");
        c.key_version = static_cast<uint32_t>(*version);
        c.generation = static_cast<uint32_t>(generation.value_or(0));
        c.envelope = *bytes;
        out.push_back(std::move(c));
    }
    return out;
}

}
