#include "ops/CloudRestore.hpp"

#include "audit/Trail.hpp"
#include "cloud/Client.hpp"
#include "cloud/Identity.hpp"
#include "crypto/SecretBytes.hpp"
#include "db/query/cloud/Link.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/kit.hpp>
#include <vl/keykit/uid.hpp>

#include <sodium.h>

#include <algorithm>
#include <map>
#include <mutex>

namespace vh::ops::cloud_restore {

// Named, not anonymous: the unity build joins this file with others.
namespace cloud_restore_detail {

namespace kev1 = vl::keykit::kev1;

// The temporary X25519 secrets of the restores this process asked for, by restore id: memory only, never stored.
struct Pending {
    crypto::SecretBytes secret;
    std::string vault_uid;
};
std::mutex& pendingMutex() {
    static std::mutex m;
    return m;
}
std::map<std::string, Pending>& pending() {
    static std::map<std::string, Pending> p;
    return p;
}

void forget(const std::string& id) {
    std::scoped_lock lock(pendingMutex());
    pending().erase(id);
}

struct Linked {
    vh::cloud::Endpoint endpoint;
    std::string installation;
    crypto::SecretBytes seed;
};

Linked linked() {
    const auto row = db::query::cloud::Link::get();
    if (!row || row->status != "linked" || !row->installation_id)
        throw Conflict("this server isn't linked to Vaulthalla Cloud: link it to the vault's account first "
                       "(`vh cloud link`)");
    auto seed = vh::cloud::identity::load();
    if (!seed) throw Refused("cloud_identity_lost", "this server's Vaulthalla Cloud identity key no longer unseals; "
                                                    "`vh cloud unlink --force`, then link again");
    return {.endpoint = vh::cloud::endpoint(row->endpoint), .installation = *row->installation_id, .seed = std::move(*seed)};
}

[[noreturn]] void refused(const vh::cloud::Reply& r) {
    if (r.status == 0) throw Refused("cloud_unreachable", r.error);
    if (r.status == 401)
        throw Refused("cloud_link_rejected", "Vaulthalla Cloud no longer accepts this server (`vh cloud status`)");
    if (r.status == 404) throw NotFound("Vaulthalla Cloud: " + r.error);
    if (r.status == 409) throw Conflict("Vaulthalla Cloud refused: " + r.error);
    throw Refused("cloud_refused", "Vaulthalla Cloud refused: " + r.error);
}

std::string b64(const std::span<const uint8_t> bytes) { return vl::keykit::base64Encode(bytes); }

std::vector<uint8_t> unb64(const nlohmann::json& j, const char* what) {
    if (!j.is_string()) throw Refused("cloud_restore_malformed", std::string("Vaulthalla Cloud sent a malformed ") + what);
    auto out = vl::keykit::base64Decode(j.get<std::string>());
    if (!out) throw Refused("cloud_restore_malformed", std::string("Vaulthalla Cloud sent a malformed ") + what);
    return std::move(*out);
}

// The checkpoint in the restore's records ({epoch, root_sha256}, or null). A malformed one refuses the restore rather
// than silently dropping the rollback bound.
std::optional<vl::keykit::KitCheckpoint> checkpointOf(const nlohmann::json& records) {
    if (!records.is_object() || !records.contains("checkpoint") || records.at("checkpoint").is_null()) return std::nullopt;
    const auto& c = records.at("checkpoint");
    const auto hex = [](const std::string& s) {
        return s.size() == 64 && std::ranges::all_of(s, [](const char ch) { return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'); });
    };
    if (!c.is_object() || !c.contains("epoch") || !c.at("epoch").is_number_unsigned() || !c.contains("root_sha256") ||
        !c.at("root_sha256").is_string() || !hex(c.at("root_sha256").get<std::string>()))
        throw Refused("cloud_restore_malformed", "Vaulthalla Cloud sent a malformed checkpoint; nothing was imported");
    return vl::keykit::KitCheckpoint{.epoch = c.at("epoch").get<uint64_t>(),
                                     .root_sha256 = c.at("root_sha256").get<std::string>(), .at = std::nullopt};
}

// The delivered bundle as a key export: each envelope opened with the temporary secret (it must be this vault's and
// the version it claims), with the key check and the origin node's attestation the cloud recorded at enrollment. The
// attestation carries its public key, which the restore pins (D1); vault_recover then requires every version to
// verify against the bucket's own manifest records too.
Delivered exportOf(const nlohmann::json& status, const Pending& p) {
    const auto uid = vl::keykit::fromBase32(p.vault_uid);
    if (!uid) throw Invalid("the vault uid isn't one");
    const auto& records = status.contains("records") ? status.at("records") : nlohmann::json::object();
    auto checkpoint = checkpointOf(records);  // before any key is opened: a refusal leaves nothing to wipe
    if (!status.contains("bundle") || !status.at("bundle").is_array() || status.at("bundle").empty())
        throw Refused("cloud_restore_malformed", "Vaulthalla Cloud delivered no keys");

    std::map<unsigned int, nlohmann::json> versionRecords;
    if (records.contains("key_versions") && records.at("key_versions").is_array())
        for (const auto& v : records.at("key_versions"))
            if (v.is_object() && v.contains("version") && v.at("version").is_number_unsigned())
                versionRecords[v.at("version").get<unsigned int>()] = v;
    std::map<unsigned int, std::string> anchors;
    if (records.contains("attestation_public_keys") && records.at("attestation_public_keys").is_array())
        for (const auto& k : records.at("attestation_public_keys"))
            if (k.is_object() && k.contains("key_id") && k.at("key_id").is_number_unsigned() && k.contains("public_key") &&
                k.at("public_key").is_string())
                anchors[k.at("key_id").get<unsigned int>()] = k.at("public_key").get<std::string>();

    std::map<unsigned int, nlohmann::json> entries;  // by version, ascending
    for (const auto& b : status.at("bundle")) {
        if (!b.is_object() || !b.contains("key_version") || !b.at("key_version").is_number_unsigned() ||
            !b.contains("envelope"))
            throw Refused("cloud_restore_malformed", "Vaulthalla Cloud sent a malformed bundle entry");
        const auto claimed = b.at("key_version").get<unsigned int>();
        const auto env = unb64(b.at("envelope"), "envelope");
        kev1::Unwrapped opened;
        try {
            opened = kev1::unwrap(env, p.secret.bytes(), kev1::Suite::X25519, *uid);
        } catch (const kev1::Error& e) {
            throw Refused("cloud_restore_unopenable", "a delivered key doesn't open with this restore's temporary key (" +
                                                          std::string(kev1::errorCodeName(e.code())) + "); nothing was "
                                                          "imported");
        }
        if (opened.key_version != claimed)
            throw Refused("cloud_restore_malformed", "a delivered key is for another version than the bundle says");
        nlohmann::json entry{{"key_version", claimed}, {"key", b64(opened.key.bytes())}};
        if (const auto r = versionRecords.find(claimed); r != versionRecords.end()) {
            if (r->second.contains("key_check") && r->second.at("key_check").is_string())
                entry["key_check"] = r->second.at("key_check");
            if (r->second.contains("attestation") && r->second.at("attestation").is_object()) {
                auto att = r->second.at("attestation");
                if (!att.contains("public_key") && att.contains("key_id") && att.at("key_id").is_number_unsigned())
                    if (const auto a = anchors.find(att.at("key_id").get<unsigned int>()); a != anchors.end())
                        att["public_key"] = a->second;
                entry["attestation"] = att;
            }
        }
        entries[claimed] = std::move(entry);
    }

    auto current = std::move(entries.rbegin()->second);
    const auto currentVersion = entries.rbegin()->first;
    entries.erase(currentVersion);
    nlohmann::json doc{{"vault_uid", p.vault_uid}, {"key", current.at("key")},
                       {"key_info", {{"key_version", currentVersion}}}};
    if (current.contains("key_check")) doc["key_check"] = current.at("key_check");
    if (current.contains("attestation")) doc["attestation"] = current.at("attestation");
    const auto& origin = records.contains("origin") ? records.at("origin") : nlohmann::json::object();
    if (origin.contains("node_id") && origin.at("node_id").is_string()) doc["node_id"] = origin.at("node_id");
    if (origin.contains("vault_id") && origin.at("vault_id").is_number_unsigned()) doc["vault_id"] = origin.at("vault_id");
    auto historical = nlohmann::json::array();
    for (auto& [_, e] : entries) historical.push_back(std::move(e));
    doc["historical_keys"] = std::move(historical);
    auto& currentKey = current.at("key").get_ref<std::string&>();
    sodium_memzero(currentKey.data(), currentKey.size());

    std::string deliverer = "a device";
    if (status.contains("deliverer") && status.at("deliverer").is_object() && status.at("deliverer").contains("name") &&
        status.at("deliverer").at("name").is_string())
        deliverer = status.at("deliverer").at("name").get<std::string>();
    return {.exported = std::move(doc), .checkpoint = std::move(checkpoint), .deliverer = std::move(deliverer),
            .versions = static_cast<unsigned int>(status.at("bundle").size())};
}

}

Started start(const Actor& actor, const std::string& vaultUid, const Channel channel) {
    using namespace cloud_restore_detail;
    vault_keys::requireKeyMaterialAccess(actor, channel, "recover_requires_device");
    if (!vl::keykit::fromBase32(vaultUid)) throw Invalid("--vault-uid is not a vault uid");
    auto link = linked();
    if (sodium_init() < 0) throw std::runtime_error("libsodium failed to initialise");
    auto secret = crypto::SecretBytes::random(kev1::kX25519KeySize);
    const auto pk = kev1::publicKeyOf(kev1::Suite::X25519, secret.bytes());
    const auto reply = vh::cloud::signedCall(link.endpoint, link.installation, link.seed.bytes(), "POST",
                                             "/v1/recovery/restores",
                                             nlohmann::json{{"vault_uid", vaultUid}, {"temporary_public_key", b64(pk)}});
    if (!reply.ok()) refused(reply);
    const auto& r = reply.body;
    if (!r.is_object() || !r.contains("id") || !r.at("id").is_string() || !r.contains("restore_code") ||
        !r.at("restore_code").is_string())
        throw Refused("cloud_restore_malformed", "Vaulthalla Cloud's answer has no restore id or code");
    Started out{.restore_id = r.at("id").get<std::string>(), .restore_code = r.at("restore_code").get<std::string>(),
                .expires_at = r.value("expires_at", std::time_t{0})};
    {
        std::scoped_lock lock(pendingMutex());
        pending().insert_or_assign(out.restore_id, Pending{.secret = std::move(secret), .vault_uid = vaultUid});
    }
    ::vh::audit::record({.action = "cloud.restore.request", .outcome = ::vh::audit::Outcome::Info,
                         .actor_id = actor->id, .actor = actor->name(),
                         .details = {{"restore_id", out.restore_id}, {"vault_uid", vaultUid}}},
                        "[ops::cloud_restore] " + actor->name() + " asked Vaulthalla Cloud to restore vault " + vaultUid +
                            " to this server (restore code " + out.restore_code + ")");
    return out;
}

std::optional<Delivered> poll(const Actor& actor, const std::string& restoreId) {
    using namespace cloud_restore_detail;
    requireActor(actor);
    auto link = linked();
    const auto reply = vh::cloud::signedCall(link.endpoint, link.installation, link.seed.bytes(), "GET",
                                             "/v1/recovery/restores/" + restoreId);
    if (!reply.ok()) refused(reply);
    const auto status = reply.body.is_object() ? reply.body.value("status", std::string()) : std::string();
    if (status == "requested" || status == "approved") return std::nullopt;
    if (status != "delivered") {
        forget(restoreId);
        throw Refused("cloud_restore_" + (status.empty() ? std::string("unknown") : status),
                      status == "denied" ? "the restore was denied on vaulthalla.cloud; nothing was imported"
                      : status == "expired" ? "the restore expired before a device delivered the keys"
                                            : "the restore is " + status + "; nothing was imported");
    }
    std::scoped_lock lock(pendingMutex());
    const auto p = pending().find(restoreId);
    if (p == pending().end())
        throw Refused("cloud_restore_key_gone", "this server no longer holds the restore's temporary key (the daemon "
                                                "restarted?); start the restore again");
    return exportOf(reply.body, p->second);
}

void complete(const Actor& actor, const std::string& restoreId) {
    using namespace cloud_restore_detail;
    requireActor(actor);
    forget(restoreId);
    auto link = linked();
    const auto reply = vh::cloud::signedCall(link.endpoint, link.installation, link.seed.bytes(), "POST",
                                             "/v1/recovery/restores/" + restoreId + "/complete", nlohmann::json::object());
    if (!reply.ok())
        log::Registry::audit()->warn("[ops::cloud_restore] Vaulthalla Cloud didn't confirm restore {} complete ({}); "
                                     "its bundle expires within a day", restoreId, reply.error);
    ::vh::audit::record({.action = "cloud.restore.complete", .outcome = ::vh::audit::Outcome::Success,
                         .actor_id = actor->id, .actor = actor->name(), .details = {{"restore_id", restoreId}}},
                        "[ops::cloud_restore] the keys Vaulthalla Cloud relayed for restore " + restoreId +
                            " were imported; the temporary key is gone");
}

void cancel(const Actor& actor, const std::string& restoreId) noexcept {
    using namespace cloud_restore_detail;
    try {
        forget(restoreId);
        auto link = linked();
        (void)vh::cloud::signedCall(link.endpoint, link.installation, link.seed.bytes(), "POST",
                                    "/v1/recovery/restores/" + restoreId + "/cancel", nlohmann::json::object());
        if (actor)
            ::vh::audit::record({.action = "cloud.restore.cancel", .outcome = ::vh::audit::Outcome::Info,
                                 .actor_id = actor->id, .actor = actor->name(), .details = {{"restore_id", restoreId}}},
                                "[ops::cloud_restore] restore " + restoreId + " was cancelled; its temporary key is gone");
    } catch (...) {
        // The restore expires on its own within a day; the temporary key is already gone.
    }
}

}
