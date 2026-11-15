#include "ops/Cloud.hpp"

#include "audit/Trail.hpp"
#include "cloud/Client.hpp"
#include "cloud/Identity.hpp"
#include "cloud/Signing.hpp"
#include "config/Registry.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/device/Device.hpp"
#include "identities/User.hpp"
#include "ops/CloudKeys.hpp"
#include "log/Registry.hpp"
#include "rbac/permission/admin/keys/Encryption.hpp"

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <chrono>

#include "ops/CloudStorage.hpp"

namespace vh::ops::cloud {

// Named, not anonymous: the unity build joins this file with others.
namespace cloud_ops_detail {

using vh::db::query::cloud::Link;
using vh::db::query::cloud::LinkRow;

void require(const Actor& actor, const Channel channel) {
    requireActor(actor);
    if (channel == Channel::Agent)
        throw Denied("Vaulthalla Cloud linking is never run by an agent; run `vh cloud` yourself");
    if (!actor->isSuperAdmin()) throw Denied("only a super admin can manage this server's Vaulthalla Cloud link");
}

vh::cloud::Endpoint configured() {
    try {
        return vh::cloud::endpoint(config::Registry::get().cloud.endpoint);
    } catch (const std::invalid_argument& e) {
        throw Invalid(e.what());
    }
}

std::string defaultName() {
    char host[256]{};
    if (gethostname(host, sizeof(host) - 1) != 0 || host[0] == '\0') return "Vaulthalla server";
    return host;
}

std::string checkedName(const std::optional<std::string>& input) {
    auto name = input.value_or(defaultName());
    name.erase(0, name.find_first_not_of(" \t"));
    name.erase(name.find_last_not_of(" \t") + 1);
    if (name.empty() || name.size() > 100 ||
        std::ranges::any_of(name, [](const unsigned char c) { return c < 0x20 || c == 0x7f; }))
        throw Invalid("the name is 1 to 100 printable characters");
    return name;
}

std::string text(const nlohmann::json& j, const char* key) {
    if (!j.is_object() || !j.contains(key) || !j[key].is_string())
        throw std::runtime_error(std::string("Vaulthalla Cloud's answer has no `") + key + "`");
    return j[key].get<std::string>();
}

[[noreturn]] void unreachable(const vh::cloud::Reply& r) { throw Refused("cloud_unreachable", r.error); }

vl::keykit::SecretBytes seedOrThrow() {
    auto seed = vh::cloud::identity::load();
    if (!seed) throw Refused("cloud_identity_lost", "this server's Vaulthalla Cloud identity key is gone or no longer "
                                                    "unseals; run `vh cloud unlink --force`, then link again");
    return std::move(*seed);
}

void forget() {
    Link::clear();
    vh::cloud::identity::destroy();
}

// The node id this server reports with a link request (device_node.node_id, a UUID string): 1 to 64 printable
// characters without spaces, as the cloud checks it (its account-model.md, "As built" 3).
std::string nodeIdForLink() {
    auto id = db::query::device::Devices::nodeId();
    if (id.empty() || id.size() > 64 ||
        std::ranges::any_of(id, [](const unsigned char c) { return c <= 0x20 || c >= 0x7f; }))
        throw std::runtime_error("this server's node id isn't 1 to 64 printable characters");
    return id;
}

bool isUuidText(const std::string& s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? s[i] != '-' : !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    }
    return true;
}

bool isBase32Id(const std::string& s) {
    static constexpr std::string_view kAlphabet = "0123456789abcdefghjkmnpqrstvwxyz";
    return s.size() == 26 && std::ranges::all_of(s, [](const char c) { return kAlphabet.find(c) != std::string_view::npos; });
}

// The account's public id and the deployment from a claim or GET /v1/installation answer. A value the cloud sends
// must be well formed; it may be missing (an older cloud), and the key check then can't run.
std::optional<std::string> accountPublicIdOf(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("account_public_id") || j["account_public_id"].is_null()) return std::nullopt;
    if (!j["account_public_id"].is_string() || !isUuidText(j["account_public_id"].get<std::string>()))
        throw std::runtime_error("Vaulthalla Cloud's answer has a malformed `account_public_id`");
    return j["account_public_id"].get<std::string>();
}

std::optional<std::string> deploymentIdOf(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("deployment_id") || j["deployment_id"].is_null()) return std::nullopt;
    if (!j["deployment_id"].is_string() || !isBase32Id(j["deployment_id"].get<std::string>()))
        throw std::runtime_error("Vaulthalla Cloud's answer has a malformed `deployment_id`");
    return j["deployment_id"].get<std::string>();
}

std::time_t parseExpiry(const nlohmann::json& j) {
    if (j.contains("expires_at") && j["expires_at"].is_number_integer()) return j["expires_at"].get<std::time_t>();
    return std::time(nullptr) + 600;
}

}

LinkStarted startLink(const Actor& actor, const Channel channel, const std::optional<std::string>& input) {
    using namespace cloud_ops_detail;
    require(actor, channel);
    const auto at = configured();
    const auto name = checkedName(input);
    if (const auto row = Link::get(); row && row->status == "linked")
        throw Conflict("this server is already linked (installation " + row->installation_id.value_or("?") +
                       "); `vh cloud unlink` first");

    const auto nodeId = nodeIdForLink();
    const auto seed = vh::cloud::identity::create();
    const auto pk = vh::cloud::publicKeyOf(seed.bytes());
    const auto pkText = vh::cloud::base64url(pk);
    // Proof of possession v2 (the cloud's installation-linking.md): covers the key, the name, the kind and the node id.
    const auto proof = vh::cloud::signDetached("vhc-link-request-v2\n" + pkText + "\n" + name + "\nserver\n" + nodeId,
                                               seed.bytes());
    const auto reply = vh::cloud::call(at, "POST", "/v1/link-requests",
                                       nlohmann::json{{"public_key", pkText}, {"name", name}, {"kind", "server"},
                                                      {"node_id", nodeId}, {"proof", proof}});
    if (!reply.ok()) {
        vh::cloud::identity::destroy();
        if (reply.status == 0) unreachable(reply);
        throw Refused("cloud_refused", "Vaulthalla Cloud refused the link request: " + reply.error);
    }
    LinkStarted out{.user_code = text(reply.body, "user_code"), .fingerprint = vh::cloud::fingerprint(pk), .name = name,
                    .endpoint = at.base, .expires_at = parseExpiry(reply.body)};
    LinkRow row{.endpoint = at.base, .status = "pending", .public_key = pk, .name = name,
                .request_id = text(reply.body, "request_id"), .request_expires_at = out.expires_at,
                .installation_id = std::nullopt, .account_id = std::nullopt, .requested_by = actor->name(),
                .requested_at = std::time(nullptr), .linked_at = std::nullopt};
    if (!Link::putPending(row)) throw Conflict("this server was linked meanwhile");
    ::vh::audit::record({.action = "cloud.link.request", .outcome = ::vh::audit::Outcome::Info, .actor_id = actor->id,
                   .actor = actor->name(), .details = {{"fingerprint", out.fingerprint}}},
                  "[ops::cloud] " + actor->name() + " asked to link this server to a Vaulthalla Cloud account (" +
                      at.base + ", key " + out.fingerprint + ")");
    return out;
}

Claim claimLink(const Actor& actor, const Channel channel) {
    using namespace cloud_ops_detail;
    require(actor, channel);
    const auto row = Link::get();
    if (!row || row->status != "pending" || !row->request_id) throw NotFound("no link request is pending (`vh cloud link`)");
    const auto at = vh::cloud::endpoint(row->endpoint);
    const auto seed = seedOrThrow();
    if (vh::cloud::publicKeyOf(seed.bytes()) != row->public_key)
        throw Refused("cloud_identity_lost", "the sealed identity key isn't the one this request was made with; run "
                                             "`vh cloud link` again");
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch()).count();
    const auto signature = vh::cloud::signDetached("vhc-link-claim-v1\n" + *row->request_id + "\n" + std::to_string(now),
                                                   seed.bytes());
    const auto reply = vh::cloud::call(at, "POST", "/v1/link-requests/" + *row->request_id + "/claim",
                                       nlohmann::json{{"timestamp", now}, {"signature", signature}});
    if (reply.status == 0) unreachable(reply);
    if (reply.status == 404 || reply.status == 410) {  // gone: treat as expired
        forget();
        return {.status = "expired", .installation_id = std::nullopt, .account_id = std::nullopt};
    }
    if (!reply.ok()) throw Refused("cloud_refused", "Vaulthalla Cloud refused the claim: " + reply.error);
    Claim out{.status = text(reply.body, "status"), .installation_id = std::nullopt, .account_id = std::nullopt};
    if (out.status == "linked") {
        out.installation_id = text(reply.body, "installation_id");
        if (!reply.body.contains("account_id") || !reply.body["account_id"].is_number_integer())
            throw std::runtime_error("Vaulthalla Cloud's answer has no `account_id`");
        out.account_id = reply.body["account_id"].get<int64_t>();
        out.deployment_id = deploymentIdOf(reply.body);
        out.account_public_id = accountPublicIdOf(reply.body);
        if (!Link::markLinked(*row->request_id, *out.installation_id, *out.account_id, out.deployment_id,
                              out.account_public_id))
            throw Conflict("the link request changed meanwhile");
        nlohmann::json details{{"installation_id", *out.installation_id}, {"account_id", *out.account_id}};
        if (out.deployment_id) details["deployment_id"] = *out.deployment_id;
        if (out.account_public_id) details["account_public_id"] = *out.account_public_id;
        ::vh::audit::record({.action = "cloud.link", .outcome = ::vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .details = details},
                      "[ops::cloud] this server is linked to Vaulthalla Cloud account " +
                          out.account_public_id.value_or(std::to_string(*out.account_id)) + " as installation " +
                          *out.installation_id);
        // The account recovery key is fetched and verified right away (design/cloud/key-manager.md, "Fetch"); a
        // failure changes nothing and the background check retries.
        try {
            (void)::vh::ops::cloud_keys::check("link");
        } catch (const std::exception& e) {
            log::Registry::vaulthalla()->warn("[ops::cloud] The account recovery key check after linking failed: {}", e.what());
        }
    } else if (out.status == "denied" || out.status == "expired") {
        forget();
        ::vh::audit::record({.action = "cloud.link.request", .outcome = ::vh::audit::Outcome::Denied, .actor_id = actor->id,
                       .actor = actor->name(), .details = {{"status", out.status}}},
                      "[ops::cloud] the Vaulthalla Cloud link request was " + out.status);
    } else if (out.status != "pending") {
        throw std::runtime_error("Vaulthalla Cloud answered an unknown link status '" + out.status + "'");
    }
    return out;
}

Status status(const Actor& actor) {
    using namespace cloud_ops_detail;
    requireActor(actor);
    if (!actor->isSuperAdmin()) throw Denied("only a super admin can see this server's Vaulthalla Cloud link");
    Status out;
    out.endpoint = config::Registry::get().cloud.endpoint;
    const auto row = Link::get();
    if (!row) return out;
    out.state = row->status;
    out.endpoint = row->endpoint;
    out.name = row->name;
    out.fingerprint = vh::cloud::fingerprint(row->public_key);
    out.requested_by = row->requested_by;
    out.installation_id = row->installation_id;
    out.account_id = row->account_id;
    out.deployment_id = row->deployment_id;
    out.account_public_id = row->account_public_id;
    out.linked_at = row->linked_at;
    out.request_expires_at = row->request_expires_at;
    if (row->status != "linked") return out;
    const auto seed = vh::cloud::identity::load();
    if (!seed) {
        out.cloud = "identity_lost";
        out.cloud_detail = "the identity key no longer unseals; `vh cloud unlink --force`, then link again";
        return out;
    }
    const auto reply = vh::cloud::signedCall(vh::cloud::endpoint(row->endpoint), *row->installation_id, seed->bytes(),
                                             "GET", "/v1/installation");
    if (reply.ok()) {
        out.cloud = "ok";
        // A link made before the cloud reported them: record them now (never replacing a recorded value).
        try {
            const auto publicId = accountPublicIdOf(reply.body);
            if (publicId && !row->account_public_id && Link::fillAccount(deploymentIdOf(reply.body), *publicId)) {
                out.account_public_id = publicId;
                out.deployment_id = deploymentIdOf(reply.body);
            } else if (publicId && row->account_public_id && *publicId != *row->account_public_id) {
                out.cloud = "account_mismatch";
                out.cloud_detail = "Vaulthalla Cloud now reports another account for this installation; nothing is "
                                   "wrapped to it. `vh cloud unlink`, then link again";
            }
        } catch (const std::exception& e) {
            out.cloud_detail = e.what();
        }
    } else if (reply.status == 401) {
        out.cloud = "revoked";
        out.cloud_detail = "Vaulthalla Cloud no longer accepts this server (unlinked on vaulthalla.cloud?); "
                           "`vh cloud unlink --force`, then link again";
    } else {
        out.cloud = "unreachable";
        out.cloud_detail = reply.error;
    }
    return out;
}

Unlinked unlink(const Actor& actor, const Channel channel, const bool force) {
    using namespace cloud_ops_detail;
    require(actor, channel);
    Unlinked out;
    const auto row = Link::get();
    if (!row) {
        vh::cloud::identity::destroy();  // a key left over from an interrupted link
        return out;
    }
    out.was = row->status;
    // Managed vaults keep their data in the account's buckets through keys this installation holds: unlinking would
    // revoke them, so it waits until each one is switched off, moved or ejected, unless forced.
    if (row->status == "linked" && !force) {
        const auto blocking = ops::cloud_storage::unlinkBlockers();
        if (!blocking.empty()) {
            std::string names;
            for (const auto& n : blocking) names += (names.empty() ? "" : ", ") + n;
            throw Refused("managed_vaults",
                          std::to_string(blocking.size()) + " vault(s) keep their data in managed storage (" + names +
                              "): switch them off first (`vh cloud storage disable <vault>`), or unlink with --force, "
                              "after which the account's service revokes this server's bucket keys");
        }
    }
    if (row->status == "linked") {
        const auto seed = vh::cloud::identity::load();
        if (seed) {
            const auto reply = vh::cloud::signedCall(vh::cloud::endpoint(row->endpoint), *row->installation_id,
                                                     seed->bytes(), "DELETE", "/v1/installation");
            out.cloud_revoked = reply.ok();
            if (!reply.ok() && reply.status != 401 && !force)
                throw Refused("cloud_unreachable", "Vaulthalla Cloud didn't confirm the unlink (" + reply.error +
                                                       "); try again, or `vh cloud unlink --force` and revoke this server "
                                                       "on vaulthalla.cloud");
        } else if (!force) {
            throw Refused("cloud_identity_lost", "the identity key no longer unseals, so this server can't revoke "
                                                 "itself; `vh cloud unlink --force`, then revoke it on vaulthalla.cloud");
        }
    }
    forget();
    ops::cloud_storage::onUnlinked();
    ::vh::audit::record({.action = "cloud.unlink", .outcome = ::vh::audit::Outcome::Success, .actor_id = actor->id,
                   .actor = actor->name(),
                   .details = {{"was", out.was}, {"cloud_revoked", out.cloud_revoked}, {"forced", force}}},
                  "[ops::cloud] " + actor->name() + " unlinked this server from Vaulthalla Cloud (" + out.was +
                      (out.cloud_revoked ? ", revoked in the cloud" : ", not confirmed by the cloud") + ")");
    return out;
}

LinkStatus linkStatus(const Actor& actor) {
    requireActor(actor);
    LinkStatus out;
    const auto row = cloud_ops_detail::Link::get();
    out.linked = row && row->status == "linked";
    if (!actor->isSuperAdmin() && !actor->encryptionKeysPerms().canView() && !actor->cloudPerms().canView()) return out;
    out.detailed = true;
    if (!out.linked) return out;
    out.installation_id = row->installation_id;
    out.deployment_id = row->deployment_id;
    out.account_public_id = row->account_public_id;
    try {
        if (const auto pinned = ::vh::ops::cloud_keys::pinnedKey()) {
            out.account_key_generation = pinned->generation;
            out.account_key_fingerprint = pinned->fingerprint;
        }
    } catch (const Refused&) {
        // A tampered pin shows as none here; cloud.key.status says why.
    }
    return out;
}

nlohmann::json toJson(const LinkStatus& s) {
    nlohmann::json out{{"linked", s.linked}};
    if (!s.detailed) return out;
    const auto opt = [](const auto& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); };
    out["installation_id"] = opt(s.installation_id);
    out["deployment_id"] = opt(s.deployment_id);
    out["account_public_id"] = opt(s.account_public_id);
    out["account_key"] = s.account_key_generation
                             ? nlohmann::json{{"generation", *s.account_key_generation},
                                              {"fingerprint", s.account_key_fingerprint.value_or("")}}
                             : nlohmann::json(nullptr);
    return out;
}

}
