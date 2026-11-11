#include "ops/Cloud.hpp"

#include "audit/Trail.hpp"
#include "cloud/Client.hpp"
#include "cloud/Identity.hpp"
#include "cloud/Signing.hpp"
#include "config/Registry.hpp"
#include "db/query/cloud/Link.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"

#include <unistd.h>

#include <algorithm>
#include <chrono>

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

crypto::SecretBytes seedOrThrow() {
    auto seed = vh::cloud::identity::load();
    if (!seed) throw Refused("cloud_identity_lost", "this server's Vaulthalla Cloud identity key is gone or no longer "
                                                    "unseals; run `vh cloud unlink --force`, then link again");
    return std::move(*seed);
}

void forget() {
    Link::clear();
    vh::cloud::identity::destroy();
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

    const auto seed = vh::cloud::identity::create();
    const auto pk = vh::cloud::publicKeyOf(seed.bytes());
    const auto pkText = vh::cloud::base64url(pk);
    const auto proof = vh::cloud::signDetached("vhc-link-request-v1\n" + pkText + "\n" + name + "\nserver", seed.bytes());
    const auto reply = vh::cloud::call(at, "POST", "/v1/link-requests",
                                       nlohmann::json{{"public_key", pkText}, {"name", name}, {"kind", "server"},
                                                      {"proof", proof}});
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
        if (!Link::markLinked(*row->request_id, *out.installation_id, *out.account_id))
            throw Conflict("the link request changed meanwhile");
        ::vh::audit::record({.action = "cloud.link", .outcome = ::vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(),
                       .details = {{"installation_id", *out.installation_id}, {"account_id", *out.account_id}}},
                      "[ops::cloud] this server is linked to Vaulthalla Cloud account " +
                          std::to_string(*out.account_id) + " as installation " + *out.installation_id);
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
    ::vh::audit::record({.action = "cloud.unlink", .outcome = ::vh::audit::Outcome::Success, .actor_id = actor->id,
                   .actor = actor->name(),
                   .details = {{"was", out.was}, {"cloud_revoked", out.cloud_revoked}, {"forced", force}}},
                  "[ops::cloud] " + actor->name() + " unlinked this server from Vaulthalla Cloud (" + out.was +
                      (out.cloud_revoked ? ", revoked in the cloud" : ", not confirmed by the cloud") + ")");
    return out;
}

}
