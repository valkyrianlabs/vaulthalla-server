#pragma once

#include "ops/Actor.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// Vaulthalla Cloud linking (design/cloud/server-link.md, the operator page held until the service opens; valkyrianlabs/vaulthalla-cloud docs/design/installation-linking.md):
// this server as an installation of a vaulthalla.cloud account. Never required: nothing here runs, and nothing
// contacts the cloud, until a super admin asks. Super admins only; CLI only (`vh cloud`), and never an agent: linking
// decides which account this server's recovery records may later be sent to.
namespace vh::ops::cloud {

enum class Channel { Cli, Agent };

struct LinkStarted {
    std::string user_code;    // XXXX-XXXX: the account holder types it on vaulthalla.cloud
    std::string fingerprint;  // the identity key's: the approver compares it with the one the cloud shows
    std::string name;
    std::string endpoint;
    std::time_t expires_at = 0;
};
// Opens a link request with a fresh identity key (replacing a pending one), with proof of possession v2 over the key,
// the name, the kind and this server's node id (device_node). Conflict when already linked.
LinkStarted startLink(const Actor& actor, Channel channel, const std::optional<std::string>& name);

struct Claim {
    std::string status;  // pending | linked | denied | expired
    std::optional<std::string> installation_id;
    std::optional<int64_t> account_id;
    std::optional<std::string> deployment_id;
    std::optional<std::string> account_public_id;
};
// Asks the cloud whether the pending request was approved (signed by the identity key). On linked the link is
// recorded; on denied or expired the request and its key are discarded. NotFound when no request is pending.
Claim claimLink(const Actor& actor, Channel channel);

struct Status {
    std::string state = "unlinked";  // unlinked | pending | linked
    std::string endpoint;
    std::optional<std::string> name, fingerprint, installation_id, requested_by;
    std::optional<int64_t> account_id;
    std::optional<std::string> deployment_id, account_public_id;
    std::optional<std::time_t> linked_at, request_expires_at;
    // For a linked server, what the cloud says now (a signed GET /v1/installation): ok | revoked | unreachable.
    std::optional<std::string> cloud;
    std::optional<std::string> cloud_detail;
};
Status status(const Actor& actor);

// cloud.link.status: whether this server is linked, from the database only (no cloud call). Super admins and the
// encryption-key View permission see the identifiers and the pinned account key; any other signed-in user `linked`.
struct LinkStatus {
    bool linked = false;
    bool detailed = false;
    std::optional<std::string> installation_id, deployment_id, account_public_id;
    std::optional<uint32_t> account_key_generation;
    std::optional<std::string> account_key_fingerprint;
};
LinkStatus linkStatus(const Actor& actor);
[[nodiscard]] nlohmann::json toJson(const LinkStatus& s);

struct Unlinked {
    std::string was = "unlinked";  // what it was: unlinked | pending | linked
    bool cloud_revoked = false;    // the cloud confirmed the revocation
};
// Revokes the link in the cloud (a signed DELETE /v1/installation), then forgets it here: the row and the sealed
// key. When the cloud can't be reached the link stays, unless `force` (then the owner revokes it on vaulthalla.cloud).
Unlinked unlink(const Actor& actor, Channel channel, bool force);

}
