#pragma once

#include "connector/Grants.hpp"
#include "db/query/connector/Connector.hpp"
#include "ops/Actor.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Remote connectors' switch, policy, clients and grants (design/core/mcp-remote-signin.md): `vh connector …` and ws
// connector.*. Off by default. Switching on, widening the policy and adding a client are super-admin decisions with a
// connector.trust step-up bound to exactly what changes (the CLI is the host: exempt, as for every Host call); turning
// off, narrowing and revoking never ask. Agents never reach any of it (`connector` is an MCP exclusion, and the
// Agent channel is refused here too). Every change is audited.
namespace vh::ops::connector {

enum class Channel { Cli, Web, Agent };

struct Status {
    db::query::connector::SettingsRow settings;
    std::size_t live_grants{};
    std::size_t clients{};
};

// Super admins.
[[nodiscard]] Status status(const Actor& actor);
// On at `url` (canonicalized: https, a host name, port 443). Step-up connector.enable:<origin> unless it is already
// on there. Audited connector.enable.
Status enable(const Actor& actor, Channel channel, const std::string& url);
// Off: every grant is revoked (switch_off). Audited connector.disable.
Status disable(const Actor& actor, Channel channel);

struct Policy {
    std::optional<std::string> max_scope{};                // read | write | destructive
    std::optional<bool> dcr_enabled{};
    std::optional<std::vector<std::string>> client_hosts{};  // empty: any https host
};
// Changes what is given; a change that widens anything (a higher max_scope, DCR on, a host allowlist cleared or grown)
// needs connector.trust connector.policy:<max_scope>:<dcr>:<hosts digest>. Live grants above a lowered max_scope are
// revoked (grantor_policy). Audited connector.policy.change.
Status setPolicy(const Actor& actor, Channel channel, const Policy& policy);

// The actor's grants; `all`: everyone's (super admins).
[[nodiscard]] std::vector<::vh::connector::Grant> listGrants(const Actor& actor, bool all);
// One grant by id or unique 8+ character prefix: its user or a super admin. NotFound otherwise.
::vh::connector::Grant revokeGrant(const Actor& actor, const std::string& idOrPrefix);
// Every live grant (super admins), or one user's (that user, or a super admin). Returns how many ended.
std::size_t revokeGrants(const Actor& actor, std::optional<uint32_t> userId);

// Super admins.
[[nodiscard]] std::vector<db::query::connector::ClientRow> listClients(const Actor& actor);
// An operator-registered client (kind registered, client id vhc_…): a name (1-64 characters) and 1-16 redirect URIs
// (urls::validRedirectUri). Step-up connector.client.add:<digest of name and URIs>. Audited connector.client.add.
db::query::connector::ClientRow addClient(const Actor& actor, Channel channel, const std::string& name,
                                          const std::vector<std::string>& redirectUris);
// Disables the client and revokes its grants (client_removed). Returns how many grants ended. Audited
// connector.client.remove.
std::size_t removeClient(const Actor& actor, Channel channel, const std::string& idOrPrefix);

[[nodiscard]] nlohmann::json toJson(const Status& s);
[[nodiscard]] nlohmann::json toJson(const ::vh::connector::Grant& g);
[[nodiscard]] nlohmann::json toJson(const db::query::connector::ClientRow& c);

}
