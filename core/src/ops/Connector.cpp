#include "ops/Connector.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "connector/Urls.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <set>

namespace vh::ops::connector {

// Named, not anonymous: the unity build joins this file with the other ops files.
namespace connector_ops_detail {

using Json = nlohmann::json;
namespace q = db::query::connector;
namespace grants = ::vh::connector;
using Effect = protocols::shell::CommandEffect;

constexpr std::size_t kMaxClientHosts = 32;
constexpr std::size_t kMaxRedirects = 16;

void requireSuperAdmin(const Actor& actor, const char* what) {
    requireActor(actor);
    if (!actor->isSuperAdmin()) throw Denied(std::string("only a super admin can ") + what);
}

void refuseAgent(const Channel channel) {
    if (channel == Channel::Agent)
        throw Denied("whether AI apps may connect to this server remotely is decided by a person, never an agent; run "
                     "`vh connector` yourself");
}

std::string digest16(const std::string& s) { return grants::digestOf(s).substr(7, 16); }

Status current() {
    Status s{.settings = q::Settings::get(), .live_grants = 0, .clients = 0};
    s.live_grants = q::Grants::listLive().size();
    for (const auto& c : q::Clients::list())
        if (c.live()) ++s.clients;
    return s;
}

Effect scopeOf(const std::string& name) {
    const auto e = vh::mcp::parseCeiling(name);
    if (!e) throw Invalid("a scope is read, write or destructive");
    return *e;
}

std::vector<std::string> canonicalHosts(const std::vector<std::string>& hosts) {
    if (hosts.size() > kMaxClientHosts) throw Invalid("at most 32 client hosts");
    std::set<std::string> out;
    for (const auto& h : hosts) {
        std::string lower(h);
        std::ranges::transform(lower, lower.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!grants::urls::isDnsName(lower)) throw Invalid("not a host name: " + h);
        out.insert(lower);
    }
    return {out.begin(), out.end()};
}

// Any host allowed by `next` that `prev` did not allow.
bool hostsWiden(const std::vector<std::string>& prev, const std::vector<std::string>& next) {
    if (next.empty()) return !prev.empty();
    if (prev.empty()) return false;
    return std::ranges::any_of(next, [&](const auto& h) { return std::ranges::find(prev, h) == prev.end(); });
}

void audit(const Actor& actor, const std::string& action, Json details, const std::string& message) {
    vh::audit::record({.action = action, .actor_id = actor->id, .actor = actor->name(), .details = std::move(details)},
                      "[ops::connector] " + actor->name() + " " + message);
}

// A grant by id or unique prefix (8+ characters) among `candidates`.
template<class T, class IdOf>
const T& byIdOrPrefix(const std::vector<T>& candidates, const std::string& key, IdOf idOf, const char* what) {
    const T* found = nullptr;
    for (const auto& c : candidates) {
        const auto& id = idOf(c);
        if (id == key) return c;
        if (key.size() >= 8 && id.starts_with(key)) {
            if (found) throw Invalid(std::string("more than one ") + what + " starts with " + key + ": give more of its id");
            found = &c;
        }
    }
    if (!found) throw NotFound(std::string("no such ") + what);
    return *found;
}

}

Status status(const Actor& actor) {
    namespace d = connector_ops_detail;
    d::requireSuperAdmin(actor, "see remote connectors");
    return d::current();
}

Status enable(const Actor& actor, const Channel channel, const std::string& url) {
    namespace d = connector_ops_detail;
    d::refuseAgent(channel);
    d::requireSuperAdmin(actor, "switch remote connectors on");
    std::string why;
    const auto origin = ::vh::connector::urls::canonicalOrigin(url, &why);
    if (!origin) throw Invalid(why);
    auto row = d::q::Settings::get();
    if (row.enabled && row.public_origin == *origin) return d::current();
    auth::stepup::require(auth::stepup::Family::ConnectorTrust, "connector.enable:" + *origin);
    row.enabled = true;
    row.public_origin = *origin;
    d::q::Settings::put(row, actor->id);
    d::audit(actor, "connector.enable", {{"origin", *origin}}, "switched remote connectors on at " + *origin);
    return d::current();
}

Status disable(const Actor& actor, const Channel channel) {
    namespace d = connector_ops_detail;
    d::refuseAgent(channel);
    d::requireSuperAdmin(actor, "switch remote connectors off");
    auto row = d::q::Settings::get();
    const bool was = row.enabled;
    row.enabled = false;
    if (was) d::q::Settings::put(row, actor->id);
    // Off means off: turning it on again never revives a forgotten connection.
    const auto ended = ::vh::connector::revokeAll(::vh::connector::Revocation::SwitchOff,
                                                 {.id = actor->id, .name = actor->name()});
    if (was || ended)
        d::audit(actor, "connector.disable", {{"grants_revoked", static_cast<int64_t>(ended)}},
                 "switched remote connectors off (" + std::to_string(ended) + " grant(s) ended)");
    return d::current();
}

Status setPolicy(const Actor& actor, const Channel channel, const Policy& p) {
    namespace d = connector_ops_detail;
    d::refuseAgent(channel);
    d::requireSuperAdmin(actor, "change the remote connector policy");
    const auto prev = d::q::Settings::get();
    auto next = prev;
    if (p.max_scope) next.max_scope = std::string(protocols::shell::effectName(d::scopeOf(*p.max_scope)));
    if (p.dcr_enabled) next.dcr_enabled = *p.dcr_enabled;
    if (p.client_hosts) next.client_hosts = d::canonicalHosts(*p.client_hosts);
    if (next.max_scope == prev.max_scope && next.dcr_enabled == prev.dcr_enabled && next.client_hosts == prev.client_hosts)
        return d::current();

    const auto prevScope = d::scopeOf(prev.max_scope);
    const auto nextScope = d::scopeOf(next.max_scope);
    const bool widened = nextScope > prevScope || (next.dcr_enabled && !prev.dcr_enabled) ||
                         d::hostsWiden(prev.client_hosts, next.client_hosts);
    std::string hosts;
    for (const auto& h : next.client_hosts) hosts += h + "\n";
    if (widened)
        auth::stepup::require(auth::stepup::Family::ConnectorTrust,
                              "connector.policy:" + next.max_scope + ":" + (next.dcr_enabled ? "1" : "0") + ":" +
                                  d::digest16(hosts));
    d::q::Settings::put(next, actor->id);
    std::size_t ended = 0;
    if (nextScope < prevScope)
        for (const auto& g : ::vh::connector::list())
            if (g.row.live() && g.scope > nextScope &&
                ::vh::connector::revoke(g.row.id, ::vh::connector::Revocation::GrantorPolicy,
                                        {.id = actor->id, .name = actor->name()}))
                ++ended;
    d::audit(actor, "connector.policy.change",
             {{"max_scope", next.max_scope}, {"dcr_enabled", next.dcr_enabled},
              {"client_hosts", static_cast<int64_t>(next.client_hosts.size())}, {"widened", widened},
              {"grants_revoked", static_cast<int64_t>(ended)}},
             "changed the remote connector policy (max scope " + next.max_scope + ", dynamic registration " +
                 (next.dcr_enabled ? "on" : "off") + ")");
    return d::current();
}

std::vector<::vh::connector::Grant> listGrants(const Actor& actor, const bool all) {
    namespace d = connector_ops_detail;
    requireActor(actor);
    if (all) {
        d::requireSuperAdmin(actor, "list every user's connected apps");
        return ::vh::connector::list();
    }
    return ::vh::connector::list(actor->id);
}

::vh::connector::Grant revokeGrant(const Actor& actor, const std::string& idOrPrefix) {
    namespace d = connector_ops_detail;
    requireActor(actor);
    const auto visible = actor->isSuperAdmin() ? ::vh::connector::list() : ::vh::connector::list(actor->id);
    const auto& g = d::byIdOrPrefix(visible, idOrPrefix, [](const auto& x) -> const std::string& { return x.row.id; },
                                    "connected app");
    if (!::vh::connector::revoke(g.row.id, ::vh::connector::Revocation::Manual, {.id = actor->id, .name = actor->name()}))
        throw Conflict("that connection had ended already");
    return *::vh::connector::get(g.row.id);
}

std::size_t revokeGrants(const Actor& actor, const std::optional<uint32_t> userId) {
    namespace d = connector_ops_detail;
    requireActor(actor);
    const ::vh::connector::Revoker by{.id = actor->id, .name = actor->name()};
    if (!userId) {
        d::requireSuperAdmin(actor, "end every user's connected apps");
        return ::vh::connector::revokeAll(::vh::connector::Revocation::Manual, by);
    }
    if (*userId != actor->id) d::requireSuperAdmin(actor, "end another user's connected apps");
    return ::vh::connector::revokeForUser(*userId, ::vh::connector::Revocation::Manual, by);
}

std::vector<db::query::connector::ClientRow> listClients(const Actor& actor) {
    namespace d = connector_ops_detail;
    d::requireSuperAdmin(actor, "list connector clients");
    return d::q::Clients::list();
}

db::query::connector::ClientRow addClient(const Actor& actor, const Channel channel, const std::string& name,
                                          const std::vector<std::string>& redirectUris) {
    namespace d = connector_ops_detail;
    d::refuseAgent(channel);
    d::requireSuperAdmin(actor, "register a connector client");
    if (name.empty() || name.size() > 64 ||
        std::ranges::any_of(name, [](const unsigned char c) { return c < 0x20 || c == 0x7f; }))
        throw Invalid("a client name is 1-64 characters, without control characters");
    if (redirectUris.empty() || redirectUris.size() > d::kMaxRedirects) throw Invalid("give 1-16 redirect URIs");
    std::string material = name;
    for (const auto& uri : redirectUris) {
        std::string why;
        if (!::vh::connector::urls::validRedirectUri(uri, &why)) throw Invalid(why + ": " + uri);
        material += std::string(1, '\0') + uri;
    }
    auth::stepup::require(auth::stepup::Family::ConnectorTrust, "connector.client.add:" + d::digest16(material));
    // The id is a public identifier, not a secret: random only so that it is never guessed into a collision.
    auto clientId = ::vh::connector::mintToken("vhc_");
    clientId.resize(4 + 22);
    const auto row = d::q::Clients::insert({.client_id = clientId, .kind = "registered", .name = name,
                                            .redirect_uris = redirectUris, .created_by = actor->id});
    d::audit(actor, "connector.client.add",
             {{"client_row", row.id}, {"kind", row.kind},
              {"redirect_host", ::vh::connector::urls::hostOf(redirectUris.front())},
              {"redirect_uris", static_cast<int64_t>(redirectUris.size())}},
             "registered a connector client (" + row.id.substr(0, 8) + ")");
    return row;
}

std::size_t removeClient(const Actor& actor, const Channel channel, const std::string& idOrPrefix) {
    namespace d = connector_ops_detail;
    d::refuseAgent(channel);
    d::requireSuperAdmin(actor, "remove a connector client");
    const auto clients = d::q::Clients::list();
    const auto& c = d::byIdOrPrefix(
        clients, idOrPrefix, [](const auto& x) -> const std::string& { return x.id; }, "client");
    if (!c.live()) throw Conflict("that client was removed already");
    (void)d::q::Clients::disable(c.id);
    std::size_t ended = 0;
    for (const auto& g : ::vh::connector::list())
        if (g.row.live() && g.row.client_row == c.id &&
            ::vh::connector::revoke(g.row.id, ::vh::connector::Revocation::ClientRemoved,
                                    {.id = actor->id, .name = actor->name()}))
            ++ended;
    d::audit(actor, "connector.client.remove",
             {{"client_row", c.id}, {"kind", c.kind}, {"grants_revoked", static_cast<int64_t>(ended)}},
             "removed a connector client (" + c.id.substr(0, 8) + ", " + std::to_string(ended) + " grant(s) ended)");
    return ended;
}

nlohmann::json toJson(const Status& s) {
    const auto& r = s.settings;
    nlohmann::json j{{"enabled", r.enabled},
                     {"public_origin", r.public_origin ? nlohmann::json(*r.public_origin) : nlohmann::json(nullptr)},
                     {"resource", r.public_origin ? nlohmann::json(*r.public_origin + "/mcp") : nlohmann::json(nullptr)},
                     {"max_scope", r.max_scope},
                     {"dcr_enabled", r.dcr_enabled},
                     {"client_hosts", r.client_hosts},
                     {"changed_by", r.changed_by ? nlohmann::json(*r.changed_by) : nlohmann::json(nullptr)},
                     {"changed_at", r.changed_at ? nlohmann::json(static_cast<int64_t>(*r.changed_at)) : nlohmann::json(nullptr)},
                     {"live_grants", s.live_grants},
                     {"clients", s.clients}};
    return j;
}

nlohmann::json toJson(const ::vh::connector::Grant& g) {
    const auto& r = g.row;
    const auto optTime = [](const std::optional<std::time_t>& t) {
        return t ? nlohmann::json(static_cast<int64_t>(*t)) : nlohmann::json(nullptr);
    };
    const auto optStr = [](const std::optional<std::string>& s) { return s ? nlohmann::json(*s) : nlohmann::json(nullptr); };
    return {{"id", r.id},
            {"user_id", r.user_id},
            {"client_id", r.client_id},
            {"client_name", r.client_name},
            {"client_host", ::vh::connector::urls::hostOf(r.client_id)},
            {"redirect_host", ::vh::connector::urls::hostOf(r.redirect_uri)},
            {"loopback", ::vh::connector::urls::isLoopbackRedirect(r.redirect_uri)},
            {"scope", r.scope},
            {"label", optStr(r.label)},
            {"created_at", static_cast<int64_t>(r.created_at)},
            {"expires_at", static_cast<int64_t>(r.expires_at)},
            {"last_used_at", optTime(r.last_used_at)},
            {"last_ip", optStr(r.last_ip)},
            {"revoked_at", optTime(r.revoked_at)},
            {"revoked_reason", optStr(r.revoked_reason)}};
}

nlohmann::json toJson(const db::query::connector::ClientRow& c) {
    return {{"id", c.id},
            {"client_id", c.client_id},
            {"kind", c.kind},
            {"name", c.name},
            {"redirect_uris", c.redirect_uris},
            {"created_by", c.created_by ? nlohmann::json(*c.created_by) : nlohmann::json(nullptr)},
            {"created_at", static_cast<int64_t>(c.created_at)},
            {"last_used_at", c.last_used_at ? nlohmann::json(static_cast<int64_t>(*c.last_used_at)) : nlohmann::json(nullptr)},
            {"disabled_at", c.disabled_at ? nlohmann::json(static_cast<int64_t>(*c.disabled_at)) : nlohmann::json(nullptr)}};
}

}
