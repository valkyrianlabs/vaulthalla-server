#pragma once

#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/VaultRecover.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

// Replicated vaults, the server side (design/cloud/mirrors.md, "Join (server side)", "Leave"; design/sync/
// manifest-applier.md, "As built: the join"). Experimental: every call refuses unless sync.replicas.experimental is on
// (Refused "replicas_experimental"). Super admins only, from the local CLI or a paired device; never an agent or a
// browser session.
namespace vh::ops::vault_replicas {

using Channel = vault_keys::Channel;

// `vh vault join`: vault_recover in join mode (Request::join, set here): the same proofs, the database built from the
// manifest with nothing downloaded, and a first publish that adds this node to the root's writers and keeps the others.
[[nodiscard]] vault_recover::Result join(const Actor& actor, vault_recover::Request request, Channel channel);
// The flag, the channel and the caller, before a join asks anyone for anything (a join --from-cloud checks them before
// its restore request, so the cloud never adds a replica this server would then refuse). Throws as join does.
void requireJoinAllowed(const Actor& actor, Channel channel);

struct LeaveResult {
    unsigned int vault_id{};
    std::optional<uint64_t> published_epoch{};   // the root without this node (nullopt: it was no writer any more)
    bool deleted_local{false};                   // scheduled for deletion here (the bucket untouched)
    std::string note{};
};
// `vh vault leave`: publishes a root without this node, turns the vault's sync off and keeps its copy here as it is,
// or deletes it from this server (never from the bucket). The last writer can't leave (Refused "last_writer"): it
// deletes or detaches the vault as a solo vault does. A server another one already removed only does the local part.
[[nodiscard]] LeaveResult leave(const Actor& actor, unsigned int vaultId, bool deleteLocal, Channel channel);

struct RemoveResult {
    unsigned int vault_id{};
    std::string node{};
    uint64_t published_epoch{};
    bool solo{false};   // this server is the vault's only writer now (it may rotate again)
    std::string cloud{};   // linked: what Vaulthalla Cloud's replica set says of that server (it stays the owner's)
};
// `vh vault replica remove`: a remaining writer drops another (a dead replica) from the root's writers. If that
// server is still running, its next publish is refused as superseded and it stops.
[[nodiscard]] RemoveResult removeReplica(const Actor& actor, unsigned int vaultId, const std::string& node,
                                         Channel channel);

[[nodiscard]] nlohmann::json toJson(const LeaveResult& r);
[[nodiscard]] nlohmann::json toJson(const RemoveResult& r);

}
