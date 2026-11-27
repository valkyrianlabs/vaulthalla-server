#pragma once

#include "db/query/mirror/Pending.hpp"
#include "mirror/leave/Leave.hpp"
#include "mirror/versions/Versions.hpp"
#include "ops/Actor.hpp"
#include "storage/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

// Leaving a mirror, for a person (design/peers/mirror.md "Leaving a mirror", "Who may do it"; mirror/leave/Leave.hpp),
// shared by `vh mirror detach` and the ws mirror.detach commands. Server mirror phase 2, wave 5, piece A.
//
// Who may: a person (never an agent, a scoped or relayed device, a linked server's session: peer_forbidden) who is a
// super admin of this server or holds "Detach mirrored vaults" (admin.mirror.detach) through an admin role. The switch
// first (peers.experimental, else peers_experimental). The paths of missing files are shown only to such a person.
namespace vh::ops::mirrors {

// Throws Refused/Denied unless `actor` may detach mirrored vaults here.
void requireDetacher(const Actor& actor, const std::string& what);
// Whether `actor` may (no throw; agents and scoped sessions answer false).
[[nodiscard]] bool mayDetach(const Actor& actor);

// What detaching the vault would give, before anything happens (the export: its `missing` list).
[[nodiscard]] vh::mirror::leave::Preview detachPreview(const Actor& actor, uint32_t vaultId);

struct DetachRequest {
    uint32_t vault_id{};
    std::optional<std::string> owner{};         // a sign-in account here, by number or name; default the caller
    std::optional<std::string> confirm_name{};  // when given (the console), it must be the vault's name
};
// Turns the held copy into a standalone vault here (mirror::leave::detach). No step-up (design decision: nothing is
// destroyed or sent anywhere; the console asks for the vault's name to be typed). Audited mirror.detach.
[[nodiscard]] vh::mirror::leave::Detached detach(const Actor& actor, const DetachRequest& request);

// ---- versions on the mirror (mirror/versions/Versions.hpp)

struct VersionsRequest {
    uint32_t vault_id{};
    bool enabled{false};
    std::optional<unsigned int> keep_last{}, max_age_days{};   // 0: no limit of that kind
    std::optional<uint64_t> quota_bytes{};
};
// Keep versions of what the core replaces or deletes, for a vault this server holds as another server's mirror. Super
// admins of this server (a person). Audited mirror.versions.set.
[[nodiscard]] vh::mirror::versions::Setting setVersions(const Actor& actor, const VersionsRequest& request);
[[nodiscard]] nlohmann::json toJson(const vh::mirror::versions::Setting& s);

// ---- a held change's bytes (carried from wave 4)

struct HeldContent {
    db::query::mirror::HeldChange held{};
    std::string name{};                                // the file's name in the person's version
    uint64_t size{};
    std::shared_ptr<storage::PlaintextReader> reader;  // the person's version, decrypted as it is read
};
// The person's version of a held write, for whoever may list held changes (super admins here). Nothing in the vault
// changes. NotFound without such a held change; Invalid for one that holds no bytes (not a write, or discarded).
[[nodiscard]] HeldContent heldContent(const Actor& actor, uint64_t id);

}
