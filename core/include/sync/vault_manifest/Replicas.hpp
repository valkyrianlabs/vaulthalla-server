#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Replicated vaults (design/cloud/mirrors.md; design/sync/manifest-applier.md, "As built: the join"): a vault whose
// recorded manifest root names a writer other than this server. Experimental (sync.replicas.experimental).
namespace vh::sync::replicas {

// sync.replicas.experimental is on.
[[nodiscard]] bool experimental();
// Refused("replicas_experimental") unless it is on; `what` names the command.
void requireExperimental(std::string_view what);

// The recorded root's writers (empty before the first root, or a path_v0 vault).
[[nodiscard]] std::vector<std::string> writers(uint32_t vaultId);
// The recorded root names a writer other than this server.
[[nodiscard]] bool replicated(uint32_t vaultId);

// Refused("vault_replicated") when the vault is replicated: `what` is refused on a replicated vault; `how` says what to
// do instead (one sentence).
void refuseIfReplicated(uint32_t vaultId, std::string_view what, std::string_view how);

// The rotation refusal's `how` (every path that mints a key version).
inline constexpr std::string_view kRotateHow =
    "remove the other replicas (vh vault leave on them, or vh vault replica remove here), rotate, then join them "
    "again (a join delivers the current keys)";

}
