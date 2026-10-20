// ws book: sync.conflicts.* (core/src/protocols/ws/handler/SyncConflicts.cpp → ops::conflicts). Shapes:
// ops::conflicts::to_json (core/src/ops/Conflicts.cpp). Who: vault.sync.action.resolve_conflicts; resolving a file
// also needs filesystem Overwrite on it (reported per row as can_overwrite).

#include "fields.hpp"

namespace vh::contract::ws::detail {

std::vector<WsCommandUsage> syncCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "sync.conflicts.summary",
        .description = "Open sync conflicts the caller can resolve: the total and a count per vault (vaults without "
                       "conflicts are left out), sorted by vault name.",
        .input = "none",
        .response = {uinteger("total"),
                     objectArray("vaults", "", {uinteger("vault_id"), str("vault_name"), uinteger("count")})},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "sync.conflicts.list",
        .description = "Open sync conflicts, newest first, in every vault where the caller may resolve them, or in "
                       "one vault (vault_id: denied when the caller may not, not_found when it doesn't exist).",
        .payload = {uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"}))},
        .response = {objectArray("conflicts", "SyncConflict")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "sync.conflicts.resolve",
        .description = "Resolve conflicts by keeping the local or the bucket copy (also accepted: local, remote, "
                       "keep-local, keep-remote). Per item: each id gets its own status and one failure never stops "
                       "the rest. 1 to 500 ids per call.",
        .payload = {str("resolution").oneOf({"keep_local", "keep_remote"}),
                    WsField{.name = "conflict_ids", .types = {"array"}, .items = "integer"}
                        .gen(gen::ref("sync_conflict", {"id"}))
                        .desc("Conflict ids (1 to 500).")},
        .response = {str("resolution").oneOf({"keep_local", "keep_remote"}),
                     uinteger("resolved"),
                     uinteger("failed"),
                     objectArray("results", "",
                                 {uinteger("conflict_id"), boolean("ok"),
                                  str("status").oneOf({"resolved", "denied", "not_found", "conflict", "invalid",
                                                       "unavailable", "error"}),
                                  str("message").nullable()})},
        .refusal_codes = opsRefusals(),
        .client_timeout = 600s,
    });

    return out;
}

}
