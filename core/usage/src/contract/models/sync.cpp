// ws models: sync conflicts (#187). ops::conflicts::to_json (core/src/ops/Conflicts.cpp).

#include "models.hpp"

namespace vh::contract::ws::detail {

std::vector<WsModel> syncModels() {
    std::vector<WsModel> out;

    out.push_back(model("SyncConflictSide",
        "One side of a sync conflict: the local copy or the bucket copy (sideJson in core/src/ops/Conflicts.cpp).",
        {uinteger("size_bytes"),
         str("mime_type").nullable(),
         str("content_hash").nullable(),
         str("modified_at").nullable().desc("ISO-8601 UTC; null when unknown."),
         str("etag").nullable().desc("The bucket copy's ETag; always null on the local side."),
         boolean("encrypted").nullable().desc(
             "Whether the bucket copy is Vaulthalla-encrypted; always null on the local side.")}));

    out.push_back(model("SyncConflict",
        "An open sync conflict the caller may resolve: ops::conflicts::to_json(ConflictView).",
        {uinteger("id"),
         uinteger("vault_id"),
         str("vault_name"),
         uinteger("file_id"),
         str("path").desc("Vault-relative path of the file."),
         str("name"),
         str("type").desc("The conflict type recorded by the sync pass (\"mismatch\")."),
         objectArray("reasons", "", {str("code"), str("message")}).desc("Why the two sides disagree."),
         str("created_at").nullable().desc("ISO-8601 UTC."),
         str("updated_at").nullable().desc("ISO-8601 UTC."),
         object("local", "SyncConflictSide"),
         object("remote", "SyncConflictSide"),
         boolean("can_overwrite").desc("Whether the caller holds filesystem Overwrite on the file (needed to resolve)."),
         object("preview", "PreviewPlan").desc("The plan for the file's preview sheet.")}));

    out.push_back(model("SyncConflictSummary",
        "Open sync conflicts the caller can resolve, counted: ops::conflicts::to_json(Summary).",
        {uinteger("total"),
         objectArray("vaults", "", {uinteger("vault_id"), str("vault_name"), uinteger("count")})
             .desc("Vaults with open conflicts, sorted by name.")}));

    out.push_back(model("SyncConflictResolveResult",
        "A resolve batch's outcome, item by item: ops::conflicts::to_json(ResolveResult).",
        {str("resolution").oneOf({"keep_local", "keep_remote"}),
         uinteger("resolved"),
         uinteger("failed"),
         objectArray("results", "",
                     {uinteger("conflict_id"),
                      boolean("ok"),
                      str("status").oneOf({"resolved", "denied", "not_found", "conflict", "invalid", "unavailable",
                                           "error"}),
                      str("message").nullable()})}));

    return out;
}

}
