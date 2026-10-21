// Contract models: sync conflict serializers against their declared shapes (see model_suites.hpp):
// ops::conflicts::to_json for ConflictView, Summary and ResolveResult.

#include "model_suites.hpp"

#include "ops/Conflicts.hpp"

namespace vh::test_contract_models_sync {

ops::conflicts::ConflictView syncConflictView() {
    ops::conflicts::ConflictView v;
    auto& r = v.record;
    r.id = 11;
    r.vault_id = 3;
    r.file_id = 44;
    r.path = "/cad/part.step";
    r.name = "part.step";
    r.created_at = 1760000000;
    r.updated_at = 1760000600;
    r.reasons = {{.code = "both_changed", .message = "Both copies changed since the last sync"}};
    r.local = {.size_bytes = 10, .mime_type = "model/step", .content_hash = "abc", .modified_at = 1760000000,
               .etag = {}, .encrypted = {}, .encryption_iv = {}, .key_version = {}};
    r.remote = {.size_bytes = 12, .mime_type = "model/step", .content_hash = "def", .modified_at = 1760000300,
                .etag = "\"etag\"", .encrypted = true, .encryption_iv = {}, .key_version = {}};
    v.vault_name = "cad";
    v.can_overwrite = true;
    v.preview = preview::classify("part.step", std::string("model/step"));
    return v;
}

}

namespace vh::test::contract_models {

void checkSyncModels(Checker& c) {
    using json = nlohmann::json;

    c.check(json(test_contract_models_sync::syncConflictView()), "SyncConflict", "sync.conflicts.list conflicts[]");
    ops::conflicts::ConflictView unknown;  // no times, no side metadata
    c.check(json(unknown), "SyncConflict", "sync.conflicts.list conflicts[] (sparse)");

    ops::conflicts::Summary summary{.total = 3, .vaults = {{.vault_id = 3, .vault_name = "cad", .count = 3}}};
    c.check(json(summary), "SyncConflictSummary", "sync.conflicts.summary");
    c.check(json(ops::conflicts::Summary{}), "SyncConflictSummary", "sync.conflicts.summary (none)");

    ops::conflicts::ResolveResult result{
        .decision = ops::conflicts::Decision::KeepRemote,
        .results = {{.conflict_id = 11, .ok = true, .status = "resolved", .message = std::nullopt},
                    {.conflict_id = 12, .ok = false, .status = "denied", .message = "you need Overwrite on /x"}},
        .resolved = 1,
        .failed = 1};
    c.check(json(result), "SyncConflictResolveResult", "sync.conflicts.resolve");
}

}
