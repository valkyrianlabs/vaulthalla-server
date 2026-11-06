// Contract models: vault key backup against their declared shapes (see model_suites.hpp): the ops::vault_keys::toJson
// overloads for key status, the export document and an import's result. DB-free: the structs are seeded directly.

#include "model_suites.hpp"

#include "crypto/SecretKey.hpp"
#include "crypto/util/encrypt.hpp"
#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/VaultLayout.hpp"
#include "ops/VaultRecover.hpp"
#include "vault/KeyAttestation.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vh::test_contract_models_keys {

namespace keys = ops::vault_keys;

crypto::SecretKeyPtr keyOf(const uint8_t fill) {
    std::array<uint8_t, 32> bytes{};
    bytes.fill(fill);
    return std::make_shared<const crypto::SecretKey>(bytes);
}

keys::KeyAttestationInfo attestationOf(const unsigned int keyId) {
    return {.key_id = keyId, .signature = std::string(86, 'A') + "==", .public_key = std::string(43, 'B') + "="};
}

keys::RecoveryMaterial missingMaterial() {
    return {.required = true, .state = "recovery_material_missing", .recipients = 1, .uncovered_versions = {3},
            .export_current = false, .rotation_needed = true,
            .detail = "recovery envelopes are missing for key version(s) 3"};
}

keys::SalvageReport salvageReport() {
    return {.id = 4, .versions = {2}, .new_version = 4, .state = "finished", .started_at = 1770000000,
            .finished_at = 1770000060, .salvaged = 10, .unrecoverable = 1, .skipped_remote = 1, .deferred = 0,
            .failed = 0,
            .failures = {{.path = "/a/broken.bin", .version = 2, .kind = "unrecoverable",
                          .reason = "does not authenticate under the supplied key"},
                         {.path = "/remote.mkv", .version = 2, .kind = "skipped_remote",
                          .reason = "S3 price budget refused key_salvage (estimate: 1 HEAD + 1 GET, 1048592 bytes)"}}};
}

// A vault mid-rotation whose current key doesn't unseal here: every nullable member set.
keys::KeyStatus unavailableStatus() {
    return {.vault_id = 12,
            .vault_name = "archive",
            .deleted = true,
            .key_retain_until = 1770000000,
            .version = 3,
            .key_check = std::string(32, 'a'),
            .key_available = false,
            .unavailable_reason = "version_missing",
            .unavailable_detail = "the outgoing key of the vault's pending rotation (version 2) is not held here; "
                                  "restore it with `vh vault keys import 12 --file <export.json>`",
            .exported_version = 2,
            .exported_at = 1760000000,
            .rotation_in_progress = true,
            .needed_versions = {{.version = 3, .key_check = std::string(32, 'a'), .reason = keys::NeedReason::Current,
                                 .attestation = attestationOf(1)},
                                {.version = 2, .key_check = std::nullopt, .reason = keys::NeedReason::Rotation},
                                {.version = 1, .key_check = std::string(32, 'b'), .reason = keys::NeedReason::Recovery,
                                 .attestation = attestationOf(1)}},
            .missing_versions = {2},
            .attestation = attestationOf(1),
            .last_salvage = salvageReport(),
            .vault_uid = std::nullopt,
            .node_id = "00000000-0000-4000-8000-000000000001",
            .attestation_public_keys = {{.key_id = 1, .public_key = std::string(43, 'B') + "=", .retired_at = 1760000000},
                                        {.key_id = 2, .public_key = std::string(43, 'C') + "=", .retired_at = std::nullopt}},
            .checkpoint = keys::ManifestCheckpoint{.epoch = 812, .root_sha256 = std::string(64, 'a')},
            .recovery = missingMaterial()};
}

// A healthy live vault never exported: the nullable members null.
keys::KeyStatus freshStatus() {
    return {.vault_id = 1,
            .vault_name = "photos",
            .version = 1,
            .key_check = std::string(32, 'c'),
            .needed_versions = {{.version = 1, .key_check = std::string(32, 'c'),
                                 .origin = keys::KeyOriginInfo{.node_id = "00000000-0000-4000-8000-00000000000a",
                                                               .vault_id = 42, .key_id = 3, .anchor = "kit",
                                                               .recovered_at = 1770000000}}},
            .missing_versions = {},
            .vault_uid = "as4f38nkrkaydxr834n3pk2xdr",
            .recovery = {.required = true, .state = "recipient", .recipients = 1}};
}

ops::recovery_recipients::Recipient recipient(const bool revoked) {
    ops::recovery_recipients::Recipient r{.grant_id = "79y1x7s0pkawdszr14d2pf2dbr", .recipient_id = std::string(64, 'e'),
                                          .public_key = std::string(43, 'D') + "=", .suite = 1,
                                          .recipient_class = "customer", .label = "Recovery kit 2026-11",
                                          .added_at = 1770000000, .authorized_by = "user:1 via cli",
                                          .envelope_versions = {1, 2}};
    if (revoked) {
        r.label = std::nullopt;
        r.revoked_at = 1770000100;
        r.revoked_by = "user:1 via device";
    }
    return r;
}

// A deleted vault mid-rotation whose recovery-referenced version 1 is gone: every optional member present.
keys::VaultExport fullExport() {
    keys::VaultExport e;
    e.vault_id = 12;
    e.vault_name = "archive";
    e.deleted = true;
    e.current = {.version = 3, .key = keyOf(3), .key_check = std::string(32, 'a'), .attestation = attestationOf(2),
                 .created_at = 1760000000};
    e.historical = {{.version = 2, .key = keyOf(2), .key_check = std::string(32, 'd'), .attestation = attestationOf(1),
                     .reason = keys::NeedReason::Rotation, .created_at = 1755000000, .retired_at = 1760000000}};
    e.missing = {1};
    e.node_id = "00000000-0000-4000-8000-000000000001";
    return e;
}

// One live vault, one version: the optional members absent.
keys::VaultExport currentOnlyExport() {
    keys::VaultExport e;
    e.vault_id = 1;
    e.vault_name = "photos";
    e.current = {.version = 1, .key = keyOf(9), .key_check = std::string(32, 'c'), .created_at = 1760000000};
    e.node_id = "00000000-0000-4000-8000-000000000001";
    e.vault_uid = "as4f38nkrkaydxr834n3pk2xdr";
    return e;
}

// What Vaulthalla Desktop sends (key-backup.md "Desktop"): only the members the import reads.
nlohmann::json desktopDocument() {
    const auto attestation = [](const unsigned int keyId) {
        return nlohmann::json{{"key_id", keyId}, {"signature", std::string(86, 'A') + "=="}};
    };
    return {{"vault_id", 12},
            {"key", crypto::util::b64_encode(std::vector<uint8_t>(32, 3))},
            {"key_check", std::string(32, 'a')},
            {"attestation", attestation(2)},
            {"key_info", {{"key_version", 3}}},
            {"historical_keys", nlohmann::json::array({{{"key_version", 2},
                                                        {"key", crypto::util::b64_encode(std::vector<uint8_t>(32, 2))},
                                                        {"key_check", std::string(32, 'd')},
                                                        {"attestation", attestation(1)}}})}};
}

keys::ImportResult restoredImport() {
    return {.vault_id = 12,
            .vault_name = "archive",
            .written = true,
            .key_available = true,
            .versions = {{.version = 2, .outcome = keys::ImportOutcome::Restored,
                          .detail = "attested by this node (signing key 1)"},
                         {.version = 3, .outcome = keys::ImportOutcome::Unchanged, .detail = "already held"},
                         {.version = 9, .outcome = keys::ImportOutcome::Refused,
                          .detail = "the vault has no record of key version 9"}}};
}

keys::ImportResult partialDeletedImport() {
    return {.vault_id = 13,
            .vault_name = "old",
            .deleted = true,
            .note = "the vault is deleted: restore it to use the imported keys",
            .versions = {{.version = 1, .outcome = keys::ImportOutcome::NeedsSalvage,
                          .detail = "the backup carries no attestation by this node for it; not restored"}}};
}

keys::ImportResult kitImport() {
    auto r = restoredImport();
    r.recovery_kit = keys::KitImportReport{.envelopes = 5, .unwrapped = 3, .skipped = 1, .rejected = 0, .ignored = 1,
                                           .root_consulted = true};
    return r;
}

keys::ImportResult salvageImport() {
    return {.vault_id = 12,
            .vault_name = "archive",
            .mode = keys::ImportMode::Salvage,
            .written = true,
            .key_available = true,
            .versions = {{.version = 2, .outcome = keys::ImportOutcome::Salvaged,
                          .detail = "not stored; its files were salvaged into key version 4"}},
            .salvage = salvageReport()};
}

// vault.recover: a canonical restore that was written, and a salvage dry run.
nlohmann::json recoverResult(const bool written) {
    ops::vault_recover::Result r;
    r.dry_run = !written;
    r.written = written;
    r.vault_name = "finance";
    r.mode = written ? "canonical" : "salvage";
    r.key_available = written;
    r.report = {
        {"vault_uid", "as4f38nkrkaydxr834n3pk2xdr"},
        {"origin", {{"node_id", "00000000-0000-4000-8000-00000000000a"}, {"vault_id", 42}}},
        {"manifest_vault_name", written ? nlohmann::json("finance") : nlohmann::json(nullptr)},
        {"blind", !written},
        {"epoch", written ? nlohmann::json(812) : nlohmann::json(nullptr)},
        {"root_sha256", written ? nlohmann::json(std::string(64, 'a')) : nlohmann::json(nullptr)},
        {"freshness", written ? "verified" : "unverified"},
        {"freshness_report", "freshness unverified: no checkpoint supplied"},
        {"issues", nlohmann::json::array({"segment x: segment_missing (blind)"})},
        {"counts", {{"files", 3}, {"folders", 2}, {"symlinks", 0}, {"trashed", 1}, {"tombstones", 1},
                    {"provider_versions", 7}, {"bytes", 1000}, {"snapshots", 1}, {"snapshot_members", 2},
                    {"snapshot_members_restorable", 1}}},
        {"key_versions",
         nlohmann::json::array(
             {{{"version", 1}, {"verdict", "verified"}, {"detail", "attested by node A"}, {"held", true},
               {"key_source", "envelope"}, {"current", true}, {"needed", true}, {"state", "canonical"},
               {"anchor", {{"key_id", 3}, {"source", "kit"}}},
               {"origin", {{"node_id", "00000000-0000-4000-8000-00000000000a"}, {"vault_id", 42}, {"source", "root"}}}},
              {{"version", 2}, {"verdict", "unattested"}, {"detail", "no material holds it"}, {"held", false},
               {"current", false}, {"needed", true}, {"state", "missing"}}})},
        {"current_version", 1},
        {"highest_version_seen", 2},
        {"canonical_versions", {1}},
        {"blocking_versions", written ? nlohmann::json::array() : nlohmann::json({2})},
        {"salvageable_versions", nlohmann::json::array()},
        {"orphans", nlohmann::json::array({"as4f38nkrkaydxr834n3pk2xdr"})},
        {"missing_objects", nlohmann::json::array()},
        {"rejected_objects", nlohmann::json::array()},
        {"envelopes", {{"listed", 3}, {"unwrapped", 2}, {"skipped", 1}, {"rejected", 0}}},
        {"anchors", {{"supplied", true}, {"keys", 1}}},
        {"downloads", {{"manifest_bytes", 4096}, {"envelope_bytes", 450}, {"header_bytes", 360}, {"content_bytes", 0},
                       {"other_bytes", 0}, {"gets", 5}, {"ranged_gets", 3}, {"lists", 2}, {"version_lists", 0}}},
        {"mode", r.mode},
        {"unrecoverable_files", written ? 0 : 1}};
    if (written) {
        r.vault_id = 7;
        r.published_epoch = 813;
        r.report["restored"] = {{"vault_id", 7}, {"files", 3}, {"folders", 2}, {"symlinks", 0}, {"trashed", 1},
                                {"index_rows", 4}, {"provider_versions", 7}, {"snapshots", 1},
                                {"snapshot_members", 2}, {"left_out", 0}, {"notes", nlohmann::json::array()},
                                {"fresh_version", 3}};
    } else {
        r.salvage = salvageReport();
        r.note = "a restore would need salvage";
    }
    return ops::vault_recover::toJson(r);
}

}

namespace vh::test::contract_models {

void checkVaultKeyModels(Checker& c) {
    namespace t = test_contract_models_keys;
    namespace keys = ops::vault_keys;
    c.check(keys::toJson(t::unavailableStatus()), "VaultKeyStatus", "vault.keys.status vaults[] (unavailable)");
    c.check(keys::toJson(t::freshStatus()), "VaultKeyStatus", "vault.keys.status vaults[] (healthy)");
    c.check(keys::toJson(t::fullExport(), "alice"), "VaultKeyExport", "vault.keys.export (deleted, mid-rotation)");
    c.check(keys::toJson(t::currentOnlyExport(), "alice"), "VaultKeyExport", "vault.keys.export (current only)");
    c.checkInput(keys::toJson(t::fullExport(), "alice"), "VaultKeyImportDocument", "vault.keys.import keys (an export)");
    c.checkInput(keys::toJson(t::currentOnlyExport(), "alice"), "VaultKeyImportDocument",
                 "vault.keys.import keys (an export, current only)");
    c.checkInput(t::desktopDocument(), "VaultKeyImportDocument", "vault.keys.import keys (Desktop's document)");
    c.check(keys::toJson(t::restoredImport()), "VaultKeyImportResult", "vault.keys.import (restored)");
    c.check(keys::toJson(t::partialDeletedImport()), "VaultKeyImportResult", "vault.keys.import (deleted, skipped)");
    c.check(keys::toJson(t::salvageImport()), "VaultKeyImportResult", "vault.keys.import (salvage)");
    c.check(keys::toJson(t::kitImport()), "VaultKeyImportResult", "vh vault keys import --recovery-kit --json");
    c.check(t::recoverResult(true), "VaultRecoverResult", "vault.recover (canonical, written)");
    c.check(t::recoverResult(false), "VaultRecoverResult", "vh vault recover --dry-run --json (salvage needed)");

    namespace rr = ops::recovery_recipients;
    c.check(rr::toJson(rr::RecipientList{.vault_id = 12, .vault_name = "archive",
                                         .vault_uid = "as4f38nkrkaydxr834n3pk2xdr",
                                         .recipients = {t::recipient(false), t::recipient(true)},
                                         .recovery = t::missingMaterial()}),
            "VaultRecoveryRecipientList", "vault.keys.recipients.list");
    c.check(rr::toJson(rr::RecipientList{.vault_id = 1, .vault_name = "photos", .vault_uid = "as4f38nkrkaydxr834n3pk2xdr",
                                         .recipients = {}, .recovery = {.state = "not_required"}}),
            "VaultRecoveryRecipientList", "vault.keys.recipients.list (none)");
    c.check(rr::toJson(rr::AddResult{.recipient = t::recipient(false), .envelopes_written = 2, .versions = {1, 2},
                                     .note = "the next sync pass writes the missing ones",
                                     .recovery = {.required = true, .state = "recipient", .recipients = 1}}),
            "VaultRecoveryRecipientAdd", "vault.keys.recipients.add");
    c.check(rr::toJson(rr::RevokeResult{.recipient = t::recipient(true), .recovery = t::missingMaterial()}),
            "VaultRecoveryRecipientRevoke", "vault.keys.recipients.revoke");

    // #373: the bucket layout migration.
    namespace vl = ops::vault_layout;
    namespace lm = vault::layout;
    vl::Status none;
    none.vault_id = 3;
    none.vault_name = "archive";
    none.layout = "path_v0";
    c.check(vl::toJson(none), "VaultLayoutStatus", "vault.layout.status (no migration)");
    lm::Row row;
    row.vault_id = 3;
    row.state = lm::State::CleanupBlocked;
    row.started_by = 1;
    row.started_at = 1'760'000'000;
    row.versioned = true;
    row.attempts = 1;
    row.verified_at = row.cutover_at = 1'760'000'600;
    row.cleanup_after = 1'760'605'400;
    row.manifest_verified_at = 1'760'000'700;
    row.cleanup_confirmed_at = row.cleanup_run_at = 1'760'700'000;
    row.estimate = lm::toJson(lm::Estimate{.list_requests = 2, .head_requests = 9, .get_requests = 12, .put_requests = 9,
                                           .delete_requests = 1, .download_bytes = 4096, .upload_bytes = 5120,
                                           .readback_worst_case_gets = 9, .readback_worst_case_bytes = 5120,
                                           .metadata_puts = 2, .objects = 4, .versions = 7, .delete_markers = 1,
                                           .backlog = 1, .current_files = 2, .sample = 9,
                                           .estimated_cost = "0.000412", .priced = true});
    row.usage = nlohmann::json{{"list_requests", 2}, {"head_requests", 9}, {"get_requests", 12}, {"put_requests", 9},
                               {"delete_requests", 1}, {"downloaded_bytes", 4096}, {"uploaded_bytes", 5120}};
    row.last_error = "manifest: transient";
    const lm::CleanupEntry locked{.key = "docs/a.txt", .version_id = "3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY",
                                  .delete_marker = false, .size = 1234, .last_modified = 1'759'000'000,
                                  .reason = "object_lock_retention", .retain_until = 1'790'000'000};
    vl::Status blocked = none;
    blocked.layout = "opaque_v1";
    blocked.migration = row;
    blocked.versions.verified = 6;
    blocked.versions.skipped = 1;
    blocked.markers.verified = 1;
    blocked.backlog.superseded = 1;
    blocked.current.verified = 2;
    blocked.legacy_listed = 2;
    blocked.legacy_deleted = 7;
    blocked.blocked = {locked};
    blocked.blocked_total = 1;
    c.check(vl::toJson(blocked), "VaultLayoutStatus", "vault.layout.status (cleanup_blocked)");
    blocked.migration->state = lm::State::Complete;
    blocked.migration->completed_at = 1'760'800'000;
    blocked.blocked.clear();
    blocked.blocked_total = 0;
    c.check(vl::toJson(blocked), "VaultLayoutStatus", "vault.layout.status (complete)");
    lm::CleanupPlan plan;
    plan.complete_listing = true;
    plan.deletable = 1;
    plan.deletable_bytes = 99;
    plan.oldest = plan.newest = 1'759'000'000;
    plan.kept = {locked};
    plan.deletable_entries = {{.key = "b.txt", .version_id = std::nullopt, .delete_marker = false, .size = 99,
                               .last_modified = 1'759'000'000, .reason = "", .retain_until = std::nullopt}};
    c.check(vl::toJson(vl::CleanupAnswer{.dry_run = true, .started = false, .cleanup_after = 1'760'605'400, .plan = plan}),
            "VaultLayoutCleanup", "vault.layout.cleanup (dry run)");
}

}

// ---- VaultKeyImportDocument against the import's own parser (ops::vault_keys::readImportDocument) -------------------

namespace vh::test_contract_models_keys {

using nlohmann::json;
using test::contract_models::Checker;

const contract::WsModel& modelNamed(const std::string& name) {
    static const auto all = contract::ws::models();
    for (const auto& m : all)
        if (m.name == name) return m;
    throw std::out_of_range(name);
}

const contract::WsField& fieldOf(const contract::WsModel& m, const std::string& name) {
    for (const auto& f : m.fields)
        if (f.name == name) return f;
    throw std::out_of_range(m.name + "." + name);
}

// The model's verdict on a document: the problems a fresh Checker reports for it as an input.
std::vector<std::string> contractProblems(const json& doc) {
    Checker c;
    c.checkInput(doc, "VaultKeyImportDocument", "doc");
    return c.problems();
}

// What the parser reads of a document as it arrives (parsed from the frame's text: positive integers are unsigned).
std::vector<keys::ImportDocumentVersion> readDoc(const json& doc) {
    return keys::readImportDocument(json::parse(doc.dump()), 12);
}

// The parser's verdict: whether the import reads the document or refuses it (invalid).
bool parserAccepts(const json& doc) {
    try {
        (void)readDoc(doc);
        return true;
    } catch (const ops::Invalid&) {
        return false;
    }
}

// Every member the model declares for an entry, at any depth of its inline objects (historical_keys through its first
// element), as (path, field, the JSON object holding it in `doc`).
void eachMember(const std::vector<contract::WsField>& fields, const std::string& path,
                const std::function<json&(json&)>& holder,
                const std::function<void(const std::string&, const contract::WsField&,
                                         const std::function<json&(json&)>&)>& visit) {
    for (const auto& f : fields) {
        visit(path + f.name, f, holder);
        if (f.fields.empty()) continue;
        const bool list = f.items == "object";
        eachMember(f.fields, path + f.name + (list ? "[]." : "."),
                   [holder, name = f.name, list](json& doc) -> json& {
                       return list ? holder(doc).at(name).at(0) : holder(doc).at(name);
                   },
                   visit);
    }
}

}

namespace vh::test_contract_models_keys_import {

namespace t = test_contract_models_keys;
namespace keys = ops::vault_keys;
using nlohmann::json;

// The model declares exactly what the import requires: removing a member, or sending null for it, is refused by the
// parser exactly when the model calls it a problem; and every document the model accepts (an export with all its
// extra members, Desktop's document, the bare minimum) the parser reads.
TEST(ContractModels, VaultKeyImportDocumentRequiresWhatTheImportReads) {
    const auto model = t::modelNamed("VaultKeyImportDocument");
    const auto exported = keys::toJson(t::fullExport(), "alice");
    const json minimal{{"vault_id", 12},
                       {"key", crypto::util::b64_encode(std::vector<uint8_t>(32, 3))},
                       {"key_info", {{"key_version", 3}}}};
    for (const auto& [doc, what] : {std::pair{exported, "an export"}, std::pair{t::desktopDocument(), "Desktop's"},
                                    std::pair{minimal, "the minimum"}}) {
        EXPECT_TRUE(t::contractProblems(doc).empty()) << what << ": " << t::contractProblems(doc).front();
        EXPECT_TRUE(t::parserAccepts(doc)) << what;
        EXPECT_TRUE(t::parserAccepts(json::array({{{"vault_id", 7}}, doc}))) << what << " in an `all` array";
    }

    int members = 0;
    t::eachMember(model.fields, "", [](json& doc) -> json& { return doc; },
                  [&](const std::string& path, const contract::WsField& f, const std::function<json&(json&)>& holder) {
                      ++members;
                      auto without = t::desktopDocument();
                      holder(without).erase(f.name);
                      EXPECT_EQ(!t::contractProblems(without).empty(), f.required) << path << " removed";
                      EXPECT_EQ(t::parserAccepts(without), !f.required) << path << " removed";

                      auto null = t::desktopDocument();
                      holder(null)[f.name] = nullptr;
                      const bool nullable = std::ranges::find(f.types, "null") != f.types.end();
                      EXPECT_EQ(t::contractProblems(null).empty(), nullable) << path << " null";
                      EXPECT_EQ(t::parserAccepts(null), nullable) << path << " null";
                  });
    EXPECT_EQ(members, 13);  // vault_id, key, key_check, attestation, key_info{3}, historical_keys{4}

    // key_version's declared bounds are the parser's.
    for (const auto* holder : {"key_info", "historical_keys"}) {
        const auto f = holder == std::string("key_info") ? t::fieldOf(model, "key_info").fields.front()
                                                          : t::fieldOf(model, "historical_keys").fields.front();
        ASSERT_EQ(f.name, "key_version");
        ASSERT_TRUE(f.minimum && f.maximum);
        const auto set = [&](const int64_t v) {
            auto doc = t::desktopDocument();
            auto& target = holder == std::string("key_info") ? doc["key_info"] : doc["historical_keys"][0];
            target["key_version"] = v;
            return doc;
        };
        for (const auto v : {*f.minimum, *f.maximum}) {
            EXPECT_TRUE(t::contractProblems(set(v)).empty()) << holder << " " << v;
            EXPECT_TRUE(t::parserAccepts(set(v))) << holder << " " << v;
        }
        for (const auto v : {*f.minimum - 1, *f.maximum + 1}) {
            EXPECT_FALSE(t::contractProblems(set(v)).empty()) << holder << " " << v;
            EXPECT_FALSE(t::parserAccepts(set(v))) << holder << " " << v;
        }
    }
}

// key_id: the contract's bounds are the signing key ids the database can hold. Outside them the attestation is
// malformed (that version needs salvage), never narrowed: 2^32 + 2 used to read as signing key 2.
TEST(ContractModels, VaultKeyAttestationKeyIdBoundsAreTheImports) {
    const auto keyId = t::fieldOf(t::modelNamed("VaultKeyAttestation"), "key_id");
    ASSERT_TRUE(keyId.minimum && keyId.maximum);
    EXPECT_EQ(*keyId.minimum, static_cast<int64_t>(vault::attestation::kMinKeyId));
    EXPECT_EQ(*keyId.maximum, static_cast<int64_t>(vault::attestation::kMaxKeyId));
    EXPECT_EQ(*keyId.maximum, std::numeric_limits<int32_t>::max());  // key_attestation_keys.id is a SERIAL

    const auto withKeyId = [](const uint64_t id) {
        auto doc = t::desktopDocument();
        doc["attestation"]["key_id"] = id;
        return doc;
    };
    const auto current = [](const json& doc) {
        for (const auto& v : t::readDoc(doc))
            if (v.version == 3) return v;
        throw std::logic_error("version 3 not read");
    };

    for (const auto id : {static_cast<uint64_t>(*keyId.minimum), static_cast<uint64_t>(*keyId.maximum)}) {
        const auto v = current(withKeyId(id));
        EXPECT_EQ(v.attestation_key_id, id);
        EXPECT_FALSE(v.attestation_problem);
        EXPECT_TRUE(t::contractProblems(withKeyId(id)).empty()) << id;
    }
    for (const uint64_t id : {uint64_t{0}, static_cast<uint64_t>(*keyId.maximum) + 1, (uint64_t{1} << 32) + 2,
                              std::numeric_limits<uint64_t>::max()}) {
        const auto v = current(withKeyId(id));
        EXPECT_FALSE(v.attestation_key_id) << id << " read as signing key " << v.attestation_key_id.value_or(0);
        ASSERT_TRUE(v.attestation_problem) << id;
        EXPECT_NE(v.attestation_problem->find("malformed"), std::string::npos) << *v.attestation_problem;
        EXPECT_FALSE(t::contractProblems(withKeyId(id)).empty()) << id;
    }
    // The other version's attestation is untouched by this one's.
    for (const auto& v : t::readDoc(withKeyId((uint64_t{1} << 32) + 2)))
        if (v.version == 2) {
            EXPECT_EQ(v.attestation_key_id, 1u);
        }
}

}
