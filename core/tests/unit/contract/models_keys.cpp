// Contract models: vault key backup against their declared shapes (see model_suites.hpp): the ops::vault_keys::toJson
// overloads for key status, the export document and an import's result. DB-free: the structs are seeded directly.

#include "model_suites.hpp"

#include "crypto/SecretKey.hpp"
#include "crypto/util/encrypt.hpp"
#include "ops/Error.hpp"
#include "ops/VaultKeys.hpp"
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
    return {.key_id = keyId, .signature = std::string(86, 'A') + "=="};
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
            .last_salvage = salvageReport()};
}

// A healthy live vault never exported: the nullable members null.
keys::KeyStatus freshStatus() {
    return {.vault_id = 1,
            .vault_name = "photos",
            .version = 1,
            .key_check = std::string(32, 'c'),
            .needed_versions = {{.version = 1, .key_check = std::string(32, 'c')}},
            .missing_versions = {}};
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
    return e;
}

// One live vault, one version: the optional members absent.
keys::VaultExport currentOnlyExport() {
    keys::VaultExport e;
    e.vault_id = 1;
    e.vault_name = "photos";
    e.current = {.version = 1, .key = keyOf(9), .key_check = std::string(32, 'c'), .created_at = 1760000000};
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
