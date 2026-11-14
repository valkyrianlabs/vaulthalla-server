#include "db/query/vault/RemoteAttach.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/u8.hpp"
#include "fs/model/File.hpp"
#include "sync/model/RemoteObject.hpp"

#include <pqxx/result>

#include <map>
#include <stdexcept>

namespace vh::db::query::vault {

namespace {

namespace ra = ::vh::vault::remote;

std::optional<int64_t> raOptI64(const std::optional<uint64_t>& v) {
    return v ? std::make_optional(static_cast<int64_t>(*v)) : std::nullopt;
}

template <class T>
std::optional<T> raOpt(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

std::optional<uint64_t> raOptU64(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    const auto v = f.as<int64_t>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
}

std::optional<std::time_t> raOptTime(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

std::optional<nlohmann::json> raOptJson(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return nlohmann::json::parse(f.as<std::string>());
}

constexpr const char* raKRowColumns =
    "vault_id, origin, api_key_id, bucket, storage_tier_id, manifest_publish, bucket_probe::TEXT AS bucket_probe, "
    "versioned, state, started_by, extract(epoch from started_at)::BIGINT AS started_at, accept_unpriced, attempts, "
    "passes, extract(epoch from verified_at)::BIGINT AS verified_at, "
    "extract(epoch from cutover_at)::BIGINT AS cutover_at, extract(epoch from done_at)::BIGINT AS done_at, "
    "extract(epoch from aborted_at)::BIGINT AS aborted_at, "
    "extract(epoch from abort_requested_at)::BIGINT AS abort_requested_at, abort_requested_by, "
    "extract(epoch from rotation_queued_at)::BIGINT AS rotation_queued_at, estimate::TEXT AS estimate, "
    "usage::TEXT AS usage, manifest::TEXT AS manifest, first_pass::TEXT AS first_pass, last_error, "
    "extract(epoch from updated_at)::BIGINT AS updated_at";

ra::Row raRowFrom(const pqxx::row_ref r) {
    ra::Row row;
    row.vault_id = r["vault_id"].as<uint32_t>();
    row.origin = r["origin"].as<std::string>();
    row.api_key_id = raOpt<uint32_t>(r["api_key_id"]);
    row.bucket = r["bucket"].as<std::string>();
    row.storage_tier_id = raOpt<std::string>(r["storage_tier_id"]);
    row.manifest_publish = raOpt<std::string>(r["manifest_publish"]);
    row.bucket_probe = raOptJson(r["bucket_probe"]);
    row.versioned = raOpt<bool>(r["versioned"]);
    row.state = ra::stateFromString(r["state"].as<std::string>());
    row.started_by = raOpt<uint32_t>(r["started_by"]);
    row.started_at = static_cast<std::time_t>(r["started_at"].as<int64_t>());
    row.accept_unpriced = r["accept_unpriced"].as<bool>();
    row.attempts = r["attempts"].as<unsigned int>();
    row.passes = r["passes"].as<unsigned int>();
    row.verified_at = raOptTime(r["verified_at"]);
    row.cutover_at = raOptTime(r["cutover_at"]);
    row.done_at = raOptTime(r["done_at"]);
    row.aborted_at = raOptTime(r["aborted_at"]);
    row.abort_requested_at = raOptTime(r["abort_requested_at"]);
    row.abort_requested_by = raOpt<uint32_t>(r["abort_requested_by"]);
    row.rotation_queued_at = raOptTime(r["rotation_queued_at"]);
    row.estimate = raOptJson(r["estimate"]);
    row.usage = raOptJson(r["usage"]);
    row.manifest = raOptJson(r["manifest"]);
    row.first_pass = raOptJson(r["first_pass"]);
    row.last_error = raOpt<std::string>(r["last_error"]);
    row.updated_at = static_cast<std::time_t>(r["updated_at"].as<int64_t>());
    return row;
}

std::optional<ra::Row> raRowIn(pqxx::transaction_base& txn, const uint32_t vaultId) {
    const auto res = txn.exec(std::string("SELECT ") + raKRowColumns + " FROM vault_remote_attach WHERE vault_id = $1",
                              pqxx::params{vaultId});
    if (res.empty()) return std::nullopt;
    return raRowFrom(res[0]);
}

constexpr const char* raKItemColumns =
    "id, vault_id, kind, file_id, object_key, generation, key_version, plaintext_bytes, content_hash, size, etag, "
    "version_id, state, error";

ra::Item raItemFrom(const pqxx::row_ref r) {
    ra::Item it;
    it.id = r["id"].as<int64_t>();
    it.vault_id = r["vault_id"].as<uint32_t>();
    it.kind = ra::itemKindFromString(r["kind"].as<std::string>());
    it.file_id = raOpt<uint32_t>(r["file_id"]);
    it.object_key = r["object_key"].as<std::string>();
    it.generation = raOpt<std::string>(r["generation"]);
    it.key_version = raOpt<unsigned int>(r["key_version"]);
    it.plaintext_bytes = raOptU64(r["plaintext_bytes"]);
    it.content_hash = raOpt<std::string>(r["content_hash"]);
    it.size = raOptU64(r["size"]);
    it.etag = raOpt<std::string>(r["etag"]);
    it.version_id = raOpt<std::string>(r["version_id"]);
    it.state = ra::itemStateFromString(r["state"].as<std::string>());
    it.error = raOpt<std::string>(r["error"]);
    return it;
}

// Every column of an item, $1.. in this order (the insert and the update share it).
pqxx::params raItemParams(const ra::Item& it) {
    return pqxx::params{it.vault_id,
                        std::string(ra::to_string(it.kind)),
                        it.file_id,
                        it.object_key,
                        it.generation,
                        it.key_version,
                        raOptI64(it.plaintext_bytes),
                        it.content_hash,
                        raOptI64(it.size),
                        it.etag,
                        it.version_id,
                        std::string(ra::to_string(it.state)),
                        it.error};
}

void raUpdate(const char* ctx, const std::string& set, const pqxx::params& params) {
    Transactions::exec(ctx, [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_attach SET " + set + ", updated_at = now() WHERE vault_id = $1", params);
    });
}

}

std::optional<RemoteAttach::Row> RemoteAttach::get(const uint32_t vaultId) {
    return Transactions::read("RemoteAttach::get",
                              [&](pqxx::transaction_base& txn) { return raRowIn(txn, vaultId); });
}

std::vector<RemoteAttach::Row> RemoteAttach::list() {
    return Transactions::read("RemoteAttach::list", [&](pqxx::transaction_base& txn) {
        std::vector<Row> out;
        for (const auto r : txn.exec(std::string("SELECT ") + raKRowColumns + " FROM vault_remote_attach ORDER BY vault_id"))
            out.push_back(raRowFrom(r));
        return out;
    });
}

RemoteAttach::Started RemoteAttach::start(const StartRequest& request) {
    return Transactions::exec("RemoteAttach::start", [&](pqxx::work& txn) {
        Started out;
        // The vault's row serialises starts of the same vault; the reservation index, starts on the same bucket.
        (void)txn.exec("SELECT 1 FROM vault WHERE id = $1 FOR UPDATE", pqxx::params{request.vault_id});
        const auto holder = txn.exec(
            "SELECT vault_id FROM vault_remote_attach WHERE api_key_id = $1 AND bucket = $2 AND vault_id <> $3 "
            "AND state NOT IN ('aborted', 'done') "
            "UNION ALL SELECT vault_id FROM s3 WHERE api_key_id = $1 AND bucket = $2 AND vault_id <> $3 LIMIT 1",
            pqxx::params{request.api_key_id, request.bucket, request.vault_id});
        if (!holder.empty()) {
            out.outcome = StartOutcome::BucketReserved;
            out.reserved_by = holder[0][0].as<uint32_t>();
            return out;
        }
        const auto existing = raRowIn(txn, request.vault_id);
        if (!existing || existing->state == State::Aborted) {
            if (existing) {
                txn.exec("DELETE FROM vault_remote_attach_item WHERE vault_id = $1", pqxx::params{request.vault_id});
                txn.exec("DELETE FROM vault_remote_attach WHERE vault_id = $1", pqxx::params{request.vault_id});
            }
            txn.exec("INSERT INTO vault_remote_attach (vault_id, origin, api_key_id, bucket, storage_tier_id, state, "
                     "  started_by, accept_unpriced) VALUES ($1, $2, $3, $4, $5, 'preparing', $6, $7)",
                     pqxx::params{request.vault_id, request.origin, request.api_key_id, request.bucket,
                                  request.storage_tier_id, request.started_by, request.accept_unpriced});
            out.outcome = StartOutcome::Started;
        } else if (existing->state == State::Failed) {
            if (existing->api_key_id != std::optional<uint32_t>(request.api_key_id) || existing->bucket != request.bucket) {
                out.outcome = StartOutcome::BindingDiffers;
                out.row = existing;
                return out;
            }
            txn.exec("UPDATE vault_remote_attach SET state = 'preparing', started_by = $2, accept_unpriced = $3, "
                     "  storage_tier_id = $4, attempts = attempts + 1, passes = 0, verified_at = NULL, last_error = NULL, "
                     "  abort_requested_at = NULL, abort_requested_by = NULL, updated_at = now() WHERE vault_id = $1",
                     pqxx::params{request.vault_id, request.started_by, request.accept_unpriced,
                                  request.storage_tier_id});
            txn.exec("UPDATE vault_remote_attach_item SET state = 'pending', error = NULL, updated_at = now() "
                     "WHERE vault_id = $1 AND state = 'failed' AND kind = 'content'",
                     pqxx::params{request.vault_id});
            out.outcome = StartOutcome::Resumed;
        } else {
            out.outcome = StartOutcome::Busy;
            out.row = existing;
            return out;
        }
        out.row = raRowIn(txn, request.vault_id);
        return out;
    });
}

void RemoteAttach::setState(const uint32_t vaultId, const State state, const std::optional<std::string>& error) {
    if (!ra::beforeCutover(state)) throw std::logic_error("setState moves an attach before its cutover only");
    Transactions::exec("RemoteAttach::setState", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_attach SET state = $2, last_error = $3, updated_at = now() "
                 "WHERE vault_id = $1 AND cutover_at IS NULL AND state <> 'aborted'",
                 pqxx::params{vaultId, std::string(ra::to_string(state)), error});
    });
}

void RemoteAttach::setProbe(const uint32_t vaultId, const std::optional<std::string>& manifestPublish,
                            const nlohmann::json& probe, const bool versioned) {
    raUpdate("RemoteAttach::setProbe", "manifest_publish = $2, bucket_probe = $3::JSONB, versioned = $4",
             pqxx::params{vaultId, manifestPublish, probe.dump(), versioned});
}

void RemoteAttach::setEstimate(const uint32_t vaultId, const nlohmann::json& estimate) {
    raUpdate("RemoteAttach::setEstimate", "estimate = $2::JSONB", pqxx::params{vaultId, estimate.dump()});
}

void RemoteAttach::setUsage(const uint32_t vaultId, const nlohmann::json& usage) {
    raUpdate("RemoteAttach::setUsage", "usage = $2::JSONB", pqxx::params{vaultId, usage.dump()});
}

void RemoteAttach::setManifest(const uint32_t vaultId, const nlohmann::json& manifest) {
    raUpdate("RemoteAttach::setManifest", "manifest = $2::JSONB", pqxx::params{vaultId, manifest.dump()});
}

void RemoteAttach::setPasses(const uint32_t vaultId, const unsigned int passes) {
    raUpdate("RemoteAttach::setPasses", "passes = $2", pqxx::params{vaultId, passes});
}

void RemoteAttach::markVerified(const uint32_t vaultId) {
    raUpdate("RemoteAttach::markVerified", "verified_at = now()", pqxx::params{vaultId});
}

void RemoteAttach::clearVerified(const uint32_t vaultId) {
    raUpdate("RemoteAttach::clearVerified", "verified_at = NULL", pqxx::params{vaultId});
}

void RemoteAttach::setError(const uint32_t vaultId, const std::optional<std::string>& error) {
    raUpdate("RemoteAttach::setError", "last_error = $2", pqxx::params{vaultId, error});
}

void RemoteAttach::touch(const uint32_t vaultId) {
    Transactions::exec("RemoteAttach::touch", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_attach SET updated_at = now() WHERE vault_id = $1", pqxx::params{vaultId});
    });
}

bool RemoteAttach::requestAbort(const uint32_t vaultId, const std::optional<uint32_t> userId) {
    return Transactions::exec("RemoteAttach::requestAbort", [&](pqxx::work& txn) {
        return txn.exec("UPDATE vault_remote_attach SET abort_requested_at = now(), abort_requested_by = $2, "
                        "  updated_at = now() WHERE vault_id = $1 AND cutover_at IS NULL AND state <> 'aborted'",
                        pqxx::params{vaultId, userId})
                   .affected_rows() == 1;
    });
}

void RemoteAttach::finishAbort(const uint32_t vaultId) {
    Transactions::exec("RemoteAttach::finishAbort", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_attach SET state = 'aborted', aborted_at = now(), verified_at = NULL, "
                 "  manifest = NULL, last_error = NULL, updated_at = now() WHERE vault_id = $1 AND cutover_at IS NULL",
                 pqxx::params{vaultId});
    });
}

bool RemoteAttach::queueRotation(const uint32_t vaultId) {
    return Transactions::exec("RemoteAttach::queueRotation", [&](pqxx::work& txn) {
        return txn.exec("UPDATE vault_remote_attach SET rotation_queued_at = COALESCE(rotation_queued_at, now()), "
                        "  updated_at = now() WHERE vault_id = $1 AND state NOT IN ('done', 'failed', 'aborted')",
                        pqxx::params{vaultId})
                   .affected_rows() == 1;
    });
}

bool RemoteAttach::takeQueuedRotation(const uint32_t vaultId) {
    return Transactions::exec("RemoteAttach::takeQueuedRotation", [&](pqxx::work& txn) {
        return txn.exec("UPDATE vault_remote_attach SET rotation_queued_at = NULL, updated_at = now() "
                        "WHERE vault_id = $1 AND rotation_queued_at IS NOT NULL "
                        "AND state IN ('done', 'failed', 'aborted')",
                        pqxx::params{vaultId})
                   .affected_rows() == 1;
    });
}

void RemoteAttach::markDone(const uint32_t vaultId, const nlohmann::json& firstPass) {
    Transactions::exec("RemoteAttach::markDone", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_remote_attach SET state = 'done', done_at = now(), first_pass = $2::JSONB, "
                 "  last_error = NULL, updated_at = now() WHERE vault_id = $1 AND state = 'cutover'",
                 pqxx::params{vaultId, firstPass.dump()});
    });
}

std::vector<RemoteAttach::Item> RemoteAttach::items(const uint32_t vaultId) {
    return Transactions::read("RemoteAttach::items", [&](pqxx::transaction_base& txn) {
        std::vector<Item> out;
        for (const auto r : txn.exec(std::string("SELECT ") + raKItemColumns +
                                         " FROM vault_remote_attach_item WHERE vault_id = $1 ORDER BY id",
                                     pqxx::params{vaultId}))
            out.push_back(raItemFrom(r));
        return out;
    });
}

RemoteAttach::Item RemoteAttach::insertItem(const Item& item) {
    return Transactions::exec("RemoteAttach::insertItem", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "INSERT INTO vault_remote_attach_item (vault_id, kind, file_id, object_key, generation, key_version, "
            "  plaintext_bytes, content_hash, size, etag, version_id, state, error) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
            raItemParams(item));
        auto stored = item;
        stored.id = res.one_field_ref().as<int64_t>();
        return stored;
    });
}

void RemoteAttach::updateItem(const Item& item) {
    Transactions::exec("RemoteAttach::updateItem", [&](pqxx::work& txn) {
        auto p = raItemParams(item);
        p.append(item.id);
        txn.exec("UPDATE vault_remote_attach_item SET vault_id = $1, kind = $2, file_id = $3, object_key = $4, "
                 "generation = $5, key_version = $6, plaintext_bytes = $7, content_hash = $8, size = $9, etag = $10, "
                 "version_id = $11, state = $12, error = $13, updated_at = now() WHERE id = $14",
                 p);
    });
}

std::vector<std::shared_ptr<::vh::fs::model::File>> RemoteAttach::liveFiles(const uint32_t vaultId) {
    return Transactions::read("RemoteAttach::liveFiles", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec("SELECT fs.*, f.* FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id "
                                  "WHERE fs.vault_id = $1 ORDER BY f.fs_entry_id",
                                  pqxx::params{vaultId});
        return ::vh::fs::model::files_from_pq_res(res);
    });
}

RemoteAttach::LegacyContent RemoteAttach::legacyContent(const uint32_t vaultId) {
    return Transactions::read("RemoteAttach::legacyContent", [&](pqxx::transaction_base& txn) {
        LegacyContent out;
        const auto files = txn.exec(
            "SELECT count(*) FILTER (WHERE f.content_format = 'gcm0'), "
            "       count(*) FILTER (WHERE f.content_format = 'plain' AND f.size_bytes > 0) "
            "FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1",
            pqxx::params{vaultId});
        out.gcm0_files = files[0][0].as<uint64_t>();
        out.plain_files = files[0][1].as<uint64_t>();
        out.gcm0_blobs = txn.exec("SELECT count(*) FROM recovery_blob WHERE vault_id = $1 AND content_format = 'gcm0'",
                                  pqxx::params{vaultId})
                             .one_field_ref()
                             .as<uint64_t>();
        return out;
    });
}

std::vector<unsigned int> RemoteAttach::unattestedKeyVersions(const uint32_t vaultId) {
    return Transactions::read("RemoteAttach::unattestedKeyVersions", [&](pqxx::transaction_base& txn) {
        std::vector<unsigned int> out;
        for (const auto r : txn.exec("SELECT version FROM vault_keys WHERE vault_id = $1 AND attestation IS NULL "
                                     "UNION ALL SELECT version FROM vault_keys_trashed WHERE vault_id = $1 "
                                     "AND attestation IS NULL ORDER BY 1",
                                     pqxx::params{vaultId}))
            out.push_back(r[0].as<unsigned int>());
        return out;
    });
}

std::optional<uint32_t> RemoteAttach::bucketHolder(const uint32_t apiKeyId, const std::string& bucket,
                                                   const uint32_t exceptVault) {
    return Transactions::read("RemoteAttach::bucketHolder", [&](pqxx::transaction_base& txn) -> std::optional<uint32_t> {
        const auto res = txn.exec(
            "SELECT vault_id FROM s3 WHERE api_key_id = $1 AND bucket = $2 AND vault_id <> $3 "
            "UNION ALL SELECT vault_id FROM vault_remote_attach WHERE api_key_id = $1 AND bucket = $2 AND vault_id <> $3 "
            "AND state NOT IN ('aborted', 'done') LIMIT 1",
            pqxx::params{apiKeyId, bucket, exceptVault});
        if (res.empty()) return std::nullopt;
        return res[0][0].as<uint32_t>();
    });
}

std::vector<RemoteAttach::StoredEnvelope> RemoteAttach::envelopes(const uint32_t vaultId) {
    return Transactions::read("RemoteAttach::envelopes", [&](pqxx::transaction_base& txn) {
        std::vector<StoredEnvelope> out;
        for (const auto r : txn.exec("SELECT grant_id, key_version, kid, envelope FROM vault_key_envelope "
                                     "WHERE vault_id = $1 ORDER BY key_version, grant_id",
                                     pqxx::params{vaultId})) {
            StoredEnvelope e{.grant_id = r["grant_id"].as<std::string>(), .key_version = r["key_version"].as<uint32_t>(),
                             .kid = r["kid"].as<std::string>(), .bytes = {}};
            if (!r["envelope"].is_null()) e.bytes = encoding::from_hex_bytea(r["envelope"].as<std::string>());
            out.push_back(std::move(e));
        }
        return out;
    });
}

std::optional<std::vector<uint8_t>> RemoteAttach::envelopeBytes(const uint32_t vaultId, const std::string& kid) {
    return Transactions::read("RemoteAttach::envelopeBytes",
                              [&](pqxx::transaction_base& txn) -> std::optional<std::vector<uint8_t>> {
        const auto res = txn.exec("SELECT envelope FROM vault_key_envelope WHERE vault_id = $1 AND kid = $2 "
                                  "AND envelope IS NOT NULL LIMIT 1",
                                  pqxx::params{vaultId, kid});
        if (res.empty()) return std::nullopt;
        return encoding::from_hex_bytea(res[0][0].as<std::string>());
    });
}

void RemoteAttach::storeEnvelopeBytes(const uint32_t vaultId, const std::string& kid, const std::vector<uint8_t>& bytes) {
    Transactions::exec("RemoteAttach::storeEnvelopeBytes", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_key_envelope SET envelope = $3 WHERE vault_id = $1 AND kid = $2",
                 pqxx::params{vaultId, kid, encoding::to_hex_bytea(bytes)});
    });
}

RemoteAttach::CutoverOutcome RemoteAttach::cutover(const uint32_t vaultId, const CutoverInput& input) {
    return Transactions::exec("RemoteAttach::cutover", [&](pqxx::work& txn) {
        CutoverOutcome out;
        const auto vault = txn.exec("SELECT type, deleted_at IS NOT NULL FROM vault WHERE id = $1 FOR UPDATE",
                                    pqxx::params{vaultId});
        if (vault.empty() || vault[0][1].as<bool>()) {
            out.refused = "the vault no longer exists";
            return out;
        }
        if (vault[0][0].as<std::string>() != "local") {
            out.refused = "the vault is not a local vault";
            return out;
        }
        const auto attach = txn.exec(
            "SELECT state, verified_at IS NOT NULL, api_key_id, bucket, storage_tier_id, manifest_publish, "
            "       bucket_probe::TEXT, abort_requested_at IS NOT NULL "
            "FROM vault_remote_attach WHERE vault_id = $1 FOR UPDATE",
            pqxx::params{vaultId});
        if (attach.empty() || attach[0][0].as<std::string>() != "verifying" || !attach[0][1].as<bool>()) {
            out.refused = "the attach is not verified";
            return out;
        }
        if (attach[0][7].as<bool>()) {
            out.refused = "an abort was requested";
            return out;
        }
        if (attach[0][2].is_null() || attach[0][5].is_null() || attach[0][6].is_null()) {
            out.refused = "the attach has no API key or bucket probe any more";
            return out;
        }
        const auto apiKeyId = attach[0][2].as<uint32_t>();
        const auto bucket = attach[0][3].as<std::string>();
        if (!txn.exec("SELECT 1 FROM s3 WHERE api_key_id = $1 AND bucket = $2", pqxx::params{apiKeyId, bucket}).empty()) {
            out.refused = "another vault holds the bucket";
            return out;
        }
        if (!txn.exec("SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1 "
                      "AND (f.content_format = 'gcm0' OR (f.content_format = 'plain' AND f.size_bytes > 0)) LIMIT 1",
                      pqxx::params{vaultId}).empty()) {
            out.refused = "legacy (gcm0 or plain) content appeared";
            return out;
        }

        // The vault becomes an encrypting, opaque_v1 S3 vault on the probed bucket.
        txn.exec("UPDATE vault SET type = 's3', updated_at = CURRENT_TIMESTAMP WHERE id = $1", pqxx::params{vaultId});
        txn.exec("INSERT INTO s3 (vault_id, api_key_id, bucket, encrypt_upstream, storage_tier_id, storage_layout, "
                 "  manifest_publish, bucket_probe) VALUES ($1, $2, $3, TRUE, $4, 'opaque_v1', $5, $6::JSONB)",
                 pqxx::params{vaultId, apiKeyId, bucket, raOpt<std::string>(attach[0][4]),
                              attach[0][5].as<std::string>(), attach[0][6].as<std::string>()});

        // fsync -> rsync, keeping the vault's interval and enabled flag (they live on the sync row).
        const auto sync = txn.exec("SELECT id FROM sync WHERE vault_id = $1 FOR UPDATE", pqxx::params{vaultId});
        if (sync.empty()) throw std::runtime_error("the vault has no sync policy row");
        const auto syncId = sync[0][0].as<uint32_t>();
        txn.exec("DELETE FROM fsync WHERE sync_id = $1", pqxx::params{syncId});
        // The policy a new S3 vault starts with (ops::vaults' freshPolicy): the operator's vaults.s3 defaults and the
        // default request budgets.
        const auto budget = [](const std::optional<uint64_t>& v) { return raOptI64(v); };
        txn.exec("INSERT INTO rsync (sync_id, strategy, conflict_policy, s3_budget_list_requests, "
                 "  s3_budget_head_requests, s3_budget_get_requests, s3_budget_put_requests, s3_budget_copy_requests, "
                 "  s3_budget_delete_requests, s3_budget_downloaded_bytes, max_remote_index_age_seconds) "
                 "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) "
                 "ON CONFLICT (sync_id) DO UPDATE SET strategy = EXCLUDED.strategy, "
                 "  conflict_policy = EXCLUDED.conflict_policy",
                 pqxx::params{syncId, input.remote_strategy, input.remote_conflict_policy,
                              budget(input.budget.max_list_requests), budget(input.budget.max_head_requests),
                              budget(input.budget.max_get_requests), budget(input.budget.max_put_requests),
                              budget(input.budget.max_copy_requests), budget(input.budget.max_delete_requests),
                              budget(input.budget.max_downloaded_bytes), input.max_remote_index_age_seconds});
        txn.exec("UPDATE sync SET updated_at = NOW() WHERE id = $1", pqxx::params{syncId});

        // The remote index and the sync baselines: every verified object as Vaulthalla's own upload of its file, at
        // the generation that was sent. A file changed since is an ordinary pending upload against that baseline.
        txn.exec(pqxx::prepped{"remote_object_index.delete_for_vault"}, pqxx::params{vaultId});
        for (const auto& f : input.files) {
            const bool live = !txn.exec("SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                        "WHERE f.fs_entry_id = $1 AND e.vault_id = $2",
                                        pqxx::params{f.file_id, vaultId}).empty();
            if (!live) {
                txn.exec("UPDATE vault_remote_attach_item SET kind = 'orphan', updated_at = now() WHERE id = $1",
                         pqxx::params{f.item_id});
                ++out.orphans;
                continue;
            }
            auto indexed = std::make_shared<::vh::fs::model::File>();
            indexed->path = "/" + f.object_key;
            indexed->size_bytes = f.plaintext_bytes;
            indexed->content_hash = f.content_hash;
            indexed->remote_etag = f.etag;
            indexed->remote_version_id = f.version_id;
            indexed->remote_storage_class = f.storage_class;
            indexed->remote_encrypted = true;
            indexed->encryption_iv = f.generation;
            indexed->encrypted_with_key_version = f.key_version;
            indexed->updated_at = std::time(nullptr);
            const ::vh::sync::model::RemoteObject object(vaultId, indexed, "manifest");
            txn.exec(pqxx::prepped{"remote_object_index.upsert"},
                     pqxx::params{object.vault_id, encoding::to_utf8_string(object.object_key.u8string()),
                                  object.size_bytes, encoding::timestampToString(object.last_modified), object.etag,
                                  object.storage_class, object.restore_status, object.version_id,
                                  object.event_sequencer, object.content_hash, object.encrypted,
                                  object.encryption_iv.empty() ? std::optional<std::string>{}
                                                               : std::make_optional(object.encryption_iv),
                                  object.encrypted_with_key_version == 0
                                      ? std::optional<unsigned int>{}
                                      : std::make_optional(object.encrypted_with_key_version),
                                  object.source});
            txn.exec("INSERT INTO sync_file_baseline (file_id, vault_id, content_hash, size_bytes, remote_etag, "
                     "  remote_size_bytes, remote_content_hash, synced_at) "
                     "VALUES ($1, $2, $3, $4, $5, $4, $3, now()) "
                     "ON CONFLICT (file_id) DO UPDATE SET vault_id = EXCLUDED.vault_id, content_hash = EXCLUDED.content_hash, "
                     "  size_bytes = EXCLUDED.size_bytes, remote_etag = EXCLUDED.remote_etag, "
                     "  remote_size_bytes = EXCLUDED.remote_size_bytes, remote_content_hash = EXCLUDED.remote_content_hash, "
                     "  synced_at = now()",
                     pqxx::params{f.file_id, vaultId, f.content_hash, static_cast<int64_t>(f.plaintext_bytes), f.etag});
            ++out.indexed;
        }

        // The manifest's chain position: the root the verification published and loaded back.
        sync::Manifest::recordRoot(txn, vaultId, input.root);

        // The envelopes live in the bucket from here on, as for every S3 vault (their rows stay: the manifest names them).
        txn.exec("UPDATE vault_key_envelope SET envelope = NULL WHERE vault_id = $1 AND envelope IS NOT NULL",
                 pqxx::params{vaultId});

        // A gateway bucket on an S3 vault is a remote_cache bucket (ops::s3_gateway).
        out.gateway_flipped = txn.exec("UPDATE s3_gateway_bucket SET mode = 'remote_cache' WHERE vault_id = $1 "
                                       "AND mode = 'local'",
                                       pqxx::params{vaultId})
                                  .affected_rows() > 0;

        // A bucket the control plane already knows (provisioned or adopted, unbound) is bound with its ownership kept.
        if (input.upstream_bucket_id)
            txn.exec("UPDATE upstream_bucket SET vault_id = $2 WHERE id = $1 AND vault_id IS NULL",
                     pqxx::params{*input.upstream_bucket_id, vaultId});

        txn.exec("UPDATE vault_remote_attach SET state = 'cutover', cutover_at = now(), last_error = NULL, "
                 "  updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId});
        out.done = true;
        return out;
    });
}

RemoteAttach::Summary RemoteAttach::summary() {
    return Transactions::read("RemoteAttach::summary", [&](pqxx::transaction_base& txn) {
        Summary s;
        for (const auto r : txn.exec("SELECT a.vault_id, a.state, v.name, a.last_error FROM vault_remote_attach a "
                                     "JOIN vault v ON v.id = a.vault_id "
                                     "WHERE v.deleted_at IS NULL AND a.state NOT IN ('done', 'aborted') "
                                     "ORDER BY a.vault_id")) {
            if (r[1].as<std::string>() == "failed")
                s.failed.push_back({.vault_id = r[0].as<uint32_t>(), .vault_name = r[2].as<std::string>(),
                                    .detail = raOpt<std::string>(r[3]).value_or("")});
            else s.unfinished.push_back(r[0].as<uint32_t>());
        }
        return s;
    });
}

std::vector<std::pair<uint32_t, std::string>> RemoteAttach::states() {
    return Transactions::read("RemoteAttach::states", [&](pqxx::transaction_base& txn) {
        std::vector<std::pair<uint32_t, std::string>> out;
        for (const auto r : txn.exec("SELECT vault_id, state FROM vault_remote_attach ORDER BY vault_id"))
            out.emplace_back(r[0].as<uint32_t>(), r[1].as<std::string>());
        return out;
    });
}

}
