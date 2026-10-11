#include "db/query/fs/Cache.hpp"
#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "fs/cache/Record.hpp"
#include "db/encoding/u8.hpp"

namespace vh::db::query::fs {

using vh::fs::cache::Record;

void Cache::upsertCacheIndex(const std::shared_ptr<Record>& index) {
    if (!index) throw std::invalid_argument("CacheIndex cannot be null");
    Transactions::exec("Cache::upsertCacheIndex", [&](pqxx::work& txn) {
        pqxx::params p;
        p.append(index->vault_id);
        p.append(index->file_id);
        p.append(encoding::to_utf8_string(index->path.u8string()));
        p.append(to_string(index->type));
        p.append(index->size);

        txn.exec(pqxx::prepped{"upsert_cache_index"}, p);
    });
}

void Cache::deleteCacheIndex(unsigned int indexId) {
    Transactions::exec("Cache::deleteCacheIndex", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"delete_cache_index"}, pqxx::params{indexId});
    });
}

void Cache::deleteCacheIndex(unsigned int vaultId, const std::filesystem::path& relPath) {
    Transactions::exec("Cache::deleteCacheIndexByPath", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"delete_cache_index_by_path"}, pqxx::params{vaultId, encoding::to_utf8_string(relPath.u8string())});
    });
}

std::shared_ptr<Record> Cache::getCacheIndex(unsigned int indexId) {
    return Transactions::exec("Cache::getCacheIndex", [&](pqxx::work& txn) -> std::shared_ptr<Record> {
        const auto res = txn.exec(pqxx::prepped{"get_cache_index"}, pqxx::params{indexId});
        return std::make_shared<Record>(res.one_row_ref());
    });
}

std::shared_ptr<Record> Cache::getCacheIndexByPath(unsigned int vaultId, const std::filesystem::path& path) {
    return Transactions::exec("Cache::getCacheIndexByPath", [&](pqxx::work& txn) -> std::shared_ptr<Record> {
        const auto res = txn.exec(pqxx::prepped{"get_cache_index_by_path"}, pqxx::params{vaultId, encoding::to_utf8_string(path.u8string())});
        return std::make_shared<Record>(res.one_row_ref());
    });
}

std::vector<std::shared_ptr<Record>> Cache::listCacheIndices(unsigned int vaultId, const std::filesystem::path& relPath, const bool recursive) {
    return Transactions::exec("Cache::listCacheindices", [&](pqxx::work& txn) -> std::vector<std::shared_ptr<Record>> {
        pqxx::result res;

        if (relPath.empty()) res = txn.exec(pqxx::prepped{"list_cache_indices"}, pqxx::params{vaultId});
        else {
            const auto patterns = computePatterns(relPath.string(), recursive);
            if (recursive) res = txn.exec(pqxx::prepped{"list_cache_indices_by_path_recursive"}, pqxx::params{vaultId, patterns.like});
            else res = txn.exec(pqxx::prepped{"list_cache_indices_by_path"}, pqxx::params{vaultId, patterns.like, patterns.not_like});
        }

        return db::sharedRows<Record>(res);
    });
}

std::vector<std::shared_ptr<Record>> Cache::listCacheIndicesByFile(unsigned int fileId) {
    return Transactions::exec("Cache::listCacheIndicesByFile", [&](pqxx::work& txn) -> std::vector<std::shared_ptr<Record>> {
        const auto res = txn.exec(pqxx::prepped{"list_cache_indices_by_file"}, pqxx::params{fileId});
        return db::sharedRows<Record>(res);
    });
}

std::vector<std::shared_ptr<Record>> Cache::listCacheIndicesByType(const unsigned int vaultId, const Record::Type& type) {
    return Transactions::exec("Cache::listCacheIndicesByType", [&](pqxx::work& txn) -> std::vector<std::shared_ptr<Record>> {
        const auto res = txn.exec(pqxx::prepped{"list_cache_indices_by_type"}, pqxx::params{vaultId, to_string(type)});
        return db::sharedRows<Record>(res);
    });
}

std::vector<std::shared_ptr<Record>> Cache::nLargestCacheIndicesByType(const unsigned int n, const unsigned int vaultId, const Record::Type& type) {
    return Transactions::exec("Cache::nLargestCacheIndicesByType", [&](pqxx::work& txn) -> std::vector<std::shared_ptr<Record>> {
        const auto res = txn.exec(pqxx::prepped{"n_largest_cache_indices_by_type"}, pqxx::params{vaultId, to_string(type), n});
        return db::sharedRows<Record>(res);
    });
}

std::vector<std::shared_ptr<Record>> Cache::nLargestCacheIndices(const unsigned int n, const unsigned int vaultId, const std::filesystem::path& relPath, const bool recursive) {
    return Transactions::exec("Cache::nLargestCacheIndicesByPath", [&](pqxx::work& txn) -> std::vector<std::shared_ptr<Record>> {
        pqxx::result res;

        if (relPath.empty()) res = txn.exec(pqxx::prepped{"n_largest_cache_indices"}, pqxx::params{vaultId, n});
        else {
            const auto patterns = computePatterns(relPath.string(), recursive);
            if (recursive) res = txn.exec(pqxx::prepped{"n_largest_cache_indices_by_path_recursive"}, pqxx::params{vaultId, patterns.like, n});
            else res = txn.exec(pqxx::prepped{"n_largest_cache_indices_by_path"}, pqxx::params{vaultId, patterns.like, patterns.not_like, n});
        }

        return db::sharedRows<Record>(res);
    });
}

bool Cache::cacheIndexExists(unsigned int vaultId, const std::filesystem::path& relPath) {
    return Transactions::exec("Cache::cacheIndexExists", [&](pqxx::work& txn) -> bool {
        return txn.exec(pqxx::prepped{"cache_index_exists"}, pqxx::params{vaultId, encoding::to_utf8_string(relPath.u8string())}).one_row_ref()["exists"].as<bool>();
    });
}

unsigned int Cache::countCacheIndices(unsigned int vaultId, const std::optional<Record::Type>& type) {
    return Transactions::exec("Cache::countCacheIndices", [&](pqxx::work& txn) -> unsigned int {
        if (type) return txn.exec(pqxx::prepped{"count_cache_indices_by_type"}, pqxx::params{vaultId, to_string(*type)}).one_row_ref()["count"].as<unsigned int>();
        return txn.exec(pqxx::prepped{"count_cache_indices"}, pqxx::params{vaultId}).one_row_ref()["count"].as<unsigned int>();
    });
}


void Cache::upsertDerivedArtifact(const RecordPtr& r) {
    if (!r) throw std::invalid_argument("Derived artifact record cannot be null");
    Transactions::exec("Cache::upsertDerivedArtifact", [&](pqxx::work& txn) {
        pqxx::params p;
        p.append(r->vault_id);
        p.append(r->file_id);
        p.append(encoding::to_utf8_string(r->path.u8string()));
        p.append(static_cast<int64_t>(r->size));
        p.append(r->kind);
        p.append(r->variant);
        p.append(r->source_id);
        p.append(r->generator_version);
        if (r->artifact_iv.empty()) p.append(); else p.append(r->artifact_iv);
        if (r->artifact_iv.empty()) p.append(); else p.append(r->artifact_key_version);
        p.append(std::string(r->status == R::Status::Failed ? "failed" : "ready"));
        if (r->failure_reason.empty()) p.append(); else p.append(r->failure_reason);
        if (r->page_count) p.append(*r->page_count); else p.append();
        txn.exec(pqxx::prepped{"upsert_derived_artifact"}, p);
    });
}

std::shared_ptr<Record> Cache::getDerivedArtifact(const unsigned int fileId, const std::string& kind, const std::string& variant) {
    // On every preview hit: one round trip, no BEGIN/COMMIT.
    return Transactions::read("Cache::getDerivedArtifact", [&](pqxx::transaction_base& txn) -> std::shared_ptr<Record> {
        const auto res = txn.exec(pqxx::prepped{"get_derived_artifact"}, pqxx::params{fileId, kind, variant});
        if (res.empty()) return nullptr;
        return std::make_shared<Record>(res[0]);
    });
}

void Cache::touchDerivedArtifacts(const std::vector<unsigned int>& ids) {
    if (ids.empty()) return;
    std::string array = "{";
    for (std::size_t i = 0; i < ids.size(); ++i) array += (i ? "," : "") + std::to_string(ids[i]);
    array += "}";
    Transactions::exec("Cache::touchDerivedArtifacts", [&](pqxx::work& txn) {
        txn.exec("UPDATE cache_index SET last_accessed = NOW() WHERE id = ANY($1::INTEGER[]) AND type = 'derived'",
                 pqxx::params{array});
    });
}

std::vector<std::shared_ptr<Record>> Cache::listDerivedArtifactsFor(const std::vector<unsigned int>& fileIds,
                                                                   const std::vector<std::string>& kinds) {
    if (fileIds.empty() || kinds.empty()) return {};
    std::string ids = "{";
    for (std::size_t i = 0; i < fileIds.size(); ++i) ids += (i ? "," : "") + std::to_string(fileIds[i]);
    ids += "}";
    std::string kindArray = "{";
    for (std::size_t i = 0; i < kinds.size(); ++i) {
        // Artifact kinds are code-defined identifiers ([a-z0-9-]); quote anyway.
        kindArray += (i ? ",\"" : "\"");
        for (const char c : kinds[i]) {
            if (c == '"' || c == '\\') kindArray += '\\';
            kindArray += c;
        }
        kindArray += '"';
    }
    kindArray += "}";
    return Transactions::read("Cache::listDerivedArtifactsFor", [&](pqxx::transaction_base& txn) {
        return db::sharedRows<Record>(txn.exec(
            "SELECT * FROM cache_index WHERE type = 'derived' AND file_id = ANY($1::INTEGER[]) AND kind = ANY($2::TEXT[])",
            pqxx::params{ids, kindArray}));
    });
}

void Cache::touchDerivedArtifact(const unsigned int id) {
    Transactions::exec("Cache::touchDerivedArtifact", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"touch_derived_artifact"}, pqxx::params{id});
    });
}

bool Cache::deleteDerivedArtifactIfUnchanged(const unsigned int id, const std::string& sourceId) {
    return Transactions::exec("Cache::deleteDerivedArtifactIfUnchanged", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"delete_derived_artifact_if_unchanged"}, pqxx::params{id, sourceId}).affected_rows() > 0;
    });
}

std::vector<std::shared_ptr<Record>> Cache::listDerivedArtifactsByFile(const unsigned int fileId) {
    return Transactions::exec("Cache::listDerivedArtifactsByFile", [&](pqxx::work& txn) {
        return db::sharedRows<Record>(txn.exec(pqxx::prepped{"list_derived_artifacts_by_file"}, pqxx::params{fileId}));
    });
}

std::vector<std::shared_ptr<Record>> Cache::listDerivedArtifactsByVault(const unsigned int vaultId) {
    return Transactions::exec("Cache::listDerivedArtifactsByVault", [&](pqxx::work& txn) {
        return db::sharedRows<Record>(txn.exec(pqxx::prepped{"list_derived_artifacts_by_vault"}, pqxx::params{vaultId}));
    });
}

uint64_t Cache::derivedArtifactsTotalSize() {
    return Transactions::exec("Cache::derivedArtifactsTotalSize", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"derived_artifacts_total_size"}).one_row_ref()["total"].as<uint64_t>();
    });
}

std::vector<std::shared_ptr<Record>> Cache::listDerivedArtifactsLru(const unsigned int limit) {
    return Transactions::exec("Cache::listDerivedArtifactsLru", [&](pqxx::work& txn) {
        return db::sharedRows<Record>(txn.exec(pqxx::prepped{"list_derived_artifacts_lru"}, pqxx::params{limit}));
    });
}

std::vector<std::shared_ptr<Record>> Cache::listDerivedArtifactsIdle(const uint64_t idleSeconds, const unsigned int limit) {
    return Transactions::exec("Cache::listDerivedArtifactsIdle", [&](pqxx::work& txn) {
        return db::sharedRows<Record>(txn.exec(pqxx::prepped{"list_derived_artifacts_idle"},
                                                  pqxx::params{static_cast<int64_t>(idleSeconds), limit}));
    });
}

std::vector<std::shared_ptr<Record>> Cache::listDerivedArtifactsWithStaleKey(const unsigned int vaultId, const unsigned int currentKeyVersion) {
    return Transactions::exec("Cache::listDerivedArtifactsWithStaleKey", [&](pqxx::work& txn) {
        return db::sharedRows<Record>(txn.exec(pqxx::prepped{"list_derived_artifacts_stale_key"},
                                                  pqxx::params{vaultId, currentKeyVersion}));
    });
}

std::vector<unsigned int> Cache::listDerivedFileIdsByVault(const unsigned int vaultId) {
    return Transactions::exec("Cache::listDerivedFileIdsByVault", [&](pqxx::work& txn) {
        std::vector<unsigned int> ids;
        for (const auto& row : txn.exec(pqxx::prepped{"list_derived_file_ids_by_vault"}, pqxx::params{vaultId}))
            ids.push_back(row["file_id"].as<unsigned int>());
        return ids;
    });
}

}
