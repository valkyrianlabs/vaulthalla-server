#pragma once

#include "fs/cache/Record.hpp"

#include <memory>
#include <filesystem>
#include <vector>
#include <optional>
#include <string>
#include <cstdint>

namespace vh::db::query::fs {

class Cache {
    using R = vh::fs::cache::Record;
    using RecordPtr = std::shared_ptr<R>;
    using Records = std::vector<RecordPtr>;

public:
    Cache() = default;

    static void addCacheIndex(const RecordPtr& index);
    static void upsertCacheIndex(const RecordPtr& index);
    static void updateCacheIndex(const RecordPtr& index);
    static void deleteCacheIndex(unsigned int indexId);
    static void deleteCacheIndex(unsigned int vaultId, const std::filesystem::path& relPath);
    static RecordPtr getCacheIndex(unsigned int indexId);
    static RecordPtr getCacheIndexByPath(unsigned int vaultId, const std::filesystem::path& path);
    static Records listCacheIndices(unsigned int vaultId, const std::filesystem::path& relPath = {}, bool recursive = false);
    static Records listCacheIndicesByFile(unsigned int fileId);
    [[nodiscard]] static Records listCacheIndicesByType(unsigned int vaultId, const R::Type& type);
    [[nodiscard]] static Records nLargestCacheIndices(unsigned int n, unsigned int vaultId, const std::filesystem::path& relPath, bool recursive = false);
    [[nodiscard]] static Records nLargestCacheIndicesByType(unsigned int n, unsigned int vaultId, const R::Type& type);

    [[nodiscard]] static unsigned int countCacheIndices(unsigned int vaultId, const std::optional<R::Type>& type = std::nullopt);

    [[nodiscard]] static bool cacheIndexExists(unsigned int vaultId, const std::filesystem::path& relPath);

    // Derived artifacts (type 'derived'), see preview::cache::Store.
    static void upsertDerivedArtifact(const RecordPtr& record);
    [[nodiscard]] static RecordPtr getDerivedArtifact(unsigned int fileId, const std::string& kind, const std::string& variant);
    static void touchDerivedArtifact(unsigned int id);
    static void touchDerivedArtifacts(const std::vector<unsigned int>& ids);
    // Every derived row of `fileIds` whose kind is one of `kinds` (one round trip; Store::status).
    [[nodiscard]] static Records listDerivedArtifactsFor(const std::vector<unsigned int>& fileIds,
                                                         const std::vector<std::string>& kinds);
    // Deletes the row only if it still describes sourceId (a concurrent regeneration wins).
    static bool deleteDerivedArtifactIfUnchanged(unsigned int id, const std::string& sourceId);
    [[nodiscard]] static Records listDerivedArtifactsByFile(unsigned int fileId);
    [[nodiscard]] static Records listDerivedArtifactsByVault(unsigned int vaultId);
    [[nodiscard]] static uint64_t derivedArtifactsTotalSize();
    [[nodiscard]] static Records listDerivedArtifactsLru(unsigned int limit);
    [[nodiscard]] static Records listDerivedArtifactsIdle(uint64_t idleSeconds, unsigned int limit);
    [[nodiscard]] static Records listDerivedArtifactsWithStaleKey(unsigned int vaultId, unsigned int currentKeyVersion);
    [[nodiscard]] static std::vector<unsigned int> listDerivedFileIdsByVault(unsigned int vaultId);
};

}
