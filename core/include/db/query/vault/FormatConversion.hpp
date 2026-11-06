#pragma once

#include "vault/FormatConversion.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// The catalog side of the local format conversion (vault/FormatConversion.hpp, #372). Legacy rows are found through
// the generated content_format columns and their partial indexes (migration 126), never by parsing ids.
namespace vh::db::query::vault {

class FormatConversion {
public:
    // Live files of the vault still gcm0 on keyVersion, id > afterId, ascending, at most limit.
    [[nodiscard]] static std::vector<std::shared_ptr<::vh::fs::model::File>> legacyFiles(uint32_t vaultId,
                                                                                 unsigned int keyVersion,
                                                                                 uint32_t afterId, std::size_t limit);

    // Legacy blobs of the vault, id > afterId, ascending, at most limit, each with the object uid of a live file it was
    // captured from. With exceptLiveOn, blobs holding the generation of a live gcm0 file on that key version are left
    // out (they convert together with it).
    [[nodiscard]] static std::vector<::vh::vault::conversion::Blob> legacyBlobs(uint32_t vaultId, int64_t afterId,
                                                                              std::size_t limit,
                                                                              std::optional<unsigned int> exceptLiveOn);

    // The blob holding exactly this generation, if any.
    [[nodiscard]] static std::optional<::vh::vault::conversion::Blob> blobByGeneration(uint32_t vaultId,
                                                                                     const std::string& generation,
                                                                                     unsigned int keyVersion);

    // One transaction: the files row (vault, path) from expected to the file's generation and key version
    // (compare-and-set, the statement key rotation uses), then, only if that moved, the blob swap.
    [[nodiscard]] static ::vh::vault::conversion::FileCommit
    commitFile(const ::vh::fs::model::File& file, const std::string& expectedGeneration, unsigned int expectedKeyVersion,
               const std::optional<::vh::vault::conversion::BlobSwap>& blob);

    // The blob swap alone: false when the row no longer holds the old generation and storage name.
    [[nodiscard]] static bool commitBlob(uint32_t vaultId, const ::vh::vault::conversion::BlobSwap& swap);

    struct Remaining {
        uint64_t files{}, file_bytes{};      // live gcm0 files on keyVersion (sealed bytes on disk)
        uint64_t files_other_versions{};     // live gcm0 files on any other key version (a rotation's or salvage's)
        uint64_t blobs{}, blob_bytes{};      // gcm0 recovery blobs
    };
    // keyVersion 0 (no engine): every legacy file counts under files.
    [[nodiscard]] static Remaining remaining(uint32_t vaultId, unsigned int keyVersion);
};

}
