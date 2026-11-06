#pragma once

#include "protocols/s3/ObjectStore.hpp"
#include "fs/Fwd.hpp"

#include <filesystem>
#include <map>
#include <memory>
#include <cstddef>
#include <string>
#include <vector>

namespace vh::protocols::s3 {

// S3 multipart uploads. Parts live in <backing>/<VH_S3_GATEWAY_MULTIPART_PARTS_DIRNAME>/<parts dir id>/ as files
// sealed under the vault's key (protocols/s3/PartCipher.hpp, #345): they survive restarts, and Complete streams them
// into the vault object with no plaintext copy on disk. Size and ETag stay those of the plaintext.
class MultipartStore {
public:
    std::string createUpload(const ResolvedBucket& bucket, const std::string& key,
                             const PutObjectOptions& options) const;
    db::query::s3::MultipartPart uploadPart(const ResolvedBucket& bucket, const std::string& key,
                                            const std::string& uploadId, uint32_t partNumber,
                                            const std::vector<uint8_t>& body) const;
    db::query::s3::MultipartPart uploadPartFromSource(const ResolvedBucket& bucket, const std::string& key,
                                                      const std::string& uploadId, uint32_t partNumber,
                                                      const fs::PlaintextSource& body) const;
    db::query::s3::ObjectState completeUpload(const ResolvedBucket& bucket, const std::string& key,
                                              const std::string& uploadId,
                                              const std::vector<std::pair<uint32_t, std::string>>& requestedParts) const;
    void abortUpload(const ResolvedBucket& bucket, const std::string& key, const std::string& uploadId) const;
    std::size_t abortExpiredUploads() const;
    std::vector<db::query::s3::MultipartUpload> listUploads(const ResolvedBucket& bucket, const std::string& prefix) const;
    std::vector<db::query::s3::MultipartPart> listParts(const ResolvedBucket& bucket, const std::string& key,
                                                        const std::string& uploadId) const;

    static std::filesystem::path partRoot();

    // What sweepAtStartup did.
    struct Sweep {
        std::size_t sealed{};         // plaintext parts from before #345 sealed (plaintext deleted)
        std::size_t unconvertible{};  // plaintext parts left as they are (no vault key, missing, or not their MD5)
        std::size_t strays{};         // files in open uploads' directories no part row points at
        std::size_t orphanDirs{};     // part directories of uploads that are no longer open
    };
    // At startup, before the gateway serves: seals every plaintext part (#345) after checking it against its recorded
    // MD5 and size, and removes what no open upload references (a crashed Complete's plaintext concatenation, a part
    // superseded mid-write, the directories of finished uploads). Throws if the uploads can't be listed (then nothing
    // is removed).
    Sweep sweepAtStartup() const;

private:
    ObjectStore objects_;
};

}
