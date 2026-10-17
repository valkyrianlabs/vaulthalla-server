// File recovery: the provider-version primitives of CloudEngine (listing, HEAD/GET of one version, CopyObject of a
// version as Vaulthalla's own write). The restore protocol that uses them is recovery::provider (Restore.cpp); see
// .claude/context/recovery.md, "Provider versioning".

#include "storage/CloudEngine.hpp"

#include "fs/model/File.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <stdexcept>

namespace vh::storage {

s3::ObjectVersionPage CloudEngine::listObjectVersionsPage(const std::string& prefix, const std::string& keyMarker,
                                                          const std::string& versionIdMarker,
                                                          const unsigned int maxKeys) const {
    if (!s3Provider_) throw std::runtime_error("Cloud engine has no S3 controller");
    return s3Provider_->listObjectVersionsPage(prefix, keyMarker, versionIdMarker, maxKeys);
}

std::optional<s3::ObjectVersionHead> CloudEngine::headObjectVersion(const std::string& key,
                                                                    const std::string& versionId) const {
    if (!s3Provider_) throw std::runtime_error("Cloud engine has no S3 controller");
    return s3Provider_->headObjectVersion(key, versionId);
}

s3::GetObjectResult CloudEngine::streamObjectVersion(const std::string& key, const std::string& versionId,
                                                     const std::optional<std::string>& ifMatch,
                                                     const std::optional<uint64_t> maxBytes,
                                                     const std::function<void(std::span<const uint8_t>)>& sink) const {
    if (!s3Provider_) throw std::runtime_error("Cloud engine has no S3 controller");
    if (versionId.empty()) throw std::invalid_argument("A provider version id is required: " + key);
    s3::GetObjectOptions options;
    options.if_match = ifMatch;
    options.max_body_bytes = maxBytes;
    options.version_id = versionId;
    return s3Provider_->streamObject(key, options, sink);
}

s3::CopyResult CloudEngine::copyObjectVersionAsOwnWrite(const std::string& sourceKey, const std::string& versionId,
                                                        const std::string& destKey, const uint64_t objectSize,
                                                        const std::string& sourceEtag,
                                                        const std::shared_ptr<vh::fs::model::File>& generation) const {
    if (!s3Provider_) throw std::runtime_error("Cloud engine has no S3 controller");
    // CopyObjectRewrite carries the vault's storage class (x-amz-storage-class) and never replacement metadata: the
    // version's vh-iv / vh-key-version / content-hash travel with directive COPY.
    const auto options = requestOptionsFor(s3::provider::RequestOperation::CopyObjectRewrite);
    auto own = noteOwnWrite(destKey, false, objectSize, generation);
    auto result = s3Provider_->copyObjectVersion(sourceKey, versionId, destKey, objectSize, options,
                                                 sourceEtag.empty() ? std::nullopt : std::make_optional(sourceEtag));
    own.done();
    return result;
}

}
