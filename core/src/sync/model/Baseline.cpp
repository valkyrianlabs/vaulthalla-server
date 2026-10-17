#include "sync/model/Baseline.hpp"

#include "fs/model/File.hpp"

#include <string_view>

namespace vh::sync::model {

namespace {

// ETags arrive quoted (PUT/HEAD headers, LIST) or bare (event notifications): compare the value.
std::string_view baselineUnquoted(const std::string& etag) {
    std::string_view v(etag);
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"') v = v.substr(1, v.size() - 2);
    return v;
}

}

Baseline Baseline::agreed(const fs::model::File& local, const fs::model::File& remote) {
    return {
        .file_id = local.id,
        .content_hash = local.content_hash,
        .size_bytes = local.size_bytes,
        .remote_content_hash = remote.content_hash,
        .remote_etag = remote.remote_etag,
        .remote_size_bytes = remote.size_bytes
    };
}

Baseline Baseline::afterUpload(const fs::model::File& local) {
    // The index row an upload writes is the local snapshot (plaintext size, content hash), so that is what the
    // next pass sees as the remote side.
    return {
        .file_id = local.id,
        .content_hash = local.content_hash,
        .size_bytes = local.size_bytes,
        .remote_content_hash = local.content_hash,
        .remote_etag = std::nullopt,
        .remote_size_bytes = local.size_bytes
    };
}

Baseline Baseline::afterDownload(const fs::model::File& local, const fs::model::File& remote) {
    return agreed(local, remote);
}

Baseline Baseline::afterReplay(const uint32_t fileId, const std::optional<std::string>& generationHash,
                               const uint64_t generationSize, const std::optional<std::string>& etag) {
    return {
        .file_id = fileId,
        .content_hash = std::string(kReplayMarker),
        .size_bytes = generationSize,
        .remote_content_hash = generationHash,
        .remote_etag = etag && !etag->empty() ? etag : std::nullopt,
        .remote_size_bytes = generationSize
    };
}

bool Baseline::publishing() const { return content_hash && *content_hash == kReplayMarker; }

bool Baseline::sameAs(const Baseline& other) const {
    return file_id == other.file_id && content_hash == other.content_hash && size_bytes == other.size_bytes &&
           remote_content_hash == other.remote_content_hash && remote_etag == other.remote_etag &&
           remote_size_bytes == other.remote_size_bytes;
}

bool localChangedSince(const fs::model::File& local, const Baseline& base) {
    if (local.content_hash && base.content_hash) return *local.content_hash != *base.content_hash;
    return local.size_bytes != base.size_bytes;
}

bool remoteChangedSince(const fs::model::File& remote, const Baseline& base) {
    if (remote.content_hash && base.remote_content_hash) return *remote.content_hash != *base.remote_content_hash;
    if (remote.remote_etag && base.remote_etag) return baselineUnquoted(*remote.remote_etag) != baselineUnquoted(*base.remote_etag);
    if (base.remote_size_bytes) return remote.size_bytes != *base.remote_size_bytes;
    return remote.size_bytes != base.size_bytes;
}

Divergence classify(const fs::model::File& local, const fs::model::File& remote, const Baseline* base) {
    if (!base) return Divergence::Unknown;
    const bool localMoved = localChangedSince(local, *base);
    const bool remoteMoved = remoteChangedSince(remote, *base);
    if (localMoved && remoteMoved) return Divergence::Both;
    if (localMoved) return Divergence::LocalOnly;
    if (remoteMoved) return Divergence::RemoteOnly;
    return Divergence::InSync;
}

const char* toString(const Divergence d) {
    switch (d) {
        case Divergence::InSync: return "in_sync";
        case Divergence::LocalOnly: return "local_only";
        case Divergence::RemoteOnly: return "remote_only";
        case Divergence::Both: return "both";
        case Divergence::Unknown: return "unknown";
    }
    return "unknown";
}

}
