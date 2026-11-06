#include "sync/manifest/Chain.hpp"

#include "sync/manifest/Objects.hpp"

#include <fmt/format.h>

#include <array>
#include <utility>

namespace vh::sync::manifest {

namespace chain_detail {

constexpr std::array<std::pair<ChainError, std::string_view>, 5> kChainErrorNames{{
    {ChainError::BadRoot, "bad_root"},
    {ChainError::Rollback, "rollback"},
    {ChainError::Fork, "fork"},
    {ChainError::SegmentMissing, "segment_missing"},
    {ChainError::SegmentMismatch, "segment_mismatch"},
}};

void checkPinned(const std::string& sid, const std::string& sha, const uint64_t size,
                 const std::vector<uint8_t>* bytes) {
    if (!bytes) throw ChainRejected(ChainError::SegmentMissing, sid);
    if (bytes->size() != size || sha256Hex(*bytes) != sha) throw ChainRejected(ChainError::SegmentMismatch, sid);
}

}

std::string_view chainErrorName(const ChainError error) {
    for (const auto& [code, name] : chain_detail::kChainErrorNames)
        if (code == error) return name;
    return "bad_root";
}

std::optional<ChainError> chainErrorFromName(const std::string_view name) {
    for (const auto& [code, n] : chain_detail::kChainErrorNames)
        if (n == name) return code;
    return std::nullopt;
}

ChainRejected::ChainRejected(const ChainError code, const std::string& detail, const uint64_t epoch,
                             std::string rootSha256)
    : std::runtime_error(detail.empty() ? fmt::format("manifest {}", chainErrorName(code))
                                        : fmt::format("manifest {}: {}", chainErrorName(code), detail)),
      code_(code), epoch_(epoch), rootSha256_(std::move(rootSha256)) {}

Acceptance checkChain(const RootDocument& root, const std::string& rootSha256, const std::optional<Known>& known,
                      const RetainedRootLookup& retained) {
    Acceptance out{root.epoch, rootSha256, false};
    if (!known) return out;

    if (root.epoch < known->epoch)
        throw ChainRejected(ChainError::Rollback,
                            fmt::format("epoch {} is older than the known epoch {}", root.epoch, known->epoch),
                            root.epoch, rootSha256);
    if (root.epoch == known->epoch) {
        if (rootSha256 != known->root_sha256)
            throw ChainRejected(ChainError::Fork, fmt::format("another root at the known epoch {}", root.epoch),
                                root.epoch, rootSha256);
        return out;
    }
    if (root.epoch == known->epoch + 1) {
        if (root.prev != known->root_sha256)
            throw ChainRejected(ChainError::Fork, fmt::format("epoch {} does not follow the known root", root.epoch),
                                root.epoch, rootSha256);
        return out;
    }

    // epoch > known + 1: walk back through retained roots.
    auto prev = root.prev;
    auto epoch = root.epoch;
    while (retained && prev && epoch > known->epoch + 1) {
        const auto older = retained(*prev);
        if (!older || older->epoch != epoch - 1) break;
        prev = older->prev;
        epoch = older->epoch;
    }
    if (epoch == known->epoch + 1) {
        if (prev != known->root_sha256)
            throw ChainRejected(ChainError::Fork,
                                fmt::format("the chain from epoch {} reaches epoch {} through another root", root.epoch,
                                            known->epoch),
                                root.epoch, rootSha256);
        return out;
    }
    out.gap = true;
    return out;
}

void checkSegment(const SegmentRef& ref, const std::vector<uint8_t>* bytes) {
    chain_detail::checkPinned(ref.sid, ref.object_sha256, ref.size, bytes);
}

void checkSnapshot(const SnapshotRef& ref, const std::vector<uint8_t>* bytes) {
    chain_detail::checkPinned(ref.sid, ref.object_sha256, ref.size, bytes);
}

Acceptance acceptRoot(const RootDocument& root, const std::span<const uint8_t> rootObject,
                      const std::optional<Known>& known, const std::map<std::string, std::vector<uint8_t>>& segments,
                      const RetainedRootLookup& retained) {
    const auto accepted = checkChain(root, sha256Hex(rootObject), known, retained);
    for (const auto& ref : root.segments) {
        const auto it = segments.find(ref.sid);
        checkSegment(ref, it == segments.end() ? nullptr : &it->second);
    }
    return accepted;
}

}
