#pragma once

#include "sync/manifest/Document.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// The reader's chain rules (spec 03 §4.1), applied after the root authenticated: what the reader knows (the daemon's
// remote_manifest_state, a customer checkpoint in a restore, nothing in a blind restore) against the root it got.
//
//   epoch <  known.epoch                         rollback: refuse
//   epoch == known.epoch,     hash != known      fork: refuse
//   epoch == known.epoch + 1, prev != known      fork
//   epoch >  known.epoch + 1                     accept if the chain back to known walks through retained roots (a
//                                                fork if it reaches known's epoch with another hash); otherwise accept
//                                                with a gap warning
//   no known state                               accept
//
// then every segment the root names must exist and match its pinned SHA-256 and size. The error names are the
// vectors' `expect.error` spellings.
namespace vh::sync::manifest {

struct Known {
    uint64_t epoch{};
    std::string root_sha256;
    // version_log buckets (spec 06 §5.2): the provider version id of that root, when known. Not part of identity: a
    // root is its epoch and hash, whichever version holds it.
    std::optional<std::string> version_id{};
    [[nodiscard]] bool operator==(const Known& o) const { return epoch == o.epoch && root_sha256 == o.root_sha256; }
};

// OrderViolation, Superseded and PublishModeMismatch are refusals of design/encryption/06-publish-without-preconditions.md
// (§5.3, §5.5, I9): a settled root displaced (the provider broke its ordering assumptions), a head whose `writers` no
// longer names this server, a head published in another mode than the bucket's.
enum class ChainError { BadRoot, Rollback, Fork, SegmentMissing, SegmentMismatch, OrderViolation, Superseded,
                        PublishModeMismatch };

[[nodiscard]] std::string_view chainErrorName(ChainError error);
[[nodiscard]] std::optional<ChainError> chainErrorFromName(std::string_view name);

class ChainRejected : public std::runtime_error {
public:
    explicit ChainRejected(ChainError code, const std::string& detail = {}, uint64_t epoch = 0,
                           std::string rootSha256 = {});
    [[nodiscard]] ChainError code() const noexcept { return code_; }
    // The refused root (rollback, fork): its epoch and object hash.
    [[nodiscard]] uint64_t epoch() const noexcept { return epoch_; }
    [[nodiscard]] const std::string& rootSha256() const noexcept { return rootSha256_; }

private:
    ChainError code_;
    uint64_t epoch_;
    std::string rootSha256_;
};

struct Acceptance {
    uint64_t epoch{};
    std::string root_sha256;
    // epoch > known + 1 and the chain back to known could not be walked: another writer published several times
    // (e.g. a restore elsewhere). Accepted, with this warning.
    bool gap{false};
    [[nodiscard]] bool operator==(const Acceptance&) const = default;
};

// A retained root by its object hash (provider versions of `.vaulthalla/root`, already authenticated), for the gap
// walk; nullopt when none is retained.
using RetainedRootLookup = std::function<std::optional<RootDocument>(const std::string& rootSha256)>;

// The root-level rules. Throws ChainRejected(Rollback | Fork).
[[nodiscard]] Acceptance checkChain(const RootDocument& root, const std::string& rootSha256,
                                    const std::optional<Known>& known, const RetainedRootLookup& retained = {});

// The pin of one segment: nullptr bytes is SegmentMissing, other bytes or size SegmentMismatch.
void checkSegment(const SegmentRef& ref, const std::vector<uint8_t>* bytes);
void checkSnapshot(const SnapshotRef& ref, const std::vector<uint8_t>* bytes);

// Everything at once, as the vectors state it: chain rules, then every segment by sid. No fallbacks (Reader.hpp has
// those).
[[nodiscard]] Acceptance acceptRoot(const RootDocument& root, std::span<const uint8_t> rootObject,
                                    const std::optional<Known>& known,
                                    const std::map<std::string, std::vector<uint8_t>>& segments,
                                    const RetainedRootLookup& retained = {});

}
